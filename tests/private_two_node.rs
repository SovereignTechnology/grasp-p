//! GRASP-P Phase-2 exit test suite (phase2-design.md §5).
//!
//! Two-node private-repo replication: TestRelay pair A/B, LMDB backend,
//! private repos + blob mirror enabled, each node bootstrapped to the other
//! (deterministic pairing — private repos have no announcement to discover
//! peers from).
//!
//! 1. Replication E2E: 30640 + 2 blobs + 30641 + one stream wrap PER
//!    accepted wire kind (legacy 1059 and CORD 3359) pushed to A are all
//!    served by B (REQ + blob GET, byte-compared) within the bound.
//! 2. Out-of-order: 30641 + both wrap kinds published to B BEFORE the 30640
//!    exists anywhere; after the 30640 lands on A and syncs, B serves them
//!    all (private rejected-index reprocess hook).
//! 3. Kill-one-node backfill: stop B, push a fresh edition + blob to A,
//!    restart B on the same LMDB paths; B backfills + mirrors.
//! 4. Disabled no-op: with private repos disabled on both nodes, a normal
//!    public 30617 repo still replicates A→B and nothing private leaks.
//! 5. Mirror bounds: a 30641 referencing a blob absent on the peer is still
//!    accepted + replicated, but the blob GET is 404 on B, the mirror
//!    failure counter increments, and mirror lag stays > 0.
//! 6. Mixed-version pair: A dual-accepting legacy wraps paired with a B that
//!    has closed the window — 3359 crosses the split, 1059 does not, and the
//!    policy fingerprints diverge.
//!
//! ```bash
//! cargo test --test private_two_node -- --nocapture --test-threads=1
//! ```

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use bitcoin_hashes::{sha256, Hash};
use nostr_sdk::prelude::*;

use common::port::reserve_port;
use common::sync_helpers::{
    fetch_metrics, setup_announcement_on_relay, wait_for_event_on_relay, ParsedMetrics,
};
use common::TestRelay;

/// Generous outer bound for cross-node replication polls. NGIT_TEST=1 gives
/// 200ms registration/batch timers and 1s mirror repair ticks, but the
/// historic-sync completion double-check carries a hardcoded 6s sleep and
/// connect/reconnect races add more — observed end-to-end latency is ~1-8s,
/// so 90s is pure headroom (and stays under the 120s rejected-hold TTL for
/// the out-of-order scenario).
const REPLICATION_BOUND: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

// ============================================================================
// Relay/WebSocket helpers (mirroring tests/private_repos.rs)
// ============================================================================

async fn connect_client(relay_url: &str, keys: Keys) -> Client {
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys))
        .build();
    client
        .add_relay(relay_url)
        .await
        .expect("Failed to add relay");
    client.connect().await;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if client
            .relays()
            .await
            .values()
            .any(|r| r.status().is_connected())
        {
            return client;
        }
    }
    panic!("Failed to connect to relay {relay_url} within 3s");
}

/// Publish an event and return `(accepted, relay_message)`.
async fn publish_with_result(relay_url: &str, event: &Event) -> (bool, String) {
    let client = connect_client(relay_url, Keys::generate()).await;
    let output = client
        .send_event(event)
        .await
        .expect("send_event transport failure");
    let accepted = !output.success.is_empty();
    let message = output
        .failed
        .values()
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    client.disconnect().await;
    (accepted, message)
}

async fn fetch_from(relay_url: &str, filter: Filter) -> Vec<Event> {
    let client = connect_client(relay_url, Keys::generate()).await;
    let events = client
        .fetch_events(filter)
        .timeout(Duration::from_secs(10))
        .await
        .expect("fetch_events failed");
    client.disconnect().await;
    events.into_iter().collect()
}

// ============================================================================
// GRASP-P event builders (two-domain variants of tests/private_repos.rs)
// ============================================================================

/// A valid alias: exactly 32 lowercase hex chars.
fn random_alias() -> String {
    Keys::generate().public_key().to_hex()[..32].to_string()
}

/// `NGIT_GRASP_P_TENANT_WHITELIST` value (comma-separated npubs) covering
/// every tenant key that authors a kind-30640 in a test. WP-E flipped the
/// shipped admission default to whitelist: pair tests run under the new
/// default with their tenants listed explicitly. The SAME value goes to
/// both nodes (identical extra_env) so the policy_fingerprint preimage —
/// which includes the whitelist — stays in parity and synced registrations
/// pass the gate on the peer.
fn whitelist_npubs(tenants: &[&Keys]) -> String {
    tenants
        .iter()
        .map(|k| k.public_key().to_bech32().expect("npub"))
        .collect::<Vec<_>>()
        .join(",")
}

fn sha256_hex(data: &[u8]) -> String {
    sha256::Hash::hash(data).to_string()
}

/// Coordinate of a 30640 registration.
fn reg_coord(tenant: &PublicKey, alias: &str) -> String {
    format!("30640:{}:{alias}", tenant.to_hex())
}

/// Schnorr proof-of-possession for a claimed w/aux key (§2 audit amendment).
fn key_pop_sig(key: &Keys, tenant: &PublicKey, alias: &str) -> String {
    let digest =
        sha256::Hash::hash(format!("grasp-p key-claim:{}:{alias}", tenant.to_hex()).as_bytes());
    key.sign_schnorr(digest.to_byte_array()).to_string()
}

fn key_entry(key: &Keys, tenant: &PublicKey, alias: &str) -> Vec<String> {
    vec![key.public_key().to_hex(), key_pop_sig(key, tenant, alias)]
}

/// Signed kind-30640 registration listing ALL `domains` in one `relays` tag
/// and one `server` tag (Phase-1 validation requires this node's domain to
/// appear in both; a two-node pair therefore lists both nodes).
fn registration_event(
    tenant: &Keys,
    alias: &str,
    writer: &Keys,
    domains: &[&str],
    created_at: Option<u64>,
) -> Event {
    let relays: Vec<String> = domains.iter().map(|d| format!("ws://{d}")).collect();
    let servers: Vec<String> = domains.iter().map(|d| format!("http://{d}")).collect();
    let tags = vec![
        Tag::identifier(alias),
        Tag::custom("relays", relays),
        Tag::custom("server", servers),
        Tag::custom("w", key_entry(writer, &tenant.public_key(), alias)),
    ];
    let mut builder = EventBuilder::new(Kind::Custom(30640), "");
    if let Some(secs) = created_at {
        builder = builder.custom_created_at(Timestamp::from_secs(secs));
    }
    builder.tags(tags).finalize(tenant).expect("sign 30640")
}

/// Signed kind-30641 state root: `m` manifest + `pack` blobs.
fn state_root_event(
    writer: &Keys,
    tenant: &PublicKey,
    alias: &str,
    manifest: (&str, u64),
    packs: &[(String, u64)],
    created_at: u64,
) -> Event {
    let mut tags = vec![
        Tag::identifier(alias),
        Tag::custom("a", vec![reg_coord(tenant, alias)]),
        Tag::custom("m", vec![manifest.0.to_string(), manifest.1.to_string()]),
    ];
    for (hash, size) in packs {
        tags.push(Tag::custom("pack", vec![hash.clone(), size.to_string()]));
    }
    EventBuilder::new(Kind::Custom(30641), "")
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize(writer)
        .expect("sign 30641")
}

/// The stored stream-wrap wire kinds a node admits under the shipped
/// `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND=true` default: the dedicated CORD
/// kind 3359 and, for the duration of the migration window, the legacy 1059.
///
/// Dual-accept means BOTH must replicate, so the pair scenarios below run
/// once per kind rather than hardcoding one: the cross-node path matches on
/// the wrap kind in several places (derived sync filters, the admission
/// arms, the rejection hold keying) and a kind missing from any one of them
/// is invisible to a single-node test.
///
/// Scope note: exit2 pins the CLIENT-submission hold
/// (`nostr/builder.rs`, the wrap arm's `None` branch). Its twin in the sync
/// ingest path (`sync/mod.rs`, the `accepts_stream_wrap_kind` arm of the
/// rejection hold) is UNCOVERED and stays so: B only asks a peer for wraps
/// by an author it has already accepted a 30640 for, so a synced wrap
/// preceding its own registration is a race, not something the harness can
/// order — deleting that arm leaves this suite green. What IS pinned is the
/// contract it depends on: `PrivateRejectedIndex` holds both wire kinds
/// under one author bucket and releases them together
/// (`sync::private_index::tests::test_wrap_hold_is_kind_agnostic_per_author`).
/// The dispatch arm itself is verified by inspection only.
const STREAM_WRAP_KINDS: [u16; 2] = [1059, 3359];

/// Opaque wrap-shaped event of the given wire `kind`, signed by `signer`.
fn wrap_event(signer: &Keys, kind: u16) -> Event {
    let recipient = Keys::generate();
    EventBuilder::new(
        Kind::Custom(kind),
        "AtQyM3BhY2VvcGFxdWUtY2lwaGVydGV4dC1zdGFuZC1pbg==",
    )
    .tags(vec![Tag::public_key(recipient.public_key())])
    .finalize(signer)
    .expect("sign wrap")
}

/// One wrap per accepted wire kind, all signed by the same write key.
fn wrap_events(signer: &Keys) -> Vec<(u16, Event)> {
    STREAM_WRAP_KINDS
        .iter()
        .map(|&kind| (kind, wrap_event(signer, kind)))
        .collect()
}

/// Poll until `relay_url` serves the EXACT event `id`.
///
/// Deliberately id-scoped: a kind+author filter is satisfied by ANY event
/// from that key, so once two wrap kinds are in flight from one write key a
/// kind-less or id-less wait would pass vacuously (the same failure mode as
/// the exit7 stale-edition wait).
async fn wait_for_exact_event(relay_url: &str, id: EventId, bound: Duration) -> bool {
    wait_for_event_on_relay(relay_url, Filter::new().id(id), bound).await
}

/// Signed kind-24242 Blossom auth event.
fn blossom_auth_event(signer: &Keys, sha: &str, tenant: &PublicKey, alias: &str) -> Event {
    EventBuilder::new(Kind::Custom(24242), "grasp-p two-node test auth")
        .tags(vec![
            Tag::custom("t", vec!["upload".to_string()]),
            Tag::custom("x", vec![sha.to_string()]),
            Tag::custom(
                "expiration",
                vec![(Timestamp::now().as_secs() + 600).to_string()],
            ),
            Tag::custom("a", vec![reg_coord(tenant, alias)]),
        ])
        .finalize(signer)
        .expect("sign 24242")
}

fn auth_header_value(event: &Event) -> String {
    format!("Nostr {}", BASE64_STANDARD.encode(event.as_json()))
}

/// Signed kind-24242 Blossom DELETE auth event.
fn blossom_delete_auth_event(signer: &Keys, sha: &str, tenant: &PublicKey, alias: &str) -> Event {
    EventBuilder::new(Kind::Custom(24242), "grasp-p two-node test auth")
        .tags(vec![
            Tag::custom("t", vec!["delete".to_string()]),
            Tag::custom("x", vec![sha.to_string()]),
            Tag::custom(
                "expiration",
                vec![(Timestamp::now().as_secs() + 600).to_string()],
            ),
            Tag::custom("a", vec![reg_coord(tenant, alias)]),
        ])
        .finalize(signer)
        .expect("sign 24242")
}

/// DELETE /<sha> → (status, X-Reason).
async fn delete_blob(relay: &TestRelay, sha: &str, auth: &Event) -> (u16, String) {
    let resp = reqwest::Client::new()
        .delete(format!("{}/{sha}", http_base(relay)))
        .header("authorization", auth_header_value(auth))
        .send()
        .await
        .expect("DELETE /<sha> transport");
    let status = resp.status().as_u16();
    let reason = resp
        .headers()
        .get("x-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, reason)
}

/// Deterministic pseudo-random blob content of `len` bytes, unique per seed.
fn blob_bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (seed as usize)
                .wrapping_mul(31)
                .wrapping_add(i.wrapping_mul(2654435761)) as u8
        })
        .collect()
}

// ============================================================================
// HTTP helpers
// ============================================================================

fn http_base(relay: &TestRelay) -> String {
    format!("http://{}", relay.domain())
}

/// PUT /upload → (status, X-Reason).
async fn put_blob(relay: &TestRelay, data: Vec<u8>, sha: &str, auth: &Event) -> (u16, String) {
    let resp = reqwest::Client::new()
        .put(format!("{}/upload", http_base(relay)))
        .header("authorization", auth_header_value(auth))
        .header("x-sha-256", sha)
        .body(data)
        .send()
        .await
        .expect("PUT /upload transport");
    let status = resp.status().as_u16();
    let reason = resp
        .headers()
        .get("x-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, reason)
}

/// GET /<sha> → (status, body bytes).
async fn get_blob(relay: &TestRelay, sha: &str) -> (u16, Vec<u8>) {
    let resp = reqwest::Client::new()
        .get(format!("{}/{sha}", http_base(relay)))
        .send()
        .await
        .expect("GET /<sha> transport");
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
    (status, body)
}

/// Fetch the NIP-11 document.
async fn nip11_doc(relay: &TestRelay) -> serde_json::Value {
    reqwest::Client::new()
        .get(http_base(relay))
        .header("accept", "application/nostr+json")
        .send()
        .await
        .expect("NIP-11 transport")
        .json()
        .await
        .expect("NIP-11 must be JSON")
}

/// Poll until `GET /<sha>` on `relay` returns 200 with sha-verified bytes.
/// Returns the body on success, None on timeout.
async fn wait_for_blob(relay: &TestRelay, sha: &str, bound: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + bound;
    loop {
        let (status, body) = get_blob(relay, sha).await;
        if status == 200 && sha256_hex(&body) == sha {
            return Some(body);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll `relay`'s /metrics until `check` passes on the parsed scrape.
async fn wait_for_metrics(
    relay: &TestRelay,
    bound: Duration,
    check: impl Fn(&ParsedMetrics) -> bool,
) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        if let Ok(text) = fetch_metrics(relay.url()).await {
            if check(&ParsedMetrics::parse(&text)) {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ============================================================================
// Pair fixture
// ============================================================================

/// Start a cross-bootstrapped A/B pair: LMDB backend, private repos + mirror
/// enabled (unless overridden via `extra_env`), each node's
/// NGIT_SYNC_BOOTSTRAP_RELAY_URL pointing at the other. Both ports are
/// reserved up front so each node's URL can be handed to its peer before
/// either has booted.
async fn start_pair(extra_env: &[(&str, &str)]) -> (TestRelay, TestRelay) {
    start_pair_with_b_paths(extra_env, None).await
}

/// Like [`start_pair`] but with explicit persistent data paths for node B
/// (kill-and-restart backfill tests reuse them across a restart).
async fn start_pair_with_b_paths(
    extra_env: &[(&str, &str)],
    b_paths: Option<(PathBuf, PathBuf)>,
) -> (TestRelay, TestRelay) {
    start_pair_inner(extra_env, extra_env, b_paths).await
}

/// Like [`start_pair`] but with a DIFFERENT env on each node — the
/// mixed-version pair a rolling upgrade actually produces.
///
/// Callers must NOT assert policy-fingerprint parity here: any knob in the
/// v3 preimage that differs between the two envs makes the fingerprints
/// diverge by design (that divergence is the operator-visible signal).
async fn start_pair_with_split_env(
    a_env: &[(&str, &str)],
    b_env: &[(&str, &str)],
) -> (TestRelay, TestRelay) {
    start_pair_inner(a_env, b_env, None).await
}

async fn start_pair_inner(
    a_env: &[(&str, &str)],
    b_env: &[(&str, &str)],
    b_paths: Option<(PathBuf, PathBuf)>,
) -> (TestRelay, TestRelay) {
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_a = format!("ws://127.0.0.1:{}", res_a.port());
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());
    let (b_git, b_relay) = match b_paths {
        Some((git, relay)) => (Some(git), Some(relay)),
        None => (None, None),
    };
    let a = TestRelay::start_grasp_p_pair_node(res_a, Some(url_b), true, None, None, a_env).await;
    let b =
        TestRelay::start_grasp_p_pair_node(res_b, Some(url_a), true, b_git, b_relay, b_env).await;
    (a, b)
}

/// Standard fixture: register `alias` on `origin` with a registration that
/// lists BOTH pair domains. Panics if rejected.
async fn register_on(
    origin: &TestRelay,
    domains: &[&str],
    tenant: &Keys,
    writer: &Keys,
    alias: &str,
) -> Event {
    let event = registration_event(tenant, alias, writer, domains, None);
    let (accepted, message) = publish_with_result(origin.url(), &event).await;
    assert!(
        accepted,
        "fixture 30640 registration must be accepted; got: {message:?}"
    );
    event
}

/// PUT a blob to `relay` under (tenant, alias) signed by `writer`; panics on
/// non-200.
async fn upload_blob(
    relay: &TestRelay,
    tenant: &Keys,
    writer: &Keys,
    alias: &str,
    data: &[u8],
) -> String {
    let sha = sha256_hex(data);
    let auth = blossom_auth_event(writer, &sha, &tenant.public_key(), alias);
    let (status, reason) = put_blob(relay, data.to_vec(), &sha, &auth).await;
    assert_eq!(status, 200, "blob PUT must be 200; X-Reason: {reason}");
    sha
}

// ============================================================================
// Exit test 1 — replication E2E
// ============================================================================

#[tokio::test]
async fn exit1_replication_e2e() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let (a, b) = start_pair(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())]).await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let writer = Keys::generate();
    let alias = random_alias();

    // Config parity (design §4): both nodes advertise the same
    // policy_fingerprint over NIP-11 (domain set {A,B} is symmetric).
    let doc_a = nip11_doc(&a).await;
    let doc_b = nip11_doc(&b).await;
    let fp_a = doc_a["private_repos"]["policy_fingerprint"]
        .as_str()
        .expect("A must advertise private_repos.policy_fingerprint")
        .to_string();
    let fp_b = doc_b["private_repos"]["policy_fingerprint"]
        .as_str()
        .expect("B must advertise private_repos.policy_fingerprint")
        .to_string();
    assert_eq!(
        fp_a, fp_b,
        "exit1: correctly-paired nodes must have equal policy fingerprints"
    );
    assert_eq!(fp_a.len(), 16, "fingerprint is a 16-hex sha256 prefix");

    // Register on A (listing both domains), PUT manifest + pack blobs to A.
    let reg = register_on(&a, &domain_refs, &tenant, &writer, &alias).await;
    let manifest = blob_bytes(1, 2048);
    let pack = blob_bytes(2, 3072);
    let manifest_sha = upload_blob(&a, &tenant, &writer, &alias, &manifest).await;
    let pack_sha = upload_blob(&a, &tenant, &writer, &alias, &pack).await;

    // Publish the 30641 + a 1059 wrap to A; the replication clock starts now.
    let edition = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&manifest_sha, manifest.len() as u64),
        &[(pack_sha.clone(), pack.len() as u64)],
        Timestamp::now().as_secs(),
    );
    let replication_started = Instant::now();
    let (accepted, message) = publish_with_result(a.url(), &edition).await;
    assert!(
        accepted,
        "exit1: 30641 must be accepted on A; got {message:?}"
    );
    // One wrap per accepted wire kind — dual-accept is only real if BOTH
    // cross the pair.
    let wraps = wrap_events(&writer);
    for (kind, wrap) in &wraps {
        let (accepted, message) = publish_with_result(a.url(), wrap).await;
        assert!(
            accepted,
            "exit1: wrap kind {kind} must be accepted on A; got {message:?}"
        );
    }

    // B serves the 30640 via REQ.
    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(tenant.public_key())
                .identifier(&alias),
            REPLICATION_BOUND,
        )
        .await,
        "exit1: 30640 must replicate to B within {REPLICATION_BOUND:?}"
    );

    // B serves the 30641 via REQ (and it is byte-identical to the original).
    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new().kind(Kind::Custom(30641)).identifier(&alias),
            REPLICATION_BOUND,
        )
        .await,
        "exit1: 30641 must replicate to B within {REPLICATION_BOUND:?}"
    );
    let served = fetch_from(
        b.url(),
        Filter::new().kind(Kind::Custom(30641)).identifier(&alias),
    )
    .await;
    assert_eq!(
        served.len(),
        1,
        "exit1: B serves exactly the latest edition"
    );
    assert_eq!(served[0].id, edition.id, "exit1: served 30641 id matches");
    assert_eq!(served[0].tags, edition.tags, "exit1: served tags intact");

    // B serves EVERY accepted wrap kind via REQ. Waited on by exact id: both
    // wraps share the outer author, so a kind+author wait would let one kind
    // satisfy the other's assertion.
    for (kind, wrap) in &wraps {
        assert!(
            wait_for_exact_event(b.url(), wrap.id, REPLICATION_BOUND).await,
            "exit1: wrap kind {kind} ({}) must replicate to B within {REPLICATION_BOUND:?}",
            wrap.id
        );
        let served = fetch_from(
            b.url(),
            Filter::new()
                .kind(Kind::Custom(*kind))
                .author(writer.public_key()),
        )
        .await;
        assert!(
            served.iter().any(|e| e.id == wrap.id),
            "exit1: B must serve wrap {} under its own kind {kind}",
            wrap.id
        );
    }

    // B serves BOTH blobs over its public GET route, sha-verified; the pack
    // is byte-compared against the original.
    let mirrored_manifest = wait_for_blob(&b, &manifest_sha, REPLICATION_BOUND)
        .await
        .expect("exit1: manifest blob must be mirrored to B");
    assert_eq!(mirrored_manifest, manifest, "exit1: manifest bytes intact");
    let mirrored_pack = wait_for_blob(&b, &pack_sha, REPLICATION_BOUND)
        .await
        .expect("exit1: pack blob must be mirrored to B");
    assert_eq!(
        mirrored_pack, pack,
        "exit1: mirrored pack must byte-compare equal to the original"
    );

    let latency = replication_started.elapsed();
    println!("exit1: full A->B replication (events + blobs) in {latency:?}");
    assert!(
        latency <= Duration::from_secs(120),
        "exit1: replication must complete within the design's 120s bound"
    );

    // The registration served by B is the exact accepted edition.
    let served_reg = fetch_from(
        b.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(tenant.public_key())
            .identifier(&alias),
    )
    .await;
    assert_eq!(served_reg.len(), 1);
    assert_eq!(served_reg[0].id, reg.id, "exit1: served 30640 id matches");

    b.stop().await;
    a.stop().await;
}

// ============================================================================
// Exit test 2 — out-of-order arrival (reprocess hook)
// ============================================================================

#[tokio::test]
async fn exit2_out_of_order_reprocess() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let (a, b) = start_pair(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())]).await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let writer = Keys::generate();
    let alias = random_alias();

    // Publish the DEPENDENT events to B first — before any 30640 exists
    // anywhere. B must reject them now (no authorizing registration)...
    let manifest = blob_bytes(21, 512);
    let manifest_sha = sha256_hex(&manifest);
    let edition = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&manifest_sha, manifest.len() as u64),
        &[],
        Timestamp::now().as_secs(),
    );
    let (accepted, _) = publish_with_result(b.url(), &edition).await;
    assert!(
        !accepted,
        "exit2: 30641 published before its 30640 must be rejected initially"
    );
    // Both wrap kinds, from the SAME write key: the sync hold keys stream
    // wraps by outer author and is deliberately kind-agnostic, so a 1059 and
    // a 3359 land in one bucket and must be released together.
    let wraps = wrap_events(&writer);
    for (kind, wrap) in &wraps {
        let (accepted, _) = publish_with_result(b.url(), wrap).await;
        assert!(
            !accepted,
            "exit2: wrap kind {kind} published before its 30640 must be rejected initially"
        );
    }

    // ...then the 30640 goes to A and syncs over. B's reprocess hook must
    // resurrect the held 30641 + every held wrap kind. (Whole sequence stays
    // well under the 120s rejected-hold TTL.)
    register_on(&a, &domain_refs, &tenant, &writer, &alias).await;

    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(tenant.public_key())
                .identifier(&alias),
            REPLICATION_BOUND,
        )
        .await,
        "exit2: 30640 must replicate A->B"
    );
    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new().kind(Kind::Custom(30641)).identifier(&alias),
            REPLICATION_BOUND,
        )
        .await,
        "exit2: B must eventually accept + serve the held 30641 (reprocess hook)"
    );
    for (kind, wrap) in &wraps {
        assert!(
            wait_for_exact_event(b.url(), wrap.id, REPLICATION_BOUND).await,
            "exit2: B must eventually accept + serve the held wrap kind {kind} ({}) \
             (reprocess hook)",
            wrap.id
        );
    }

    // The exact held events are served (not some other edition).
    let served = fetch_from(
        b.url(),
        Filter::new().kind(Kind::Custom(30641)).identifier(&alias),
    )
    .await;
    assert_eq!(served.len(), 1);
    assert_eq!(
        served[0].id, edition.id,
        "exit2: served 30641 is the held one"
    );

    b.stop().await;
    a.stop().await;
}

// ============================================================================
// Exit test 3 — kill-one-node backfill
// ============================================================================

#[tokio::test]
async fn exit3_kill_node_backfill() {
    // B gets explicit persistent paths so it can be restarted on the same
    // LMDB + git data.
    let b_git_dir = tempfile::tempdir().expect("b git dir");
    let b_relay_dir = tempfile::tempdir().expect("b relay dir");
    let b_paths = (
        b_git_dir.path().to_path_buf(),
        b_relay_dir.path().to_path_buf(),
    );

    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let (a, b) = start_pair_with_b_paths(
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
        Some(b_paths.clone()),
    )
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let writer = Keys::generate();
    let alias = random_alias();

    // Baseline: registration + first edition fully replicated to B.
    register_on(&a, &domain_refs, &tenant, &writer, &alias).await;
    let blob1 = blob_bytes(31, 1024);
    let sha1 = upload_blob(&a, &tenant, &writer, &alias, &blob1).await;
    let t0 = Timestamp::now().as_secs();
    let edition1 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha1, blob1.len() as u64),
        &[],
        t0,
    );
    let (accepted, message) = publish_with_result(a.url(), &edition1).await;
    assert!(accepted, "exit3: edition1 accepted on A; got {message:?}");
    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new().kind(Kind::Custom(30640)).identifier(&alias),
            REPLICATION_BOUND,
        )
        .await,
        "exit3: baseline 30640 must reach B before the kill"
    );
    assert!(
        wait_for_blob(&b, &sha1, REPLICATION_BOUND).await.is_some(),
        "exit3: baseline blob must be mirrored to B before the kill"
    );

    // Kill B. While it is down, push a fresh edition + new blob to A.
    b.stop().await;
    let blob2 = blob_bytes(32, 2048);
    let sha2 = upload_blob(&a, &tenant, &writer, &alias, &blob2).await;
    let edition2 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha2, blob2.len() as u64),
        &[(sha1.clone(), blob1.len() as u64)],
        t0 + 5,
    );
    let (accepted, message) = publish_with_result(a.url(), &edition2).await;
    assert!(accepted, "exit3: edition2 accepted on A; got {message:?}");

    // Restart B on the SAME data paths (fresh port; it re-bootstraps to A —
    // backfill comes from its own since=None historic sync + boot mirror
    // repair scan, not from A dialing in). Same whitelist as before the
    // kill — policy-fingerprint parity must survive the restart.
    let res_b2 = reserve_port();
    let b = TestRelay::start_grasp_p_pair_node(
        res_b2,
        Some(a.url().to_string()),
        true,
        Some(b_paths.0.clone()),
        Some(b_paths.1.clone()),
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;

    // B backfills the new edition (addressable replacement: latest only)...
    let deadline = Instant::now() + REPLICATION_BOUND;
    let mut backfilled = false;
    while Instant::now() < deadline {
        let served = fetch_from(
            b.url(),
            Filter::new().kind(Kind::Custom(30641)).identifier(&alias),
        )
        .await;
        if served.len() == 1 && served[0].id == edition2.id {
            backfilled = true;
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    assert!(
        backfilled,
        "exit3: restarted B must backfill edition2 within {REPLICATION_BOUND:?}"
    );

    // ...and mirrors the new blob (boot repair / accept-hook fetch from A).
    let mirrored = wait_for_blob(&b, &sha2, REPLICATION_BOUND)
        .await
        .expect("exit3: restarted B must mirror the new blob");
    assert_eq!(mirrored, blob2, "exit3: mirrored blob bytes intact");
    // The old blob survived the restart on the persistent paths.
    let (status, body) = get_blob(&b, &sha1).await;
    assert_eq!(
        status, 200,
        "exit3: pre-kill blob still served after restart"
    );
    assert_eq!(body, blob1);

    b.stop().await;
    a.stop().await;
}

// ============================================================================
// Exit test 4 — disabled no-op (public sync unchanged)
// ============================================================================

#[tokio::test]
async fn exit4_disabled_is_noop() {
    // Same pair topology, but private repos + mirror OFF on both nodes
    // (extra_env overrides the constructor defaults). The full existing
    // tests/sync suite passing unchanged is the primary regression guard;
    // this asserts the pair itself still does plain 30617 replication.
    let (a, b) = start_pair(&[
        ("NGIT_GRASP_P_REPOS_ENABLE", "false"),
        ("NGIT_GRASP_P_MIRROR_ENABLE", "false"),
    ])
    .await;

    // No private advertisement on either node.
    for (name, relay) in [("A", &a), ("B", &b)] {
        let doc = nip11_doc(relay).await;
        assert!(
            doc.get("private_repos").is_none(),
            "exit4: node {name} must not advertise private_repos when disabled"
        );
    }

    // A well-formed 30640 is just an orphan custom event.
    let tenant = Keys::generate();
    let writer = Keys::generate();
    let alias = random_alias();
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let reg = registration_event(&tenant, &alias, &writer, &domain_refs, None);
    let (accepted, message) = publish_with_result(a.url(), &reg).await;
    assert!(
        !accepted && message.contains("restricted:"),
        "exit4: 30640 must be orphan-rejected when disabled; got accepted={accepted} {message:?}"
    );

    // A normal public repo (30617 + git data) still replicates A -> B over
    // the same bootstrap pairing.
    let keys = Keys::generate();
    let (announcement, _git_dir) =
        setup_announcement_on_relay(&a, &keys, &domain_refs, "two-node-disabled-repo").await;
    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(keys.public_key())
                .identifier("two-node-disabled-repo"),
            REPLICATION_BOUND,
        )
        .await,
        "exit4: public 30617 {} must still replicate A->B with private repos disabled",
        announcement.id
    );

    // No private mirror activity is ever reported.
    let metrics = ParsedMetrics::parse(
        &fetch_metrics(b.url())
            .await
            .expect("exit4: B /metrics must be reachable"),
    );
    let fetched = metrics
        .counter("ngit_private_mirror_fetched_total", &[])
        .unwrap_or(0);
    let lag = metrics
        .gauge("ngit_private_mirror_lag_blobs", &[])
        .unwrap_or(0);
    assert_eq!(fetched, 0, "exit4: no mirror fetches when disabled");
    assert_eq!(lag, 0, "exit4: no mirror lag when disabled");

    b.stop().await;
    a.stop().await;
}

// ============================================================================
// Exit test 5 — mirror bounds (missing peer blob)
// ============================================================================

#[tokio::test]
async fn exit5_mirror_bounds_missing_blob() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let (a, b) = start_pair(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())]).await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let writer = Keys::generate();
    let alias = random_alias();
    register_on(&a, &domain_refs, &tenant, &writer, &alias).await;

    // A 30641 referencing a blob that was NEVER uploaded anywhere. Event
    // replication is independent of blob availability: both nodes accept it.
    let phantom = blob_bytes(51, 4096);
    let phantom_sha = sha256_hex(&phantom);
    let edition = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&phantom_sha, phantom.len() as u64),
        &[],
        Timestamp::now().as_secs(),
    );
    let (accepted, message) = publish_with_result(a.url(), &edition).await;
    assert!(
        accepted,
        "exit5: 30641 referencing a missing blob must still be accepted; got {message:?}"
    );

    // The 30641 replicates and is served by B...
    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new().kind(Kind::Custom(30641)).identifier(&alias),
            REPLICATION_BOUND,
        )
        .await,
        "exit5: the 30641 must replicate to B despite the missing blob"
    );

    // ...but the mirror cannot fetch the blob: B records the failure
    // (peer GET is a 404 → reason "http_status") and the lag gauge stays
    // above zero across repair ticks.
    assert!(
        wait_for_metrics(&b, REPLICATION_BOUND, |m| {
            m.counter(
                "ngit_private_mirror_failed_total",
                &[("reason", "http_status")],
            )
            .unwrap_or(0)
                >= 1
        })
        .await,
        "exit5: B must record a mirror failure with reason=http_status"
    );
    assert!(
        wait_for_metrics(&b, REPLICATION_BOUND, |m| {
            m.gauge("ngit_private_mirror_lag_blobs", &[]).unwrap_or(0) > 0
        })
        .await,
        "exit5: B's mirror lag gauge must stay > 0 while the blob is missing"
    );

    // No partial/poisoned blob was stored: the GET is a clean 404, and stays
    // a 404 after further repair ticks.
    let (status, _) = get_blob(&b, &phantom_sha).await;
    assert_eq!(status, 404, "exit5: missing blob must GET 404 on B");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (status, body) = get_blob(&b, &phantom_sha).await;
    assert_eq!(
        status, 404,
        "exit5: repair retries must not store a partial blob"
    );
    assert!(
        !body
            .windows(32)
            .any(|w| phantom.windows(32).next() == Some(w))
            || body.is_empty(),
        "exit5: 404 body must not contain blob content"
    );

    // The event itself keeps being served (replication independent of blobs).
    let served = fetch_from(
        b.url(),
        Filter::new().kind(Kind::Custom(30641)).identifier(&alias),
    )
    .await;
    assert_eq!(served.len(), 1);
    assert_eq!(served[0].id, edition.id, "exit5: 30641 still served by B");

    b.stop().await;
    a.stop().await;
}

// ============================================================================
// Exit test 6 — §3.2 split-brain registration merge converges (issue !11)
// ============================================================================

/// Conflicting registrations for the same alias injected on BOTH nodes
/// (partition seat / alias squat) must converge to the same deterministic
/// winner everywhere: lowest (created_at, id) wins, the loser is evicted
/// (key claims freed, relay-DB coordinate pruned) and the conflict alert
/// fires on the node that had accepted the loser.
#[tokio::test]
async fn exit6_registration_split_brain_merge() {
    let squatter = Keys::generate();
    let victim = Keys::generate();
    let third = Keys::generate();
    let whitelist = whitelist_npubs(&[&squatter, &victim, &third]);
    let (a, b) = start_pair(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())]).await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let squat_writer = Keys::generate();
    let victim_writer = Keys::generate();
    let alias = random_alias();
    let now = Timestamp::now().as_secs();

    // The squatter's registration (HIGHER created_at) lands on B first and
    // is accepted there — B now holds the future merge loser.
    let squat = registration_event(&squatter, &alias, &squat_writer, &domain_refs, Some(now));
    let (accepted, message) = publish_with_result(b.url(), &squat).await;
    assert!(
        accepted,
        "exit6: squatter registration on B failed: {message:?}"
    );

    // The victim's registration (LOWER created_at) is published to A.
    // Whether or not the squatter's edition already synced over, the
    // deterministic merge makes the victim win on both nodes.
    let genuine = registration_event(
        &victim,
        &alias,
        &victim_writer,
        &domain_refs,
        Some(now - 300),
    );
    let (accepted, message) = publish_with_result(a.url(), &genuine).await;
    assert!(
        accepted,
        "exit6: the earlier-created registration must win everywhere; got {message:?}"
    );

    // Both nodes converge: REQ resolves exactly the winner's event (the
    // loser's coordinate is pruned wherever it had been stored).
    for (name, node) in [("A", &a), ("B", &b)] {
        let deadline = Instant::now() + REPLICATION_BOUND;
        loop {
            let events = fetch_from(
                node.url(),
                Filter::new().kind(Kind::Custom(30640)).identifier(&alias),
            )
            .await;
            if events.len() == 1 && events[0].id == genuine.id {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "exit6: node {name} must converge to the merge winner; still sees {:?}",
                events.iter().map(|e| e.id.to_hex()).collect::<Vec<_>>()
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    // The eviction freed the loser's write key on B: a third tenant can
    // claim it under a fresh alias (fresh proof-of-possession).
    let alias2 = random_alias();
    let reclaim = registration_event(&third, &alias2, &squat_writer, &domain_refs, Some(now + 10));
    let (accepted, message) = publish_with_result(b.url(), &reclaim).await;
    assert!(
        accepted,
        "exit6: the evicted loser's key must be claimable on B; got {message:?}"
    );

    // The conflict alert fired on B (it held the evicted loser when the
    // winner synced over).
    let alerted = wait_for_metrics(&b, REPLICATION_BOUND, |m| {
        m.counter(
            "ngit_private_registration_conflicts_total",
            &[("resolution", "stored_evicted")],
        )
        .unwrap_or(0)
            >= 1
    })
    .await;
    assert!(
        alerted,
        "exit6: stored_evicted conflict alert must fire on B"
    );

    a.stop().await;
    b.stop().await;
}

// ============================================================================
// Exit test 7 — rotation/skew still converges on the first-edition anchor
// (verify round 1 FA, scenario B)
// ============================================================================

/// FA scenario B: the victim rotates on A while B is still pre-rotation; the
/// squatter's intermediate-created_at registration (t0 < t1 < t2) is pushed
/// to BOTH nodes. Pre-FA the rotated node (latest edition = t2) ACCEPTED it
/// and evicted the victim while the pre-rotation node rejected it —
/// permanent cross-node disagreement. Anchored to the first edition, both
/// nodes reject it in every order, and after sync both converge on the
/// victim's rotation.
#[tokio::test]
async fn exit7_rotation_skew_converges_on_anchor() {
    let victim = Keys::generate();
    let squatter = Keys::generate();
    let whitelist = whitelist_npubs(&[&victim, &squatter]);
    let (a, b) = start_pair(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())]).await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let victim_w1 = Keys::generate();
    let victim_w2 = Keys::generate();
    let squat_writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs() - 600;

    // Edition 1 (t0) on A replicates to B: both nodes pre-rotation.
    let reg1 = registration_event(&victim, &alias, &victim_w1, &domain_refs, Some(t0));
    let (accepted, message) = publish_with_result(a.url(), &reg1).await;
    assert!(accepted, "exit7: victim registration failed: {message:?}");
    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(victim.public_key())
                .identifier(&alias),
            REPLICATION_BOUND,
        )
        .await,
        "exit7: edition 1 must replicate to B"
    );

    // The squatter (t1) reaches B while it is pre-rotation: rejected there.
    let squat = registration_event(
        &squatter,
        &alias,
        &squat_writer,
        &domain_refs,
        Some(t0 + 100),
    );
    let (accepted, _) = publish_with_result(b.url(), &squat).await;
    assert!(
        !accepted,
        "exit7: pre-rotation node must reject the squatter"
    );

    // The victim rotates on A (t2 > t1). The SAME squatter event reaching
    // the rotated node must STILL lose — this is the pre-FA split-brain.
    let reg2 = registration_event(&victim, &alias, &victim_w2, &domain_refs, Some(t0 + 200));
    let (accepted, message) = publish_with_result(a.url(), &reg2).await;
    assert!(accepted, "exit7: rotation failed: {message:?}");
    let (accepted, _) = publish_with_result(a.url(), &squat).await;
    assert!(
        !accepted,
        "exit7: rotated node must still reject the intermediate squatter (FA)"
    );

    // The rotation must actually reach B before the squatter re-try below
    // (R2-E: the author+identifier filter alone matches edition 1 instantly
    // — poll for the rotation's own event id, like the convergence loop).
    let deadline = Instant::now() + REPLICATION_BOUND;
    let mut rotation_synced = false;
    while Instant::now() < deadline {
        let events = fetch_from(
            b.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(victim.public_key())
                .identifier(&alias),
        )
        .await;
        if events.iter().any(|e| e.id == reg2.id) {
            rotation_synced = true;
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    assert!(
        rotation_synced,
        "exit7: the rotation (reg2) must replicate to B"
    );
    let (accepted, _) = publish_with_result(b.url(), &squat).await;
    assert!(
        !accepted,
        "exit7: caught-up node must keep rejecting the squatter"
    );

    // Both nodes converge: REQ resolves exactly the victim's rotation.
    for (name, node) in [("A", &a), ("B", &b)] {
        let deadline = Instant::now() + REPLICATION_BOUND;
        loop {
            let events = fetch_from(
                node.url(),
                Filter::new().kind(Kind::Custom(30640)).identifier(&alias),
            )
            .await;
            if events.len() == 1 && events[0].id == reg2.id {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "exit7: node {name} must converge on the victim's rotation; still sees {:?}",
                events.iter().map(|e| e.id.to_hex()).collect::<Vec<_>>()
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    // The victim's seat is live on both nodes: a fresh 30641 is accepted on
    // each (distinct seconds — the editions sync and replace).
    for (name, node, at) in [("A", &a, t0 + 300), ("B", &b, t0 + 301)] {
        let sha = sha256_hex(&blob_bytes(71, 128));
        let state = state_root_event(
            &victim_w2,
            &victim.public_key(),
            &alias,
            (&sha, 128),
            &[],
            at,
        );
        let (accepted, message) = publish_with_result(node.url(), &state).await;
        assert!(
            accepted,
            "exit7: post-merge 30641 must be accepted on node {name}; got {message:?}"
        );
    }

    a.stop().await;
    b.stop().await;
}

// ============================================================================
// Exit test 8 — late-witness mis-anchor + backdated self-heal (verify R2-B)
// ============================================================================

/// R2-B: B joins AFTER the victim's rotation — edition 1 was already purged
/// from A's relay DB by addressable replacement, so B anchors on edition 2
/// and the intermediate-created_at squatter WINS there (while A, anchored on
/// edition 1, rejects it). The documented self-heal then closes the gap: the
/// victim re-mints a registration with created_at ≤ the squatter's — a
/// same-tenant no-op that LOWERS the anchor on correctly-witnessed nodes
/// (R2-B fix) and a cross-tenant winner on mis-anchored ones — and both
/// nodes converge.
#[tokio::test]
async fn exit8_late_witness_misanchor_and_backdated_self_heal() {
    // A starts alone, bootstrapped at B's reserved (not yet bound) URL; B's
    // domain is known up front, so registrations can list both nodes.
    let victim = Keys::generate();
    let squatter = Keys::generate();
    let whitelist = whitelist_npubs(&[&victim, &squatter]);
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());
    let a = TestRelay::start_grasp_p_pair_node(
        res_a,
        Some(url_b.clone()),
        true,
        None,
        None,
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;

    let victim_writer = Keys::generate();
    let squat_writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs() - 600;
    let domains = [a.domain(), format!("127.0.0.1:{}", res_b.port())];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    // The victim registers edition 1 AND rotates to edition 2 while B does
    // not exist; A's relay DB keeps only edition 2 (addressable
    // replacement), so B can never witness edition 1.
    let ed1 = registration_event(&victim, &alias, &victim_writer, &domain_refs, Some(t0));
    let (accepted, message) = publish_with_result(a.url(), &ed1).await;
    assert!(accepted, "exit8: edition 1 failed: {message:?}");
    let ed2 = registration_event(
        &victim,
        &alias,
        &victim_writer,
        &domain_refs,
        Some(t0 + 200),
    );
    let (accepted, message) = publish_with_result(a.url(), &ed2).await;
    assert!(accepted, "exit8: edition 2 failed: {message:?}");

    // B joins now: it syncs ONLY edition 2 and anchors on it (t2).
    let b = TestRelay::start_grasp_p_pair_node(
        res_b,
        Some(a.url().to_string()),
        true,
        None,
        None,
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;
    let deadline = Instant::now() + REPLICATION_BOUND;
    let mut ed2_on_b = false;
    while Instant::now() < deadline {
        let events = fetch_from(
            b.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(victim.public_key())
                .identifier(&alias),
        )
        .await;
        if events.iter().any(|e| e.id == ed2.id) {
            ed2_on_b = true;
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    assert!(ed2_on_b, "exit8: edition 2 must sync to late-joining B");

    // The squatter (t1, t0 < t1 < t2): LOSES on A (anchor = edition 1) but
    // WINS on mis-anchored B (anchor = edition 2) — the R2-B split-brain.
    let squat = registration_event(
        &squatter,
        &alias,
        &squat_writer,
        &domain_refs,
        Some(t0 + 100),
    );
    let (accepted, _) = publish_with_result(a.url(), &squat).await;
    assert!(
        !accepted,
        "exit8: A (anchored on edition 1) must reject the squatter"
    );
    let (accepted, message) = publish_with_result(b.url(), &squat).await;
    assert!(
        accepted,
        "exit8: late-witness B (anchored on edition 2) accepts the squatter — the mis-anchor being pinned; got {message:?}"
    );

    // Self-heal: the victim re-mints with created_at ≤ the squatter's
    // (t0-50). On B it is a cross-tenant WINNER (squatter evicted); on A a
    // same-tenant stale no-op that LOWERS the anchor to t0-50 (policy
    // accepts, the relay DB reports "error: unknown" — it already holds the
    // newer edition 2; gotcha 9).
    let heal = registration_event(&victim, &alias, &victim_writer, &domain_refs, Some(t0 - 50));
    let (accepted, message) = publish_with_result(b.url(), &heal).await;
    assert!(
        accepted,
        "exit8: the backdated re-mint must win on mis-anchored B; got {message:?}"
    );
    let (accepted, message) = publish_with_result(a.url(), &heal).await;
    assert!(
        !accepted && message.contains("error: unknown"),
        "exit8: on A the heal is a stale no-op (DB holds edition 2); got accepted={accepted} {message:?}"
    );

    // The victim re-publishes edition 2 directly to B (deterministic — no
    // dependence on sync re-delivery after the eviction prune): both nodes
    // now serve edition 2 with the anchor at t0-50.
    let (accepted, message) = publish_with_result(b.url(), &ed2).await;
    assert!(
        accepted,
        "exit8: edition 2 must land on healed B; got {message:?}"
    );
    for (name, node) in [("A", &a), ("B", &b)] {
        let served = fetch_from(
            node.url(),
            Filter::new().kind(Kind::Custom(30640)).identifier(&alias),
        )
        .await;
        assert_eq!(
            served.len(),
            1,
            "exit8: node {name} serves exactly one 30640"
        );
        assert_eq!(served[0].id, ed2.id, "exit8: node {name} serves edition 2");
    }

    // Convergence pin, including A's LOWERED anchor: a second squatter at
    // t0-25 (older than the squatter's t1, newer than the heal) loses on
    // BOTH nodes — pre-lowering it would win on A (anchor was edition 1).
    let squat2 = registration_event(
        &squatter,
        &alias,
        &squat_writer,
        &domain_refs,
        Some(t0 - 25),
    );
    for (name, node) in [("A", &a), ("B", &b)] {
        let (accepted, _) = publish_with_result(node.url(), &squat2).await;
        assert!(
            !accepted,
            "exit8: the t0-25 squatter must lose on node {name} (anchor lowered to the heal)"
        );
    }

    // The victim's seat is functional on both nodes.
    for (name, node, at) in [("A", &a, t0 + 300), ("B", &b, t0 + 301)] {
        let sha = sha256_hex(&blob_bytes(82, 128));
        let state = state_root_event(
            &victim_writer,
            &victim.public_key(),
            &alias,
            (&sha, 128),
            &[],
            at,
        );
        let (accepted, message) = publish_with_result(node.url(), &state).await;
        assert!(
            accepted,
            "exit8: post-heal 30641 must be accepted on node {name}; got {message:?}"
        );
    }

    a.stop().await;
    b.stop().await;
}

// ============================================================================
// Exit test 9 — mirror finish() re-check + no re-enqueue after death (R2-C)
// ============================================================================

/// R2-C (mirror caller sweep): a registration death racing the mirror's
/// fetch must fail finish() without storing/charging (or, if the fetch
/// completed before the death, the death cleanup + GC still release it) —
/// and afterwards repair scans must NOT re-enqueue (no live claimant), so
/// the blob is never (re-)stored and no zombie charge survives.
#[tokio::test]
async fn exit9_mirror_finish_recheck_and_no_reenqueue_after_death() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let (a, b) = start_pair(&[
        ("NGIT_GRASP_P_GC_GRACE_SECS", "0"),
        ("NGIT_GRASP_P_GC_INTERVAL_SECS", "1"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs() - 600;

    let b_global = || async {
        ParsedMetrics::parse(&fetch_metrics(b.url()).await.expect("metrics scrape"))
            .gauge("ngit_private_ledger_bytes", &[("scope", "global")])
            .unwrap_or(-1)
    };

    // Registration (created at t0 so the later kind-5 honors the cutoff) on
    // A → syncs to B.
    let reg = registration_event(&tenant, &alias, &writer, &domain_refs, Some(t0));
    let (accepted, message) = publish_with_result(a.url(), &reg).await;
    assert!(accepted, "exit9: registration failed: {message:?}");
    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(tenant.public_key())
                .identifier(&alias),
            REPLICATION_BOUND,
        )
        .await,
        "exit9: registration must replicate to B"
    );

    // The blob lives on A; a 30641 referencing it lands directly on B — B's
    // mirror wants the blob from A (fetch may start immediately).
    let blob = blob_bytes(83, 1024);
    let sha = upload_blob(&a, &tenant, &writer, &alias, &blob).await;
    let edition = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha, blob.len() as u64),
        &[],
        t0 + 10,
    );
    let (accepted, message) = publish_with_result(b.url(), &edition).await;
    assert!(accepted, "exit9: 30641 on B failed: {message:?}");

    // The registration dies on B immediately (honored kind-5): any
    // in-flight mirror finish() must now fail the identity re-check; if the
    // fetch already completed, the death cleanup + GC release it instead.
    let deletion = EventBuilder::new(Kind::EventDeletion, "offboard")
        .tags(vec![
            Tag::custom("a", vec![reg_coord(&tenant.public_key(), &alias)]),
            Tag::custom("k", vec!["30640".to_string()]),
        ])
        .custom_created_at(Timestamp::from_secs(t0 + 20))
        .finalize(&tenant)
        .expect("sign kind-5");
    let (accepted, message) = publish_with_result(b.url(), &deletion).await;
    assert!(accepted, "exit9: kind-5 rejected: {message:?}");

    // Settle: B's ledger falls back to registration + edition event bytes
    // only — the 1024 declared/stored bytes are gone in every interleaving
    // (spec released at death; stored charge released by GC after the
    // strip; or never charged because finish() rejected). This also proves
    // the death was processed.
    let want = reg.as_json().len() as i64 + edition.as_json().len() as i64;
    let mut settled = -1;
    for _ in 0..100 {
        settled = b_global().await;
        if settled == want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        settled, want,
        "exit9: no zombie charge may survive the death (spec or stored)"
    );

    // Repair scans must NOT re-enqueue (no live claimant): the lag stays
    // zero and the blob is never (re-)stored across several repair ticks.
    assert!(
        wait_for_metrics(&b, REPLICATION_BOUND, |m| {
            m.gauge("ngit_private_mirror_lag_blobs", &[]).unwrap_or(-1) == 0
        })
        .await,
        "exit9: mirror lag must be zero after the death"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (status, _) = get_blob(&b, &sha).await;
    assert_eq!(
        status, 404,
        "exit9: the blob must never be (re-)stored on B after the death"
    );
    assert!(
        wait_for_metrics(&b, Duration::from_secs(5), |m| {
            m.gauge("ngit_private_mirror_lag_blobs", &[]).unwrap_or(-1) == 0
        })
        .await,
        "exit9: repair scans must not re-enqueue after the death"
    );

    a.stop().await;
    b.stop().await;
}

// ============================================================================
// Exit test 10 — Phase-4b B1: periodic since=None full re-issue heals a
// missed 30641 WITHOUT any index change
// ============================================================================

/// Signed kind-30640 registration with MULTIPLE writer keys (edition
/// upgrades that widen the writer set).
fn registration_event_multi(
    tenant: &Keys,
    alias: &str,
    writers: &[&Keys],
    domains: &[&str],
    created_at: Option<u64>,
) -> Event {
    let relays: Vec<String> = domains.iter().map(|d| format!("ws://{d}")).collect();
    let servers: Vec<String> = domains.iter().map(|d| format!("http://{d}")).collect();
    let mut tags = vec![
        Tag::identifier(alias),
        Tag::custom("relays", relays),
        Tag::custom("server", servers),
    ];
    for writer in writers {
        tags.push(Tag::custom(
            "w",
            key_entry(writer, &tenant.public_key(), alias),
        ));
    }
    let mut builder = EventBuilder::new(Kind::Custom(30640), "");
    if let Some(secs) = created_at {
        builder = builder.custom_created_at(Timestamp::from_secs(secs));
    }
    builder.tags(tags).finalize(tenant).expect("sign 30640")
}

/// A 30641 that missed live delivery must be healed by the periodic
/// since=None re-issue timer — and NOT by any PrivateSyncIndex change.
///
/// Scenario (carefully arranged so the timer is the ONLY possible healer):
/// B's registration set never changes after boot, so neither the inline
/// take_for_alias reprocess (which fires on every 30640 accept) nor the
/// index-change re-issue can fire. B quota-rejects the 30641 on its first
/// (live) delivery — a TRANSIENT rejection under a fixed registration —
/// which holds it and poisons the skip-set; A's one live push is spent, so
/// only a since=None historic redelivery can bring it back. Freeing the
/// quota (blob DELETE, not a registration change) plus the skip-set TTL
/// lapse leaves the re-issue timer as the sole path.
///
/// Run on both historic transports: REQ+EOSE (negentropy disabled) and
/// negentropy (FS-4: the rejected-id exclusion now filters TTL-expired
/// entries lazily, so the exclusion no longer outlives the skip-set TTL).
#[tokio::test]
async fn exit10_full_reissue_heals_missed_state_root() {
    exit10_full_reissue_heals_missed_state_root_inner(true).await;
}

/// FS-4 (review L3-F5) negentropy leg: same heal, with the negentropy
/// transport ENABLED — pre-FS-4 the exclusion set kept the expired
/// rejected id until the 60s physical cleanup, so redelivery had to ride
/// the REQ path.
#[tokio::test]
async fn exit10_full_reissue_heals_missed_state_root_negentropy() {
    exit10_full_reissue_heals_missed_state_root_inner(false).await;
}

async fn exit10_full_reissue_heals_missed_state_root_inner(disable_negentropy: bool) {
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_a = format!("ws://127.0.0.1:{}", res_a.port());
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());
    let domain_a = format!("127.0.0.1:{}", res_a.port());
    let domain_b = format!("127.0.0.1:{}", res_b.port());
    let domains = [domain_a.as_str(), domain_b.as_str()];

    let tenant = Keys::generate();
    let writer1 = Keys::generate();
    let writer2 = Keys::generate();
    // Key claims are unique: alias2 gets its own writer (filler auth).
    let writer3 = Keys::generate();
    let alias1 = random_alias();
    let alias2 = random_alias();
    let t0 = Timestamp::now().as_secs() - 60;

    // Build every event BEFORE boot so exact charged sizes are known.
    let reg1 =
        registration_event_multi(&tenant, &alias1, &[&writer1, &writer2], &domains, Some(t0));
    let reg2 = registration_event(&tenant, &alias2, &writer3, &domains, Some(t0));
    let manifest = blob_bytes(61, 1024);
    let manifest_sha = sha256_hex(&manifest);
    let edition = state_root_event(
        &writer2,
        &tenant.public_key(),
        &alias1,
        (&manifest_sha, manifest.len() as u64),
        &[],
        t0 + 10,
    );
    let filler = blob_bytes(62, 4096);

    // B's tenant quota: both registrations + the filler + 100 bytes of
    // slack. The 30641 (event bytes + 1024 speculative manifest bytes)
    // does NOT fit until the filler is deleted; after the delete it does.
    let reg_bytes = (reg1.as_json().len() + reg2.as_json().len()) as u64;
    let tenant_quota = reg_bytes + filler.len() as u64 + 100;
    let need = edition.as_json().len() as u64 + manifest.len() as u64;
    assert!(100 < need, "exit10: slack must not fit the 30641");
    assert!(
        filler.len() as u64 + 100 >= need,
        "exit10: post-delete headroom must fit the 30641"
    );

    let quota_s = tenant_quota.to_string();
    let huge = (1u64 << 40).to_string();
    let whitelist = whitelist_npubs(&[&tenant]);
    let a_env: Vec<(&str, &str)> = vec![
        ("NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS", "2"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ];
    let mut b_env: Vec<(&str, &str)> = vec![
        ("NGIT_GRASP_P_QUOTA_TENANT_BYTES", quota_s.as_str()),
        ("NGIT_GRASP_P_QUOTA_REPO_BYTES", quota_s.as_str()),
        ("NGIT_GRASP_P_GLOBAL_BUDGET_BYTES", huge.as_str()),
        // Short skip-set TTL so redelivery unblocks inside the test bound.
        ("NGIT_REJECTED_HOT_CACHE_DURATION_SECS", "8"),
        // Instant GC so the DELETEd filler's stored charge is released
        // within ~1 GC pass (blob DELETE only unreferences; GC releases).
        ("NGIT_GRASP_P_GC_GRACE_SECS", "0"),
        ("NGIT_GRASP_P_GC_INTERVAL_SECS", "1"),
        ("NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS", "2"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ];
    if disable_negentropy {
        // REQ+EOSE leg: the REQ pre-filter has always honored the hot-cache
        // TTL (the negentropy exclusion only learned to with FS-4).
        b_env.push(("NGIT_SYNC_DISABLE_NEGENTROPY", "true"));
    }
    let a = TestRelay::start_grasp_p_pair_node(res_a, Some(url_b), true, None, None, &a_env).await;
    let b = TestRelay::start_grasp_p_pair_node(res_b, Some(url_a), true, None, None, &b_env).await;

    // Both registrations land on B (the LAST registration changes of the
    // test — from here on B's index is fixed).
    for (reg, alias) in [(&reg1, &alias1), (&reg2, &alias2)] {
        let (accepted, message) = publish_with_result(a.url(), reg).await;
        assert!(accepted, "exit10: registration {alias} failed: {message:?}");
        assert!(
            wait_for_event_on_relay(
                b.url(),
                Filter::new().kind(Kind::Custom(30640)).identifier(alias),
                REPLICATION_BOUND,
            )
            .await,
            "exit10: registration {alias} must sync to B"
        );
    }

    // The filler fills B's tenant quota (stored charge under alias2); the
    // manifest blob lives on A under alias1.
    let filler_sha = upload_blob(&b, &tenant, &writer3, &alias2, &filler).await;
    let m_sha = upload_blob(&a, &tenant, &writer1, &alias1, &manifest).await;
    assert_eq!(m_sha, manifest_sha);

    // The 30641 is accepted on A (default quotas) and live-delivered to B,
    // which quota-rejects it: held by alias + id into the skip-set.
    let (accepted, message) = publish_with_result(a.url(), &edition).await;
    assert!(accepted, "exit10: 30641 must be accepted on A: {message:?}");
    assert!(
        wait_for_metrics(&b, REPLICATION_BOUND, |m| {
            m.counter("ngit_private_events_rejected_total", &[("kind", "30641")])
                .unwrap_or(0)
                >= 1
        })
        .await,
        "exit10: B must quota-reject the 30641 on first delivery"
    );
    let served = fetch_from(
        b.url(),
        Filter::new().kind(Kind::Custom(30641)).identifier(&alias1),
    )
    .await;
    assert!(
        served.is_empty(),
        "exit10: B must not serve the 30641 while quota-blocked"
    );

    // Free the quota WITHOUT any registration change: writer3 deletes the
    // filler from B (unreferences the claim; the instant GC pass releases
    // the stored charge). Still no healer: the skip-set blocks redelivery
    // for the TTL, and no 30640 ever lands to drain the hold.
    let delete_auth =
        blossom_delete_auth_event(&writer3, &filler_sha, &tenant.public_key(), &alias2);
    let (status, reason) = delete_blob(&b, &filler_sha, &delete_auth).await;
    assert_eq!(
        status, 200,
        "exit10: filler DELETE must be 200; X-Reason: {reason}"
    );

    // The re-issue timer is firing on B...
    assert!(
        wait_for_metrics(&b, Duration::from_secs(20), |m| {
            m.counter("ngit_private_full_reissue_total", &[])
                .unwrap_or(0)
                >= 1
        })
        .await,
        "exit10: B's full re-issue timer must be firing"
    );

    // ...and once the skip-set TTL lapses, its since=None backfill
    // redelivers the 30641, which now fits the quota — healed with zero
    // index changes.
    assert!(
        wait_for_event_on_relay(
            b.url(),
            Filter::new().kind(Kind::Custom(30641)).identifier(&alias1),
            Duration::from_secs(45),
        )
        .await,
        "exit10: the re-issue timer must heal the missed 30641 without any index change"
    );
    let served = fetch_from(
        b.url(),
        Filter::new().kind(Kind::Custom(30641)).identifier(&alias1),
    )
    .await;
    assert_eq!(served.len(), 1);
    assert_eq!(
        served[0].id, edition.id,
        "exit10: healed 30641 must be the exact event B missed"
    );

    a.stop().await;
    b.stop().await;
}

// ============================================================================
// Exit test 11 — Phase-4b B2: mirror retry backoff (no tight retry loop,
// eventual success after the peer recovers)
// ============================================================================

/// A minimal flake-serving blob peer: 500s every GET while `serve` is
/// false, then serves the seeded blobs (404 for unknown hashes).
struct FlakyBlobServer {
    base_url: String,
    serve: Arc<std::sync::atomic::AtomicBool>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl FlakyBlobServer {
    async fn start(blobs: Vec<(String, Vec<u8>)>) -> Self {
        let std_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind flaky blob server");
        let port = std_listener.local_addr().expect("local addr").port();
        std_listener.set_nonblocking(true).expect("nonblocking");
        let listener = tokio::net::TcpListener::from_std(std_listener).expect("tokio listener");
        let serve = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let blobs = Arc::new(std::sync::Mutex::new(
            blobs
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        ));
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve_loop = serve.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        let Ok((stream, _)) = accept_result else { continue };
                        let serve = serve_loop.clone();
                        let blobs = blobs.clone();
                        tokio::spawn(async move {
                            use http_body_util::Full;
                            use hyper::body::Bytes;
                            let service = hyper::service::service_fn(
                                move |req: hyper::Request<hyper::body::Incoming>| {
                                    let serve = serve.clone();
                                    let blobs = blobs.clone();
                                    async move {
                                        let sha =
                                            req.uri().path().trim_start_matches('/').to_string();
                                        let (status, body) = if !serve
                                            .load(std::sync::atomic::Ordering::SeqCst)
                                        {
                                            (500, Vec::new())
                                        } else {
                                            match blobs.lock().expect("blobs lock").get(&sha) {
                                                Some(bytes) => (200, bytes.clone()),
                                                None => (404, Vec::new()),
                                            }
                                        };
                                        Ok::<_, std::convert::Infallible>(
                                            hyper::Response::builder()
                                                .status(status)
                                                .body(Full::new(Bytes::from(body)))
                                                .expect("response"),
                                        )
                                    }
                                },
                            );
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                                .await;
                        });
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });
        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            serve,
            shutdown: Some(shutdown_tx),
        }
    }
}

impl Drop for FlakyBlobServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// While the peer 500s every fetch, B's per-blob backoff must keep the
/// failure count growing SLOWER than the 1s repair tick (no tight retry
/// loop) with lag held > 0; once the peer recovers, the next eligible
/// retry succeeds and the failures stop.
#[tokio::test]
async fn exit11_mirror_retry_backoff() {
    let blob = blob_bytes(71, 1024);
    let sha = sha256_hex(&blob);
    let stub = FlakyBlobServer::start(vec![(sha.clone(), blob.clone())]).await;

    // The mirror peer override (both nodes) points at the stub — the
    // registration's own server tags are bypassed. NGIT_TEST clamps the
    // backoff base to 1s and the repair tick is 1s.
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let (a, b) = start_pair(&[
        ("NGIT_GRASP_P_MIRROR_PEER_URLS", &stub.base_url),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let b_failed = || async {
        ParsedMetrics::parse(&fetch_metrics(b.url()).await.expect("metrics scrape"))
            .counter(
                "ngit_private_mirror_failed_total",
                &[("reason", "http_status")],
            )
            .unwrap_or(0)
    };

    let writer = Keys::generate();
    let alias = random_alias();
    register_on(&a, &domain_refs, &tenant, &writer, &alias).await;
    let sha = upload_blob(&a, &tenant, &writer, &alias, &blob).await;
    let edition = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha, blob.len() as u64),
        &[],
        Timestamp::now().as_secs(),
    );
    let (accepted, message) = publish_with_result(a.url(), &edition).await;
    assert!(accepted, "exit11: 30641 failed on A: {message:?}");

    // Phase 1 — peer down: failures accumulate, but the backoff gate keeps
    // them well below one-per-repair-tick, and the blob stays lagging.
    assert!(
        wait_for_metrics(&b, REPLICATION_BOUND, |m| {
            m.counter(
                "ngit_private_mirror_failed_total",
                &[("reason", "http_status")],
            )
            .unwrap_or(0)
                >= 1
        })
        .await,
        "exit11: B must record mirror failures while the peer 500s"
    );
    let c0 = b_failed().await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let c1 = b_failed().await;
    assert!(
        c1 - c0 <= 4,
        "exit11: backoff must prevent a tight retry loop: failed went {c0} -> {c1} \
         across 6s of 1s repair ticks (unthrottled would be ~6)"
    );
    assert!(
        wait_for_metrics(&b, Duration::from_secs(10), |m| {
            m.gauge("ngit_private_mirror_lag_blobs", &[]).unwrap_or(0) > 0
        })
        .await,
        "exit11: the gated blob must remain counted in the lag gauge"
    );

    // Phase 2 — peer recovers: the next eligible retry succeeds.
    stub.serve.store(true, std::sync::atomic::Ordering::SeqCst);
    let mirrored = wait_for_blob(&b, &sha, Duration::from_secs(30))
        .await
        .expect("exit11: blob must be mirrored once the peer recovers");
    assert_eq!(mirrored, blob, "exit11: mirrored blob bytes intact");
    assert!(
        wait_for_metrics(&b, Duration::from_secs(10), |m| {
            m.gauge("ngit_private_mirror_lag_blobs", &[]).unwrap_or(-1) == 0
        })
        .await,
        "exit11: lag must drain after the successful retry"
    );
    assert!(
        wait_for_metrics(&b, Duration::from_secs(10), |m| {
            m.counter("ngit_private_mirror_fetched_total", &[])
                .unwrap_or(0)
                >= 1
        })
        .await,
        "exit11: the recovered fetch must be counted as mirrored"
    );

    // Failures stop entirely once the blob is local.
    let c2 = b_failed().await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let c3 = b_failed().await;
    assert_eq!(
        c2, c3,
        "exit11: failure counter must stop growing once the blob is mirrored"
    );

    a.stop().await;
    b.stop().await;
}

// ============================================================================
// Exit test 12 — WP-E upgrade path: open-mode registrations survive the
// whitelist-default flip (boot_reconcile is non-destructive)
// ============================================================================

/// Server issue !7 upgrade footgun, pinned: registrations accumulated under
/// open mode must SURVIVE a reboot into whitelist-with-empty-whitelist (the
/// WP-E shipped default). boot_reconcile re-runs a stored 30640 only when
/// the meta record is missing/stale, and a replay rejection never evicts or
/// prunes — mode enforcement happens at admission time, not retroactively.
/// After the flip: existing tenants keep serving (30640 REQ, blob GET, new
/// 30641 editions), while NEW aliases are rejected by the whitelist gate.
#[tokio::test]
async fn exit12_open_registrations_survive_whitelist_flip() {
    // Persistent LMDB paths so the node reboots onto the same data.
    let git_dir = tempfile::tempdir().expect("git dir");
    let relay_dir = tempfile::tempdir().expect("relay dir");
    let paths = (git_dir.path().to_path_buf(), relay_dir.path().to_path_buf());

    // --- Boot 1: OPEN mode (the pre-WP-E default) --------------------------
    let tenant = Keys::generate();
    let writer = Keys::generate();
    let alias = random_alias();
    let res1 = reserve_port();
    let node = TestRelay::start_grasp_p_pair_node(
        res1,
        None,
        true,
        Some(paths.0.clone()),
        Some(paths.1.clone()),
        &[("NGIT_GRASP_P_REGISTRATION_MODE", "open")],
    )
    .await;
    let domains = [node.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let reg = register_on(&node, &domain_refs, &tenant, &writer, &alias).await;
    let blob = blob_bytes(81, 1024);
    let sha = upload_blob(&node, &tenant, &writer, &alias, &blob).await;
    let t0 = Timestamp::now().as_secs();
    let edition1 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha, blob.len() as u64),
        &[],
        t0,
    );
    let (accepted, message) = publish_with_result(node.url(), &edition1).await;
    assert!(accepted, "exit12: boot-1 edition failed: {message:?}");
    node.stop().await;

    // --- Boot 2: shipped defaults — whitelist mode, EMPTY whitelist --------
    let res2 = reserve_port();
    let boot2_port = res2.port();
    // The relay log is opened APPEND-mode (/tmp/relay-<port>.log): a stale
    // file from a prior run that happened to reuse this port could
    // false-pass the warn assertion below. Record the length BEFORE boot 2
    // and search only what this boot appended.
    let boot2_log_path = format!("/tmp/relay-{boot2_port}.log");
    let boot2_log_offset = std::fs::metadata(&boot2_log_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let node = TestRelay::start_grasp_p_pair_node(
        res2,
        None,
        true,
        Some(paths.0.clone()),
        Some(paths.1.clone()),
        &[],
    )
    .await;

    // The startup warn fired loudly for the empty-whitelist posture.
    let log = std::fs::read_to_string(&boot2_log_path).expect("boot-2 relay log");
    let log_tail = log.get(boot2_log_offset as usize..).unwrap_or("");
    assert!(
        log_tail.contains("all new private-repo registrations will be rejected"),
        "exit12: boot 2 must warn about whitelist mode with an empty whitelist"
    );

    // NIP-11 confirms the flipped posture.
    let doc = nip11_doc(&node).await;
    assert_eq!(
        doc["private_repos"]["registration_mode"], "whitelist",
        "exit12: boot 2 must advertise whitelist mode"
    );

    // The pre-flip registration is still served (relay DB kept it; the meta
    // record matched its event id, so boot_reconcile did not even replay it).
    let served = fetch_from(
        node.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(tenant.public_key())
            .identifier(&alias),
    )
    .await;
    assert_eq!(
        served.len(),
        1,
        "exit12: the open-mode registration must survive the flip"
    );
    assert_eq!(served[0].id, reg.id);

    // Its blobs still read back (meta ledger + blob store intact).
    let (status, body) = get_blob(&node, &sha).await;
    assert_eq!(status, 200, "exit12: pre-flip blob must still be served");
    assert_eq!(body, blob, "exit12: blob bytes intact");

    // The existing tenant can still write to the EXISTING alias (mode gates
    // are NEW-alias only): a newer 30641 edition is accepted.
    let blob2 = blob_bytes(82, 512);
    let sha2 = upload_blob(&node, &tenant, &writer, &alias, &blob2).await;
    let edition2 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha2, blob2.len() as u64),
        &[(sha.clone(), blob.len() as u64)],
        t0 + 5,
    );
    let (accepted, message) = publish_with_result(node.url(), &edition2).await;
    assert!(
        accepted,
        "exit12: existing-alias writes must keep working post-flip: {message:?}"
    );

    // A NEW alias — even from the pre-existing tenant — is rejected by the
    // whitelist gate. It must name boot-2's domain so the relays/server tag
    // checks pass, and use a FRESH writer key so the key-conflict check
    // passes — the whitelist gate is then what fires.
    let domains2 = [node.domain()];
    let domain2_refs: Vec<&str> = domains2.iter().map(|s| s.as_str()).collect();
    let alias2 = random_alias();
    let writer2 = Keys::generate();
    let reg2 = registration_event(&tenant, &alias2, &writer2, &domain2_refs, None);
    let (accepted, message) = publish_with_result(node.url(), &reg2).await;
    assert!(
        !accepted && message.contains("whitelist"),
        "exit12: a new alias must be whitelist-rejected post-flip; got accepted={accepted} {message:?}"
    );

    // And a brand-new tenant is rejected the same way.
    let fresh = Keys::generate();
    let fresh_writer = Keys::generate();
    let reg3 = registration_event(&fresh, &random_alias(), &fresh_writer, &domain2_refs, None);
    let (accepted, message) = publish_with_result(node.url(), &reg3).await;
    assert!(
        !accepted && message.contains("whitelist"),
        "exit12: a fresh tenant must be whitelist-rejected; got accepted={accepted} {message:?}"
    );

    node.stop().await;
}

// ============================================================================
// Exit test 13 — mixed-version pair across the 1059 -> 3359 migration window
// ============================================================================

/// The deployment risk the wire-kind migration actually creates: a rolling
/// upgrade transiently pairs a node still dual-accepting legacy wraps (A,
/// the shipped default) with one that has already closed the window (B,
/// `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND=false`).
///
/// Pinned contract for that window:
///
/// * the NEW kind crosses the split — this is what makes it safe to start
///   emitting 3359 before every node has flipped;
/// * the LEGACY kind does not — B never asks for 1059 in its derived filter
///   (asking for a kind it would reject is a refetch loop), and one arriving
///   by any other route is refused outright by the retired-kind arm (NOT
///   handed to the public related-event path, which would store an
///   `a`/`e`-tagged wrap from any key — see exit38). So a 1059 authored
///   during the window lives only on the nodes that still accept it;
/// * the policy fingerprints DIVERGE, which is precisely why v3 put
///   `accept_legacy_wrap_kind` in the preimage — the operator sees the split
///   view over NIP-11 instead of inferring it from missing events.
///
/// The absence assertion is ordered strictly behind a positive control: it
/// runs only after the 3359 from the SAME write key has landed on B, so
/// "did not replicate" can never be an unrun sync in disguise.
#[tokio::test]
async fn exit13_mixed_legacy_accept_pair() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    // Identical whitelist on both nodes; the ONLY divergence is the legacy
    // wrap-kind acceptance, so the fingerprint difference below isolates it.
    let (a, b) = start_pair_with_split_env(
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND", "false"),
        ],
    )
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    // The split view is advertised, not silent.
    let doc_a = nip11_doc(&a).await;
    let doc_b = nip11_doc(&b).await;
    let fp_a = doc_a["private_repos"]["policy_fingerprint"]
        .as_str()
        .expect("A must advertise private_repos.policy_fingerprint");
    let fp_b = doc_b["private_repos"]["policy_fingerprint"]
        .as_str()
        .expect("B must advertise private_repos.policy_fingerprint");
    assert_ne!(
        fp_a, fp_b,
        "exit13: differing legacy-wrap acceptance must change the policy \
         fingerprint — that mismatch IS the operator's split-view signal"
    );

    let kinds_of = |doc: &serde_json::Value| -> Vec<u64> {
        doc["private_repos"]["kinds"]
            .as_array()
            .expect("private_repos.kinds array")
            .iter()
            .filter_map(|k| k.as_u64())
            .collect()
    };
    let kinds_a = kinds_of(&doc_a);
    let kinds_b = kinds_of(&doc_b);
    assert!(
        kinds_a.contains(&1059) && kinds_a.contains(&3359),
        "exit13: A must advertise both wrap kinds; got {kinds_a:?}"
    );
    assert!(
        kinds_b.contains(&3359) && !kinds_b.contains(&1059),
        "exit13: B must advertise 3359 only; got {kinds_b:?}"
    );

    // Register on A (listing both domains) and publish one wrap per kind.
    let writer = Keys::generate();
    let alias = random_alias();
    let reg = register_on(&a, &domain_refs, &tenant, &writer, &alias).await;
    let legacy = wrap_event(&writer, 1059);
    let (accepted, message) = publish_with_result(a.url(), &legacy).await;
    assert!(
        accepted,
        "exit13: A still dual-accepts, so the 1059 must land there; got {message:?}"
    );
    let modern = wrap_event(&writer, 3359);
    let (accepted, message) = publish_with_result(a.url(), &modern).await;
    assert!(
        accepted,
        "exit13: the 3359 must be accepted on A; got {message:?}"
    );

    // B must first take the registration — until it does, its derived wrap
    // filter has no authors and NOTHING would replicate, legacy or not.
    assert!(
        wait_for_exact_event(b.url(), reg.id, REPLICATION_BOUND).await,
        "exit13: the 30640 {} must replicate A->B despite the fingerprint split",
        reg.id
    );

    // Positive control: the new kind crosses the split.
    assert!(
        wait_for_exact_event(b.url(), modern.id, REPLICATION_BOUND).await,
        "exit13: the 3359 {} must replicate to a peer with legacy accept off",
        modern.id
    );

    // Only NOW is absence meaningful. Settle past one more sync tick so a
    // late-arriving 1059 would still be caught.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let by_id = fetch_from(b.url(), Filter::new().id(legacy.id)).await;
    assert!(
        by_id.is_empty(),
        "exit13: the legacy 1059 {} must NOT replicate to a node that has \
         closed the migration window; B served {} event(s)",
        legacy.id,
        by_id.len()
    );
    let by_kind = fetch_from(
        b.url(),
        Filter::new()
            .kind(Kind::Custom(1059))
            .author(writer.public_key()),
    )
    .await;
    assert!(
        by_kind.is_empty(),
        "exit13: B must hold no 1059 from the registered write key at all; got {} event(s)",
        by_kind.len()
    );

    // A is unaffected by its peer's stricter policy: it still serves both.
    let served_a = fetch_from(
        a.url(),
        Filter::new()
            .kinds([Kind::Custom(1059), Kind::Custom(3359)])
            .author(writer.public_key()),
    )
    .await;
    assert!(
        served_a.iter().any(|e| e.id == legacy.id) && served_a.iter().any(|e| e.id == modern.id),
        "exit13: A must keep serving both wraps regardless of B's policy"
    );

    b.stop().await;
    a.stop().await;
}
