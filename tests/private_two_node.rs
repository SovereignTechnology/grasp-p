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
use bitcoin_hashes::sha256;
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
/// (`grasp_p/admission.rs`, the wrap arm's `None` branch). Its twin in the
/// sync ingest path (`sync/grasp_p_sync.rs`, `grasp_p_after_rejected`) is
/// UNCOVERED by this suite and stays so: B only asks a peer for wraps
/// by an author it has already accepted a 30640 for, so a synced wrap
/// preceding its own registration is a race, not something the harness can
/// order — deleting that arm leaves this suite green. What IS pinned is the
/// contract it depends on: `PrivateRejectedIndex` holds both wire kinds
/// under one author bucket and releases them together
/// (`sync::private_index::tests::test_wrap_hold_is_kind_agnostic_per_author`),
/// and that both paths reach the hold through one decision that holds
/// every dependency rejection
/// (`grasp_p::tests::dependency_rejections_are_held_on_both_paths`).
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

/// Poll the metrics endpoint of `relay`, a GRASP-P node, until `check`
/// passes on the parsed scrape. A scrape that is not a 200 panics.
async fn wait_for_metrics(
    relay: &TestRelay,
    bound: Duration,
    check: impl Fn(&ParsedMetrics) -> bool,
) -> bool {
    wait_for_scrape(relay, bound, check).await.is_some()
}

/// Like [`wait_for_metrics`], and hands back the scrape that passed, so
/// that what a test asserts next is read from that answer and not from a
/// later one.
async fn wait_for_scrape(
    relay: &TestRelay,
    bound: Duration,
    check: impl Fn(&ParsedMetrics) -> bool,
) -> Option<String> {
    let deadline = Instant::now() + bound;
    loop {
        let scrape = relay.grasp_p_metrics().await;
        if check(&ParsedMetrics::parse(&scrape)) {
            return Some(scrape);
        }
        if Instant::now() >= deadline {
            return None;
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
/// policy preimage that differs between the two envs makes the fingerprints
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

    let warnings = count_log_lines(&b.log_path(), |line| {
        line.contains("the blob mirror has no peers")
    });
    assert_eq!(warnings, 0, "exit1: a node with a blob peer must not warn");

    let latency = replication_started.elapsed();
    println!("exit1: full A->B replication (events + blobs) in {latency:?}");
    assert!(
        latency <= Duration::from_secs(120),
        "exit1: replication must complete within the design's 120s bound"
    );

    // The mirror needed no blob listing: /list answers only the listed key,
    // and a peer holds no such authorization (issue 14).
    for node in [&a, &b] {
        let status = reqwest::Client::new()
            .get(format!(
                "{}/list/{}",
                http_base(node),
                tenant.public_key().to_hex()
            ))
            .send()
            .await
            .expect("GET /list transport")
            .status()
            .as_u16();
        assert_eq!(status, 401, "exit1: an anonymous /list must be refused");
    }

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
    // kill. A still lists B's old address, so the fingerprints differ from
    // here on; nothing below compares them.
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

    // No private mirror activity is ever reported. With GRASP-P off the
    // scrape is upstream's, on the public port: the fixture still passes a
    // metrics bind address, and a node without GRASP-P must ignore it.
    assert_eq!(
        b.grasp_p_metrics_address(),
        None,
        "exit4: a node without GRASP-P must not open a metrics endpoint"
    );
    let scrape = fetch_metrics(b.url())
        .await
        .expect("exit4: B /metrics must be reachable");
    // `fetch_metrics` returns the body of any status, and the two readings
    // below take a missing series for 0. A series every scrape carries
    // shows that this is a scrape and not an error page.
    assert!(
        scrape.contains("ngit_uptime_seconds"),
        "exit4: B must still serve upstream's /metrics on its public port"
    );
    let metrics = ParsedMetrics::parse(&scrape);
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
// Exit test 21 — a settled seat keeps its alias on both nodes (D8)
// ============================================================================

/// A seat whose first edition is dated more than an hour back is settled
/// the moment it arrives, so the test needs no waiting: the holder's
/// registration, dated two hours back, reaches B through sync, and a claim
/// dated before it is then refused by both nodes, by B against a seat that
/// sync delivered, the same way as by A, which took the seat from a client.
/// Both keep serving the holder's registration alone.
#[tokio::test]
async fn exit21_settled_seat_is_kept_on_both_nodes() {
    let holder = Keys::generate();
    let challenger = Keys::generate();
    let whitelist = whitelist_npubs(&[&holder, &challenger]);
    let (a, b) = start_pair(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())]).await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let holder_writer = Keys::generate();
    let challenger_writer = Keys::generate();
    let alias = random_alias();
    let now = Timestamp::now().as_secs();

    let held = registration_event(
        &holder,
        &alias,
        &holder_writer,
        &domain_refs,
        Some(now - 7200),
    );
    let (accepted, message) = publish_with_result(a.url(), &held).await;
    assert!(
        accepted,
        "exit21: the holder's registration failed: {message:?}"
    );
    assert!(
        wait_for_exact_event(b.url(), held.id, REPLICATION_BOUND).await,
        "exit21: the holder's registration must replicate to B"
    );

    let backdated = registration_event(
        &challenger,
        &alias,
        &challenger_writer,
        &domain_refs,
        Some(now - 10800),
    );
    for (name, node) in [("A", &a), ("B", &b)] {
        let (accepted, message) = publish_with_result(node.url(), &backdated).await;
        assert!(
            !accepted && message.contains("alias already registered"),
            "exit21: node {name} must refuse a claim dated before a settled seat; got accepted={accepted} {message:?}"
        );
    }

    for (name, node) in [("A", &a), ("B", &b)] {
        let served = fetch_from(
            node.url(),
            Filter::new().kind(Kind::Custom(30640)).identifier(&alias),
        )
        .await;
        assert_eq!(
            served.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![held.id],
            "exit21: node {name} serves the holder's registration alone"
        );
    }

    a.stop().await;
    b.stop().await;
}

// ============================================================================
// Exit test 22 — the account's offboard request reaches the peer; a write key
// cannot delete (decision D6)
// ============================================================================

/// Only the account key deletes, and only a whole repository, through its
/// registration. A write key's deletion of its own state root, by event id
/// or by coordinate, is refused on both nodes and the state root stays
/// served on both. The account's offboard request, published on A alone,
/// reaches B by sync (the offboard filter rides the peer link), B judges it
/// as A did, and the registration is no longer live on either node: a new
/// state root is refused on both. A second account then closes by vanish on
/// A alone; B asks A for the vanishes of the accounts it hosts, a filter it
/// adds when its index changes, and stops serving that account's
/// registration too. Ledger and purge assertions belong to the hold and
/// purge work.
#[tokio::test]
async fn exit22_offboard_request_reaches_the_peer_and_a_write_key_cannot_delete() {
    let tenant = Keys::generate();
    let tenant2 = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant, &tenant2]);
    let (a, b) = start_pair(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())]).await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let writer = Keys::generate();
    let alias = random_alias();
    let now = Timestamp::now().as_secs();

    let registration = registration_event(&tenant, &alias, &writer, &domain_refs, Some(now - 120));
    let (accepted, message) = publish_with_result(a.url(), &registration).await;
    assert!(accepted, "exit22: registration failed: {message:?}");
    assert!(
        wait_for_exact_event(b.url(), registration.id, REPLICATION_BOUND).await,
        "exit22: the registration must replicate to B"
    );

    let manifest = sha256_hex(&blob_bytes(97, 64));
    let root = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&manifest, 64),
        &[],
        now - 60,
    );
    let (accepted, message) = publish_with_result(a.url(), &root).await;
    assert!(accepted, "exit22: state root failed: {message:?}");
    assert!(
        wait_for_exact_event(b.url(), root.id, REPLICATION_BOUND).await,
        "exit22: the state root must replicate to B"
    );

    // The write key deletes its own state root: upstream alone would take
    // both, and the coordinate form would also refuse the key's later state
    // roots for this alias.
    let by_id = EventBuilder::new(Kind::EventDeletion, "")
        .tags(vec![
            Tag::event(root.id),
            Tag::custom("k", vec!["30641".to_string()]),
        ])
        .finalize(&writer)
        .expect("sign kind-5");
    let by_coordinate = EventBuilder::new(Kind::EventDeletion, "")
        .tags(vec![
            Tag::custom(
                "a",
                vec![format!("30641:{}:{alias}", writer.public_key().to_hex())],
            ),
            Tag::custom("k", vec!["30641".to_string()]),
        ])
        .finalize(&writer)
        .expect("sign kind-5");
    for (name, node) in [("A", &a), ("B", &b)] {
        for (what, request) in [("by id", &by_id), ("by coordinate", &by_coordinate)] {
            let (accepted, message) = publish_with_result(node.url(), request).await;
            assert!(
                !accepted && message.contains("restricted:") && !message.contains("unregistered"),
                "exit22: node {name} must refuse the write key's deletion {what}; got accepted={accepted} {message:?}"
            );
        }
    }
    for (name, node) in [("A", &a), ("B", &b)] {
        let served = fetch_from(node.url(), Filter::new().id(root.id)).await;
        assert_eq!(
            served.len(),
            1,
            "exit22: node {name} must still serve the state root"
        );
    }

    // The account's offboard request, on A only.
    let offboard = EventBuilder::new(Kind::EventDeletion, "offboard")
        .tags(vec![
            Tag::custom("a", vec![reg_coord(&tenant.public_key(), &alias)]),
            Tag::custom("k", vec!["30640".to_string()]),
        ])
        .finalize(&tenant)
        .expect("sign kind-5");
    let (accepted, message) = publish_with_result(a.url(), &offboard).await;
    assert!(
        accepted,
        "exit22: A refused the offboard request: {message:?}"
    );
    assert!(
        wait_for_exact_event(b.url(), offboard.id, REPLICATION_BOUND).await,
        "exit22: the offboard request must reach B by sync"
    );

    // B stores a request only after acting on it; poll anyway, so a slow
    // save cannot fail the test for the wrong reason.
    let registrations = Filter::new()
        .kind(Kind::Custom(30640))
        .author(tenant.public_key())
        .identifier(&alias);
    let deadline = Instant::now() + REPLICATION_BOUND;
    while !fetch_from(b.url(), registrations.clone()).await.is_empty() {
        assert!(
            Instant::now() < deadline,
            "exit22: B still serves the registration after the offboard request arrived"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    let after = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&manifest, 64),
        &[],
        Timestamp::now().as_secs(),
    );
    for (name, node) in [("A", &a), ("B", &b)] {
        let (accepted, message) = publish_with_result(node.url(), &after).await;
        assert!(
            !accepted && message.contains("unregistered alias"),
            "exit22: node {name} must refuse a state root once the registration is deleted; got accepted={accepted} {message:?}"
        );
    }

    // A second account closes by vanish on A only. B asks A for the
    // vanishes of the accounts it hosts, a filter added when its index
    // changes.
    let writer2 = Keys::generate();
    let alias2 = random_alias();
    let registration2 =
        registration_event(&tenant2, &alias2, &writer2, &domain_refs, Some(now - 120));
    let (accepted, message) = publish_with_result(a.url(), &registration2).await;
    assert!(accepted, "exit22: second registration failed: {message:?}");
    assert!(
        wait_for_exact_event(b.url(), registration2.id, REPLICATION_BOUND).await,
        "exit22: the second registration must replicate to B"
    );
    let vanish = EventBuilder::new(Kind::RequestToVanish, "")
        .tags(vec![Tag::custom("relay", vec!["ALL_RELAYS".to_string()])])
        .finalize(&tenant2)
        .expect("sign kind-62");
    let (accepted, message) = publish_with_result(a.url(), &vanish).await;
    assert!(
        accepted,
        "exit22: A refused the account's vanish: {message:?}"
    );
    assert!(
        wait_for_exact_event(b.url(), vanish.id, REPLICATION_BOUND).await,
        "exit22: the vanish must reach B by sync"
    );
    let registrations2 = Filter::new()
        .kind(Kind::Custom(30640))
        .author(tenant2.public_key())
        .identifier(&alias2);
    let deadline = Instant::now() + REPLICATION_BOUND;
    while !fetch_from(b.url(), registrations2.clone()).await.is_empty() {
        assert!(
            Instant::now() < deadline,
            "exit22: B still serves the vanished account's registration"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    a.stop().await;
    b.stop().await;
}

// ============================================================================
// Exit test 23 — the peer refuses a synced write of an account it lists
// ============================================================================

/// Decision D9 across a pair. B holds an account's registration when its
/// operator lists the account on `NGIT_EVENT_BLACKLIST` and restarts it; A,
/// whose list is still empty, takes a new state root of that account. When
/// sync brings it to B, B refuses it as it refuses a client's, while a state
/// root of another account published after it replicates. Upstream checked
/// only the author, a write key the operator never sees, so B took it.
#[tokio::test]
async fn exit23_peer_refuses_a_synced_state_root_of_an_account_it_lists() {
    let b_git_dir = tempfile::tempdir().expect("b git dir");
    let b_relay_dir = tempfile::tempdir().expect("b relay dir");
    let b_paths = (
        b_git_dir.path().to_path_buf(),
        b_relay_dir.path().to_path_buf(),
    );

    let frozen = Keys::generate();
    let free = Keys::generate();
    let whitelist = whitelist_npubs(&[&frozen, &free]);
    let (a, b) = start_pair_with_b_paths(
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
        Some(b_paths.clone()),
    )
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let frozen_writer = Keys::generate();
    let frozen_alias = random_alias();
    let frozen_registration =
        register_on(&a, &domain_refs, &frozen, &frozen_writer, &frozen_alias).await;
    let free_writer = Keys::generate();
    let free_alias = random_alias();
    let free_registration = register_on(&a, &domain_refs, &free, &free_writer, &free_alias).await;
    for registration in [&frozen_registration, &free_registration] {
        assert!(
            wait_for_exact_event(b.url(), registration.id, REPLICATION_BOUND).await,
            "exit23: both registrations must reach B before it is restarted"
        );
    }

    // B's operator lists the account and restarts B on the same data.
    b.stop().await;
    let listed = frozen.public_key().to_bech32().expect("npub");
    let b = TestRelay::start_grasp_p_pair_node(
        reserve_port(),
        Some(a.url().to_string()),
        true,
        Some(b_paths.0.clone()),
        Some(b_paths.1.clone()),
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("NGIT_EVENT_BLACKLIST", listed.as_str()),
        ],
    )
    .await;
    // A takes a state root of the listed account, then one of the other.
    let now = Timestamp::now().as_secs();
    let manifest = sha256_hex(&blob_bytes(98, 64));
    let frozen_root = state_root_event(
        &frozen_writer,
        &frozen.public_key(),
        &frozen_alias,
        (&manifest, 64),
        &[],
        now,
    );
    let (accepted, message) = publish_with_result(a.url(), &frozen_root).await;
    assert!(accepted, "exit23: A has no list; got {message:?}");
    let free_root = state_root_event(
        &free_writer,
        &free.public_key(),
        &free_alias,
        (&manifest, 64),
        &[],
        now,
    );
    let (accepted, message) = publish_with_result(a.url(), &free_root).await;
    assert!(
        accepted,
        "exit23: the other state root on A; got {message:?}"
    );

    // B takes the other account's state root and refuses this one, which it
    // was sent: the refusal is counted, and nothing is stored.
    assert!(
        wait_for_exact_event(b.url(), free_root.id, REPLICATION_BOUND).await,
        "exit23: the other account's state root must replicate to B"
    );
    assert!(
        wait_for_metrics(&b, REPLICATION_BOUND, |m| {
            m.counter("ngit_private_events_rejected_total", &[("kind", "30641")])
                .unwrap_or(0)
                >= 1
        })
        .await,
        "exit23: B must refuse the listed account's state root when sync brings it"
    );
    assert!(
        fetch_from(b.url(), Filter::new().id(frozen_root.id))
            .await
            .is_empty(),
        "exit23: B must not store the listed account's state root"
    );

    // A client is told why, and what the account stored before stays served.
    let (accepted, message) = publish_with_result(b.url(), &frozen_root).await;
    assert!(
        !accepted && message.contains(&format!("blocked: Account {listed} is blacklisted")),
        "exit23: B's answer to a client; got {message:?}"
    );
    assert!(
        wait_for_exact_event(b.url(), frozen_registration.id, Duration::from_secs(10)).await,
        "exit23: B must still serve the listed account's registration"
    );

    b.stop().await;
    a.stop().await;
}

// ============================================================================
// Exit test 24 — nothing attaches to private-repository events, on both nodes
// ============================================================================

/// Decision A across a pair. A registration and a wrap that A takes reach
/// B by sync. A public note that tags the wrap, and a report that names the
/// registration, are then refused on both nodes, each judging by its own
/// store, and neither is served; each node counts the report it refused.
/// Upstream alone would store both on the stored private event as their
/// anchor.
#[tokio::test]
async fn exit24_nothing_attaches_to_private_events_on_either_node() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let (a, b) = start_pair(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())]).await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let writer = Keys::generate();
    let alias = random_alias();
    let registration = register_on(&a, &domain_refs, &tenant, &writer, &alias).await;
    let wrap = wrap_event(&writer, 3359);
    let (accepted, message) = publish_with_result(a.url(), &wrap).await;
    assert!(accepted, "exit24: the wrap on A; got {message:?}");
    for event in [&registration, &wrap] {
        assert!(
            wait_for_exact_event(b.url(), event.id, REPLICATION_BOUND).await,
            "exit24: kind {} must replicate to B",
            event.kind.as_u16()
        );
    }

    let stranger = Keys::generate();
    for (name, node) in [("A", &a), ("B", &b)] {
        let note = EventBuilder::new(Kind::TextNote, format!("a note sent to {name}"))
            .tags(vec![Tag::event(wrap.id)])
            .finalize(&stranger)
            .expect("sign note");
        let (accepted, message) = publish_with_result(node.url(), &note).await;
        assert!(
            !accepted
                && message.contains(
                    "restricted: events that reference private repositories are not stored on this service"
                ),
            "exit24: {name} must refuse a note that tags the wrap; got {message:?}"
        );
        let report = EventBuilder::new(Kind::Reporting, format!("a report sent to {name}"))
            .tags(vec![Tag::event(registration.id)])
            .finalize(&stranger)
            .expect("sign report");
        let (accepted, message) = publish_with_result(node.url(), &report).await;
        assert!(
            !accepted
                && message.contains(
                    "restricted: reports about private repositories are not stored on this service"
                ),
            "exit24: {name} must refuse a report on the registration; got {message:?}"
        );
        assert!(
            fetch_from(node.url(), Filter::new().ids([note.id, report.id]))
                .await
                .is_empty(),
            "exit24: {name} must serve neither"
        );
        assert!(
            wait_for_metrics(node, Duration::from_secs(10), |m| {
                m.counter("ngit_private_report_events_total", &[])
                    .unwrap_or(0)
                    == 1
            })
            .await,
            "exit24: {name} counts the report it refused"
        );
    }

    b.stop().await;
    a.stop().await;
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
        ParsedMetrics::parse(&b.grasp_p_metrics().await)
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
/// (live) delivery — a TRANSIENT rejection under a fixed registration, and
/// not one a registration could cure, so the event is not held: only its id
/// goes into the skip-set. A's one live push is spent, so only a since=None
/// historic redelivery can bring it back. Freeing the quota (blob DELETE,
/// not a registration change) plus the skip-set TTL lapse leaves the
/// re-issue timer as the sole path.
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
    // which quota-rejects it: its id goes into the skip-set (a quota
    // rejection is not held, no registration can cure it).
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
    // for the TTL, and no 30640 ever lands.
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
/// false, then serves the seeded blobs (404 for unknown hashes). A blob
/// with a delay is answered that much later, every time.
struct FlakyBlobServer {
    base_url: String,
    serve: Arc<std::sync::atomic::AtomicBool>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl FlakyBlobServer {
    async fn start(blobs: Vec<(String, Vec<u8>)>) -> Self {
        Self::start_slow(blobs, std::collections::HashMap::new()).await
    }

    /// Like [`Self::start`], answering each hash in `delays` only after its
    /// delay.
    async fn start_slow(
        blobs: Vec<(String, Vec<u8>)>,
        delays: std::collections::HashMap<String, Duration>,
    ) -> Self {
        let delays = Arc::new(delays);
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
                        let delays = delays.clone();
                        tokio::spawn(async move {
                            use http_body_util::Full;
                            use hyper::body::Bytes;
                            let service = hyper::service::service_fn(
                                move |req: hyper::Request<hyper::body::Incoming>| {
                                    let serve = serve.clone();
                                    let blobs = blobs.clone();
                                    let delays = delays.clone();
                                    async move {
                                        let sha =
                                            req.uri().path().trim_start_matches('/').to_string();
                                        if let Some(delay) = delays.get(&sha).copied() {
                                            tokio::time::sleep(delay).await;
                                        }
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

    // The stub is the only blob peer of both nodes: the list given here
    // replaces the one the fixture derives from the other node. NGIT_TEST
    // clamps the backoff base to 1s and the repair tick is 1s.
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
        ParsedMetrics::parse(&b.grasp_p_metrics().await)
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
// Exit test 15 — one account's slow backlog does not starve another account
// ============================================================================

/// Issue 26. One account has forty blobs that the peer serves slowly; a
/// second account then declares one blob the peer serves at once. The
/// second account's blob must be on the replica within seconds, while the
/// first account is still far behind, and the first account must keep
/// being served too.
///
/// Before the mirror kept one queue per account, its worker took the forty
/// blobs as one job and waited for a fetch slot for each of them in turn,
/// so the second account's blob waited for all forty: about 45 seconds
/// with the numbers below.
#[tokio::test]
async fn exit15_one_tenants_backlog_does_not_starve_another() {
    const SLOW_BLOBS: usize = 40;
    const SLOW_DELAY: Duration = Duration::from_secs(5);

    let slow_blobs: Vec<Vec<u8>> = (0..SLOW_BLOBS)
        .map(|i| blob_bytes(100 + i as u8, 512))
        .collect();
    let slow_refs: Vec<(String, u64)> = slow_blobs
        .iter()
        .map(|blob| (sha256_hex(blob), blob.len() as u64))
        .collect();
    let quick_blob = blob_bytes(90, 512);
    let quick_sha = sha256_hex(&quick_blob);

    let mut served: Vec<(String, Vec<u8>)> = slow_refs
        .iter()
        .map(|(sha, _)| sha.clone())
        .zip(slow_blobs.iter().cloned())
        .collect();
    served.push((quick_sha.clone(), quick_blob.clone()));
    let delays: std::collections::HashMap<String, Duration> = slow_refs
        .iter()
        .map(|(sha, _)| (sha.clone(), SLOW_DELAY))
        .collect();
    let stub = FlakyBlobServer::start_slow(served, delays).await;
    stub.serve.store(true, std::sync::atomic::Ordering::SeqCst);

    // The stub is the only blob peer of both nodes, so every blob B ends
    // up with came through B's mirror.
    let slow_tenant = Keys::generate();
    let quick_tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&slow_tenant, &quick_tenant]);
    let (a, b) = start_pair(&[
        ("NGIT_GRASP_P_MIRROR_PEER_URLS", &stub.base_url),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    // Everything is published on B itself, so no step below waits for the
    // pair to sync: the bounds measure B's mirror and nothing else.
    let slow_writer = Keys::generate();
    let slow_alias = random_alias();
    register_on(&b, &domain_refs, &slow_tenant, &slow_writer, &slow_alias).await;
    let quick_writer = Keys::generate();
    let quick_alias = random_alias();
    register_on(&b, &domain_refs, &quick_tenant, &quick_writer, &quick_alias).await;

    // The slow account declares its forty blobs in one state root.
    let slow_edition = state_root_event(
        &slow_writer,
        &slow_tenant.public_key(),
        &slow_alias,
        (&slow_refs[0].0, slow_refs[0].1),
        &slow_refs[1..],
        Timestamp::now().as_secs(),
    );
    let (accepted, message) = publish_with_result(b.url(), &slow_edition).await;
    assert!(accepted, "exit15: the slow 30641 failed on B: {message:?}");
    assert!(
        wait_for_metrics(&b, REPLICATION_BOUND, |m| {
            m.gauge("ngit_private_mirror_lag_blobs", &[]).unwrap_or(0) >= 30
        })
        .await,
        "exit15: B must be behind on the slow account's blobs"
    );

    // The quick account's one blob is not behind them.
    let quick_edition = state_root_event(
        &quick_writer,
        &quick_tenant.public_key(),
        &quick_alias,
        (&quick_sha, quick_blob.len() as u64),
        &[],
        Timestamp::now().as_secs(),
    );
    let (accepted, message) = publish_with_result(b.url(), &quick_edition).await;
    assert!(accepted, "exit15: the quick 30641 failed on B: {message:?}");
    let mirrored = wait_for_blob(&b, &quick_sha, Duration::from_secs(20))
        .await
        .expect("exit15: the quick account's blob must not wait for the slow account's backlog");
    assert_eq!(mirrored, quick_blob, "exit15: mirrored blob bytes intact");

    let lag = ParsedMetrics::parse(&b.grasp_p_metrics().await)
        .gauge("ngit_private_mirror_lag_blobs", &[])
        .unwrap_or(0);
    assert!(
        lag > 0,
        "exit15: the slow account must still be behind when the quick blob has arrived"
    );

    // The slow account is served as well: its first blob arrives.
    let first_slow = wait_for_blob(&b, &slow_refs[0].0, Duration::from_secs(150))
        .await
        .expect("exit15: the slow account's blobs must keep arriving");
    assert_eq!(
        first_slow, slow_blobs[0],
        "exit15: mirrored blob bytes intact"
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
    let node = TestRelay::start_grasp_p_pair_node(
        res2,
        None,
        true,
        Some(paths.0.clone()),
        Some(paths.1.clone()),
        &[],
    )
    .await;

    // The startup warn fired loudly for the empty-whitelist posture. Every
    // spawn truncates the relay log (/tmp/relay-<port>.log), so the whole
    // file belongs to this boot, whatever an earlier relay on the same port
    // left there. Skipping the old file's length, as this test did while
    // the log was opened in append mode, looked past the end of the new log
    // whenever the port had been used before, and the warning was missed.
    let log = std::fs::read_to_string(node.log_path()).expect("boot-2 relay log");
    assert!(
        log.contains("all new private-repo registrations will be rejected"),
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

// ============================================================================
// Peer redial: a configured peer that is not the bootstrap relay
// ============================================================================

/// A configured peer that is down at the first dial must be dialled again.
/// The peer here is not the bootstrap relay and shares no public repository,
/// so only what the node knows of its configured peers brings it back: the
/// reconnect loop counts it as wanted and the bounded redial dials it.
/// Before that, one failed dial left it disconnected for the life of the
/// process. The reconnect loop alone is pinned by the unit test
/// `failed_first_dial_of_the_bootstrap_relay_is_retried_only_when_listed`.
#[tokio::test]
async fn exit14_peer_down_at_first_dial_is_redialled() {
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());

    // B's port is bound by the reservation but nothing accepts on it yet, so
    // A's first dial times out.
    let a = TestRelay::start_grasp_p_pair_node(
        res_a,
        None,
        true,
        None,
        None,
        &[("NGIT_GRASP_P_SYNC_PEER_URLS", url_b.as_str())],
    )
    .await;
    assert!(
        common::sync_helpers::wait_for_log_line(&a.log_path(), REPLICATION_BOUND, |line| {
            line.contains("degraded") && line.contains(&url_b)
        })
        .await,
        "A's first dial of {url_b} must fail while B is down"
    );

    let b = TestRelay::start_grasp_p_pair_node(res_b, None, true, None, None, &[]).await;
    assert!(
        common::sync_helpers::wait_for_log_line(&a.log_path(), REPLICATION_BOUND, |line| {
            line.contains("Connected to relay") && line.contains(&url_b)
        })
        .await,
        "A must redial {url_b} once B is up"
    );

    a.stop().await;
    b.stop().await;
}

// ============================================================================
// Exit test 16 — a pair on a private link with upstream's guard on
// ============================================================================

/// How many lines of `log_path` pass `predicate`.
fn count_log_lines(log_path: &std::path::Path, predicate: impl Fn(&str) -> bool) -> usize {
    std::fs::read_to_string(log_path)
        .map(|log| log.lines().filter(|line| predicate(line)).count())
        .unwrap_or(0)
}

/// Poll until `count` lines of `log_path` or more pass `predicate`.
async fn wait_for_log_lines(
    log_path: &std::path::Path,
    bound: Duration,
    count: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        if count_log_lines(log_path, &predicate) >= count {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The two nodes of a pair reach each other on loopback, as a production
/// pair would over a private network, and upstream's outbound target policy
/// stays on: `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS` is not set on either node.
/// The link is allowed by `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`
/// alone. Each node names the other in its two peer lists (sync and blob)
/// and nowhere else, so the connection is not upstream's exempt bootstrap
/// relay: without the peer's own dial policy it is refused at registration
/// and nothing replicates. A relay that an event names on loopback is still
/// refused.
#[tokio::test]
async fn exit16_pair_replicates_with_the_upstream_guard_on() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_a = format!("ws://127.0.0.1:{}", res_a.port());
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());
    // With no bootstrap relay the fixture names no peer, so each node is
    // given the other as its sync peer and as its blob peer here.
    let blobs_a = TestRelay::blob_peer_url(&url_a);
    let blobs_b = TestRelay::blob_peer_url(&url_b);
    let a = TestRelay::start_grasp_p_pair_node_with_upstream_guard(
        res_a,
        None,
        true,
        None,
        None,
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("NGIT_GRASP_P_SYNC_PEER_URLS", url_b.as_str()),
            ("NGIT_GRASP_P_MIRROR_PEER_URLS", blobs_b.as_str()),
        ],
    )
    .await;
    let b = TestRelay::start_grasp_p_pair_node_with_upstream_guard(
        res_b,
        None,
        true,
        None,
        None,
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("NGIT_GRASP_P_SYNC_PEER_URLS", url_a.as_str()),
            ("NGIT_GRASP_P_MIRROR_PEER_URLS", blobs_a.as_str()),
        ],
    )
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let writer = Keys::generate();

    // A to B: a registration, a blob and the state root that names it.
    let alias = random_alias();
    register_on(&a, &domain_refs, &tenant, &writer, &alias).await;
    let blob = blob_bytes(61, 2048);
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
    assert!(accepted, "exit16: 30641 accepted on A; got {message:?}");
    assert!(
        wait_for_exact_event(b.url(), edition.id, REPLICATION_BOUND).await,
        "exit16: the state root must replicate A to B with upstream's guard on"
    );
    let mirrored = wait_for_blob(&b, &sha, REPLICATION_BOUND)
        .await
        .expect("exit16: the blob must be mirrored to B");
    assert_eq!(mirrored, blob);

    // B to A: the link works in both directions.
    // A write key belongs to one alias, so the second alias has its own.
    let alias_b = random_alias();
    let writer_b = Keys::generate();
    let registration_b = register_on(&b, &domain_refs, &tenant, &writer_b, &alias_b).await;
    assert!(
        wait_for_exact_event(a.url(), registration_b.id, REPLICATION_BOUND).await,
        "exit16: a registration must replicate B to A with upstream's guard on"
    );

    // The guard is on for everything else: a public announcement on A names
    // a relay on loopback, and A refuses it without a connection.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the listener that stands in for an internal service");
    let internal_relay = format!("ws://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepted_connections = Arc::clone(&connections);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            accepted_connections.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let maintainer = Keys::generate();
    let identifier = "exit16-internal-relay";
    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{}/{identifier}.git",
                    a.domain(),
                    maintainer.public_key().to_bech32().expect("npub")
                )],
            ),
            Tag::custom(
                "relays",
                vec![format!("ws://{}", a.domain()), internal_relay.clone()],
            ),
        ])
        .finalize(&maintainer)
        .expect("sign the announcement");
    let (accepted, message) = publish_with_result(a.url(), &announcement).await;
    assert!(
        accepted,
        "exit16: an announcement that lists A must be admitted; got {message:?}"
    );
    assert!(
        common::sync_helpers::wait_for_log_line(&a.log_path(), REPLICATION_BOUND, |line| {
            line.contains("Rejecting event-directed sync relay target")
                && line.contains(&internal_relay)
        })
        .await,
        "exit16: A must refuse {internal_relay}, which only an event names"
    );
    assert_eq!(
        connections.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "exit16: no connection may reach the relay an event names on loopback"
    );
    // The peer itself was never refused, on either node.
    for (node, peer) in [(&a, &url_b), (&b, &url_a)] {
        assert_eq!(
            count_log_lines(&node.log_path(), |line| {
                line.contains("Rejecting event-directed") && line.contains(peer.as_str())
            }),
            0,
            "exit16: the configured peer {peer} must not be refused"
        );
    }

    b.stop().await;
    a.stop().await;
}

// ============================================================================
// Exit test 17 — a peer that goes away is kept and dialled again
// ============================================================================

/// Node B is killed and started again on the same address while node A
/// keeps running. A must keep B as a relay it tracks, dial it again, and
/// replicate from it afterwards, without a restart of its own.
///
/// A names B in `NGIT_GRASP_P_SYNC_PEER_URLS`, and `also_bootstrap` names it
/// in `NGIT_SYNC_BOOTSTRAP_RELAY_URL` as well, so that the connection is the
/// one upstream registers for its bootstrap relay. Either way B is a peer
/// that no public repository names, which is the relay upstream retires
/// when its session ends. A bootstrap relay the list does not name is no
/// peer at all (`exit18`).
async fn restarted_peer_is_kept_and_redialled(also_bootstrap: bool) {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_a = format!("ws://127.0.0.1:{}", res_a.port());
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());

    // B is up first, so that A's first dial of it succeeds.
    let b = TestRelay::start_grasp_p_pair_node(
        res_b,
        None,
        true,
        None,
        None,
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("NGIT_GRASP_P_SYNC_PEER_URLS", url_a.as_str()),
        ],
    )
    .await;
    let a = TestRelay::start_grasp_p_pair_node(
        res_a,
        also_bootstrap.then(|| url_b.clone()),
        true,
        None,
        None,
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("NGIT_GRASP_P_SYNC_PEER_URLS", url_b.as_str()),
        ],
    )
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let writer = Keys::generate();
    let connected_to_b = |line: &str| line.contains("Connected to relay") && line.contains(&url_b);

    // Baseline: A pulls from B over the session it opened.
    let before = register_on(&b, &domain_refs, &tenant, &writer, &random_alias()).await;
    assert!(
        wait_for_exact_event(a.url(), before.id, REPLICATION_BOUND).await,
        "exit17: a registration on B must reach A before the restart"
    );
    assert!(
        count_log_lines(&a.log_path(), connected_to_b) >= 1,
        "exit17: A must have logged its session to {url_b}"
    );
    let sessions_before = count_log_lines(&a.log_path(), connected_to_b);

    // B goes away and comes back on the same address, empty. A stays up.
    let b = b.restart().await;

    assert!(
        common::sync_helpers::wait_for_log_line(&a.log_path(), REPLICATION_BOUND, |line| {
            line.contains("Unexpected relay disconnect detected") && line.contains(&url_b)
        })
        .await,
        "exit17: A must treat the end of its session to {url_b} as one to recover from"
    );
    assert!(
        wait_for_log_lines(
            &a.log_path(),
            REPLICATION_BOUND,
            sessions_before + 1,
            connected_to_b
        )
        .await,
        "exit17: A must dial {url_b} again once it is back"
    );
    assert_eq!(
        count_log_lines(&a.log_path(), |line| {
            line.contains("retiring without reconnect") && line.contains(&url_b)
        }),
        0,
        "exit17: A must never retire its configured peer {url_b}"
    );

    // The new session carries events: one published on B now reaches A.
    // With a write key of its own: A still holds the first registration, and
    // a write key belongs to one alias, so A would refuse a second alias
    // under the first one's key.
    let writer_after = Keys::generate();
    let after = register_on(&b, &domain_refs, &tenant, &writer_after, &random_alias()).await;
    assert!(
        wait_for_exact_event(a.url(), after.id, REPLICATION_BOUND).await,
        "exit17: a registration on the restarted B must reach A without a restart of A"
    );

    b.stop().await;
    a.stop().await;
}

#[tokio::test]
async fn exit17_restarted_listed_peer_is_kept_and_redialled() {
    restarted_peer_is_kept_and_redialled(false).await;
}

#[tokio::test]
async fn exit17_restarted_peer_that_is_also_the_bootstrap_relay_is_kept_and_redialled() {
    restarted_peer_is_kept_and_redialled(true).await;
}

// ============================================================================
// Exit test 18 — the bootstrap relay is a peer only when the list names it
// ============================================================================

/// Node A is bootstrapped to node C and lists no peer, so C is the relay A's
/// public sync starts from and nothing more. Public sync runs over that
/// connection as upstream's does; GRASP-P sync does not: A never asks C for
/// a registration, takes none from it, and has no peer in its scrape. A node
/// that treated its bootstrap relay as a peer would hold both registrations
/// within seconds, one from its first sync of C and one from the live
/// subscription.
#[tokio::test]
async fn exit18_bootstrap_relay_that_is_not_a_peer_carries_no_grasp_p_sync() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let res_a = reserve_port();
    let res_c = reserve_port();
    let url_c = format!("ws://127.0.0.1:{}", res_c.port());
    let a_domain = format!("127.0.0.1:{}", res_a.port());

    let c = TestRelay::start_grasp_p_pair_node(
        res_c,
        None,
        true,
        None,
        None,
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;
    let domains = [a_domain.clone(), c.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    // Both registrations name both nodes and their tenant is listed on both,
    // so A would accept either if it were given one.
    let (first_writer, second_writer) = (Keys::generate(), Keys::generate());
    let before = register_on(&c, &domain_refs, &tenant, &first_writer, &random_alias()).await;

    // The fixture lists a bootstrap relay as a sync peer and a blob peer
    // too; the empty values take it out again, so C is no peer of A in any
    // sense.
    let a = TestRelay::start_grasp_p_pair_node(
        res_a,
        Some(url_c.clone()),
        true,
        None,
        None,
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("NGIT_GRASP_P_SYNC_PEER_URLS", ""),
            ("NGIT_GRASP_P_MIRROR_PEER_URLS", ""),
        ],
    )
    .await;
    assert!(
        common::sync_helpers::wait_for_log_line(&a.log_path(), REPLICATION_BOUND, |line| {
            line.contains("the blob mirror has no peers")
        })
        .await,
        "exit18: A runs the mirror with no blob peer and must warn at startup"
    );

    // Public sync over the bootstrap connection: an announcement on C that
    // lists A reaches A. By then A's first sync of C is done.
    let maintainer = Keys::generate();
    let identifier = "exit18-public-over-bootstrap";
    let (_announcement, _repository) =
        setup_announcement_on_relay(&c, &maintainer, &domain_refs, identifier).await;
    assert!(
        wait_for_event_on_relay(
            a.url(),
            Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(maintainer.public_key())
                .identifier(identifier),
            REPLICATION_BOUND,
        )
        .await,
        "exit18: a public announcement on C must reach A over the bootstrap connection"
    );

    // A registration published on C while A is connected, then three
    // periods of the full re-issue (2 s under NGIT_TEST) and some.
    let after = register_on(&c, &domain_refs, &tenant, &second_writer, &random_alias()).await;
    tokio::time::sleep(Duration::from_secs(10)).await;

    let held = fetch_from(
        a.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(tenant.public_key()),
    )
    .await;
    assert!(
        held.is_empty(),
        "exit18: A must take no registration from a bootstrap relay that is not a peer; \
         it serves {:?} (before {}, after {})",
        held.iter().map(|event| event.id).collect::<Vec<_>>(),
        before.id,
        after.id
    );

    // The scrape follows the same set: C has no alias on A, and A still
    // counts it among the relays it tracks.
    let scrape = wait_for_scrape(&a, REPLICATION_BOUND, |m| {
        m.relays_tracked_total().is_some_and(|tracked| tracked >= 1)
    })
    .await
    .expect("exit18: A's scrape must count the bootstrap relay it tracks");
    assert!(
        relay_label_values(&scrape).is_empty(),
        "exit18: a bootstrap relay that is not a peer has no series of its own; got {:?}",
        relay_label_values(&scrape)
    );

    a.stop().await;
    c.stop().await;
}

// ============================================================================
// Exit test 19 — the connect-time sync of a peer carries the private filters
// ============================================================================

/// With the periodic full re-issue off, a node that starts after its peer
/// already holds a registration and a state root still gets both: the
/// registration from its first sync of the peer, the state root from the
/// re-issue that the new registration triggers. Every other pair test would
/// also pass on the full re-issue alone, so this is the one that fails when
/// the seam in `sync_generic_filters` goes.
#[tokio::test]
async fn exit19_connect_time_sync_replicates_with_the_full_reissue_off() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let env = [
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
        ("NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS", "0"),
    ];
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_a = format!("ws://127.0.0.1:{}", res_a.port());
    let b_domain = format!("127.0.0.1:{}", res_b.port());

    // A first, with no peer of its own: it never dials B.
    let a = TestRelay::start_grasp_p_pair_node(res_a, None, true, None, None, &env).await;
    let domains = [a.domain(), b_domain];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let writer = Keys::generate();
    let alias = random_alias();
    let registration = register_on(&a, &domain_refs, &tenant, &writer, &alias).await;
    let blob = blob_bytes(71, 1024);
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
    assert!(accepted, "exit19: 30641 accepted on A; got {message:?}");

    // B starts with A as its peer and its bootstrap relay.
    let b = TestRelay::start_grasp_p_pair_node(res_b, Some(url_a), true, None, None, &env).await;
    assert!(
        wait_for_exact_event(b.url(), registration.id, REPLICATION_BOUND).await,
        "exit19: B's first sync of A must bring the registration"
    );
    assert!(
        wait_for_exact_event(b.url(), edition.id, REPLICATION_BOUND).await,
        "exit19: the state root must follow its registration to B"
    );

    b.stop().await;
    a.stop().await;
}

// ============================================================================
// Exit test 20 — the blob mirror uses no proxy from the environment
// ============================================================================

/// B runs with every proxy variable pointing at a listener that only counts
/// connections: B still mirrors the blob from A, and the listener sees
/// nothing. A node is its own process, so its environment races with no
/// other test. `NO_PROXY` is emptied so that a value the test runner
/// inherits cannot exempt loopback and pass this by itself.
#[tokio::test]
async fn exit20_mirror_ignores_the_proxy_variables() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stand-in proxy");
    let proxy = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("the proxy's address").port()
    );
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let (a, b) = start_pair_with_split_env(
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("HTTP_PROXY", proxy.as_str()),
            ("http_proxy", proxy.as_str()),
            ("HTTPS_PROXY", proxy.as_str()),
            ("https_proxy", proxy.as_str()),
            ("ALL_PROXY", proxy.as_str()),
            ("all_proxy", proxy.as_str()),
            ("NO_PROXY", ""),
            ("no_proxy", ""),
        ],
    )
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(String::as_str).collect();
    let writer = Keys::generate();
    let alias = random_alias();
    register_on(&a, &domain_refs, &tenant, &writer, &alias).await;
    let blob = blob_bytes(91, 1024);
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
    assert!(accepted, "exit20: 30641 accepted on A; got {message:?}");

    let mirrored = wait_for_blob(&b, &sha, REPLICATION_BOUND)
        .await
        .expect("exit20: B must mirror the blob whatever its proxy variables say");
    assert_eq!(mirrored, blob, "exit20: mirrored bytes intact");
    assert_eq!(
        connections.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "exit20: nothing may reach the proxy"
    );

    b.stop().await;
    a.stop().await;
}

// ============================================================================
// The scrape of a replicating pair names no relay
// ============================================================================

/// The value of every `relay` label in a scrape.
fn relay_label_values(scrape: &str) -> Vec<&str> {
    scrape
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once("relay=\"")?.1.split_once('"'))
        .map(|(value, _)| value)
        .collect()
}

/// Each node of a pair dials the other, so upstream's sync series would
/// carry the other node's address as a label. The scrape of either node has
/// to show that peer under its alias, connected, and no relay URL anywhere.
/// The first half is what tells a working rewrite from a scrape that only
/// lost its series; the second is what a family upstream labels with a relay
/// later would break if it got past the rewrite. A also dials a relay that
/// only a public repository names, as a customer's would: that relay must
/// have no series in A's scrape and still be counted there.
#[tokio::test]
async fn scrape_never_names_a_relay() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let (a, b) = start_pair(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())]).await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    // One registration from A to B, so that the link whose series are read
    // below has carried events.
    let writer = Keys::generate();
    let alias = random_alias();
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
        "the 30640 must replicate to B within {REPLICATION_BOUND:?}"
    );

    // A relay that only an event names: a public repository on A lists a
    // third relay, as any customer's announcement may. A files that relay
    // like any other, so its series are in A's registry from the log line
    // on, and their absence from the scrape below is the rewrite's doing.
    let stranger = TestRelay::start().await;
    let stranger_address = stranger.domain();
    let maintainer = Keys::generate();
    let (_announcement, _repository) = setup_announcement_on_relay(
        &a,
        &maintainer,
        &[domain_refs[0], stranger_address.as_str()],
        "scrape-names-no-relay",
    )
    .await;
    assert!(
        common::sync_helpers::wait_for_log_line(&a.log_path(), REPLICATION_BOUND, |line| {
            line.contains("Registered new relay for tracking") && line.contains(&stranger_address)
        })
        .await,
        "A must track the relay at {stranger_address} that the announcement names"
    );

    // On each node the other one is its only configured peer, named by the
    // peer list and by the bootstrap setting alike: `peer-1` on both.
    for (name, node, peer, tracked_at_least) in [("B", &b, &a, 1), ("A", &a, &b, 2)] {
        let Some(scrape) = wait_for_scrape(node, REPLICATION_BOUND, |m| {
            m.relay_connected("peer-1") == Some(true)
                && m.counter(
                    "ngit_sync_connection_attempts_total",
                    &[("relay", "peer-1"), ("result", "success")],
                )
                .is_some_and(|dials| dials >= 1)
                && m.gauge("ngit_sync_relay_status", &[("relay", "peer-1")])
                    .is_some()
        })
        .await
        else {
            // What the node did report tells a peer that never connected,
            // whose series are there with other values, from a peer whose
            // series were dropped, which only the aggregates still count.
            let last = node.grasp_p_metrics().await;
            let sync_series: Vec<&str> = last
                .lines()
                .filter(|line| {
                    line.starts_with("ngit_sync_relay")
                        || line.starts_with("ngit_sync_connection_attempts_total")
                })
                .collect();
            panic!(
                "node {name}: within {REPLICATION_BOUND:?} the scrape must show the peer as \
                 relay=\"peer-1\", connected, with a successful dial counted and a health \
                 state; it showed {sync_series:#?}"
            );
        };

        let peer_address = peer.domain();
        assert!(
            !scrape.contains(&peer_address),
            "node {name}: the scrape must not hold its peer's address {peer_address}"
        );
        assert!(
            !scrape.contains(&stranger_address),
            "node {name}: the scrape must not hold {stranger_address}, which only an event names"
        );
        for scheme in ["ws://", "wss://"] {
            assert!(
                !scrape.contains(scheme),
                "node {name}: the scrape must not hold a relay URL ({scheme})"
            );
        }
        let named = relay_label_values(&scrape);
        assert!(
            !named.is_empty() && named.iter().all(|value| *value == "peer-1"),
            "node {name}: every relay label must be the alias of the one peer; got {named:?}"
        );
        // The aggregate series carry no relay label and stay as they were.
        // On A the count covers the relay the announcement names, which has
        // no series of its own in this scrape.
        assert!(
            ParsedMetrics::parse(&scrape)
                .relays_tracked_total()
                .is_some_and(|tracked| tracked >= tracked_at_least),
            "node {name}: the scrape must still count {tracked_at_least} tracked relay(s) or more"
        );
    }

    stranger.stop().await;
    b.stop().await;
    a.stop().await;
}
