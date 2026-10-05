//! GRASP-P Phase-1 exit test suite (design contract §10).
//!
//! Drives a live ngit-grasp subprocess (TestRelay + NGIT_GRASP_P_* env vars)
//! through all eight Phase-1 exit scenarios:
//!
//! 1. enable=false: 30640 orphan-rejected, /upload 404, no NIP-11 advert
//! 2. open-mode E2E: register → preflight → PUT 2 blobs → GET (hash-verified)
//!    → 30641 accepted → edition ring (latest-only REQ, all blobs GET-able)
//! 3. wraps: foreign-key 1059 rejected; registered 1059 stored + served to
//!    anonymous REQ; 21059 broadcast to live subscriber, never stored
//! 4. quota 507 + oversize 413 at preflight AND on the PUT after a lying
//!    preflight; chunked PUT (no Content-Length) → 411; short body → no blob
//! 5. Blossom auth failures: bad sig 401, expired 401, wrong-alias key 403,
//!    aux key 403, x-mismatch 400, missing auth 401
//! 6. whitelist + pow registration modes
//! 7. write-key/alias conflicts; rotation frees a released key
//! 8. NIP-09 a-tag deletion of the 30640 kills 30641/1059 admission
//!
//! ```bash
//! cargo test --test private_repos -- --nocapture
//! ```

mod common;

use std::num::NonZeroU8;
use std::time::Duration;

use base64::prelude::{
    BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD,
};
use base64::Engine as _;
use bitcoin_hashes::{sha256, Hash};
use nostr::nips::nip13::SingleThreadPow;
use nostr_sdk::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::TestRelay;

// ============================================================================
// Relay/WebSocket helpers (mirroring tests/phase0_gates.rs)
// ============================================================================

async fn connect_client(relay_url: &str, keys: Keys) -> Client {
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys))
        .build();
    connect_added(&client, relay_url).await;
    client
}

async fn connect_anonymous_client(relay_url: &str) -> Client {
    let client = Client::builder().build();
    connect_added(&client, relay_url).await;
    client
}

async fn connect_added(client: &Client, relay_url: &str) {
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
            return;
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
// GRASP-P event builders
// ============================================================================

/// A valid alias: exactly 32 lowercase hex chars.
fn random_alias() -> String {
    Keys::generate().public_key().to_hex()[..32].to_string()
}

/// `NGIT_GRASP_P_TENANT_WHITELIST` value (comma-separated npubs) covering
/// every tenant key that authors a kind-30640 in a test. WP-E flipped the
/// shipped admission default to whitelist: tests that exercise open mode
/// set `NGIT_GRASP_P_REGISTRATION_MODE=open` explicitly, and tests that do
/// not care about the mode run under the whitelist default with their
/// tenants listed explicitly (identical registration semantics).
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

/// Schnorr proof-of-possession for a claimed w/aux key, per the §2 audit
/// amendment: sig by `key` over sha256("grasp-p key-claim:<tenant-hex>:<alias>").
fn key_pop_sig(key: &Keys, tenant: &PublicKey, alias: &str) -> String {
    let digest =
        sha256::Hash::hash(format!("grasp-p key-claim:{}:{alias}", tenant.to_hex()).as_bytes());
    key.sign_schnorr(digest.to_byte_array()).to_string()
}

/// A `w`/`aux` tag value list: [pubkey-hex, proof-of-possession sig].
fn key_entry(key: &Keys, tenant: &PublicKey, alias: &str) -> Vec<String> {
    vec![key.public_key().to_hex(), key_pop_sig(key, tenant, alias)]
}

/// Tags for a kind-30640 registration listing this relay in both `relays`
/// and `server` (domain substring match, per §2). Each w/aux entry is the
/// full tag value list (pubkey [+ proof-of-possession sig]).
fn registration_tags(
    alias: &str,
    w_entries: &[Vec<String>],
    aux_entries: &[Vec<String>],
    domain: &str,
) -> Vec<Tag> {
    let mut tags = vec![
        Tag::identifier(alias),
        Tag::custom("relays", vec![format!("ws://{domain}")]),
        Tag::custom("server", vec![format!("http://{domain}")]),
    ];
    for entry in w_entries {
        tags.push(Tag::custom("w", entry.clone()));
    }
    for entry in aux_entries {
        tags.push(Tag::custom("aux", entry.clone()));
    }
    tags
}

/// Signed kind-30640 registration.
fn registration_event(
    tenant: &Keys,
    alias: &str,
    w_entries: &[Vec<String>],
    aux_entries: &[Vec<String>],
    domain: &str,
    created_at: Option<u64>,
) -> Event {
    let mut builder = EventBuilder::new(Kind::Custom(30640), "").tags(registration_tags(
        alias,
        w_entries,
        aux_entries,
        domain,
    ));
    if let Some(secs) = created_at {
        builder = builder.custom_created_at(Timestamp::from_secs(secs));
    }
    builder.finalize(tenant).expect("sign 30640")
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

/// Opaque wrap-shaped event (1059 or 21059) signed by `signer`.
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

/// Signed kind-24242 Blossom auth event.
fn blossom_auth_event(
    signer: &Keys,
    op: &str,
    sha: &str,
    tenant: &PublicKey,
    alias: &str,
    expiration: u64,
) -> Event {
    EventBuilder::new(Kind::Custom(24242), "grasp-p test auth")
        .tags(vec![
            Tag::custom("t", vec![op.to_string()]),
            Tag::custom("x", vec![sha.to_string()]),
            Tag::custom("expiration", vec![expiration.to_string()]),
            Tag::custom("a", vec![reg_coord(tenant, alias)]),
        ])
        .finalize(signer)
        .expect("sign 24242")
}

fn auth_header_value(event: &Event) -> String {
    format!("Nostr {}", BASE64_STANDARD.encode(event.as_json()))
}

/// Signed kind-24242 authorization for `GET /list/<pubkey>`: a `t` tag and
/// an expiration, with no `x` and no `a` tag.
fn list_auth_event(signer: &Keys, op: &str, expiration: u64) -> Event {
    list_event(signer, 24242, op, expiration, "grasp-p test list auth")
}

/// The same event shape, with the kind and the content chosen by the caller.
fn list_event(signer: &Keys, kind: u16, op: &str, expiration: u64, content: &str) -> Event {
    EventBuilder::new(Kind::Custom(kind), content)
        .tags(vec![
            Tag::custom("t", vec![op.to_string()]),
            Tag::custom("expiration", vec![expiration.to_string()]),
        ])
        .finalize(signer)
        .expect("sign list event")
}

fn future_expiration() -> u64 {
    Timestamp::now().as_secs() + 600
}

// ============================================================================
// HTTP helpers (Blossom-subset routes)
// ============================================================================

fn http_base(relay: &TestRelay) -> String {
    format!("http://{}", relay.domain())
}

fn relay_port(relay: &TestRelay) -> u16 {
    relay
        .domain()
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("domain always host:port")
}

/// HEAD /upload preflight → (status, X-Reason header if any).
async fn head_upload(
    relay: &TestRelay,
    sha: &str,
    len: u64,
    auth: Option<&Event>,
) -> (u16, String) {
    let mut req = reqwest::Client::new()
        .request(
            reqwest::Method::HEAD,
            format!("{}/upload", http_base(relay)),
        )
        .header("x-sha-256", sha)
        .header("x-content-length", len.to_string());
    if let Some(auth) = auth {
        req = req.header("authorization", auth_header_value(auth));
    }
    let resp = req.send().await.expect("HEAD /upload transport");
    let reason = resp
        .headers()
        .get("x-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (resp.status().as_u16(), reason)
}

/// PUT /upload → (status, JSON descriptor or Null, X-Reason).
async fn put_blob(
    relay: &TestRelay,
    data: Vec<u8>,
    sha: &str,
    auth: &Event,
) -> (u16, serde_json::Value, String) {
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
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body, reason)
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

/// Raw HTTP/1.1 exchange over TCP (for requests reqwest cannot produce:
/// chunked PUT without Content-Length, deliberately truncated bodies).
/// Returns whatever response bytes the server sent (possibly empty if it
/// just closed the connection).
async fn raw_http_exchange(port: u16, request: &[u8], truncate_after: bool) -> String {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("raw TCP connect");
    stream.write_all(request).await.expect("raw TCP write");
    if truncate_after {
        // Half-close: signal EOF on the request body mid-stream while the
        // read half stays open for the server's error response.
        let _ = stream.shutdown().await;
    }
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).to_string()
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

/// Standard fixture: tenant keys + write key + alias, registered on `relay`.
/// Panics if the registration is rejected.
async fn register_alias(relay: &TestRelay, tenant: &Keys, writer: &Keys, alias: &str) -> Event {
    let event = registration_event(
        tenant,
        alias,
        &[key_entry(writer, &tenant.public_key(), alias)],
        &[],
        &relay.domain(),
        None,
    );
    let (accepted, message) = publish_with_result(relay.url(), &event).await;
    assert!(
        accepted,
        "fixture 30640 registration must be accepted; got: {message:?}"
    );
    event
}

// ============================================================================
// Exit test 1 — enable=false is a strict no-op
// ============================================================================

#[tokio::test]
async fn exit1_disabled_is_noop() {
    // Plain TestRelay: NGIT_GRASP_P_REPOS_ENABLE defaults to false.
    let relay = TestRelay::start().await;
    let tenant = Keys::generate();
    let writer = Keys::generate();

    // A fully well-formed 30640 registration is still just an orphan custom
    // event: rejected by the pre-existing related-events catch-all.
    let alias = random_alias();
    let reg = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        None,
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg).await;
    assert!(
        !accepted,
        "exit1: 30640 must be rejected when private repos are disabled"
    );
    assert!(
        message.contains("restricted:"),
        "exit1: rejection must be the orphan 'restricted:' veto; got: {message:?}"
    );

    // Blob routes do not exist: PUT and HEAD /upload → 404 even with a
    // syntactically valid Blossom auth header.
    let data = blob_bytes(1, 512);
    let sha = sha256_hex(&data);
    let auth = blossom_auth_event(
        &writer,
        "upload",
        &sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (put_status, _, _) = put_blob(&relay, data, &sha, &auth).await;
    assert_eq!(put_status, 404, "exit1: PUT /upload must 404 when disabled");
    let (head_status, _) = head_upload(&relay, &sha, 512, Some(&auth)).await;
    assert_eq!(
        head_status, 404,
        "exit1: HEAD /upload must 404 when disabled"
    );

    // NIP-11 must NOT advertise private repos.
    let doc = nip11_doc(&relay).await;
    assert!(
        doc.get("private_repos").is_none(),
        "exit1: NIP-11 must not contain private_repos when disabled; got: {doc}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 2 — open-mode end-to-end
// ============================================================================

#[tokio::test]
async fn exit2_open_mode_e2e() {
    // Exercises OPEN mode specifically — opt in explicitly (the shipped
    // default is whitelist since WP-E).
    let relay = TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_REGISTRATION_MODE", "open")]).await;
    let tenant = Keys::generate();
    let writer = Keys::generate();
    let alias = random_alias();

    // NIP-11 advertises the subsystem.
    let doc = nip11_doc(&relay).await;
    let private = doc
        .get("private_repos")
        .expect("exit2: NIP-11 must contain private_repos when enabled");
    let kinds: Vec<u64> = private["kinds"]
        .as_array()
        .expect("private_repos.kinds array")
        .iter()
        .filter_map(|k| k.as_u64())
        .collect();
    assert!(
        kinds.contains(&30640)
            && kinds.contains(&30641)
            && kinds.contains(&3359)
            && kinds.contains(&1059),
        "exit2: NIP-11 kinds must list the private kinds (incl. both stream-wrap \
         kinds while legacy accept is on); got {kinds:?}"
    );
    assert_eq!(private["registration_mode"], "open");

    // 30640 accepted + REQ round-trip.
    let reg = register_alias(&relay, &tenant, &writer, &alias).await;
    let served = fetch_from(
        relay.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(tenant.public_key())
            .identifier(&alias),
    )
    .await;
    assert_eq!(
        served.len(),
        1,
        "exit2: registration must round-trip via REQ"
    );
    assert_eq!(served[0].id, reg.id);
    assert_eq!(served[0].tags, reg.tags, "exit2: served tags intact");

    // Two blobs, few KiB each.
    let blob1 = blob_bytes(10, 2048);
    let blob2 = blob_bytes(20, 3072);
    let sha1 = sha256_hex(&blob1);
    let sha2 = sha256_hex(&blob2);
    assert_ne!(sha1, sha2);

    // Preflight 200 for blob1.
    let auth1 = blossom_auth_event(
        &writer,
        "upload",
        &sha1,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, reason) = head_upload(&relay, &sha1, blob1.len() as u64, Some(&auth1)).await;
    assert_eq!(
        status, 200,
        "exit2: preflight must be 200; X-Reason: {reason}"
    );

    // PUT both blobs; descriptors must carry the committed sha + size.
    let (status, descriptor, reason) = put_blob(&relay, blob1.clone(), &sha1, &auth1).await;
    assert_eq!(
        status, 200,
        "exit2: PUT blob1 must be 200; X-Reason: {reason}"
    );
    assert_eq!(descriptor["sha256"], sha1.as_str());
    assert_eq!(descriptor["size"], blob1.len() as u64);
    assert!(
        descriptor["url"].as_str().unwrap_or("").contains(&sha1),
        "exit2: descriptor url must reference the sha; got {descriptor}"
    );

    let auth2 = blossom_auth_event(
        &writer,
        "upload",
        &sha2,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, descriptor2, reason) = put_blob(&relay, blob2.clone(), &sha2, &auth2).await;
    assert_eq!(
        status, 200,
        "exit2: PUT blob2 must be 200; X-Reason: {reason}"
    );
    assert_eq!(descriptor2["sha256"], sha2.as_str());

    // GET both back, hash-verified, public (no auth).
    let (status, body) = get_blob(&relay, &sha1).await;
    assert_eq!(status, 200, "exit2: GET blob1 must be 200");
    assert_eq!(body, blob1, "exit2: blob1 bytes must round-trip");
    assert_eq!(sha256_hex(&body), sha1, "exit2: blob1 hash-verified");
    let (status, body) = get_blob(&relay, &sha2).await;
    assert_eq!(status, 200, "exit2: GET blob2 must be 200");
    assert_eq!(sha256_hex(&body), sha2, "exit2: blob2 hash-verified");

    // First 30641 edition: m=blob1, pack=blob2.
    let t0 = Timestamp::now().as_secs();
    let edition1 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha1, blob1.len() as u64),
        &[(sha2.clone(), blob2.len() as u64)],
        t0,
    );
    let (accepted, message) = publish_with_result(relay.url(), &edition1).await;
    assert!(
        accepted,
        "exit2: first 30641 must be accepted; got {message:?}"
    );

    // Second edition (strictly newer) referencing a NEW blob3 + blob2,
    // dropping blob1 from the live state.
    let blob3 = blob_bytes(30, 1024);
    let sha3 = sha256_hex(&blob3);
    let auth3 = blossom_auth_event(
        &writer,
        "upload",
        &sha3,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, blob3.clone(), &sha3, &auth3).await;
    assert_eq!(
        status, 200,
        "exit2: PUT blob3 must be 200; X-Reason: {reason}"
    );

    let edition2 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha3, blob3.len() as u64),
        &[(sha2.clone(), blob2.len() as u64)],
        t0 + 5,
    );
    let (accepted, message) = publish_with_result(relay.url(), &edition2).await;
    assert!(
        accepted,
        "exit2: second 30641 must be accepted; got {message:?}"
    );

    // Addressable replacement: REQ serves ONLY the latest edition.
    let editions = fetch_from(
        relay.url(),
        Filter::new().kind(Kind::Custom(30641)).identifier(&alias),
    )
    .await;
    assert_eq!(
        editions.len(),
        1,
        "exit2: relay must serve only the latest 30641 edition"
    );
    assert_eq!(editions[0].id, edition2.id, "exit2: latest edition wins");

    // Edition-ring semantics (G7 amendment, verified indirectly): blobs of
    // BOTH editions remain GET-able — claims are retained across the ring.
    for (sha, data) in [(&sha1, &blob1), (&sha2, &blob2), (&sha3, &blob3)] {
        let (status, body) = get_blob(&relay, sha).await;
        assert_eq!(status, 200, "exit2: blob {sha} must remain GET-able");
        assert_eq!(&body, data, "exit2: blob {sha} content intact");
    }

    relay.stop().await;
}

// ============================================================================
// Exit test 3 — wraps: foreign key rejected, registered stored, 21059 ephemeral
// ============================================================================

#[tokio::test]
async fn exit3_wrap_admission() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    // (a) 1059 signed by an unregistered key falls through to the public
    // related-events path and is rejected as an orphan.
    let foreign = wrap_event(&Keys::generate(), 1059);
    let (accepted, message) = publish_with_result(relay.url(), &foreign).await;
    assert!(!accepted, "exit3: foreign-key 1059 must be rejected");
    assert!(
        message.contains("restricted:"),
        "exit3: foreign wrap rejection must be 'restricted:'; got {message:?}"
    );

    // (b) 1059 signed by the registered write key: accepted, stored,
    // quota-charged its event bytes, and served to a completely anonymous
    // client.
    let ledger_before_wrap = global_ledger_bytes(relay.url()).await;
    assert!(
        ledger_before_wrap > 0,
        "exit3: the registration must already be on the ledger"
    );
    let wrap = wrap_event(&writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        accepted,
        "exit3: registered-key 1059 must be accepted; got {message:?}"
    );
    let want = ledger_before_wrap + wrap.as_json().len() as i64;
    let ledger_after_wrap = poll_until(want, || global_ledger_bytes(relay.url())).await;
    assert_eq!(
        ledger_after_wrap, want,
        "exit3: the stored 1059 must be quota-charged its event bytes"
    );
    let anon = connect_anonymous_client(relay.url()).await;
    let served = anon
        .fetch_events(Filter::new().kind(Kind::Custom(1059)))
        .timeout(Duration::from_secs(10))
        .await
        .expect("exit3: anonymous fetch failed");
    let served: Vec<Event> = served.into_iter().collect();
    assert!(
        served.iter().any(|e| e.id == wrap.id),
        "exit3: stored 1059 must be served to an anonymous REQ"
    );
    anon.disconnect().await;

    // (c) 21059 by the registered key: subscriber connected FIRST, then the
    // publish must broadcast live — and never be stored.
    let subscriber = connect_client(relay.url(), Keys::generate()).await;
    let mut notifications = subscriber.notifications();
    let sub_output = subscriber
        .subscribe(Filter::new().kind(Kind::Custom(21059)))
        .await
        .expect("exit3: subscribe failed");
    let sub_id = sub_output.value;
    let eose = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(notification) = notifications.next().await {
            if let ClientNotification::Message { message, .. } = notification {
                if let RelayMessage::EndOfStoredEvents(id) = message.as_ref() {
                    if id.as_ref() == &sub_id {
                        return;
                    }
                }
            }
        }
        panic!("notification stream ended before EOSE");
    })
    .await;
    assert!(eose.is_ok(), "exit3: did not receive EOSE within 5s");

    let ephemeral = wrap_event(&writer, 21059);
    let (accepted, message) = publish_with_result(relay.url(), &ephemeral).await;
    assert!(
        accepted,
        "exit3: registered-key 21059 must be accepted; got {message:?}"
    );

    let received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(notification) = notifications.next().await {
            if let ClientNotification::Event { event, .. } = notification {
                if event.kind.as_u16() == 21059 {
                    return *event;
                }
            }
        }
        panic!("notification stream ended before the live 21059 arrived");
    })
    .await
    .expect("exit3: live subscriber must receive the accepted 21059");
    assert_eq!(received.id, ephemeral.id, "exit3: broadcast id must match");
    subscriber.disconnect().await;

    // Never stored.
    let stored = fetch_from(relay.url(), Filter::new().kind(Kind::Custom(21059))).await;
    assert!(
        stored.is_empty(),
        "exit3: 21059 must never be stored; got {} event(s)",
        stored.len()
    );

    // ...and never QUOTA-CHARGED (the invariant `try_handle_wrap(_, true)`
    // exists for — see exit37 for the full rationale: ephemeral wrap bytes
    // have no credit path, so charging them would let a registered write
    // key brick a scope with zero bytes stored). Positive control: a second
    // STORED 1059 published right after must move the ledger by exactly its
    // own size, so this cannot pass vacuously.
    let control = wrap_event(&writer, 1059);
    assert_ne!(control.id, wrap.id, "exit3: the control must be a fresh id");
    let (accepted, message) = publish_with_result(relay.url(), &control).await;
    assert!(
        accepted,
        "exit3: the control 1059 must be accepted; got {message:?}"
    );
    let want = ledger_after_wrap + control.as_json().len() as i64;
    let ledger_after_control = poll_until(want, || global_ledger_bytes(relay.url())).await;
    assert_eq!(
        ledger_after_control,
        want,
        "exit3: the ledger must move by the STORED 1059 only — the ephemeral \
         21059 must never be quota-charged. before={ledger_after_wrap} \
         control_1059_bytes={} ephemeral_21059_bytes={}",
        control.as_json().len(),
        ephemeral.as_json().len()
    );

    // (d) 21059 from an unregistered key also falls through and is vetoed.
    let foreign_eph = wrap_event(&Keys::generate(), 21059);
    let (accepted, message) = publish_with_result(relay.url(), &foreign_eph).await;
    assert!(
        !accepted && message.contains("restricted:"),
        "exit3: foreign-key 21059 must be vetoed; got accepted={accepted} {message:?}"
    );

    // (e) REFERENCED junk: a 1059 from an unregistered key carrying an e-tag
    // that references a STORED event must still be rejected (never the public
    // related-event path). This is what makes deregistered rekey addresses
    // unfloodable between rotations (§3.2: outer author must be registered).
    // It carries exactly one `p` tag: since nostr-sdk 0.45 the relay refuses
    // a 1059 without one before any write policy runs, and this case must
    // reach the private arm to test it.
    let referenced_junk = EventBuilder::new(
        Kind::Custom(1059),
        "AtQyM3BhY2VvcGFxdWUtY2lwaGVydGV4dC1zdGFuZC1pbg==",
    )
    .tags(vec![
        Tag::event(wrap.id),
        Tag::public_key(Keys::generate().public_key()),
    ])
    .finalize(&Keys::generate())
    .expect("sign junk wrap");
    let (accepted, message) = publish_with_result(relay.url(), &referenced_junk).await;
    assert!(
        !accepted && message.contains("restricted:") && message.contains("unregistered key"),
        "exit3: referenced junk from an unregistered key must be rejected; \
         got accepted={accepted} {message:?}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 4 — quota 507 + oversize 413 (preflight and on the PUT)
// ============================================================================

#[tokio::test]
async fn exit4_quota_and_size_caps() {
    // Tiny per-repo quota + small per-blob cap. (repo <= tenant <= global
    // still holds against the defaults.)
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_QUOTA_REPO_BYTES", "4096"),
        ("NGIT_GRASP_P_MAX_BLOB_BYTES", "8192"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    // Blob #1 (2 KiB) fits under the 4 KiB repo quota (minus the ~700-byte
    // registration event charge).
    let blob1 = blob_bytes(41, 2048);
    let sha1 = sha256_hex(&blob1);
    let auth1 = blossom_auth_event(
        &writer,
        "upload",
        &sha1,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, blob1.clone(), &sha1, &auth1).await;
    assert_eq!(
        status, 200,
        "exit4: blob1 must fit the quota; X-Reason: {reason}"
    );

    // Blob #2 (2 KiB) blows the repo quota: 507 at preflight AND on PUT.
    let blob2 = blob_bytes(42, 2048);
    let sha2 = sha256_hex(&blob2);
    let auth2 = blossom_auth_event(
        &writer,
        "upload",
        &sha2,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, reason) = head_upload(&relay, &sha2, blob2.len() as u64, Some(&auth2)).await;
    assert_eq!(
        status, 507,
        "exit4: over-quota preflight must be 507; X-Reason: {reason}"
    );
    let (status, _, reason) = put_blob(&relay, blob2, &sha2, &auth2).await;
    assert_eq!(
        status, 507,
        "exit4: over-quota PUT must be 507; X-Reason: {reason}"
    );
    let (status, _) = get_blob(&relay, &sha2).await;
    assert_eq!(status, 404, "exit4: the 507'd blob must not be stored");

    // Oversize single blob (10000 > 8192):
    let big = blob_bytes(43, 10_000);
    let big_sha = sha256_hex(&big);
    let big_auth = blossom_auth_event(
        &writer,
        "upload",
        &big_sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );

    // (a) truthful preflight → 413;
    let (status, reason) = head_upload(&relay, &big_sha, big.len() as u64, Some(&big_auth)).await;
    assert_eq!(
        status, 413,
        "exit4: truthful oversize preflight must be 413; X-Reason: {reason}"
    );

    // (b) LYING preflight (declares 1000 bytes) → 200 — then the PUT's real
    // Content-Length (10000) trips the cap → 413 and nothing is stored.
    let (status, reason) = head_upload(&relay, &big_sha, 1000, Some(&big_auth)).await;
    assert_eq!(
        status, 200,
        "exit4: lying (small) preflight passes by design; X-Reason: {reason}"
    );
    let (status, _, reason) = put_blob(&relay, big, &big_sha, &big_auth).await;
    assert_eq!(
        status, 413,
        "exit4: oversize PUT after lying preflight must be 413; X-Reason: {reason}"
    );
    let (status, _) = get_blob(&relay, &big_sha).await;
    assert_eq!(status, 404, "exit4: the 413'd blob must not be stored");

    // (c) chunked PUT (no Content-Length at all) → 411, per §7: the header
    // is mandatory, so a body that cannot be preflight-checked is refused
    // before any bytes are consumed.
    let port = relay_port(&relay);
    let domain = relay.domain();
    let small = blob_bytes(44, 512);
    let small_sha = sha256_hex(&small);
    let small_auth = blossom_auth_event(
        &writer,
        "upload",
        &small_sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let chunked = format!(
        "PUT /upload HTTP/1.1\r\nHost: {domain}\r\nAuthorization: {}\r\nX-SHA-256: {small_sha}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
        auth_header_value(&small_auth)
    );
    let response = raw_http_exchange(port, chunked.as_bytes(), false).await;
    assert!(
        response.starts_with("HTTP/1.1 411"),
        "exit4: chunked PUT without Content-Length must be 411; got: {:?}",
        response.lines().next()
    );

    // (d) mid-stream client abort: Content-Length declares 1000 bytes (small
    // enough to clear the remaining repo quota) but the connection half-closes
    // after 300 — the temp file must be discarded and the blob must not
    // appear. (Hyper caps reads at Content-Length, so a body physically LONGER
    // than declared is not producible by any conformant client; the in-sink
    // overrun guard stays defense-in-depth.)
    let short_body = blob_bytes(45, 1000);
    let short_sha = sha256_hex(&short_body);
    let short_auth = blossom_auth_event(
        &writer,
        "upload",
        &short_sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let mut truncated = format!(
        "PUT /upload HTTP/1.1\r\nHost: {domain}\r\nAuthorization: {}\r\nX-SHA-256: {short_sha}\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n",
        auth_header_value(&short_auth)
    )
    .into_bytes();
    truncated.extend_from_slice(&short_body[..300]);
    let response = raw_http_exchange(port, &truncated, true).await;
    assert!(
        response.is_empty() || response.starts_with("HTTP/1.1 4"),
        "exit4: truncated PUT must fail (4xx or dropped conn); got: {:?}",
        response.lines().next()
    );
    let (status, _) = get_blob(&relay, &short_sha).await;
    assert_eq!(
        status, 404,
        "exit4: aborted upload must leave no blob behind"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 5 — Blossom auth failures
// ============================================================================

#[tokio::test]
async fn exit5_blossom_auth_failures() {
    // Alias A: tenant_a + writer_a (w) + aux_a (aux).
    let tenant_a = Keys::generate();
    // Alias B: a different tenant with its own write key.
    let tenant_b = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant_a, &tenant_b]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;

    let writer_a = Keys::generate();
    let aux_a = Keys::generate();
    let alias_a = random_alias();
    let reg_a = registration_event(
        &tenant_a,
        &alias_a,
        &[key_entry(&writer_a, &tenant_a.public_key(), &alias_a)],
        &[key_entry(&aux_a, &tenant_a.public_key(), &alias_a)],
        &relay.domain(),
        None,
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg_a).await;
    assert!(accepted, "exit5: alias A registration failed: {message:?}");

    let writer_b = Keys::generate();
    let alias_b = random_alias();
    register_alias(&relay, &tenant_b, &writer_b, &alias_b).await;

    let data = blob_bytes(50, 700);
    let sha = sha256_hex(&data);
    let len = data.len() as u64;

    // Baseline sanity: a correct auth preflights 200.
    let good = blossom_auth_event(
        &writer_a,
        "upload",
        &sha,
        &tenant_a.public_key(),
        &alias_a,
        future_expiration(),
    );
    let (status, reason) = head_upload(&relay, &sha, len, Some(&good)).await;
    assert_eq!(
        status, 200,
        "exit5 baseline must be 200; X-Reason: {reason}"
    );

    // (a) Missing Authorization header → 401.
    let (status, _) = head_upload(&relay, &sha, len, None).await;
    assert_eq!(status, 401, "exit5: missing auth must be 401");

    // (b) Bad signature → 401: tamper with the signed event's content so the
    // id/sig no longer verify.
    let tampered_json = good.as_json().replace("grasp-p test auth", "tampered!!");
    assert_ne!(tampered_json, good.as_json(), "tamper must change the JSON");
    let tampered = Event::from_json(&tampered_json).expect("tampered JSON still parses");
    let (status, reason) = head_upload(&relay, &sha, len, Some(&tampered)).await;
    assert_eq!(
        status, 401,
        "exit5: bad sig must be 401; X-Reason: {reason}"
    );

    // (c) Expired → 401: expiration tag in the past.
    let expired = blossom_auth_event(
        &writer_a,
        "upload",
        &sha,
        &tenant_a.public_key(),
        &alias_a,
        Timestamp::now().as_secs() - 60,
    );
    let (status, reason) = head_upload(&relay, &sha, len, Some(&expired)).await;
    assert_eq!(
        status, 401,
        "exit5: expired auth must be 401; X-Reason: {reason}"
    );

    // (d) Wrong-alias key → 403: writer_b signs an auth attributed to alias A.
    let wrong_key = blossom_auth_event(
        &writer_b,
        "upload",
        &sha,
        &tenant_a.public_key(),
        &alias_a,
        future_expiration(),
    );
    let (status, reason) = head_upload(&relay, &sha, len, Some(&wrong_key)).await;
    assert_eq!(
        status, 403,
        "exit5: foreign w key must be 403; X-Reason: {reason}"
    );

    // (e) Aux keys cannot PUT → 403 (read-side publish keys only).
    let aux_auth = blossom_auth_event(
        &aux_a,
        "upload",
        &sha,
        &tenant_a.public_key(),
        &alias_a,
        future_expiration(),
    );
    let (status, reason) = head_upload(&relay, &sha, len, Some(&aux_auth)).await;
    assert_eq!(
        status, 403,
        "exit5: aux key upload must be 403; X-Reason: {reason}"
    );

    // (f) x-tag mismatch → 400: auth commits to a different sha than the
    // operation targets.
    let other_sha = sha256_hex(&blob_bytes(51, 700));
    let mismatched = blossom_auth_event(
        &writer_a,
        "upload",
        &other_sha,
        &tenant_a.public_key(),
        &alias_a,
        future_expiration(),
    );
    let (status, reason) = head_upload(&relay, &sha, len, Some(&mismatched)).await;
    assert_eq!(
        status, 400,
        "exit5: x mismatch must be 400; X-Reason: {reason}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 6 — whitelist and pow registration modes
// ============================================================================

#[tokio::test]
async fn exit6_whitelist_and_pow_modes() {
    // --- whitelist mode -----------------------------------------------------
    let listed = Keys::generate();
    let listed_npub = listed.public_key().to_bech32().expect("npub");
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_REGISTRATION_MODE", "whitelist"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", listed_npub.as_str()),
    ])
    .await;

    let outsider = Keys::generate();
    let outsider_writer = Keys::generate();
    let outsider_alias = random_alias();
    let reg = registration_event(
        &outsider,
        &outsider_alias,
        &[key_entry(
            &outsider_writer,
            &outsider.public_key(),
            &outsider_alias,
        )],
        &[],
        &relay.domain(),
        None,
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg).await;
    assert!(!accepted, "exit6: non-listed tenant must be rejected");
    assert!(
        message.contains("restricted:") && message.contains("whitelist"),
        "exit6: whitelist rejection message; got {message:?}"
    );

    let listed_writer = Keys::generate();
    let listed_alias = random_alias();
    let reg = registration_event(
        &listed,
        &listed_alias,
        &[key_entry(
            &listed_writer,
            &listed.public_key(),
            &listed_alias,
        )],
        &[],
        &relay.domain(),
        None,
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg).await;
    assert!(
        accepted,
        "exit6: whitelisted tenant must be accepted; got {message:?}"
    );
    relay.stop().await;

    // --- pow mode (8 bits for test speed) -----------------------------------
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_REGISTRATION_MODE", "pow"),
        ("NGIT_GRASP_P_POW_BITS", "8"),
    ])
    .await;
    let tenant = Keys::generate();
    let writer = Keys::generate();

    // Unmined registration: overwhelmingly likely to lack 8 leading zero
    // bits; regenerate in the (1/256) fluke case where it accidentally has
    // them.
    let low_pow = loop {
        let candidate_alias = random_alias();
        let candidate = registration_event(
            &tenant,
            &candidate_alias,
            &[key_entry(&writer, &tenant.public_key(), &candidate_alias)],
            &[],
            &relay.domain(),
            None,
        );
        if !candidate.id.check_pow(8) {
            break candidate;
        }
    };
    let (accepted, message) = publish_with_result(relay.url(), &low_pow).await;
    assert!(!accepted, "exit6: low-pow registration must be rejected");
    assert!(
        message.contains("restricted:") && message.contains("proof of work"),
        "exit6: pow rejection message; got {message:?}"
    );

    // Mined registration (NIP-13 nonce tag) with ≥8 bits.
    let alias = random_alias();
    let unsigned = EventBuilder::new(Kind::Custom(30640), "")
        .tags(registration_tags(
            &alias,
            &[key_entry(&writer, &tenant.public_key(), &alias)],
            &[],
            &relay.domain(),
        ))
        .finalize_unsigned(tenant.public_key());
    let mined = unsigned
        .mine(&SingleThreadPow, NonZeroU8::new(8).expect("nonzero"))
        .expect("mining 8 bits cannot fail");
    let mined_event = SignEvent::sign_event(&tenant, mined).expect("sign mined event");
    assert!(mined_event.id.check_pow(8), "mined event must carry 8 bits");
    let (accepted, message) = publish_with_result(relay.url(), &mined_event).await;
    assert!(
        accepted,
        "exit6: sufficient-pow registration must be accepted; got {message:?}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 7 — write-key/alias conflicts + rotation frees keys
// ============================================================================

#[tokio::test]
async fn exit7_key_conflicts_and_rotation() {
    let tenant1 = Keys::generate();
    let tenant2 = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant1, &tenant2]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let domain = relay.domain();

    let key_old = Keys::generate();
    let key_new = Keys::generate();
    let key_other = Keys::generate();
    let alias1 = random_alias();
    let alias2 = random_alias();

    let t0 = Timestamp::now().as_secs();

    // tenant1 registers alias1 with w={key_old, key_new}.
    let reg1 = registration_event(
        &tenant1,
        &alias1,
        &[
            key_entry(&key_old, &tenant1.public_key(), &alias1),
            key_entry(&key_new, &tenant1.public_key(), &alias1),
        ],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg1).await;
    assert!(accepted, "exit7: initial registration failed: {message:?}");

    // (a) tenant2 claiming key_old under a different alias → rejected even
    // with a valid proof-of-possession (first-registrant-wins conflict).
    let steal_key = registration_event(
        &tenant2,
        &alias2,
        &[key_entry(&key_old, &tenant2.public_key(), &alias2)],
        &[],
        &domain,
        Some(t0 + 1),
    );
    let (accepted, message) = publish_with_result(relay.url(), &steal_key).await;
    assert!(!accepted, "exit7: cross-tenant key claim must be rejected");
    assert!(
        message.contains("restricted:") && message.contains("write key already registered"),
        "exit7: key-conflict message; got {message:?}"
    );

    // (a2) Claiming a key WITHOUT proof-of-possession → rejected (squatting
    // someone's known pubkey must be impossible).
    let squat_alias = random_alias();
    let squat = registration_event(
        &tenant2,
        &squat_alias,
        &[vec![Keys::generate().public_key().to_hex()]],
        &[],
        &domain,
        Some(t0 + 1),
    );
    let (accepted, message) = publish_with_result(relay.url(), &squat).await;
    assert!(!accepted, "exit7: PoP-less key claim must be rejected");
    assert!(
        message.contains("invalid:") && message.contains("proof-of-possession"),
        "exit7: proof-of-possession message; got {message:?}"
    );

    // (a3) A proof-of-possession from ANOTHER (tenant, alias) context must
    // not be replayable: key_other signs for (tenant1, alias1) but tenant2
    // claims it for alias2.
    let replayed_pop = registration_event(
        &tenant2,
        &alias2,
        &[vec![
            key_other.public_key().to_hex(),
            key_pop_sig(&key_other, &tenant1.public_key(), &alias1),
        ]],
        &[],
        &domain,
        Some(t0 + 1),
    );
    let (accepted, message) = publish_with_result(relay.url(), &replayed_pop).await;
    assert!(!accepted, "exit7: replayed PoP must be rejected");
    assert!(
        message.contains("invalid:") && message.contains("proof-of-possession"),
        "exit7: replayed-PoP message; got {message:?}"
    );

    // (b) tenant2 claiming alias1 itself → rejected.
    let steal_alias = registration_event(
        &tenant2,
        &alias1,
        &[key_entry(&key_other, &tenant2.public_key(), &alias1)],
        &[],
        &domain,
        Some(t0 + 2),
    );
    let (accepted, message) = publish_with_result(relay.url(), &steal_alias).await;
    assert!(
        !accepted,
        "exit7: cross-tenant alias claim must be rejected"
    );
    assert!(
        message.contains("restricted:") && message.contains("alias already registered"),
        "exit7: alias-conflict message; got {message:?}"
    );

    // (c) Rotation by tenant1: w={key_old,key_new} → w={key_new} (strictly
    // newer edition). Always allowed; frees key_old.
    let rotation = registration_event(
        &tenant1,
        &alias1,
        &[key_entry(&key_new, &tenant1.public_key(), &alias1)],
        &[],
        &domain,
        Some(t0 + 5),
    );
    let (accepted, message) = publish_with_result(relay.url(), &rotation).await;
    assert!(
        accepted,
        "exit7: rotation must be accepted; got {message:?}"
    );

    // (d) key_old is now free: tenant2 can claim it for alias2.
    let reclaim = registration_event(
        &tenant2,
        &alias2,
        &[key_entry(&key_old, &tenant2.public_key(), &alias2)],
        &[],
        &domain,
        Some(t0 + 6),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reclaim).await;
    assert!(
        accepted,
        "exit7: released key must be claimable by another tenant; got {message:?}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 8 — NIP-09 deletion of the 30640 kills 30641/1059 admission
// ============================================================================

#[tokio::test]
async fn exit8_registration_deletion_liveness() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    // Pre-deletion sanity: a 30641 and a 1059 are both admitted.
    let t0 = Timestamp::now().as_secs();
    let sha = sha256_hex(&blob_bytes(80, 256));
    let state = state_root_event(&writer, &tenant.public_key(), &alias, (&sha, 256), &[], t0);
    let (accepted, message) = publish_with_result(relay.url(), &state).await;
    assert!(accepted, "exit8: pre-deletion 30641 failed: {message:?}");
    let wrap = wrap_event(&writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(accepted, "exit8: pre-deletion 1059 failed: {message:?}");

    // NIP-09 kind-5 deletion by the tenant, targeting the 30640 coordinate.
    let deletion = EventBuilder::new(Kind::EventDeletion, "offboarding")
        .tags(vec![
            Tag::custom("a", vec![reg_coord(&tenant.public_key(), &alias)]),
            Tag::custom("k", vec!["30640".to_string()]),
        ])
        .finalize(&tenant)
        .expect("sign kind-5");
    let (accepted, message) = publish_with_result(relay.url(), &deletion).await;
    assert!(accepted, "exit8: kind-5 deletion rejected: {message:?}");

    // Wait until the deletion has actually been actioned (the 30640 stops
    // being served) — NGIT_TEST=1 gives fast lifecycle timers.
    let mut deleted = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let remaining = fetch_from(
            relay.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(tenant.public_key())
                .identifier(&alias),
        )
        .await;
        if remaining.is_empty() {
            deleted = true;
            break;
        }
    }
    assert!(
        deleted,
        "exit8: 30640 still served 10s after NIP-09 deletion"
    );

    // A new 30641 edition is now rejected by the liveness check.
    let state2 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha, 256),
        &[],
        t0 + 10,
    );
    let (accepted, message) = publish_with_result(relay.url(), &state2).await;
    assert!(!accepted, "exit8: post-deletion 30641 must be rejected");
    assert!(
        message.contains("restricted:") && message.contains("unregistered alias"),
        "exit8: 30641 liveness rejection; got {message:?}"
    );

    // Wraps from the (now dead) registered key are rejected too.
    let wrap2 = wrap_event(&writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap2).await;
    assert!(!accepted, "exit8: post-deletion 1059 must be rejected");
    assert!(
        message.contains("restricted:") && message.contains("unregistered key"),
        "exit8: wrap liveness rejection; got {message:?}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 9 — NIP-09 deletion of a 30640 FREES its key claims
// ============================================================================
// cord-git !13 verify-round: claims were freed only by a newer edition from
// the same tenant, so a kind-5'd registration left them dangling forever —
// a member could squat derivable rekey addresses, delete their registration,
// and permanently wedge every rotation whose widen lists those keys.

#[tokio::test]
async fn exit9_registration_deletion_frees_key_claims() {
    let squatter = Keys::generate();
    let owner = Keys::generate();
    let whitelist = whitelist_npubs(&[&squatter, &owner]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let squat_key = Keys::generate();
    let owner_writer = Keys::generate();
    let domain = relay.domain();

    // The squatter claims `squat_key` as aux under their own alias (valid
    // PoP — the squat threat model: rekey addresses are derivable keys).
    let squat_alias = random_alias();
    let t0 = Timestamp::now().as_secs();
    let squat = registration_event(
        &squatter,
        &squat_alias,
        &[key_entry(
            &Keys::generate(),
            &squatter.public_key(),
            &squat_alias,
        )],
        &[key_entry(&squat_key, &squatter.public_key(), &squat_alias)],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &squat).await;
    assert!(accepted, "exit9: squat registration failed: {message:?}");

    // While the squat holds, the owner's registration listing the same key
    // is rejected (first-registrant-wins conflict).
    let owner_alias = random_alias();
    let widen = registration_event(
        &owner,
        &owner_alias,
        &[key_entry(&owner_writer, &owner.public_key(), &owner_alias)],
        &[key_entry(&squat_key, &owner.public_key(), &owner_alias)],
        &domain,
        Some(t0 + 1),
    );
    let (accepted, message) = publish_with_result(relay.url(), &widen).await;
    assert!(
        !accepted,
        "exit9: registration listing the squatted key must be rejected"
    );
    assert!(
        message.contains("write key already registered"),
        "exit9: key-conflict message; got {message:?}"
    );

    // The squatter kind-5 deletes their registration's coordinate.
    let deletion = EventBuilder::new(Kind::EventDeletion, "withdrawing the squat")
        .tags(vec![
            Tag::custom("a", vec![reg_coord(&squatter.public_key(), &squat_alias)]),
            Tag::custom("k", vec!["30640".to_string()]),
        ])
        .finalize(&squatter)
        .expect("sign kind-5");
    let (accepted, message) = publish_with_result(relay.url(), &deletion).await;
    assert!(accepted, "exit9: kind-5 deletion rejected: {message:?}");

    // The squatted key is now FREE: the owner's registration listing it is
    // accepted — no dangling "write key already registered" wedge.
    let widen2 = registration_event(
        &owner,
        &owner_alias,
        &[key_entry(&owner_writer, &owner.public_key(), &owner_alias)],
        &[key_entry(&squat_key, &owner.public_key(), &owner_alias)],
        &domain,
        Some(t0 + 2),
    );
    let (accepted, message) = publish_with_result(relay.url(), &widen2).await;
    assert!(
        accepted,
        "exit9: key claims must be freed with the deleted registration; got {message:?}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 10 — claim-freeing honors the NIP-09 created_at cutoff + e-tags
// ============================================================================

#[tokio::test]
async fn exit10_claim_freeing_cutoff_and_etags() {
    let tenant = Keys::generate();
    let other = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant, &other]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let w1 = Keys::generate();
    let w2 = Keys::generate();
    let alias = random_alias();
    let domain = relay.domain();
    let t0 = Timestamp::now().as_secs();

    // Register edition 1, then kind-5 (created_at t0+1) targeting the
    // coordinate, then RE-register edition 2 (t0+2) with NEW keys.
    let reg1 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&w1, &tenant.public_key(), &alias)],
        &[],
        &domain,
        Some(t0),
    );
    publish_with_result(relay.url(), &reg1).await;
    let stale_deletion = EventBuilder::new(Kind::EventDeletion, "stale")
        .tags(vec![
            Tag::custom("a", vec![reg_coord(&tenant.public_key(), &alias)]),
            Tag::custom("k", vec!["30640".to_string()]),
        ])
        .custom_created_at(Timestamp::from_secs(t0 + 1))
        .finalize(&tenant)
        .expect("sign kind-5");
    let reg2 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&w2, &tenant.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 2),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg2).await;
    assert!(accepted, "exit10: re-registration failed: {message:?}");

    // The STALE deletion (created before edition 2) must NOT free edition 2's
    // claims: edition 2 stays the served latest AND its keys stay claimed —
    // another tenant still cannot grab them.
    let (accepted, message) = publish_with_result(relay.url(), &stale_deletion).await;
    assert!(accepted, "exit10: stale kind-5 rejected: {message:?}");
    let grab_alias1 = random_alias();
    let grab = registration_event(
        &other,
        &grab_alias1,
        &[key_entry(&w2, &other.public_key(), &grab_alias1)],
        &[],
        &domain,
        Some(t0 + 3),
    );
    let (accepted, message) = publish_with_result(relay.url(), &grab).await;
    assert!(
        !accepted && message.contains("write key already registered"),
        "exit10: a newer edition's claims must survive a stale deletion; got {message:?}"
    );

    // e-tag deletion of the CURRENT edition frees its claims (the author
    // knows their own event id; this is the same wedge vector as the a-tag).
    let etag_deletion = EventBuilder::new(Kind::EventDeletion, "by id")
        .tags(vec![
            Tag::event(reg2.id),
            Tag::custom("k", vec!["30640".to_string()]),
        ])
        .custom_created_at(Timestamp::from_secs(t0 + 4))
        .finalize(&tenant)
        .expect("sign kind-5");
    let (accepted, message) = publish_with_result(relay.url(), &etag_deletion).await;
    assert!(accepted, "exit10: e-tag kind-5 rejected: {message:?}");
    let grab_alias2 = random_alias();
    let grab2 = registration_event(
        &other,
        &grab_alias2,
        &[key_entry(&w2, &other.public_key(), &grab_alias2)],
        &[],
        &domain,
        Some(t0 + 5),
    );
    let (accepted, message) = publish_with_result(relay.url(), &grab2).await;
    assert!(
        accepted,
        "exit10: e-tag deletion of the current edition must free its claims; got {message:?}"
    );

    // A FOREIGN author cannot free claims with a deletion naming the
    // coordinate: register once more, then a stranger "deletes" it.
    let reg3 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&w2, &tenant.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 6),
    );
    publish_with_result(relay.url(), &reg3).await;
    let foreign = EventBuilder::new(Kind::EventDeletion, "malicious")
        .tags(vec![
            Tag::custom("a", vec![reg_coord(&tenant.public_key(), &alias)]),
            Tag::custom("k", vec!["30640".to_string()]),
        ])
        .custom_created_at(Timestamp::from_secs(t0 + 7))
        .finalize(&other)
        .expect("sign foreign kind-5");
    let _ = publish_with_result(relay.url(), &foreign).await;
    let grab_alias3 = random_alias();
    let grab3 = registration_event(
        &other,
        &grab_alias3,
        &[key_entry(&w2, &other.public_key(), &grab_alias3)],
        &[],
        &domain,
        Some(t0 + 8),
    );
    let (accepted, _message) = publish_with_result(relay.url(), &grab3).await;
    assert!(
        !accepted,
        "exit10: a foreign deletion must never free the tenant's claims"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 11 — §3.2 deterministic registration conflict merge (issue !11)
// ============================================================================

/// Cross-tenant conflicts must resolve by (created_at, id) — lowest wins —
/// never by arrival order: an earlier-created registration arriving second
/// takes the alias, the stored loser is evicted (claims freed, coordinate
/// pruned from the relay DB), the conflict alert fires, and a later-created
/// challenger keeps losing no matter when it arrives.
#[tokio::test]
async fn exit11_registration_conflict_merge() {
    let late_tenant = Keys::generate();
    let early_tenant = Keys::generate();
    let third = Keys::generate();
    let whitelist = whitelist_npubs(&[&late_tenant, &early_tenant, &third]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let domain = relay.domain();

    let late_writer = Keys::generate();
    let early_writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs() - 600;

    // (a) The LATER-created registration arrives first and is accepted.
    let late_reg = registration_event(
        &late_tenant,
        &alias,
        &[key_entry(&late_writer, &late_tenant.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 100),
    );
    let (accepted, message) = publish_with_result(relay.url(), &late_reg).await;
    assert!(
        accepted,
        "exit11: first-arriving registration failed: {message:?}"
    );

    // (b) The EARLIER-created registration arrives second and must WIN the
    // deterministic merge (pre-!11 it was rejected as "alias already
    // registered" — first-arrival-wins split-brain).
    let early_reg = registration_event(
        &early_tenant,
        &alias,
        &[key_entry(&early_writer, &early_tenant.public_key(), &alias)],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &early_reg).await;
    assert!(
        accepted,
        "exit11: the earlier-created registration must win the merge; got {message:?}"
    );

    // (c) REQ resolves ONLY the winner: the loser's coordinate is pruned.
    let mut winner_only = false;
    for _ in 0..50 {
        let events = fetch_from(
            relay.url(),
            Filter::new().kind(Kind::Custom(30640)).identifier(&alias),
        )
        .await;
        if events.len() == 1 && events[0].id == early_reg.id {
            winner_only = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        winner_only,
        "exit11: REQ must resolve exactly the merge winner (loser pruned)"
    );

    // (d) The loser's writer key is DEAD for the alias: its wraps are
    // rejected outright (claims were freed with the eviction).
    let wrap = wrap_event(&late_writer, 1059);
    let (accepted, _message) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        !accepted,
        "exit11: the evicted loser's writer key must not admit wraps"
    );

    // (e) …and freed means reusable: a third tenant claims the loser's
    // writer key under a fresh alias with a fresh proof-of-possession.
    let alias2 = random_alias();
    let reclaim = registration_event(
        &third,
        &alias2,
        &[key_entry(&late_writer, &third.public_key(), &alias2)],
        &[],
        &domain,
        Some(t0 + 200),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reclaim).await;
    assert!(
        accepted,
        "exit11: the evicted loser's key must be claimable again; got {message:?}"
    );

    // (f) A later-created challenger still loses to the winner, whenever it
    // arrives.
    let challenger = Keys::generate();
    let challenge = registration_event(
        &challenger,
        &alias,
        &[key_entry(
            &Keys::generate(),
            &challenger.public_key(),
            &alias,
        )],
        &[],
        &domain,
        Some(t0 + 300),
    );
    let (accepted, message) = publish_with_result(relay.url(), &challenge).await;
    assert!(
        !accepted,
        "exit11: a later-created registration must keep losing"
    );
    assert!(
        message.contains("alias already registered"),
        "exit11: conflict-loss message; got {message:?}"
    );

    // (g) The conflict alert fired for both resolutions.
    let metrics = common::sync_helpers::ParsedMetrics::parse(
        &common::sync_helpers::fetch_metrics(relay.url())
            .await
            .expect("metrics scrape"),
    );
    assert!(
        metrics
            .counter(
                "ngit_private_registration_conflicts_total",
                &[("resolution", "stored_evicted")],
            )
            .unwrap_or(0)
            >= 1,
        "exit11: stored_evicted conflict alert must fire"
    );
    assert!(
        metrics
            .counter(
                "ngit_private_registration_conflicts_total",
                &[("resolution", "incoming_rejected")],
            )
            .unwrap_or(0)
            >= 1,
        "exit11: incoming_rejected conflict alert must fire"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 13 — merge winner is exempt from node-local quota (issue !11)
// ============================================================================

/// The quota ledger is node-local state, so it must not be able to flip the
/// deterministic merge: a squatter who saturates the shared r:<alias> scope
/// (wraps up to the repo cap) must not get the genuine earlier registration
/// rejected with "quota exceeded" on this node while it wins on the peer.
/// A conflict-merge winner is admitted past the quota CHECK (still charged).
#[tokio::test]
async fn exit13_conflict_winner_exempt_from_node_local_quota() {
    let squatter = Keys::generate();
    let victim = Keys::generate();
    let whitelist = whitelist_npubs(&[&squatter, &victim]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_QUOTA_REPO_BYTES", "4096"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let domain = relay.domain();

    let squat_writer = Keys::generate();
    let victim_writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs() - 600;

    // Squatter takes the alias (later created_at) and saturates the shared
    // r:<alias> quota scope with wraps until one is refused.
    let squat = registration_event(
        &squatter,
        &alias,
        &[key_entry(&squat_writer, &squatter.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 100),
    );
    let (accepted, message) = publish_with_result(relay.url(), &squat).await;
    assert!(
        accepted,
        "exit13: squatter registration failed: {message:?}"
    );

    let mut saturated = false;
    for _ in 0..24 {
        let wrap = wrap_event(&squat_writer, 1059);
        let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
        if !accepted {
            assert!(
                message.contains("quota exceeded"),
                "exit13: expected quota refusal while saturating; got {message:?}"
            );
            saturated = true;
            break;
        }
    }
    assert!(
        saturated,
        "exit13: alias quota must saturate within the loop"
    );

    // The genuine earlier registration must STILL win the merge here —
    // pre-!11-fix this came back "restricted: quota exceeded" and the node
    // would permanently disagree with its unsaturated peer.
    let genuine = registration_event(
        &victim,
        &alias,
        &[key_entry(&victim_writer, &victim.public_key(), &alias)],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &genuine).await;
    assert!(
        accepted,
        "exit13: the merge winner must be exempt from node-local quota; got {message:?}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 12 — speculative 30641 blob claims are charged + GC'd (issue !12)
// ============================================================================

/// A 30641 declaring never-uploaded blobs must charge the declared bytes to
/// the declaring (tenant, alias) — speculative claims can no longer grow the
/// meta store unbilled — and the charge must be released when the claim dies
/// (edition superseded → ring trim → GC). Over-quota speculation is rejected
/// up front.
#[tokio::test]
async fn exit12_speculative_blob_claims_charged_and_released() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        // One retained edition + immediate GC so a superseded edition's
        // speculative claim is collectable within the test bound.
        ("NGIT_GRASP_P_STATE_HISTORY_EDITIONS", "1"),
        ("NGIT_GRASP_P_GC_GRACE_SECS", "0"),
        ("NGIT_GRASP_P_GC_INTERVAL_SECS", "1"),
        ("NGIT_GRASP_P_QUOTA_REPO_BYTES", "16384"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;

    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    let global_ledger = || async {
        common::sync_helpers::ParsedMetrics::parse(
            &common::sync_helpers::fetch_metrics(relay.url())
                .await
                .expect("metrics scrape"),
        )
        .gauge("ngit_private_ledger_bytes", &[("scope", "global")])
        .unwrap_or(-1)
    };
    let g0 = global_ledger().await;
    assert!(g0 > 0, "exit12: registration must already be on the ledger");

    // (a) v1 declares a never-uploaded 4096-byte manifest blob: accepted,
    // and the declared bytes are charged (speculative claim).
    let t0 = Timestamp::now().as_secs();
    let fake_sha = sha256_hex(&blob_bytes(91, 64));
    let v1 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&fake_sha, 4096),
        &[],
        t0,
    );
    let (accepted, message) = publish_with_result(relay.url(), &v1).await;
    assert!(accepted, "exit12: v1 must be accepted; got {message:?}");
    let v1_bytes = v1.as_json().len() as i64;

    let mut g1 = -1;
    for _ in 0..50 {
        g1 = global_ledger().await;
        if g1 == g0 + v1_bytes + 4096 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        g1,
        g0 + v1_bytes + 4096,
        "exit12: declared-but-unstored bytes must be charged speculatively"
    );

    // (b) Speculation cannot exceed quota: an edition declaring more bytes
    // than the repo has left is rejected outright.
    let big_sha = sha256_hex(&blob_bytes(92, 64));
    let over = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&big_sha, 12_000),
        &[],
        t0 + 1,
    );
    let (accepted, message) = publish_with_result(relay.url(), &over).await;
    assert!(
        !accepted && message.contains("quota exceeded"),
        "exit12: over-quota speculation must be rejected; got {message:?}"
    );

    // (c) v2 supersedes v1 (ring keeps 1 edition): v1's fake ref loses its
    // alias, GC (grace 0) deletes the claim and refunds the 4096.
    let sha2 = sha256_hex(&blob_bytes(93, 64));
    let v2 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha2, 100),
        &[],
        t0 + 2,
    );
    let (accepted, message) = publish_with_result(relay.url(), &v2).await;
    assert!(accepted, "exit12: v2 must be accepted; got {message:?}");
    let v2_bytes = v2.as_json().len() as i64;

    let expected = g0 + v1_bytes + v2_bytes + 100;
    let mut g2 = -1;
    for _ in 0..100 {
        g2 = global_ledger().await;
        if g2 == expected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        g2, expected,
        "exit12: the superseded edition's speculative charge must be GC-refunded \
         (v2's own 100-byte speculation stays charged)"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 14 — rotation does not decay §3.2 conflict priority (verify FA)
// ============================================================================

/// FA: a seat's conflict priority is anchored to the FIRST registration
/// edition, not the latest. Victim registers at t0; the squatter's t1
/// registration (t0 < t1) loses; the victim then ROTATES (t2 > t1) and the
/// squatter re-publishes the SAME t1 event — it must still lose. Pre-FA the
/// rotation overwrote the stored created_at, the re-published squatter event
/// won the merge, and the victim was evicted from its own alias.
#[tokio::test]
async fn exit14_rotation_preserves_conflict_anchor() {
    let victim = Keys::generate();
    let squatter = Keys::generate();
    let whitelist = whitelist_npubs(&[&victim, &squatter]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let domain = relay.domain();

    let victim_w1 = Keys::generate();
    let victim_w2 = Keys::generate();
    let squat_writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs() - 600;

    // Victim registers edition 1 at t0.
    let reg1 = registration_event(
        &victim,
        &alias,
        &[key_entry(&victim_w1, &victim.public_key(), &alias)],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg1).await;
    assert!(accepted, "exit14: victim registration failed: {message:?}");

    // The squatter's t1 registration loses (t0 < t1) and is rejected.
    let squat = registration_event(
        &squatter,
        &alias,
        &[key_entry(&squat_writer, &squatter.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 100),
    );
    let (accepted, _) = publish_with_result(relay.url(), &squat).await;
    assert!(
        !accepted,
        "exit14: the later squatter registration must lose"
    );

    // The victim rotates at t2 = t0+200 (new writer key, strictly newer).
    let reg2 = registration_event(
        &victim,
        &alias,
        &[key_entry(&victim_w2, &victim.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 200),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg2).await;
    assert!(accepted, "exit14: rotation failed: {message:?}");

    // The squatter re-publishes the SAME t1 event: must STILL lose — pre-FA
    // this won the merge and evicted the victim (scenario A).
    let (accepted, message) = publish_with_result(relay.url(), &squat).await;
    assert!(
        !accepted,
        "exit14: re-published squatter must keep losing after the rotation"
    );
    assert!(
        message.contains("alias already registered"),
        "exit14: conflict-loss message; got {message:?}"
    );

    // The victim keeps the seat: its rotation is still the served 30640…
    let served = fetch_from(
        relay.url(),
        Filter::new().kind(Kind::Custom(30640)).identifier(&alias),
    )
    .await;
    assert_eq!(
        served.len(),
        1,
        "exit14: exactly the victim's edition served"
    );
    assert_eq!(
        served[0].id, reg2.id,
        "exit14: the victim's rotation stays live"
    );

    // …and the seat is fully functional: 30641 + 1059 still accepted.
    let sha = sha256_hex(&blob_bytes(61, 256));
    let state = state_root_event(
        &victim_w2,
        &victim.public_key(),
        &alias,
        (&sha, 256),
        &[],
        t0 + 300,
    );
    let (accepted, message) = publish_with_result(relay.url(), &state).await;
    assert!(
        accepted,
        "exit14: post-attack 30641 must be accepted; got {message:?}"
    );
    let wrap = wrap_event(&victim_w2, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        accepted,
        "exit14: post-attack 1059 must be accepted; got {message:?}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 15 — same-second cross-tenant tie breaks by event id (Lens-4 F4)
// ============================================================================

/// Two tenants publish conflicting registrations with EQUAL created_at: the
/// lowest event id must win on every node, regardless of publish order.
#[tokio::test]
async fn exit15_same_second_conflict_tie_breaks_by_event_id() {
    let tenant_a = Keys::generate();
    let tenant_b = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant_a, &tenant_b]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let domain = relay.domain();
    let t0 = Timestamp::now().as_secs() - 600;

    let mk = |tenant: &Keys, alias: &str| {
        let writer = Keys::generate();
        registration_event(
            tenant,
            alias,
            &[key_entry(&writer, &tenant.public_key(), alias)],
            &[],
            &domain,
            Some(t0),
        )
    };
    let split = |x: Event, y: Event| {
        assert_ne!(x.id, y.id);
        if x.id.to_hex() < y.id.to_hex() {
            (y, x) // (loser, winner)
        } else {
            (x, y)
        }
    };

    // Order 1: the higher-id registration arrives FIRST (accepted), the
    // lower-id one second — the lower-id one must win the tie and evict the
    // first arrival.
    let alias1 = random_alias();
    let (loser1, winner1) = split(mk(&tenant_a, &alias1), mk(&tenant_b, &alias1));
    let (accepted, message) = publish_with_result(relay.url(), &loser1).await;
    assert!(
        accepted,
        "exit15: first arrival must be accepted: {message:?}"
    );
    let (accepted, message) = publish_with_result(relay.url(), &winner1).await;
    assert!(
        accepted,
        "exit15: equal-created_at lower-id registration must win: {message:?}"
    );
    let mut converged = false;
    for _ in 0..50 {
        let events = fetch_from(
            relay.url(),
            Filter::new().kind(Kind::Custom(30640)).identifier(&alias1),
        )
        .await;
        if events.len() == 1 && events[0].id == winner1.id {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        converged,
        "exit15: REQ must resolve exactly the lower-id winner (loser pruned)"
    );

    // Order 2 (reverse): the lower-id winner arrives first, the loser second
    // — the loser is rejected outright. Same winner either way.
    let alias2 = random_alias();
    let (loser2, winner2) = split(mk(&tenant_a, &alias2), mk(&tenant_b, &alias2));
    let (accepted, message) = publish_with_result(relay.url(), &winner2).await;
    assert!(
        accepted,
        "exit15: winner-first must be accepted: {message:?}"
    );
    let (accepted, message) = publish_with_result(relay.url(), &loser2).await;
    assert!(
        !accepted && message.contains("alias already registered"),
        "exit15: equal-created_at higher-id registration must lose; got {message:?}"
    );
    let served = fetch_from(
        relay.url(),
        Filter::new().kind(Kind::Custom(30640)).identifier(&alias2),
    )
    .await;
    assert_eq!(served.len(), 1);
    assert_eq!(
        served[0].id, winner2.id,
        "exit15: same winner in both orders"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 16 — merge winner is exempt from the alias limit (verify FB)
// ============================================================================

/// FB: the per-tenant alias limit is node-local OCCUPANCY state and must not
/// flip the deterministic merge. The winner's tenant is AT
/// `max_aliases_per_tenant`; its earlier-created conflicting registration
/// must still win (the alias is recorded — overshoot by exactly one), the
/// squatter is evicted, and a FRESH non-conflict alias past the limit keeps
/// being rejected (the anti-sybil limit itself is intact).
#[tokio::test]
async fn exit16_conflict_winner_exempt_from_alias_limit() {
    let squatter = Keys::generate();
    let winner = Keys::generate();
    let whitelist = whitelist_npubs(&[&squatter, &winner]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_MAX_ALIASES_PER_TENANT", "1"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let domain = relay.domain();
    let t0 = Timestamp::now().as_secs() - 600;

    let squat_writer = Keys::generate();
    // Key claims are one-alias-per-key: each of the winner's aliases needs
    // its OWN writer key (sharing one would make the contested registration
    // evict the filler alias on a key conflict instead of testing the limit).
    let filler_writer = Keys::generate();
    let contested_writer = Keys::generate();
    let contested = random_alias();

    // The squatter holds the contested alias (later created_at).
    let squat = registration_event(
        &squatter,
        &contested,
        &[key_entry(&squat_writer, &squatter.public_key(), &contested)],
        &[],
        &domain,
        Some(t0 + 100),
    );
    let (accepted, message) = publish_with_result(relay.url(), &squat).await;
    assert!(
        accepted,
        "exit16: squatter registration failed: {message:?}"
    );

    // The winner is AT the limit with an unrelated alias.
    let filler = random_alias();
    let filler_reg = registration_event(
        &winner,
        &filler,
        &[key_entry(&filler_writer, &winner.public_key(), &filler)],
        &[],
        &domain,
        Some(t0 + 50),
    );
    let (accepted, message) = publish_with_result(relay.url(), &filler_reg).await;
    assert!(accepted, "exit16: filler registration failed: {message:?}");

    // A FRESH alias past the limit is still rejected (limit intact).
    let over = random_alias();
    let over_writer = Keys::generate();
    let over_reg = registration_event(
        &winner,
        &over,
        &[key_entry(&over_writer, &winner.public_key(), &over)],
        &[],
        &domain,
        Some(t0 + 60),
    );
    let (accepted, message) = publish_with_result(relay.url(), &over_reg).await;
    assert!(
        !accepted && message.contains("alias limit"),
        "exit16: a fresh non-conflict alias past the limit must be rejected; got {message:?}"
    );

    // The winner's EARLIER-created registration for the contested alias must
    // STILL win the merge — exempt from the node-local limit (pre-FB this
    // came back "tenant has reached the alias limit" and split the pair).
    let genuine = registration_event(
        &winner,
        &contested,
        &[key_entry(
            &contested_writer,
            &winner.public_key(),
            &contested,
        )],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &genuine).await;
    assert!(
        accepted,
        "exit16: the merge winner must be exempt from the alias limit; got {message:?}"
    );

    // The squatter is evicted: REQ resolves only the winner's edition.
    let mut converged = false;
    for _ in 0..50 {
        let events = fetch_from(
            relay.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .identifier(&contested),
        )
        .await;
        if events.len() == 1 && events[0].id == genuine.id {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        converged,
        "exit16: the contested alias must resolve to the winner"
    );

    // The accounting was NOT exempted: the winner's tenant now holds both
    // aliases (overshoot by exactly one) and both seats are live — a 30641
    // for each is accepted.
    let sha = sha256_hex(&blob_bytes(62, 128));
    for (a, writer, at) in [
        (&filler, &filler_writer, t0 + 150),
        (&contested, &contested_writer, t0 + 160),
    ] {
        let state = state_root_event(writer, &winner.public_key(), a, (&sha, 128), &[], at);
        let (accepted, message) = publish_with_result(relay.url(), &state).await;
        assert!(
            accepted,
            "exit16: 30641 for {a} must be accepted after the merge; got {message:?}"
        );
    }

    relay.stop().await;
}

// ============================================================================
// Exit test 17 — eviction frees the loser's whole footprint (verify FC/FD)
// ============================================================================

/// FC/FD (subsumes Lens-4 F3): the squatter saturates `r:<alias>` with
/// wraps, declares unstored blobs (speculatively charged), and stores one
/// real blob; the genuine earlier registration then wins the merge. In the
/// eviction's own txn the loser must lose its whole footprint: the alias
/// scope's EVENT column is reset (the winner is not quota-bricked), the
/// orphaned speculative charge is released from t:/r:/g: immediately, and
/// the stored blob's claim is stripped so GC releases its charge after
/// grace. (Ring-edition deletion is pinned at meta level in
/// `registration::tests::eviction_cleans_loser_footprint` — the ring has no
/// externally visible surface.)
#[tokio::test]
async fn exit17_eviction_releases_loser_footprint() {
    let squatter = Keys::generate();
    let victim = Keys::generate();
    let whitelist = whitelist_npubs(&[&squatter, &victim]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_QUOTA_REPO_BYTES", "16384"),
        // Short (non-zero) grace so the post-eviction spec-release sample is
        // race-free while GC still collects within the test bound.
        ("NGIT_GRASP_P_GC_GRACE_SECS", "3"),
        ("NGIT_GRASP_P_GC_INTERVAL_SECS", "1"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let domain = relay.domain();

    let squat_writer = Keys::generate();
    let victim_writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs() - 600;

    let global_ledger = || async {
        common::sync_helpers::ParsedMetrics::parse(
            &common::sync_helpers::fetch_metrics(relay.url())
                .await
                .expect("metrics scrape"),
        )
        .gauge("ngit_private_ledger_bytes", &[("scope", "global")])
        .unwrap_or(-1)
    };

    // The squatter takes the alias (later created_at), stores one real blob,
    // and declares a never-uploaded 4096-byte blob (speculatively charged).
    let squat = registration_event(
        &squatter,
        &alias,
        &[key_entry(&squat_writer, &squatter.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 100),
    );
    let (accepted, message) = publish_with_result(relay.url(), &squat).await;
    assert!(
        accepted,
        "exit17: squatter registration failed: {message:?}"
    );

    let stored_blob = blob_bytes(63, 512);
    let stored_sha = sha256_hex(&stored_blob);
    let auth = blossom_auth_event(
        &squat_writer,
        "upload",
        &stored_sha,
        &squatter.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, stored_blob.clone(), &stored_sha, &auth).await;
    assert_eq!(
        status, 200,
        "exit17: squatter blob PUT failed; X-Reason: {reason}"
    );

    // The 30641 declares a never-uploaded 4096-byte blob (speculatively
    // charged) AND references the stored blob — an unreferenced PUT blob is
    // unclaimed by the ring release loop at the next edition, and this test
    // needs the stored claim alive (and charged) until the eviction.
    let fake_sha = sha256_hex(&blob_bytes(64, 64));
    let v1 = state_root_event(
        &squat_writer,
        &squatter.public_key(),
        &alias,
        (&fake_sha, 4096),
        &[(stored_sha.clone(), 512)],
        t0 + 110,
    );
    let (accepted, message) = publish_with_result(relay.url(), &v1).await;
    assert!(accepted, "exit17: squatter 30641 failed: {message:?}");

    // …and saturates the shared r:<alias> scope with wraps.
    let mut saturated = false;
    for _ in 0..64 {
        let wrap = wrap_event(&squat_writer, 1059);
        let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
        if !accepted {
            assert!(
                message.contains("quota exceeded"),
                "exit17: expected quota refusal while saturating; got {message:?}"
            );
            saturated = true;
            break;
        }
    }
    assert!(
        saturated,
        "exit17: alias quota must saturate within the loop"
    );
    let g_before = global_ledger().await;
    assert!(g_before > 0);

    // The genuine earlier registration wins the merge.
    let genuine = registration_event(
        &victim,
        &alias,
        &[key_entry(&victim_writer, &victim.public_key(), &alias)],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &genuine).await;
    assert!(
        accepted,
        "exit17: the earlier registration must win the merge; got {message:?}"
    );
    let winner_reg_bytes = genuine.as_json().len() as i64;

    // (b) The loser's speculative 4096 was released from the ledger IN the
    // eviction txn (not after GC grace): global drops by exactly the spec
    // bytes and rises by exactly the winner's registration bytes. GC grace
    // is 3s, so this sample (taken immediately) is race-free.
    let mut g_after = -1;
    for _ in 0..50 {
        g_after = global_ledger().await;
        if g_after == g_before - 4096 + winner_reg_bytes {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        g_after,
        g_before - 4096 + winner_reg_bytes,
        "exit17: the orphaned spec charge must be released in the eviction txn"
    );

    // (a) The winner is NOT quota-bricked: 30641, wrap, and upload all pass
    // against the reset event column (pre-FC every one of these came back
    // "quota exceeded" because the squatter had filled the shared scope).
    let winner_fake = sha256_hex(&blob_bytes(65, 32));
    let state = state_root_event(
        &victim_writer,
        &victim.public_key(),
        &alias,
        (&winner_fake, 100),
        &[],
        t0 + 200,
    );
    let (accepted, message) = publish_with_result(relay.url(), &state).await;
    assert!(
        accepted,
        "exit17: winner's 30641 must not be quota-rejected; got {message:?}"
    );
    let state_bytes = state.as_json().len() as i64;
    let wrap = wrap_event(&victim_writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        accepted,
        "exit17: winner's wrap must not be quota-rejected; got {message:?}"
    );
    let wrap_bytes = wrap.as_json().len() as i64;
    let winner_blob = blob_bytes(66, 256);
    let winner_sha = sha256_hex(&winner_blob);
    let auth = blossom_auth_event(
        &victim_writer,
        "upload",
        &winner_sha,
        &victim.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, winner_blob.clone(), &winner_sha, &auth).await;
    assert_eq!(
        status, 200,
        "exit17: winner's upload must not be quota-rejected; X-Reason: {reason}"
    );
    // A trailing wrap: its charge refreshes the ledger gauge AFTER the PUT
    // (PUT finish() does not refresh it), so the settled sample below is
    // race-free against the GC collection.
    let wrap2 = wrap_event(&victim_writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap2).await;
    assert!(
        accepted,
        "exit17: trailing wrap must be accepted; got {message:?}"
    );
    let wrap2_bytes = wrap2.as_json().len() as i64;

    // (c) The loser's stored-blob claim was stripped at eviction: after GC
    // grace its 512 bytes are released (and the file removed). The winner's
    // own claims (256-byte stored blob + 100-byte spec) are referenced and
    // survive.
    let settled = g_after + state_bytes + wrap_bytes + 100 + 256 + wrap2_bytes - 512;
    let mut g_settled = -1;
    for _ in 0..150 {
        g_settled = global_ledger().await;
        if g_settled == settled {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if g_settled != settled {
        let (loser_status, _) = get_blob(&relay, &stored_sha).await;
        panic!(
            "exit17: GC must release the stripped stored-blob charge after grace \
             (port {}): gauge {g_settled} != expected {settled}; loser blob GET \
             status {loser_status} (200 = GC never collected, 404 = collected)",
            relay_port(&relay),
        );
    }
    let (status, _) = get_blob(&relay, &stored_sha).await;
    assert_eq!(
        status, 404,
        "exit17: the loser's stripped blob must be GC'd"
    );
    let (status, body) = get_blob(&relay, &winner_sha).await;
    assert_eq!(status, 200, "exit17: the winner's blob must survive GC");
    assert_eq!(body, winner_blob);

    relay.stop().await;
}

// ============================================================================
// Exit test 18 — kind-5 death releases the speculative footprint (verify FD)
// ============================================================================

/// FD: a tenant declares never-uploaded blobs (speculatively charged) and
/// then kind-5-deletes its own registration — the death path must strip the
/// dead alias from its blob claims and release the orphaned spec charges,
/// not strand them in the ledger forever. The NIP-09 cutoff discipline is
/// preserved: a kind-5 dated BEFORE the latest edition is partial survival
/// and must NOT strip or release anything.
#[tokio::test]
async fn exit18_kind5_death_releases_speculative_footprint() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let domain = relay.domain();

    let writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs() - 600;

    let global_ledger = || async {
        common::sync_helpers::ParsedMetrics::parse(
            &common::sync_helpers::fetch_metrics(relay.url())
                .await
                .expect("metrics scrape"),
        )
        .gauge("ngit_private_ledger_bytes", &[("scope", "global")])
        .unwrap_or(-1)
    };

    // Edition 1 (t0) + a 30641 declaring a never-uploaded 4096-byte blob.
    let reg1 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg1).await;
    assert!(accepted, "exit18: registration failed: {message:?}");
    let g0 = global_ledger().await;

    let fake_sha = sha256_hex(&blob_bytes(67, 64));
    let v1 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&fake_sha, 4096),
        &[],
        t0 + 10,
    );
    let (accepted, message) = publish_with_result(relay.url(), &v1).await;
    assert!(accepted, "exit18: 30641 failed: {message:?}");
    let v1_bytes = v1.as_json().len() as i64;
    let mut g1 = -1;
    for _ in 0..50 {
        g1 = global_ledger().await;
        if g1 == g0 + v1_bytes + 4096 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(g1, g0 + v1_bytes + 4096, "exit18: spec charge must land");

    // Rotate (t0+20, anchor preserved) so a deletion dated between the
    // editions is a PARTIAL-survival cutoff case.
    let reg2 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 20),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg2).await;
    assert!(accepted, "exit18: rotation failed: {message:?}");
    let reg2_bytes = reg2.as_json().len() as i64;
    let g2 = g1 + reg2_bytes;

    // NEGATIVE: a kind-5 dated t0+15 — BEFORE the latest edition (t0+20) —
    // must NOT strip claims or release the spec charge, and the seat stays
    // live.
    let stale = EventBuilder::new(Kind::EventDeletion, "stale")
        .tags(vec![
            Tag::custom("a", vec![reg_coord(&tenant.public_key(), &alias)]),
            Tag::custom("k", vec!["30640".to_string()]),
        ])
        .custom_created_at(Timestamp::from_secs(t0 + 15))
        .finalize(&tenant)
        .expect("sign stale kind-5");
    let (accepted, message) = publish_with_result(relay.url(), &stale).await;
    assert!(accepted, "exit18: stale kind-5 rejected: {message:?}");
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            global_ledger().await,
            g2,
            "exit18: partial-survival kind-5 must not release the spec charge"
        );
    }
    let state = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&fake_sha, 4096),
        &[],
        t0 + 25,
    );
    let (accepted, message) = publish_with_result(relay.url(), &state).await;
    assert!(
        accepted,
        "exit18: the seat must stay live after a stale deletion; got {message:?}"
    );
    let v2_bytes = state.as_json().len() as i64;
    let g3 = g2 + v2_bytes;

    // POSITIVE: a kind-5 dated AFTER the latest edition is honored — the
    // death cleanup releases the orphaned 4096 spec charge and strips the
    // dead alias from its claims.
    let deletion = EventBuilder::new(Kind::EventDeletion, "offboarding")
        .tags(vec![
            Tag::custom("a", vec![reg_coord(&tenant.public_key(), &alias)]),
            Tag::custom("k", vec!["30640".to_string()]),
        ])
        .custom_created_at(Timestamp::from_secs(t0 + 30))
        .finalize(&tenant)
        .expect("sign kind-5");
    let (accepted, message) = publish_with_result(relay.url(), &deletion).await;
    assert!(accepted, "exit18: kind-5 deletion rejected: {message:?}");

    let mut g4 = -1;
    for _ in 0..75 {
        g4 = global_ledger().await;
        if g4 == g3 - 4096 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        g4,
        g3 - 4096,
        "exit18: honored kind-5 must release the dead registration's spec charge"
    );

    // The registration is gone and the seat is dead for new editions.
    let mut deleted = false;
    for _ in 0..50 {
        let remaining = fetch_from(
            relay.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(tenant.public_key())
                .identifier(&alias),
        )
        .await;
        if remaining.is_empty() {
            deleted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        deleted,
        "exit18: the honored deletion must remove the 30640"
    );
    let state2 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&fake_sha, 4096),
        &[],
        t0 + 40,
    );
    let (accepted, _) = publish_with_result(relay.url(), &state2).await;
    assert!(!accepted, "exit18: post-death 30641 must be rejected");

    relay.stop().await;
}

// ============================================================================
// Exit test 19 — upload preflight nets the pending spec release (verify FF)
// ============================================================================

/// FF: a blob declared by a 30641 (speculatively charged) and then PUT must
/// not be double-counted at preflight: finish() releases the spec charge
/// before its quota check, and the preflight/reserve paths now mirror that
/// netting. With the alias scope within `len` of the cap, preflight and PUT
/// must be 200 — pre-FF both came back 507 until un-declare + GC grace.
#[tokio::test]
async fn exit19_upload_preflight_nets_pending_spec_release() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_QUOTA_REPO_BYTES", "8192"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;

    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    // Declare the real blob's sha at its true size: the ledger then holds
    // 4096 speculative bytes for the claim (repo scope ≈ registration ~750
    // + edition ~700 + spec 4096 ≈ 5.4k of the 8192 cap — within 4096 of it,
    // so the un-netted preflight would see ≈9.6k and 507).
    let data = blob_bytes(68, 4096);
    let sha = sha256_hex(&data);
    let t0 = Timestamp::now().as_secs();
    let declare = state_root_event(&writer, &tenant.public_key(), &alias, (&sha, 4096), &[], t0);
    let (accepted, message) = publish_with_result(relay.url(), &declare).await;
    assert!(
        accepted,
        "exit19: declaration must be accepted; got {message:?}"
    );

    // Preflight must net the pending spec release for the same (tenant,
    // alias): effective additional bytes = 4096 - 4096 = 0 → 200, not 507.
    let auth = blossom_auth_event(
        &writer,
        "upload",
        &sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, reason) = head_upload(&relay, &sha, data.len() as u64, Some(&auth)).await;
    assert_eq!(
        status, 200,
        "exit19: preflight must net the pending spec release; X-Reason: {reason}"
    );

    // The PUT itself (begin_upload re-runs preflight + reserve) → 200.
    let (status, _, reason) = put_blob(&relay, data.clone(), &sha, &auth).await;
    assert_eq!(
        status, 200,
        "exit19: declare-then-upload must succeed near the cap; X-Reason: {reason}"
    );
    let (status, body) = get_blob(&relay, &sha).await;
    assert_eq!(status, 200);
    assert_eq!(body, data, "exit19: blob bytes must round-trip");

    relay.stop().await;
}

// ============================================================================
// Exit test 20 — conflict alert deduped on replay (verify FG)
// ============================================================================

/// FG: the `incoming_rejected` conflict alert must fire once per loser
/// EVENT id — replaying an already-resolved loser (sync redelivery, boot
/// reconcile) must not re-alert — while a NEW conflict on the same alias
/// (a different event id) must still alert.
#[tokio::test]
async fn exit20_conflict_alert_deduped_on_replay() {
    let winner = Keys::generate();
    let loser = Keys::generate();
    let whitelist = whitelist_npubs(&[&winner, &loser]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let domain = relay.domain();
    let t0 = Timestamp::now().as_secs() - 600;

    let conflicts = || async {
        common::sync_helpers::ParsedMetrics::parse(
            &common::sync_helpers::fetch_metrics(relay.url())
                .await
                .expect("metrics scrape"),
        )
        .counter(
            "ngit_private_registration_conflicts_total",
            &[("resolution", "incoming_rejected")],
        )
        .unwrap_or(0)
    };

    let winner_writer = Keys::generate();
    let loser_writer = Keys::generate();
    let alias = random_alias();

    let win = registration_event(
        &winner,
        &alias,
        &[key_entry(&winner_writer, &winner.public_key(), &alias)],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &win).await;
    assert!(accepted, "exit20: winner registration failed: {message:?}");

    // The loser conflicts and is rejected: first firing increments.
    let lose1 = registration_event(
        &loser,
        &alias,
        &[key_entry(&loser_writer, &loser.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 100),
    );
    let (accepted, _) = publish_with_result(relay.url(), &lose1).await;
    assert!(!accepted, "exit20: loser must be rejected");
    let mut c = 0;
    for _ in 0..30 {
        c = conflicts().await;
        if c == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(c, 1, "exit20: first conflict firing must increment");

    // Replay the SAME loser event: rejected again, but no second alert.
    for _ in 0..3 {
        let (accepted, _) = publish_with_result(relay.url(), &lose1).await;
        assert!(!accepted, "exit20: replayed loser must still be rejected");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        conflicts().await,
        1,
        "exit20: replays of a resolved loser must not re-alert"
    );

    // A NEW conflict on the same alias (new event id) still alerts.
    let lose2 = registration_event(
        &loser,
        &alias,
        &[key_entry(&loser_writer, &loser.public_key(), &alias)],
        &[],
        &domain,
        Some(t0 + 200),
    );
    let (accepted, _) = publish_with_result(relay.url(), &lose2).await;
    assert!(!accepted, "exit20: second loser must be rejected");
    let mut c = 0;
    for _ in 0..30 {
        c = conflicts().await;
        if c == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(c, 2, "exit20: a new conflict on the same alias must alert");

    relay.stop().await;
}

// ============================================================================
// Exit test 21 — spec charge released on declarer's supersede when a second
// alias references the sha (verify FH)
// ============================================================================

/// FH: two aliases (different tenants) reference one unstored sha; the
/// declarer's speculative charge must be released when its own edition
/// flushes the reference (pre-FH it kept paying until claim death/upload).
/// The claim survives for the second referrer, which is then charged on its
/// next referencing 30641 (the dedup upgrade path). Exactly-once throughout.
#[tokio::test]
async fn exit21_spec_released_when_declarer_supersedes_with_second_referrer() {
    let tenant_v = Keys::generate();
    let tenant_a = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant_v, &tenant_a]);
    let relay = TestRelay::start_with_grasp_p(&[
        // One retained edition so v2 flushes v1's reference (cf. exit12).
        ("NGIT_GRASP_P_STATE_HISTORY_EDITIONS", "1"),
        ("NGIT_GRASP_P_GC_GRACE_SECS", "0"),
        ("NGIT_GRASP_P_GC_INTERVAL_SECS", "1"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;

    let writer_v = Keys::generate();
    let writer_a = Keys::generate();
    let alias_v = random_alias();
    let alias_a = random_alias();
    register_alias(&relay, &tenant_v, &writer_v, &alias_v).await;
    register_alias(&relay, &tenant_a, &writer_a, &alias_a).await;

    let global_ledger = || async {
        common::sync_helpers::ParsedMetrics::parse(
            &common::sync_helpers::fetch_metrics(relay.url())
                .await
                .expect("metrics scrape"),
        )
        .gauge("ngit_private_ledger_bytes", &[("scope", "global")])
        .unwrap_or(-1)
    };
    let poll_gauge = |want: i64| async move {
        for _ in 0..75 {
            let got = global_ledger().await;
            if got == want {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        global_ledger().await
    };

    let g0 = global_ledger().await;
    assert!(g0 > 0, "exit21: registrations must be on the ledger");
    let t0 = Timestamp::now().as_secs();

    // V declares the never-uploaded 4096-byte sha: speculatively charged.
    let fake_sha = sha256_hex(&blob_bytes(69, 64));
    let v1 = state_root_event(
        &writer_v,
        &tenant_v.public_key(),
        &alias_v,
        (&fake_sha, 4096),
        &[],
        t0 + 10,
    );
    let (accepted, message) = publish_with_result(relay.url(), &v1).await;
    assert!(accepted, "exit21: v1 must be accepted; got {message:?}");
    let g1 = poll_gauge(g0 + v1.as_json().len() as i64 + 4096).await;
    assert_eq!(
        g1,
        g0 + v1.as_json().len() as i64 + 4096,
        "exit21: V charged"
    );

    // A references the same sha: NOT charged again (single-charge dedup —
    // second referrers stay free).
    let a1 = state_root_event(
        &writer_a,
        &tenant_a.public_key(),
        &alias_a,
        (&fake_sha, 4096),
        &[],
        t0 + 11,
    );
    let (accepted, message) = publish_with_result(relay.url(), &a1).await;
    assert!(accepted, "exit21: a1 must be accepted; got {message:?}");
    let g2 = poll_gauge(g1 + a1.as_json().len() as i64).await;
    assert_eq!(
        g2,
        g1 + a1.as_json().len() as i64,
        "exit21: second referrer must not be double-charged"
    );

    // V supersedes with an edition that drops the sha (small replacement
    // declaration keeps V's own accounting visible): V's 4096 charge is
    // released while the claim survives on A's reference.
    let replacement = sha256_hex(&blob_bytes(70, 32));
    let v2 = state_root_event(
        &writer_v,
        &tenant_v.public_key(),
        &alias_v,
        (&replacement, 100),
        &[],
        t0 + 12,
    );
    let (accepted, message) = publish_with_result(relay.url(), &v2).await;
    assert!(accepted, "exit21: v2 must be accepted; got {message:?}");
    let g3 = poll_gauge(g2 + v2.as_json().len() as i64 + 100 - 4096).await;
    assert_eq!(
        g3,
        g2 + v2.as_json().len() as i64 + 100 - 4096,
        "exit21: the declarer must be refunded on supersede (FH)"
    );

    // The claim survived for A: A's next edition still references the sha,
    // and the upgrade path charges A exactly once for it now.
    let a2 = state_root_event(
        &writer_a,
        &tenant_a.public_key(),
        &alias_a,
        (&fake_sha, 4096),
        &[],
        t0 + 13,
    );
    let (accepted, message) = publish_with_result(relay.url(), &a2).await;
    assert!(accepted, "exit21: a2 must be accepted; got {message:?}");
    let g4 = poll_gauge(g3 + a2.as_json().len() as i64 + 4096).await;
    assert_eq!(
        g4,
        g3 + a2.as_json().len() as i64 + 4096,
        "exit21: the surviving referrer is charged exactly once on its next edition"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 22 — key-conflict merge + stale-edition prune guard (Lens-4 F2)
// ============================================================================

/// Two tenants with DIFFERENT aliases but an OVERLAPPING w key: the earlier
/// created_at wins the key claim (and evicts the loser's whole
/// registration). Separately, a same-tenant STALE edition that loses a key
/// conflict must NOT prune the tenant's own live coordinate
/// (`prune_incoming = false`): the live 30640 keeps serving and 30641/1059
/// stay accepted.
#[tokio::test]
async fn exit22_key_conflict_merge_and_stale_edition_prune_guard() {
    // Part 1: cross-tenant key conflict resolves by created_at.
    let tenant1 = Keys::generate();
    let tenant2 = Keys::generate();
    let tenant_b = Keys::generate();
    let tenant_c = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant1, &tenant2, &tenant_b, &tenant_c]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let domain = relay.domain();
    let t0 = Timestamp::now().as_secs() - 600;

    let shared_key = Keys::generate();
    let alias1 = random_alias();
    let alias2 = random_alias();

    // tenant1 holds alias1 with the shared key (t0).
    let reg1 = registration_event(
        &tenant1,
        &alias1,
        &[key_entry(&shared_key, &tenant1.public_key(), &alias1)],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg1).await;
    assert!(accepted, "exit22: tenant1 registration failed: {message:?}");

    // tenant2's LATER registration claiming the same key loses…
    let late = registration_event(
        &tenant2,
        &alias2,
        &[key_entry(&shared_key, &tenant2.public_key(), &alias2)],
        &[],
        &domain,
        Some(t0 + 100),
    );
    let (accepted, message) = publish_with_result(relay.url(), &late).await;
    assert!(
        !accepted && message.contains("write key already registered"),
        "exit22: later key claim must lose; got {message:?}"
    );

    // …but tenant2's EARLIER-created registration wins the key claim and
    // evicts tenant1's whole registration.
    let early = registration_event(
        &tenant2,
        &alias2,
        &[key_entry(&shared_key, &tenant2.public_key(), &alias2)],
        &[],
        &domain,
        Some(t0 - 50),
    );
    let (accepted, message) = publish_with_result(relay.url(), &early).await;
    assert!(
        accepted,
        "exit22: the earlier-created key claim must win; got {message:?}"
    );
    let mut pruned = false;
    for _ in 0..50 {
        let events = fetch_from(
            relay.url(),
            Filter::new().kind(Kind::Custom(30640)).identifier(&alias1),
        )
        .await;
        if events.is_empty() {
            pruned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(pruned, "exit22: the key-loser's coordinate must be pruned");
    let served = fetch_from(
        relay.url(),
        Filter::new().kind(Kind::Custom(30640)).identifier(&alias2),
    )
    .await;
    assert_eq!(served.len(), 1);
    assert_eq!(served[0].id, early.id, "exit22: key-conflict winner served");

    // Part 2: a same-tenant stale edition losing a key conflict must not
    // prune its own live coordinate.
    let writer_b = Keys::generate();
    let key_c = Keys::generate();
    let alias_b = random_alias();
    let alias_c = random_alias();

    // tenant_c holds key_c under alias_c (t1).
    let reg_c = registration_event(
        &tenant_c,
        &alias_c,
        &[key_entry(&key_c, &tenant_c.public_key(), &alias_c)],
        &[],
        &domain,
        Some(t0 + 200),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg_c).await;
    assert!(
        accepted,
        "exit22: tenant_c registration failed: {message:?}"
    );

    // tenant_b's alias_b: edition 1 (t2) then a live rotation (t4).
    let reg_b1 = registration_event(
        &tenant_b,
        &alias_b,
        &[key_entry(&writer_b, &tenant_b.public_key(), &alias_b)],
        &[],
        &domain,
        Some(t0 + 210),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg_b1).await;
    assert!(accepted, "exit22: tenant_b edition 1 failed: {message:?}");
    let reg_b2 = registration_event(
        &tenant_b,
        &alias_b,
        &[key_entry(&writer_b, &tenant_b.public_key(), &alias_b)],
        &[],
        &domain,
        Some(t0 + 240),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg_b2).await;
    assert!(
        accepted,
        "exit22: tenant_b live edition failed: {message:?}"
    );

    // A STALE edition of alias_b (t3, between t2 and t4) that ALSO claims
    // tenant_c's key: it loses the key conflict (t1 < t3) and must NOT take
    // down tenant_b's live coordinate (prune_incoming = false).
    let stale = registration_event(
        &tenant_b,
        &alias_b,
        &[
            key_entry(&writer_b, &tenant_b.public_key(), &alias_b),
            key_entry(&key_c, &tenant_b.public_key(), &alias_b),
        ],
        &[],
        &domain,
        Some(t0 + 230),
    );
    let (accepted, message) = publish_with_result(relay.url(), &stale).await;
    assert!(
        !accepted && message.contains("write key already registered"),
        "exit22: the stale edition must lose the key conflict; got {message:?}"
    );

    // tenant_b's LIVE 30640 is still served…
    let served = fetch_from(
        relay.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(tenant_b.public_key())
            .identifier(&alias_b),
    )
    .await;
    assert_eq!(served.len(), 1, "exit22: the live coordinate must survive");
    assert_eq!(
        served[0].id, reg_b2.id,
        "exit22: the live edition is served"
    );

    // …and the seat is fully functional: 30641 + 1059 still accepted.
    let sha = sha256_hex(&blob_bytes(71, 256));
    let state = state_root_event(
        &writer_b,
        &tenant_b.public_key(),
        &alias_b,
        (&sha, 256),
        &[],
        t0 + 250,
    );
    let (accepted, message) = publish_with_result(relay.url(), &state).await;
    assert!(
        accepted,
        "exit22: 30641 must be accepted after the stale-edition loss; got {message:?}"
    );
    let wrap = wrap_event(&writer_b, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        accepted,
        "exit22: 1059 must be accepted after the stale-edition loss; got {message:?}"
    );

    // tenant_c is untouched.
    let served = fetch_from(
        relay.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(tenant_c.public_key())
            .identifier(&alias_c),
    )
    .await;
    assert_eq!(served.len(), 1, "exit22: tenant_c must be unaffected");

    relay.stop().await;
}

// ============================================================================
// Exit test 23 — duplicate sha within one edition is charged once
// ============================================================================

/// The single-charge dedup at state_root.rs: a 30641 whose `m` and `pack`
/// tags name the SAME sha must speculatively charge it ONCE, not per tag.
#[tokio::test]
async fn exit23_duplicate_sha_in_one_edition_charged_once() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;

    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    let global_ledger = || async {
        common::sync_helpers::ParsedMetrics::parse(
            &common::sync_helpers::fetch_metrics(relay.url())
                .await
                .expect("metrics scrape"),
        )
        .gauge("ngit_private_ledger_bytes", &[("scope", "global")])
        .unwrap_or(-1)
    };
    let g0 = global_ledger().await;

    let fake_sha = sha256_hex(&blob_bytes(72, 64));
    let t0 = Timestamp::now().as_secs();
    let edition = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&fake_sha, 4096),
        &[(fake_sha.clone(), 4096)],
        t0,
    );
    let (accepted, message) = publish_with_result(relay.url(), &edition).await;
    assert!(
        accepted,
        "exit23: duplicate-sha edition must be accepted; got {message:?}"
    );

    let mut g1 = -1;
    let want = g0 + edition.as_json().len() as i64 + 4096;
    for _ in 0..50 {
        g1 = global_ledger().await;
        if g1 == want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        g1, want,
        "exit23: the same sha in m + pack must be charged exactly once"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 24 — eviction releases the dead charger's spec charge even when
// a second live alias references the sha (verify round 2, R2-A scenario B)
// ============================================================================

/// R2-A: the squatter holds alias X, declares never-uploaded shas under X
/// (speculatively charged), and re-references them under its own second live
/// alias Y. The victim's earlier registration wins the merge for X: the dead
/// charger's spec bytes must leave the r:X blob column even though Y keeps
/// referencing — otherwise every victim upload 507s against a cap of dead
/// bytes (and the global scope stays billed forever). The survivor is
/// re-charged on its next referencing 30641 (exactly-once migration).
#[tokio::test]
async fn exit24_eviction_releases_dead_charger_spec_on_shared_claims() {
    let squatter = Keys::generate();
    let victim = Keys::generate();
    let whitelist = whitelist_npubs(&[&squatter, &victim]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_QUOTA_REPO_BYTES", "8192"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let domain = relay.domain();
    let t0 = Timestamp::now().as_secs() - 600;

    let squat_wx = Keys::generate();
    let squat_wy = Keys::generate();
    let victim_writer = Keys::generate();
    let alias_x = random_alias();
    let alias_y = random_alias();

    let global_ledger = || async {
        common::sync_helpers::ParsedMetrics::parse(
            &common::sync_helpers::fetch_metrics(relay.url())
                .await
                .expect("metrics scrape"),
        )
        .gauge("ngit_private_ledger_bytes", &[("scope", "global")])
        .unwrap_or(-1)
    };

    // The squatter holds X (later created_at) and Y.
    for (alias, writer, at) in [
        (&alias_x, &squat_wx, t0 + 100),
        (&alias_y, &squat_wy, t0 + 110),
    ] {
        let reg = registration_event(
            &squatter,
            alias,
            &[key_entry(writer, &squatter.public_key(), alias)],
            &[],
            &domain,
            Some(at),
        );
        let (accepted, message) = publish_with_result(relay.url(), &reg).await;
        assert!(
            accepted,
            "exit24: squatter registration failed: {message:?}"
        );
    }

    // X declares the never-uploaded 4096-byte sha (speculatively charged to
    // (squatter, X))…
    let fake_sha = sha256_hex(&blob_bytes(73, 64));
    let x1 = state_root_event(
        &squat_wx,
        &squatter.public_key(),
        &alias_x,
        (&fake_sha, 4096),
        &[],
        t0 + 120,
    );
    let (accepted, message) = publish_with_result(relay.url(), &x1).await;
    assert!(accepted, "exit24: X declaration failed: {message:?}");

    // …and Y re-references the same sha (dedup: no second charge; the claim
    // now lists both aliases while the charge stays on X's scope).
    let y1 = state_root_event(
        &squat_wy,
        &squatter.public_key(),
        &alias_y,
        (&fake_sha, 4096),
        &[],
        t0 + 130,
    );
    let (accepted, message) = publish_with_result(relay.url(), &y1).await;
    assert!(accepted, "exit24: Y re-reference failed: {message:?}");
    let g_before = global_ledger().await;
    assert!(g_before > 0);

    // The victim's earlier registration wins the merge for X.
    let genuine = registration_event(
        &victim,
        &alias_x,
        &[key_entry(&victim_writer, &victim.public_key(), &alias_x)],
        &[],
        &domain,
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &genuine).await;
    assert!(
        accepted,
        "exit24: the earlier registration must win the merge; got {message:?}"
    );
    let winner_reg_bytes = genuine.as_json().len() as i64;

    // The dead charger's 4096 spec bytes are released in the eviction txn
    // even though Y still references the claim.
    let mut g_after = -1;
    for _ in 0..50 {
        g_after = global_ledger().await;
        if g_after == g_before - 4096 + winner_reg_bytes {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        g_after,
        g_before - 4096 + winner_reg_bytes,
        "exit24: the dead charger's spec charge must be released at eviction"
    );

    // The r:X blob column dropped the dead spec bytes: the victim's 4096-byte
    // upload PASSES (pre-R2-A it 507'd against a cap of dead bytes).
    let blob = blob_bytes(74, 4096);
    let sha = sha256_hex(&blob);
    let auth = blossom_auth_event(
        &victim_writer,
        "upload",
        &sha,
        &victim.public_key(),
        &alias_x,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, blob.clone(), &sha, &auth).await;
    assert_eq!(
        status, 200,
        "exit24: the winner's upload must not be quota-bricked by dead spec bytes; X-Reason: {reason}"
    );

    // The survivor is re-charged exactly once on its next referencing 30641.
    let y2 = state_root_event(
        &squat_wy,
        &squatter.public_key(),
        &alias_y,
        (&fake_sha, 4096),
        &[],
        t0 + 140,
    );
    let (accepted, message) = publish_with_result(relay.url(), &y2).await;
    assert!(accepted, "exit24: Y's next edition failed: {message:?}");
    let mut g_migrated = -1;
    // y2's accept also refreshes the gauge past the victim's PUT (finish()
    // charges the ledger but does not refresh the gauge).
    let want = g_after + 4096 + y2.as_json().len() as i64 + 4096;
    for _ in 0..50 {
        g_migrated = global_ledger().await;
        if g_migrated == want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        g_migrated, want,
        "exit24: the surviving referrer must be re-charged exactly once"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 25 — Blossom DELETE releases the deleting charger's spec charge
// (verify round 2, R2-D)
// ============================================================================

/// R2-D: the Blossom DELETE path strips the deleting alias but used to leave
/// its spec_charge pinned while another alias referenced the sha (the same
/// FH-class hole on a path FH didn't touch). The deleting charger's charge
/// is released; the claim survives for the remaining referrer, which is
/// re-charged exactly once on its next referencing 30641.
#[tokio::test]
async fn exit25_blob_delete_releases_deleting_charger_spec() {
    let tenant_v = Keys::generate();
    let tenant_a = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant_v, &tenant_a]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;

    let writer_v = Keys::generate();
    let writer_a = Keys::generate();
    let alias_v = random_alias();
    let alias_a = random_alias();
    register_alias(&relay, &tenant_v, &writer_v, &alias_v).await;
    register_alias(&relay, &tenant_a, &writer_a, &alias_a).await;

    let global_ledger = || async {
        common::sync_helpers::ParsedMetrics::parse(
            &common::sync_helpers::fetch_metrics(relay.url())
                .await
                .expect("metrics scrape"),
        )
        .gauge("ngit_private_ledger_bytes", &[("scope", "global")])
        .unwrap_or(-1)
    };
    let poll_gauge = |want: i64| async move {
        for _ in 0..75 {
            let got = global_ledger().await;
            if got == want {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        global_ledger().await
    };

    let g0 = global_ledger().await;
    let t0 = Timestamp::now().as_secs();

    // V declares the never-uploaded 4096-byte sha: speculatively charged.
    let fake_sha = sha256_hex(&blob_bytes(75, 64));
    let v1 = state_root_event(
        &writer_v,
        &tenant_v.public_key(),
        &alias_v,
        (&fake_sha, 4096),
        &[],
        t0 + 10,
    );
    let (accepted, message) = publish_with_result(relay.url(), &v1).await;
    assert!(accepted, "exit25: v1 failed: {message:?}");
    let g1 = poll_gauge(g0 + v1.as_json().len() as i64 + 4096).await;
    assert_eq!(
        g1,
        g0 + v1.as_json().len() as i64 + 4096,
        "exit25: V charged"
    );

    // A references the same sha: not charged again (dedup).
    let a1 = state_root_event(
        &writer_a,
        &tenant_a.public_key(),
        &alias_a,
        (&fake_sha, 4096),
        &[],
        t0 + 11,
    );
    let (accepted, message) = publish_with_result(relay.url(), &a1).await;
    assert!(accepted, "exit25: a1 failed: {message:?}");
    let g2 = poll_gauge(g1 + a1.as_json().len() as i64).await;
    assert_eq!(g2, g1 + a1.as_json().len() as i64, "exit25: dedup holds");

    // V DELETEs the blob: its spec charge is released even though A still
    // references the sha (pre-R2-D the charge stayed pinned on V's scope).
    let delete_auth = blossom_auth_event(
        &writer_v,
        "delete",
        &fake_sha,
        &tenant_v.public_key(),
        &alias_v,
        future_expiration(),
    );
    let (status, reason) = delete_blob(&relay, &fake_sha, &delete_auth).await;
    assert_eq!(
        status, 200,
        "exit25: DELETE must be 200; X-Reason: {reason}"
    );
    let g3 = poll_gauge(g2 - 4096).await;
    assert_eq!(
        g3,
        g2 - 4096,
        "exit25: the deleting charger's spec charge must be released"
    );

    // The claim survives for A: A's next edition still references the sha
    // and the upgrade path charges A exactly once.
    let a2 = state_root_event(
        &writer_a,
        &tenant_a.public_key(),
        &alias_a,
        (&fake_sha, 4096),
        &[],
        t0 + 12,
    );
    let (accepted, message) = publish_with_result(relay.url(), &a2).await;
    assert!(accepted, "exit25: a2 failed: {message:?}");
    let g4 = poll_gauge(g3 + a2.as_json().len() as i64 + 4096).await;
    assert_eq!(
        g4,
        g3 + a2.as_json().len() as i64 + 4096,
        "exit25: the surviving referrer is charged exactly once"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 26 — Phase-4b A1: per-write-key client write rate limit
// ============================================================================
// Capacity 3, refill 1/min (no meaningful refill during the test). Client
// submissions of 30641/1059/PUT are capped; the sync/loopback reprocess
// path (held out-of-order 30641 drained on 30640 Accept) bypasses the
// bucket entirely.

#[tokio::test]
async fn exit26_client_write_rate_limit() {
    let tenant = Keys::generate();
    let tenant2 = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant, &tenant2]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_WRITE_RATE_CAPACITY", "3"),
        ("NGIT_GRASP_P_WRITE_RATE_REFILL_PER_MIN", "1"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs();

    // A 30641 pushed BEFORE its 30640: rejected (unregistered alias) and
    // held keyed by the alias for reprocess — and it spends one client
    // write token (bucket: 3 -> 2). Its created_at is deliberately the
    // NEWEST of this test's editions: 30641 is addressable, so an older
    // reprocessed edition would be shadowed at the coordinate by the
    // in-budget editions below and could not prove storage by fetch.
    let manifest_sha = sha256_hex(&blob_bytes(90, 64));
    let e0 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&manifest_sha, 64),
        &[],
        t0 + 100,
    );
    let (accepted, _) = publish_with_result(relay.url(), &e0).await;
    assert!(!accepted, "exit26: pre-registration 30641 must be rejected");

    // The 30640 registration is NOT write-rate gated (that is A2's bucket).
    register_alias(&relay, &tenant, &writer, &alias).await;

    // Two 1059 wraps fit the remaining budget (2 -> 0). Wraps are not
    // addressable, so — unlike 30641 editions — they cannot go stale at a
    // coordinate when the 200ms reprocess timer lands e0 mid-test.
    for _ in 0..2 {
        let wrap = wrap_event(&writer, 1059);
        let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
        assert!(
            accepted,
            "exit26: in-budget 1059 must be accepted; got {message:?}"
        );
    }

    // The next 30641 exceeds the bucket: NIP-20 OK false with the distinct
    // machine-readable message (the rate gate fires before any storage
    // semantics, so coordinate freshness is irrelevant here).
    let sha = sha256_hex(&blob_bytes(93, 64));
    let over = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha, 64),
        &[],
        t0 + 4,
    );
    let (accepted, message) = publish_with_result(relay.url(), &over).await;
    assert!(!accepted, "exit26: over-budget 30641 must be rejected");
    assert!(
        message.contains("rate-limited; retry later"),
        "exit26: rejection must be the rate-limit message; got: {message:?}"
    );

    // The bucket is shared per write key across paths: a 1059 wrap from the
    // same writer is rate-limited too.
    let wrap = wrap_event(&writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(!accepted, "exit26: over-budget 1059 must be rejected");
    assert!(
        message.contains("rate-limited; retry later"),
        "exit26: wrap rejection must be the rate-limit message; got: {message:?}"
    );

    // Sync-path bypass proof: the HELD pre-registration 30641 (e0) is
    // reprocessed via the loopback sync path once the 30640 is indexed —
    // that traffic never touches the client bucket, so e0 is accepted and
    // stored even though the writer's bucket is empty. e0 is the only
    // edition on this alias (the rate-limited `over` was never held), so
    // the addressable coordinate serves it once stored.
    let mut e0_stored = false;
    for _ in 0..50 {
        let events = fetch_from(
            relay.url(),
            Filter::new()
                .kind(Kind::Custom(30641))
                .author(writer.public_key())
                .identifier(&alias),
        )
        .await;
        if events.iter().any(|e| e.id == e0.id) {
            e0_stored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        e0_stored,
        "exit26: the held 30641 must be reprocessed via the loopback path \
         (rate-bucket bypass) after the 30640 is accepted"
    );

    // Blob PUT: one token per request, keyed by the auth pubkey — a fresh
    // writer gets a fresh bucket (capacity 3: three PUTs pass, the fourth
    // is 429 + Retry-After).
    let writer2 = Keys::generate();
    let alias2 = random_alias();
    register_alias(&relay, &tenant2, &writer2, &alias2).await;
    for i in 0..3u8 {
        let data = blob_bytes(120 + i, 256);
        let sha = sha256_hex(&data);
        let auth = blossom_auth_event(
            &writer2,
            "upload",
            &sha,
            &tenant2.public_key(),
            &alias2,
            future_expiration(),
        );
        let (status, _, reason) = put_blob(&relay, data, &sha, &auth).await;
        assert_eq!(
            status, 200,
            "exit26: in-budget PUT must succeed; X-Reason: {reason}"
        );
    }
    let data = blob_bytes(123, 256);
    let sha = sha256_hex(&data);
    let auth = blossom_auth_event(
        &writer2,
        "upload",
        &sha,
        &tenant2.public_key(),
        &alias2,
        future_expiration(),
    );
    let resp = reqwest::Client::new()
        .put(format!("{}/upload", http_base(&relay)))
        .header("authorization", auth_header_value(&auth))
        .header("x-sha-256", &sha)
        .body(data)
        .send()
        .await
        .expect("PUT /upload transport");
    assert_eq!(
        resp.status().as_u16(),
        429,
        "exit26: over-budget PUT must be 429"
    );
    assert!(
        resp.headers().get("retry-after").is_some(),
        "exit26: 429 must carry a Retry-After hint"
    );
    let reason = resp
        .headers()
        .get("x-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        reason.contains("rate-limited; retry later"),
        "exit26: 429 X-Reason must be the rate-limit message; got: {reason:?}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 27 — Phase-4b A2: kind-30640 replacement-cadence limit
// ============================================================================
// Capacity 2, refill 1/hour. Same-tenant newer replacements are gated; new
// aliases, stale editions (anchor repair), and the first registration are
// exempt.

#[tokio::test]
async fn exit27_registration_replace_cadence() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY", "2"),
        ("NGIT_GRASP_P_REGISTRATION_REPLACE_REFILL_PER_HOUR", "1"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs();

    // First edition: a NEW alias — exempt from the cadence bucket.
    let ed1 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &ed1).await;
    assert!(accepted, "exit27: initial registration failed: {message:?}");

    // Rotation burst within capacity: two same-tenant newer replacements.
    let ed2 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0 + 10),
    );
    let (accepted, message) = publish_with_result(relay.url(), &ed2).await;
    assert!(accepted, "exit27: burst replacement 1 failed: {message:?}");
    let ed3 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0 + 20),
    );
    let (accepted, message) = publish_with_result(relay.url(), &ed3).await;
    assert!(accepted, "exit27: burst replacement 2 failed: {message:?}");

    // The flood beyond capacity is rejected with the distinct cadence
    // message, and the stored/served edition stays ed3.
    for i in 0..3u64 {
        let flood = registration_event(
            &tenant,
            &alias,
            &[key_entry(&writer, &tenant.public_key(), &alias)],
            &[],
            &relay.domain(),
            Some(t0 + 30 + i * 10),
        );
        let (accepted, message) = publish_with_result(relay.url(), &flood).await;
        assert!(!accepted, "exit27: flood replacement must be rejected");
        assert!(
            message.contains("replacement rate-limited; retry later"),
            "exit27: rejection must be the cadence message; got: {message:?}"
        );
    }
    let served = fetch_from(
        relay.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(tenant.public_key())
            .identifier(&alias),
    )
    .await;
    assert_eq!(
        served.len(),
        1,
        "exit27: exactly one edition must be served"
    );
    assert_eq!(
        served[0].id, ed3.id,
        "exit27: the last in-budget edition must survive the flood"
    );

    // Stale same-tenant edition (anchor repair accept-no-op): exempt from
    // the cadence gate. The DB layer answers OK-false for a stale
    // addressable edition with its own generic message — the point here is
    // that the rejection is NOT the cadence one (the unit test pins the
    // policy-level accept-no-op).
    let stale = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0 + 15),
    );
    let (_, message) = publish_with_result(relay.url(), &stale).await;
    assert!(
        !message.contains("replacement rate-limited"),
        "exit27: stale same-tenant editions must not be cadence-gated: {message:?}"
    );

    // New alias from the SAME tenant: exempt (fresh bucket key + new-alias
    // path). Needs a dedicated writer key (the first is claimed by `alias`).
    let alias2 = random_alias();
    let writer2 = Keys::generate();
    let reg2 = registration_event(
        &tenant,
        &alias2,
        &[key_entry(&writer2, &tenant.public_key(), &alias2)],
        &[],
        &relay.domain(),
        Some(t0 + 40),
    );
    let (accepted, message) = publish_with_result(relay.url(), &reg2).await;
    assert!(
        accepted,
        "exit27: new-alias registrations must not be cadence-gated: {message:?}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 28 — Phase-4b A3: exact-host URL check on 30640 relays/server tags
// ============================================================================

#[tokio::test]
async fn exit28_exact_host_registration_tags() {
    // One tenant per attempt below, all whitelisted up front so only the
    // relays/server tag checks decide the verdicts.
    let tenants: Vec<Keys> = (0..5).map(|_| Keys::generate()).collect();
    let tenant_refs: Vec<&Keys> = tenants.iter().collect();
    let whitelist = whitelist_npubs(&tenant_refs);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let domain = relay.domain();

    let mut tenant_iter = tenants.iter();
    let mut attempt = move |relays: String, server: String| {
        let tenant = tenant_iter.next().expect("one tenant per attempt");
        let writer = Keys::generate();
        let alias = random_alias();
        let tags = vec![
            Tag::identifier(&alias),
            Tag::custom("relays", vec![relays]),
            Tag::custom("server", vec![server]),
            Tag::custom("w", key_entry(&writer, &tenant.public_key(), &alias)),
        ];
        let event = EventBuilder::new(Kind::Custom(30640), "")
            .tags(tags)
            .finalize(tenant)
            .expect("sign 30640");
        (event, alias)
    };

    // (a) Domain as a leading label of a hostile host: rejected (the old
    // substring check passed this).
    let (event, _) = attempt(
        "ws://127.0.0.1.attacker.tld".to_string(),
        format!("http://{domain}"),
    );
    let (accepted, message) = publish_with_result(relay.url(), &event).await;
    assert!(!accepted, "exit28: attacker-suffix host must be rejected");
    assert!(
        message.contains("must list this node"),
        "exit28: rejection must name the relays check; got: {message:?}"
    );

    // (b) Domain smuggled into the query string of a foreign host: rejected.
    let (event, _) = attempt(
        format!("ws://evil.example.com/x?{domain}"),
        format!("http://{domain}"),
    );
    let (accepted, message) = publish_with_result(relay.url(), &event).await;
    assert!(!accepted, "exit28: query-smuggled domain must be rejected");
    assert!(
        message.contains("must list this node"),
        "exit28: rejection must name the relays check; got: {message:?}"
    );

    // (c) Scheme-less value: conservatively rejected.
    let (event, _) = attempt(domain.clone(), format!("http://{domain}"));
    let (accepted, message) = publish_with_result(relay.url(), &event).await;
    assert!(
        !accepted,
        "exit28: scheme-less relays value must be rejected"
    );
    assert!(
        message.contains("must list this node"),
        "exit28: rejection must name the relays check; got: {message:?}"
    );

    // (d) The server tag is checked the same way.
    let (event, _) = attempt(
        format!("ws://{domain}"),
        "http://attacker.tld/?server=127.0.0.1".to_string(),
    );
    let (accepted, message) = publish_with_result(relay.url(), &event).await;
    assert!(!accepted, "exit28: hostile server host must be rejected");
    assert!(
        message.contains("must list this node"),
        "exit28: rejection must name the server check; got: {message:?}"
    );

    // (e) Exact host:port on both tags: accepted (unchanged happy path).
    let (event, alias) = attempt(format!("ws://{domain}"), format!("http://{domain}"));
    let (accepted, message) = publish_with_result(relay.url(), &event).await;
    assert!(
        accepted,
        "exit28: exact-host registration failed: {message:?}"
    );
    let served = fetch_from(
        relay.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(event.pubkey)
            .identifier(&alias),
    )
    .await;
    assert_eq!(
        served.len(),
        1,
        "exit28: exact-host registration must round-trip"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 29 — Phase-4b D1: denylisted reads + writes are 451
// ============================================================================
// Multi-file boot semantics (one missing file tolerated, one present file
// enforced) with a denylisted sha that never touches disk: GET and HEAD
// return 451, and the upload preflight of the denylisted sha is 451 too
// (the anonymous-probe gap — a takedown must not be discoverable via a
// cheaper write-path probe).

/// HEAD /<sha> → status.
async fn head_blob(relay: &TestRelay, sha: &str) -> u16 {
    reqwest::Client::new()
        .head(format!("{}/{sha}", http_base(relay)))
        .send()
        .await
        .expect("HEAD /<sha> transport")
        .status()
        .as_u16()
}

/// GET /list/<target> with an optional Authorization header value.
/// Returns (status, X-Reason, body).
async fn get_list(
    relay: &TestRelay,
    target: &str,
    authorization: Option<&str>,
) -> (u16, String, Vec<u8>) {
    let mut request = reqwest::Client::new().get(format!("{}/list/{}", http_base(relay), target));
    if let Some(value) = authorization {
        request = request.header("Authorization", value);
    }
    let response = request.send().await.expect("GET /list transport");
    let status = response.status().as_u16();
    let reason = response
        .headers()
        .get("x-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = response.bytes().await.expect("GET /list body").to_vec();
    (status, reason, body)
}

/// GET /list/<tenant-hex>, authorized by the tenant itself → the descriptor
/// sha256 list.
async fn list_blob_shas(relay: &TestRelay, tenant: &Keys) -> Vec<String> {
    let authorization = auth_header_value(&list_auth_event(tenant, "list", future_expiration()));
    let (status, reason, body) = get_list(
        relay,
        &tenant.public_key().to_hex(),
        Some(authorization.as_str()),
    )
    .await;
    assert_eq!(
        status, 200,
        "GET /list signed by the listed key must succeed; X-Reason: {reason}"
    );
    let body: serde_json::Value = serde_json::from_slice(&body).expect("/list must be JSON");
    body.as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|d| d.get("sha256").and_then(|s| s.as_str()).map(String::from))
        .collect()
}

/// Global-scope ledger gauge from the relay's /metrics endpoint.
async fn global_ledger_bytes(relay_url: &str) -> i64 {
    common::sync_helpers::ParsedMetrics::parse(
        &common::sync_helpers::fetch_metrics(relay_url)
            .await
            .expect("metrics scrape"),
    )
    .gauge("ngit_private_ledger_bytes", &[("scope", "global")])
    .unwrap_or(-1)
}

/// Poll `probe` until it yields `want`, returning its last value (200ms step).
async fn poll_until<T, F, Fut>(want: T, mut probe: F) -> T
where
    T: PartialEq,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    for _ in 0..75 {
        let got = probe().await;
        if got == want {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    probe().await
}

/// Write the denylist file and force a STRICTLY-newer mtime (the reload
/// loop diffs on mtime — a coarse-granularity filesystem can alias two
/// writes inside one reload tick and silently skip the swap).
fn write_denylist(path: &std::path::Path, contents: String) {
    std::fs::write(path, contents).expect("write denylist");
    let mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .expect("denylist mtime");
    let file = std::fs::File::open(path).expect("open denylist");
    file.set_modified(mtime + Duration::from_secs(2))
        .expect("bump denylist mtime");
}

/// On-disk path of a stored blob inside the relay's default blob root.
fn relay_blob_path(relay: &TestRelay, sha: &str) -> std::path::PathBuf {
    relay
        .relay_data_path()
        .join("blobs")
        .join(&sha[0..2])
        .join(&sha[2..4])
        .join(sha)
}

#[tokio::test]
async fn exit29_denylisted_get_head_and_upload_preflight_are_451() {
    let dir = tempfile::tempdir().expect("denylist tempdir");
    let deny_path = dir.path().join("deny.txt");
    let blocked_sha = sha256_hex(&blob_bytes(201, 64));
    std::fs::write(
        &deny_path,
        format!("# operator takedown list\n{blocked_sha}\n"),
    )
    .expect("write denylist");
    // Multi-file semantics: a MISSING entry in the list is tolerated at
    // boot (warn + empty) while the present file is enforced.
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        (
            "NGIT_GRASP_P_DENYLIST_PATH",
            &format!("{},/nonexistent/grasp-p-denylist.txt", deny_path.display()),
        ),
        ("NGIT_GRASP_P_DENYLIST_RELOAD_SECS", "0"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;

    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    // GET + HEAD of the denylisted sha: 451 (never uploaded — the denylist
    // check precedes the existence check, so even an absent hash is 451).
    let (status, _) = get_blob(&relay, &blocked_sha).await;
    assert_eq!(status, 451, "exit29: denylisted GET must be 451");
    assert_eq!(
        head_blob(&relay, &blocked_sha).await,
        451,
        "exit29: denylisted HEAD must be 451"
    );

    // Upload preflight of the denylisted sha with VALID auth: 451 (the
    // write path must not be a cheaper probe than the read path).
    let auth = blossom_auth_event(
        &writer,
        "upload",
        &blocked_sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, reason) = head_upload(&relay, &blocked_sha, 64, Some(&auth)).await;
    assert_eq!(
        status, 451,
        "exit29: denylisted upload preflight must be 451; X-Reason: {reason}"
    );

    // The full PUT is 451 as well (preflight inside begin_upload).
    let data = blob_bytes(201, 64);
    let (status, _, reason) = put_blob(&relay, data, &blocked_sha, &auth).await;
    assert_eq!(
        status, 451,
        "exit29: denylisted PUT must be 451; X-Reason: {reason}"
    );

    // Control: a non-denylisted blob uploads and reads back fine.
    let ok_data = blob_bytes(202, 256);
    let ok_sha = sha256_hex(&ok_data);
    let ok_auth = blossom_auth_event(
        &writer,
        "upload",
        &ok_sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, ok_data.clone(), &ok_sha, &ok_auth).await;
    assert_eq!(
        status, 200,
        "exit29: control PUT must succeed; X-Reason: {reason}"
    );
    let (status, body) = get_blob(&relay, &ok_sha).await;
    assert_eq!(status, 200, "exit29: control GET must be 200");
    assert_eq!(body, ok_data, "exit29: control bytes must round-trip");

    relay.stop().await;
}

// ============================================================================
// Exit test 30 — Phase-4b D1: reload purge-on-add
// ============================================================================
// A sha appended to the denylist file is purged at the next reload tick:
// reads 451, bytes unlinked, ledger charge released, /list excludes it,
// and re-upload is refused. The reload interval here is 60s — the
// NGIT_TEST=1 clamp (<= 1s) is what makes the swap observable in-test.

#[tokio::test]
async fn exit30_reload_purge_on_add() {
    let dir = tempfile::tempdir().expect("denylist tempdir");
    let deny_path = dir.path().join("deny.txt");
    std::fs::write(&deny_path, "# initially empty\n").expect("write denylist");
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        (
            "NGIT_GRASP_P_DENYLIST_PATH",
            &deny_path.display().to_string(),
        ),
        ("NGIT_GRASP_P_DENYLIST_RELOAD_SECS", "60"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;

    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;
    let g0 = global_ledger_bytes(relay.url()).await;
    assert!(g0 > 0, "exit30: registration must be on the ledger");

    let data = blob_bytes(203, 512);
    let sha = sha256_hex(&data);
    let auth = blossom_auth_event(
        &writer,
        "upload",
        &sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, data.clone(), &sha, &auth).await;
    assert_eq!(status, 200, "exit30: PUT must succeed; X-Reason: {reason}");
    let (status, body) = get_blob(&relay, &sha).await;
    assert_eq!((status, body.len()), (200, 512), "exit30: pre-takedown GET");
    assert!(
        relay_blob_path(&relay, &sha).is_file(),
        "exit30: bytes on disk"
    );

    // Takedown: append the sha; the reload (NGIT_TEST-clamped to 1s)
    // swaps the set and purges immediately. The mtime is bumped
    // strictly-newer so a coarse-mtime filesystem cannot alias the write
    // with the pre-boot one and skip the reload.
    write_denylist(&deny_path, format!("{sha}\n"));

    let status = poll_until(451u16, || async { get_blob(&relay, &sha).await.0 }).await;
    assert_eq!(status, 451, "exit30: GET must turn 451 after the reload");

    // Bytes unlinked, ledger released, purged counter incremented.
    assert!(
        !relay_blob_path(&relay, &sha).exists(),
        "exit30: purge must unlink the bytes"
    );
    let ledger = poll_until(g0, || global_ledger_bytes(relay.url())).await;
    assert_eq!(ledger, g0, "exit30: the blob charge must be released");
    let metrics = common::sync_helpers::ParsedMetrics::parse(
        &common::sync_helpers::fetch_metrics(relay.url())
            .await
            .expect("metrics scrape"),
    );
    assert!(
        metrics
            .counter("ngit_private_denylist_purged_total", &[])
            .unwrap_or(0)
            >= 1,
        "exit30: ngit_private_denylist_purged_total must increment"
    );
    assert_eq!(
        metrics
            .gauge("ngit_private_denylist_entries", &[])
            .unwrap_or(-1),
        1,
        "exit30: the live denylist must hold the one entry"
    );

    // /list no longer carries the blob.
    assert!(
        !list_blob_shas(&relay, &tenant).await.contains(&sha),
        "exit30: purged blob must leave /list"
    );

    // Re-upload is refused at the preflight.
    let (status, reason) = head_upload(&relay, &sha, 512, Some(&auth)).await;
    assert_eq!(
        status, 451,
        "exit30: re-upload preflight must be 451; X-Reason: {reason}"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 31 — Phase-4b D1: reload removal unblocks reads, not bytes
// ============================================================================
// Removing the sha from the file swaps it out of the live set: GET stops
// being 451 — but the purged bytes stayed gone (404, not 200), and the
// client must re-upload to restore the blob.

#[tokio::test]
async fn exit31_reload_removal_unblocks_read_but_bytes_stay_gone() {
    let dir = tempfile::tempdir().expect("denylist tempdir");
    let deny_path = dir.path().join("deny.txt");
    std::fs::write(&deny_path, "# initially empty\n").expect("write denylist");
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        (
            "NGIT_GRASP_P_DENYLIST_PATH",
            &deny_path.display().to_string(),
        ),
        ("NGIT_GRASP_P_DENYLIST_RELOAD_SECS", "1"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;

    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    let data = blob_bytes(204, 256);
    let sha = sha256_hex(&data);
    let auth = blossom_auth_event(
        &writer,
        "upload",
        &sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, data.clone(), &sha, &auth).await;
    assert_eq!(status, 200, "exit31: PUT must succeed; X-Reason: {reason}");

    // Takedown, wait for the purge. The mtime is bumped strictly-newer
    // (coarse-mtime filesystems could otherwise alias the writes and the
    // reload would never fire).
    write_denylist(&deny_path, format!("{sha}\n"));
    let status = poll_until(451u16, || async { get_blob(&relay, &sha).await.0 }).await;
    assert_eq!(status, 451, "exit31: GET must turn 451 after the reload");

    // Un-takedown: the next swap drops the entry; GET unblocks to 404
    // (purged bytes are gone — NOT resurrected), never back to 200.
    write_denylist(&deny_path, "# cleared\n".to_string());
    let status = poll_until(404u16, || async { get_blob(&relay, &sha).await.0 }).await;
    assert_eq!(
        status, 404,
        "exit31: removed-from-list GET must be 404 (purged), not 451 or 200"
    );

    // Re-upload succeeds (fresh charge) and reads back.
    let (status, _, reason) = put_blob(&relay, data.clone(), &sha, &auth).await;
    assert_eq!(
        status, 200,
        "exit31: re-upload must succeed; X-Reason: {reason}"
    );
    let (status, body) = get_blob(&relay, &sha).await;
    assert_eq!(status, 200, "exit31: re-uploaded GET must be 200");
    assert_eq!(body, data, "exit31: re-uploaded bytes must round-trip");

    relay.stop().await;
}

// ============================================================================
// Exit test 32 — Phase-4b D3: kind-1984 (NIP-56 report) intake
// ============================================================================
// Reports are observed (metric) and then admitted under the UNCHANGED
// related-event rules: one referencing the accepted 30640 is stored, one
// orphan is rejected — both increment ngit_private_report_events_total.

#[tokio::test]
async fn exit32_kind1984_report_intake() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let writer = Keys::generate();
    let alias = random_alias();
    let registration = register_alias(&relay, &tenant, &writer, &alias).await;
    let reporter = Keys::generate();

    // (a) A report referencing the accepted registration (e tag) and
    // carrying blob-sha evidence (x tag): stored per related-event rules.
    let blob_sha = sha256_hex(&blob_bytes(205, 64));
    let report = EventBuilder::new(Kind::Reporting, "takedown request")
        .tags(vec![
            Tag::custom("e", vec![registration.id.to_hex()]),
            Tag::custom("x", vec![blob_sha.clone()]),
        ])
        .finalize(&reporter)
        .expect("sign report");
    let (accepted, message) = publish_with_result(relay.url(), &report).await;
    assert!(
        accepted,
        "exit32: a report referencing accepted content must be stored; got {message:?}"
    );
    let served = fetch_from(relay.url(), Filter::new().kind(Kind::Reporting)).await;
    assert!(
        served.iter().any(|e| e.id == report.id),
        "exit32: the accepted report must be fetchable"
    );

    // (b) An orphan report (references nothing accepted): rejected as
    // today — observation happens regardless.
    let orphan = EventBuilder::new(Kind::Reporting, "orphan report")
        .tags(vec![Tag::custom(
            "e",
            vec![sha256_hex(&blob_bytes(206, 64))],
        )])
        .finalize(&reporter)
        .expect("sign orphan report");
    let (accepted, _) = publish_with_result(relay.url(), &orphan).await;
    assert!(
        !accepted,
        "exit32: an orphan report must keep being rejected (admission unchanged)"
    );

    // Both reports were observed by the intake arm.
    let metrics = common::sync_helpers::ParsedMetrics::parse(
        &common::sync_helpers::fetch_metrics(relay.url())
            .await
            .expect("metrics scrape"),
    );
    assert_eq!(
        metrics
            .counter("ngit_private_report_events_total", &[])
            .unwrap_or(0),
        2,
        "exit32: both reports must increment ngit_private_report_events_total"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 33 — FS-2 (review L3-F4): cadence-rejected 30640 replacements
// are held and retried after bucket refill
// ============================================================================
// Capacity 1, refill 3600/hour (1 token/sec — the NGIT_TEST-shrunk cadence
// knob). The burst drains the bucket; the flood replacement is rejected to
// the client (NIP-20 cadence message) AND held locally. The 5s sync timer
// (200ms under NGIT_TEST) re-offers the held edition through normal Live
// admission once wall-clock refill lands a token: the edition is accepted
// and served WITHOUT any client republish.

#[tokio::test]
async fn exit33_cadence_rejected_replacement_held_and_retried() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY", "1"),
        ("NGIT_GRASP_P_REGISTRATION_REPLACE_REFILL_PER_HOUR", "3600"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs();

    let ed1 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &ed1).await;
    assert!(accepted, "exit33: initial registration failed: {message:?}");

    // Drain the single replacement token.
    let ed2 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0 + 10),
    );
    let (accepted, message) = publish_with_result(relay.url(), &ed2).await;
    assert!(accepted, "exit33: burst replacement failed: {message:?}");

    // The next replacement is cadence-rejected to the client...
    let ed3 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0 + 20),
    );
    let (accepted, message) = publish_with_result(relay.url(), &ed3).await;
    assert!(
        !accepted && message.contains("replacement rate-limited; retry later"),
        "exit33: the flood replacement must be cadence-rejected; got: {message:?}"
    );
    // ...and is NOT served yet (the in-budget edition survives).
    let served_id = || async {
        fetch_from(
            relay.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(tenant.public_key())
                .identifier(&alias),
        )
        .await
        .first()
        .map(|e| e.id)
    };
    assert_eq!(
        served_id().await,
        Some(ed2.id),
        "exit33: the cadence-rejected edition must not be served immediately"
    );

    // WITHOUT any client republish, the held edition is retried by the
    // sync timer and accepted once the bucket refills (~1s at 1 token/sec).
    let healed = poll_until(Some(ed3.id), served_id).await;
    assert_eq!(
        healed,
        Some(ed3.id),
        "exit33: the held replacement must be accepted after refill with no client republish"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 34 — R2-1 (verify round 2): newest-only hold convergence
// ============================================================================
// Capacity 1, refill 1800/hour (1 token per 2s). The burst drains the
// bucket; E2 is cadence-rejected and HELD; the client then republishes a
// strictly newer E3 while the bucket is still empty — also cadence-rejected,
// so E3 REPLACES E2 in the newest-only (tenant, alias) hold. After refill
// the drain accepts E3 (never E2), the hold empties, and a stale E2
// republication is absorbed by the anchor-repair no-op (non-cadence
// rejection). Hold-emptiness is pinned behaviorally: a still-held E2 would
// win the FIFO drain race and be served first; the relay log must show the
// R2-1(d) per-tick drain summary (proof the heal rode the retry drain).

#[tokio::test]
async fn exit34_cadence_rejected_newest_only_convergence() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY", "1"),
        ("NGIT_GRASP_P_REGISTRATION_REPLACE_REFILL_PER_HOUR", "1800"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
    ])
    .await;
    let writer = Keys::generate();
    let alias = random_alias();
    let t0 = Timestamp::now().as_secs();

    let ed1 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0),
    );
    let (accepted, message) = publish_with_result(relay.url(), &ed1).await;
    assert!(accepted, "exit34: initial registration failed: {message:?}");

    // Drain the single replacement token.
    let ed_burst = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0 + 10),
    );
    let (accepted, message) = publish_with_result(relay.url(), &ed_burst).await;
    assert!(accepted, "exit34: burst replacement failed: {message:?}");

    // E2: cadence-rejected to the client and held.
    let e2 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0 + 20),
    );
    let (accepted, message) = publish_with_result(relay.url(), &e2).await;
    assert!(
        !accepted && message.contains("replacement rate-limited; retry later"),
        "exit34: E2 must be cadence-rejected; got: {message:?}"
    );

    // The client republishes a STRICTLY NEWER E3 while the bucket is still
    // empty: also cadence-rejected, so E3 displaces E2 in the newest-only
    // hold (E2 keeps only an id-only skip-set entry).
    let e3 = registration_event(
        &tenant,
        &alias,
        &[key_entry(&writer, &tenant.public_key(), &alias)],
        &[],
        &relay.domain(),
        Some(t0 + 30),
    );
    let (accepted, message) = publish_with_result(relay.url(), &e3).await;
    assert!(
        !accepted && message.contains("replacement rate-limited; retry later"),
        "exit34: E3 must also be cadence-rejected (bucket still empty); got: {message:?}"
    );

    let served_id = || async {
        fetch_from(
            relay.url(),
            Filter::new()
                .kind(Kind::Custom(30640))
                .author(tenant.public_key())
                .identifier(&alias),
        )
        .await
        .first()
        .map(|e| e.id)
    };
    assert_eq!(
        served_id().await,
        Some(ed_burst.id),
        "exit34: neither cadence-rejected edition may be served immediately"
    );

    // After refill the drain offers the held NEWEST (E3) — accepted with no
    // further client action. E2 must NEVER be served: a still-held E2 would
    // have won the FIFO drain race, so E3-first proves the newest-only
    // replacement AND that the hold emptied on E3's accept.
    let healed = poll_until(Some(e3.id), served_id).await;
    assert_eq!(
        healed,
        Some(e3.id),
        "exit34: the drain must accept the held newest edition (E3), never E2"
    );

    // The heal rode the R2-1 retry drain: the per-tick summary line
    // (retried > 0) must appear in the relay log.
    let port = relay
        .url()
        .rsplit(':')
        .next()
        .expect("relay url has a port");
    let log = std::fs::read_to_string(format!("/tmp/relay-{port}.log")).expect("relay log");
    assert!(
        log.contains("Private cadence-rejected 30640 retry drain"),
        "exit34: the R2-1(d) drain summary must be logged while the hold was non-empty"
    );

    // E2 absorbed: a stale republication is the anchor-repair no-op — a
    // NON-cadence rejection (exit27 pins the stale message), and the served
    // edition stays E3.
    let (accepted, message) = publish_with_result(relay.url(), &e2).await;
    assert!(
        !accepted && !message.contains("replacement rate-limited; retry later"),
        "exit34: stale E2 must be absorbed (non-cadence rejection); got: {message:?}"
    );
    assert_eq!(
        served_id().await,
        Some(e3.id),
        "exit34: the absorbed E2 must not displace E3"
    );

    relay.stop().await;
}

// ============================================================================
// Exit test 35 — phase-4b exit gate: sybil-load soak under whitelist
// ============================================================================

/// Leg 1 pins the whitelist flood path: 50 well-formed sybil registrations
/// (valid shape, valid PoPs) are ALL rejected, nothing is stored or charged
/// (aliases gauge 0, global ledger 0, anonymous REQ empty, flooded-alias
/// upload preflight 403), and the one whitelisted tenant then registers and
/// operates normally — 50 rejections do not poison relay state.
///
/// Leg 2 pins budget survival: the same 50-flood, now whitelisted with tiny
/// per-tenant/per-repo caps against a generous global budget — every sybil
/// registers, fills to its cap, then 507s, while the global ledger stays far
/// below budget and a 51st tenant still gets full service (quota isolation
/// holds; no cross-tenant interference).
#[tokio::test]
async fn exit35_sybil_soak_under_whitelist() {
    const SYBILS: usize = 50;

    // ---- Leg 1: registration flood against a whitelist relay -------------
    let legit = Keys::generate();
    let legit_npub = legit.public_key().to_bech32().expect("npub");
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_REGISTRATION_MODE", "whitelist"),
        ("NGIT_GRASP_P_TENANT_WHITELIST", legit_npub.as_str()),
        ("NGIT_GRASP_P_QUOTA_REPO_BYTES", "1048576"),
        ("NGIT_GRASP_P_QUOTA_TENANT_BYTES", "1048576"),
        ("NGIT_GRASP_P_GLOBAL_BUDGET_BYTES", "4194304"),
    ])
    .await;

    let doc = nip11_doc(&relay).await;
    assert_eq!(
        doc["private_repos"]["registration_mode"], "whitelist",
        "exit35: NIP-11 must advertise whitelist mode; got {doc}"
    );

    // The flood: every attempt is a fresh tenant with a valid registration.
    let mut flooded: Vec<(Keys, Keys, String)> = Vec::with_capacity(SYBILS);
    for i in 0..SYBILS {
        let sybil = Keys::generate();
        let writer = Keys::generate();
        let alias = random_alias();
        let reg = registration_event(
            &sybil,
            &alias,
            &[key_entry(&writer, &sybil.public_key(), &alias)],
            &[],
            &relay.domain(),
            None,
        );
        let (accepted, message) = publish_with_result(relay.url(), &reg).await;
        assert!(
            !accepted && message.contains("restricted:") && message.contains("whitelist"),
            "exit35: sybil #{i} must be whitelist-rejected; got: {message:?}"
        );
        flooded.push((sybil, writer, alias));
    }

    // Nothing landed: no aliases, no ledger bytes, nothing served.
    let metrics = common::sync_helpers::ParsedMetrics::parse(
        &common::sync_helpers::fetch_metrics(relay.url())
            .await
            .expect("metrics scrape"),
    );
    assert_eq!(
        metrics.gauge("ngit_private_aliases_total", &[]),
        Some(0),
        "exit35: the flood must leave zero live aliases"
    );
    assert_eq!(
        global_ledger_bytes(relay.url()).await,
        0,
        "exit35: rejected registrations must charge nothing to the ledger"
    );
    let served = fetch_from(relay.url(), Filter::new().kind(Kind::Custom(30640))).await;
    assert!(
        served.is_empty(),
        "exit35: anonymous REQ must serve none of the flooded registrations"
    );

    // A flooded alias cannot upload either (no live registration → 403).
    let (sybil0, sybil0_writer, sybil0_alias) = &flooded[0];
    let flood_sha = sha256_hex(&blob_bytes(59, 512));
    let flood_auth = blossom_auth_event(
        sybil0_writer,
        "upload",
        &flood_sha,
        &sybil0.public_key(),
        sybil0_alias,
        future_expiration(),
    );
    let (status, reason) = head_upload(&relay, &flood_sha, 512, Some(&flood_auth)).await;
    assert_eq!(
        status, 403,
        "exit35: upload preflight for a flooded alias must be 403; X-Reason: {reason}"
    );

    // The soak assertion: the whitelisted tenant operates normally AFTER the
    // flood — register, upload, 30641, GET 200.
    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &legit, &writer, &alias).await;
    let blob = blob_bytes(60, 2048);
    let sha = sha256_hex(&blob);
    let auth = blossom_auth_event(
        &writer,
        "upload",
        &sha,
        &legit.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, blob.clone(), &sha, &auth).await;
    assert_eq!(
        status, 200,
        "exit35: legit upload after the flood must be 200; X-Reason: {reason}"
    );
    let edition = state_root_event(
        &writer,
        &legit.public_key(),
        &alias,
        (&sha, blob.len() as u64),
        &[],
        Timestamp::now().as_secs(),
    );
    let (accepted, message) = publish_with_result(relay.url(), &edition).await;
    assert!(
        accepted,
        "exit35: legit 30641 after the flood must be accepted; got {message:?}"
    );
    let (status, body) = get_blob(&relay, &sha).await;
    assert_eq!(status, 200, "exit35: legit blob must be GET-able");
    assert_eq!(body, blob, "exit35: legit blob bytes must round-trip");

    let metrics = common::sync_helpers::ParsedMetrics::parse(
        &common::sync_helpers::fetch_metrics(relay.url())
            .await
            .expect("metrics scrape"),
    );
    assert_eq!(
        metrics.gauge("ngit_private_aliases_total", &[]),
        Some(1),
        "exit35: exactly the legit alias must be live after the flood"
    );
    assert!(
        global_ledger_bytes(relay.url()).await > 0,
        "exit35: the legit tenant's footprint must be charged"
    );
    relay.stop().await;

    // ---- Leg 2: same flood whitelisted, tiny caps, generous global budget -
    // 51 tenants (50 flood + 1 post-flood probe), each capped at 8 KiB.
    let tenants: Vec<Keys> = (0..=SYBILS).map(|_| Keys::generate()).collect();
    let whitelist = whitelist_npubs(&tenants.iter().collect::<Vec<_>>());
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
        ("NGIT_GRASP_P_QUOTA_REPO_BYTES", "8192"),
        ("NGIT_GRASP_P_QUOTA_TENANT_BYTES", "8192"),
        ("NGIT_GRASP_P_GLOBAL_BUDGET_BYTES", "4194304"),
    ])
    .await;

    for (i, tenant) in tenants[..SYBILS].iter().enumerate() {
        let writer = Keys::generate();
        let alias = random_alias();
        register_alias(&relay, tenant, &writer, &alias).await;

        // Fill to the cap: reg (~700 B) + 4 KiB blob fits the 8 KiB scope.
        let blob1 = blob_bytes(i as u8, 4096);
        let sha1 = sha256_hex(&blob1);
        let auth1 = blossom_auth_event(
            &writer,
            "upload",
            &sha1,
            &tenant.public_key(),
            &alias,
            future_expiration(),
        );
        let (status, _, reason) = put_blob(&relay, blob1, &sha1, &auth1).await;
        assert_eq!(
            status, 200,
            "exit35: sybil #{i} in-cap upload must be 200; X-Reason: {reason}"
        );

        // The next blob would exceed the tenant/repo cap → 507 at preflight.
        let blob2 = blob_bytes((i as u8).wrapping_add(128), 8192);
        let sha2 = sha256_hex(&blob2);
        let auth2 = blossom_auth_event(
            &writer,
            "upload",
            &sha2,
            &tenant.public_key(),
            &alias,
            future_expiration(),
        );
        let (status, reason) = head_upload(&relay, &sha2, blob2.len() as u64, Some(&auth2)).await;
        assert_eq!(
            status, 507,
            "exit35: sybil #{i} over-cap preflight must be 507; X-Reason: {reason}"
        );
    }

    // Budget survival: 50 capped tenants consumed ~250 KiB of the 4 MiB
    // global budget — far from exhausted.
    let global = global_ledger_bytes(relay.url()).await;
    assert!(
        global > 0 && global < 4_194_304 / 4,
        "exit35: the global budget must survive the capped flood; ledger: {global}"
    );

    // And a 51st whitelisted tenant still gets full service.
    let probe = &tenants[SYBILS];
    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, probe, &writer, &alias).await;
    let blob = blob_bytes(200, 4096);
    let sha = sha256_hex(&blob);
    let auth = blossom_auth_event(
        &writer,
        "upload",
        &sha,
        &probe.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, blob.clone(), &sha, &auth).await;
    assert_eq!(
        status, 200,
        "exit35: post-flood tenant upload must be 200; X-Reason: {reason}"
    );
    let (status, body) = get_blob(&relay, &sha).await;
    assert_eq!(
        status, 200,
        "exit35: post-flood tenant blob must be GET-able"
    );
    assert_eq!(body, blob, "exit35: post-flood tenant blob must round-trip");

    relay.stop().await;
}

// ============================================================================
// Exit tests 36-39 — stream wraps in the shape GRASP-P actually ships
// ============================================================================
//
// The pre-existing wrap coverage does NOT pin this shape. G3
// (tests/phase0_gates.rs) runs with NGIT_GRASP_P_REPOS_ENABLE unset and uses
// a p-tagged AND a-tagged fixture, so it only exercises the PUBLIC
// related-event path. exit3 above does enable private repos with a
// registered outer author, but its fixture is p-tagged too — so the wrap
// would satisfy the public policy even if the private arm vanished.
//
// A real GRASP-P stream wrap is TAGLESS: no `p` (there is no NIP-59
// recipient — the wrap is symmetric-AEAD to an epoch key), and no `a` (the
// server must not learn which repo a wrap belongs to). Such an event is an
// ORPHAN to the public related-event policy, so admission can ONLY come from
// the private wrap arm. These tests pin that, on both wire kinds across the
// 1059 -> 3359 migration window.

/// A stream wrap as actually shipped: opaque ciphertext, NO `p` tag, NO `a`
/// tag. Admission is possible only via the GRASP-P private wrap arm.
fn tagless_wrap_event(signer: &Keys, kind: u16) -> Event {
    EventBuilder::new(
        Kind::Custom(kind),
        "AtQyM3BhY2VvcGFxdWUtY2lwaGVydGV4dC1zdGFuZC1pbg==",
    )
    .finalize(signer)
    .expect("sign tagless wrap")
}

/// Full admission contract for a TAGLESS stream wrap of `wrap_kind`:
/// admitted from a registered outer key, quota-charged, stored, and served
/// to a completely anonymous (never-AUTHed) reader.
async fn assert_tagless_wrap_admitted(wrap_kind: u16, extra_env: &[(&str, &str)]) {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let mut env: Vec<(&str, &str)> = vec![("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())];
    env.extend_from_slice(extra_env);
    let relay = TestRelay::start_with_grasp_p(&env).await;

    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    let before = global_ledger_bytes(relay.url()).await;
    assert!(
        before > 0,
        "kind {wrap_kind}: the registration must already be on the ledger"
    );

    let wrap = tagless_wrap_event(&writer, wrap_kind);
    assert!(
        wrap.tags.is_empty(),
        "kind {wrap_kind}: the fixture must carry NO tags — a p/a-tagged wrap \
         could be admitted by the public related-event path instead"
    );
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        accepted,
        "kind {wrap_kind}: a tagless wrap from a registered write key must be \
         admitted by the private arm; got {message:?}"
    );

    // Quota: a stored wrap is charged its serialized size, exactly once.
    let wrap_bytes = wrap.as_json().len() as i64;
    let after = poll_until(before + wrap_bytes, || global_ledger_bytes(relay.url())).await;
    assert_eq!(
        after,
        before + wrap_bytes,
        "kind {wrap_kind}: the stored wrap must be quota-charged its event bytes"
    );

    // Stored AND served to a client that never AUTHed (§ no read gate).
    let anon = connect_anonymous_client(relay.url()).await;
    let served = anon
        .fetch_events(Filter::new().kind(Kind::Custom(wrap_kind)))
        .timeout(Duration::from_secs(10))
        .await
        .expect("anonymous fetch failed");
    let served: Vec<Event> = served.into_iter().collect();
    assert!(
        served.iter().any(|e| e.id == wrap.id),
        "kind {wrap_kind}: the stored tagless wrap must be served to an \
         anonymous REQ"
    );
    anon.disconnect().await;

    relay.stop().await;
}

/// The legacy wire kind, under the shipped dual-accept default.
///
/// Since nostr-sdk 0.45 (ngit-grasp v3) the relay itself refuses a kind-1059
/// event without exactly one `p` tag, before any write policy runs. The
/// tagless form clients sent before the 3359 migration therefore no longer
/// reaches the private arm at all; a 1059 with one `p` tag from a registered
/// key still does, and is admitted, charged and served exactly as before.
#[tokio::test]
async fn exit36_tagless_stream_wrap_legacy_kind() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    let tagless = tagless_wrap_event(&writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &tagless).await;
    assert!(
        !accepted && message.contains("GiftWrap must contain exactly one recipient"),
        "kind 1059: a tagless wrap is refused by the relay's NIP-59 shape check; \
         got accepted={accepted} {message:?}"
    );

    let before = global_ledger_bytes(relay.url()).await;
    let wrap = wrap_event(&writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        accepted,
        "kind 1059: a p-tagged wrap from a registered write key must be admitted \
         by the private arm; got {message:?}"
    );
    let wrap_bytes = wrap.as_json().len() as i64;
    let after = poll_until(before + wrap_bytes, || global_ledger_bytes(relay.url())).await;
    assert_eq!(
        after,
        before + wrap_bytes,
        "kind 1059: the stored wrap must be quota-charged its event bytes"
    );
    let anon = connect_anonymous_client(relay.url()).await;
    let served: Vec<Event> = anon
        .fetch_events(Filter::new().kind(Kind::Custom(1059)))
        .timeout(Duration::from_secs(10))
        .await
        .expect("anonymous fetch failed")
        .into_iter()
        .collect();
    assert!(
        served.iter().any(|e| e.id == wrap.id),
        "kind 1059: the stored wrap must be served to an anonymous REQ"
    );
    anon.disconnect().await;

    relay.stop().await;
}

/// The new dedicated wire kind. This is the ordering-critical half of the
/// migration: the server must accept 3359 BEFORE any client emits it.
///
/// Numbered exit39, out of file order, because it is exit36's twin: exit
/// numbers are quoted from the ops docs, so "exit36 failed" must name
/// exactly one test.
#[tokio::test]
async fn exit39_tagless_stream_wrap_new_kind() {
    assert_tagless_wrap_admitted(3359, &[]).await;
}

/// §3.2 gating and the ephemeral contract on the NEW kinds: an unregistered
/// outer key is rejected outright on both 3359 and 23359, and a 23359 from a
/// registered key is admitted but NEVER stored.
#[tokio::test]
async fn exit37_new_wrap_kind_gating_and_ephemerality() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;
    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    // (a) 3359 from an unregistered key: rejected outright. NOT a
    // fall-through to the public related-event path — §3.2 requires the
    // outer author to be in w∪aux of a live registration, otherwise every
    // deregistered rekey address is permanently floodable.
    let foreign = tagless_wrap_event(&Keys::generate(), 3359);
    let (accepted, message) = publish_with_result(relay.url(), &foreign).await;
    assert!(!accepted, "exit37: unregistered 3359 must be rejected");
    assert!(
        message.contains("restricted:") && message.contains("unregistered key"),
        "exit37: unregistered 3359 must be refused as an unregistered key; got {message:?}"
    );

    // (b) 23359 from an unregistered key: same gate on the ephemeral arm.
    let foreign_ephemeral = tagless_wrap_event(&Keys::generate(), 23359);
    let (accepted, message) = publish_with_result(relay.url(), &foreign_ephemeral).await;
    assert!(!accepted, "exit37: unregistered 23359 must be rejected");
    assert!(
        message.contains("unregistered key"),
        "exit37: unregistered 23359 must be refused as an unregistered key; got {message:?}"
    );

    // (c) 23359 from the registered key: accepted, never stored, and — the
    // invariant that actually bounds the abuse — NEVER QUOTA-CHARGED.
    //
    // Ephemeral wraps have no credit path: `quota::charge` is unwound only
    // by `reset_alias_event_bytes` at registration death, and the GC sweeps
    // blobs, never event bytes. So if an ephemeral wrap were charged, a
    // registered write key could drive (tenant, alias).event_bytes to the
    // cap with distinct-id wraps that store ZERO bytes — the repo is then
    // permanently bricked and invisible as "storage used". The whole
    // defence is `try_handle_wrap(event, /* ephemeral */ true)` in
    // builder.rs; NGIT_GRASP_P_WRITE_RATE_CAPACITY's doc names this abuse
    // and ASSUMES this invariant, so pin it here.
    //
    // The assertion is bracketed with a POSITIVE CONTROL (a stored 3359
    // charged in the same window) so it cannot pass vacuously: the final
    // ledger must equal before + the 3359's bytes EXACTLY — a charged
    // ephemeral shows up as the extra term.
    let before = global_ledger_bytes(relay.url()).await;
    assert!(
        before > 0,
        "exit37: the registration must already be on the ledger"
    );

    let ephemeral = tagless_wrap_event(&writer, 23359);
    let (accepted, message) = publish_with_result(relay.url(), &ephemeral).await;
    assert!(
        accepted,
        "exit37: registered-key 23359 must be accepted; got {message:?}"
    );
    let stored = fetch_from(relay.url(), Filter::new().kind(Kind::Custom(23359))).await;
    assert!(
        stored.is_empty(),
        "exit37: 23359 is ephemeral and must never be stored; got {} events",
        stored.len()
    );

    // Positive control: a STORED 3359 in the same window must move the
    // ledger by exactly its own serialized size.
    let charged = tagless_wrap_event(&writer, 3359);
    let (accepted, message) = publish_with_result(relay.url(), &charged).await;
    assert!(
        accepted,
        "exit37: registered-key 3359 must be accepted; got {message:?}"
    );
    let charged_bytes = charged.as_json().len() as i64;
    let want = before + charged_bytes;
    let after = poll_until(want, || global_ledger_bytes(relay.url())).await;
    assert_eq!(
        after,
        want,
        "exit37: the ledger must move by the STORED 3359 only — the \
         ephemeral 23359 must never be quota-charged (ephemeral wrap bytes \
         have no credit path, so charging them bricks the scope with zero \
         bytes stored). before={before} charged_3359_bytes={charged_bytes} \
         ephemeral_23359_bytes={}",
        ephemeral.as_json().len()
    );

    relay.stop().await;
}

/// NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND=false closes the migration window:
/// the legacy kinds stop being stream wraps (a tagless 1059 is then just an
/// orphan) while 3359 keeps working — and the NIP-11 advert follows, so a
/// client can discover the change instead of guessing.
#[tokio::test]
async fn exit38_legacy_wrap_kind_can_be_disabled() {
    let tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant]);
    let relay = TestRelay::start_with_grasp_p(&[
        ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
        ("NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND", "false"),
    ])
    .await;
    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;

    // The advert drops the legacy kinds and keeps the new ones.
    let doc = nip11_doc(&relay).await;
    let private = doc
        .get("private_repos")
        .expect("exit38: NIP-11 must contain private_repos when enabled");
    let kinds: Vec<u64> = private["kinds"]
        .as_array()
        .expect("private_repos.kinds array")
        .iter()
        .filter_map(|k| k.as_u64())
        .collect();
    assert!(
        kinds.contains(&3359) && kinds.contains(&23359),
        "exit38: the new stream-wrap kinds must stay advertised; got {kinds:?}"
    );
    assert!(
        !kinds.contains(&1059) && !kinds.contains(&21059),
        "exit38: the legacy wrap kinds must leave the advert; got {kinds:?}"
    );

    // A 1059 from the REGISTERED write key is no longer a stream wrap: the
    // legacy kinds are RETIRED and refused outright. (It carries one `p` tag
    // so that nostr-sdk's own NIP-59 shape check lets it reach the policy.)
    let legacy = wrap_event(&writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &legacy).await;
    assert!(
        !accepted,
        "exit38: a legacy 1059 stream wrap must be rejected once legacy \
         accept is off; got {message:?}"
    );
    assert!(
        message.contains("restricted:") && message.contains("legacy stream-wrap kind"),
        "exit38: the retired legacy wrap must be refused by the private \
         retired-kind arm; got {message:?}"
    );
    let stored = fetch_from(relay.url(), Filter::new().kind(Kind::Custom(1059))).await;
    assert!(
        stored.is_empty(),
        "exit38: the rejected legacy wrap must not be stored"
    );

    // The case that decides whether "off" NARROWS the accepted set: a 1059
    // carrying an `a` tag that references accepted content. Without an
    // explicit retired-kind arm, such an event falls past every private arm
    // onto the PUBLIC related-event policy, which stores anything
    // referencing an accepted coordinate — from ANY key, with no §3.2
    // registered-key gate, no private_max_event_bytes cap, no private quota
    // charge and no private GC. That would make legacy-OFF strictly more
    // permissive than legacy-ON (where an unregistered 1059 is rejected
    // outright), so the retired kinds are refused before that path.
    //
    // The coordinate is the tenant's own 30640 — derivable by anyone who
    // can read the registration, so this is an UNREGISTERED author.
    let coordinate = format!("30640:{}:{alias}", tenant.public_key().to_hex());
    let a_tagged = EventBuilder::new(
        Kind::Custom(1059),
        "AtQyM3BhY2VvcGFxdWUtY2lwaGVydGV4dC1zdGFuZC1pbg==",
    )
    .tags(vec![
        Tag::custom("a", vec![coordinate.clone()]),
        Tag::public_key(Keys::generate().public_key()),
    ])
    .finalize(&Keys::generate())
    .expect("sign a-tagged legacy wrap");
    let (accepted, message) = publish_with_result(relay.url(), &a_tagged).await;
    assert!(
        !accepted,
        "exit38: an `a`-tagged 1059 must NOT be reclassified onto the public \
         related-event path once legacy accept is off — that path would store \
         it from any key, uncharged and outside private quota/GC; got \
         {message:?}"
    );
    assert!(
        message.contains("restricted:") && message.contains("legacy stream-wrap kind"),
        "exit38: the `a`-tagged legacy wrap must be refused by the retired-kind \
         arm, not by the public orphan check; got {message:?}"
    );
    let stored = fetch_from(relay.url(), Filter::new().kind(Kind::Custom(1059))).await;
    assert!(
        stored.is_empty(),
        "exit38: no 1059 may be stored once legacy accept is off; got {} event(s)",
        stored.len()
    );

    // The ephemeral legacy kind is retired on the same terms.
    let legacy_ephemeral = tagless_wrap_event(&writer, 21059);
    let (accepted, message) = publish_with_result(relay.url(), &legacy_ephemeral).await;
    assert!(
        !accepted && message.contains("legacy stream-wrap kind"),
        "exit38: a legacy 21059 must be rejected once legacy accept is off; \
         got accepted={accepted} {message:?}"
    );

    // ...while the new kind still round-trips end to end.
    let wrap = tagless_wrap_event(&writer, 3359);
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        accepted,
        "exit38: 3359 must still be admitted with legacy accept off; got {message:?}"
    );
    let served = fetch_from(relay.url(), Filter::new().kind(Kind::Custom(3359))).await;
    assert!(
        served.iter().any(|e| e.id == wrap.id),
        "exit38: the 3359 wrap must be stored and served"
    );

    relay.stop().await;
}

// ============================================================================
// exit40 — GET /list/<pubkey> answers only the listed key (issue 14)
// ============================================================================
// A tenant's blob inventory (hashes, sizes, count) is metadata the encryption
// does not cover, and an open /list also told anyone whether a pubkey is a
// tenant here. The route needs a kind-24242 `list` authorization signed by the
// listed pubkey, and every refusal is the same response: for a tenant with
// blobs, a tenant with none, and a pubkey this node has never seen.

#[tokio::test]
async fn exit40_list_answers_only_the_listed_key() {
    let tenant = Keys::generate();
    let empty_tenant = Keys::generate();
    let whitelist = whitelist_npubs(&[&tenant, &empty_tenant]);
    let relay =
        TestRelay::start_with_grasp_p(&[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())])
            .await;

    let writer = Keys::generate();
    let alias = random_alias();
    register_alias(&relay, &tenant, &writer, &alias).await;
    register_alias(&relay, &empty_tenant, &Keys::generate(), &random_alias()).await;

    let data = blob_bytes(240, 512);
    let sha = sha256_hex(&data);
    let upload = blossom_auth_event(
        &writer,
        "upload",
        &sha,
        &tenant.public_key(),
        &alias,
        future_expiration(),
    );
    let (status, _, reason) = put_blob(&relay, data, &sha, &upload).await;
    assert_eq!(status, 200, "exit40: PUT must succeed; X-Reason: {reason}");

    // The listed key's own authorization gets its inventory.
    assert_eq!(
        list_blob_shas(&relay, &tenant).await,
        vec![sha.clone()],
        "exit40: the tenant must see its one blob"
    );
    // BUD-11's form of the token, base64url without padding, works as well as
    // the standard base64 the helper sends, and so do the two forms in between.
    // The helper's own event cannot show it: its JSON is ASCII whose length is
    // a multiple of three, so every form of its token is the same text. This
    // content forces the difference. Of three consecutive '?' one encodes to
    // '_' and of three '>' one to '-' ('/' and '+' in the standard alphabet),
    // and of three consecutive lengths two need padding.
    let mut unpadded = 0;
    for content in ["???>>>", "???>>>.", "???>>>.."] {
        let json = list_event(&tenant, 24242, "list", future_expiration(), content).as_json();
        let url_safe_no_pad = BASE64_URL_SAFE_NO_PAD.encode(json.as_bytes());
        assert!(
            url_safe_no_pad.contains('-') && url_safe_no_pad.contains('_'),
            "exit40: the token must use the URL-safe alphabet: {url_safe_no_pad}"
        );
        if !url_safe_no_pad.len().is_multiple_of(4) {
            unpadded += 1;
        }
        for token in [
            url_safe_no_pad,
            BASE64_URL_SAFE.encode(json.as_bytes()),
            BASE64_STANDARD_NO_PAD.encode(json.as_bytes()),
        ] {
            let authorization = format!("Nostr {token}");
            let (status, reason, _) = get_list(
                &relay,
                &tenant.public_key().to_hex(),
                Some(authorization.as_str()),
            )
            .await;
            assert_eq!(
                status, 200,
                "exit40: the token {token} must be accepted; X-Reason: {reason}"
            );
        }
    }
    assert_eq!(
        unpadded, 2,
        "exit40: two of the three tokens must lack the padding base64 would add"
    );
    // A tenant with no blobs, and a key this node has never seen, each get
    // their own empty list.
    assert!(
        list_blob_shas(&relay, &empty_tenant).await.is_empty(),
        "exit40: a tenant with no blobs lists nothing"
    );
    assert!(
        list_blob_shas(&relay, &Keys::generate()).await.is_empty(),
        "exit40: an unknown key lists nothing of its own"
    );

    // Refusals: nobody else's authorization, and no malformed one, opens a
    // list. The alias's own write key is not the listed key either.
    let stranger = Keys::generate();
    let by_writer = auth_header_value(&list_auth_event(&writer, "list", future_expiration()));
    let by_stranger = auth_header_value(&list_auth_event(&stranger, "list", future_expiration()));
    let wrong_verb = auth_header_value(&list_auth_event(&tenant, "upload", future_expiration()));
    let expired = auth_header_value(&list_auth_event(
        &tenant,
        "list",
        Timestamp::now().as_secs() - 60,
    ));
    // A stranger's valid authorization with the tenant's pubkey written over
    // the stranger's: the id and the signature no longer cover the event.
    let forged_event = Event::from_json(
        list_auth_event(&stranger, "list", future_expiration())
            .as_json()
            .replace(
                &stranger.public_key().to_hex(),
                &tenant.public_key().to_hex(),
            ),
    )
    .expect("forged JSON still parses");
    assert_eq!(
        forged_event.pubkey,
        tenant.public_key(),
        "exit40: the forged event must name the tenant"
    );
    let forged = auth_header_value(&forged_event);
    // Signed by the tenant, `t` = list, unexpired, but a NIP-98 event (kind
    // 27235) and not a Blossom authorization.
    let wrong_kind = auth_header_value(&list_event(
        &tenant,
        27235,
        "list",
        future_expiration(),
        "grasp-p test list auth",
    ));
    let targets = [
        tenant.public_key().to_hex(),
        empty_tenant.public_key().to_hex(),
        Keys::generate().public_key().to_hex(),
    ];
    let attempts = [
        None,
        Some(by_writer.as_str()),
        Some(by_stranger.as_str()),
        Some(wrong_verb.as_str()),
        Some(expired.as_str()),
        Some(forged.as_str()),
        Some(wrong_kind.as_str()),
        Some("Nostr not-base64!"),
        Some("Bearer anything"),
    ];
    let mut refusals = Vec::new();
    for target in &targets {
        for authorization in attempts {
            refusals.push(get_list(&relay, target, authorization).await);
        }
    }
    let first = refusals[0].clone();
    assert_eq!(first.0, 401, "exit40: a refused list is a 401");
    assert!(first.2.is_empty(), "exit40: a refused list has no body");
    for (index, refusal) in refusals.iter().enumerate() {
        assert_eq!(
            refusal, &first,
            "exit40: refusal {index} must be identical to the first (status, reason, body)"
        );
    }

    // Headers too, not only X-Reason: one that appeared for real tenants
    // alone would reopen the oracle. `date` is the only one that may differ.
    let mut header_sets = Vec::new();
    for target in &targets {
        let response = reqwest::Client::new()
            .get(format!("{}/list/{}", http_base(&relay), target))
            .send()
            .await
            .expect("GET /list transport");
        let mut headers: Vec<(String, Vec<u8>)> = response
            .headers()
            .iter()
            .filter(|(name, _)| name.as_str() != "date")
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect();
        headers.sort();
        header_sets.push(headers);
    }
    assert!(
        header_sets.windows(2).all(|pair| pair[0] == pair[1]),
        "exit40: refused lists must carry identical headers: {header_sets:?}"
    );

    relay.stop().await;
}
