//! GRASP-P Phase-1 exit test suite (design contract §10).
//!
//! Drives a live ngit-grasp subprocess (TestRelay + NGIT_PRIVATE_* env vars)
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

use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use nostr::hashes::{sha256, Hash};
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
    let digest = sha256::Hash::hash(
        format!("grasp-p key-claim:{}:{alias}", tenant.to_hex()).as_bytes(),
    );
    key.sign_schnorr(&nostr::secp256k1::Message::from_digest(
        digest.to_byte_array(),
    ))
    .to_string()
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
    let mut builder = EventBuilder::new(Kind::Custom(30640), "")
        .tags(registration_tags(alias, w_entries, aux_entries, domain));
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
        .request(reqwest::Method::HEAD, format!("{}/upload", http_base(relay)))
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
        .map(|i| (seed as usize).wrapping_mul(31).wrapping_add(i.wrapping_mul(2654435761)) as u8)
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
    // Plain TestRelay: NGIT_PRIVATE_REPOS_ENABLE defaults to false.
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
    assert_eq!(head_status, 404, "exit1: HEAD /upload must 404 when disabled");

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
    let relay = TestRelay::start_with_private_repos(&[]).await;
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
        kinds.contains(&30640) && kinds.contains(&30641) && kinds.contains(&1059),
        "exit2: NIP-11 kinds must list the private kinds; got {kinds:?}"
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
    assert_eq!(served.len(), 1, "exit2: registration must round-trip via REQ");
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
    assert_eq!(status, 200, "exit2: preflight must be 200; X-Reason: {reason}");

    // PUT both blobs; descriptors must carry the committed sha + size.
    let (status, descriptor, reason) = put_blob(&relay, blob1.clone(), &sha1, &auth1).await;
    assert_eq!(status, 200, "exit2: PUT blob1 must be 200; X-Reason: {reason}");
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
    assert_eq!(status, 200, "exit2: PUT blob2 must be 200; X-Reason: {reason}");
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
    assert!(accepted, "exit2: first 30641 must be accepted; got {message:?}");

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
    assert_eq!(status, 200, "exit2: PUT blob3 must be 200; X-Reason: {reason}");

    let edition2 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&sha3, blob3.len() as u64),
        &[(sha2.clone(), blob2.len() as u64)],
        t0 + 5,
    );
    let (accepted, message) = publish_with_result(relay.url(), &edition2).await;
    assert!(accepted, "exit2: second 30641 must be accepted; got {message:?}");

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
    let relay = TestRelay::start_with_private_repos(&[]).await;
    let tenant = Keys::generate();
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

    // (b) 1059 signed by the registered write key: accepted, stored, and
    // served to a completely anonymous client.
    let wrap = wrap_event(&writer, 1059);
    let (accepted, message) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        accepted,
        "exit3: registered-key 1059 must be accepted; got {message:?}"
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

    // (d) 21059 from an unregistered key also falls through and is vetoed.
    let foreign_eph = wrap_event(&Keys::generate(), 21059);
    let (accepted, message) = publish_with_result(relay.url(), &foreign_eph).await;
    assert!(
        !accepted && message.contains("restricted:"),
        "exit3: foreign-key 21059 must be vetoed; got accepted={accepted} {message:?}"
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
    let relay = TestRelay::start_with_private_repos(&[
        ("NGIT_PRIVATE_QUOTA_REPO_BYTES", "4096"),
        ("NGIT_PRIVATE_MAX_BLOB_BYTES", "8192"),
    ])
    .await;
    let tenant = Keys::generate();
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
    assert_eq!(status, 200, "exit4: blob1 must fit the quota; X-Reason: {reason}");

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
    assert_eq!(status, 507, "exit4: over-quota PUT must be 507; X-Reason: {reason}");
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
    assert_eq!(status, 404, "exit4: aborted upload must leave no blob behind");

    relay.stop().await;
}

// ============================================================================
// Exit test 5 — Blossom auth failures
// ============================================================================

#[tokio::test]
async fn exit5_blossom_auth_failures() {
    let relay = TestRelay::start_with_private_repos(&[]).await;

    // Alias A: tenant_a + writer_a (w) + aux_a (aux).
    let tenant_a = Keys::generate();
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

    // Alias B: a different tenant with its own write key.
    let tenant_b = Keys::generate();
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
    assert_eq!(status, 200, "exit5 baseline must be 200; X-Reason: {reason}");

    // (a) Missing Authorization header → 401.
    let (status, _) = head_upload(&relay, &sha, len, None).await;
    assert_eq!(status, 401, "exit5: missing auth must be 401");

    // (b) Bad signature → 401: tamper with the signed event's content so the
    // id/sig no longer verify.
    let tampered_json = good.as_json().replace("grasp-p test auth", "tampered!!");
    assert_ne!(tampered_json, good.as_json(), "tamper must change the JSON");
    let tampered = Event::from_json(&tampered_json).expect("tampered JSON still parses");
    let (status, reason) = head_upload(&relay, &sha, len, Some(&tampered)).await;
    assert_eq!(status, 401, "exit5: bad sig must be 401; X-Reason: {reason}");

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
    assert_eq!(status, 401, "exit5: expired auth must be 401; X-Reason: {reason}");

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
    assert_eq!(status, 403, "exit5: foreign w key must be 403; X-Reason: {reason}");

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
    assert_eq!(status, 403, "exit5: aux key upload must be 403; X-Reason: {reason}");

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
    assert_eq!(status, 400, "exit5: x mismatch must be 400; X-Reason: {reason}");

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
    let relay = TestRelay::start_with_private_repos(&[
        ("NGIT_PRIVATE_REGISTRATION_MODE", "whitelist"),
        ("NGIT_PRIVATE_TENANT_WHITELIST", listed_npub.as_str()),
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
        &[key_entry(&listed_writer, &listed.public_key(), &listed_alias)],
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
    let relay = TestRelay::start_with_private_repos(&[
        ("NGIT_PRIVATE_REGISTRATION_MODE", "pow"),
        ("NGIT_PRIVATE_POW_BITS", "8"),
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
    let relay = TestRelay::start_with_private_repos(&[]).await;
    let domain = relay.domain();

    let tenant1 = Keys::generate();
    let tenant2 = Keys::generate();
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
    assert!(!accepted, "exit7: cross-tenant alias claim must be rejected");
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
    assert!(accepted, "exit7: rotation must be accepted; got {message:?}");

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
    let relay = TestRelay::start_with_private_repos(&[]).await;
    let tenant = Keys::generate();
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
    assert!(deleted, "exit8: 30640 still served 10s after NIP-09 deletion");

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
        message.contains("restricted:") && message.contains("not registered"),
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
