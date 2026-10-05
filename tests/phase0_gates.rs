//! GRASP-P Phase-0 Verification Gates
//!
//! Executable proofs that the stock ngit-grasp relay (branch `grasp-p`) has the
//! substrate properties GRASP-P (multi-tenant private repos) depends on, BEFORE
//! any product code is written. Zero `src/` changes; these tests only observe.
//!
//! Gates implemented here:
//! - G1: custom kinds (30640) traverse the full `admit_event` pipeline
//! - G2: LMDB stores/serves Custom + GiftWrap kinds; NIP-77 negentropy syncs
//!   them across two independent relay instances (Down from A, Up to B)
//! - G3: no hidden read guard on stored kind-1059 gift wraps
//! - G4: a 128 KiB event passes every layer and a 1 MiB one is refused by the
//!   relay's own ceiling (`NGIT_RELAY_MAX_EVENT_SIZE_BYTES`, 192 KiB by
//!   default, new in v3), which sits ahead of GRASP-P's 128 KiB check
//! - G5: ephemeral kind 21059 routes through the write policy, broadcasts to
//!   live subscribers when accepted, and is never stored
//! - G7: ReplaceableHistoryStore multi-edition characterization (KNOWN
//!   LIMITATION: only the latest superseded payload per coordinate survives)
//!
//! NOTE on gift wraps: this workspace compiles the `nostr` crate WITHOUT the
//! `nip59`/`nip44` features (verified via `cargo tree -e features -i nostr`),
//! so `GiftWrapBuilder` is unavailable to tests. The relay never unwraps or
//! validates gift-wrap *content* — it stores the outer event verbatim — so
//! these gates build wrap-SHAPED kind-1059 events manually: throwaway random
//! signer (as NIP-59 requires), `p` tag = receiver, opaque content, an extra
//! `["a", "30617:<hex>:<d>"]` tag to satisfy the related-events write policy,
//! and a created_at backdated up to 2 days (mirroring `Timestamp::tweaked`
//! in the real builder — which is also why no `since` filter is ever used
//! near `now` for kind 1059 in these tests).
//!
//! NOTE on announcements: a bare kind-30617 send lands in purgatory and is NOT
//! stored in the relay DB (`AcceptPurgatory`); the related-events policy only
//! resolves `a` refs against DB-promoted announcements. Tests therefore use
//! `common::sync_helpers::setup_announcement_on_relay`, which performs the
//! real git push that promotes the announcement out of purgatory.
//!
//! # Running
//!
//! ```bash
//! cargo test --test phase0_gates -- --nocapture
//! ```

mod common;

use std::collections::HashSet;
use std::time::Duration;

use nostr_sdk::prelude::*;

use common::{sync_helpers::*, TestRelay};

// ============================================================================
// Local helpers (tests/common is intentionally left untouched)
// ============================================================================

/// Connect a nostr-sdk client (with signer authenticator) to a relay,
/// retrying for up to 3 seconds.
async fn connect_client(relay_url: &str, keys: Keys) -> Client {
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys))
        .build();
    connect_added(&client, relay_url).await;
    client
}

/// Connect a completely anonymous client: NO signer, NO authenticator.
/// It cannot AUTH even if challenged.
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
///
/// `accepted == true` means the relay answered OK=true. On OK=false the
/// rejection message (which embeds the machine-readable "restricted:" prefix)
/// is returned in the second slot.
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

/// REQ a relay with `filter` and return all matching events.
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

/// Random 32-byte hex string (for `d` tags).
fn random_hex_32() -> String {
    Keys::generate().public_key().to_hex()
}

/// Build a signed addressable Custom-kind event carrying a `d` tag and an
/// `["a", <coord>]` reference to an accepted repository announcement.
fn custom_event_with_aref(
    keys: &Keys,
    kind: u16,
    d_tag: &str,
    coord: &str,
    content: &str,
) -> Event {
    EventBuilder::new(Kind::Custom(kind), content)
        .tags(vec![
            Tag::identifier(d_tag),
            Tag::custom("a", vec![coord.to_string()]),
        ])
        .finalize(keys)
        .expect("Failed to sign custom event")
}

/// Build a wrap-shaped kind-1059 event (see module docs for why the real
/// `GiftWrapBuilder` is not usable in this workspace): random throwaway
/// signer, `p` tag = receiver, opaque content, extra `a` ref, and a
/// created_at backdated up to 2 days like NIP-59 prescribes.
fn wrap_shaped_giftwrap(receiver: &PublicKey, coord: &str) -> Event {
    let throwaway = Keys::generate();
    // Deterministic-ish backdate in (0, 2 days], mirroring nip59's
    // Timestamp::tweaked(RANGE_RANDOM_TIMESTAMP_TWEAK).
    let backdate_secs = 1
        + (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .subsec_nanos() as u64
            % (2 * 24 * 60 * 60));
    let created_at = Timestamp::from_secs(Timestamp::now().as_secs() - backdate_secs);
    EventBuilder::new(
        Kind::GiftWrap,
        // Opaque payload standing in for NIP-44 ciphertext; the relay never
        // decrypts or validates gift-wrap content.
        "AtQyM3BhY2VvcGFxdWUtY2lwaGVydGV4dC1zdGFuZC1pbg==",
    )
    .tags(vec![
        Tag::custom("a", vec![coord.to_string()]),
        Tag::public_key(*receiver),
    ])
    .custom_created_at(created_at)
    .finalize(&throwaway)
    .expect("Failed to sign wrap-shaped giftwrap")
}

/// Extract the first `p` tag value from an event.
fn first_p_tag(event: &Event) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.as_slice();
        if v.len() >= 2 && v[0] == "p" {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

// ============================================================================
// G1 — custom kinds traverse admit_event
// ============================================================================

/// (a) A bare kind-30640 (no reference tags) must be rejected by the
/// related-events catch-all with a "restricted:" OK message — proof the
/// Custom kind traversed the full relay pipeline into `admit_event` rather
/// than being dropped or erroring earlier.
/// (b) With an `a` ref to an accepted (git-promoted) announcement, the same
/// kind is accepted, stored, and served back intact by authors and by `#d`.
#[tokio::test]
async fn g1_custom_kinds_traverse_admit_event() {
    let relay = TestRelay::start().await;
    let author = Keys::generate();

    // (a) Orphan 30640: random 32-byte-hex d tag, no reference tags.
    let orphan = EventBuilder::new(Kind::Custom(30640), "phase0 g1 orphan")
        .tags(vec![Tag::identifier(random_hex_32())])
        .finalize(&author)
        .expect("sign orphan 30640");
    let (accepted, message) = publish_with_result(relay.url(), &orphan).await;
    assert!(
        !accepted,
        "G1a: bare kind-30640 must be rejected, but relay accepted it"
    );
    assert!(
        message.contains("restricted:"),
        "G1a: rejection must carry the admit_event 'restricted:' prefix; got: {message:?}"
    );
    println!("G1a rejection message: {message}");

    // (b) Promote an announcement (git push releases it from purgatory into
    // the DB), then publish a 30640 that a-refs its coordinate.
    let owner = Keys::generate();
    let (_announcement, _git_dir) =
        setup_announcement_on_relay(&relay, &owner, &[&relay.domain()], "phase0-g1").await;
    let coord = repo_coord(&owner, "phase0-g1");

    let d_tag = random_hex_32();
    let doc = custom_event_with_aref(&author, 30640, &d_tag, &coord, "phase0 g1 doc");
    let (accepted, message) = publish_with_result(relay.url(), &doc).await;
    assert!(
        accepted,
        "G1b: kind-30640 with a-ref to accepted announcement must be accepted; got: {message:?}"
    );

    // REQ back by kinds + authors.
    let by_author = fetch_from(
        relay.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(author.public_key()),
    )
    .await;
    assert_eq!(
        by_author.len(),
        1,
        "G1b: expected exactly 1 stored kind-30640 for author"
    );
    let served = &by_author[0];
    assert_eq!(served.id, doc.id, "G1b: served event id mismatch");
    assert_eq!(served.kind.as_u16(), 30640, "G1b: served kind mismatch");
    assert_eq!(served.tags, doc.tags, "G1b: served tags not intact");
    assert_eq!(served.content, doc.content, "G1b: served content mismatch");

    // REQ back by #d.
    let by_d = fetch_from(
        relay.url(),
        Filter::new().kind(Kind::Custom(30640)).identifier(&d_tag),
    )
    .await;
    assert_eq!(by_d.len(), 1, "G1b: expected 1 kind-30640 by #d filter");
    assert_eq!(by_d[0].id, doc.id, "G1b: #d round-trip id mismatch");

    relay.stop().await;
}

// ============================================================================
// G2 — LMDB serves Custom + GiftWrap; NIP-77 syncs across two instances
// ============================================================================

/// Two independent LMDB-backed relays A and B (no server-side sync config).
/// A holds a kind-30640 and a kind-1059; a fresh nostr-sdk client
/// negentropy-syncs them DOWN from A into its own in-memory DB, then UP to B
/// through the normal EVENT write path, after which B serves both.
///
/// DISCOVERY (characterized during gate development): if the promoted
/// announcement on B lists relay A's domain in its clone/relays tags,
/// ngit-grasp's announcement-driven PROACTIVE SYNC activates with no
/// bootstrap configuration at all — B connects to A on its own and
/// replicates the repo-referenced 30640 AND 1059 within ~2s (observed: B
/// served both ids before the client Up sync ran, and the Up correctly
/// found nothing left to send). That is a bonus positive result for
/// GRASP-P Phase 2 (two-node replication of custom kinds works natively),
/// but it makes the client-driven Up leg unprovable. This gate therefore
/// pins each relay's announcement to ITS OWN domain only, so the only
/// possible transport into B is the client's negentropy Up sync.
#[tokio::test]
async fn g2_lmdb_custom_and_giftwrap_negentropy_sync() {
    let relay_a = TestRelay::start_with_lmdb().await;
    let relay_b = TestRelay::start_with_lmdb().await;
    let dom_a = relay_a.domain();
    let dom_b = relay_b.domain();

    // Same owner + identifier => same repo coordinate on both relays, but
    // each announcement lists only the local domain (see DISCOVERY above).
    let owner = Keys::generate();
    let (_ann_a, _git_a) =
        setup_announcement_on_relay(&relay_a, &owner, &[dom_a.as_str()], "phase0-g2").await;
    let (_ann_b, _git_b) =
        setup_announcement_on_relay(&relay_b, &owner, &[dom_b.as_str()], "phase0-g2").await;
    let coord = repo_coord(&owner, "phase0-g2");

    // To A ONLY: a 30640 (with a-ref) and a wrap-shaped 1059 (extra a-ref).
    let author = Keys::generate();
    let d_tag = random_hex_32();
    let doc = custom_event_with_aref(&author, 30640, &d_tag, &coord, "phase0 g2 meta");
    let recipient = Keys::generate();
    let wrap = wrap_shaped_giftwrap(&recipient.public_key(), &coord);

    let (ok, msg) = publish_with_result(relay_a.url(), &doc).await;
    assert!(ok, "G2: relay A must accept the kind-30640; got: {msg:?}");
    let (ok, msg) = publish_with_result(relay_a.url(), &wrap).await;
    assert!(
        ok,
        "G2: relay A must accept the kind-1059 wrap; got: {msg:?}"
    );

    // A serves both: by authors, by #d (30640), and by kinds=[1059].
    let by_author = fetch_from(
        relay_a.url(),
        Filter::new()
            .kind(Kind::Custom(30640))
            .author(author.public_key()),
    )
    .await;
    assert_eq!(by_author.len(), 1, "G2: A must serve the 30640 by author");
    assert_eq!(by_author[0].id, doc.id);

    let by_d = fetch_from(
        relay_a.url(),
        Filter::new().kind(Kind::Custom(30640)).identifier(&d_tag),
    )
    .await;
    assert_eq!(by_d.len(), 1, "G2: A must serve the 30640 by #d");
    assert_eq!(by_d[0].id, doc.id);

    // No `since` bound: NIP-59 wraps are backdated up to 2 days.
    let wraps_on_a = fetch_from(relay_a.url(), Filter::new().kind(Kind::GiftWrap)).await;
    assert_eq!(wraps_on_a.len(), 1, "G2: A must serve the stored 1059 wrap");
    assert_eq!(wraps_on_a[0].id, wrap.id);

    // Fresh client with its OWN in-memory event database. (nostr-sdk's
    // default client database is a MemoryEventsTracker that only tracks
    // seen ids — it cannot store/query events, which both the Down-sync
    // landing assertion and the Up-sync send path require.)
    let sync_client = Client::builder()
        .authenticator(SignerAuthenticator::new(Keys::generate()))
        .database(nostr_memory::MemoryDatabase::unbounded())
        .build();
    sync_client
        .add_relay(relay_a.url())
        .await
        .expect("add relay A");
    sync_client
        .add_relay(relay_b.url())
        .await
        .expect("add relay B");
    sync_client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let filter = Filter::new().kinds([Kind::Custom(30640), Kind::GiftWrap]);

    let down = sync_client
        .sync(filter.clone())
        .with([relay_a.url()])
        .opts(SyncOptions::default().direction(SyncDirection::Down))
        .await
        .expect("G2: negentropy Down sync against A failed — NIP-77 not served?");
    let down_summary = down.value;
    println!(
        "G2 down summary: received={:?} remote={:?} local={:?}",
        down_summary.received, down_summary.remote, down_summary.local
    );
    assert!(
        down_summary.received.contains_key(&doc.id),
        "G2: negentropy Down must have received the 30640 {} from A; summary: {down_summary:?}",
        doc.id
    );
    assert!(
        down_summary.received.contains_key(&wrap.id),
        "G2: negentropy Down must have received the 1059 {} from A; summary: {down_summary:?}",
        wrap.id
    );

    // Both events landed in the client's own database.
    let local = sync_client
        .database()
        .query(filter.clone())
        .await
        .expect("client DB query");
    let local_ids: HashSet<EventId> = local.into_iter().map(|e| e.id).collect();
    assert!(
        local_ids.contains(&doc.id) && local_ids.contains(&wrap.id),
        "G2: both events must be in the sync client's DB after Down sync; got {local_ids:?}"
    );

    // Guard: B must NOT have the events yet — proves the only way they can
    // arrive is the client-driven negentropy Up below (i.e. announcement-
    // driven proactive sync is not active with local-only announcements).
    let pre_up_b = fetch_from(relay_b.url(), Filter::new().ids([doc.id, wrap.id])).await;
    assert!(
        pre_up_b.is_empty(),
        "G2: B unexpectedly already has {:?} before the client Up sync — \
         announcement-driven proactive sync activated despite local-only \
         relays/clone tags",
        pre_up_b.iter().map(|e| e.id).collect::<Vec<_>>()
    );

    // Negentropy Up to B: events flow through the normal EVENT write path,
    // so B's write policy (a-refs against its own promoted announcement)
    // must accept them.
    let up = sync_client
        .sync(filter.clone())
        .with([relay_b.url()])
        .opts(SyncOptions::default().direction(SyncDirection::Up))
        .await
        .expect("G2: negentropy Up sync against B failed");
    let up_summary = up.value;
    println!(
        "G2 up summary: sent={:?} send_failures={:?}",
        up_summary.sent, up_summary.send_failures
    );
    assert!(
        up_summary.sent.contains_key(&doc.id),
        "G2: Up sync must have sent the 30640 to B; summary: {up_summary:?}"
    );
    assert!(
        up_summary.sent.contains_key(&wrap.id),
        "G2: Up sync must have sent the 1059 to B; summary: {up_summary:?}"
    );

    sync_client.disconnect().await;

    // B now serves both with identical ids.
    let on_b = fetch_from(relay_b.url(), Filter::new().ids([doc.id, wrap.id])).await;
    let b_ids: HashSet<EventId> = on_b.iter().map(|e| e.id).collect();
    assert!(
        b_ids.contains(&doc.id) && b_ids.contains(&wrap.id),
        "G2: B must serve both synced events by id; got {b_ids:?}"
    );

    relay_a.stop().await;
    relay_b.stop().await;
}

// ============================================================================
// G3 — no hidden 1059 p-tag serving guard
// ============================================================================

/// A stored gift wrap is served to a completely anonymous client (no signer,
/// never AUTHs) that is NOT the p-tagged recipient — both via kinds=[1059]
/// and via a bare ids=[...] filter.
#[tokio::test]
async fn g3_no_hidden_giftwrap_read_guard() {
    let relay = TestRelay::start().await;

    let owner = Keys::generate();
    let (_ann, _git_dir) =
        setup_announcement_on_relay(&relay, &owner, &[&relay.domain()], "phase0-g3").await;
    let coord = repo_coord(&owner, "phase0-g3");

    let recipient = Keys::generate();
    let wrap = wrap_shaped_giftwrap(&recipient.public_key(), &coord);
    let (ok, msg) = publish_with_result(relay.url(), &wrap).await;
    assert!(
        ok,
        "G3: relay must accept the a-ref'd 1059 wrap; got: {msg:?}"
    );

    // Fresh keys that are NOT the recipient and are never used to AUTH
    // (the client has no signer/authenticator at all).
    let anon_keys = Keys::generate();
    assert_ne!(anon_keys.public_key(), recipient.public_key());

    let anon = connect_anonymous_client(relay.url()).await;

    // REQ kinds=[1059] (no since: wraps are backdated).
    let by_kind = anon
        .fetch_events(Filter::new().kind(Kind::GiftWrap))
        .timeout(Duration::from_secs(10))
        .await
        .expect("G3: anonymous fetch by kind failed");
    let by_kind: Vec<Event> = by_kind.into_iter().collect();
    assert_eq!(
        by_kind.len(),
        1,
        "G3: anonymous client must be served the stored wrap via kinds=[1059]"
    );
    assert_eq!(by_kind[0].id, wrap.id);

    // REQ ids=[wrap_id] with no kinds filter.
    let by_id = anon
        .fetch_events(Filter::new().id(wrap.id))
        .timeout(Duration::from_secs(10))
        .await
        .expect("G3: anonymous fetch by id failed");
    let by_id: Vec<Event> = by_id.into_iter().collect();
    assert_eq!(
        by_id.len(),
        1,
        "G3: anonymous client must be served the wrap via bare ids filter"
    );
    assert_eq!(by_id[0].id, wrap.id);

    // The served wrap's p tag is someone else's pubkey, proving we fetched a
    // wrap addressed to a different recipient without any AUTH.
    let p_tag = first_p_tag(&by_id[0]).expect("wrap must carry a p tag");
    assert_eq!(p_tag, recipient.public_key().to_hex());
    assert_ne!(
        p_tag,
        anon_keys.public_key().to_hex(),
        "G3: p tag must NOT match the requesting client's pubkey"
    );

    anon.disconnect().await;
    relay.stop().await;
}

// ============================================================================
// G4 — 128 KiB events pass; the relay ceiling sits above GRASP-P's cap
// ============================================================================

/// A 131072-byte-content event is accepted and round-trips with its content
/// length preserved, so GRASP-P's own 128 KiB check (the
/// `NGIT_GRASP_P_MAX_EVENT_BYTES` default) is the binding limit for private
/// kinds. Since v3 upstream enforces its own per-event ceiling,
/// `NGIT_RELAY_MAX_EVENT_SIZE_BYTES` (default 192 KiB), ahead of any write
/// policy: a ~1 MiB event is refused there. On v1.2 there was no such layer
/// and this gate asserted that 1 MiB passed.
#[tokio::test]
async fn g4_large_events_pass() {
    let relay = TestRelay::start().await;

    let owner = Keys::generate();
    let (_ann, _git_dir) =
        setup_announcement_on_relay(&relay, &owner, &[&relay.domain()], "phase0-g4").await;
    let coord = repo_coord(&owner, "phase0-g4");

    let author = Keys::generate();

    // ~128 KiB content on a custom regular kind that passes policy via a-ref.
    let content_128k = "x".repeat(131_072);
    let big = EventBuilder::new(Kind::Custom(4444), content_128k)
        .tags(vec![Tag::custom("a", vec![coord.clone()])])
        .finalize(&author)
        .expect("sign 128KiB event");
    let (ok, msg) = publish_with_result(relay.url(), &big).await;
    assert!(ok, "G4: 128 KiB event must be accepted; got: {msg:?}");

    let served = fetch_from(relay.url(), Filter::new().id(big.id)).await;
    assert_eq!(served.len(), 1, "G4: 128 KiB event must round-trip");
    assert_eq!(
        served[0].content.len(),
        131_072,
        "G4: 128 KiB content length must be preserved"
    );

    // ~1 MiB content: refused by upstream's relay-level size ceiling before
    // the write policy runs.
    let content_1m = "y".repeat(1_048_576);
    let bigger = EventBuilder::new(Kind::Custom(4444), content_1m)
        .tags(vec![Tag::custom("a", vec![coord])])
        .finalize(&author)
        .expect("sign 1MiB event");
    let (ok, msg) = publish_with_result(relay.url(), &bigger).await;
    assert!(
        !ok && msg.contains("event size"),
        "G4: a 1 MiB event must be refused by the relay size ceiling; got: {ok} {msg:?}"
    );

    relay.stop().await;
}

// ============================================================================
// G5 — 21059 ephemeral routes through policy + broadcasts unstored
// ============================================================================

/// Ephemeral kind 21059: the write policy runs FIRST (a bare 21059 is vetoed
/// with "restricted:" and never broadcast), an a-ref'd 21059 is OK'd and
/// broadcast live to matching subscribers, and nothing is ever stored.
#[tokio::test]
async fn g5_ephemeral_21059_policy_and_broadcast() {
    let relay = TestRelay::start().await;

    let owner = Keys::generate();
    let (_ann, _git_dir) =
        setup_announcement_on_relay(&relay, &owner, &[&relay.domain()], "phase0-g5").await;
    let coord = repo_coord(&owner, "phase0-g5");

    // (a) Live subscription for kinds=[21059] FIRST; wait for EOSE.
    let subscriber = connect_client(relay.url(), Keys::generate()).await;
    let mut notifications = subscriber.notifications();
    let sub_output = subscriber
        .subscribe(Filter::new().kind(Kind::Custom(21059)))
        .await
        .expect("G5: subscribe failed");
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
    assert!(eose.is_ok(), "G5: did not receive EOSE within 5s");

    let author = Keys::generate();

    // (b) Bare 21059 (no refs): policy veto precedes the ephemeral branch.
    let bare = EventBuilder::new(Kind::Custom(21059), "phase0 g5 bare")
        .finalize(&author)
        .expect("sign bare 21059");
    let (ok, msg) = publish_with_result(relay.url(), &bare).await;
    assert!(!ok, "G5b: bare 21059 must be rejected by the write policy");
    assert!(
        msg.contains("restricted:"),
        "G5b: rejection must carry 'restricted:'; got: {msg:?}"
    );

    // The live subscription must receive NOTHING for the vetoed event.
    let leaked = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(notification) = notifications.next().await {
            if let ClientNotification::Event { event, .. } = notification {
                if event.kind.as_u16() == 21059 {
                    return *event;
                }
            }
        }
        panic!("notification stream ended unexpectedly");
    })
    .await;
    assert!(
        leaked.is_err(),
        "G5b: vetoed ephemeral must NOT be broadcast to subscribers; got: {:?}",
        leaked.map(|e| e.id)
    );

    // (c) 21059 with a-ref: accepted AND broadcast live.
    let good = EventBuilder::new(Kind::Custom(21059), "phase0 g5 live")
        .tags(vec![Tag::custom("a", vec![coord])])
        .finalize(&author)
        .expect("sign a-ref'd 21059");
    let (ok, msg) = publish_with_result(relay.url(), &good).await;
    assert!(
        ok,
        "G5c: a-ref'd 21059 must be accepted (OK=true); got: {msg:?}"
    );

    let received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(notification) = notifications.next().await {
            if let ClientNotification::Event { event, .. } = notification {
                if event.kind.as_u16() == 21059 {
                    return *event;
                }
            }
        }
        panic!("notification stream ended before live 21059 arrived");
    })
    .await
    .expect("G5c: live subscription must receive the accepted ephemeral within 10s");
    assert_eq!(
        received.id, good.id,
        "G5c: broadcast ephemeral id must match the published event"
    );

    subscriber.disconnect().await;

    // (d) Fresh REQ afterwards: EOSE with zero stored 21059 events.
    let stored = fetch_from(relay.url(), Filter::new().kind(Kind::Custom(21059))).await;
    assert!(
        stored.is_empty(),
        "G5d: ephemeral events must never be stored; REQ returned {} event(s)",
        stored.len()
    );

    relay.stop().await;
}

// ============================================================================
// G7 — ReplaceableHistoryStore multi-edition characterization
// ============================================================================

/// CHARACTERIZATION TEST of a verified KNOWN LIMITATION — the assertions
/// below encode the ACTUAL behavior, not the desired one.
///
/// Desired property for GRASP-P: archiving N successive editions of the same
/// addressable coordinate retains all N superseded PAYLOADS for rollback.
///
/// Actual behavior: `ReplaceableHistoryStore` persists superseded payloads
/// into a backing store (nostr-memory / nostr-lmdb) that itself applies
/// NIP-01 addressable replacement. Archiving edition2 of the same
/// (kind, pubkey, d) coordinate therefore hard-deletes the previously
/// archived edition1 PAYLOAD (`event_by_id(edition1) -> None`); only the
/// LATEST superseded payload per coordinate survives. The kind-9906 metadata
/// rows (regular events) all survive, so the history *index* is complete
/// while the history *payloads* are not.
///
/// Additionally (verified in src/nostr/lifecycle/deletion/service.rs:722-724), capture is only
/// ever invoked for kinds 30617/30618 — a kind-30641 flowing through the
/// relay's `handle_related_event` path never triggers capture at all.
///
/// Consequence for GRASP-P: G7's desired property FAILS here, so GRASP-P
/// must keep its own 30641 edition ring in the private meta store instead of
/// leaning on `ReplaceableHistoryStore` for multi-edition payload retention.
#[tokio::test]
async fn g7_replaceable_history_multi_edition_characterization() {
    use ngit_grasp::nostr::lifecycle::ReplaceableHistoryStore;

    fn edition(keys: &Keys, d_tag: &str, created_at: u64, content: &str) -> Event {
        EventBuilder::new(Kind::Custom(30641), content)
            .tags(vec![Tag::identifier(d_tag)])
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .expect("sign 30641 edition")
    }

    async fn characterize(store: ReplaceableHistoryStore, label: &str) {
        let keys = Keys::generate();
        let d_tag = "phase0-g7";
        let coord = format!("30641:{}:{}", keys.public_key().to_hex(), d_tag);

        // Three successive editions t, t+1, t+2 of the same coordinate.
        let t = Timestamp::now().as_secs() - 600;
        let edition1 = edition(&keys, d_tag, t, "edition v1");
        let edition2 = edition(&keys, d_tag, t + 1, "edition v2");
        let edition3 = edition(&keys, d_tag, t + 2, "edition v3");

        store
            .archive_superseded_event(&edition1, &edition2, &coord)
            .await
            .unwrap_or_else(|e| panic!("{label}: archive edition1 failed: {e}"));
        store
            .archive_superseded_event(&edition2, &edition3, &coord)
            .await
            .unwrap_or_else(|e| panic!("{label}: archive edition2 failed: {e}"));

        // Metadata: BOTH archived editions are indexed.
        let records = store
            .superseded_records_for_coordinate_before(&coord, Timestamp::now())
            .await;
        assert_eq!(
            records.len(),
            2,
            "{label}: both kind-9906 metadata rows must survive"
        );
        let recorded_ids: HashSet<EventId> = records
            .iter()
            .filter_map(|r| r.superseded_event_id)
            .collect();
        assert!(
            recorded_ids.contains(&edition1.id) && recorded_ids.contains(&edition2.id),
            "{label}: metadata must reference both archived editions; got {recorded_ids:?}"
        );

        // Payloads: KNOWN LIMITATION — addressable replacement in the backing
        // store deleted edition1's payload when edition2 was archived under
        // the same (kind, pubkey, d) coordinate. Only the latest superseded
        // payload survives.
        let payload1 = store
            .event_by_id(&edition1.id)
            .await
            .unwrap_or_else(|e| panic!("{label}: payload lookup edition1 failed: {e}"));
        assert!(
            payload1.is_none(),
            "{label}: CHARACTERIZED LIMITATION violated — edition1 payload unexpectedly \
             survived; if this now returns Some, the store's retention semantics changed \
             and G7 should be re-evaluated"
        );

        let payload2 = store
            .event_by_id(&edition2.id)
            .await
            .unwrap_or_else(|e| panic!("{label}: payload lookup edition2 failed: {e}"));
        let payload2 = payload2.unwrap_or_else(|| {
            panic!("{label}: latest superseded payload (edition2) must be retained")
        });
        assert_eq!(payload2.id, edition2.id);
        assert_eq!(payload2.content, "edition v2");
    }

    // In-memory backend.
    characterize(ReplaceableHistoryStore::in_memory(), "in_memory").await;

    // LMDB backend.
    let tempdir = tempfile::tempdir().expect("tempdir for lmdb history");
    let lmdb_store = ReplaceableHistoryStore::open_lmdb(tempdir.path())
        .await
        .expect("open lmdb history store");
    characterize(lmdb_store, "lmdb").await;
}
