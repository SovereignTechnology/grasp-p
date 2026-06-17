//! NIP-62 request-to-vanish validation integration tests
//!
//! Characterises the relay's kind-62 (`RequestToVanish`) handling end-to-end
//! against a live ngit-grasp instance driven by the [`TestRelay`] fixture.
//!
//! These tests are the NIP-62 counterpart of `nip09_validation.rs`. They lock
//! in the current `handle_vanish` / `deletion_gate` behaviour
//! (`src/nostr/builder.rs`) and the persistent tombstone store
//! (`src/nostr/tombstones.rs`):
//!
//! - a kind-62 targeting this relay (via `["relay", "ALL_RELAYS"]`) is accepted,
//!   hard-deletes the author's served events, and lays down a vanish tombstone;
//! - once a pubkey has vanished, any *new* event it submits is rejected by the
//!   deletion/vanish gate with a message mentioning the vanish;
//! - a vanish request is author-bound: author B's vanish must never delete or
//!   block author A's events;
//! - a vanish request that names a *different* relay URL (not this one) is
//!   accepted but NOT actioned — the author's events remain served and the
//!   author may keep publishing;
//! - the kind-62 request event itself is accepted (the author signs their own
//!   vanish, so author validation is inherent).
//!
//! The disrespector-specific NIP-62 behaviour (NIP-11 omits NIP-62 in archival
//! mode) lives in `nip09_disrespector.rs`.
//!
//! Shared helpers (`publish_served_repo`, `announcement_served_by_coordinate`,
//! `announcement_coordinate`, `build_vanish`) live in
//! `tests/common/nip09_helpers.rs`.
//!
//! # Running
//!
//! ```bash
//! cargo test --test nip62_validation
//! cargo test --test nip62_validation -- --nocapture
//! ```

mod common;

use common::{
    announcement_served_by_coordinate, build_vanish, publish_served_repo, TestRelay,
};

use grasp_audit::{AuditClient, AuditConfig};
use std::time::Duration;

/// 1. A kind-62 vanish targeting this relay (`ALL_RELAYS`) is accepted and the
///    author's served events are removed.
#[tokio::test]
async fn vanish_removes_authors_served_events() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "vanish-removes").await;

    // A served Layer-2 issue referencing the promoted repo.
    let issue = client
        .create_issue(&announcement, "Issue to vanish", "bye", vec![])
        .expect("build issue");
    let issue_id = issue.id;
    client
        .send_event(issue)
        .await
        .expect("relay should accept issue");

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        client
            .is_event_on_relay(issue_id)
            .await
            .expect("query issue before vanish"),
        "issue should be served before the vanish request"
    );
    assert!(
        client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query announcement before vanish"),
        "announcement should be served before the vanish request"
    );

    // Send the vanish request (targets ALL_RELAYS).
    let vanish = build_vanish(&client, None);
    client
        .send_event(vanish)
        .await
        .expect("relay should accept a well-formed vanish request");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let issue_served = client
        .is_event_on_relay(issue_id)
        .await
        .expect("query issue after vanish");
    let announcement_served_by_id = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement by id after vanish");
    let announcement_served_by_coord =
        announcement_served_by_coordinate(&client, &announcement, &repo_id).await;

    relay.stop().await;

    assert!(
        !issue_served,
        "issue {} should be deleted after the author requested to vanish",
        issue_id
    );
    assert!(
        !announcement_served_by_id,
        "announcement {} should be deleted after the author vanished (by-id check)",
        announcement.id
    );
    assert!(
        !announcement_served_by_coord,
        "announcement {} should be deleted after the author vanished \
         (author+kind+identifier check)",
        announcement.id
    );
}

/// 2. After a pubkey has vanished, any NEW event it submits is rejected by the
///    deletion/vanish gate with a message mentioning the vanish.
#[tokio::test]
async fn events_from_vanished_pubkey_are_rejected() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    // Promote a repo so we have a well-formed announcement to build issues
    // against later (the issue itself is built after the vanish).
    let (announcement, _repo_id) = publish_served_repo(&client, "vanished-blocked").await;

    // The author vanishes.
    let vanish = build_vanish(&client, None);
    client
        .send_event(vanish)
        .await
        .expect("relay should accept the vanish request");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // A brand-new event from the now-vanished pubkey must be rejected.
    let issue = client
        .create_issue(&announcement, "Post-vanish issue", "should be blocked", vec![])
        .expect("build issue");
    let issue_id = issue.id;

    let result = client.send_event(issue).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let served = client
        .is_event_on_relay(issue_id)
        .await
        .expect("query post-vanish issue");

    relay.stop().await;

    assert!(
        result.is_err(),
        "an event from a vanished pubkey must be rejected, but it was accepted"
    );
    let msg = result.err().unwrap().to_string().to_lowercase();
    assert!(
        msg.contains("vanish"),
        "rejection message should mention the pubkey requested to vanish; got: {}",
        msg
    );
    assert!(
        !served,
        "event {} from a vanished pubkey must never be served",
        issue_id
    );
}

/// 3. A vanish request is author-bound: author B vanishing must never delete or
///    block author A's events.
#[tokio::test]
async fn vanish_does_not_affect_other_authors() {
    let relay = TestRelay::start().await;

    let author_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create author A client");
    let author_b = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create author B client");

    // Author A publishes a repo + a served issue.
    let (announcement_a, repo_id) = publish_served_repo(&author_a, "vanish-other-author").await;
    let issue = author_a
        .create_issue(&announcement_a, "A's issue", "owned by A", vec![])
        .expect("build A's issue");
    let issue_id = issue.id;
    author_a
        .send_event(issue)
        .await
        .expect("relay should accept A's issue");

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        author_a
            .is_event_on_relay(issue_id)
            .await
            .expect("query A's issue before B vanishes"),
        "A's issue should be served before B's vanish"
    );

    // Author B requests to vanish (ALL_RELAYS).
    let vanish = build_vanish(&author_b, None);
    author_b
        .send_event(vanish)
        .await
        .expect("relay should accept B's vanish request");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // A's events must be untouched.
    let issue_served = author_a
        .is_event_on_relay(issue_id)
        .await
        .expect("query A's issue after B vanishes");
    let announcement_served_by_coord =
        announcement_served_by_coordinate(&author_a, &announcement_a, &repo_id).await;

    // A may still publish freely: B's vanish must not have blocked A.
    let new_issue = author_a
        .create_issue(&announcement_a, "A's later issue", "still here", vec![])
        .expect("build A's later issue");
    let new_issue_id = new_issue.id;
    let new_result = author_a.send_event(new_issue).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let new_served = author_a
        .is_event_on_relay(new_issue_id)
        .await
        .expect("query A's later issue");

    relay.stop().await;

    assert!(
        issue_served,
        "A's issue {} must remain served after B's vanish (vanish is author-bound)",
        issue_id
    );
    assert!(
        announcement_served_by_coord,
        "A's announcement {} must remain served after B's vanish",
        announcement_a.id
    );
    assert!(
        new_result.is_ok(),
        "A must be able to keep publishing after B's vanish, but submission was \
         rejected: {:?}",
        new_result.err()
    );
    assert!(
        new_served,
        "A's later issue {} must be served: B's vanish must not block A",
        new_issue_id
    );
}

/// 4. A vanish request that names a DIFFERENT relay (not this one) is accepted
///    but NOT actioned: the author's events remain served and the author may
///    keep publishing.
///
/// The relay validates vanish requests with
/// `is_valid_vanish_request_for_relay(tags, None)`, so a request naming a
/// specific relay URL never matches and is stored-without-action.
#[tokio::test]
async fn vanish_targeting_other_relay_is_not_actioned() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "vanish-other-relay").await;
    let issue = client
        .create_issue(&announcement, "Issue kept", "stays", vec![])
        .expect("build issue");
    let issue_id = issue.id;
    client
        .send_event(issue)
        .await
        .expect("relay should accept issue");

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        client
            .is_event_on_relay(issue_id)
            .await
            .expect("query issue before vanish"),
        "issue should be served before the vanish request"
    );

    // Vanish request naming an unrelated relay — must not be actioned here.
    let vanish = build_vanish(&client, Some("wss://some.other.relay.example"));
    client
        .send_event(vanish)
        .await
        .expect("relay should accept a vanish request that does not target it");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let issue_served = client
        .is_event_on_relay(issue_id)
        .await
        .expect("query issue after non-targeting vanish");
    let announcement_served_by_coord =
        announcement_served_by_coordinate(&client, &announcement, &repo_id).await;

    // The author must still be able to publish: no vanish tombstone was laid.
    let later = client
        .create_issue(&announcement, "Later issue", "still allowed", vec![])
        .expect("build later issue");
    let later_id = later.id;
    let later_result = client.send_event(later).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let later_served = client
        .is_event_on_relay(later_id)
        .await
        .expect("query later issue");

    relay.stop().await;

    assert!(
        issue_served,
        "issue {} must remain served: a vanish naming another relay must not be actioned",
        issue_id
    );
    assert!(
        announcement_served_by_coord,
        "announcement {} must remain served: a vanish naming another relay must not be actioned",
        announcement.id
    );
    assert!(
        later_result.is_ok(),
        "author must keep publishing after a non-targeting vanish, but submission was \
         rejected: {:?}",
        later_result.err()
    );
    assert!(
        later_served,
        "later issue {} must be served: a non-targeting vanish must not block the author",
        later_id
    );
}

/// 5. The kind-62 vanish request event itself is accepted (the author signs
///    their own vanish, so authorship is inherent and no target is required).
#[tokio::test]
async fn vanish_request_event_is_accepted() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let vanish = build_vanish(&client, None);
    let result = client.send_event(vanish).await;

    relay.stop().await;

    assert!(
        result.is_ok(),
        "a well-formed kind-62 vanish request must be accepted; got: {:?}",
        result.err()
    );
}
