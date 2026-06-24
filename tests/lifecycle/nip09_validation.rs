//! NIP-09 deletion-request standard-behaviour integration tests
//!
//! This suite is the canonical, end-to-end characterisation of the relay's
//! kind-5 (EventDeletion) handling **as specified by NIP-09**, driven against a
//! live ngit-grasp instance via the [`TestRelay`] fixture.
//!
//! SCOPE — STANDARD NIP-09 BEHAVIOUR ONLY. Every test in this file must assert
//! plain, spec-compliant NIP-09 deletion semantics: an author deleting their
//! own events, the cross-author authorship guard, pre-emptive deletion, and the
//! `created_at` timestamp rule for addressable coordinates. This file is the
//! reference that proves ngit-grasp still behaves like a vanilla NIP-09 relay.
//!
//! DO NOT add tests here for any custom, non-standard, or ngit-grasp-specific
//! deletion behaviour (e.g. cascade deletion, multi-maintainer deletion graphs,
//! holding-DB / archival / recovery, or any extension layered on top of
//! NIP-09). Such behaviour is deliberately out of scope and, when it is built,
//! belongs in its own dedicated test file so this suite remains a pure
//! standard-conformance baseline. If a change you are testing diverges from
//! what a stock NIP-09 relay would do, it does NOT belong in this file.
//!
//! These tests mirror the live [`DeletionPolicy`] (`src/nostr/policy/deletion.rs`):
//! - `e`-tag targets owned by another pubkey cause the whole deletion to be
//!   rejected (`reject_invalid`);
//! - `e`-tag targets owned by the deleter are hard-deleted (and tombstoned);
//! - `a`-tag coordinates are deleted when the coordinate pubkey matches the
//!   deleter;
//! - deletion of a non-existent target is accepted (NIP-09 pre-emptive delete);
//! - a pre-emptive delete that arrives *before* its target lays down a
//!   tombstone, so the later-arriving target is rejected and never served;
//! - malformed `a` coordinates are silently treated as no-ops (accepted);
//! - the NIP-09 timestamp rule for `a`-coordinate deletions: a version of an
//!   addressable event *newer* than the deletion request is accepted and served
//!   (the deletion only applies up to its own `created_at`).
//!
//! The "normal mode honours deletion" baseline (a default relay removing an
//! announcement deleted by its `a` coordinate) lives here as a basic NIP-09
//! test (`normal_mode_honours_deletion`). The disrespector-specific
//! counterparts (accept-but-ignore, NIP-11 advertisement) live in
//! `nip09_disrespector.rs`.
//!
//! Shared helpers (`publish_served_repo`, `announcement_served_by_coordinate`,
//! `announcement_coordinate`, `build_deletion`) live in
//! `tests/common/nip09_helpers.rs` and are used by both suites.
//!
//! # Running
//!
//! ```bash
//! cargo test --test nip09_validation
//! cargo test --test nip09_validation -- --nocapture
//! ```

#[path = "../common/mod.rs"]
mod common;

use common::{
    announcement_coordinate, announcement_served_by_coordinate, build_deletion,
    publish_served_repo, TestRelay,
};

use grasp_audit::{AuditClient, AuditConfig};
use nostr_sdk::prelude::*;
use std::time::Duration;

/// 1. A deletion targeting an existing, author-owned event by `e` tag is
///    accepted and the target is no longer served.
#[tokio::test]
async fn valid_deletion_by_event_id_removes_target() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, _repo_id) = publish_served_repo(&client, "valid-e-id").await;

    // An issue referencing the promoted repo is a Layer-2 event: it is served
    // immediately (no purgatory).
    let issue = client
        .create_issue(&announcement, "Issue to delete", "delete me", vec![])
        .expect("build issue");
    let issue_id = issue.id;

    client
        .send_event(issue.clone())
        .await
        .expect("relay should accept issue");

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        client
            .is_event_on_relay(issue_id)
            .await
            .expect("query issue before deletion"),
        "issue should be served before deletion"
    );

    let deletion = build_deletion(&client, &[issue_id], &[]);
    client
        .send_event(deletion)
        .await
        .expect("relay should accept deletion of own event");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let still_served = client
        .is_event_on_relay(issue_id)
        .await
        .expect("query issue after deletion");

    relay.stop().await;

    assert!(
        !still_served,
        "issue {} should no longer be served after deletion by event id",
        issue_id
    );
}

/// 2. A deletion referencing an `e` tag for an event the relay has never seen
///    is accepted (NIP-09 allows pre-emptive deletion).
#[tokio::test]
async fn deletion_of_nonexistent_event_is_accepted() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    // A random id the relay has never stored.
    let nonexistent =
        EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("parse nonexistent id");

    let deletion = build_deletion(&client, &[nonexistent], &[]);

    let result = client.send_event(deletion).await;

    relay.stop().await;

    assert!(
        result.is_ok(),
        "deletion of a non-existent event must be accepted (NIP-09 pre-emptive delete), got: {:?}",
        result.err()
    );
}

/// 2b. Out-of-order deletion: a kind-5 deleting an own event arrives *before*
///     the relay has ever seen that event. The deletion is accepted (NIP-09
///     pre-emptive delete) and records a tombstone; a subsequent submission of
///     the now-deleted event is rejected by the resubmission gate ("this event
///     is deleted") and the event is never served.
///
/// This exercises the delete-then-create ordering: the server receives the
/// deletion request first and must still honour it when the target finally
/// shows up.
#[tokio::test]
async fn deletion_before_target_rejects_later_submission() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    // Promote a repo so we can build a well-formed issue against it. The issue
    // is built (so we know its id) but deliberately NOT sent yet.
    let (announcement, _repo_id) = publish_served_repo(&client, "delete-first").await;

    let issue = client
        .create_issue(
            &announcement,
            "Issue deleted before it arrives",
            "delete me",
            vec![],
        )
        .expect("build issue");
    let issue_id = issue.id;

    // Sanity: the relay has never seen the issue.
    assert!(
        !client
            .is_event_on_relay(issue_id)
            .await
            .expect("query issue before anything is sent"),
        "issue should not be served before it is ever submitted"
    );

    // Send the deletion FIRST — the relay receives the deletion request before
    // the event it deletes. This must be accepted (pre-emptive delete) and lay
    // down a tombstone for the issue id.
    let deletion = build_deletion(&client, &[issue_id], &[]);
    client
        .send_event(deletion)
        .await
        .expect("relay should accept pre-emptive deletion of own (not-yet-seen) event");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now send the issue the deletion already targeted. The resubmission gate
    // must reject it because a tombstone for this id already exists.
    let result = client.send_event(issue.clone()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let served = client
        .is_event_on_relay(issue_id)
        .await
        .expect("query issue after late submission");

    relay.stop().await;

    assert!(
        result.is_err(),
        "submission of an already-deleted event must be rejected, but it was accepted"
    );
    let msg = result.err().unwrap().to_string().to_lowercase();
    assert!(
        msg.contains("delete"),
        "rejection message should mention the event was deleted; got: {}",
        msg
    );
    assert!(
        !served,
        "issue {} must never be served: it was deleted before it arrived",
        issue_id
    );
}

/// 2c. Out-of-order deletion by a DIFFERENT pubkey must NOT be actioned.
///
/// Author B sends a kind-5 targeting (by `e` tag) an event id that the relay
/// has never seen — an id that will later belong to author A's event. Because
/// B is not the author of the target, the deletion must not lay down a
/// tombstone that censors A: when A subsequently submits the genuine event it
/// must be accepted and served.
///
/// This is the cross-author counterpart of
/// `deletion_before_target_rejects_later_submission`. The earlier
/// `deletion_author_mismatch_rejected` test only covers the case where the
/// target already exists; this one covers the harder out-of-order case where B
/// races ahead of A and could otherwise pre-emptively block A's event.
#[tokio::test]
async fn out_of_order_deletion_by_other_pubkey_not_actioned() {
    let relay = TestRelay::start().await;

    let author_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create author A client");
    let author_b = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create author B client");

    // A promotes a repo and builds (but does NOT yet send) an issue, so we know
    // the id of A's future event.
    let (announcement_a, _repo_id) = publish_served_repo(&author_a, "other-pubkey-race").await;
    let issue = author_a
        .create_issue(&announcement_a, "A's issue", "owned by A", vec![])
        .expect("build issue");
    let issue_id = issue.id;

    // Sanity: the relay has never seen the issue.
    assert!(
        !author_a
            .is_event_on_relay(issue_id)
            .await
            .expect("query issue before anything is sent"),
        "issue should not be served before it is ever submitted"
    );

    // B races ahead and sends a deletion targeting A's not-yet-seen event id.
    // The relay cannot yet know the author of the target. Whether the relay
    // accepts B's kind-5 (as a pre-emptive no-op) or rejects it outright, the
    // critical requirement is that it MUST NOT lay down a tombstone that blocks
    // A's genuine event.
    let deletion = build_deletion(&author_b, &[issue_id], &[]);
    let _ = author_b.send_event(deletion).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A now submits the genuine event. It must be accepted: B's deletion of an
    // event B does not own must never have been actioned.
    let result = author_a.send_event(issue.clone()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let served = author_a
        .is_event_on_relay(issue_id)
        .await
        .expect("query A's issue after submission");

    relay.stop().await;

    assert!(
        result.is_ok(),
        "A's genuine event must be accepted: a deletion from another pubkey \
         must not block it, but submission was rejected: {:?}",
        result.err()
    );
    assert!(
        served,
        "A's issue {} must be served: a deletion request from another pubkey \
         must not be actioned against A's events",
        issue_id
    );
}

/// 3. Author B cannot delete an event owned by author A: the relay rejects the
///    kind-5 with a message mentioning the authorship problem.
#[tokio::test]
async fn deletion_author_mismatch_rejected() {
    let relay = TestRelay::start().await;

    let author_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create author A client");

    // Author A publishes a repo + an issue (the e-tag target that EXISTS and is
    // owned by A).
    let (announcement_a, _repo_id) = publish_served_repo(&author_a, "author-mismatch").await;
    let issue = author_a
        .create_issue(&announcement_a, "A's issue", "owned by A", vec![])
        .expect("build issue");
    let issue_id = issue.id;
    author_a
        .send_event(issue.clone())
        .await
        .expect("relay should accept A's issue");

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        author_a
            .is_event_on_relay(issue_id)
            .await
            .expect("query A's issue"),
        "A's issue should be served before B's deletion attempt"
    );

    // Author B (a second, independent client / Keys) attempts to delete A's
    // event by `e` tag.
    let author_b = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create author B client");
    let deletion = build_deletion(&author_b, &[issue_id], &[]);

    let result = author_b.send_event(deletion).await;

    // The target must still be served (deletion was rejected, not acted upon).
    let still_served = author_a
        .is_event_on_relay(issue_id)
        .await
        .expect("query A's issue after B's rejected deletion");

    relay.stop().await;

    assert!(
        result.is_err(),
        "deletion of another author's event must be rejected"
    );
    let msg = result.err().unwrap().to_string().to_lowercase();
    assert!(
        msg.contains("author") || msg.contains("another pubkey") || msg.contains("pubkey"),
        "rejection message should mention authorship; got: {}",
        msg
    );
    assert!(
        still_served,
        "A's issue {} must remain served after B's rejected deletion",
        issue_id
    );
}

/// 4. A single kind-5 carrying three `e` tags deletes all three targets.
#[tokio::test]
async fn multiple_event_targets_in_one_deletion() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, _repo_id) = publish_served_repo(&client, "multi-e").await;

    let mut ids = Vec::new();
    for i in 0..3 {
        let issue = client
            .create_issue(
                &announcement,
                &format!("Issue {}", i),
                &format!("content {}", i),
                vec![],
            )
            .expect("build issue");
        ids.push(issue.id);
        client
            .send_event(issue)
            .await
            .expect("relay should accept issue");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    for id in &ids {
        assert!(
            client
                .is_event_on_relay(*id)
                .await
                .expect("query issue before deletion"),
            "issue {} should be served before deletion",
            id
        );
    }

    let deletion = build_deletion(&client, &ids, &[]);
    client
        .send_event(deletion)
        .await
        .expect("relay should accept multi-target deletion");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut still_served = Vec::new();
    for id in &ids {
        if client
            .is_event_on_relay(*id)
            .await
            .expect("query issue after deletion")
        {
            still_served.push(*id);
        }
    }

    relay.stop().await;

    assert!(
        still_served.is_empty(),
        "all three issues should be deleted; still served: {:?}",
        still_served
    );
}

/// 5. A single kind-5 carrying both an `e` tag (a served issue) and an `a`
///    coordinate (the promoted announcement) deletes both.
#[tokio::test]
async fn mixed_e_and_a_tag_deletion() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "mixed-ea").await;

    let issue = client
        .create_issue(&announcement, "Mixed issue", "delete via e tag", vec![])
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
            .expect("query issue before deletion"),
        "issue should be served before deletion"
    );

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    let deletion = build_deletion(&client, &[issue_id], &[coordinate]);
    client
        .send_event(deletion)
        .await
        .expect("relay should accept mixed e/a deletion");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let issue_served = client
        .is_event_on_relay(issue_id)
        .await
        .expect("query issue after deletion");
    let announcement_served_by_id = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement by id after deletion");
    let announcement_served_by_coord =
        announcement_served_by_coordinate(&client, &announcement, &repo_id).await;

    relay.stop().await;

    assert!(
        !issue_served,
        "issue {} should be deleted by its e tag",
        issue_id
    );
    assert!(
        !announcement_served_by_id,
        "announcement {} should be deleted by its a coordinate (by-id check)",
        announcement.id
    );
    assert!(
        !announcement_served_by_coord,
        "announcement {} should be deleted by its a coordinate (author+kind+identifier check)",
        announcement.id
    );
}

/// 6. Malformed `a` coordinates do not crash the relay. The live
///    `DeletionPolicy` silently treats unparseable coordinates as no-ops, so
///    each such request is accepted (acted on as a no-op). We assert the relay
///    keeps responding (the OK round-trips) for every malformed request.
#[tokio::test]
async fn deletion_invalid_address_format_handled_gracefully() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let malformed = [
        "invalid:format",   // only two parts
        "notanumber:pk:id", // unparseable kind
        "30617:badhex:id",  // unparseable pubkey hex
    ];

    for coord in malformed {
        let deletion = build_deletion(&client, &[], &[coord.to_string()]);
        let result = client.send_event(deletion).await;

        // Current behaviour: malformed coordinates are silently no-ops, so the
        // kind-5 is accepted. If the standard handling is ever tightened to a
        // rejection, the rejection message must still be non-empty.
        match result {
            Ok(_) => { /* accepted as a no-op — current behaviour */ }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.is_empty(),
                    "rejection of malformed coordinate {:?} must carry a non-empty message",
                    coord
                );
            }
        }
    }

    // The relay must still be alive and serving after all malformed requests:
    // prove it by round-tripping a normal acceptance.
    let probe = build_deletion(
        &client,
        &[
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .expect("parse probe id"),
        ],
        &[],
    );
    let probe_result = client.send_event(probe).await;

    relay.stop().await;

    assert!(
        probe_result.is_ok(),
        "relay must remain responsive after malformed-coordinate deletions; got: {:?}",
        probe_result.err()
    );
}

/// Status-quo characterisation: a kind-5 with NO `e`/`a` tags is currently
/// ACCEPTED by the relay (the `DeletionPolicy` simply records nothing and
/// returns Accept; there is no pre-gate requiring at least one target).
///
/// NIP-09 arguably calls for rejecting a deletion request that targets nothing.
/// This test documents the current standard-relay accept-as-no-op outcome; if
/// the NIP-09 policy is ever tightened to reject empty deletions, update this
/// test (and flip the assertion) to match the new standard behaviour.
#[tokio::test]
async fn empty_deletion_currently_accepted() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let deletion = build_deletion(&client, &[], &[]);

    let result = client.send_event(deletion).await;

    relay.stop().await;

    assert!(
        result.is_ok(),
        "status quo: an empty kind-5 (no e/a tags) is currently accepted; got: {:?}",
        result.err()
    );
}

/// 7. NIP-09 timestamp rule for addressable events: an `a`-coordinate deletion
///    only deletes versions of that coordinate with `created_at` *up to* the
///    deletion request's `created_at`. A NEWER version of the same coordinate,
///    published after the deletion, must be accepted and served — the deletion
///    must not censor it.
///
/// To keep this focused on the NIP-09 timestamp rule (and away from the
/// purgatory/git-promotion machinery that kind-30617 announcements require), the
/// addressable event under test is a generic kind-30078 (NIP-78
/// application-specific data) event that references the promoted repo by its `a`
/// coordinate. Like an issue, a referencing event is a Layer-2 event served
/// immediately — but unlike an issue it is *addressable*, so the NIP-09
/// `created_at` rule for `a`-tag deletions applies to it.
///
/// Flow:
///   1. Promote a repo announcement (served) to anchor referencing events.
///   2. Publish addressable event v1 (kind 30078, own `d`) referencing the repo;
///      it is served immediately.
///   3. Delete it by its own `a` coordinate (`30078:<pubkey>:<d>`), with the
///      deletion's `created_at == now`.
///   4. Verify v1 is gone.
///   5. Publish v2 of the SAME coordinate with a strictly newer `created_at` and
///      assert it is accepted and served — the deletion must not block it.
///
/// This is the served/main-DB counterpart of the purgatory-only unit test
/// `test_deletion_by_coordinate_respects_created_at` in
/// `src/nostr/policy/deletion.rs`, and exercises the resubmission gate's
/// `is_coordinate_deleted` timestamp check (a newer event must NOT be blocked).
#[tokio::test]
async fn newer_addressable_event_survives_a_tag_deletion() {
    // A generic addressable (parameterized-replaceable) kind in the 30000-39999
    // range. NIP-78 application-specific data; any addressable kind works.
    const ADDRESSABLE_KIND: u16 = 30078;

    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    // Stage 1: promote a repo so referencing events are accepted/served.
    let (announcement, repo_id) = publish_served_repo(&client, "newer-survives").await;
    let repo_coord = announcement_coordinate(&announcement, &repo_id);

    // Build the addressable coordinate under test: `30078:<pubkey>:<d>`.
    let addr_d = format!("note-{}", &repo_id);
    let addr_coord = format!(
        "{}:{}:{}",
        ADDRESSABLE_KIND,
        client.public_key().to_hex(),
        addr_d
    );

    // Helper: build a kind-30078 addressable event referencing the repo's `a`
    // coordinate, with the given content and created_at.
    let build_addressable = |content: &str, ts: Timestamp| {
        client
            .event_builder(Kind::from(ADDRESSABLE_KIND), content)
            .tag(Tag::identifier(&addr_d))
            .tag(Tag::custom("a", vec![repo_coord.clone()]))
            .custom_time(ts)
            .build(client.keys())
            .expect("build addressable event")
    };

    // Stage 2: publish addressable v1 (older). It references the promoted repo,
    // so it is a Layer-2 event served immediately.
    let v1 = build_addressable("version 1", Timestamp::now());
    let v1_id = v1.id;
    client
        .send_event(v1.clone())
        .await
        .expect("relay should accept addressable event referencing the repo");

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        client
            .is_event_on_relay(v1_id)
            .await
            .expect("query v1 before deletion"),
        "addressable v1 should be served before deletion"
    );

    // Stage 3: delete v1 by its own `a` coordinate. The deletion's created_at is
    // "now", so only versions at or before now are deleted.
    let deletion = build_deletion(&client, &[], std::slice::from_ref(&addr_coord));
    let deletion_ts = deletion.created_at;
    client
        .send_event(deletion)
        .await
        .expect("relay should accept deletion by coordinate");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Stage 4: v1 must be gone.
    assert!(
        !client
            .is_event_on_relay(v1_id)
            .await
            .expect("query v1 after deletion"),
        "addressable v1 {} should be deleted by its a coordinate",
        v1_id
    );

    // Stage 5: publish v2 of the SAME coordinate with a strictly newer
    // created_at than the deletion request. The resubmission gate must NOT block
    // it (it is newer than the deletion), so it is accepted and served.
    let newer_ts = Timestamp::from(deletion_ts.as_secs() + 60);
    let v2 = build_addressable("version 2", newer_ts);
    let v2_id = v2.id;
    assert!(
        v2.created_at > deletion_ts,
        "v2 must be strictly newer than the deletion request"
    );

    client
        .send_event(v2.clone())
        .await
        .expect("relay should accept an addressable event newer than the deletion request");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let served_by_id = client
        .is_event_on_relay(v2_id)
        .await
        .expect("query v2 by id");

    // Also confirm it is served via a real NIP-01 addressable-event query
    // (author + kind + d identifier), not just by id.
    let coord_filter = Filter::new()
        .kind(Kind::from(ADDRESSABLE_KIND))
        .author(client.public_key())
        .identifier(&addr_d);
    let served_by_coord = client
        .query(coord_filter)
        .await
        .expect("query v2 by coordinate")
        .iter()
        .any(|e| e.id == v2_id);

    relay.stop().await;

    assert!(
        served_by_id,
        "newer addressable v2 {} must be served (by-id): a NIP-09 deletion \
         must not censor a version newer than the deletion request",
        v2_id
    );
    assert!(
        served_by_coord,
        "newer addressable v2 {} must be served (by author+kind+identifier): \
         a NIP-09 deletion must not censor a version newer than the deletion request",
        v2_id
    );
}

/// 8. Baseline: a default (normal-mode) relay honours a kind-5 deletion that
///    targets a promoted announcement by its `a` coordinate — the announcement
///    is no longer served, neither by id nor by author+kind+identifier.
///
/// This is the deletion-honoured counterpart to the disrespector mode's
/// "accept but ignore" behaviour (`disrespector_accepts_but_ignores_deletion`
/// in `nip09_disrespector.rs`), kept here as a basic NIP-09 validation test.
#[tokio::test]
async fn normal_mode_honours_deletion() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "normal-honours").await;

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    let deletion = build_deletion(&client, &[announcement.id], &[coordinate]);

    client
        .send_event(deletion)
        .await
        .expect("normal relay should OK the kind-5 deletion");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let served_by_id = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement by id after deletion");
    let served_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement, &repo_id).await;

    relay.stop().await;

    assert!(
        !served_by_id,
        "normal relay must honour the deletion: announcement {} should no longer be \
         queryable by id",
        announcement.id
    );
    assert!(
        !served_by_coordinate,
        "normal relay must honour the deletion: announcement {} should no longer be served \
         for an author+kind+identifier query",
        announcement.id
    );
}
