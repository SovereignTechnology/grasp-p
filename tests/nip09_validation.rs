//! NIP-09 deletion-request validation integration tests (Phase 1)
//!
//! Characterises the *current* `pr/cascade-delete` branch behaviour of the
//! relay's kind-5 (EventDeletion) handling end-to-end against a live
//! ngit-grasp instance driven by the [`TestRelay`] fixture.
//!
//! This is Phase 1 of the cascade/multi-maintainer deletion work: it locks in
//! validation-only behaviour. There is deliberately NO cascade, NO
//! multi-maintainer graph, and NO holding-DB / archival / recovery exercised
//! here.
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
//! - malformed `a` coordinates are silently treated as no-ops (accepted).
//!
//! `normal_mode_honours_deletion` in `nip09_disrespector.rs` already covers the
//! "announcement deleted by `a` coordinate is removed" path, so it is NOT
//! duplicated here.
//!
//! # Running
//!
//! ```bash
//! cargo test --test nip09_validation
//! cargo test --test nip09_validation -- --nocapture
//! ```

mod common;

use common::TestRelay;

use grasp_audit::{
    clone_repo, create_deterministic_commit, try_push, AuditClient, AuditConfig,
    DETERMINISTIC_COMMIT_HASH,
};
use nostr_sdk::prelude::*;
use std::path::PathBuf;
use std::time::Duration;

/// Publish a repo announcement, submit a matching state event, and push the
/// deterministic git data so the announcement is promoted out of purgatory and
/// becomes queryable.
///
/// Returns the announcement event (kind 30617) and its repo identifier.
///
/// Copied (inline) from `nip09_disrespector.rs` so this file is self-contained.
/// A kind-30617 announcement is NOT queryable until git data is pushed; the
/// tests that target the announcement therefore need it promoted first. Layer-2
/// events (issues/notes) that reference the promoted repo are served
/// immediately and do not need this dance.
async fn publish_served_repo(client: &AuditClient, test_name: &str) -> (Event, String) {
    let relay_url = client
        .relay_url()
        .await
        .expect("client should have a relay");
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let http_url = format!("http://{}", relay_domain);

    let npub = client.public_key().to_bech32().expect("pubkey to bech32");

    let repo_id = format!(
        "{}-{}",
        test_name,
        &Keys::generate().public_key().to_hex()[..8]
    );

    // Stage 1: announcement (enters purgatory until git data arrives)
    let announcement = client
        .event_builder(Kind::GitRepoAnnouncement, "")
        .tag(Tag::identifier(&repo_id))
        .tag(Tag::custom("name", vec![repo_id.clone()]))
        .tag(Tag::custom(
            "clone",
            vec![format!("{}/{}/{}.git", http_url, npub, repo_id)],
        ))
        .tag(Tag::custom("relays", vec![relay_url.clone()]))
        .build(client.keys())
        .expect("build announcement");

    client
        .send_event(announcement.clone())
        .await
        .expect("relay should accept announcement");

    // Stage 2: state event pointing at the deterministic commit (purgatory)
    let state_event = client
        .event_builder(Kind::RepoState, "")
        .tag(Tag::identifier(&repo_id))
        .tag(Tag::custom(
            "refs/heads/main",
            vec![DETERMINISTIC_COMMIT_HASH.to_string()],
        ))
        .tag(Tag::custom(
            "HEAD",
            vec!["ref: refs/heads/main".to_string()],
        ))
        .build(client.keys())
        .expect("build state event");

    client
        .send_event_and_note_purgatory(state_event.clone())
        .await
        .expect("relay should accept state event");

    // Stage 3: clone, create the deterministic commit, push — promotes the repo
    let clone_path =
        clone_repo(&relay_domain, &npub, &repo_id).expect("clone purgatory repo over git http");

    let cleanup = |path: &PathBuf| {
        let _ = std::fs::remove_dir_all(path);
    };

    let commit_hash = match create_deterministic_commit(&clone_path, "Initial commit") {
        Ok(h) => h,
        Err(e) => {
            cleanup(&clone_path);
            panic!("failed to create deterministic commit: {}", e);
        }
    };
    assert_eq!(
        commit_hash, DETERMINISTIC_COMMIT_HASH,
        "deterministic commit hash mismatch"
    );

    let _ = std::process::Command::new("git")
        .args(["branch", "main"])
        .current_dir(&clone_path)
        .output();
    let _ = std::process::Command::new("git")
        .args(["checkout", "main"])
        .current_dir(&clone_path)
        .output();

    let pushed = try_push(&clone_path);
    cleanup(&clone_path);
    match pushed {
        Ok(true) => {}
        Ok(false) => panic!("git push rejected while promoting repo out of purgatory"),
        Err(e) => panic!("git push error while promoting repo: {}", e),
    }

    // Give the relay a moment to promote the events out of purgatory.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query announcement"),
        "announcement should be served after git data arrives"
    );

    (announcement, repo_id)
}

/// Query the relay for a served repo announcement using a real client's access
/// pattern: author + kind + `d` identifier (a NIP-01 addressable-event query),
/// rather than a by-id lookup. Returns whether the relay serves it.
///
/// Copied (inline) from `nip09_disrespector.rs`.
async fn announcement_served_by_coordinate(
    client: &AuditClient,
    announcement: &Event,
    repo_id: &str,
) -> bool {
    let filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(announcement.pubkey)
        .identifier(repo_id);

    client
        .query(filter)
        .await
        .expect("query announcement by coordinate")
        .iter()
        .any(|e| e.id == announcement.id)
}

/// Build a kind-5 deletion request signed by `client` carrying the supplied
/// `e`-tag event ids and `a`-tag coordinate strings.
///
/// A more general form of the `nip09_disrespector.rs` `build_deletion` helper;
/// kept inline here so this file is self-contained.
fn build_deletion(client: &AuditClient, event_ids: &[EventId], coordinates: &[String]) -> Event {
    let mut builder = client.event_builder(Kind::EventDeletion, "delete");

    for id in event_ids {
        builder = builder.tag(Tag::event(*id));
    }
    for coord in coordinates {
        builder = builder.tag(Tag::custom("a", vec![coord.clone()]));
    }

    builder.build(client.keys()).expect("build deletion event")
}

/// Coordinate string for a kind-30617 announcement: `30617:<pubkey-hex>:<d>`.
fn announcement_coordinate(announcement: &Event, repo_id: &str) -> String {
    format!(
        "{}:{}:{}",
        Kind::GitRepoAnnouncement.as_u16(),
        announcement.pubkey.to_hex(),
        repo_id
    )
}

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
    let nonexistent = EventId::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
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
        .create_issue(&announcement, "Issue deleted before it arrives", "delete me", vec![])
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
        "invalid:format",      // only two parts
        "notanumber:pk:id",    // unparseable kind
        "30617:badhex:id",     // unparseable pubkey hex
    ];

    for coord in malformed {
        let deletion = build_deletion(&client, &[], &[coord.to_string()]);
        let result = client.send_event(deletion).await;

        // Current behaviour: malformed coordinates are silently no-ops, so the
        // kind-5 is accepted. If a future phase tightens this to a rejection,
        // the rejection message must still be non-empty.
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
        &[EventId::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .expect("parse probe id")],
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
/// TODO(phase-?): NIP-09 arguably calls for rejecting a deletion request that
/// targets nothing. Phase 1 only characterises existing behaviour and must not
/// change production code, so this test documents the current accept-as-no-op
/// outcome. Tighten to a rejection (and flip this assertion) in a later phase
/// if/when the policy is updated.
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
