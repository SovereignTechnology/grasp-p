//! NIP-09 announcement cascade-deletion integration test.
//!
//! This is the end-to-end characterisation of ngit-grasp's *custom* cascade
//! deletion: deleting a kind-30617 repository announcement by its `a`
//! coordinate must hard-delete the announcement AND every dependent event that
//! is only reachable through that announcement (issues, patches, comments,
//! status events, etc.).
//!
//! This is deliberately NOT in `nip09_validation.rs`, which is reserved for
//! stock NIP-09 behaviour. Cascade deletion is an ngit-grasp extension.
//!
//! The announcement is promoted out of purgatory via the shared
//! [`publish_served_repo`] helper (which performs the real git clone + commit +
//! push dance), so the announcement and its dependents are genuinely in the
//! main database before deletion. We assert that pre-condition, submit the
//! kind-5 `a`-tag deletion, and then assert the announcement AND all dependents
//! are hard-deleted from the main DB (no "moved to holding" hand-waving — real
//! `is_empty()` / `!served` checks).
//!
//! # Running
//!
//! ```bash
//! cargo test --test nip09_announcement_cascade
//! cargo test --test nip09_announcement_cascade -- --nocapture
//! ```

mod common;

use common::{announcement_coordinate, build_deletion, publish_served_repo, TestRelay};

use grasp_audit::{AuditClient, AuditConfig};
use nostr_sdk::prelude::*;
use std::time::Duration;

/// Deleting a repository announcement by its `a` coordinate cascades to all
/// dependent events that are only reachable through that announcement.
///
/// Setup (all genuinely stored in the main DB before deletion):
///   - announcement (kind 30617), promoted out of purgatory via git push
///   - issue (kind 1621) referencing the announcement via an `a` tag
///   - patch (kind 1617) referencing the announcement via an `a` tag
///   - issue status (kind 1630) referencing the issue via an `e` tag
///   - comment (kind 1111) referencing the issue via an `e` tag
///
/// After deleting the announcement: announcement + ALL dependents must be gone.
#[tokio::test]
async fn test_announcement_cascade_deletes_dependents() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    // Stage 1: promote a repo announcement out of purgatory (real git push) so
    // it (and everything referencing it) is genuinely served from the main DB.
    let (announcement, repo_id) = publish_served_repo(&client, "cascade-deletes").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    // Stage 2: build dependent events.
    //
    // issue / patch reference the announcement via an `a` tag (the graph's
    // address edge). issue_status / comment reference the issue via an `e` tag
    // (the graph's event edge), so they are only transitively reachable through
    // the announcement.
    let issue = client
        .create_issue(&announcement, "Cascade issue", "issue body", vec![])
        .expect("build issue");

    let patch = client
        .event_builder(Kind::from(1617), "patch content")
        .tag(Tag::custom("a", vec![coordinate.clone()]))
        .build(&keys)
        .expect("build patch");

    let issue_status = client
        .event_builder(Kind::from(1630), "status: open")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build issue status");

    let comment = client
        .event_builder(Kind::from(1111), "a comment on the issue")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build comment");

    for event in [&issue, &patch, &issue_status, &comment] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept dependent event");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Stage 3: STRICT pre-condition — every event is genuinely served from the
    // main DB before the deletion. If any of these is missing the cascade test
    // would be vacuous, so assert them all.
    let dependents = [
        ("announcement", announcement.id),
        ("issue", issue.id),
        ("patch", patch.id),
        ("issue_status", issue_status.id),
        ("comment", comment.id),
    ];
    for (label, id) in dependents {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served from the main DB before deletion"
        );
    }

    // Stage 4: delete the announcement by its `a` coordinate. This is the only
    // trigger for the graph-based cascade path.
    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate));
    client
        .send_event(deletion)
        .await
        .expect("relay should accept the announcement deletion");

    tokio::time::sleep(Duration::from_millis(600)).await;

    // Stage 5: STRICT post-condition — the announcement AND every dependent are
    // hard-deleted from the main DB. These are real removal checks, not
    // "moved to holding" placeholders.
    let mut survivors = Vec::new();
    for (label, id) in dependents {
        let served = client
            .is_event_on_relay(id)
            .await
            .expect("query event after deletion");
        if served {
            survivors.push(format!("{label} ({id})"));
        }
    }

    // Also confirm the announcement is gone for a real NIP-01 addressable query
    // (author + kind + d identifier), not just a by-id lookup.
    let announcement_by_coord = client
        .query(
            Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(announcement.pubkey)
                .identifier(&repo_id),
        )
        .await
        .expect("query announcement by coordinate")
        .iter()
        .any(|e| e.id == announcement.id);

    relay.stop().await;

    assert!(
        survivors.is_empty(),
        "deleting the announcement must cascade-delete all dependents; \
         these events survived: {survivors:?}"
    );
    assert!(
        !announcement_by_coord,
        "announcement {} must not be served for an author+kind+identifier query after deletion",
        announcement.id
    );
}

/// Deleting a patch by `e` tag must stay on the simple deletion path:
/// only the patch is removed, while the announcement and unrelated siblings
/// survive.
#[tokio::test]
async fn test_deleting_patch_by_event_id_does_not_delete_announcement_or_siblings() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, repo_id) = publish_served_repo(&client, "simple-delete-patch").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let issue = client
        .create_issue(&announcement, "Sibling issue", "must survive", vec![])
        .expect("build issue");

    let patch = client
        .event_builder(Kind::from(1617), "patch to delete")
        .tag(Tag::custom("a", vec![coordinate.clone()]))
        .build(&keys)
        .expect("build patch");

    for event in [&issue, &patch] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept dependent event");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    let precondition = [
        ("announcement", announcement.id),
        ("issue", issue.id),
        ("patch", patch.id),
    ];
    for (label, id) in precondition {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before patch deletion"
        );
    }

    let deletion = build_deletion(&client, &[patch.id], &[]);
    client
        .send_event(deletion)
        .await
        .expect("relay should accept patch deletion");

    tokio::time::sleep(Duration::from_millis(600)).await;

    let announcement_survived = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement after deletion");
    let issue_survived = client
        .is_event_on_relay(issue.id)
        .await
        .expect("query issue after deletion");
    let patch_survived = client
        .is_event_on_relay(patch.id)
        .await
        .expect("query patch after deletion");
    relay.stop().await;

    assert!(
        announcement_survived,
        "announcement must survive patch e-tag deletion"
    );
    assert!(
        issue_survived,
        "unrelated sibling issue must survive patch e-tag deletion"
    );
    assert!(!patch_survived, "patch must be deleted by its e-tag");
}

/// Deleting a comment by `e` tag must not trigger repository graph cascade:
/// the parent issue and announcement must survive.
#[tokio::test]
async fn test_deleting_comment_by_event_id_does_not_cascade_to_issue_or_announcement() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, _repo_id) = publish_served_repo(&client, "simple-delete-comment").await;

    let issue = client
        .create_issue(&announcement, "Issue anchor", "must survive", vec![])
        .expect("build issue");
    let comment = client
        .event_builder(Kind::from(1111), "comment to delete")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build comment");

    for event in [&issue, &comment] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept event");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    for (label, id) in [
        ("announcement", announcement.id),
        ("issue", issue.id),
        ("comment", comment.id),
    ] {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before comment deletion"
        );
    }

    let deletion = build_deletion(&client, &[comment.id], &[]);
    client
        .send_event(deletion)
        .await
        .expect("relay should accept comment deletion");

    tokio::time::sleep(Duration::from_millis(600)).await;

    let announcement_survived = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement after deletion");
    let issue_survived = client
        .is_event_on_relay(issue.id)
        .await
        .expect("query issue after deletion");
    let comment_survived = client
        .is_event_on_relay(comment.id)
        .await
        .expect("query comment after deletion");

    relay.stop().await;

    assert!(
        announcement_survived,
        "announcement must survive comment e-tag deletion"
    );
    assert!(issue_survived, "issue must survive comment e-tag deletion");
    assert!(!comment_survived, "comment must be deleted by its e-tag");
}
