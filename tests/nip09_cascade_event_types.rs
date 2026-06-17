//! NIP-09 announcement cascade coverage across supported dependent kinds.
//!
//! Covered here (single-maintainer): patch (1617), issue (1621), issue-status
//! (1630), comment (1111), repo-status (1633).
//!
//! Not covered here: PR/PR-update/status chain (1618/1619/1631/1632), because
//! those events require additional PR-specific git wiring and acceptance setup.

mod common;

use common::{announcement_coordinate, build_deletion, publish_served_repo, TestRelay};

use grasp_audit::{AuditClient, AuditConfig};
use nostr_sdk::prelude::*;
use std::time::Duration;

#[tokio::test]
async fn test_announcement_cascade_deletes_supported_dependent_kinds() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, repo_id) = publish_served_repo(&client, "cascade-event-types").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

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
        .event_builder(Kind::from(1111), "issue comment")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build comment");

    let repo_status = client
        .event_builder(Kind::from(1633), "repo status")
        .tag(Tag::custom("e", vec![announcement.id.to_hex()]))
        .build(&keys)
        .expect("build repository status");

    for event in [&issue, &patch, &issue_status, &comment, &repo_status] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept dependent event");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    let dependents = [
        ("announcement", announcement.id),
        ("issue", issue.id),
        ("patch", patch.id),
        ("issue_status", issue_status.id),
        ("comment", comment.id),
        ("repo_status", repo_status.id),
    ];

    for (label, id) in dependents {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate));
    client
        .send_event(deletion)
        .await
        .expect("relay should accept announcement deletion");

    tokio::time::sleep(Duration::from_millis(600)).await;

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

    relay.stop().await;

    assert!(
        survivors.is_empty(),
        "announcement deletion should cascade across covered dependent kinds; survivors: {survivors:?}"
    );
}
