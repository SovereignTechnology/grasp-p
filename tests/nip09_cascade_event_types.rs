//! NIP-09 announcement cascade coverage across supported dependent kinds.
//!
//! Covered here (single-maintainer): patch (1617), issue (1621), issue-status
//! (1630), comment (1111), repo-status (1633), PR chain
//! (1618/1619/1631/1632).

mod common;

use common::{
    announcement_coordinate, build_deletion, create_pr_event, publish_served_repo,
    push_ref_to_relay, TestRelay,
};

use grasp_audit::{clone_repo, AuditClient, AuditConfig, DETERMINISTIC_COMMIT_HASH};
use nostr_sdk::prelude::*;
use std::fs;
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

#[tokio::test]
async fn test_announcement_cascade_deletes_served_pr_chain_kinds() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let relay_url = client
        .relay_url()
        .await
        .expect("client should have relay url");
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let npub = client.public_key().to_bech32().expect("pubkey to bech32");

    let (announcement, repo_id) = publish_served_repo(&client, "cascade-pr-chain").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let pr = create_pr_event(&keys, &coordinate, DETERMINISTIC_COMMIT_HASH, "cascade pr")
        .expect("build PR event");
    client
        .send_event(pr.clone())
        .await
        .expect("relay should accept PR event");

    let pr_update = client
        .event_builder(Kind::GitPullRequestUpdate, "cascade pr update")
        .tag(Tag::custom("a", vec![coordinate.clone()]))
        .tag(Tag::custom("e", vec![pr.id.to_hex()]))
        .tag(Tag::custom(
            "c",
            vec![DETERMINISTIC_COMMIT_HASH.to_string()],
        ))
        .build(&keys)
        .expect("build PR update event");
    client
        .send_event(pr_update.clone())
        .await
        .expect("relay should accept PR update event");

    let clone_path = clone_repo(&relay_domain, &npub, &repo_id).expect("clone served repo");
    let pr_ref = format!("refs/nostr/{}", pr.id.to_hex());
    let pr_update_ref = format!("refs/nostr/{}", pr_update.id.to_hex());
    push_ref_to_relay(
        clone_path.as_path(),
        &relay_domain,
        &npub,
        &repo_id,
        DETERMINISTIC_COMMIT_HASH,
        &pr_ref,
    )
    .expect("push PR ref should succeed");
    push_ref_to_relay(
        clone_path.as_path(),
        &relay_domain,
        &npub,
        &repo_id,
        DETERMINISTIC_COMMIT_HASH,
        &pr_update_ref,
    )
    .expect("push PR update ref should succeed");
    fs::remove_dir_all(&clone_path).expect("remove cloned repo");

    let pr_status = client
        .event_builder(Kind::from(1631), "pr status")
        .tag(Tag::custom("e", vec![pr.id.to_hex()]))
        .build(&keys)
        .expect("build PR status");
    let patch_status = client
        .event_builder(Kind::from(1632), "patch status")
        .tag(Tag::custom("e", vec![pr_update.id.to_hex()]))
        .build(&keys)
        .expect("build patch status");

    for event in [&pr_status, &patch_status] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept status event");
    }

    tokio::time::sleep(Duration::from_millis(600)).await;

    let cascade_chain = [
        ("announcement", announcement.id),
        ("pr", pr.id),
        ("pr_update", pr_update.id),
        ("pr_status", pr_status.id),
        ("patch_status", patch_status.id),
    ];

    for (label, id) in cascade_chain {
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

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut survivors = Vec::new();
    for (label, id) in cascade_chain {
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
        "announcement deletion should cascade across PR-chain dependent kinds; survivors: {survivors:?}"
    );
}

#[tokio::test]
async fn test_announcement_cascade_deletes_deep_mixed_reference_chain() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, repo_id) = publish_served_repo(&client, "cascade-deep-mixed-chain").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    // Root-dependent issue and patch via `a` tags.
    let issue = client
        .create_issue(&announcement, "Deep chain issue", "issue body", vec![])
        .expect("build issue");
    let patch = client
        .event_builder(Kind::from(1617), "deep chain patch")
        .tag(Tag::custom("a", vec![coordinate.clone()]))
        .build(&keys)
        .expect("build patch");

    // Mid-chain descendants mix `e` and `q` references.
    let comment = client
        .event_builder(Kind::from(1111), "comment on issue")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build issue comment");
    let quote = client
        .event_builder(Kind::from(1111), "quote patch and comment")
        .tag(Tag::custom("q", vec![patch.id.to_hex()]))
        .tag(Tag::custom("e", vec![comment.id.to_hex()]))
        .build(&keys)
        .expect("build quote event");

    // Deep leaf status references quote by `q` and issue by `e`.
    let status = client
        .event_builder(Kind::from(1630), "deep chain status")
        .tag(Tag::custom("q", vec![quote.id.to_hex()]))
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build deep status");

    for event in [&issue, &patch, &comment, &quote, &status] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept deep-chain event");
    }

    tokio::time::sleep(Duration::from_millis(350)).await;

    let deep_chain = [
        ("announcement", announcement.id),
        ("issue", issue.id),
        ("patch", patch.id),
        ("comment", comment.id),
        ("quote", quote.id),
        ("status", status.id),
    ];

    for (label, id) in deep_chain {
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

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut survivors = Vec::new();
    for (label, id) in deep_chain {
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
        "announcement deletion should cascade through deep mixed-tag chains; survivors: {survivors:?}"
    );
}

#[tokio::test]
async fn test_sequential_overlapping_deletions_are_idempotent() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, repo_id) = publish_served_repo(&client, "cascade-idempotent-order").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let issue = client
        .create_issue(&announcement, "Ordering issue", "issue body", vec![])
        .expect("build issue");
    let patch = client
        .event_builder(Kind::from(1617), "ordering patch")
        .tag(Tag::custom("a", vec![coordinate.clone()]))
        .build(&keys)
        .expect("build patch");
    let comment = client
        .event_builder(Kind::from(1111), "ordering comment")
        .tag(Tag::custom("e", vec![patch.id.to_hex()]))
        .build(&keys)
        .expect("build comment");

    for event in [&issue, &patch, &comment] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept ordering test event");
    }

    tokio::time::sleep(Duration::from_millis(350)).await;

    let chain = [
        ("announcement", announcement.id),
        ("issue", issue.id),
        ("patch", patch.id),
        ("comment", comment.id),
    ];
    for (label, id) in chain {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }

    // Step 1: remove one dependent by event-id.
    client
        .send_event(build_deletion(&client, &[patch.id], &[]))
        .await
        .expect("relay should accept patch deletion");

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query announcement after step 1"),
        "announcement should still exist after deleting patch by e-tag"
    );
    assert!(
        !client
            .is_event_on_relay(patch.id)
            .await
            .expect("query patch after step 1"),
        "patch should be deleted after step 1"
    );

    // Step 2: delete root coordinate to trigger full cascade.
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("relay should accept announcement deletion");

    // Step 3: repeat overlapping deletions (idempotence / no-op semantics).
    client
        .send_event(build_deletion(
            &client,
            &[patch.id, comment.id],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("relay should accept repeated overlapping deletion");

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut survivors = Vec::new();
    for (label, id) in chain {
        if client
            .is_event_on_relay(id)
            .await
            .expect("query event after final deletion")
        {
            survivors.push(format!("{label} ({id})"));
        }
    }

    relay.stop().await;

    assert!(
        survivors.is_empty(),
        "sequential overlapping deletions must converge to the same final empty state; survivors: {survivors:?}"
    );
}

#[tokio::test]
async fn test_announcement_cascade_traverses_mixed_tag_variants() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, repo_id) = publish_served_repo(&client, "cascade-tag-variants").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    // Use accepted uppercase/lowercase variants for address/event references.
    let patch_upper_a = client
        .event_builder(Kind::from(1617), "patch via uppercase A")
        .tag(Tag::custom("A", vec![coordinate.clone()]))
        .build(&keys)
        .expect("build uppercase-A patch");
    let comment_upper_e = client
        .event_builder(Kind::from(1111), "comment via uppercase E")
        .tag(Tag::custom("E", vec![patch_upper_a.id.to_hex()]))
        .build(&keys)
        .expect("build uppercase-E comment");
    let quote_lower_q = client
        .event_builder(Kind::from(1111), "quote via lowercase q")
        .tag(Tag::custom("q", vec![comment_upper_e.id.to_hex()]))
        .build(&keys)
        .expect("build lowercase-q quote");

    for event in [&patch_upper_a, &comment_upper_e, &quote_lower_q] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept mixed-tag event");
    }

    tokio::time::sleep(Duration::from_millis(350)).await;

    for (label, id) in [
        ("announcement", announcement.id),
        ("patch_upper_a", patch_upper_a.id),
        ("comment_upper_e", comment_upper_e.id),
        ("quote_lower_q", quote_lower_q.id),
    ] {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }

    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("relay should accept announcement deletion");

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut survivors = Vec::new();
    for (label, id) in [
        ("announcement", announcement.id),
        ("patch_upper_a", patch_upper_a.id),
        ("comment_upper_e", comment_upper_e.id),
        ("quote_lower_q", quote_lower_q.id),
    ] {
        if client
            .is_event_on_relay(id)
            .await
            .expect("query event after deletion")
        {
            survivors.push(format!("{label} ({id})"));
        }
    }

    relay.stop().await;

    assert!(
        survivors.is_empty(),
        "announcement deletion should traverse mixed tag variants; survivors: {survivors:?}"
    );
}

#[tokio::test]
async fn test_announcement_cascade_covers_fanout_fanin_graph() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, repo_id) = publish_served_repo(&client, "cascade-fanout-fanin").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    // Fan-out: multiple top-level dependents from the same root.
    let top_a = client
        .event_builder(Kind::from(1617), "top A")
        .tag(Tag::custom("a", vec![coordinate.clone()]))
        .build(&keys)
        .expect("build top A");
    let top_b = client
        .event_builder(Kind::from(1617), "top B")
        .tag(Tag::custom("a", vec![coordinate.clone()]))
        .build(&keys)
        .expect("build top B");
    let top_c = client
        .event_builder(Kind::from(1617), "top C")
        .tag(Tag::custom("a", vec![coordinate.clone()]))
        .build(&keys)
        .expect("build top C");

    // Fan-in: converging descendants referencing multiple parents.
    let fanin_left = client
        .event_builder(Kind::from(1111), "fanin left")
        .tag(Tag::custom("e", vec![top_a.id.to_hex()]))
        .tag(Tag::custom("q", vec![top_b.id.to_hex()]))
        .build(&keys)
        .expect("build fanin left");
    let fanin_right = client
        .event_builder(Kind::from(1111), "fanin right")
        .tag(Tag::custom("e", vec![top_b.id.to_hex()]))
        .tag(Tag::custom("q", vec![top_c.id.to_hex()]))
        .build(&keys)
        .expect("build fanin right");
    let sink_status = client
        .event_builder(Kind::from(1630), "fanin sink status")
        .tag(Tag::custom("e", vec![fanin_left.id.to_hex()]))
        .tag(Tag::custom("q", vec![fanin_right.id.to_hex()]))
        .build(&keys)
        .expect("build sink status");

    for event in [
        &top_a,
        &top_b,
        &top_c,
        &fanin_left,
        &fanin_right,
        &sink_status,
    ] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept fanout/fanin event");
    }

    tokio::time::sleep(Duration::from_millis(350)).await;

    let graph = [
        ("announcement", announcement.id),
        ("top_a", top_a.id),
        ("top_b", top_b.id),
        ("top_c", top_c.id),
        ("fanin_left", fanin_left.id),
        ("fanin_right", fanin_right.id),
        ("sink_status", sink_status.id),
    ];

    for (label, id) in graph {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }

    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("relay should accept announcement deletion");

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut survivors = Vec::new();
    for (label, id) in graph {
        if client
            .is_event_on_relay(id)
            .await
            .expect("query event after deletion")
        {
            survivors.push(format!("{label} ({id})"));
        }
    }

    relay.stop().await;

    assert!(
        survivors.is_empty(),
        "announcement deletion should traverse complete fanout/fanin graph; survivors: {survivors:?}"
    );
}
