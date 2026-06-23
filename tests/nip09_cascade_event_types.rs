//! NIP-09 announcement cascade coverage across supported dependent kinds.
//!
//! Covered here (single-maintainer): patch (1617), issue (1621), issue-status
//! (1630), comment (1111), repo-status (1633), PR chain
//! (1618/1619/1631/1632).

mod common;

use common::{
    announcement_coordinate, build_deletion, create_pr_event, create_pr_event_with_clone,
    publish_served_repo, push_ref_to_relay, TestRelay,
};

use grasp_audit::{clone_repo, AuditClient, AuditConfig, DETERMINISTIC_COMMIT_HASH};
use nostr_sdk::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn repo_has_ref(repo_path: &Path, ref_name: &str) -> bool {
    let output = Command::new("git")
        .args([
            "--git-dir",
            repo_path.to_str().expect("repo path utf8"),
            "show-ref",
            "--verify",
            ref_name,
        ])
        .output()
        .expect("run git show-ref");
    output.status.success()
}

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

    let repo_path = relay
        .git_data_path()
        .join(client.public_key().to_bech32().expect("pubkey to bech32"))
        .join(format!("{}.git", repo_id));
    assert!(
        repo_has_ref(&repo_path, &pr_ref),
        "PR ref should exist before deletion"
    );
    assert!(
        repo_has_ref(&repo_path, &pr_update_ref),
        "PR update ref should exist before deletion"
    );

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
    assert!(
        !repo_has_ref(&repo_path, &pr_ref),
        "announcement deletion should remove PR git ref"
    );
    assert!(
        !repo_has_ref(&repo_path, &pr_update_ref),
        "announcement deletion should remove PR update git ref"
    );
}

#[tokio::test]
async fn test_announcement_cascade_excludes_grasp06_pr_subgraph() {
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

    let (announcement, repo_id) =
        publish_served_repo(&client, "cascade-grasp06-pr-exclusion").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);
    let prs_clone_url = format!("http://{relay_domain}/prs/{npub}/{repo_id}.git");

    let pr = create_pr_event_with_clone(
        &keys,
        &coordinate,
        DETERMINISTIC_COMMIT_HASH,
        "grasp06 cascade exclusion pr",
        &[prs_clone_url.as_str()],
    )
    .expect("build PR event with /prs/ clone tag");
    client
        .send_event(pr.clone())
        .await
        .expect("relay should accept PR event");

    let pr_update = client
        .event_builder(
            Kind::GitPullRequestUpdate,
            "grasp06 cascade exclusion pr update",
        )
        .tag(Tag::custom("a", vec![coordinate.clone()]))
        .tag(Tag::custom("e", vec![pr.id.to_hex()]))
        .tag(Tag::custom(
            "c",
            vec![DETERMINISTIC_COMMIT_HASH.to_string()],
        ))
        .tag(Tag::custom("clone", vec![prs_clone_url.clone()]))
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

    for (label, id) in [
        ("announcement", announcement.id),
        ("pr", pr.id),
        ("pr_update", pr_update.id),
        ("pr_status", pr_status.id),
        ("patch_status", patch_status.id),
    ] {
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

    assert!(
        !client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query announcement after deletion"),
        "announcement should be deleted"
    );

    for (label, id) in [
        ("pr", pr.id),
        ("pr_update", pr_update.id),
        ("pr_status", pr_status.id),
        ("patch_status", patch_status.id),
    ] {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event after deletion"),
            "{label} ({id}) should be excluded from announcement cascade"
        );
    }

    relay.stop().await;
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
async fn test_cascade_recurses_to_unknown_kind_via_comment_only_edge() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, repo_id) = publish_served_repo(&client, "cascade-unknown-via-comment").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let issue = client
        .create_issue(&announcement, "Deleted repo issue", "issue body", vec![])
        .expect("build issue");
    let comment = client
        .event_builder(Kind::from(1111), "comment on deleted repo issue")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build comment");
    let kind1 = client
        .event_builder(Kind::from(1), "kind 1 references only the comment")
        .tag(Tag::custom("e", vec![comment.id.to_hex()]))
        .build(&keys)
        .expect("build kind 1 event");

    for event in [&issue, &comment, &kind1] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept dependent event");
    }

    tokio::time::sleep(Duration::from_millis(350)).await;

    for (label, id) in [
        ("announcement", announcement.id),
        ("issue", issue.id),
        ("comment", comment.id),
        ("kind1", kind1.id),
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

    for (label, id) in [("issue", issue.id), ("comment", comment.id), ("kind1", kind1.id)] {
        assert!(
            !client
                .is_event_on_relay(id)
                .await
                .expect("query event after deletion"),
            "{label} ({id}) should be deleted when reachable only via deleted repo -> issue -> comment chain"
        );
    }

    relay.stop().await;
}

#[tokio::test]
async fn test_unknown_kind_leaf_referenced_only_by_deleted_chain_is_removed() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, repo_id) = publish_served_repo(&client, "cascade-unknown-leaf").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let issue = client
        .create_issue(&announcement, "Issue for deleted chain", "issue body", vec![])
        .expect("build issue");
    let kind1 = client
        .event_builder(Kind::from(1), "kind 1 note accepted via deleted-chain comment")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build kind 1 note");
    let comment = client
        .event_builder(Kind::from(1111), "comment quoting kind 1 note")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .tag(Tag::custom("q", vec![kind1.id.to_hex()]))
        .build(&keys)
        .expect("build comment quoting kind 1 note");

    for event in [&issue, &kind1, &comment] {
        client
            .send_event(event.clone())
            .await
            .expect("relay should accept event");
    }

    tokio::time::sleep(Duration::from_millis(350)).await;

    for (label, id) in [
        ("announcement", announcement.id),
        ("issue", issue.id),
        ("comment", comment.id),
        ("kind1", kind1.id),
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

    for (label, id) in [("issue", issue.id), ("comment", comment.id), ("kind1", kind1.id)] {
        assert!(
            !client
                .is_event_on_relay(id)
                .await
                .expect("query event after deletion"),
            "{label} ({id}) should be deleted when its only retained path is through the deleted repo chain"
        );
    }

    relay.stop().await;
}

#[tokio::test]
async fn test_unknown_kind_shared_with_retained_repo_is_kept_while_deleted_repo_issue_is_removed() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement_a, repo_id_a) = publish_served_repo(&client, "cascade-shared-repo-a").await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id_a);
    let (announcement_b, _repo_id_b) = publish_served_repo(&client, "cascade-shared-repo-b").await;

    let issue_a = client
        .create_issue(
            &announcement_a,
            "Repo A issue",
            "issue body",
            vec![],
        )
        .expect("build repo A issue");
    client
        .send_event(issue_a.clone())
        .await
        .expect("relay should accept repo A issue");

    let kind1 = client
        .event_builder(Kind::from(1), "shared kind 1 note")
        .tag(Tag::custom("e", vec![issue_a.id.to_hex()]))
        .build(&keys)
        .expect("build shared kind 1 note");
    client
        .send_event(kind1.clone())
        .await
        .expect("relay should accept shared kind 1 note");

    // This extra kind-1 submission exercises the scenario requirement that a
    // plain kind-1 event should remain acceptable once issue A already exists.
    let kind1_followup = client
        .event_builder(Kind::from(1), "kind 1 submitted after repo A issue exists")
        .tag(Tag::custom("e", vec![issue_a.id.to_hex()]))
        .build(&keys)
        .expect("build kind 1 followup");
    client
        .send_event(kind1_followup.clone())
        .await
        .expect("relay should accept followup kind 1 event");

    let issue_b = client
        .create_issue(
            &announcement_b,
            "Repo B issue",
            "issue body",
            vec![Tag::custom("q", vec![kind1.id.to_hex()])],
        )
        .expect("build repo B issue");
    client
        .send_event(issue_b.clone())
        .await
        .expect("relay should accept repo B issue");

    tokio::time::sleep(Duration::from_millis(350)).await;

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("announcement_b", announcement_b.id),
        ("issue_a", issue_a.id),
        ("issue_b", issue_b.id),
        ("kind1", kind1.id),
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
            std::slice::from_ref(&coordinate_a),
        ))
        .await
        .expect("relay should accept repo A announcement deletion");

    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(
        !client
            .is_event_on_relay(issue_a.id)
            .await
            .expect("query repo A issue after deletion"),
        "issue_A ({}) should be deleted with repo A",
        issue_a.id
    );
    assert!(
        client
            .is_event_on_relay(issue_b.id)
            .await
            .expect("query repo B issue after deletion"),
        "issue_B ({}) should remain because repo B is retained",
        issue_b.id
    );
    assert!(
        client
            .is_event_on_relay(kind1.id)
            .await
            .expect("query shared kind 1 after deletion"),
        "shared kind1 ({}) should remain because repo B still references it",
        kind1.id
    );

    relay.stop().await;
}

#[tokio::test]
async fn test_deleted_repo_issue_retained_when_its_comment_is_quoted_in_retained_repo_issue() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement_a, repo_id_a) = publish_served_repo(&client, "cascade-quoted-comment-repo-a").await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id_a);
    let (announcement_b, _repo_id_b) = publish_served_repo(&client, "cascade-quoted-comment-repo-b").await;

    let issue_a = client
        .create_issue(&announcement_a, "Repo A issue", "issue body", vec![])
        .expect("build repo A issue");
    client
        .send_event(issue_a.clone())
        .await
        .expect("relay should accept repo A issue");

    let comment_a = client
        .event_builder(Kind::from(1111), "comment on repo A issue")
        .tag(Tag::custom("e", vec![issue_a.id.to_hex()]))
        .build(&keys)
        .expect("build repo A comment");
    client
        .send_event(comment_a.clone())
        .await
        .expect("relay should accept repo A comment");

    let issue_b = client
        .create_issue(
            &announcement_b,
            "Repo B issue quoting repo A comment",
            "issue body",
            vec![Tag::custom("q", vec![comment_a.id.to_hex()])],
        )
        .expect("build repo B issue");
    client
        .send_event(issue_b.clone())
        .await
        .expect("relay should accept repo B issue");

    tokio::time::sleep(Duration::from_millis(350)).await;

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("announcement_b", announcement_b.id),
        ("issue_a", issue_a.id),
        ("comment_a", comment_a.id),
        ("issue_b", issue_b.id),
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
            std::slice::from_ref(&coordinate_a),
        ))
        .await
        .expect("relay should accept repo A announcement deletion");

    tokio::time::sleep(Duration::from_millis(700)).await;

    // New requirement: a retained repo conversation quoting comment_A should
    // keep comment_A reachable, and issue_A should also stay for graph
    // consistency because comment_A cannot remain without its parent issue.
    assert!(
        client
            .is_event_on_relay(comment_a.id)
            .await
            .expect("query repo A comment after deletion"),
        "comment_A ({}) should remain because retained repo B issue quotes it",
        comment_a.id
    );
    assert!(
        client
            .is_event_on_relay(issue_a.id)
            .await
            .expect("query repo A issue after deletion"),
        "issue_A ({}) should remain for reachability consistency from retained comment_A",
        issue_a.id
    );
    assert!(
        client
            .is_event_on_relay(issue_b.id)
            .await
            .expect("query repo B issue after deletion"),
        "issue_B ({}) should remain because repo B is retained",
        issue_b.id
    );

    relay.stop().await;
}
