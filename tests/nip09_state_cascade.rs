//! NIP-09 repository-state cascade-deletion integration tests.
//!
//! These tests extend the announcement-cascade coverage to kind-30618
//! repository state events in the **single-maintainer** case.

mod common;

use common::{
    announcement_coordinate, announcement_served_by_coordinate, build_deletion,
    publish_served_announcement_with_state_for_identifier, publish_served_repo,
    publish_served_repo_with_state_event, publish_served_repo_with_state_event_and_maintainers,
    TestRelay,
};

use grasp_audit::{AuditClient, AuditConfig, DETERMINISTIC_COMMIT_HASH};
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::process::Command;
use std::time::Duration;

fn build_state_with_branches(
    client: &AuditClient,
    repo_id: &str,
    created_at: Timestamp,
    branches: &[&str],
) -> Event {
    let mut tags = vec![Tag::identifier(repo_id)];
    for branch in branches {
        tags.push(Tag::custom(
            format!("refs/heads/{branch}"),
            vec![DETERMINISTIC_COMMIT_HASH.to_string()],
        ));
    }
    tags.push(Tag::custom(
        "HEAD",
        vec!["ref: refs/heads/main".to_string()],
    ));

    EventBuilder::new(Kind::RepoState, "")
        .tags(tags)
        .custom_created_at(created_at)
        .finalize(client.keys())
        .expect("build state event")
}

fn repo_path(relay: &TestRelay, client: &AuditClient, repo_id: &str) -> std::path::PathBuf {
    relay
        .git_data_path()
        .join(client.public_key().to_bech32().expect("npub"))
        .join(format!("{repo_id}.git"))
}

fn list_repo_refs(repo_path: &std::path::Path) -> HashSet<String> {
    let output = Command::new("git")
        .args([
            "--git-dir",
            repo_path.to_str().expect("repo path"),
            "show-ref",
        ])
        .output()
        .expect("run git show-ref");

    if !output.status.success() {
        return HashSet::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|s| s.to_string())
        .collect()
}

/// Deleting an announcement by coordinate must hard-delete the repository state
/// event (kind 30618) for the same repository from the main DB.
#[tokio::test]
async fn test_state_event_deleted_with_announcement() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "state-cascade-single").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    // STRICT pre-condition: both announcement and state are genuinely served.
    for (label, id) in [("announcement", announcement.id), ("state", state_event.id)] {
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

    let announcement_survived = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement after deletion");
    let state_survived = client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query state event after deletion");
    let announcement_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement, &repo_id).await;

    relay.stop().await;

    assert!(
        !announcement_survived,
        "announcement {} must be hard-deleted",
        announcement.id
    );
    assert!(
        !state_survived,
        "state event {} must be hard-deleted with its announcement",
        state_event.id
    );
    assert!(
        !announcement_by_coordinate,
        "announcement must not be served by author+kind+identifier after deletion"
    );
}

/// Two repositories by the same maintainer are independent: deleting one
/// announcement must delete only that repository's state event.
#[tokio::test]
async fn test_state_events_are_independent_per_repository() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement_a, repo_a, state_a) =
        publish_served_repo_with_state_event(&client, "state-cascade-a").await;
    let (announcement_b, repo_b, state_b) =
        publish_served_repo_with_state_event(&client, "state-cascade-b").await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_a);

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("state_a", state_a.id),
        ("announcement_b", announcement_b.id),
        ("state_b", state_b.id),
    ] {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate_a));
    client
        .send_event(deletion)
        .await
        .expect("relay should accept announcement deletion");

    tokio::time::sleep(Duration::from_millis(600)).await;

    let announcement_a_survived = client
        .is_event_on_relay(announcement_a.id)
        .await
        .expect("query announcement a after deletion");
    let state_a_survived = client
        .is_event_on_relay(state_a.id)
        .await
        .expect("query state a after deletion");
    let announcement_b_survived = client
        .is_event_on_relay(announcement_b.id)
        .await
        .expect("query announcement b after deletion");
    let state_b_survived = client
        .is_event_on_relay(state_b.id)
        .await
        .expect("query state b after deletion");

    let announcement_a_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement_a, &repo_a).await;
    let announcement_b_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement_b, &repo_b).await;

    relay.stop().await;

    assert!(
        !announcement_a_survived && !state_a_survived,
        "deleted repository must lose both announcement and state event"
    );
    assert!(
        announcement_b_survived && state_b_survived,
        "unrelated repository announcement and state must survive"
    );
    assert!(
        !announcement_a_by_coordinate,
        "deleted repository coordinate must not be served"
    );
    assert!(
        announcement_b_by_coordinate,
        "unrelated repository coordinate must remain served"
    );
}

#[tokio::test]
async fn test_e_delete_active_state_rolls_back_and_realigns_refs() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (_announcement, repo_id) = publish_served_repo(&client, "state-rollback-e").await;
    let base = Timestamp::from_secs(Timestamp::now().as_secs() + 20);
    let v1 = build_state_with_branches(&client, &repo_id, base, &["main"]);
    let v2 = build_state_with_branches(
        &client,
        &repo_id,
        Timestamp::from_secs(base.as_secs() + 1),
        &["main", "feature"],
    );

    client.send_event(v1.clone()).await.expect("send v1 state");
    client.send_event(v2.clone()).await.expect("send v2 state");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let owner_repo = repo_path(&relay, &client, &repo_id);
    let refs_before = list_repo_refs(&owner_repo);
    assert!(
        refs_before.contains("refs/heads/feature"),
        "feature ref must exist before rollback deletion"
    );

    client
        .send_event(build_deletion(&client, &[v2.id], &[]))
        .await
        .expect("send e-tag deletion for active state");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(
        client
            .is_event_on_relay(v1.id)
            .await
            .expect("query v1 after rollback"),
        "previous state must be restored"
    );
    assert!(
        !client
            .is_event_on_relay(v2.id)
            .await
            .expect("query v2 after rollback"),
        "deleted active state must stay deleted"
    );

    let refs_after = list_repo_refs(&owner_repo);
    assert!(refs_after.contains("refs/heads/main"));
    assert!(
        !refs_after.contains("refs/heads/feature"),
        "feature ref must be removed after rollback realignment"
    );

    relay.stop().await;
}

#[tokio::test]
async fn test_e_delete_active_announcement_rolls_back_previous_version() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (v1, repo_id) = publish_served_repo(&client, "announcement-rollback-e").await;
    let base = Timestamp::from_secs(Timestamp::now().as_secs() + 60);
    let v2 = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(v1.tags.clone())
        .custom_created_at(base)
        .finalize(client.keys())
        .expect("build replacement announcement");

    client
        .send_event(v2.clone())
        .await
        .expect("send replacement announcement");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        client
            .is_event_on_relay(v2.id)
            .await
            .expect("query replacement announcement before deletion"),
        "replacement announcement must be active before deletion"
    );

    client
        .send_event(build_deletion(&client, &[v2.id], &[]))
        .await
        .expect("send e-tag deletion for active announcement");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(
        client
            .is_event_on_relay(v1.id)
            .await
            .expect("query v1 after announcement rollback"),
        "previous announcement must be restored"
    );
    assert!(
        !client
            .is_event_on_relay(v2.id)
            .await
            .expect("query v2 after announcement rollback"),
        "deleted active announcement must stay deleted"
    );

    assert!(
        announcement_served_by_coordinate(&client, &v1, &repo_id).await,
        "announcement coordinate must remain served after rollback"
    );

    relay.stop().await;
}

#[tokio::test]
async fn test_a_delete_coordinate_old_cutoff_keeps_newer_active_state() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (_announcement, repo_id) = publish_served_repo(&client, "state-rollback-a").await;
    let base = Timestamp::from_secs(Timestamp::now().as_secs() + 40);
    let v1 = build_state_with_branches(&client, &repo_id, base, &["main"]);
    let v2 = build_state_with_branches(
        &client,
        &repo_id,
        Timestamp::from_secs(base.as_secs() + 1),
        &["main", "feature"],
    );

    client.send_event(v1.clone()).await.expect("send v1 state");
    client.send_event(v2.clone()).await.expect("send v2 state");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let owner_repo = repo_path(&relay, &client, &repo_id);
    let refs_before = list_repo_refs(&owner_repo);
    assert!(refs_before.contains("refs/heads/feature"));

    let coordinate = format!("30618:{}:{}", client.public_key().to_hex(), repo_id);
    let deletion = EventBuilder::new(Kind::EventDeletion, "")
        .tags(vec![Tag::custom("a", vec![coordinate])])
        .custom_created_at(v1.created_at)
        .finalize(client.keys())
        .expect("build coordinate deletion");

    client
        .send_event(deletion)
        .await
        .expect("send a-tag deletion with cutoff");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(
        !client
            .is_event_on_relay(v1.id)
            .await
            .expect("query v1 after coordinate deletion"),
        "state at or before cutoff must be deleted"
    );
    assert!(
        client
            .is_event_on_relay(v2.id)
            .await
            .expect("query v2 after coordinate deletion"),
        "newer active state must remain served"
    );

    let refs_after = list_repo_refs(&owner_repo);
    assert!(refs_after.contains("refs/heads/main"));
    assert!(
        refs_after.contains("refs/heads/feature"),
        "realignment must keep refs from surviving active state"
    );

    relay.stop().await;
}

#[tokio::test]
async fn test_a_delete_coordinate_cutoff_deletes_active_without_history_resurrection() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (_announcement, repo_id) = publish_served_repo(&client, "state-rollback-a-active").await;
    let base = Timestamp::from_secs(Timestamp::now().as_secs() + 50);
    let v1 = build_state_with_branches(&client, &repo_id, base, &["main"]);
    let v2 = build_state_with_branches(
        &client,
        &repo_id,
        Timestamp::from_secs(base.as_secs() + 1),
        &["main", "feature"],
    );

    client.send_event(v1.clone()).await.expect("send v1 state");
    client.send_event(v2.clone()).await.expect("send v2 state");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let owner_repo = repo_path(&relay, &client, &repo_id);
    let coordinate = format!("30618:{}:{}", client.public_key().to_hex(), repo_id);
    let deletion = EventBuilder::new(Kind::EventDeletion, "")
        .tags(vec![Tag::custom("a", vec![coordinate])])
        .custom_created_at(v2.created_at)
        .finalize(client.keys())
        .expect("build coordinate deletion");

    client
        .send_event(deletion)
        .await
        .expect("send a-tag deletion with active cutoff");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(
        !client
            .is_event_on_relay(v1.id)
            .await
            .expect("query v1 after active cutoff deletion"),
        "deleted coordinate versions must not be restored from history"
    );
    assert!(
        !client
            .is_event_on_relay(v2.id)
            .await
            .expect("query v2 after active cutoff deletion"),
        "active state at cutoff must be deleted"
    );

    let refs_after = list_repo_refs(&owner_repo);
    assert!(
        !refs_after.iter().any(|r| r.starts_with("refs/heads/")),
        "managed branch refs must be cleared when no state survives"
    );
    assert!(
        !refs_after.iter().any(|r| r.starts_with("refs/tags/")),
        "managed tag refs must be cleared when no state survives"
    );

    relay.stop().await;
}

#[tokio::test]
async fn test_delete_only_active_state_with_no_history_clears_managed_refs() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (_announcement, repo_id, original_state) =
        publish_served_repo_with_state_event(&client, "state-rollback-none").await;
    let owner_repo = repo_path(&relay, &client, &repo_id);

    assert!(
        list_repo_refs(&owner_repo).contains("refs/heads/main"),
        "main ref must exist before deleting the only active state"
    );

    client
        .send_event(build_deletion(&client, &[original_state.id], &[]))
        .await
        .expect("send deletion for only active state");
    tokio::time::sleep(Duration::from_millis(700)).await;

    let refs_after = list_repo_refs(&owner_repo);
    assert!(
        !refs_after.iter().any(|r| r.starts_with("refs/heads/")),
        "no branch refs should remain when there is no active state"
    );
    assert!(
        !refs_after.iter().any(|r| r.starts_with("refs/tags/")),
        "no tag refs should remain when there is no active state"
    );

    relay.stop().await;
}

#[tokio::test]
async fn test_multi_maintainer_state_deletion_rolls_back_without_affecting_other_maintainer() {
    let relay = TestRelay::start().await;
    let client_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create maintainer A client");
    let client_b =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer B client");

    let (_announcement_a, repo_id, _state_a) =
        publish_served_repo_with_state_event_and_maintainers(
            &client_a,
            "state-rollback-multi",
            &[client_b.public_key().to_hex()],
        )
        .await;
    let (_announcement_b, state_b) =
        publish_served_announcement_with_state_for_identifier(&client_b, &repo_id).await;

    let base = Timestamp::from_secs(Timestamp::now().as_secs() + 60);
    let a_v1 = build_state_with_branches(&client_a, &repo_id, base, &["main"]);
    let a_v2 = build_state_with_branches(
        &client_a,
        &repo_id,
        Timestamp::from_secs(base.as_secs() + 1),
        &["main", "feature"],
    );
    client_a
        .send_event(a_v1.clone())
        .await
        .expect("send maintainer A v1");
    client_a
        .send_event(a_v2.clone())
        .await
        .expect("send maintainer A v2");
    tokio::time::sleep(Duration::from_millis(700)).await;

    client_a
        .send_event(build_deletion(&client_a, &[a_v2.id], &[]))
        .await
        .expect("delete maintainer A active state");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(
        client_a
            .is_event_on_relay(a_v1.id)
            .await
            .expect("query restored maintainer A state"),
        "maintainer A should rollback to previous state"
    );
    assert!(
        client_b
            .is_event_on_relay(state_b.id)
            .await
            .expect("query maintainer B state"),
        "maintainer B state must remain served"
    );

    relay.stop().await;
}
