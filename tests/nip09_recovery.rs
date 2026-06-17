//! Integration tests for Phase 5 NIP-09 recovery workflow.

mod common;

use common::{
    announcement_coordinate, build_deletion, publish_served_announcement_for_identifier,
    publish_served_repo, publish_served_repo_with_maintainers,
    publish_served_repo_with_state_event, TestRelay,
};
use grasp_audit::{AuditClient, AuditConfig};
use ngit_grasp::nostr::holding::{
    HoldingStore, DEFAULT_RETENTION, HOLDING_ARCHIVE_PATH_TAG, HOLDING_METADATA_KIND,
};
use nostr_sdk::prelude::*;
use std::process::Command;
use std::time::Duration;

async fn open_holding(relay: &TestRelay) -> HoldingStore {
    HoldingStore::open_lmdb(relay.relay_data_path(), relay.git_data_path())
        .await
        .expect("open holding db")
}

fn metadata_tag_value(event: &Event, key: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.as_slice();
        if v.len() >= 2 && v[0] == key {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

fn build_reannouncement(client: &AuditClient, relay: &TestRelay, repo_id: &str) -> Event {
    let relay_url = relay.url().to_string();
    let relay_domain = relay
        .url()
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let npub = client.public_key().to_bech32().expect("pubkey to bech32");

    client
        .event_builder(Kind::GitRepoAnnouncement, "reannounce")
        .tag(Tag::identifier(repo_id))
        .tag(Tag::custom("name", vec![repo_id.to_string()]))
        .tag(Tag::custom(
            "clone",
            vec![format!("http://{}/{}/{}.git", relay_domain, npub, repo_id)],
        ))
        .tag(Tag::custom("relays", vec![relay_url]))
        .build(client.keys())
        .expect("build re-announcement")
}

#[tokio::test]
async fn reannouncement_restores_events_and_git_archive_happy_path() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "recovery-happy").await;
    let issue = client
        .create_issue(&announcement, "recovery issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(!client
        .is_event_on_relay(issue.id)
        .await
        .expect("query issue after deletion"));
    assert!(!client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query state after deletion"));

    let repo_path = relay
        .git_data_path()
        .join(client.public_key().to_bech32().expect("npub"))
        .join(format!("{}.git", repo_id));
    if repo_path.exists() {
        std::fs::remove_dir_all(&repo_path).expect("remove live repo to force archive restore");
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce.clone())
        .await
        .expect("send re-announcement");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(client
        .is_event_on_relay(reannounce.id)
        .await
        .expect("query re-announcement"));
    assert!(client
        .is_event_on_relay(issue.id)
        .await
        .expect("query restored issue"));
    assert!(client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query restored state"));
    assert!(repo_path.is_dir(), "git repo must be restored");

    let show_ref = Command::new("git")
        .args(["--git-dir", repo_path.to_str().unwrap(), "show-ref"])
        .output()
        .expect("run git show-ref on restored repo");
    assert!(show_ref.status.success(), "restored repo must contain refs");

    let store = open_holding(&relay).await;
    assert!(store.metadata_for_event(&issue.id).await.is_empty());
    assert!(store.metadata_for_event(&state_event.id).await.is_empty());

    relay.stop().await;
}

#[tokio::test]
async fn out_of_retention_reannouncement_behaves_as_fresh_new_repo() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "recovery-expired").await;
    let issue = client
        .create_issue(&announcement, "expired issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    let store = open_holding(&relay).await;
    store
        .cleanup_expired(
            Timestamp::from_secs(Timestamp::now().as_secs() + 10_000),
            Duration::from_secs(1),
        )
        .await
        .expect("force cleanup expired holding records");

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce.clone())
        .await
        .expect("send re-announcement");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        !client
            .is_event_on_relay(reannounce.id)
            .await
            .expect("query re-announcement"),
        "without recovery data, re-announcement should be a fresh purgatory entry"
    );
    assert!(!client
        .is_event_on_relay(issue.id)
        .await
        .expect("query issue after out-of-retention re-announcement"));
    assert!(!client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query state after out-of-retention re-announcement"));

    relay.stop().await;
}

#[tokio::test]
async fn partial_recovery_missing_archive_restores_events_only_deterministically() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "recovery-missing-archive").await;
    let issue = client
        .create_issue(&announcement, "missing archive issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    let store = open_holding(&relay).await;
    let archive_rel = store
        .metadata_for_event(&announcement.id)
        .await
        .into_iter()
        .find(|e| e.kind == Kind::from(HOLDING_METADATA_KIND))
        .and_then(|e| metadata_tag_value(&e, HOLDING_ARCHIVE_PATH_TAG))
        .expect("archive relative path in metadata");
    let archive_path = relay.git_data_path().join(".archive").join(archive_rel);
    std::fs::remove_file(&archive_path).expect("remove archive file to force partial recovery");

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce.clone())
        .await
        .expect("send re-announcement");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(client
        .is_event_on_relay(reannounce.id)
        .await
        .expect("query re-announcement"));
    assert!(client
        .is_event_on_relay(issue.id)
        .await
        .expect("query restored issue"));
    assert!(client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query restored state"));

    let store = open_holding(&relay).await;
    assert!(store.metadata_for_event(&issue.id).await.is_empty());

    relay.stop().await;
}

#[tokio::test]
async fn partial_recovery_missing_holding_payload_restores_git_only_deterministically() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id) = publish_served_repo(&client, "recovery-missing-payload").await;
    let issue = client
        .create_issue(&announcement, "missing payload issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    let store = open_holding(&relay).await;
    store
        .delete_archived_payload(&issue.id)
        .await
        .expect("delete archived issue payload from holding");

    let repo_path = relay
        .git_data_path()
        .join(client.public_key().to_bech32().expect("npub"))
        .join(format!("{}.git", repo_id));
    if repo_path.exists() {
        std::fs::remove_dir_all(&repo_path).expect("remove live repo to require archive restore");
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce.clone())
        .await
        .expect("send re-announcement");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(
        repo_path.is_dir(),
        "git repository should be restored from archive"
    );
    assert!(!client
        .is_event_on_relay(issue.id)
        .await
        .expect("query missing-payload issue after recovery"));

    let store = open_holding(&relay).await;
    assert!(store.metadata_for_event(&issue.id).await.is_empty());

    relay.stop().await;
}

#[tokio::test]
async fn repeated_reannouncement_recovery_trigger_is_idempotent() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id) = publish_served_repo(&client, "recovery-idempotent").await;
    let issue = client
        .create_issue(&announcement, "idempotent issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    client
        .send_event(build_reannouncement(&client, &relay, &repo_id))
        .await
        .expect("first re-announcement");
    tokio::time::sleep(Duration::from_millis(700)).await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    let second = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(second.clone())
        .await
        .expect("second re-announcement");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(client
        .is_event_on_relay(issue.id)
        .await
        .expect("query issue after repeated recovery"));
    assert!(client
        .is_event_on_relay(second.id)
        .await
        .expect("query second re-announcement"));

    let store = open_holding(&relay).await;
    let pending = store
        .eligible_recovery_records(
            &client.public_key().to_hex(),
            &repo_id,
            Timestamp::now(),
            DEFAULT_RETENTION,
        )
        .await;
    assert!(
        pending.is_empty(),
        "recovered metadata must not remain pending"
    );

    relay.stop().await;
}

#[tokio::test]
async fn multi_maintainer_reannouncement_restores_deleted_owner_slice() {
    let relay = TestRelay::start_with_lmdb().await;
    let client_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create maintainer a");
    let client_b =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer b");

    let (announcement_a, repo_id) = publish_served_repo_with_maintainers(
        &client_a,
        "recovery-multi",
        &[client_b.public_key().to_hex()],
    )
    .await;
    let announcement_b = publish_served_announcement_for_identifier(&client_b, &repo_id).await;

    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id);
    let coordinate_b = announcement_coordinate(&announcement_b, &repo_id);

    let shared_patch = client_a
        .event_builder(Kind::from(1617), "shared patch")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .tag(Tag::custom("a", vec![coordinate_b.clone()]))
        .build(client_a.keys())
        .expect("build shared patch");
    let deleted_patch = client_a
        .event_builder(Kind::from(1617), "a-only patch")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .build(client_a.keys())
        .expect("build deleted patch");
    for event in [&shared_patch, &deleted_patch] {
        client_a
            .send_event(event.clone())
            .await
            .expect("send patch event");
    }

    client_a
        .send_event(build_deletion(
            &client_a,
            &[],
            std::slice::from_ref(&coordinate_a),
        ))
        .await
        .expect("delete maintainer a announcement");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(!client_a
        .is_event_on_relay(deleted_patch.id)
        .await
        .expect("query deleted patch"));
    assert!(client_a
        .is_event_on_relay(shared_patch.id)
        .await
        .expect("query shared patch"));
    assert!(client_b
        .is_event_on_relay(announcement_b.id)
        .await
        .expect("query surviving announcement b"));

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce_a = build_reannouncement(&client_a, &relay, &repo_id);
    client_a
        .send_event(reannounce_a)
        .await
        .expect("reannounce maintainer a");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(client_a
        .is_event_on_relay(deleted_patch.id)
        .await
        .expect("query restored a-only patch"));
    assert!(client_b
        .is_event_on_relay(announcement_b.id)
        .await
        .expect("query surviving announcement b after recovery"));

    relay.stop().await;
}

#[tokio::test]
async fn disrespector_mode_has_no_recovery_state_to_apply() {
    let relay = TestRelay::start_with_lmdb_deletion_disrespector().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id) = publish_served_repo(&client, "recovery-disrespector").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[announcement.id],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion request in disrespector mode");
    tokio::time::sleep(Duration::from_millis(500)).await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce)
        .await
        .expect("send replacement announcement in disrespector mode");

    let store = open_holding(&relay).await;
    let pending = store
        .eligible_recovery_records(
            &client.public_key().to_hex(),
            &repo_id,
            Timestamp::now(),
            DEFAULT_RETENTION,
        )
        .await;
    assert!(
        pending.is_empty(),
        "disrespector mode must not create holding recovery entries"
    );

    relay.stop().await;
}
