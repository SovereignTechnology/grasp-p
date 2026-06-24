//! Integration tests for Phase 4 git archive lifecycle.

mod common;

use common::{announcement_coordinate, build_deletion, publish_served_repo, TestRelay};
use grasp_audit::{AuditClient, AuditConfig};
use ngit_grasp::nostr::lifecycle::{
    HoldingStore, HOLDING_ARCHIVE_PATH_TAG, HOLDING_METADATA_KIND, HOLDING_OWNER_PUBKEY_TAG,
};
use nostr_sdk::prelude::*;
use std::time::Duration;

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

async fn open_holding(relay: &TestRelay) -> HoldingStore {
    HoldingStore::open_lmdb(relay.relay_data_path(), relay.git_data_path())
        .await
        .expect("open holding db")
}

#[tokio::test]
async fn announcement_deletion_creates_git_archive_and_metadata_linkage() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "git-archive-create").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);
    let owner_npub = client.public_key().to_bech32().expect("pubkey to npub");
    let live_repo_path = relay
        .git_data_path()
        .join(owner_npub)
        .join(format!("{repo_id}.git"));
    assert!(
        live_repo_path.is_dir(),
        "live bare repo must exist before announcement deletion"
    );

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate));
    client.send_event(deletion).await.expect("send deletion");
    tokio::time::sleep(Duration::from_millis(600)).await;

    let store = open_holding(&relay).await;
    let metadata = store.metadata_for_event(&announcement.id).await;
    assert!(
        !metadata.is_empty(),
        "announcement must have holding metadata"
    );

    let archive_rel_path = metadata
        .iter()
        .find_map(|m| metadata_tag_value(m, HOLDING_ARCHIVE_PATH_TAG))
        .expect("holding metadata must include archive path");
    let owner = metadata
        .iter()
        .find_map(|m| metadata_tag_value(m, HOLDING_OWNER_PUBKEY_TAG))
        .expect("holding metadata must include owner linkage");

    let archive_path = relay
        .git_data_path()
        .join(".archive")
        .join(&archive_rel_path);
    assert!(archive_path.exists(), "archive file must exist on disk");
    assert!(
        !live_repo_path.exists(),
        "live bare repo must be removed after successful announcement archival and deletion"
    );
    assert_eq!(owner, client.public_key().to_hex());

    relay.stop().await;
}

#[tokio::test]
async fn cleanup_removes_expired_archive_file_and_metadata() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "git-archive-cleanup").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate));
    client.send_event(deletion).await.expect("send deletion");
    tokio::time::sleep(Duration::from_millis(600)).await;

    let store = open_holding(&relay).await;
    let metadata = store.metadata_for_event(&announcement.id).await;
    let archive_rel_path = metadata
        .iter()
        .find_map(|m| metadata_tag_value(m, HOLDING_ARCHIVE_PATH_TAG))
        .expect("holding metadata must include archive path");
    let archive_path = relay
        .git_data_path()
        .join(".archive")
        .join(&archive_rel_path);
    assert!(
        archive_path.exists(),
        "archive file should exist before cleanup"
    );

    let first = store
        .cleanup_expired(
            Timestamp::from_secs(Timestamp::now().as_secs() + 10_000),
            Duration::from_secs(1),
        )
        .await
        .expect("cleanup should succeed");

    assert!(
        first.archive_files_deleted >= 1,
        "cleanup should delete at least one archive file"
    );
    assert!(
        !archive_path.exists(),
        "archive file must be removed by cleanup"
    );
    assert!(store.metadata_for_event(&announcement.id).await.is_empty());

    let second = store
        .cleanup_expired(
            Timestamp::from_secs(Timestamp::now().as_secs() + 10_000),
            Duration::from_secs(1),
        )
        .await
        .expect("second cleanup should succeed");
    assert_eq!(second.expired_records, 0);
    assert_eq!(second.metadata_deleted, 0);
    assert_eq!(second.archive_files_deleted, 0);

    relay.stop().await;
}

#[tokio::test]
async fn cleanup_tolerates_missing_archive_file_and_removes_stale_metadata() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "git-archive-missing").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate));
    client.send_event(deletion).await.expect("send deletion");
    tokio::time::sleep(Duration::from_millis(600)).await;

    let store = open_holding(&relay).await;
    let metadata = store.metadata_for_event(&announcement.id).await;
    let archive_rel_path = metadata
        .iter()
        .find_map(|m| metadata_tag_value(m, HOLDING_ARCHIVE_PATH_TAG))
        .expect("holding metadata must include archive path");
    let archive_path = relay
        .git_data_path()
        .join(".archive")
        .join(&archive_rel_path);
    std::fs::remove_file(&archive_path).expect("remove archive file to simulate missing file");

    let stats = store
        .cleanup_expired(
            Timestamp::from_secs(Timestamp::now().as_secs() + 10_000),
            Duration::from_secs(1),
        )
        .await
        .expect("cleanup should succeed when archive file is missing");

    assert!(
        stats.metadata_deleted >= 1,
        "stale metadata must be removed"
    );
    assert_eq!(stats.archive_files_deleted, 0);
    assert!(store.metadata_for_event(&announcement.id).await.is_empty());

    relay.stop().await;
}

#[tokio::test]
async fn disrespector_mode_does_not_archive_repository_data() {
    let relay = TestRelay::start_with_lmdb_deletion_disrespector().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "git-archive-disrespector").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);
    let deletion = build_deletion(
        &client,
        &[announcement.id],
        std::slice::from_ref(&coordinate),
    );
    client.send_event(deletion).await.expect("send deletion");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query announcement after disrespector deletion"),
        "announcement must remain served in disrespector mode"
    );

    let store = open_holding(&relay).await;
    let metadata = store
        .metadata_for_event(&announcement.id)
        .await
        .into_iter()
        .filter(|e| e.kind == Kind::from(HOLDING_METADATA_KIND))
        .collect::<Vec<_>>();
    assert!(
        metadata.is_empty(),
        "disrespector mode must not move to holding"
    );

    let archive_root = relay.git_data_path().join(".archive");
    assert!(
        !archive_root.exists(),
        "disrespector mode must not create archive files"
    );

    relay.stop().await;
}
