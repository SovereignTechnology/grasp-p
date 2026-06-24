//! Focused integration tests for Phase 3 holding-DB expiry/cleanup behavior.

use ngit_grasp::nostr::lifecycle::{
    DeletionSource, HoldingMetadata, HoldingStore, DEFAULT_CLEANUP_INTERVAL, DEFAULT_RETENTION,
};
use nostr_sdk::prelude::*;
use std::time::Duration;

fn build_test_event(content: &str, created_at: Timestamp) -> Event {
    EventBuilder::new(Kind::TextNote, content)
        .custom_created_at(created_at)
        .finalize(&Keys::generate())
        .expect("build test event")
}

#[tokio::test]
async fn cleanup_removes_expired_holding_events_and_metadata() {
    let store = HoldingStore::in_memory();
    let event = build_test_event("expired", Timestamp::from_secs(100));

    store
        .archive_event(
            &event,
            &HoldingMetadata {
                deleted_at: Timestamp::from_secs(120),
                source: DeletionSource::Nip09,
                coordinate: None,
                identifier: None,
                owner_pubkey: None,
                git_archive: None,
            },
        )
        .await
        .expect("archive event");

    let stats = store
        .cleanup_expired(Timestamp::from_secs(200), Duration::from_secs(30))
        .await
        .expect("cleanup should succeed");

    assert_eq!(stats.expired_records, 1);
    assert_eq!(stats.metadata_deleted, 1);
    assert_eq!(stats.archived_events_deleted, 1);
    assert!(!store.has_event(&event.id).await);
    assert!(store.metadata_for_event(&event.id).await.is_empty());
}

#[tokio::test]
async fn cleanup_preserves_non_expired_entries() {
    let store = HoldingStore::in_memory();
    let event = build_test_event("fresh", Timestamp::from_secs(100));

    store
        .archive_event(
            &event,
            &HoldingMetadata {
                deleted_at: Timestamp::from_secs(190),
                source: DeletionSource::Nip09,
                coordinate: None,
                identifier: None,
                owner_pubkey: None,
                git_archive: None,
            },
        )
        .await
        .expect("archive event");

    let stats = store
        .cleanup_expired(Timestamp::from_secs(200), Duration::from_secs(30))
        .await
        .expect("cleanup should succeed");

    assert_eq!(stats.expired_records, 0);
    assert!(store.has_event(&event.id).await);
    assert_eq!(store.metadata_for_event(&event.id).await.len(), 1);
}

#[tokio::test]
async fn startup_catchup_cleanup_removes_expired_entries_after_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");

    let event_id = {
        let store = HoldingStore::open_lmdb(temp.path(), temp.path())
            .await
            .expect("open holding");
        let event = build_test_event("restart-expired", Timestamp::from_secs(10));
        let id = event.id;
        store
            .archive_event(
                &event,
                &HoldingMetadata {
                    deleted_at: Timestamp::from_secs(20),
                    source: DeletionSource::Nip09,
                    coordinate: None,
                    identifier: None,
                    owner_pubkey: None,
                    git_archive: None,
                },
            )
            .await
            .expect("archive event");
        id
    };

    // Simulate process restart: reopen store and run startup catch-up pass.
    let reopened = HoldingStore::open_lmdb(temp.path(), temp.path())
        .await
        .expect("reopen holding");
    let stats = reopened
        .cleanup_expired(Timestamp::from_secs(300), Duration::from_secs(60))
        .await
        .expect("startup catch-up cleanup should succeed");

    assert_eq!(stats.expired_records, 1);
    assert!(!reopened.has_event(&event_id).await);
    assert!(reopened.metadata_for_event(&event_id).await.is_empty());
}

#[tokio::test]
async fn cleanup_is_idempotent_with_partial_missing_event_data() {
    let store = HoldingStore::in_memory();
    let event = build_test_event("partial", Timestamp::from_secs(50));
    let metadata = HoldingMetadata {
        deleted_at: Timestamp::from_secs(55),
        source: DeletionSource::Nip09,
        coordinate: None,
        identifier: None,
        owner_pubkey: None,
        git_archive: None,
    };

    // Two metadata rows referencing the same archived event: first delete removes
    // the event, second row becomes metadata-only cleanup.
    store
        .archive_event(&event, &metadata)
        .await
        .expect("archive event first time");
    let metadata_with_coordinate = HoldingMetadata {
        coordinate: Some("30617:deadbeef:partial".to_string()),
        ..metadata.clone()
    };
    store
        .archive_event(&event, &metadata_with_coordinate)
        .await
        .expect("archive event second time");

    assert_eq!(store.metadata_for_event(&event.id).await.len(), 2);

    let first = store
        .cleanup_expired(Timestamp::from_secs(500), Duration::from_secs(1))
        .await
        .expect("first cleanup should succeed");
    assert_eq!(first.expired_records, 2);
    assert_eq!(first.metadata_deleted, 2);
    assert_eq!(first.archived_events_deleted, 1);

    let second = store
        .cleanup_expired(Timestamp::from_secs(500), Duration::from_secs(1))
        .await
        .expect("second cleanup should still succeed");
    assert_eq!(second.expired_records, 0);
    assert_eq!(second.metadata_deleted, 0);
    assert_eq!(second.archived_events_deleted, 0);
    assert!(!store.has_event(&event.id).await);
    assert!(store.metadata_for_event(&event.id).await.is_empty());
}

#[test]
fn cleanup_defaults_are_non_zero() {
    assert!(DEFAULT_RETENTION.as_secs() > 0);
    assert!(DEFAULT_CLEANUP_INTERVAL.as_secs() > 0);
}
