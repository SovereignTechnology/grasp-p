//! Purgatory Persistence Integration Tests
//!
//! Tests that verify the full purgatory persistence save/restore cycle:
//! - Purgatory save/restore with state events, PR events, and expired events
//! - Rejected cache save/restore with hot cache and cold index entries
//! - Integration with shutdown/startup hooks
//! - Graceful degradation with missing or corrupted files
//! - Time adjustment for downtime
//!
//! # Test Strategy
//!
//! These tests verify end-to-end persistence functionality:
//! 1. Create purgatory/rejected cache instances with various entries
//! 2. Save state to disk
//! 3. Create new instances and restore from disk
//! 4. Verify all data is restored correctly
//! 5. Verify system continues to work after restore
//!
//! # Running Tests
//!
//! ```bash
//! # Run all purgatory persistence tests
//! cargo test --test purgatory_persistence
//!
//! # Run specific test
//! cargo test --test purgatory_persistence test_full_purgatory_save_restore_cycle
//!
//! # With output for debugging
//! cargo test --test purgatory_persistence -- --nocapture
//! ```

mod common;

use common::purgatory_helpers::create_announcement_event;
use ngit_grasp::purgatory::Purgatory;
use ngit_grasp::sync::rejected_index::{EventType, RejectedEventsIndex, RejectionReason};
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::time::Duration;

/// Helper to create a test event
async fn create_test_event(keys: &Keys, content: &str) -> Event {
    EventBuilder::new(Kind::TextNote, content)
        .finalize(keys)
        .unwrap()
}

/// Helper to create a state event with specific refs
fn create_state_event_with_refs(
    keys: &Keys,
    identifier: &str,
    refs: &[(&str, &str)],
) -> Result<Event, Box<dyn std::error::Error>> {
    let mut tags = vec![Tag::identifier(identifier)];

    // Add ref tags
    for (ref_name, commit_hash) in refs {
        tags.push(Tag::custom(
            "ref",
            vec![ref_name.to_string(), commit_hash.to_string()],
        ));
    }

    let event = EventBuilder::new(Kind::from(30618), "")
        .tags(tags)
        .finalize(keys)?;

    Ok(event)
}

/// Test 1: Full save/restore cycle with state events, PR events, and expired events
#[tokio::test]
async fn test_full_purgatory_save_restore_cycle() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("purgatory.json");

    // Create purgatory instance
    let purgatory = Purgatory::new(&git_data_path);

    // Create test keys and events
    let keys1 = Keys::generate();
    let keys2 = Keys::generate();
    let keys3 = Keys::generate();

    let state_event1 =
        create_state_event_with_refs(&keys1, "repo1", &[("main", "abc123")]).unwrap();
    let state_event2 =
        create_state_event_with_refs(&keys2, "repo2", &[("main", "def456")]).unwrap();

    let pr_event1 = create_test_event(&keys3, "PR 1").await;
    let pr_event2 = create_test_event(&keys3, "PR 2").await;

    // Add state events to purgatory
    purgatory.add_state(
        state_event1.clone(),
        "repo1".to_string(),
        keys1.public_key(),
        false,
    );
    purgatory.add_state(
        state_event2.clone(),
        "repo2".to_string(),
        keys2.public_key(),
        false,
    );

    // Add PR events to purgatory
    purgatory.add_pr(
        pr_event1.clone(),
        pr_event1.id.to_hex(),
        "commit-abc".to_string(),
        false,
    );
    purgatory.add_pr(
        pr_event2.clone(),
        pr_event2.id.to_hex(),
        "commit-def".to_string(),
        false,
    );

    // Add a PR placeholder (git-data-first scenario)
    purgatory.add_pr_placeholder("placeholder-id".to_string(), "commit-xyz".to_string());

    // Add an announcement to purgatory (requires a real directory for the repo path)
    let repo_dir = temp_dir.path().join("repo.git");
    std::fs::create_dir_all(&repo_dir).unwrap();
    let ann_keys = Keys::generate();
    let ann_event = create_announcement_event(
        &ann_keys,
        "my-repo",
        &["http://example.com/my-repo.git"],
        &["wss://relay.example.com"],
    )
    .unwrap();
    let ann_event_id = ann_event.id;
    let mut ann_relays = HashSet::new();
    ann_relays.insert("wss://relay.example.com".to_string());
    purgatory.add_announcement(
        ann_event,
        "my-repo".to_string(),
        ann_keys.public_key(),
        repo_dir.clone(),
        ann_relays,
    );

    // Verify initial counts
    let (announcement_count, state_count, pr_count) = purgatory.count();
    assert_eq!(announcement_count, 1, "Should have 1 announcement");
    assert_eq!(state_count, 2, "Should have 2 state events");
    assert_eq!(
        pr_count, 3,
        "Should have 3 PR events (2 events + 1 placeholder)"
    );

    // Save to disk
    purgatory.save_to_disk(&state_path).unwrap();
    assert!(state_path.exists(), "State file should exist after save");

    // Create new purgatory instance and restore
    let purgatory2 = Purgatory::new(&git_data_path);
    purgatory2.restore_from_disk(&state_path).unwrap();

    // Verify state file was deleted after restore
    assert!(
        !state_path.exists(),
        "State file should be deleted after restore"
    );

    // Verify all data was restored
    let (announcement_count2, state_count2, pr_count2) = purgatory2.count();
    assert_eq!(
        announcement_count2, 1,
        "Should have 1 announcement after restore"
    );
    assert_eq!(state_count2, 2, "Should have 2 state events after restore");
    assert_eq!(
        pr_count2, 3,
        "Should have 3 PR events after restore (2 events + 1 placeholder)"
    );

    // Verify announcement was restored correctly
    let restored_ann = purgatory2
        .find_announcement(&ann_keys.public_key(), "my-repo")
        .expect("Announcement should be restored");
    assert_eq!(restored_ann.event.id, ann_event_id);
    assert_eq!(restored_ann.identifier, "my-repo");
    assert_eq!(restored_ann.repo_path, repo_dir);
    assert!(!restored_ann.soft_expired);

    // Verify specific state events
    let repo1_states = purgatory2.find_state("repo1");
    assert_eq!(repo1_states.len(), 1);
    assert_eq!(repo1_states[0].event.id, state_event1.id);

    let repo2_states = purgatory2.find_state("repo2");
    assert_eq!(repo2_states.len(), 1);
    assert_eq!(repo2_states[0].event.id, state_event2.id);

    // Verify PR events
    let pr1 = purgatory2.find_pr(&pr_event1.id.to_hex());
    assert!(pr1.is_some());
    assert_eq!(pr1.unwrap().commit, "commit-abc");

    let pr2 = purgatory2.find_pr(&pr_event2.id.to_hex());
    assert!(pr2.is_some());
    assert_eq!(pr2.unwrap().commit, "commit-def");

    // Verify placeholder
    let placeholder = purgatory2.find_pr_placeholder("placeholder-id");
    assert_eq!(placeholder, Some("commit-xyz".to_string()));

    // Verify re-queueing works - get all identifiers
    let identifiers = purgatory2.get_all_identifiers();
    assert_eq!(identifiers.len(), 2);
    assert!(identifiers.contains(&"repo1".to_string()));
    assert!(identifiers.contains(&"repo2".to_string()));
}

/// Test 2: Rejected cache integration - save/restore hot cache and cold index
#[tokio::test]
async fn test_rejected_cache_save_restore_cycle() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("rejected_cache.json");

    // Create rejected events index
    let index = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));

    // Create test events
    let keys1 = Keys::generate();
    let keys2 = Keys::generate();

    let event1 = create_test_event(&keys1, "announcement 1").await;
    let event2 = create_test_event(&keys2, "announcement 2").await;
    let event3 = create_test_event(&keys1, "state 1").await;

    // Add announcements to rejected cache
    index.add_announcement(
        event1.clone(),
        event1.pubkey,
        "repo1".to_string(),
        RejectionReason::DoesNotListService,
    );

    index.add_announcement(
        event2.clone(),
        event2.pubkey,
        "repo2".to_string(),
        RejectionReason::MaintainerNotYetValid,
    );

    // Add state event to rejected cache
    index.add_state(
        event3.clone(),
        event3.pubkey,
        "repo1".to_string(),
        RejectionReason::Other,
    );

    // Verify initial counts
    assert_eq!(index.hot_cache_len(), 3);
    assert_eq!(index.cold_index_len(), 3);

    // Save to disk
    index.save_to_disk(&state_path).unwrap();
    assert!(state_path.exists());

    // Create new index and restore
    let index2 = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));
    index2.restore_from_disk(&state_path).unwrap();

    // Verify state file was deleted
    assert!(!state_path.exists());

    // Verify all entries restored
    assert_eq!(index2.hot_cache_len(), 3);
    assert_eq!(index2.cold_index_len(), 3);

    // Verify specific entries
    assert!(index2.contains(&event1.id));
    assert!(index2.contains(&event2.id));
    assert!(index2.contains(&event3.id));

    // Verify we can invalidate and get events
    let (removed, hot_events) =
        index2.invalidate_and_get(&event1.pubkey, "repo1", Some(EventType::Announcement));
    assert_eq!(removed, 1);
    assert_eq!(hot_events.len(), 1);
    assert_eq!(hot_events[0].id, event1.id);
}

/// Test 3: Simulated downtime - verify expiry times are adjusted correctly
#[tokio::test]
async fn test_purgatory_downtime_adjustment() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("purgatory.json");

    let purgatory = Purgatory::new(&git_data_path);
    let keys = Keys::generate();

    let state_event = create_state_event_with_refs(&keys, "repo1", &[("main", "abc123")]).unwrap();

    purgatory.add_state(
        state_event.clone(),
        "repo1".to_string(),
        keys.public_key(),
        false,
    );

    // Save to disk
    purgatory.save_to_disk(&state_path).unwrap();

    // Simulate downtime
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Restore
    let purgatory2 = Purgatory::new(&git_data_path);
    purgatory2.restore_from_disk(&state_path).unwrap();

    // Verify event is still there (downtime was accounted for)
    let (_, state_count, _) = purgatory2.count();
    assert_eq!(state_count, 1);

    let repo1_states = purgatory2.find_state("repo1");
    assert_eq!(repo1_states.len(), 1);
    assert_eq!(repo1_states[0].event.id, state_event.id);

    // Verify the event hasn't expired yet (expiry time was adjusted)
    // The event should have ~30 minutes minus the downtime
    let entry = &repo1_states[0];
    let remaining = entry
        .expires_at
        .saturating_duration_since(std::time::Instant::now());
    assert!(
        remaining > Duration::from_secs(1700),
        "Event should have most of its 30min expiry remaining"
    );
}

/// Test 4: Rejected cache downtime adjustment
#[tokio::test]
async fn test_rejected_cache_downtime_adjustment() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("rejected_cache.json");

    let index = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));
    let keys = Keys::generate();

    let event = create_test_event(&keys, "test").await;

    index.add_announcement(
        event.clone(),
        event.pubkey,
        "repo1".to_string(),
        RejectionReason::DoesNotListService,
    );

    // Save to disk
    index.save_to_disk(&state_path).unwrap();

    // Simulate downtime
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Restore
    let index2 = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));
    index2.restore_from_disk(&state_path).unwrap();

    // Verify event is still in both caches (downtime was accounted for)
    assert_eq!(index2.hot_cache_len(), 1);
    assert_eq!(index2.cold_index_len(), 1);
    assert!(index2.contains(&event.id));
}

/// Test 5: File cleanup - verify state files are deleted after successful restore
#[tokio::test]
async fn test_purgatory_file_cleanup_after_restore() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("purgatory.json");

    let purgatory = Purgatory::new(&git_data_path);
    let keys = Keys::generate();

    let state_event = create_state_event_with_refs(&keys, "repo1", &[("main", "abc123")]).unwrap();

    purgatory.add_state(state_event, "repo1".to_string(), keys.public_key(), false);

    // Save to disk
    purgatory.save_to_disk(&state_path).unwrap();
    assert!(state_path.exists(), "State file should exist after save");

    // Restore
    let purgatory2 = Purgatory::new(&git_data_path);
    purgatory2.restore_from_disk(&state_path).unwrap();

    // Verify file was deleted
    assert!(
        !state_path.exists(),
        "State file should be deleted after successful restore"
    );
}

/// Test 6: Rejected cache file cleanup
#[tokio::test]
async fn test_rejected_cache_file_cleanup_after_restore() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("rejected_cache.json");

    let index = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));
    let keys = Keys::generate();

    let event = create_test_event(&keys, "test").await;

    index.add_announcement(
        event,
        keys.public_key(),
        "repo1".to_string(),
        RejectionReason::DoesNotListService,
    );

    // Save to disk
    index.save_to_disk(&state_path).unwrap();
    assert!(state_path.exists());

    // Restore
    let index2 = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));
    index2.restore_from_disk(&state_path).unwrap();

    // Verify file was deleted
    assert!(!state_path.exists());
}

/// Test 7: Graceful degradation - missing purgatory file
#[tokio::test]
async fn test_purgatory_restore_missing_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("nonexistent.json");

    let purgatory = Purgatory::new(&git_data_path);

    // Attempting to restore missing file should return error
    let result = purgatory.restore_from_disk(&state_path);
    assert!(result.is_err(), "Should error on missing file");

    // Purgatory should still be usable (empty state)
    let (_, state_count, pr_count) = purgatory.count();
    assert_eq!(state_count, 0);
    assert_eq!(pr_count, 0);

    // Should be able to add events normally
    let keys = Keys::generate();
    let event = create_test_event(&keys, "test").await;
    purgatory.add_state(event, "repo1".to_string(), keys.public_key(), false);

    let (_, state_count, _) = purgatory.count();
    assert_eq!(state_count, 1);
}

/// Test 8: Graceful degradation - missing rejected cache file
#[tokio::test]
async fn test_rejected_cache_restore_missing_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("nonexistent.json");

    let index = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));

    // Attempting to restore missing file should return error
    let result = index.restore_from_disk(&state_path);
    assert!(result.is_err());

    // Index should still be usable (empty state)
    assert_eq!(index.hot_cache_len(), 0);
    assert_eq!(index.cold_index_len(), 0);

    // Should be able to add events normally
    let keys = Keys::generate();
    let event = create_test_event(&keys, "test").await;
    index.add_announcement(
        event,
        keys.public_key(),
        "repo1".to_string(),
        RejectionReason::DoesNotListService,
    );

    assert_eq!(index.hot_cache_len(), 1);
    assert_eq!(index.cold_index_len(), 1);
}

/// Test 9: Graceful degradation - corrupted purgatory file
#[tokio::test]
async fn test_purgatory_restore_corrupted_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("corrupted.json");

    // Write corrupted JSON
    std::fs::write(&state_path, "{ invalid json !!!").unwrap();

    let purgatory = Purgatory::new(&git_data_path);

    // Attempting to restore corrupted file should return error
    let result = purgatory.restore_from_disk(&state_path);
    assert!(result.is_err(), "Should error on corrupted file");

    // Purgatory should still be usable
    let (_, state_count, pr_count) = purgatory.count();
    assert_eq!(state_count, 0);
    assert_eq!(pr_count, 0);
}

/// Test 10: Graceful degradation - corrupted rejected cache file
#[tokio::test]
async fn test_rejected_cache_restore_corrupted_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("corrupted.json");

    // Write corrupted JSON
    std::fs::write(&state_path, "{ invalid json !!!").unwrap();

    let index = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));

    // Attempting to restore corrupted file should return error
    let result = index.restore_from_disk(&state_path);
    assert!(result.is_err());

    // Index should still be usable
    assert_eq!(index.hot_cache_len(), 0);
    assert_eq!(index.cold_index_len(), 0);
}

/// Test 11: Empty purgatory save/restore
#[tokio::test]
async fn test_empty_purgatory_save_restore() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("purgatory.json");

    let purgatory = Purgatory::new(&git_data_path);

    // Save empty purgatory
    purgatory.save_to_disk(&state_path).unwrap();
    assert!(state_path.exists());

    // Restore
    let purgatory2 = Purgatory::new(&git_data_path);
    purgatory2.restore_from_disk(&state_path).unwrap();

    // Verify empty state
    let (_, state_count, pr_count) = purgatory2.count();
    assert_eq!(state_count, 0);
    assert_eq!(pr_count, 0);
    assert_eq!(purgatory2.expired_count(), 0);
}

/// Test 12: Empty rejected cache save/restore
#[tokio::test]
async fn test_empty_rejected_cache_save_restore() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("rejected_cache.json");

    let index = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));

    // Save empty cache
    index.save_to_disk(&state_path).unwrap();
    assert!(state_path.exists());

    // Restore
    let index2 = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));
    index2.restore_from_disk(&state_path).unwrap();

    // Verify empty state
    assert_eq!(index2.hot_cache_len(), 0);
    assert_eq!(index2.cold_index_len(), 0);
}

/// Test 13: Multiple state events for same identifier
#[tokio::test]
async fn test_purgatory_multiple_state_events_same_identifier() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("purgatory.json");

    let purgatory = Purgatory::new(&git_data_path);

    // Create multiple state events for same identifier (different maintainers)
    let keys1 = Keys::generate();
    let keys2 = Keys::generate();

    let event1 = create_state_event_with_refs(&keys1, "repo1", &[("main", "abc123")]).unwrap();
    let event2 = create_state_event_with_refs(&keys2, "repo1", &[("main", "def456")]).unwrap();

    purgatory.add_state(
        event1.clone(),
        "repo1".to_string(),
        keys1.public_key(),
        false,
    );
    purgatory.add_state(
        event2.clone(),
        "repo1".to_string(),
        keys2.public_key(),
        false,
    );

    // Save and restore
    purgatory.save_to_disk(&state_path).unwrap();

    let purgatory2 = Purgatory::new(&git_data_path);
    purgatory2.restore_from_disk(&state_path).unwrap();

    // Verify both events restored
    let repo1_states = purgatory2.find_state("repo1");
    assert_eq!(repo1_states.len(), 2);

    let event_ids: Vec<_> = repo1_states.iter().map(|e| e.event.id).collect();
    assert!(event_ids.contains(&event1.id));
    assert!(event_ids.contains(&event2.id));
}

/// Test 14: Verify system continues to work after restore
#[tokio::test]
async fn test_purgatory_continues_working_after_restore() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("purgatory.json");

    let purgatory = Purgatory::new(&git_data_path);
    let keys = Keys::generate();

    let event1 = create_state_event_with_refs(&keys, "repo1", &[("main", "abc123")]).unwrap();

    purgatory.add_state(
        event1.clone(),
        "repo1".to_string(),
        keys.public_key(),
        false,
    );

    // Save and restore
    purgatory.save_to_disk(&state_path).unwrap();

    let purgatory2 = Purgatory::new(&git_data_path);
    purgatory2.restore_from_disk(&state_path).unwrap();

    // Add new events after restore
    let event2 = create_state_event_with_refs(&keys, "repo2", &[("main", "xyz789")]).unwrap();

    purgatory2.add_state(
        event2.clone(),
        "repo2".to_string(),
        keys.public_key(),
        false,
    );

    // Verify both old and new events work
    let (_, state_count, _) = purgatory2.count();
    assert_eq!(state_count, 2);

    let repo1_states = purgatory2.find_state("repo1");
    assert_eq!(repo1_states.len(), 1);
    assert_eq!(repo1_states[0].event.id, event1.id);

    let repo2_states = purgatory2.find_state("repo2");
    assert_eq!(repo2_states.len(), 1);
    assert_eq!(repo2_states[0].event.id, event2.id);

    // Verify cleanup still works
    let (_, state_removed, pr_removed) = purgatory2.cleanup();
    // Nothing should be expired yet
    assert_eq!(state_removed, 0);
    assert_eq!(pr_removed, 0);
}

/// Test 15: Verify rejected cache continues working after restore
#[tokio::test]
async fn test_rejected_cache_continues_working_after_restore() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("rejected_cache.json");

    let index = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));
    let keys = Keys::generate();

    let event1 = create_test_event(&keys, "event1").await;

    index.add_announcement(
        event1.clone(),
        event1.pubkey,
        "repo1".to_string(),
        RejectionReason::DoesNotListService,
    );

    // Save and restore
    index.save_to_disk(&state_path).unwrap();

    let index2 = RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));
    index2.restore_from_disk(&state_path).unwrap();

    // Add new events after restore
    let event2 = create_test_event(&keys, "event2").await;

    index2.add_announcement(
        event2.clone(),
        event2.pubkey,
        "repo2".to_string(),
        RejectionReason::MaintainerNotYetValid,
    );

    // Verify both old and new events work
    assert_eq!(index2.hot_cache_len(), 2);
    assert_eq!(index2.cold_index_len(), 2);
    assert!(index2.contains(&event1.id));
    assert!(index2.contains(&event2.id));

    // Verify invalidation still works
    let (removed, hot_events) =
        index2.invalidate_and_get(&event1.pubkey, "repo1", Some(EventType::Announcement));
    assert_eq!(removed, 1);
    assert_eq!(hot_events.len(), 1);
    assert_eq!(hot_events[0].id, event1.id);
}

/// Test 16: Entries that expired during downtime are properly handled
#[tokio::test]
async fn test_purgatory_entries_expired_during_downtime() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("purgatory.json");

    let purgatory = Purgatory::new(&git_data_path);
    let keys = Keys::generate();

    let event = create_state_event_with_refs(&keys, "repo1", &[("main", "abc123")]).unwrap();

    purgatory.add_state(event.clone(), "repo1".to_string(), keys.public_key(), false);

    // Save to disk
    purgatory.save_to_disk(&state_path).unwrap();

    // Simulate very long downtime (longer than the 30min default expiry)
    // Note: We can't manually set expiry without accessing private fields,
    // so this test verifies that the system handles already-expired entries gracefully
    // In a real scenario, if downtime > 30 minutes, entries would be expired on restore

    // For this test, we'll just verify the restore works and cleanup can be called
    let purgatory2 = Purgatory::new(&git_data_path);
    purgatory2.restore_from_disk(&state_path).unwrap();

    // Event should be restored
    let (_, state_count, _) = purgatory2.count();
    assert_eq!(state_count, 1);

    // Cleanup should work (even if nothing is expired yet)
    let (_, state_removed, _) = purgatory2.cleanup();
    // Nothing expired yet since we didn't wait 30 minutes
    assert_eq!(state_removed, 0);

    let (_, state_count, _) = purgatory2.count();
    assert_eq!(state_count, 1);
}

/// Test 17: Rejected cache entries that expired during downtime
#[tokio::test]
async fn test_rejected_cache_entries_expired_during_downtime() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("rejected_cache.json");

    // Create index with very short expiry
    let index = RejectedEventsIndex::new(
        Duration::from_millis(50),  // Hot cache: 50ms
        Duration::from_millis(100), // Cold index: 100ms
    );
    let keys = Keys::generate();

    let event = create_test_event(&keys, "test").await;

    index.add_announcement(
        event.clone(),
        event.pubkey,
        "repo1".to_string(),
        RejectionReason::DoesNotListService,
    );

    // Save to disk
    index.save_to_disk(&state_path).unwrap();

    // Simulate downtime longer than hot cache expiry
    tokio::time::sleep(Duration::from_millis(75)).await;

    // Restore
    let index2 = RejectedEventsIndex::new(Duration::from_millis(50), Duration::from_millis(100));
    index2.restore_from_disk(&state_path).unwrap();

    // Both should be restored initially
    assert_eq!(index2.hot_cache_len(), 1);
    assert_eq!(index2.cold_index_len(), 1);

    // Note: We can't directly access hot_cache.get_maintainer_events (private method)
    // But we can verify the entry is there via contains() and test cleanup

    // Verify entry is still tracked
    assert!(index2.contains(&event.id));

    // Cleanup should remove expired hot cache entry
    let (hot_expired, cold_expired) = index2.cleanup_expired_for_type("announcement");
    assert_eq!(hot_expired, 1);
    assert_eq!(cold_expired, 0); // Cold index still valid

    assert_eq!(index2.hot_cache_len(), 0);
    assert_eq!(index2.cold_index_len(), 1);
}

/// Test 18: Announcement events are saved and restored across restarts
#[tokio::test]
async fn test_announcement_save_restore_cycle() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("purgatory.json");

    // Create a real bare repo directory (restore skips entries whose path is missing)
    let repo_dir = temp_dir.path().join("owner.git");
    std::fs::create_dir_all(&repo_dir).unwrap();

    let purgatory = Purgatory::new(&git_data_path);
    let keys = Keys::generate();

    let ann_event = create_announcement_event(
        &keys,
        "my-repo",
        &["http://example.com/my-repo.git"],
        &["wss://relay.example.com"],
    )
    .unwrap();
    let ann_event_id = ann_event.id;

    let mut relays = HashSet::new();
    relays.insert("wss://relay.example.com".to_string());

    purgatory.add_announcement(
        ann_event,
        "my-repo".to_string(),
        keys.public_key(),
        repo_dir.clone(),
        relays.clone(),
    );

    let (ann_count, _, _) = purgatory.count();
    assert_eq!(ann_count, 1);

    // Save to disk
    purgatory.save_to_disk(&state_path).unwrap();
    assert!(state_path.exists());

    // Restore into a fresh purgatory
    let purgatory2 = Purgatory::new(&git_data_path);
    purgatory2.restore_from_disk(&state_path).unwrap();

    assert!(
        !state_path.exists(),
        "State file should be deleted after restore"
    );

    let (ann_count2, _, _) = purgatory2.count();
    assert_eq!(ann_count2, 1, "Announcement should be restored");

    let restored = purgatory2
        .find_announcement(&keys.public_key(), "my-repo")
        .expect("Announcement should be findable after restore");

    assert_eq!(restored.event.id, ann_event_id);
    assert_eq!(restored.identifier, "my-repo");
    assert_eq!(restored.owner, keys.public_key());
    assert_eq!(restored.repo_path, repo_dir);
    assert_eq!(restored.relays, relays);
    assert!(!restored.soft_expired);
}

/// Test 19: Announcement with missing repo path is skipped on restore
#[tokio::test]
async fn test_announcement_missing_repo_skipped_on_restore() {
    let temp_dir = tempfile::tempdir().unwrap();
    let git_data_path = temp_dir.path().join("git");
    let state_path = temp_dir.path().join("purgatory.json");

    // Point to a path that does NOT exist on disk
    let missing_repo = temp_dir.path().join("nonexistent.git");

    let purgatory = Purgatory::new(&git_data_path);
    let keys = Keys::generate();

    let ann_event = create_announcement_event(&keys, "my-repo", &[], &[]).unwrap();

    purgatory.add_announcement(
        ann_event,
        "my-repo".to_string(),
        keys.public_key(),
        missing_repo,
        HashSet::new(),
    );

    purgatory.save_to_disk(&state_path).unwrap();

    let purgatory2 = Purgatory::new(&git_data_path);
    purgatory2.restore_from_disk(&state_path).unwrap();

    let (ann_count, _, _) = purgatory2.count();
    assert_eq!(
        ann_count, 0,
        "Announcement with missing repo path must be skipped"
    );
}
