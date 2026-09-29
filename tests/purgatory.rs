//! Purgatory Integration Tests
//!
//! Tests ngit-grasp relay's implementation of GRASP-01 purgatory behavior.
//! Uses grasp-audit library to avoid code duplication.
//!
//! # Test Strategy
//!
//! - Each test runs in complete isolation with its own fresh relay instance
//! - Uses macro to eliminate boilerplate while maintaining test isolation
//! - Calls individual test methods from grasp-audit for minimal duplication
//! - Automatic cleanup via TestRelay fixture (removes container and temp dirs)
//!
//! # Running Tests
//!
//! ```bash
//! # Run all purgatory tests
//! cargo test --test purgatory
//!
//! # Run specific test
//! cargo test --test purgatory test_state_event_not_served_before_git_data
//!
//! # With output
//! cargo test --test purgatory -- --nocapture
//! ```

mod common;

use common::TestRelay;
use grasp_audit::specs::grasp01::PurgatoryTests;
use grasp_audit::{AuditClient, AuditConfig};

/// Macro to generate isolated integration tests for purgatory
///
/// Each test runs with its own fresh relay instance to ensure complete isolation.
/// This eliminates issues with leftover repositories and ensures clean state.
macro_rules! isolated_purgatory_test {
    ($test_name:ident) => {
        #[tokio::test]
        async fn $test_name() {
            let relay = TestRelay::start().await;
            let config = AuditConfig::isolated();
            let client = AuditClient::new(relay.url(), config)
                .await
                .expect("Failed to create audit client");

            let result = PurgatoryTests::$test_name(&client).await;

            relay.stop().await;

            assert!(
                result.passed,
                "{} failed: {}",
                stringify!($test_name),
                result.error.as_deref().unwrap_or("unknown error")
            );
        }
    };
}

// ============================================================
// Announcement Purgatory Tests
// ============================================================

isolated_purgatory_test!(test_announcement_not_served_before_git_data);
isolated_purgatory_test!(test_announcement_served_after_git_push);
isolated_purgatory_test!(test_bare_repo_exists_for_purgatory_announcement);
isolated_purgatory_test!(test_state_event_accepted_for_purgatory_announcement);

// ============================================================
// Deletion Event Tests (NIP-09)
// ============================================================

isolated_purgatory_test!(test_deletion_by_event_id_removes_purgatory_state_event);
isolated_purgatory_test!(test_deletion_by_coordinate_removes_purgatory_state_event);

// ============================================================
// State Event Purgatory Tests (already implemented)
// ============================================================

isolated_purgatory_test!(test_state_event_not_served_before_git_data);
isolated_purgatory_test!(test_state_event_served_after_git_push);

// ============================================================
// PR Purgatory Tests
// ============================================================

isolated_purgatory_test!(test_pr_event_accepted_into_purgatory_and_isnt_served);
isolated_purgatory_test!(test_pr_event_in_purgatory_git_push_accepted);
isolated_purgatory_test!(test_pr_event_served_after_git_push);

#[tokio::test]
async fn graceful_shutdown_keeps_pending_pr_refs() {
    use nostr_sdk::prelude::*;
    let persistent = tempfile::tempdir().unwrap();
    let git_data = persistent.path().join("git");
    let relay = TestRelay::start_with_existing_lmdb_paths(
        git_data.clone(),
        persistent.path().join("relay"),
        None,
        false,
    )
    .await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .unwrap();
    let (announcement, identifier) =
        common::publish_served_repo(&client, "shutdown-pending-pr").await;
    let local = tempfile::tempdir().unwrap();
    let tip =
        common::create_test_repo_with_commit(local.path(), common::CommitVariant::PrTest).unwrap();
    // The event is never sent, so the pushed ref stays a pending placeholder.
    let event = common::create_pr_event(
        client.keys(),
        &common::announcement_coordinate(&announcement, &identifier),
        &tip,
        "pending across shutdown",
    )
    .unwrap();
    let npub = client.public_key().to_bech32().unwrap();
    let reference = format!("refs/nostr/{}", event.id);
    common::push_ref_to_relay(
        local.path(),
        &relay.domain(),
        &npub,
        &identifier,
        &tip,
        &reference,
    )
    .unwrap();
    let view = git_data.join(&npub).join(format!("{identifier}.git"));
    assert_eq!(
        ngit_grasp::git::get_ref_commit(&view, &reference).as_deref(),
        Some(tip.as_str())
    );
    relay.stop_gracefully().await;
    assert_eq!(
        ngit_grasp::git::get_ref_commit(&view, &reference).as_deref(),
        Some(tip.as_str()),
        "shutdown must keep the pending ref for expiry after restart"
    );
    assert!(ngit_grasp::git::oid_exists(&view, &tip));
}
