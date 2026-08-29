//! Push Authorization Integration Tests
//!
//! Tests that verify push authorization state events work correctly.
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
//! # Run all push authorization tests
//! cargo test --test push_authorization
//!
//! # Run specific test
//! cargo test --test push_authorization test_push_authorized_by_owner_state
//!
//! # With output
//! cargo test --test push_authorization -- --nocapture
//! ```

mod common;

use common::TestRelay;
use grasp_audit::specs::grasp01::PushAuthorizationTests;
use grasp_audit::*;

/// Macro to generate isolated integration tests for push authorization
///
/// Each test runs with its own fresh relay instance to ensure complete isolation.
/// This eliminates issues with leftover repositories and ensures clean state.
/// Push authorization tests require git_data_dir and relay_domain parameters.
macro_rules! isolated_push_test {
    ($test_name:ident) => {
        #[tokio::test]
        async fn $test_name() {
            let relay = TestRelay::start().await;
            let config = AuditConfig::isolated();
            let client = AuditClient::new(relay.url(), config)
                .await
                .expect("Failed to create audit client");

            let result = PushAuthorizationTests::$test_name(&client, &relay.domain()).await;

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

// Generate isolated tests for all push authorization tests
isolated_push_test!(test_push_rejected_without_state_event);
isolated_push_test!(test_push_authorized_by_owner_state);
isolated_push_test!(test_push_rejected_wrong_commit);
isolated_push_test!(test_push_authorized_by_confirmed_maintainer_state);
isolated_push_test!(test_push_authorized_by_recursive_maintainer_state);
isolated_push_test!(test_push_to_nostr_ref_with_invalid_event_id_rejected);
isolated_push_test!(test_pr_push_to_nostr_ref_with_wrong_commit_accepted_before_event_received);
isolated_push_test!(test_pr_event_published_removes_nostr_ref_at_incorrect_commit);
isolated_push_test!(test_push_to_nostr_ref_with_wrong_commit_after_event_received_rejected);
isolated_push_test!(
    test_push_to_nostr_ref_with_correct_commit_after_event_received_accepted_and_event_served
);
isolated_push_test!(test_head_set_after_state_event_with_existing_commit);
isolated_push_test!(test_head_set_after_git_push_with_required_oids);
