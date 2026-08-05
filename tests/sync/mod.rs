//! Proactive Sync Integration Tests
//!
//! This module organizes tests for ngit-grasp's proactive sync functionality.
//! Tests are grouped by sync scenario:
//!
//! - Historic sync (relay syncs from pre-configured bootstrap relay)
//! - Relay discovery (relay discovers other relays from announcement events)
//! - Live sync (events sync in real-time after connection established)
//! - Tag variations (testing different Layer 2/3 tag types: a/A/q, e/E/q)
//! - Catchup sync (events from disconnected period sync on reconnect)
//! - Metrics (Prometheus metrics for sync operations)
//!
//! # Test Files
//!
//! - `historic_sync.rs` - Bootstrap and replay tests (uses `run_sync_test()` helper)
//! - `discovery.rs` - Relay discovery from announcements (manual setup required)
//! - `live_sync.rs` - Real-time sync after connection (manual setup required)
//! - `tag_variations.rs` - Layer 2/3 tag type coverage (manual setup required)
//! - `catchup.rs` - Catchup after disconnect (stub, `#[ignore]`)
//! - `metrics.rs` - Prometheus metrics integration tests
//!
//! # Test Patterns
//!
//! This module uses two main testing approaches, each suited to different scenarios:
//!
//! ## Pattern 1: Helper-Based Tests (Historic Sync)
//!
//! **Use `run_sync_test()` for:**
//! - Verifying historic event sync (events published before relay starts)
//! - Bootstrap and initialization tests
//! - Simple count-based event verification
//! - Single-relay scenarios
//!
//! **Example from `historic_sync.rs`:**
//! ```rust
//! use common::sync_helpers::{run_sync_test, build_layer2_issue_event};
//!
//! #[tokio::test]
//! async fn test_bootstrap_syncs_existing_layer2_events() {
//!     let repo_event = /* create repo announcement */;
//!     let issue1 = build_layer2_issue_event(&repo_event, "Issue 1");
//!     let issue2 = build_layer2_issue_event(&repo_event, "Issue 2");
//!
//!     run_sync_test(
//!         &[&repo_event],           // Bootstrap events
//!         &[&issue1, &issue2],      // Events to verify
//!         2,                         // Expected count
//!     ).await;
//! }
//! ```
//!
//! **Helper Architecture:**
//! - Publishes all events to bootstrap relay before target relay starts
//! - Automatically starts target relay with bootstrap relay configured
//! - Verifies event counts after sync completes
//! - Handles all relay lifecycle management
//!
//! ## Pattern 2: Manual Setup Tests (Live, Discovery, Tag Variations)
//!
//! **Use manual setup for:**
//! - Live sync (events published *during* relay operation)
//! - Multi-relay coordination (discovery chains)
//! - Detailed event inspection (tag format verification)
//! - Precise timing control
//!
//! **Example from `live_sync.rs`:**
//! ```rust
//! #[tokio::test]
//! async fn test_live_sync_layer2_events() {
//!     let bootstrap = TestRelay::start().await;
//!     let target = TestRelay::start_with_bootstrap(bootstrap.url()).await;
//!
//!     // Publish AFTER relay is running (live sync)
//!     let event = build_layer2_issue_event(&repo, "Live Issue");
//!     client.publish_event(event).await;
//!
//!     // Verify with timing control
//!     wait_for_event_on_relay(&target, &event.id, timeout).await;
//! }
//! ```
//!
//! **Example from `discovery.rs`:**
//! ```rust
//! #[tokio::test]
//! async fn test_discovers_layer3_via_layer2() {
//!     // Multi-relay orchestration
//!     let relay_a = TestRelay::start().await;
//!     let relay_b = TestRelay::start_with_sync(None).await;
//!
//!     // relay_b receives announcement listing relay_a, discovers and syncs from it
//! }
//! ```
//!
//! **Example from `tag_variations.rs`:**
//! ```rust
//! #[tokio::test]
//! async fn test_layer2_sync_with_uppercase_a_tag() {
//!     // Detailed tag format verification
//!     let event = build_event_with_uppercase_A();
//!
//!     // Custom assertions about tag normalization
//!     assert!(synced_event.tags.contains_uppercase_a());
//! }
//! ```
//!
//! ## Why Two Patterns?
//!
//! The `run_sync_test()` helper embodies a specific pattern:
//! ```
//! Setup → Publish Batch → Start Relay → Verify Counts
//! ```
//!
//! This pattern is **incompatible** with tests needing:
//! - Event publication *during* relay operation (live sync)
//! - Multiple relay coordination (discovery)
//! - Detailed event inspection beyond counts (tag variations)
//! - Precise timing control
//!
//! For these scenarios, manual setup provides necessary flexibility.
//!
//! # Shared Imports
//!
//! All sync tests use helpers from `common::sync_helpers`:
//! - `TestClient` - Client with retry logic
//! - `run_sync_test()` - Helper for historic sync tests
//! - Event builders for Layer 2/3 events
//! - `wait_for_event_on_relay()` - Non-panicking assertion helper
//! - `fetch_metrics()` - Prometheus metrics fetching

// Test modules
pub mod historic_recovery;
pub mod historic_sync;
pub mod catchup;
pub mod discovery;
pub mod live_sync;
pub mod maintainer_reprocessing;
pub mod metrics;
pub mod neg_concurrency;
pub mod req_concurrency;
pub mod tag_variations;