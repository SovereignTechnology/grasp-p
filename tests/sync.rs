//! Proactive Sync Integration Tests
//!
//! This test file organizes tests for ngit-grasp's proactive sync functionality.
//! Tests are grouped into submodules by sync scenario:
//!
//! - `historic_sync` - Tests for sync from pre-configured bootstrap relay (historic events)
//! - `discovery` - Tests for relay discovery from announcement events
//! - `live_sync` - Tests for real-time sync after connection established
//! - `tag_variations` - Tests for different Layer 2/3 tag types
//! - `catchup` - Tests for catchup sync after disconnect (not yet implemented)
//! - `metrics` - Tests for Prometheus metrics integration
//!
//! # Running Tests
//!
//! ```bash
//! # Run all sync tests
//! cargo test --test sync
//!
//! # Run with output
//! cargo test --test sync -- --nocapture
//!
//! # Run specific test
//! cargo test --test sync test_bootstrap_syncs -- --nocapture
//!
//! # Run ignored tests (like catchup)
//! cargo test --test sync -- --ignored
//! ```

// Include the common test utilities
mod common;

// Include sync test submodules (located in tests/sync/)
mod sync {
    pub mod adaptive_pagination;
    pub mod catchup;
    pub mod descendant_sync;
    pub mod discovery;
    pub mod historic_recovery;
    pub mod historic_sync;
    pub mod live_sync;
    pub mod maintainer_reprocessing;
    pub mod metrics;
    pub mod naughty_list_scheduling;
    pub mod neg_concurrency;
    pub mod outbound_auth;
    pub mod proactive_sync_plus;
    pub mod purgatory_fetch;
    pub mod reconnect_backoff;
    pub mod req_concurrency;
    pub mod stale_connect_result;
    pub mod tag_variations;
}
