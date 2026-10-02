//! Purgatory sync module for background git data synchronization.
//!
//! This module implements identifier-based syncing with:
//! - Batched OID fetching across all purgatory events for an identifier
//! - Domain-based throttling (configurable requests/minute per domain)
//! - Exponential backoff per identifier (20s → 2m, then 2m intervals)
//! - Debouncing for burst event arrivals
//! - Background sync loop processing ready identifiers every 1 second

mod context;
mod functions;
mod git_budget;
mod r#loop;
mod queue;
mod throttle;

pub use context::{GitFetchRole, ProcessResult, RealSyncContext, SyncContext};
pub use functions::{
    get_throttled_domains_with_untried_urls, sync_identifier, sync_identifier_from_url,
    sync_identifier_next_url, ThrottledDomainInfo,
};
pub(crate) use git_budget::GitBudgetDeferred;
pub use queue::SyncQueueEntry;
pub use throttle::{DomainThrottle, ThrottleManager};

#[cfg(test)]
pub use context::mock::MockSyncContext;
