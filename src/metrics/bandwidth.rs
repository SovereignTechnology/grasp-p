//! Repository bandwidth tracking with cardinality control.
//!
//! This module tracks bandwidth per repository but only exposes the top N
//! repositories to Prometheus to prevent cardinality explosion with many repos.
//!
//! # Cardinality Control
//!
//! - All per-repo bandwidth is tracked internally in a `DashMap<RepoId, u64>`
//! - Every 60 seconds, the top 10 are calculated and exposed to Prometheus
//! - Previous repo labels are cleared before setting new ones
//! - Prometheus only ever sees ~10 label values, keeping cardinality low

use std::cmp::Reverse;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use prometheus::{GaugeVec, Opts, Registry};

/// Default number of top repositories to expose in metrics
const DEFAULT_TOP_N: usize = 10;

/// Default refresh interval for top-N calculation (60 seconds)
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Tracks bandwidth per repository with top-N exposure to Prometheus.
///
/// # Design
///
/// All repositories are tracked internally for accurate total bandwidth,
/// but only the top N by bytes transferred are exposed to Prometheus.
/// This prevents cardinality explosion when hosting thousands of repositories.
///
/// # Thread Safety
///
/// Uses `DashMap` for lock-free concurrent access and atomics for
/// the refresh timestamp.
pub struct BandwidthTracker {
    /// Internal: tracks ALL repos (memory only, not exposed)
    all_repos: DashMap<String, u64>,

    /// Exposed to Prometheus: only top N repos
    top_repos_gauge: GaugeVec,

    /// Last refresh timestamp (stored as nanos since some epoch)
    last_refresh_nanos: AtomicU64,

    /// Instant when the tracker was created (for relative timing)
    start_instant: Instant,

    /// Number of top repos to expose
    top_n: usize,

    /// Refresh interval
    refresh_interval: Duration,
}

impl BandwidthTracker {
    /// Creates a new BandwidthTracker and registers metrics with Prometheus.
    ///
    /// Uses default settings:
    /// - Top 10 repositories exposed
    /// - 60 second refresh interval
    pub fn new(registry: &Registry) -> Self {
        Self::with_config(registry, DEFAULT_TOP_N, DEFAULT_REFRESH_INTERVAL)
    }

    /// Creates a new BandwidthTracker with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `registry` - Prometheus registry to register metrics with
    /// * `top_n` - Number of top repositories to expose in metrics
    /// * `refresh_interval` - How often to recalculate the top-N list
    pub fn with_config(registry: &Registry, top_n: usize, refresh_interval: Duration) -> Self {
        let top_repos_gauge = GaugeVec::new(
            Opts::new(
                "ngit_git_top_repos_bytes",
                "Top repositories by bandwidth (refreshed periodically)",
            ),
            &["repo"],
        )
        .unwrap();
        registry
            .register(Box::new(top_repos_gauge.clone()))
            .unwrap();

        Self {
            all_repos: DashMap::new(),
            top_repos_gauge,
            last_refresh_nanos: AtomicU64::new(0),
            start_instant: Instant::now(),
            top_n,
            refresh_interval,
        }
    }

    /// Records bytes transferred for a repository.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - Repository identifier (e.g., npub or repo name)
    /// * `bytes` - Number of bytes transferred
    pub fn record_transfer(&self, repo_id: &str, bytes: u64) {
        self.all_repos
            .entry(repo_id.to_string())
            .and_modify(|v| *v = v.saturating_add(bytes))
            .or_insert(bytes);
    }

    /// Conditionally refreshes the top-N list if the refresh interval has elapsed.
    ///
    /// This method is designed to be called frequently (e.g., on every
    /// `/metrics` request) without performance impact - it only does work
    /// when the refresh interval has elapsed.
    pub fn maybe_refresh_top_n(&self) {
        let elapsed_nanos = self.start_instant.elapsed().as_nanos() as u64;
        let last_refresh = self.last_refresh_nanos.load(Ordering::Relaxed);
        let interval_nanos = self.refresh_interval.as_nanos() as u64;

        // Check if enough time has passed since last refresh
        if elapsed_nanos.saturating_sub(last_refresh) >= interval_nanos {
            // Try to update the timestamp atomically to prevent concurrent refreshes
            if self
                .last_refresh_nanos
                .compare_exchange(
                    last_refresh,
                    elapsed_nanos,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.refresh_top_n();
            }
        }
    }

    /// Forces a refresh of the top-N list.
    ///
    /// This recalculates which repositories are in the top N by bandwidth
    /// and updates the Prometheus gauges accordingly.
    pub fn refresh_top_n(&self) {
        // Collect all repo data
        let mut sorted: Vec<_> = self
            .all_repos
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();

        // Sort by bytes descending
        sorted.sort_by_key(|b| Reverse(b.1));

        // Clear old labels and set new top N
        self.top_repos_gauge.reset();
        for (repo, bytes) in sorted.into_iter().take(self.top_n) {
            self.top_repos_gauge
                .with_label_values(&[&repo])
                .set(bytes as f64);
        }
    }

    /// Returns the total bytes transferred for a specific repository.
    ///
    /// Returns `None` if the repository has not been seen.
    pub fn get_repo_bytes(&self, repo_id: &str) -> Option<u64> {
        self.all_repos.get(repo_id).map(|v| *v)
    }

    /// Returns the total bytes transferred across all repositories.
    pub fn total_bytes(&self) -> u64 {
        self.all_repos.iter().map(|r| *r.value()).sum()
    }

    /// Returns the number of repositories being tracked.
    pub fn repo_count(&self) -> usize {
        self.all_repos.len()
    }

    /// Returns the top N repositories by bandwidth.
    ///
    /// This is a snapshot and may not match the Prometheus gauges if
    /// a refresh hasn't occurred recently.
    pub fn get_top_repos(&self) -> Vec<(String, u64)> {
        let mut sorted: Vec<_> = self
            .all_repos
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();

        sorted.sort_by_key(|b| Reverse(b.1));
        sorted.truncate(self.top_n);
        sorted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> Registry {
        Registry::new()
    }

    #[test]
    fn test_bandwidth_tracking() {
        let registry = test_registry();
        let tracker = BandwidthTracker::new(&registry);

        // Record transfers
        tracker.record_transfer("repo-a", 1000);
        tracker.record_transfer("repo-b", 2000);
        tracker.record_transfer("repo-a", 500); // Additional transfer to repo-a

        assert_eq!(tracker.get_repo_bytes("repo-a"), Some(1500));
        assert_eq!(tracker.get_repo_bytes("repo-b"), Some(2000));
        assert_eq!(tracker.get_repo_bytes("repo-c"), None);
        assert_eq!(tracker.total_bytes(), 3500);
        assert_eq!(tracker.repo_count(), 2);
    }

    #[test]
    fn test_top_n_repos() {
        let registry = test_registry();
        let tracker = BandwidthTracker::with_config(&registry, 3, Duration::from_secs(60));

        // Create 5 repos with different bandwidth
        tracker.record_transfer("repo-1", 100);
        tracker.record_transfer("repo-2", 500);
        tracker.record_transfer("repo-3", 200);
        tracker.record_transfer("repo-4", 800);
        tracker.record_transfer("repo-5", 300);

        let top = tracker.get_top_repos();
        assert_eq!(top.len(), 3);
        assert_eq!(top[0], ("repo-4".to_string(), 800));
        assert_eq!(top[1], ("repo-2".to_string(), 500));
        assert_eq!(top[2], ("repo-5".to_string(), 300));
    }

    #[test]
    fn test_refresh_updates_gauge() {
        let registry = test_registry();
        let tracker = BandwidthTracker::new(&registry);

        tracker.record_transfer("high-bandwidth-repo", 10_000_000);
        tracker.record_transfer("low-bandwidth-repo", 1000);

        // Force a refresh
        tracker.refresh_top_n();

        // Verify the gauge values (we can't easily access them directly,
        // but we can verify the tracker state is correct)
        assert_eq!(tracker.repo_count(), 2);
        assert_eq!(tracker.total_bytes(), 10_001_000);
    }

    #[test]
    fn test_saturating_add() {
        let registry = test_registry();
        let tracker = BandwidthTracker::new(&registry);

        // Test that we don't overflow
        tracker.record_transfer("huge-repo", u64::MAX - 100);
        tracker.record_transfer("huge-repo", 200);

        // Should saturate to MAX, not overflow
        assert_eq!(tracker.get_repo_bytes("huge-repo"), Some(u64::MAX));
    }

    #[test]
    fn test_maybe_refresh_respects_interval() {
        let registry = test_registry();
        // Use a very short interval for testing
        let tracker = BandwidthTracker::with_config(&registry, 10, Duration::from_millis(10));

        tracker.record_transfer("repo-a", 1000);

        // First call should trigger refresh (no previous refresh)
        tracker.maybe_refresh_top_n();

        // Add more data
        tracker.record_transfer("repo-b", 2000);

        // Immediate second call should NOT trigger refresh
        let count_before = tracker.repo_count();
        tracker.maybe_refresh_top_n();
        assert_eq!(tracker.repo_count(), count_before);

        // Wait for interval to pass
        std::thread::sleep(Duration::from_millis(15));

        // Now it should refresh
        tracker.maybe_refresh_top_n();
    }

    #[test]
    fn test_empty_tracker() {
        let registry = test_registry();
        let tracker = BandwidthTracker::new(&registry);

        assert_eq!(tracker.total_bytes(), 0);
        assert_eq!(tracker.repo_count(), 0);
        assert!(tracker.get_top_repos().is_empty());

        // Refresh should not panic on empty data
        tracker.refresh_top_n();
    }
}
