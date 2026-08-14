//! Prometheus Metrics for Proactive Sync (GRASP-02)
//!
//! This module provides comprehensive sync monitoring metrics including:
//! - Connection status and attempts per relay
//! - Health state tracking (Healthy/Degraded/Dead)
//! - Event sync tracking (only newly saved events)
//!
//! All metrics follow the `ngit_sync_` prefix convention.

use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};

use super::health::HealthState;

/// Prometheus metrics for the proactive sync system.
///
/// Tracks relay connections, sync progress, health states, and operational statistics.
/// Designed for comprehensive monitoring of GRASP-02 proactive sync operations.
#[derive(Clone)]
pub struct SyncMetrics {
    // === Connection metrics ===
    /// Per-relay connection status (1=connected, 0=disconnected)
    relay_connected: IntGaugeVec,
    /// Connection attempts by relay and result (success/failure)
    connection_attempts_total: IntCounterVec,

    // === Health metrics ===
    /// Per-relay health status (healthy=1, degraded=2, dead=3)
    relay_status: IntGaugeVec,
    /// Per-relay consecutive failure count
    relay_failures: IntGaugeVec,
    /// Subscription policy refusals by relay and bounded category.
    policy_refusals_total: IntCounterVec,

    // === Event metrics ===
    /// Total events synced (newly saved events only)
    events_synced_total: IntCounter,
    /// Historic/live hydration deliveries and terminal processing outcomes.
    hydration_events_total: IntCounterVec,

    // === Summary metrics ===
    /// Total relays discovered and tracked
    relays_tracked_total: IntGauge,
    /// Currently connected relay count
    relays_connected_total: IntGauge,
    /// Relays marked as dead
    relays_dead_total: IntGauge,
    /// Aggregate cardinality of long-lived sync-manager state by fixed class.
    retained_state_current: IntGaugeVec,

    // === Rejected Events Index Metrics (unified with event_type label) ===
    /// Current number of entries in hot cache (by event_type: announcement, state)
    rejected_hot_cache_current: IntGaugeVec,
    /// Total hot cache hits (by event_type: announcement, state)
    rejected_hot_cache_hits_total: IntCounterVec,
    /// Total hot cache misses (by event_type: announcement, state)
    rejected_hot_cache_misses_total: IntCounterVec,
    /// Total expired entries removed from hot cache (by event_type: announcement, state)
    rejected_hot_cache_expired_total: IntCounterVec,
    /// Current number of entries in cold index (by event_type: announcement, state)
    rejected_cold_index_current: IntGaugeVec,
    /// Total cold index entries expired and removed (by event_type: announcement, state)
    rejected_cold_index_expired_total: IntCounterVec,
    /// Total invalidations (by event_type: announcement, state)
    rejected_invalidated_total: IntCounterVec,

    // === Naughty List Metrics ===
    /// Number of relays on naughty list by category
    naughty_relays_total: IntGaugeVec,
}

impl SyncMetrics {
    /// Register all sync metrics with the provided Prometheus registry.
    ///
    /// # Errors
    ///
    /// Returns an error if metrics are already registered (e.g., in tests).
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        // Connection metrics
        let relay_connected = IntGaugeVec::new(
            Opts::new(
                "ngit_sync_relay_connected",
                "Relay connection status (0=disconnected, 1=connecting, 2=syncing, 3=connected, 4=connected_historic_sync_failures)",
            ),
            &["relay"],
        )?;
        registry.register(Box::new(relay_connected.clone()))?;

        let connection_attempts_total = IntCounterVec::new(
            Opts::new(
                "ngit_sync_connection_attempts_total",
                "Total connection attempts by relay and result",
            ),
            &["relay", "result"],
        )?;
        registry.register(Box::new(connection_attempts_total.clone()))?;

        // Health metrics
        let relay_status = IntGaugeVec::new(
            Opts::new(
                "ngit_sync_relay_status",
                "Relay health status (1=healthy, 2=disconnected, 3=degraded, 4=dead, 5=rate_limited, 6=policy_limited)",
            ),
            &["relay"],
        )?;
        registry.register(Box::new(relay_status.clone()))?;

        let relay_failures = IntGaugeVec::new(
            Opts::new(
                "ngit_sync_relay_failures",
                "Consecutive failure count per relay",
            ),
            &["relay"],
        )?;
        registry.register(Box::new(relay_failures.clone()))?;

        let policy_refusals_total = IntCounterVec::new(
            Opts::new(
                "ngit_sync_policy_refusals_total",
                "Subscription refusals by relay and bounded policy category",
            ),
            &["relay", "category"],
        )?;
        registry.register(Box::new(policy_refusals_total.clone()))?;

        // Event metrics
        let events_synced_total = IntCounter::with_opts(Opts::new(
            "ngit_sync_events_synced_total",
            "Total events synced (newly saved events only)",
        ))?;
        registry.register(Box::new(events_synced_total.clone()))?;

        let hydration_events_total = IntCounterVec::new(
            Opts::new(
                "ngit_sync_hydration_events_total",
                "Hydration events by relay, phase, and bounded delivery or persistence outcome",
            ),
            &["relay", "phase", "outcome"],
        )?;
        registry.register(Box::new(hydration_events_total.clone()))?;

        // Summary metrics
        let relays_tracked_total = IntGauge::with_opts(Opts::new(
            "ngit_sync_relays_tracked_total",
            "Total number of relays discovered and tracked",
        ))?;
        registry.register(Box::new(relays_tracked_total.clone()))?;

        let relays_connected_total = IntGauge::with_opts(Opts::new(
            "ngit_sync_relays_connected_total",
            "Number of currently connected relays",
        ))?;
        registry.register(Box::new(relays_connected_total.clone()))?;

        let relays_dead_total = IntGauge::with_opts(Opts::new(
            "ngit_sync_relays_dead_total",
            "Number of relays marked as dead",
        ))?;
        registry.register(Box::new(relays_dead_total.clone()))?;

        let retained_state_current = IntGaugeVec::new(
            Opts::new(
                "ngit_sync_retained_state_current",
                "Current retained sync-manager entries by fixed state class",
            ),
            &["class"],
        )?;
        registry.register(Box::new(retained_state_current.clone()))?;

        // Rejected events metrics (unified with event_type label)
        let rejected_hot_cache_current = IntGaugeVec::new(
            Opts::new(
                "ngit_sync_rejected_hot_cache_current",
                "Current number of entries in hot cache (full events, 2 min expiry)",
            ),
            &["event_type"],
        )?;
        registry.register(Box::new(rejected_hot_cache_current.clone()))?;

        let rejected_hot_cache_hits_total = IntCounterVec::new(
            Opts::new(
                "ngit_sync_rejected_hot_cache_hits_total",
                "Total hot cache hits (events re-processed from cache)",
            ),
            &["event_type"],
        )?;
        registry.register(Box::new(rejected_hot_cache_hits_total.clone()))?;

        let rejected_hot_cache_misses_total = IntCounterVec::new(
            Opts::new(
                "ngit_sync_rejected_hot_cache_misses_total",
                "Total hot cache misses (events not in cache when invalidated)",
            ),
            &["event_type"],
        )?;
        registry.register(Box::new(rejected_hot_cache_misses_total.clone()))?;

        let rejected_hot_cache_expired_total = IntCounterVec::new(
            Opts::new(
                "ngit_sync_rejected_hot_cache_expired_total",
                "Total expired entries removed from hot cache",
            ),
            &["event_type"],
        )?;
        registry.register(Box::new(rejected_hot_cache_expired_total.clone()))?;

        let rejected_cold_index_current = IntGaugeVec::new(
            Opts::new(
                "ngit_sync_rejected_cold_index_current",
                "Current number of entries in cold index (metadata only, 7 day expiry)",
            ),
            &["event_type"],
        )?;
        registry.register(Box::new(rejected_cold_index_current.clone()))?;

        let rejected_cold_index_expired_total = IntCounterVec::new(
            Opts::new(
                "ngit_sync_rejected_cold_index_expired_total",
                "Total expired entries removed from cold index",
            ),
            &["event_type"],
        )?;
        registry.register(Box::new(rejected_cold_index_expired_total.clone()))?;

        let rejected_invalidated_total = IntCounterVec::new(
            Opts::new(
                "ngit_sync_rejected_invalidated_total",
                "Total invalidations (events invalidated when dependencies resolved)",
            ),
            &["event_type"],
        )?;
        registry.register(Box::new(rejected_invalidated_total.clone()))?;

        // Naughty list metrics
        let naughty_relays_total = IntGaugeVec::new(
            Opts::new(
                "ngit_sync_naughty_relays_total",
                "Number of relays on naughty list by category",
            ),
            &["category"],
        )?;
        registry.register(Box::new(naughty_relays_total.clone()))?;

        Ok(Self {
            relay_connected,
            connection_attempts_total,
            relay_status,
            relay_failures,
            policy_refusals_total,
            events_synced_total,
            hydration_events_total,
            relays_tracked_total,
            relays_connected_total,
            relays_dead_total,
            retained_state_current,
            rejected_hot_cache_current,
            rejected_hot_cache_hits_total,
            rejected_hot_cache_misses_total,
            rejected_hot_cache_expired_total,
            rejected_cold_index_current,
            rejected_cold_index_expired_total,
            rejected_invalidated_total,
            naughty_relays_total,
        })
    }

    // === Connection Recording Methods ===

    /// Record a connection attempt (success or failure).
    ///
    /// # Arguments
    ///
    /// * `relay` - The relay URL
    /// * `success` - Whether the connection attempt succeeded
    pub fn record_connection_attempt(&self, relay: &str, success: bool) {
        let result = if success { "success" } else { "failure" };
        self.connection_attempts_total
            .with_label_values(&[relay, result])
            .inc();
        self.set_relay_connected(relay, success);
    }

    /// Set relay connection status.
    ///
    /// # Arguments
    ///
    /// * `relay` - The relay URL
    /// * `connected` - Whether the relay is currently connected
    pub fn set_relay_connected(&self, relay: &str, connected: bool) {
        self.relay_connected
            .with_label_values(&[relay])
            .set(if connected { 1 } else { 0 });

        // Note: Connected count should be updated via update_connected_count() for accuracy
    }

    /// Update the total connected relay count.
    ///
    /// This directly sets the count rather than deriving it from individual relay states,
    /// which is more accurate when relay connection states are managed elsewhere.
    pub fn update_connected_count(&self, count: i64) {
        self.relays_connected_total.set(count);
    }

    /// Increment connected count by one.
    pub fn inc_connected_count(&self) {
        self.relays_connected_total.inc();
    }

    /// Decrement connected count by one.
    pub fn dec_connected_count(&self) {
        self.relays_connected_total.dec();
    }

    // === Health Recording Methods ===

    /// Record relay health state change.
    ///
    /// Maps health states to numeric values for Prometheus:
    /// - Healthy = 1 (connected and stable)
    /// - Disconnected = 2 (not connected, but no issues)
    /// - Degraded = 3 (connection problems or unstable after recovery)
    /// - Dead = 4 (24h+ of failures)
    /// - RateLimited = 5 (rate limit cooldown active)
    /// - PolicyLimited = 6 (relay policy refusal; daily probe pending)
    ///
    /// # Arguments
    ///
    /// * `relay` - The relay URL
    /// * `state` - The current health state
    pub fn record_health_state(&self, relay: &str, state: HealthState) {
        let state_value = match state {
            HealthState::Healthy => 1,
            HealthState::Disconnected => 2,
            HealthState::Degraded => 3,
            HealthState::Dead => 4,
            HealthState::RateLimited => 5,
            HealthState::PolicyLimited => 6,
        };
        self.relay_status
            .with_label_values(&[relay])
            .set(state_value);
    }

    /// Record relay connection status change.
    ///
    /// Maps connection status to numeric values for Prometheus:
    /// - Disconnected = 0 (not connected)
    /// - Connecting = 1 (connection attempt in progress)
    /// - Syncing = 2 (connected, historic sync in progress)
    /// - Connected = 3 (connected, historic sync complete)
    /// - ConnectedHistoricSyncFailures = 4 (connected, historic sync had failures but live sync active)
    ///
    /// This is separate from health state and provides more granular connection lifecycle tracking.
    ///
    /// # Arguments
    ///
    /// * `relay` - The relay URL
    /// * `status` - The current connection status
    pub fn record_connection_status(&self, relay: &str, status: super::ConnectionStatus) {
        use super::ConnectionStatus;
        let status_value = match status {
            ConnectionStatus::Disconnected => 0,
            ConnectionStatus::Connecting => 1,
            ConnectionStatus::Syncing => 2,
            ConnectionStatus::Connected => 3,
            ConnectionStatus::ConnectedHistoricSyncFailures => 4,
            ConnectionStatus::Disconnecting => 5,
        };
        self.relay_connected
            .with_label_values(&[relay])
            .set(status_value);
    }

    /// Record relay failure count.
    ///
    /// # Arguments
    ///
    /// * `relay` - The relay URL
    /// * `count` - The number of consecutive failures
    pub fn record_failure_count(&self, relay: &str, count: u32) {
        self.relay_failures
            .with_label_values(&[relay])
            .set(count as i64);
    }

    pub fn record_policy_refusal(&self, relay: &str, category: &str) {
        self.policy_refusals_total
            .with_label_values(&[relay, category])
            .inc();
    }

    /// Update dead relay count.
    pub fn update_dead_count(&self, count: i64) {
        self.relays_dead_total.set(count);
    }

    /// Increment dead relay count by one.
    pub fn inc_dead_count(&self) {
        self.relays_dead_total.inc();
    }

    /// Decrement dead relay count by one.
    pub fn dec_dead_count(&self) {
        self.relays_dead_total.dec();
    }

    // === Event Recording Methods ===

    /// Record a successfully synced event (newly saved to database).
    ///
    /// Only events that are new AND pass write policy should be counted.
    /// Duplicates and rejected events are not counted.
    pub fn record_synced_event(&self) {
        self.events_synced_total.inc();
    }

    /// Record hydration work using a fixed outcome vocabulary supplied by the
    /// sync manager. `count` allows exact-ID attempts to account for a batch
    /// without performing one Prometheus update per absent response.
    pub fn record_hydration_events(&self, relay: &str, phase: &str, outcome: &str, count: usize) {
        if count == 0 {
            return;
        }
        self.hydration_events_total
            .with_label_values(&[relay, phase, outcome])
            .inc_by(count as u64);
    }

    // === Summary Recording Methods ===

    /// Set the total tracked relay count.
    pub fn set_tracked_count(&self, count: i64) {
        self.relays_tracked_total.set(count);
    }

    /// Increment tracked relay count by one.
    pub fn inc_tracked_count(&self) {
        self.relays_tracked_total.inc();
    }

    /// Remove current-state metric series for a relay that is no longer tracked.
    pub fn forget_relay(&self, relay: &str) {
        let _ = self.relay_connected.remove_label_values(&[relay]);
        let _ = self.relay_status.remove_label_values(&[relay]);
        let _ = self.relay_failures.remove_label_values(&[relay]);
        self.relays_tracked_total.dec();
    }

    /// Get current tracked relay count.
    pub fn get_tracked_count(&self) -> i64 {
        self.relays_tracked_total.get()
    }

    /// Get current connected relay count.
    pub fn get_connected_count(&self) -> i64 {
        self.relays_connected_total.get()
    }

    /// Get current dead relay count.
    pub fn get_dead_count(&self) -> i64 {
        self.relays_dead_total.get()
    }

    /// Record one aggregate long-lived state cardinality. Callers must use the
    /// fixed class vocabulary documented by the sync manager.
    pub fn set_retained_state(&self, class: &str, count: usize) {
        self.retained_state_current
            .with_label_values(&[class])
            .set(count as i64);
    }

    // === Rejected Events Recording Methods (unified with event_type parameter) ===

    /// Update hot cache current size gauge for a specific event type.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Either "announcement" or "state"
    /// * `size` - Current number of entries
    pub fn update_rejected_hot_cache_size(&self, event_type: &str, size: usize) {
        self.rejected_hot_cache_current
            .with_label_values(&[event_type])
            .set(size as i64);
    }

    /// Record hot cache hit for a specific event type.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Either "announcement" or "state"
    pub fn record_rejected_hot_cache_hit(&self, event_type: &str) {
        self.rejected_hot_cache_hits_total
            .with_label_values(&[event_type])
            .inc();
    }

    /// Record hot cache miss for a specific event type.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Either "announcement" or "state"
    pub fn record_rejected_hot_cache_miss(&self, event_type: &str) {
        self.rejected_hot_cache_misses_total
            .with_label_values(&[event_type])
            .inc();
    }

    /// Record hot cache expired entries for a specific event type.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Either "announcement" or "state"
    /// * `count` - Number of expired entries
    pub fn record_rejected_hot_cache_expired(&self, event_type: &str, count: usize) {
        self.rejected_hot_cache_expired_total
            .with_label_values(&[event_type])
            .inc_by(count as u64);
    }

    /// Update cold index current size gauge for a specific event type.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Either "announcement" or "state"
    /// * `size` - Current number of entries
    pub fn update_rejected_cold_index_size(&self, event_type: &str, size: usize) {
        self.rejected_cold_index_current
            .with_label_values(&[event_type])
            .set(size as i64);
    }

    /// Record cold index expired entries for a specific event type.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Either "announcement" or "state"
    /// * `count` - Number of expired entries
    pub fn record_rejected_cold_index_expired(&self, event_type: &str, count: usize) {
        self.rejected_cold_index_expired_total
            .with_label_values(&[event_type])
            .inc_by(count as u64);
    }

    /// Record invalidation for a specific event type.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Either "announcement" or "state"
    /// * `count` - Number of invalidated entries
    pub fn record_rejected_invalidation(&self, event_type: &str, count: usize) {
        self.rejected_invalidated_total
            .with_label_values(&[event_type])
            .inc_by(count as u64);
    }

    // === Naughty List Recording Methods ===

    /// Update naughty list metrics from current naughty list state
    ///
    /// This method resets and rebuilds all naughty list metrics based on
    /// the provided entries. Should be called periodically to keep metrics
    /// in sync with the naughty list state.
    ///
    /// # Arguments
    ///
    /// * `entries` - Vector of (relay_url, naughty_entry) tuples from NaughtyListTracker::get_all()
    pub fn update_naughty_list(&self, entries: Vec<(String, super::naughty_list::NaughtyEntry)>) {
        use super::naughty_list::NaughtyCategory;

        // Reset the bounded aggregate before rebuilding its three categories.
        self.naughty_relays_total.reset();

        // Count by category
        let mut dns_count = 0;
        let mut tls_count = 0;
        let mut protocol_count = 0;

        for (_, entry) in entries {
            match entry.category {
                NaughtyCategory::DnsLookupFailed => dns_count += 1,
                NaughtyCategory::TlsCertificateInvalid => tls_count += 1,
                NaughtyCategory::ProtocolError => protocol_count += 1,
            }
        }

        // Set category totals
        self.naughty_relays_total
            .with_label_values(&["dns_lookup_failed"])
            .set(dns_count);
        self.naughty_relays_total
            .with_label_values(&["tls_certificate_invalid"])
            .set(tls_count);
        self.naughty_relays_total
            .with_label_values(&["protocol_error"])
            .set(protocol_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Encoder, TextEncoder};
    use std::time::Instant;

    fn create_test_registry() -> Registry {
        Registry::new()
    }

    #[test]
    fn test_metrics_registration() {
        let registry = create_test_registry();
        let metrics = SyncMetrics::register(&registry);
        assert!(metrics.is_ok());
    }

    #[test]
    fn test_connection_metrics() {
        let registry = create_test_registry();
        let metrics = SyncMetrics::register(&registry).unwrap();

        // Record connection attempts
        metrics.record_connection_attempt("wss://relay1.example.com", true);
        metrics.record_connection_attempt("wss://relay1.example.com", false);
        metrics.record_connection_attempt("wss://relay2.example.com", true);

        // Set relay connection status
        metrics.set_relay_connected("wss://relay1.example.com", true);
        metrics.inc_connected_count();

        assert_eq!(metrics.get_connected_count(), 1);

        // Test decrement
        metrics.dec_connected_count();
        assert_eq!(metrics.get_connected_count(), 0);
    }

    #[test]
    fn test_health_metrics() {
        let registry = create_test_registry();
        let metrics = SyncMetrics::register(&registry).unwrap();

        // Record health states
        metrics.record_health_state("wss://relay1.example.com", HealthState::Healthy);
        metrics.record_health_state("wss://relay2.example.com", HealthState::Degraded);
        metrics.record_health_state("wss://relay3.example.com", HealthState::Dead);

        // Record failure count
        metrics.record_failure_count("wss://relay2.example.com", 5);

        // Test dead count tracking
        metrics.update_dead_count(1);
        assert_eq!(metrics.get_dead_count(), 1);

        metrics.inc_dead_count();
        assert_eq!(metrics.get_dead_count(), 2);

        metrics.dec_dead_count();
        assert_eq!(metrics.get_dead_count(), 1);
    }

    #[test]
    fn test_event_metrics() {
        let registry = create_test_registry();
        let metrics = SyncMetrics::register(&registry).unwrap();

        // Record synced events
        metrics.record_synced_event();
        metrics.record_synced_event();
        metrics.record_synced_event();

        metrics.record_hydration_events("wss://relay.example", "recovery", "requested", 3);
        metrics.record_hydration_events("wss://relay.example", "recovery", "saved", 2);
        metrics.record_hydration_events("wss://relay.example", "recovery", "not_delivered", 1);

        let hydration = registry
            .gather()
            .into_iter()
            .find(|family| family.name() == "ngit_sync_hydration_events_total")
            .expect("hydration outcome metric must be exported");
        assert_eq!(hydration.get_metric().len(), 3);
        assert_eq!(
            hydration
                .get_metric()
                .iter()
                .map(|metric| metric.get_counter().value() as u64)
                .sum::<u64>(),
            6
        );
    }

    #[test]
    fn test_summary_metrics() {
        let registry = create_test_registry();
        let metrics = SyncMetrics::register(&registry).unwrap();

        // Test tracked count
        metrics.set_tracked_count(5);
        assert_eq!(metrics.get_tracked_count(), 5);

        metrics.inc_tracked_count();
        assert_eq!(metrics.get_tracked_count(), 6);

        metrics.record_connection_status(
            "wss://obsolete.example",
            crate::sync::ConnectionStatus::Connected,
        );
        metrics.record_health_state("wss://obsolete.example", HealthState::Healthy);
        metrics.forget_relay("wss://obsolete.example");
        assert_eq!(metrics.get_tracked_count(), 5);

        // Test connected count
        metrics.update_connected_count(3);
        assert_eq!(metrics.get_connected_count(), 3);
    }

    #[test]
    fn test_duplicate_registration_fails() {
        let registry = create_test_registry();

        // First registration should succeed
        let metrics1 = SyncMetrics::register(&registry);
        assert!(metrics1.is_ok());

        // Second registration should fail (metrics already registered)
        let metrics2 = SyncMetrics::register(&registry);
        assert!(metrics2.is_err());
    }

    #[test]
    fn retained_state_metric_uses_fixed_aggregate_classes() {
        let registry = create_test_registry();
        let metrics = SyncMetrics::register(&registry).unwrap();

        metrics.set_retained_state("pending_batches", 12);
        metrics.set_retained_state("queued_connection_attempts", 3);

        let family = registry
            .gather()
            .into_iter()
            .find(|family| family.name() == "ngit_sync_retained_state_current")
            .expect("retained-state metric must be exported");
        assert_eq!(family.get_metric().len(), 2);
        assert_eq!(
            family
                .get_metric()
                .iter()
                .map(|metric| metric.get_gauge().value() as i64)
                .sum::<i64>(),
            15
        );
    }

    #[test]
    fn test_rejected_events_metrics() {
        let registry = create_test_registry();
        let metrics = SyncMetrics::register(&registry).unwrap();

        // Test announcement hot cache metrics
        metrics.update_rejected_hot_cache_size("announcement", 10);
        metrics.record_rejected_hot_cache_hit("announcement");
        metrics.record_rejected_hot_cache_hit("announcement");
        metrics.record_rejected_hot_cache_miss("announcement");
        metrics.record_rejected_hot_cache_expired("announcement", 5);

        // Test announcement cold index metrics
        metrics.update_rejected_cold_index_size("announcement", 100);
        metrics.record_rejected_cold_index_expired("announcement", 10);

        // Test announcement invalidation metrics
        metrics.record_rejected_invalidation("announcement", 3);
        metrics.record_rejected_invalidation("announcement", 2);

        // Test state hot cache metrics
        metrics.update_rejected_hot_cache_size("state", 20);
        metrics.record_rejected_hot_cache_hit("state");
        metrics.record_rejected_hot_cache_miss("state");
        metrics.record_rejected_hot_cache_expired("state", 3);

        // Test state cold index metrics
        metrics.update_rejected_cold_index_size("state", 50);
        metrics.record_rejected_cold_index_expired("state", 5);

        // Test state invalidation metrics
        metrics.record_rejected_invalidation("state", 1);
    }

    #[test]
    fn test_naughty_list_metrics_have_fixed_peer_independent_cardinality() {
        use super::super::naughty_list::{NaughtyCategory, NaughtyEntry};

        let registry = create_test_registry();
        let metrics = SyncMetrics::register(&registry).unwrap();
        let categories = [
            NaughtyCategory::DnsLookupFailed,
            NaughtyCategory::TlsCertificateInvalid,
            NaughtyCategory::ProtocolError,
        ];

        for batch in 0..4 {
            let entries = (0..300)
                .map(|index| {
                    (
                        format!("wss://peer-{batch}-{index}.attacker.example"),
                        NaughtyEntry {
                            category: categories[index % categories.len()],
                            reason: format!("peer-controlled-reason-{batch}-{index}"),
                            first_seen: Instant::now(),
                            last_seen: Instant::now(),
                            occurrence_count: index as u32 + 1,
                        },
                    )
                })
                .collect();

            metrics.update_naughty_list(entries);

            let families = registry.gather();
            assert!(families
                .iter()
                .all(|family| family.name() != "ngit_sync_naughty_relay_info"));
            let aggregate = families
                .iter()
                .find(|family| family.name() == "ngit_sync_naughty_relays_total")
                .expect("missing aggregate naughty-list metric");
            assert_eq!(aggregate.get_metric().len(), 3);
            assert!(aggregate.get_metric().iter().all(|metric| {
                metric.get_label().len() == 1
                    && metric.get_label()[0].name() == "category"
                    && matches!(
                        metric.get_label()[0].value(),
                        "dns_lookup_failed" | "tls_certificate_invalid" | "protocol_error"
                    )
                    && metric.get_gauge().value() == 100.0
            }));

            let mut encoded = Vec::new();
            TextEncoder::new().encode(&families, &mut encoded).unwrap();
            let encoded = String::from_utf8(encoded).unwrap();
            assert!(!encoded.contains("attacker.example"));
            assert!(!encoded.contains("peer-controlled-reason"));
        }
    }
}
