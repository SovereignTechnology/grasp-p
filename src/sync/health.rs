//! Relay Health Tracking for GRASP-02 Proactive Sync
//!
//! This module implements health tracking for relay connections, including:
//! - Health state machine (Healthy -> Degraded -> Dead -> RateLimited)
//! - Exponential backoff with configurable max delay
//! - Dead relay detection after 24h of continuous failures
//! - Rate limit detection and fixed cooldown period
//! - Naughty list for persistent infrastructure issues (DNS, TLS, protocol errors)
//!
//! ## Health States
//!
//! - **Healthy**: Working connection, no recent failures
//! - **Degraded**: Connection failed, retrying with backoff
//! - **Dead**: 24h+ of continuous failures, minimal retry (once per day)
//! - **RateLimited**: NOTICE-triggered 65-second cooldown to avoid rate limits

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::naughty_list::NaughtyListTracker;
use crate::config::Config;

/// Duration threshold before a relay is considered dead (24 hours)
const DEAD_THRESHOLD_HOURS: u64 = 24;

/// How often dead relays are retried (once per 24 hours)
const DEAD_RETRY_INTERVAL_HOURS: u64 = 24;

/// Default maximum backoff duration in seconds (1 hour)
const DEFAULT_MAX_BACKOFF_SECS: u64 = 3600;

/// Default base backoff duration in seconds
const DEFAULT_BASE_BACKOFF_SECS: u64 = 5;

/// Rate limit cooldown duration in seconds (65 seconds = typical 60s limit + buffer)
const RATE_LIMIT_COOLDOWN_SECS: u64 = 65;

/// Stability period after recovery before marking relay as fully healthy (5 minutes)
/// A relay must maintain connection for this duration after failures before being marked Healthy
const STABILITY_PERIOD_SECS: u64 = 300;

/// Health state of a relay connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Working connection, no recent failures, proven stable
    Healthy,
    /// Not currently connected, but no recent failures or issues
    Disconnected,
    /// Connection problems: failing to connect OR recently recovered but not yet stable
    Degraded,
    /// 24h+ of continuous failures, minimal retry
    Dead,
    /// Rate limited by relay, temporary cooldown active
    RateLimited,
}

impl std::fmt::Display for HealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthState::Healthy => write!(f, "healthy"),
            HealthState::Disconnected => write!(f, "disconnected"),
            HealthState::Degraded => write!(f, "degraded"),
            HealthState::Dead => write!(f, "dead"),
            HealthState::RateLimited => write!(f, "rate_limited"),
        }
    }
}

/// Health information for a single relay
#[derive(Debug, Clone, Default)]
pub struct RelayHealth {
    /// Are we currently connected to this relay
    pub connected: bool,
    /// Has this relay sent us a rate-limiting NOTICE recently
    pub rate_limited: bool,
    /// Number of consecutive connection failures
    pub consecutive_failures: u32,
    /// Time of the first failure in the current failure streak
    pub first_failure_time: Option<Instant>,
    /// Time of the last failure (kept after recovery for stability period tracking)
    pub last_failure_time: Option<Instant>,
    /// Time of the last successful connection
    pub last_success_time: Option<Instant>,
    /// Time of the last connection attempt (success or failure)
    pub last_attempt_time: Option<Instant>,
    /// Next time a connection attempt should be made
    pub next_retry_at: Option<Instant>,
}

impl RelayHealth {
    /// Create a new RelayHealth with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current health state based on the relay's properties
    ///
    /// State is computed dynamically from:
    /// - Rate limit status
    /// - Connection status
    /// - Failure history and timing
    /// - Stability period after recovery
    ///
    /// ## State Logic
    ///
    /// 1. **RateLimited**: If the rate-limit cooldown hasn't expired
    /// 2. **Dead**: 24+ hours of continuous failures
    /// 3. **Degraded**: Active connection failures OR in stability period after recovery
    /// 4. **Disconnected**: Not connected, but no recent failures or issues
    /// 5. **Healthy**: Connected and stable (past stability period with no failures)
    pub fn state(&self) -> HealthState {
        let now = Instant::now();

        // Check rate limiting first (highest priority)
        if self.rate_limited {
            if let Some(next_retry) = self.next_retry_at {
                if now < next_retry {
                    return HealthState::RateLimited;
                }
            }
        }

        // Check for dead state (24+ hours of failures)
        if let Some(first_failure) = self.first_failure_time {
            let failure_duration = now.duration_since(first_failure);
            let dead_threshold = Duration::from_secs(DEAD_THRESHOLD_HOURS * 3600);
            if failure_duration >= dead_threshold {
                return HealthState::Dead;
            }
        }

        // Check if we have active failures (currently failing to connect)
        if self.consecutive_failures > 0 {
            return HealthState::Degraded;
        }

        // Check if we're in stability period after recovery
        // (recovered from failures but not yet proven stable)
        if let (Some(last_success), Some(last_failure)) =
            (self.last_success_time, self.last_failure_time)
        {
            // Only consider stability period if recovery happened after the last failure
            if last_success > last_failure {
                let time_since_recovery = now.duration_since(last_success);
                let stability_period = Duration::from_secs(STABILITY_PERIOD_SECS);

                if time_since_recovery < stability_period {
                    // Still in stability period - remain degraded to prove stability
                    return HealthState::Degraded;
                }
            }
        }

        // Check connection status for final state
        if self.connected {
            // Connected and stable (no failures, past stability period)
            HealthState::Healthy
        } else {
            // Not connected, but no recent failures - just disconnected
            HealthState::Disconnected
        }
    }

    /// Check if the relay is currently connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Check if the relay is currently rate limited (cooldown active)
    pub fn is_rate_limited_now(&self) -> bool {
        if !self.rate_limited {
            return false;
        }
        if let Some(next_retry) = self.next_retry_at {
            Instant::now() < next_retry
        } else {
            false
        }
    }

    /// Get the consecutive failure count
    pub fn failure_count(&self) -> u32 {
        self.consecutive_failures
    }

    /// Get time since last successful connection
    pub fn time_since_last_success(&self) -> Option<Duration> {
        self.last_success_time
            .map(|t| Instant::now().duration_since(t))
    }

    /// Get time since first failure in current streak
    pub fn time_since_first_failure(&self) -> Option<Duration> {
        self.first_failure_time
            .map(|t| Instant::now().duration_since(t))
    }

    /// Get remaining backoff/cooldown duration
    pub fn remaining_backoff(&self) -> Option<Duration> {
        let next_retry = self.next_retry_at?;
        let now = Instant::now();
        if now >= next_retry {
            None
        } else {
            Some(next_retry - now)
        }
    }
}

/// Thread-safe relay health tracker using DashMap
#[derive(Debug)]
pub struct RelayHealthTracker {
    health: DashMap<String, RelayHealth>,
    max_backoff_secs: u64,
    base_backoff_secs: u64,
    naughty_list: Option<Arc<NaughtyListTracker>>,
}

impl RelayHealthTracker {
    /// Create a new RelayHealthTracker
    pub fn new(config: &Config) -> Self {
        let naughty_list = Some(Arc::new(NaughtyListTracker::new(
            config.naughty_list_expiration_hours,
        )));

        Self {
            health: DashMap::new(),
            max_backoff_secs: config.sync_max_backoff_secs,
            base_backoff_secs: config.sync_base_backoff_secs,
            naughty_list,
        }
    }

    /// Create a new RelayHealthTracker with default settings
    pub fn with_defaults() -> Self {
        Self {
            health: DashMap::new(),
            max_backoff_secs: DEFAULT_MAX_BACKOFF_SECS,
            base_backoff_secs: DEFAULT_BASE_BACKOFF_SECS,
            naughty_list: Some(Arc::new(NaughtyListTracker::with_defaults())),
        }
    }

    /// Create a new RelayHealthTracker with custom max backoff
    pub fn with_max_backoff(max_backoff_secs: u64) -> Self {
        Self {
            health: DashMap::new(),
            max_backoff_secs,
            base_backoff_secs: DEFAULT_BASE_BACKOFF_SECS,
            naughty_list: Some(Arc::new(NaughtyListTracker::with_defaults())),
        }
    }

    /// Get the base backoff duration in seconds
    ///
    /// This is used by SyncManager to set connection timeout
    /// (connection timeout should not exceed base backoff)
    pub fn base_backoff_secs(&self) -> u64 {
        self.base_backoff_secs
    }

    /// Record a connection attempt (updates last_attempt_time)
    ///
    /// This should be called before trying to connect, to track when
    /// attempts are made regardless of success or failure.
    pub fn record_attempt(&self, relay_url: &str) {
        let now = Instant::now();
        let mut entry = self.health.entry(relay_url.to_string()).or_default();
        let health = entry.value_mut();
        health.last_attempt_time = Some(now);
    }

    /// Record a successful connection to a relay
    ///
    /// Sets connected = true. A relay recovering from failures keeps its
    /// failure streak until it survives the stability period under normal
    /// workload; a WebSocket handshake alone is not proof of recovery.
    ///
    /// A successful WebSocket connection does not prove that the relay will
    /// accept a new REQ, so it deliberately leaves any active rate-limit
    /// cooldown unchanged.
    pub fn record_success(&self, relay_url: &str) {
        let now = Instant::now();
        let mut entry = self.health.entry(relay_url.to_string()).or_default();
        let health = entry.value_mut();

        let old_state = health.state();
        let active_rate_limit = health
            .rate_limited
            .then_some(health.next_retry_at)
            .flatten()
            .filter(|deadline| *deadline > now);

        let was_connected = health.connected;
        let recovering = health.consecutive_failures > 0 || health.last_failure_time.is_some();

        // A live rate-limit cooldown is independent of whether the WebSocket
        // handshake succeeded.
        health.connected = true;
        health.rate_limited = active_rate_limit.is_some();
        if !recovering {
            health.consecutive_failures = 0;
            health.first_failure_time = None;
            health.last_failure_time = None;
        }
        // Keep one stability boundary per session if a duplicate connection
        // notification reaches this idempotent accounting boundary.
        if !was_connected {
            health.last_success_time = Some(now);
        }
        health.last_attempt_time = Some(now);
        health.next_retry_at = active_rate_limit;

        let new_state = health.state();
        if recovering && !was_connected {
            tracing::info!(
                relay = %relay_url,
                consecutive_failures = health.consecutive_failures,
                stability_secs = STABILITY_PERIOD_SECS,
                "Relay connected; preserving failure streak until stable"
            );
        } else if old_state != new_state {
            tracing::info!(
                "Relay {} connection recovered ({:?} -> {:?})",
                relay_url,
                old_state,
                new_state
            );
        }
    }

    /// Promote recovered connections that have remained established through
    /// the stability period under their normal workload.
    pub fn promote_stable_connections(&self) -> Vec<String> {
        let now = Instant::now();
        let stability_period = Duration::from_secs(STABILITY_PERIOD_SECS);
        let mut promoted = Vec::new();

        for mut entry in self.health.iter_mut() {
            let (relay_url, health) = entry.pair_mut();
            if !health.connected || health.consecutive_failures == 0 {
                continue;
            }
            let Some(connected_at) = health.last_success_time else {
                continue;
            };
            if now.duration_since(connected_at) < stability_period {
                continue;
            }

            health.consecutive_failures = 0;
            health.first_failure_time = None;
            health.last_failure_time = None;
            if !health.is_rate_limited_now() {
                health.next_retry_at = None;
            }
            promoted.push(relay_url.clone());
            tracing::info!(
                relay = %relay_url,
                stability_secs = STABILITY_PERIOD_SECS,
                "Relay connection proved stable; failure streak reset"
            );
        }

        promoted
    }

    /// Record a connection failure for a relay
    ///
    /// Increments failure counter and calculates next retry time with exponential backoff.
    /// Sets connected = false.
    pub fn record_failure(&self, relay_url: &str) {
        let now = Instant::now();
        let mut entry = self.health.entry(relay_url.to_string()).or_default();
        let health = entry.value_mut();

        let old_state = health.state();

        // Mark as disconnected
        health.connected = false;

        // Set first_failure_time if this is a new failure streak
        if health.first_failure_time.is_none() {
            health.first_failure_time = Some(now);
        }

        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        health.last_failure_time = Some(now);

        // Calculate backoff based on whether we're dead or degraded
        if let Some(first_failure) = health.first_failure_time {
            let failure_duration = now.duration_since(first_failure);
            let dead_threshold = Duration::from_secs(DEAD_THRESHOLD_HOURS * 3600);

            if failure_duration >= dead_threshold {
                // Dead relays retry once per day
                health.next_retry_at =
                    Some(now + Duration::from_secs(DEAD_RETRY_INTERVAL_HOURS * 3600));

                let new_state = health.state();
                if old_state != HealthState::Dead && new_state == HealthState::Dead {
                    tracing::warn!(
                        "Relay {} marked dead after 24h failures ({} consecutive failures)",
                        relay_url,
                        health.consecutive_failures
                    );
                }
            } else {
                // Degraded state with exponential backoff
                let backoff = Self::get_backoff_duration(
                    health.consecutive_failures,
                    self.base_backoff_secs,
                    self.max_backoff_secs,
                );
                // Respect existing next_retry_at if it's later (e.g., from rate limiting)
                let new_retry_at = now + backoff;
                health.next_retry_at = Some(
                    health
                        .next_retry_at
                        .unwrap_or(new_retry_at)
                        .max(new_retry_at),
                );

                let new_state = health.state();
                if old_state != HealthState::Degraded && new_state == HealthState::Degraded {
                    tracing::warn!("Relay {} degraded, backoff {:?}", relay_url, backoff);
                } else {
                    tracing::debug!(
                        "Relay {} failure #{}, backoff {:?}",
                        relay_url,
                        health.consecutive_failures,
                        backoff
                    );
                }
            }
        }
    }

    /// Record a rate limit NOTICE from a relay
    ///
    /// Sets the relay to RateLimited state with a fixed 65-second cooldown.
    /// This is distinct from connection failures (Degraded state) - it's triggered
    /// by NOTICE messages from the relay indicating we're sending too many requests.
    pub fn record_rate_limit(&self, relay_url: &str) {
        let now = Instant::now();
        let mut entry = self.health.entry(relay_url.to_string()).or_default();
        let health = entry.value_mut();

        // A relay may repeat the same NOTICE throughout a cooldown. Ignore
        // reminders for that episode, but treat a rejection after the deadline
        // as a failed recovery probe and begin a new cooldown.
        if health.rate_limited && health.next_retry_at.is_some_and(|deadline| now < deadline) {
            return;
        }

        health.rate_limited = true;
        health.next_retry_at = Some(now + Duration::from_secs(RATE_LIMIT_COOLDOWN_SECS));

        tracing::warn!(
            relay = %relay_url,
            cooldown_secs = RATE_LIMIT_COOLDOWN_SECS,
            "Relay rate limited, pausing new subscriptions"
        );
    }

    /// Clear rate limiting state for a specific relay
    ///
    /// This clears the rate-limit episode without affecting connection status
    /// or failure counters. Use this when the cooldown has expired and new
    /// subscriptions may probe the relay again.
    pub fn clear_rate_limit(&self, relay_url: &str) {
        if let Some(mut entry) = self.health.get_mut(relay_url) {
            let health = entry.value_mut();
            health.rate_limited = false;
            health.next_retry_at = None;
        }
    }

    /// Check if relay is currently rate limited
    ///
    /// Returns true if the relay is in RateLimited state and the cooldown period
    /// has not yet expired. Once the cooldown expires, this returns false and the
    /// relay can accept new subscriptions again.
    pub fn is_rate_limited(&self, relay_url: &str) -> bool {
        if let Some(entry) = self.health.get(relay_url) {
            let health = entry.value();
            health.is_rate_limited_now()
        } else {
            false
        }
    }

    /// Exit rate limiting state for relays whose cooldown has expired
    ///
    /// Finds all relays that are currently rate limited but whose cooldown period
    /// has expired, clears their rate_limited flag, and returns their URLs.
    ///
    /// This method mutates state by clearing the rate_limited flag for recovered relays.
    ///
    /// Returns a vector of relay URLs that were recovered from rate limiting.
    pub fn exit_expired_rate_limits(&self) -> Vec<String> {
        let now = Instant::now();
        let mut recovered_relays = Vec::new();

        for mut entry in self.health.iter_mut() {
            let (url, health) = entry.pair_mut();

            // Check if rate limited and cooldown has expired
            if health.rate_limited {
                if let Some(deadline) = health.next_retry_at {
                    if now >= deadline {
                        // Cooldown expired - clear rate limiting
                        health.rate_limited = false;
                        health.next_retry_at = None;
                        recovered_relays.push(url.clone());

                        tracing::info!(
                            relay = %url,
                            "Rate limit cooldown expired, relay ready for new subscriptions"
                        );
                    }
                }
            }
        }

        recovered_relays
    }

    /// Check if a connection attempt should be made to a relay
    ///
    /// Returns true if:
    /// - The relay has no health record (first attempt)
    /// - The relay is healthy
    /// - The backoff period has elapsed
    pub fn should_attempt_connection(&self, relay_url: &str) -> bool {
        if self
            .naughty_list
            .as_ref()
            .is_some_and(|naughty_list| naughty_list.is_naughty(relay_url))
        {
            return false;
        }

        let entry = self.health.get(relay_url);

        match entry {
            None => true, // No record, allow first attempt
            Some(entry) => {
                let health = entry.value();

                // Don't reconnect if currently rate-limited
                if health.is_rate_limited_now() {
                    return false;
                }

                // Check state-based logic
                match health.state() {
                    HealthState::Healthy | HealthState::Disconnected => true,
                    HealthState::Degraded | HealthState::Dead | HealthState::RateLimited => {
                        // Check if backoff/cooldown period has elapsed
                        match health.next_retry_at {
                            None => true,
                            Some(next_retry) => Instant::now() >= next_retry,
                        }
                    }
                }
            }
        }
    }

    /// Get the current health state of a relay
    pub fn get_state(&self, relay_url: &str) -> HealthState {
        self.health
            .get(relay_url)
            .map(|entry| entry.value().state())
            .unwrap_or(HealthState::Healthy)
    }

    /// Check if a relay is marked as dead
    pub fn is_dead(&self, relay_url: &str) -> bool {
        self.get_state(relay_url) == HealthState::Dead
    }

    /// Get the remaining backoff duration for a relay
    ///
    /// Returns None if no backoff is active.
    pub fn get_remaining_backoff(&self, relay_url: &str) -> Option<Duration> {
        let entry = self.health.get(relay_url)?;
        let health = entry.value();
        let next_retry = health.next_retry_at?;
        let now = Instant::now();

        if now >= next_retry {
            None
        } else {
            Some(next_retry - now)
        }
    }

    /// Get the consecutive failure count for a relay
    pub fn get_failure_count(&self, relay_url: &str) -> u32 {
        self.health
            .get(relay_url)
            .map(|entry| entry.value().consecutive_failures)
            .unwrap_or(0)
    }

    /// Calculate the backoff duration based on failure count
    ///
    /// Uses exponential backoff: base * 2^(failures-1), capped at max_backoff
    ///
    /// # Arguments
    /// * `consecutive_failures` - Number of consecutive failures (1 = first failure)
    /// * `base_backoff_secs` - Base backoff time in seconds
    /// * `max_backoff_secs` - Maximum backoff cap in seconds
    pub fn get_backoff_duration(
        consecutive_failures: u32,
        base_backoff_secs: u64,
        max_backoff_secs: u64,
    ) -> Duration {
        let backoff_secs = base_backoff_secs
            .saturating_mul(2u64.saturating_pow(consecutive_failures.saturating_sub(1)));
        Duration::from_secs(backoff_secs.min(max_backoff_secs))
    }

    /// Get all tracked relay URLs
    pub fn get_tracked_relays(&self) -> Vec<String> {
        self.health
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get a clone of the health info for a relay
    pub fn get_health(&self, relay_url: &str) -> Option<RelayHealth> {
        self.health
            .get(relay_url)
            .map(|entry| entry.value().clone())
    }

    /// Get a reference to the naughty list tracker
    pub fn naughty_list(&self) -> Option<Arc<NaughtyListTracker>> {
        self.naughty_list.clone()
    }
}

/// Create a shared RelayHealthTracker wrapped in Arc
pub fn create_health_tracker(config: &Config) -> Arc<RelayHealthTracker> {
    Arc::new(RelayHealthTracker::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_state_display() {
        assert_eq!(HealthState::Healthy.to_string(), "healthy");
        assert_eq!(HealthState::Degraded.to_string(), "degraded");
        assert_eq!(HealthState::Dead.to_string(), "dead");
    }

    #[test]
    fn test_default_health_is_disconnected() {
        let health = RelayHealth::default();
        // Default state: not connected, no failures = Disconnected
        assert_eq!(health.state(), HealthState::Disconnected);
        assert_eq!(health.consecutive_failures, 0);
        assert!(!health.connected);
        assert!(health.first_failure_time.is_none());
    }

    #[test]
    fn test_should_attempt_connection_new_relay() {
        let tracker = RelayHealthTracker::with_defaults();
        assert!(tracker.should_attempt_connection("wss://new-relay.example.com"));
    }

    #[test]
    fn recovered_handshake_preserves_backoff_until_stable() {
        let tracker = RelayHealthTracker::with_defaults();
        let url = "wss://test-relay.example.com";

        // Simulate a few failures
        tracker.record_failure(url);
        tracker.record_failure(url);
        assert_eq!(tracker.get_state(url), HealthState::Degraded);
        assert_eq!(tracker.get_failure_count(url), 2);

        // Record success
        tracker.record_success(url);
        assert_eq!(tracker.get_state(url), HealthState::Degraded);
        assert_eq!(tracker.get_failure_count(url), 2);
        assert!(tracker.should_attempt_connection(url));

        // A further disconnect continues the existing failure streak rather
        // than returning to the base backoff.
        tracker.record_failure(url);
        assert_eq!(tracker.get_failure_count(url), 3);
        let remaining = tracker.get_remaining_backoff(url).unwrap();
        assert!(remaining > Duration::from_secs(10));
    }

    #[test]
    fn stable_recovered_connection_resets_failure_history() {
        let tracker = RelayHealthTracker::with_defaults();
        let url = "wss://stable-relay.example.com";

        tracker.record_failure(url);
        tracker.record_success(url);
        {
            let mut entry = tracker.health.get_mut(url).unwrap();
            entry.last_success_time =
                Some(Instant::now() - Duration::from_secs(STABILITY_PERIOD_SECS + 1));
        }

        assert_eq!(tracker.promote_stable_connections(), vec![url.to_string()]);
        assert_eq!(tracker.get_state(url), HealthState::Healthy);
        assert_eq!(tracker.get_failure_count(url), 0);
    }

    #[test]
    fn disconnected_relay_cannot_age_into_stable_recovery() {
        let tracker = RelayHealthTracker::with_defaults();
        let url = "wss://disconnected-relay.example.com";

        tracker.record_failure(url);
        tracker.record_success(url);
        tracker.record_failure(url);
        {
            let mut entry = tracker.health.get_mut(url).unwrap();
            entry.last_success_time =
                Some(Instant::now() - Duration::from_secs(STABILITY_PERIOD_SECS + 1));
        }

        assert!(tracker.promote_stable_connections().is_empty());
        assert_eq!(tracker.get_state(url), HealthState::Degraded);
        assert_eq!(tracker.get_failure_count(url), 2);
    }

    #[test]
    fn test_backoff_increases_exponentially() {
        let base = DEFAULT_BASE_BACKOFF_SECS; // 5 seconds
        let max = 3600u64;

        // failure 1: 5s (base * 2^0 = 5)
        assert_eq!(
            RelayHealthTracker::get_backoff_duration(1, base, max),
            Duration::from_secs(5)
        );
        // failure 2: 10s (base * 2^1 = 10)
        assert_eq!(
            RelayHealthTracker::get_backoff_duration(2, base, max),
            Duration::from_secs(10)
        );
        // failure 3: 20s (base * 2^2 = 20)
        assert_eq!(
            RelayHealthTracker::get_backoff_duration(3, base, max),
            Duration::from_secs(20)
        );
        // failure 4: 40s (base * 2^3 = 40)
        assert_eq!(
            RelayHealthTracker::get_backoff_duration(4, base, max),
            Duration::from_secs(40)
        );
        // failure 5: 80s (base * 2^4 = 80)
        assert_eq!(
            RelayHealthTracker::get_backoff_duration(5, base, max),
            Duration::from_secs(80)
        );
    }

    #[test]
    fn test_backoff_capped_at_max() {
        let base = DEFAULT_BASE_BACKOFF_SECS;
        let max_backoff = 3600u64;
        // After many failures, should cap at max_backoff (1 hour)
        assert_eq!(
            RelayHealthTracker::get_backoff_duration(20, base, max_backoff),
            Duration::from_secs(max_backoff)
        );
    }

    #[test]
    fn test_degraded_state_after_failure() {
        let tracker = RelayHealthTracker::with_defaults();
        let url = "wss://test-relay.example.com";

        tracker.record_failure(url);
        assert_eq!(tracker.get_state(url), HealthState::Degraded);
        assert_eq!(tracker.get_failure_count(url), 1);
    }

    #[test]
    fn test_backoff_blocks_immediate_reconnection() {
        let tracker = RelayHealthTracker::with_defaults();
        let url = "wss://test-relay.example.com";

        tracker.record_failure(url);

        // Immediately after failure, should not attempt (backoff active)
        assert!(!tracker.should_attempt_connection(url));

        // Remaining backoff should be some positive duration
        let remaining = tracker.get_remaining_backoff(url);
        assert!(remaining.is_some());
        assert!(remaining.unwrap() > Duration::ZERO);
    }

    #[test]
    fn test_is_dead() {
        let tracker = RelayHealthTracker::with_defaults();
        let url = "wss://test-relay.example.com";

        // Initially not dead
        assert!(!tracker.is_dead(url));

        // After a failure, still not dead (just degraded)
        tracker.record_failure(url);
        assert!(!tracker.is_dead(url));
        assert_eq!(tracker.get_state(url), HealthState::Degraded);
    }

    #[test]
    fn test_get_tracked_relays() {
        let tracker = RelayHealthTracker::with_defaults();

        tracker.record_success("wss://relay1.example.com");
        tracker.record_failure("wss://relay2.example.com");

        let tracked = tracker.get_tracked_relays();
        assert_eq!(tracked.len(), 2);
        assert!(tracked.contains(&"wss://relay1.example.com".to_string()));
        assert!(tracked.contains(&"wss://relay2.example.com".to_string()));
    }

    #[test]
    fn test_custom_max_backoff() {
        let custom_max = 60u64; // 1 minute max
        let tracker = RelayHealthTracker::with_max_backoff(custom_max);
        let url = "wss://test-relay.example.com";

        // Simulate many failures
        for _ in 0..20 {
            tracker.record_failure(url);
        }

        // The remaining backoff should respect the custom max
        // Note: We can't easily test the internal backoff calculation here,
        // but we can verify the tracker was created with the custom setting
        assert_eq!(tracker.max_backoff_secs, custom_max);
    }

    #[test]
    fn test_get_health_returns_clone() {
        let tracker = RelayHealthTracker::with_defaults();
        let url = "wss://test-relay.example.com";

        tracker.record_success(url);
        let health = tracker.get_health(url);

        assert!(health.is_some());
        let health = health.unwrap();
        assert_eq!(health.state(), HealthState::Healthy);
        assert!(health.last_success_time.is_some());
    }

    #[test]
    fn test_get_health_nonexistent() {
        let tracker = RelayHealthTracker::with_defaults();
        let health = tracker.get_health("wss://nonexistent.example.com");
        assert!(health.is_none());
    }

    #[test]
    fn repeated_rate_limit_notice_does_not_extend_cooldown() {
        let tracker = RelayHealthTracker::with_defaults();
        let relay = "wss://limited.example";

        tracker.record_rate_limit(relay);
        let first_deadline = tracker.get_health(relay).unwrap().next_retry_at;
        tracker.record_rate_limit(relay);

        assert_eq!(
            tracker.get_health(relay).unwrap().next_retry_at,
            first_deadline
        );
    }

    #[test]
    fn rate_limit_notice_after_deadline_starts_new_cooldown() {
        let tracker = RelayHealthTracker::with_defaults();
        let relay = "wss://limited.example";

        tracker.record_rate_limit(relay);
        tracker.health.get_mut(relay).unwrap().next_retry_at =
            Some(Instant::now() - Duration::from_millis(1));

        tracker.record_rate_limit(relay);

        assert!(tracker.get_health(relay).unwrap().is_rate_limited_now());
    }

    #[test]
    fn connection_success_does_not_clear_rate_limit_cooldown() {
        let tracker = RelayHealthTracker::with_defaults();
        let relay = "wss://limited.example";

        tracker.record_rate_limit(relay);
        let deadline = tracker.get_health(relay).unwrap().next_retry_at;
        tracker.record_success(relay);

        let health = tracker.get_health(relay).unwrap();
        assert!(health.is_rate_limited_now());
        assert_eq!(health.next_retry_at, deadline);
        assert!(health.connected);
    }
}
