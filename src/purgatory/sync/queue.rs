//! Sync queue entry for tracking sync state per identifier.

use std::time::{Duration, Instant};

/// Entry in the sync queue tracking when/how to sync an identifier.
///
/// Each identifier in purgatory has at most one `SyncQueueEntry` that tracks:
/// - When the next sync attempt should occur
/// - How many attempts have been made (for backoff calculation)
/// - Whether a sync is currently in progress
#[derive(Debug, Clone)]
pub struct SyncQueueEntry {
    /// Don't attempt sync before this time
    pub next_attempt: Instant,

    /// Number of sync attempts (for backoff calculation).
    /// Reset to 0 when new event arrives for this identifier.
    pub attempt_count: u32,

    /// Whether a sync is currently in progress for this identifier.
    /// Prevents concurrent sync operations for the same identifier.
    pub in_progress: bool,
}

impl SyncQueueEntry {
    /// Create a new sync queue entry with the given initial delay.
    ///
    /// # Arguments
    /// * `delay` - How long to wait before the first sync attempt
    pub fn new(delay: Duration) -> Self {
        Self {
            next_attempt: Instant::now() + delay,
            attempt_count: 0,
            in_progress: false,
        }
    }

    /// Calculate backoff duration based on attempt count.
    ///
    /// Backoff schedule:
    /// - Attempt 1: 20s
    /// - Attempt 2: 40s
    /// - Attempt 3: 80s
    /// - Attempt 4+: 120s (capped at 2 minutes)
    ///
    /// The formula is: min(20s * 2^(attempt_count-1), 120s)
    pub fn backoff(&self) -> Duration {
        if self.attempt_count == 0 {
            return Duration::from_secs(20);
        }

        let base = Duration::from_secs(20);
        let exponent = self.attempt_count.saturating_sub(1).min(3);
        let multiplier = 2u32.saturating_pow(exponent);
        (base * multiplier).min(Duration::from_secs(120))
    }

    /// Check if this entry is ready for a sync attempt.
    ///
    /// Returns true if:
    /// - No sync is currently in progress
    /// - The next_attempt time has passed
    pub fn is_ready(&self) -> bool {
        !self.in_progress && Instant::now() >= self.next_attempt
    }

    /// Called when a new event arrives for this identifier.
    ///
    /// Resets the attempt count to 0 (fresh start) and updates
    /// next_attempt if the new delay would be sooner.
    ///
    /// # Arguments
    /// * `delay` - The delay for the new event
    pub fn on_new_event(&mut self, delay: Duration) {
        self.attempt_count = 0;
        let new_attempt = Instant::now() + delay;
        if new_attempt < self.next_attempt {
            self.next_attempt = new_attempt;
        }
    }

    /// Called when a sync attempt completes (successfully or not).
    ///
    /// Marks the entry as not in progress, increments the attempt count,
    /// and schedules the next attempt based on backoff.
    ///
    /// Only updates timing if the current next_attempt has passed
    /// (prevents double-scheduling if called multiple times).
    pub fn on_sync_complete(&mut self) {
        self.in_progress = false;
        if self.next_attempt <= Instant::now() {
            self.attempt_count += 1;
            self.next_attempt = Instant::now() + self.backoff();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_cap() {
        // Test that backoff follows: 20s → 40s → 80s → 120s → 120s (capped)
        let mut entry = SyncQueueEntry::new(Duration::from_secs(0));

        // Attempt 0 (initial state): 20s
        assert_eq!(entry.backoff(), Duration::from_secs(20));

        // Simulate completing attempts and check backoff
        entry.attempt_count = 1;
        assert_eq!(entry.backoff(), Duration::from_secs(20)); // 20 * 2^0 = 20

        entry.attempt_count = 2;
        assert_eq!(entry.backoff(), Duration::from_secs(40)); // 20 * 2^1 = 40

        entry.attempt_count = 3;
        assert_eq!(entry.backoff(), Duration::from_secs(80)); // 20 * 2^2 = 80

        entry.attempt_count = 4;
        assert_eq!(entry.backoff(), Duration::from_secs(120)); // 20 * 2^3 = 160, capped to 120

        entry.attempt_count = 5;
        assert_eq!(entry.backoff(), Duration::from_secs(120)); // Still capped

        entry.attempt_count = 100;
        assert_eq!(entry.backoff(), Duration::from_secs(120)); // Always capped
    }

    #[test]
    fn new_event_resets_attempt_count() {
        let mut entry = SyncQueueEntry::new(Duration::from_secs(60));

        // Simulate several sync attempts
        entry.attempt_count = 5;
        entry.next_attempt = Instant::now() + Duration::from_secs(120);

        // Capture the call bounds instead of assuming the scheduler runs promptly.
        let original_next = entry.next_attempt;
        let before = Instant::now();
        entry.on_new_event(Duration::from_secs(10));
        let after = Instant::now();

        // Attempt count should be reset
        assert_eq!(entry.attempt_count, 0);

        assert!(entry.next_attempt >= original_next.min(before + Duration::from_secs(10)));
        assert!(entry.next_attempt <= original_next.min(after + Duration::from_secs(10)));
    }

    #[test]
    fn new_event_does_not_delay_if_already_sooner() {
        let mut entry = SyncQueueEntry::new(Duration::from_secs(5));
        let original_next = entry.next_attempt;

        // New event arrives with longer delay - should not push back
        entry.on_new_event(Duration::from_secs(60));

        // Attempt count should still be reset
        assert_eq!(entry.attempt_count, 0);

        // But next_attempt should not be pushed back
        assert_eq!(entry.next_attempt, original_next);
    }

    #[test]
    fn is_ready_checks_both_conditions() {
        let mut entry = SyncQueueEntry::new(Duration::from_secs(0));

        // A zero delay is already ready; monotonic time cannot move backward.
        assert!(entry.is_ready());

        // Mark as in progress - should not be ready
        entry.in_progress = true;
        assert!(!entry.is_ready());

        // Not in progress but future next_attempt - should not be ready
        entry.in_progress = false;
        entry.next_attempt = Instant::now() + Duration::from_secs(60);
        assert!(!entry.is_ready());
    }

    #[test]
    fn on_sync_complete_increments_and_schedules() {
        let mut entry = SyncQueueEntry::new(Duration::from_secs(0));

        entry.in_progress = true;
        entry.attempt_count = 0;

        let before = Instant::now();
        entry.on_sync_complete();
        let after = Instant::now();

        // Should no longer be in progress
        assert!(!entry.in_progress);

        // Attempt count should be incremented
        assert_eq!(entry.attempt_count, 1);

        // Next attempt should be scheduled with backoff (20s for attempt 1)
        assert!(entry.next_attempt >= before + Duration::from_secs(20));
        assert!(entry.next_attempt <= after + Duration::from_secs(20));
    }
}
