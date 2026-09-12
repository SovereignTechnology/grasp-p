//! Persistence utilities for purgatory state.
//!
//! This module provides conversion functions between `Instant` (which cannot be
//! serialized) and `Duration` offsets from a reference `SystemTime`. This allows
//! purgatory state to be persisted to disk and restored across restarts.
//!
//! ## Time Handling
//!
//! - `Instant` is monotonic but cannot be serialized
//! - `SystemTime` can be serialized but may go backwards (NTP, user changes)
//! - We use `SystemTime` for persistence and convert to/from `Instant` at runtime
//! - Downtime is accounted for when restoring state (elapsed time is preserved)

use std::time::{Duration, Instant, SystemTime};

/// Convert an `Instant` to a `Duration` offset from a reference `SystemTime`.
///
/// This allows storing an `Instant` as a serializable offset that can be
/// restored later, accounting for system downtime.
///
/// # Arguments
/// * `instant` - The `Instant` to convert
/// * `reference_time` - The reference `SystemTime` (typically SystemTime::now())
/// * `reference_instant` - The corresponding `Instant` (typically Instant::now())
///
/// # Returns
/// Duration offset from the reference time
///
/// # Example
/// ```
/// use std::time::{Duration, Instant, SystemTime};
/// use ngit_grasp::purgatory::persistence::instant_to_offset;
///
/// let now_system = SystemTime::now();
/// let now_instant = Instant::now();
/// let future = now_instant + Duration::from_secs(60);
///
/// let offset = instant_to_offset(future, now_system, now_instant);
/// assert!(offset.as_secs() >= 60);
/// ```
pub fn instant_to_offset(
    instant: Instant,
    _reference_time: SystemTime,
    reference_instant: Instant,
) -> Duration {
    if instant >= reference_instant {
        // Future instant - return positive offset
        instant.duration_since(reference_instant)
    } else {
        // Past instant - this shouldn't happen in normal operation,
        // but we handle it by returning zero duration
        Duration::ZERO
    }
}

/// Convert a `Duration` offset back to an `Instant`, accounting for downtime.
///
/// This restores an `Instant` from a serialized offset, adjusting for the time
/// that has elapsed since the state was saved.
///
/// # Arguments
/// * `offset` - The duration offset from the saved reference time
/// * `saved_at` - The `SystemTime` when the state was saved
/// * `reference_instant` - The current `Instant` (typically Instant::now())
///
/// # Returns
/// The restored `Instant`, adjusted for downtime
///
/// # Example
/// ```
/// use std::time::{Duration, Instant, SystemTime};
/// use ngit_grasp::purgatory::persistence::offset_to_instant;
///
/// let saved_at = SystemTime::now();
/// let offset = Duration::from_secs(60);
/// let now_instant = Instant::now();
///
/// let restored = offset_to_instant(offset, saved_at, now_instant);
/// // restored will be approximately now_instant + 60 seconds
/// ```
pub fn offset_to_instant(
    offset: Duration,
    saved_at: SystemTime,
    reference_instant: Instant,
) -> Instant {
    // Calculate how much time has elapsed since the state was saved
    let now_system = SystemTime::now();
    let elapsed_since_save = now_system
        .duration_since(saved_at)
        .unwrap_or(Duration::ZERO);

    // The original deadline was: saved_at + offset
    // Time remaining = (saved_at + offset) - now_system
    //                = offset - elapsed_since_save

    if offset > elapsed_since_save {
        // Deadline is still in the future
        let remaining = offset - elapsed_since_save;
        reference_instant + remaining
    } else {
        // Deadline has already passed or is right now
        reference_instant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_instant_to_offset_future() {
        let now_system = SystemTime::now();
        let now_instant = Instant::now();
        let future = now_instant + Duration::from_secs(60);

        let offset = instant_to_offset(future, now_system, now_instant);

        assert_eq!(offset, Duration::from_secs(60));
    }

    #[test]
    fn test_instant_to_offset_past() {
        let now_system = SystemTime::now();
        let now_instant = Instant::now();
        let past_instant = now_instant - Duration::from_secs(10);

        let offset = instant_to_offset(past_instant, now_system, now_instant);

        // Past instants return zero duration
        assert_eq!(offset, Duration::ZERO);
    }

    #[test]
    fn test_offset_to_instant_with_time_remaining() {
        let saved_at = SystemTime::now() - Duration::from_secs(10);
        let offset = Duration::from_secs(60);
        assert_restored_within_call_bounds(offset, saved_at, Instant::now());
    }

    #[test]
    fn test_offset_to_instant_deadline_passed() {
        // Simulate state saved 70 seconds ago with 60 second offset
        let saved_at = SystemTime::now() - Duration::from_secs(70);
        let offset = Duration::from_secs(60);

        let now_instant = Instant::now();
        let restored = offset_to_instant(offset, saved_at, now_instant);

        // Deadline has passed, should be now or in the past
        let remaining = restored.saturating_duration_since(now_instant);
        assert_eq!(remaining, Duration::ZERO);
    }

    #[test]
    fn test_round_trip_conversion() {
        let now_system = SystemTime::now();
        let now_instant = Instant::now();
        let future = now_instant + Duration::from_secs(120);

        // Convert to offset
        let offset = instant_to_offset(future, now_system, now_instant);

        assert_restored_within_call_bounds(offset, now_system, now_instant);
    }

    // The conversion reads SystemTime internally. Bound that read with actual
    // observations instead of assuming a maximum scheduling delay.
    fn assert_restored_within_call_bounds(
        offset: Duration,
        saved_at: SystemTime,
        reference: Instant,
    ) {
        let before = SystemTime::now();
        let restored = offset_to_instant(offset, saved_at, reference);
        let after = SystemTime::now();
        let remaining_at = |now: SystemTime| {
            offset.saturating_sub(now.duration_since(saved_at).unwrap_or(Duration::ZERO))
        };
        assert!(restored >= reference + remaining_at(after));
        assert!(restored <= reference + remaining_at(before));
    }
}
