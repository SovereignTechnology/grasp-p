//! Missing-Event Recovery for Incomplete Historic Sync Batches
//!
//! NIP-77 negentropy reconciliation identifies event IDs a relay holds that
//! are missing locally. Those IDs are fetched with exact-ID REQs, but relays
//! can return only a subset (result limits, truncation) or nothing at all.
//! When the batch also lacks repository/root-event metadata, no semantic
//! REQ+EOSE fallback can be constructed and the batch is finalized with
//! partial results.
//!
//! This module keeps the still-missing IDs represented after such a batch is
//! finalized, so the sync maintenance timer can retry them with bounded,
//! exponentially backed-off exact-ID fetches. It is a per-relay bookkeeping
//! structure only: all network work is driven by `SyncManager`.
//!
//! ## Policy
//!
//! - Attempts are scheduled per relay with exponential backoff
//!   (30s base doubling up to 15min in production; sub-second in `NGIT_TEST`).
//! - Any progress (at least one ID recovered) resets the backoff; the pending
//!   set shrinks monotonically, so this cannot loop forever.
//! - After [`MAX_ATTEMPTS_WITHOUT_PROGRESS`] consecutive attempts with zero
//!   progress the relay's pending IDs are expired: they are dropped with an
//!   explicit warning and the relay remains in
//!   `ConnectedHistoricSyncFailures` until the next daily sync re-discovers
//!   the gap. Nothing is persisted across restarts - a restart re-runs
//!   historic sync from scratch, which re-detects any still-missing events.
//! - Recovery state never blocks startup: batches still finalize (as failed)
//!   and the relay serves traffic while attempts continue in the background.
//! - A relay whose pending set empties through actual recovery can be
//!   promoted back to `Connected`, unless an unrelated batch failure was
//!   observed for that relay (the entry is then marked as unable to restore
//!   health, so the degraded status stays visible).

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use nostr_sdk::prelude::EventId;

/// Maximum IDs fetched per recovery attempt, matching the exact-ID chunk size
/// used by historic sync. Larger pending sets recover across several attempts.
pub const MAX_RECOVERY_IDS_PER_ATTEMPT: usize = 300;

/// Consecutive zero-progress attempts before a relay's pending IDs expire.
pub const MAX_ATTEMPTS_WITHOUT_PROGRESS: u32 = 12;

/// Cap on remembered source batch IDs (for logging only).
const MAX_TRACKED_SOURCE_BATCHES: usize = 16;

fn in_test_mode() -> bool {
    std::env::var("NGIT_TEST").as_deref() == Ok("1")
}

fn base_backoff() -> Duration {
    if in_test_mode() {
        Duration::from_millis(500)
    } else {
        Duration::from_secs(30)
    }
}

fn max_backoff() -> Duration {
    if in_test_mode() {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(15 * 60)
    }
}

fn backoff_for(attempts_without_progress: u32) -> Duration {
    let base = base_backoff();
    let doubled = base.saturating_mul(1u32 << attempts_without_progress.min(16));
    doubled.min(max_backoff())
}

/// Pending recovery work for one relay.
#[derive(Debug)]
struct RelayRecoveryState {
    /// Event IDs the relay reported but has not yet delivered.
    missing: HashSet<EventId>,
    /// Consecutive attempts that recovered nothing. Reset on progress.
    attempts_without_progress: u32,
    /// Total attempts issued, for logging.
    total_attempts: u32,
    /// Earliest time the next attempt may run.
    next_attempt_at: Instant,
    /// One recovery fetch in flight per relay at a time.
    in_flight: bool,
    /// False when an unrelated batch failure means full recovery of the
    /// pending IDs would not make the relay's historic sync complete.
    can_restore_health: bool,
    /// Batch IDs that contributed missing IDs, for logging (bounded).
    source_batches: Vec<u64>,
    /// Total IDs recovered so far, for logging.
    total_recovered: usize,
}

/// Result of registering missing IDs for a relay.
#[derive(Debug, PartialEq, Eq)]
pub struct RegisterOutcome {
    /// IDs that were not already pending.
    pub newly_added: usize,
    /// Total pending IDs for the relay after registration.
    pub pending_total: usize,
}

/// A recovery fetch reserved by [`MissingEventRecoveryIndex::begin_attempt`].
#[derive(Debug)]
pub struct RecoveryAttempt {
    /// IDs to fetch in this attempt (bounded).
    pub ids: Vec<EventId>,
    /// 1-based attempt number for the relay, for logging.
    pub attempt_number: u32,
}

/// Outcome of completing a recovery attempt or a local-satisfaction check.
#[derive(Debug, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Every pending ID for the relay has been recovered.
    FullyRecovered {
        recovered: usize,
        total_recovered: usize,
        can_restore_health: bool,
    },
    /// Some IDs were recovered; the rest are rescheduled.
    PartiallyRecovered {
        recovered: usize,
        remaining: usize,
        next_attempt_in: Duration,
    },
    /// Nothing was recovered; the next attempt is scheduled with backoff.
    RetryScheduled {
        attempt: u32,
        remaining: usize,
        next_attempt_in: Duration,
    },
    /// The zero-progress attempt budget is exhausted; pending IDs dropped.
    Expired { remaining: usize, attempts: u32 },
}

/// Per-relay index of events that historic sync failed to fetch.
#[derive(Debug, Default)]
pub struct MissingEventRecoveryIndex {
    relays: HashMap<String, RelayRecoveryState>,
}

impl MissingEventRecoveryIndex {
    /// Record IDs a finalized batch failed to fetch from `relay_url`.
    ///
    /// Duplicate registrations merge into the existing pending set, so
    /// repeated incomplete responses cannot create duplicate work.
    /// `relay_already_degraded` poisons health restoration when the relay had
    /// unrelated historic-sync failures before this entry existed.
    pub fn register(
        &mut self,
        relay_url: &str,
        batch_id: u64,
        ids: impl IntoIterator<Item = EventId>,
        relay_already_degraded: bool,
        now: Instant,
    ) -> RegisterOutcome {
        let entry =
            self.relays
                .entry(relay_url.to_string())
                .or_insert_with(|| RelayRecoveryState {
                    missing: HashSet::new(),
                    attempts_without_progress: 0,
                    total_attempts: 0,
                    next_attempt_at: now + base_backoff(),
                    in_flight: false,
                    can_restore_health: !relay_already_degraded,
                    source_batches: Vec::new(),
                    total_recovered: 0,
                });

        if relay_already_degraded {
            entry.can_restore_health = false;
        }
        if entry.source_batches.len() < MAX_TRACKED_SOURCE_BATCHES
            && !entry.source_batches.contains(&batch_id)
        {
            entry.source_batches.push(batch_id);
        }

        let before = entry.missing.len();
        entry.missing.extend(ids);
        RegisterOutcome {
            newly_added: entry.missing.len() - before,
            pending_total: entry.missing.len(),
        }
    }

    /// Note a failed batch confirmation for `relay_url`.
    ///
    /// If the batch did not contribute this relay's pending IDs, the failure
    /// is unrelated, so recovering every pending ID must not promote the
    /// relay back to a healthy status.
    pub fn note_failed_batch(&mut self, relay_url: &str, batch_id: u64) {
        if let Some(entry) = self.relays.get_mut(relay_url) {
            if !entry.source_batches.contains(&batch_id) {
                entry.can_restore_health = false;
            }
        }
    }

    /// Relays with pending IDs and no attempt currently in flight.
    pub fn idle_relays(&self) -> Vec<String> {
        self.relays
            .iter()
            .filter(|(_, entry)| !entry.in_flight)
            .map(|(relay, _)| relay.clone())
            .collect()
    }

    /// Pending IDs for a relay, if any attempt is not in flight.
    pub fn pending_ids(&self, relay_url: &str) -> Option<Vec<EventId>> {
        let entry = self.relays.get(relay_url)?;
        if entry.in_flight {
            return None;
        }
        Some(entry.missing.iter().copied().collect())
    }

    /// Remove IDs that were satisfied outside recovery (live sync, user
    /// submission). Not counted as an attempt. Returns `FullyRecovered` when
    /// the pending set empties.
    pub fn clear_satisfied(
        &mut self,
        relay_url: &str,
        satisfied: &[EventId],
    ) -> Option<AttemptOutcome> {
        let entry = self.relays.get_mut(relay_url)?;
        let before = entry.missing.len();
        for id in satisfied {
            entry.missing.remove(id);
        }
        let recovered = before - entry.missing.len();
        entry.total_recovered += recovered;
        if recovered > 0 {
            entry.attempts_without_progress = 0;
        }
        if entry.missing.is_empty() {
            let entry = self
                .relays
                .remove(relay_url)
                .expect("entry present just above");
            return Some(AttemptOutcome::FullyRecovered {
                recovered,
                total_recovered: entry.total_recovered,
                can_restore_health: entry.can_restore_health,
            });
        }
        None
    }

    /// Reserve a recovery fetch for a relay whose backoff deadline passed.
    pub fn begin_attempt(&mut self, relay_url: &str, now: Instant) -> Option<RecoveryAttempt> {
        let entry = self.relays.get_mut(relay_url)?;
        if entry.in_flight || entry.missing.is_empty() || now < entry.next_attempt_at {
            return None;
        }
        entry.in_flight = true;
        entry.total_attempts += 1;
        Some(RecoveryAttempt {
            ids: entry
                .missing
                .iter()
                .take(MAX_RECOVERY_IDS_PER_ATTEMPT)
                .copied()
                .collect(),
            attempt_number: entry.total_attempts,
        })
    }

    /// Push the next attempt out without consuming attempt budget. Used when
    /// the relay has no live connection, so a disconnected relay can neither
    /// expire its pending IDs nor spin in a tight loop.
    pub fn defer_attempt(&mut self, relay_url: &str, now: Instant) {
        if let Some(entry) = self.relays.get_mut(relay_url) {
            if !entry.in_flight {
                entry.next_attempt_at = now + base_backoff();
            }
        }
    }

    /// Complete a reserved attempt: clear only the recovered IDs, then either
    /// finish, reschedule with backoff, or expire by policy.
    ///
    /// Returns `None` when the relay's entry disappeared while the attempt was
    /// in flight (daily sync reset or intentional relay removal).
    pub fn complete_attempt(
        &mut self,
        relay_url: &str,
        recovered: &HashSet<EventId>,
        now: Instant,
    ) -> Option<AttemptOutcome> {
        let entry = self.relays.get_mut(relay_url)?;
        entry.in_flight = false;

        let before = entry.missing.len();
        entry.missing.retain(|id| !recovered.contains(id));
        let recovered_count = before - entry.missing.len();
        entry.total_recovered += recovered_count;

        if entry.missing.is_empty() {
            let entry = self
                .relays
                .remove(relay_url)
                .expect("entry present just above");
            return Some(AttemptOutcome::FullyRecovered {
                recovered: recovered_count,
                total_recovered: entry.total_recovered,
                can_restore_health: entry.can_restore_health,
            });
        }

        if recovered_count > 0 {
            entry.attempts_without_progress = 0;
            let delay = backoff_for(0);
            entry.next_attempt_at = now + delay;
            return Some(AttemptOutcome::PartiallyRecovered {
                recovered: recovered_count,
                remaining: entry.missing.len(),
                next_attempt_in: delay,
            });
        }

        entry.attempts_without_progress += 1;
        if entry.attempts_without_progress >= MAX_ATTEMPTS_WITHOUT_PROGRESS {
            let entry = self
                .relays
                .remove(relay_url)
                .expect("entry present just above");
            return Some(AttemptOutcome::Expired {
                remaining: entry.missing.len(),
                attempts: entry.total_attempts,
            });
        }
        let delay = backoff_for(entry.attempts_without_progress);
        entry.next_attempt_at = now + delay;
        Some(AttemptOutcome::RetryScheduled {
            attempt: entry.total_attempts,
            remaining: entry.missing.len(),
            next_attempt_in: delay,
        })
    }

    /// Drop all pending IDs for a relay (daily sync reset or relay removal).
    /// Returns the number of IDs dropped.
    pub fn clear_relay(&mut self, relay_url: &str) -> usize {
        self.relays
            .remove(relay_url)
            .map(|entry| entry.missing.len())
            .unwrap_or(0)
    }

    /// Batch IDs that contributed a relay's pending IDs, for logging.
    pub fn source_batches(&self, relay_url: &str) -> Vec<u64> {
        self.relays
            .get(relay_url)
            .map(|entry| entry.source_batches.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> EventId {
        EventId::from_slice(&[byte; 32]).expect("valid event id")
    }

    fn registered(index: &mut MissingEventRecoveryIndex, ids: &[EventId]) -> Instant {
        let now = Instant::now();
        index.register("ws://relay", 1, ids.iter().copied(), false, now);
        now
    }

    fn due(now: Instant) -> Instant {
        now + Duration::from_secs(24 * 3600)
    }

    #[test]
    fn duplicate_registrations_do_not_duplicate_pending_work() {
        let mut index = MissingEventRecoveryIndex::default();
        let now = registered(&mut index, &[id(1), id(2)]);
        let outcome = index.register("ws://relay", 2, [id(2), id(3)], false, now);
        assert_eq!(
            outcome,
            RegisterOutcome {
                newly_added: 1,
                pending_total: 3,
            }
        );
        assert_eq!(index.pending_ids("ws://relay").unwrap().len(), 3);
    }

    #[test]
    fn attempts_wait_for_backoff_deadline_and_single_flight() {
        let mut index = MissingEventRecoveryIndex::default();
        let now = registered(&mut index, &[id(1)]);

        assert!(
            index.begin_attempt("ws://relay", now).is_none(),
            "attempt before the backoff deadline must not run"
        );
        let attempt = index
            .begin_attempt("ws://relay", due(now))
            .expect("due attempt");
        assert_eq!(attempt.ids, vec![id(1)]);
        assert_eq!(attempt.attempt_number, 1);
        assert!(
            index.begin_attempt("ws://relay", due(now)).is_none(),
            "only one attempt may be in flight per relay"
        );
        assert!(
            index.pending_ids("ws://relay").is_none(),
            "in-flight relays are skipped by local-satisfaction checks"
        );
    }

    #[test]
    fn successful_attempt_clears_only_recovered_ids_and_resets_backoff() {
        let mut index = MissingEventRecoveryIndex::default();
        let now = registered(&mut index, &[id(1), id(2), id(3)]);

        // Two failed attempts grow the backoff.
        for _ in 0..2 {
            index.begin_attempt("ws://relay", due(now)).unwrap();
            index
                .complete_attempt("ws://relay", &HashSet::new(), now)
                .unwrap();
        }

        index.begin_attempt("ws://relay", due(now)).unwrap();
        let outcome = index
            .complete_attempt("ws://relay", &HashSet::from([id(2)]), now)
            .unwrap();
        assert_eq!(
            outcome,
            AttemptOutcome::PartiallyRecovered {
                recovered: 1,
                remaining: 2,
                next_attempt_in: backoff_for(0),
            },
            "progress must clear only the recovered ID and reset the backoff"
        );
        let mut remaining = index.pending_ids("ws://relay").unwrap();
        remaining.sort();
        assert_eq!(remaining, vec![id(1), id(3)]);
    }

    #[test]
    fn zero_progress_attempts_back_off_exponentially_with_a_cap() {
        assert!(backoff_for(1) > backoff_for(0));
        assert!(backoff_for(2) > backoff_for(1));
        assert_eq!(backoff_for(30), max_backoff());
    }

    #[test]
    fn zero_progress_budget_expires_pending_ids_explicitly() {
        let mut index = MissingEventRecoveryIndex::default();
        let now = registered(&mut index, &[id(1), id(2)]);

        for attempt in 1..MAX_ATTEMPTS_WITHOUT_PROGRESS {
            index.begin_attempt("ws://relay", due(now)).unwrap();
            let outcome = index
                .complete_attempt("ws://relay", &HashSet::new(), now)
                .unwrap();
            assert!(
                matches!(outcome, AttemptOutcome::RetryScheduled { .. }),
                "attempt {attempt} should reschedule, got {outcome:?}"
            );
        }

        index.begin_attempt("ws://relay", due(now)).unwrap();
        let outcome = index
            .complete_attempt("ws://relay", &HashSet::new(), now)
            .unwrap();
        assert_eq!(
            outcome,
            AttemptOutcome::Expired {
                remaining: 2,
                attempts: MAX_ATTEMPTS_WITHOUT_PROGRESS,
            }
        );
        assert!(
            index.pending_ids("ws://relay").is_none(),
            "expired relays carry no pending work"
        );
    }

    #[test]
    fn full_recovery_reports_whether_health_can_be_restored() {
        let mut index = MissingEventRecoveryIndex::default();
        let now = registered(&mut index, &[id(1)]);
        index.begin_attempt("ws://relay", due(now)).unwrap();
        let outcome = index
            .complete_attempt("ws://relay", &HashSet::from([id(1)]), now)
            .unwrap();
        assert_eq!(
            outcome,
            AttemptOutcome::FullyRecovered {
                recovered: 1,
                total_recovered: 1,
                can_restore_health: true,
            }
        );
    }

    #[test]
    fn unrelated_failures_poison_health_restoration() {
        let mut index = MissingEventRecoveryIndex::default();
        let now = registered(&mut index, &[id(1)]);

        // Batch 1 registered the IDs; its own failed confirmation is related.
        index.note_failed_batch("ws://relay", 1);
        // Batch 7 never registered recovery work: unrelated failure.
        index.note_failed_batch("ws://relay", 7);

        index.begin_attempt("ws://relay", due(now)).unwrap();
        let outcome = index
            .complete_attempt("ws://relay", &HashSet::from([id(1)]), now)
            .unwrap();
        assert_eq!(
            outcome,
            AttemptOutcome::FullyRecovered {
                recovered: 1,
                total_recovered: 1,
                can_restore_health: false,
            }
        );
    }

    #[test]
    fn registration_on_an_already_degraded_relay_poisons_health_restoration() {
        let mut index = MissingEventRecoveryIndex::default();
        let now = Instant::now();
        index.register("ws://relay", 1, [id(1)], true, now);
        index.begin_attempt("ws://relay", due(now)).unwrap();
        let outcome = index
            .complete_attempt("ws://relay", &HashSet::from([id(1)]), now)
            .unwrap();
        assert!(matches!(
            outcome,
            AttemptOutcome::FullyRecovered {
                can_restore_health: false,
                ..
            }
        ));
    }

    #[test]
    fn locally_satisfied_ids_clear_promptly_without_consuming_attempts() {
        let mut index = MissingEventRecoveryIndex::default();
        registered(&mut index, &[id(1), id(2)]);

        assert_eq!(index.clear_satisfied("ws://relay", &[id(1)]), None);
        assert_eq!(index.pending_ids("ws://relay").unwrap(), vec![id(2)]);

        let outcome = index.clear_satisfied("ws://relay", &[id(2)]).unwrap();
        assert!(matches!(outcome, AttemptOutcome::FullyRecovered { .. }));
    }

    #[test]
    fn completing_an_attempt_after_relay_reset_is_a_no_op() {
        let mut index = MissingEventRecoveryIndex::default();
        let now = registered(&mut index, &[id(1)]);
        index.begin_attempt("ws://relay", due(now)).unwrap();
        assert_eq!(index.clear_relay("ws://relay"), 1);
        assert!(index
            .complete_attempt("ws://relay", &HashSet::new(), now)
            .is_none());
    }

    #[test]
    fn deferred_attempts_do_not_consume_the_zero_progress_budget() {
        let mut index = MissingEventRecoveryIndex::default();
        let now = registered(&mut index, &[id(1)]);
        index.defer_attempt("ws://relay", due(now));
        assert!(
            index.begin_attempt("ws://relay", due(now)).is_none(),
            "deferral must push the next attempt out"
        );
        let attempt = index
            .begin_attempt("ws://relay", due(due(now)))
            .expect("attempt after deferral window");
        assert_eq!(
            attempt.attempt_number, 1,
            "deferrals are not counted as attempts"
        );
    }
}
