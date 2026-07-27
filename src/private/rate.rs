//! GRASP-P rate limiting: in-memory keyed token buckets.
//!
//! One bucket per key (write pubkey for client writes, `(tenant, alias)` for
//! registration replacements), refilled at a fixed rate. All state is
//! node-local and in-memory only — a restart resets every bucket.
//!
//! Memory bound: at most [`MAX_TRACKED_KEYS`] keys are tracked. Idle entries
//! (no activity for [`IDLE_ENTRY_TTL`]) are reclaimed by a periodic sweep,
//! and an insert into a full map first force-sweeps, then evicts the
//! stalest entry — key-churn therefore cannot exhaust memory (worst case
//! ~65k × (key bytes + bucket) ≈ a few MiB) and an attacker cycling fresh
//! keys only ever displaces OTHER attackers' stale entries, never raises the
//! process footprint.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Hard bound on tracked keys per limiter instance.
const MAX_TRACKED_KEYS: usize = 65_536;

/// Entries with no activity for this long are reclaimed by the sweep.
const IDLE_ENTRY_TTL: Duration = Duration::from_secs(3600);

/// Minimum wall time between amortized full sweeps.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_seen: Instant,
}

/// Keyed token bucket. `capacity == 0` disables the limiter entirely:
/// [`Self::try_take`] always succeeds and no state is tracked.
#[derive(Debug)]
pub struct KeyedTokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    buckets: HashMap<String, Bucket>,
    last_sweep: Instant,
}

impl KeyedTokenBucket {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: capacity as f64,
            refill_per_sec,
            buckets: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    /// Is the limiter active (capacity > 0)?
    pub fn is_enabled(&self) -> bool {
        self.capacity > 0.0
    }

    /// Try to spend `cost` tokens for `key`. True when the spend succeeded
    /// (or the limiter is disabled); false when the bucket is empty.
    pub fn try_take(&mut self, key: &str, cost: u32) -> bool {
        self.try_take_at(key, cost, Instant::now())
    }

    /// Wall-clock seconds until `cost` tokens have refilled from empty —
    /// the `Retry-After` hint for HTTP rejections.
    pub fn retry_after_secs(&self, cost: u32) -> u64 {
        if self.refill_per_sec <= 0.0 {
            return 60;
        }
        (cost as f64 / self.refill_per_sec).ceil().max(1.0) as u64
    }

    fn try_take_at(&mut self, key: &str, cost: u32, now: Instant) -> bool {
        if !self.is_enabled() {
            return true;
        }
        if now.duration_since(self.last_sweep) >= SWEEP_INTERVAL {
            self.sweep(now);
        }
        if !self.buckets.contains_key(key) {
            self.evict_for_insert(now);
            self.buckets.insert(
                key.to_string(),
                Bucket {
                    tokens: self.capacity,
                    last_seen: now,
                },
            );
        }
        let bucket = self.buckets.get_mut(key).expect("bucket exists");
        let elapsed = now.duration_since(bucket.last_seen).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last_seen = now;
        let cost = cost as f64;
        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            true
        } else {
            false
        }
    }

    fn sweep(&mut self, now: Instant) {
        self.last_sweep = now;
        self.buckets
            .retain(|_, b| now.duration_since(b.last_seen) < IDLE_ENTRY_TTL);
    }

    /// Make room for one insert when the map is at the bound: force an idle
    /// sweep, then evict the stalest entry if still full (a fresh key must
    /// never be turned away — that would hand an attacker a free DoS on
    /// legitimate keys by churning the map full).
    fn evict_for_insert(&mut self, now: Instant) {
        if self.buckets.len() < MAX_TRACKED_KEYS {
            return;
        }
        self.sweep(now);
        if self.buckets.len() >= MAX_TRACKED_KEYS {
            if let Some(stalest) = self
                .buckets
                .iter()
                .max_by_key(|(_, b)| now.duration_since(b.last_seen))
                .map(|(k, _)| k.clone())
            {
                self.buckets.remove(&stalest);
            }
        }
    }

    #[cfg(test)]
    fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(limit: &mut KeyedTokenBucket, key: &str, secs: u64) -> bool {
        let now = Instant::now() + Duration::from_secs(secs);
        limit.try_take_at(key, 1, now)
    }

    #[test]
    fn disabled_at_zero_capacity() {
        let mut limit = KeyedTokenBucket::new(0, 0.0);
        assert!(!limit.is_enabled());
        for _ in 0..1000 {
            assert!(limit.try_take("anything", 1));
        }
        assert_eq!(limit.tracked_keys(), 0, "disabled tracks no state");
    }

    #[test]
    fn capacity_bounds_burst_then_refills() {
        let mut limit = KeyedTokenBucket::new(3, 1.0); // 1 token/sec
        assert!(at(&mut limit, "k", 0));
        assert!(at(&mut limit, "k", 0));
        assert!(at(&mut limit, "k", 0));
        assert!(!at(&mut limit, "k", 0), "fourth spend must fail");
        // Other keys are independent.
        assert!(at(&mut limit, "other", 0));
        // After 2s: exactly 2 tokens refilled.
        assert!(at(&mut limit, "k", 2));
        assert!(at(&mut limit, "k", 2));
        assert!(!at(&mut limit, "k", 2));
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let mut limit = KeyedTokenBucket::new(2, 1000.0);
        // A long idle gap refills to capacity, not beyond.
        assert!(at(&mut limit, "k", 0));
        assert!(at(&mut limit, "k", 3600));
        assert!(at(&mut limit, "k", 3600));
        assert!(!at(&mut limit, "k", 3600));
    }

    #[test]
    fn idle_entries_are_swept() {
        let mut limit = KeyedTokenBucket::new(1, 1.0);
        let t0 = Instant::now();
        assert!(limit.try_take_at("old", 1, t0));
        // Force a sweep after the idle TTL: the stale entry is reclaimed.
        let t1 = t0 + IDLE_ENTRY_TTL + SWEEP_INTERVAL + Duration::from_secs(1);
        assert!(limit.try_take_at("new", 1, t1));
        assert_eq!(limit.tracked_keys(), 1, "idle entry must be swept");
    }

    #[test]
    fn map_bound_evicts_stalest_not_newest() {
        let mut limit = KeyedTokenBucket::new(1, 0.0);
        let t0 = Instant::now();
        // Fill the map to the bound with distinct keys.
        for i in 0..MAX_TRACKED_KEYS {
            assert!(limit.try_take_at(&format!("flood-{i}"), 1, t0));
        }
        assert_eq!(limit.tracked_keys(), MAX_TRACKED_KEYS);
        // A fresh key at the bound: admitted (stalest flood entry evicted),
        // and its tokens are intact (denial here would be a churn DoS).
        assert!(limit.try_take_at("legit", 1, t0 + Duration::from_secs(1)));
        assert!(limit.tracked_keys() <= MAX_TRACKED_KEYS);
    }

    #[test]
    fn retry_after_hint_scales_with_refill() {
        let limit = KeyedTokenBucket::new(60, 1.0); // 1 token/sec
        assert_eq!(limit.retry_after_secs(1), 1);
        let slow = KeyedTokenBucket::new(60, 1.0 / 60.0); // 1 token/min
        assert_eq!(slow.retry_after_secs(1), 60);
        let stopped = KeyedTokenBucket::new(60, 0.0);
        assert_eq!(stopped.retry_after_secs(1), 60, "fallback hint");
    }
}
