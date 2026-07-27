//! GRASP-P Phase 2 sync-side indexes.
//!
//! Two small additive structures, both inert unless
//! `NGIT_PRIVATE_REPOS_ENABLE=true`:
//!
//! - [`PrivateSyncIndex`]: alias → {w+aux keys, relay URLs, server URLs},
//!   rebuilt from the relay DB's accepted kind-30640 registrations. Parallel
//!   to `RepoSyncIndex`; drives the derived 30641/1059 sync filters. The
//!   private peer-relay set is NOT derived from it — outbound sync peers
//!   come only from the operator allowlist
//!   ([`configured_peer_relay_urls`]).
//! - [`PrivateRejectedIndex`]: a dedicated hot cache for 30641/1059 events
//!   rejected because their authorizing 30640 has not arrived yet
//!   (out-of-order sync). Keyed by target alias (30641) and outer author
//!   pubkey (1059) — gift wraps have an ephemeral pubkey and no `d` tag, so
//!   the existing (pubkey, d-tag) `RejectedEventsIndex` keying cannot apply.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Event, EventId};

/// One registration's sync-relevant fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivateRepoEntry {
    /// Registered w + aux key pubkeys (lowercase hex).
    pub keys: Vec<String>,
    /// `relays` tag values from the registration. ADVISORY METADATA ONLY —
    /// tenant-supplied, so it must never drive outbound connections (SSRF /
    /// membership-map-leak vector); peers come from the operator allowlist
    /// via [`configured_peer_relay_urls`].
    pub relay_urls: Vec<String>,
    /// `server` tag values from the registration.
    pub server_urls: Vec<String>,
}

/// Diff produced when the index is rebuilt from the DB.
#[derive(Debug, Default)]
pub struct PrivateIndexDiff {
    /// True when anything (aliases, keys, relays, servers) changed.
    pub changed: bool,
    /// Aliases present now that were absent before.
    pub added_aliases: Vec<String>,
    /// Keys present now that were absent before (across all aliases).
    pub added_keys: Vec<String>,
}

/// alias → registration sync needs. Rebuilt wholesale from the relay DB's
/// kind-30640 events (which only contains accepted editions), so NIP-09
/// deletes fall out naturally on the next rebuild.
#[derive(Debug, Default)]
pub struct PrivateSyncIndex {
    entries: HashMap<String, PrivateRepoEntry>,
}

impl PrivateSyncIndex {
    /// Replace the whole index with `entries`, returning what changed.
    pub fn replace_all(&mut self, entries: HashMap<String, PrivateRepoEntry>) -> PrivateIndexDiff {
        let old_keys: HashSet<&String> = self
            .entries
            .values()
            .flat_map(|e| e.keys.iter())
            .collect();
        let added_aliases: Vec<String> = entries
            .keys()
            .filter(|alias| !self.entries.contains_key(*alias))
            .cloned()
            .collect();
        let added_keys: Vec<String> = {
            let mut seen = HashSet::new();
            entries
                .values()
                .flat_map(|e| e.keys.iter())
                .filter(|k| !old_keys.contains(*k) && seen.insert((*k).clone()))
                .cloned()
                .collect()
        };
        let changed = self.entries != entries;
        self.entries = entries;
        PrivateIndexDiff {
            changed,
            added_aliases,
            added_keys,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// (alias, w+aux keys) pairs for `build_private_derived_filters`.
    pub fn derived_inputs(&self) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = self
            .entries
            .iter()
            .map(|(alias, entry)| (alias.clone(), entry.keys.clone()))
            .collect();
        out.sort();
        out
    }

}

/// Normalized ws(s):// private-sync peer relay URLs: EXCLUSIVELY the
/// operator-configured allowlist (`NGIT_PRIVATE_SYNC_PEER_URLS`), minus this
/// node's own domain. Tenant 30640 `relays` tags deliberately do NOT
/// contribute — deriving outbound connections from tenant input would let a
/// single registration point the node at internal infrastructure or an
/// attacker relay and leak the entire private-repo membership map through
/// the derived sync filters. Empty allowlist ⇒ empty set (no connections).
pub fn configured_peer_relay_urls(allowlist: &[String], own_domain: &str) -> HashSet<String> {
    allowlist
        .iter()
        // Normalize FIRST (bare host[:port] -> wss://) so the exact-host
        // own-domain exclusion also recognizes scheme-less self entries —
        // the pre-A3 substring check excluded those too.
        .filter_map(|v| normalize_relay_url(v))
        // Phase-4b A3: exact-host own-domain exclusion (host + port, so
        // loopback test pairs stay distinct; the old substring check also
        // excluded look-alike hosts such as evil twin suffix domains).
        .filter(|v| !crate::private::host::url_denotes_domain(v, own_domain))
        .collect()
}

/// http(s) → ws(s) conversion + trailing-slash trim; bare host:port → wss://.
pub fn normalize_relay_url(value: &str) -> Option<String> {
    let v = value.trim().trim_end_matches('/');
    if v.is_empty() {
        return None;
    }
    let url = if v.starts_with("ws://") || v.starts_with("wss://") {
        v.to_string()
    } else if let Some(rest) = v.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if let Some(rest) = v.strip_prefix("https://") {
        format!("wss://{rest}")
    } else {
        format!("wss://{v}")
    };
    Some(url)
}

// =============================================================================
// PrivateRejectedIndex
// =============================================================================

/// Hard cap on held full events (memory bound against hostile floods).
const MAX_HELD_EVENTS: usize = 4096;

/// R2-1 (verify round 2): registrations sub-cap within MAX_HELD_EVENTS so a
/// registration-hold flood cannot crowd out the 30641/1059 dependency
/// holds. Newest-only replacement (below) bounds the hold by the live
/// (tenant, alias) universe in practice; this cap is the flood backstop.
const MAX_HELD_REGISTRATIONS: usize = 1024;

/// R2-1(c): per-tick drain cap for held-registration retries. Each retry
/// pays FULL Live admission (parse, up to 64 PoP schnorr verifies ≈ 4-7ms,
/// plus an LMDB write txn that commits even on reject), so an uncapped drain
/// of a flooded 4096-entry hold cost ~3.3-5.7 cores sustained under the
/// SyncManager mutex. Worst case now: 64 × ~4-7ms ≈ 0.26-0.45s per 5s tick
/// (≤ ~0.5s/tick), and the refill-aware eligibility gate means a flooded
/// hold drains that burst at most once per refill period, not every tick.
pub const MAX_REGISTRATION_RETRIES_PER_TICK: usize = 64;

/// R2-1(b): derive the per-held-registration retry period from the cadence
/// knobs — the per-token refill period of the (tenant, alias) replacement
/// bucket (retrying faster than refill is pure waste), clamped to
/// [60s, 1h]. The clamp ceiling equals the slowest configurable refill
/// (1/hour), so an event that stays newest IS eventually retried after one
/// full refill — the FS-2 convergence guarantee (validate() enforces
/// refill > 0 whenever the limiter is enabled). 0 refill is only possible
/// with the limiter disabled (which never cadence-rejects) and maps to the
/// ceiling. NGIT_TEST caps the period at 1s so tests exercise the gate
/// without 15-minute stalls (the drain timer itself runs at 200ms there).
pub fn registration_retry_period(refill_per_hour: u32) -> Duration {
    let raw = if refill_per_hour > 0 {
        Duration::from_secs_f64(3600.0 / refill_per_hour as f64)
    } else {
        Duration::from_secs(3600)
    };
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        return raw.min(Duration::from_secs(1));
    }
    raw.clamp(Duration::from_secs(60), Duration::from_secs(3600))
}

#[derive(Debug)]
struct HeldEvent {
    event: Event,
    held_at: Instant,
}

/// R2-1: a held cadence-rejected 30640 replacement, one per (tenant, alias)
/// bucket (newest-only).
#[derive(Debug)]
struct HeldRegistration {
    event: Event,
    /// Retry before this instant is pure waste: the cadence bucket cannot
    /// have refilled a full token sooner. Insert time + per-token refill
    /// period with ±20% jitter (sampled once per hold, same idiom as the
    /// mirror backoff) so flooded holds do not retry in lockstep.
    next_eligible: Instant,
    /// Insertion sequence — FIFO order for the per-tick drain cap.
    seq: u64,
}

#[derive(Debug, Default)]
struct PrivateRejectedInner {
    /// 30641 rejections keyed by target alias (`d` tag).
    by_alias: HashMap<String, Vec<HeldEvent>>,
    /// 1059 rejections keyed by outer author pubkey hex.
    by_author: HashMap<String, Vec<HeldEvent>>,
    /// FS-2 (review L3-F4) + R2-1 (verify round 2): cadence-rejected
    /// same-tenant 30640 REPLACEMENTS held for retry by the 5s
    /// `sync_private_registrations_to_index` timer, keyed by
    /// (tenant pubkey hex, alias) with NEWEST-ONLY replacement: a strictly
    /// newer cadence-rejected edition replaces the held one, an
    /// older-or-equal one is id-only dropped. When every node
    /// cadence-rejects the same replacement (lockstep drain) the event used
    /// to be stored NOWHERE and the hourly re-issue could not heal it
    /// (re-issue only re-fetches what a peer holds); holding the newest
    /// edition locally and re-offering it after the wall-clock bucket
    /// refill makes convergence independent of the client retrying.
    registrations: HashMap<(String, String), HeldRegistration>,
    /// Skip-set ids of CURRENTLY HELD registrations. These live outside
    /// `ids` because a held registration outlives the skip-set TTL (its
    /// refill-aware eligibility can be up to 1h out vs the default 120s
    /// TTL): while held, the id must keep the pre-filter skip and
    /// negentropy exclusion active with no expiry.
    registration_ids: HashSet<EventId>,
    /// Next insertion sequence for held registrations (FIFO drain order).
    next_reg_seq: u64,
    /// All known-rejected private event ids (incl. id-only 30640 rejections
    /// and the ids of 30641/1059 holds) with their rejection time — drives
    /// the sync pre-filter skip and the negentropy exclusion set.
    ids: HashMap<EventId, Instant>,
    held_count: usize,
}

/// Drain result for the cadence-retry timer (R2-1).
#[derive(Debug, Default)]
pub struct RegistrationDrain {
    /// Eligible held registrations, oldest-insertion first.
    pub events: Vec<Event>,
    /// Still held after the drain (not-yet-eligible + beyond-cap).
    pub remaining: usize,
}

/// Dedicated hot cache for rejected private-repo events awaiting their
/// authorizing kind-30640 registration. TTL matches the existing rejected
/// hot-cache duration (default 120s); raise
/// `--rejected-hot-cache-duration-secs` if 30640/dependent ordering is slow.
#[derive(Debug)]
pub struct PrivateRejectedIndex {
    inner: parking_lot::Mutex<PrivateRejectedInner>,
    ttl: Duration,
    /// R2-1(b): per-token refill period of the (tenant, alias) replacement
    /// cadence bucket, from [`registration_retry_period`]; per-hold ±20%
    /// jitter is sampled in [`Self::insert_registration`].
    registration_retry_period: Duration,
}

impl PrivateRejectedIndex {
    pub fn new(ttl: Duration, registration_retry_period: Duration) -> Self {
        Self {
            inner: parking_lot::Mutex::new(PrivateRejectedInner::default()),
            ttl,
            registration_retry_period,
        }
    }

    /// Is this event id known-rejected (still within TTL)?
    pub fn contains(&self, id: &EventId) -> bool {
        let inner = self.inner.lock();
        if inner.registration_ids.contains(id) {
            return true;
        }
        match inner.ids.get(id) {
            Some(at) => at.elapsed() < self.ttl,
            None => false,
        }
    }

    /// All known-rejected ids (for negentropy exclusion). FS-4 (review
    /// L3-F5): TTL-expired entries are filtered out LAZILY here — the same
    /// idiom as the REQ-path [`Self::contains`] — instead of waiting for
    /// the 60s physical `cleanup_expired` pass, so the negentropy
    /// transport's heal latency is bounded by the TTL plus the re-issue
    /// interval, not TTL + cleanup interval + re-issue interval. Held
    /// registrations are always included (they outlive the TTL by design —
    /// see `registration_ids`).
    pub fn all_event_ids(&self) -> HashSet<EventId> {
        let ttl = self.ttl;
        let inner = self.inner.lock();
        let mut out: HashSet<EventId> = inner
            .ids
            .iter()
            .filter(|(_, at)| at.elapsed() < ttl)
            .map(|(id, _)| *id)
            .collect();
        out.extend(inner.registration_ids.iter().copied());
        out
    }

    /// Record an id-only rejection (30640s have no held-event semantics).
    pub fn add_id_only(&self, id: EventId) {
        self.inner.lock().ids.insert(id, Instant::now());
    }

    /// Hold a rejected 30641 keyed by its target alias.
    pub fn add_state_root(&self, alias: String, event: Event) {
        let mut inner = self.inner.lock();
        Self::add_held(&mut inner, event, |inner, held| {
            inner.by_alias.entry(alias).or_default().push(held);
        });
    }

    /// Hold a rejected 1059 keyed by its outer author pubkey.
    pub fn add_wrap(&self, author_hex: String, event: Event) {
        let mut inner = self.inner.lock();
        Self::add_held(&mut inner, event, |inner, held| {
            inner.by_author.entry(author_hex).or_default().push(held);
        });
    }

    /// FS-2 + R2-1: hold a cadence-rejected same-tenant 30640 replacement
    /// for the sync timer's post-refill retry — NEWEST-ONLY per
    /// (tenant, alias) bucket:
    ///
    /// - a strictly newer edition (same created_at/id ordering as
    ///   `registration::is_newer_than_stored`: higher created_at wins,
    ///   equal created_at -> LOWER id wins) REPLACES the held edition.
    ///   Accepting the held newest edition later stales the displaced older
    ///   one into the harmless anchor-repair no-op, so the displaced
    ///   edition keeps only an id-only skip-set entry (TTL'd);
    /// - an older-or-equal edition for the same bucket is id-only dropped;
    /// - a NEW bucket is subject to the registrations sub-cap
    ///   ([`MAX_HELD_REGISTRATIONS`], so dependency holds keep their share
    ///   of [`MAX_HELD_EVENTS`]) and the global hold cap — overflow drops
    ///   WITHOUT poisoning the skip-set, exactly like [`Self::add_held`]
    ///   (replacements of an existing bucket never grow the hold and are
    ///   therefore never cap-dropped).
    ///
    /// While held, the event id keeps the pre-filter skip and negentropy
    /// exclusion out of refetch loops (no TTL — the refill-aware
    /// eligibility can sit up to 1h past the 120s default TTL). The event
    /// leaves the hold on accept, on expiry (TTL past its eligibility —
    /// the hourly full re-issue is the backstop healer), or on sub-cap
    /// overflow.
    pub fn add_registration(&self, event: Event) {
        let tenant_hex = event.pubkey.to_hex();
        let alias = event.tags.iter().find_map(|tag| {
            let v = tag.clone().to_vec();
            if v.len() >= 2 && v[0] == "d" {
                Some(v[1].clone())
            } else {
                None
            }
        });
        let Some(alias) = alias else {
            // Shape-invalid 30640s cannot reach the cadence rejection
            // (parse_shape fails earlier with `invalid:`), but never hold
            // an event we cannot key into a bucket.
            self.add_id_only(event.id);
            return;
        };
        let mut inner = self.inner.lock();
        if inner.registration_ids.contains(&event.id) || inner.ids.contains_key(&event.id) {
            // Already tracked (held, or id-only from an older-or-equal
            // drop) — don't hold duplicates.
            return;
        }
        let key = (tenant_hex, alias);
        if let Some(held) = inner.registrations.get(&key) {
            let newer = event.created_at.as_secs() > held.event.created_at.as_secs()
                || (event.created_at == held.event.created_at && event.id < held.event.id);
            if !newer {
                // Older-or-equal: id-only drop (it would be absorbed by the
                // accept-no-op anchor repair anyway).
                inner.ids.insert(event.id, Instant::now());
                return;
            }
            // Strictly newer: replace — free the old full event (held_count
            // nets to zero) and keep its id as an id-only skip-set entry.
            let old = inner.registrations.remove(&key).expect("checked above");
            inner.registration_ids.remove(&old.event.id);
            inner.ids.insert(old.event.id, Instant::now());
            inner.held_count = inner.held_count.saturating_sub(1);
            Self::insert_registration(&mut inner, key, event, self.registration_retry_period);
            return;
        }
        if inner.registrations.len() >= MAX_HELD_REGISTRATIONS {
            // Sub-cap overflow: drop WITHOUT touching the skip-set.
            return;
        }
        if inner.held_count >= MAX_HELD_EVENTS {
            // Global memory bound: same no-poison discipline as add_held.
            return;
        }
        Self::insert_registration(&mut inner, key, event, self.registration_retry_period);
    }

    fn insert_registration(
        inner: &mut PrivateRejectedInner,
        key: (String, String),
        event: Event,
        period: Duration,
    ) {
        use rand::RngExt;

        let now = Instant::now();
        // ±20% jitter, sampled once per hold (mirror-backoff idiom).
        let jitter = 0.8 + ::rand::rng().random::<f64>() * 0.4;
        let seq = inner.next_reg_seq;
        inner.next_reg_seq += 1;
        inner.registration_ids.insert(event.id);
        inner.held_count += 1;
        inner.registrations.insert(
            key,
            HeldRegistration {
                event,
                next_eligible: now + period.mul_f64(jitter),
                seq,
            },
        );
    }

    fn add_held(
        inner: &mut PrivateRejectedInner,
        event: Event,
        insert: impl FnOnce(&mut PrivateRejectedInner, HeldEvent),
    ) {
        if inner.ids.contains_key(&event.id) {
            // Already tracked (skip-set or held) — don't hold duplicates.
            return;
        }
        if inner.held_count >= MAX_HELD_EVENTS {
            // Memory bound: drop the event WITHOUT touching the skip-set —
            // a skip-set entry for an event we are not actually holding
            // would block it from ever being refetched/replayed until TTL
            // expiry, letting a hold-cap flood starve legitimate events.
            return;
        }
        inner.ids.insert(event.id, Instant::now());
        inner.held_count += 1;
        insert(
            inner,
            HeldEvent {
                event,
                held_at: Instant::now(),
            },
        );
    }

    /// Remove and return all held events for `alias` (30641s), clearing
    /// their skip-set entries so re-processing is not pre-filtered.
    pub fn take_for_alias(&self, alias: &str) -> Vec<Event> {
        let mut inner = self.inner.lock();
        let held = inner.by_alias.remove(alias).unwrap_or_default();
        Self::release(&mut inner, held)
    }

    /// Remove and return all held events authored by any of `authors`
    /// (1059 wraps), clearing their skip-set entries.
    pub fn take_for_authors(&self, authors: &[String]) -> Vec<Event> {
        let mut inner = self.inner.lock();
        let mut held = Vec::new();
        for author in authors {
            if let Some(events) = inner.by_author.remove(author) {
                held.extend(events);
            }
        }
        Self::release(&mut inner, held)
    }

    /// FS-2 + R2-1(b)(c): remove and return up to `max` ELIGIBLE held
    /// cadence-rejected 30640 replacements (`next_eligible <= now`),
    /// oldest-insertion first (FIFO by `seq`), clearing their skip-set
    /// entries so the timer's retry is not pre-filtered. Not-yet-eligible
    /// entries stay held untouched; eligible entries beyond `max` also stay
    /// held — they are first in line next tick (no starvation of older
    /// entries). A retry that is cadence-rejected again re-holds through
    /// the normal rejection path (fresh eligibility + TTL); an accepted
    /// retry — including the accept-no-op anchor-repair for an edition that
    /// went stale while held — ends the cycle.
    pub fn drain_registrations(&self, now: Instant, max: usize) -> RegistrationDrain {
        let mut inner = self.inner.lock();
        let mut eligible: Vec<(u64, (String, String))> = inner
            .registrations
            .iter()
            .filter(|(_, h)| h.next_eligible <= now)
            .map(|(key, h)| (h.seq, key.clone()))
            .collect();
        eligible.sort_unstable();
        eligible.truncate(max);
        let mut events = Vec::with_capacity(eligible.len());
        for (_, key) in eligible {
            if let Some(h) = inner.registrations.remove(&key) {
                inner.registration_ids.remove(&h.event.id);
                inner.held_count = inner.held_count.saturating_sub(1);
                events.push(h.event);
            }
        }
        RegistrationDrain {
            events,
            remaining: inner.registrations.len(),
        }
    }

    fn release(inner: &mut PrivateRejectedInner, held: Vec<HeldEvent>) -> Vec<Event> {
        inner.held_count = inner.held_count.saturating_sub(held.len());
        held.into_iter()
            .map(|h| {
                inner.ids.remove(&h.event.id);
                h.event
            })
            .collect()
    }

    /// Drop entries older than the TTL. Returns how many were removed.
    pub fn cleanup_expired(&self) -> usize {
        let ttl = self.ttl;
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let mut removed = 0_usize;

        for map in [&mut inner.by_alias, &mut inner.by_author] {
            for events in map.values_mut() {
                let before = events.len();
                events.retain(|h| h.held_at.elapsed() < ttl);
                removed += before - events.len();
            }
            map.retain(|_, v| !v.is_empty());
        }
        {
            // Registrations expire TTL past their ELIGIBILITY, not past
            // insertion: the refill-aware eligibility can sit up to 1h out
            // (vs the 120s default TTL) and the entry must survive to its
            // first retry. (Instant::elapsed saturates to zero for a
            // future next_eligible.)
            let mut expired_ids = Vec::new();
            let before = inner.registrations.len();
            inner.registrations.retain(|_, h| {
                let keep = h.next_eligible.elapsed() < ttl;
                if !keep {
                    expired_ids.push(h.event.id);
                }
                keep
            });
            removed += before - inner.registrations.len();
            for id in expired_ids {
                inner.registration_ids.remove(&id);
            }
        }
        inner.held_count = inner.held_count.saturating_sub(removed);

        // Expire skip-set ids on the same TTL. Held events keep their ids
        // alive because both were inserted at the same instant; held
        // REGISTRATION ids live in `registration_ids` (dropped above with
        // their hold entry) and never in `ids`.
        inner.ids.retain(|_, at| at.elapsed() < ttl);
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic distinct-bucket alias (32 lowercase hex chars).
    fn alias_for(seed: u64) -> String {
        format!("{seed:032x}")
    }

    /// A 30640-shaped event (d tag + explicit created_at) so the
    /// newest-only bucket ordering is testable.
    fn registration_like(
        keys: &nostr_sdk::prelude::Keys,
        alias: &str,
        created_at: u64,
    ) -> nostr_sdk::prelude::Event {
        use nostr_sdk::prelude::*;
        EventBuilder::new(Kind::Custom(30640u16), "rotation")
            .tag(Tag::custom("d", [alias.to_string()]))
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .expect("sign")
    }

    #[test]
    fn test_replace_all_diff() {
        let mut index = PrivateSyncIndex::default();
        let mut entries = HashMap::new();
        entries.insert(
            "a".repeat(32),
            PrivateRepoEntry {
                keys: vec!["k1".into()],
                relay_urls: vec!["ws://peer:1".into()],
                server_urls: vec!["http://peer:1".into()],
            },
        );
        let diff = index.replace_all(entries.clone());
        assert!(diff.changed);
        assert_eq!(diff.added_aliases.len(), 1);
        assert_eq!(diff.added_keys, vec!["k1".to_string()]);

        // Same content again: no change.
        let diff = index.replace_all(entries);
        assert!(!diff.changed);
        assert!(diff.added_aliases.is_empty());
        assert!(diff.added_keys.is_empty());
    }

    #[test]
    fn test_configured_peer_relay_urls_excludes_own_domain() {
        let allowlist: Vec<String> = vec![
            "ws://127.0.0.1:1111".into(),
            "ws://127.0.0.1:2222/".into(),
            "http://127.0.0.1:3333".into(),
        ];
        let peers = configured_peer_relay_urls(&allowlist, "127.0.0.1:1111");
        assert!(!peers.contains("ws://127.0.0.1:1111"));
        assert!(peers.contains("ws://127.0.0.1:2222"));
        assert!(peers.contains("ws://127.0.0.1:3333"));
    }

    #[test]
    fn test_tenant_relays_tags_never_become_sync_peers() {
        // A hostile 30640 registration listing internal infrastructure and
        // an attacker relay in its `relays` tag must NOT produce outbound
        // sync peers: peers come exclusively from the operator allowlist.
        let mut index = PrivateSyncIndex::default();
        let mut entries = HashMap::new();
        entries.insert(
            "c".repeat(32),
            PrivateRepoEntry {
                keys: vec!["k1".into()],
                relay_urls: vec![
                    "ws://169.254.169.254".into(),
                    "wss://attacker.example.com".into(),
                ],
                server_urls: vec![],
            },
        );
        index.replace_all(entries);

        // No allowlist configured: zero peers, regardless of tenant input.
        let peers = configured_peer_relay_urls(&[], "thisnode.example.com");
        assert!(peers.is_empty());

        // Allowlist configured: exactly the allowlist, tenant values ignored.
        let allowlist: Vec<String> = vec!["wss://peer.example.com".into()];
        let peers = configured_peer_relay_urls(&allowlist, "thisnode.example.com");
        assert_eq!(
            peers,
            HashSet::from(["wss://peer.example.com".to_string()])
        );
        assert!(!peers.contains("ws://169.254.169.254"));
        assert!(!peers.contains("wss://attacker.example.com"));
    }

    #[test]
    fn test_rejected_index_hold_and_take() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO);
        let keys = Keys::generate();
        let event = EventBuilder::text_note("x")
            .finalize(&keys)
            .expect("sign");
        let id = event.id;

        index.add_state_root("alias1".into(), event.clone());
        assert!(index.contains(&id));

        let taken = index.take_for_alias("alias1");
        assert_eq!(taken.len(), 1);
        assert!(!index.contains(&id));

        // Wrap path keyed by author.
        index.add_wrap(keys.public_key().to_hex(), event);
        let taken = index.take_for_authors(&[keys.public_key().to_hex()]);
        assert_eq!(taken.len(), 1);
        assert!(!index.contains(&id));
    }

    #[test]
    fn test_held_cap_overflow_does_not_poison_skip_set() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO);
        let keys = Keys::generate();

        // Flood to the cap with bogus held events.
        for i in 0..MAX_HELD_EVENTS {
            let event = EventBuilder::text_note(format!("flood {i}"))
                .finalize(&keys)
                .expect("sign");
            index.add_state_root(format!("flood-alias-{i}"), event);
        }

        // A legitimate event arriving over the cap is dropped...
        let legit = EventBuilder::text_note("legit")
            .finalize(&keys)
            .expect("sign");
        let id = legit.id;
        index.add_state_root("legit-alias".into(), legit.clone());
        assert!(index.take_for_alias("legit-alias").is_empty());
        // ...but must NOT be poisoned into the skip-set (it has to stay
        // refetchable — pre-filter skip and negentropy exclusion both key
        // off these ids).
        assert!(!index.contains(&id));
        assert!(!index.all_event_ids().contains(&id));

        // Once capacity frees up, the same event holds normally.
        assert_eq!(index.take_for_alias("flood-alias-0").len(), 1);
        index.add_state_root("legit-alias".into(), legit);
        assert!(index.contains(&id));
        assert_eq!(index.take_for_alias("legit-alias").len(), 1);
    }

    /// FS-2 + R2-1: cadence-rejected 30640 replacements are held (not
    /// id-only), drained by the sync timer's retry once ELIGIBLE, deduped
    /// by id, expired TTL past their eligibility, and bounded by the
    /// registrations sub-cap. (Period ZERO => immediately eligible.)
    #[test]
    fn test_registration_hold_take_and_expiry() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO);
        let keys = Keys::generate();
        let event = registration_like(&keys, &alias_for(1), 100);
        let id = event.id;

        // Held and skip-set tracked; re-adding the same id is a no-op.
        index.add_registration(event.clone());
        index.add_registration(event);
        assert!(index.contains(&id));
        assert!(index.all_event_ids().contains(&id));
        let drain = index.drain_registrations(Instant::now(), MAX_REGISTRATION_RETRIES_PER_TICK);
        assert_eq!(drain.events.len(), 1);
        assert_eq!(drain.remaining, 0);
        assert!(index
            .drain_registrations(Instant::now(), 64)
            .events
            .is_empty());
        assert!(!index.contains(&id), "the drain clears the skip-set entry");

        // Expiry: a zero TTL drops the held registration on cleanup (it
        // expires TTL past its eligibility; TTL zero is immediately past).
        let expiring = PrivateRejectedIndex::new(Duration::ZERO, Duration::ZERO);
        expiring.add_registration(registration_like(&keys, &alias_for(1), 100));
        assert_eq!(expiring.cleanup_expired(), 1);
        assert!(expiring
            .drain_registrations(Instant::now(), 64)
            .events
            .is_empty());
    }

    /// R2-1(a): newest-only replacement per (tenant, alias) bucket. An
    /// older-or-equal edition is id-only dropped; a strictly newer edition
    /// replaces the held one (the displaced edition keeps an id-only
    /// skip-set entry); equal created_at breaks to the LOWER id — the same
    /// ordering as registration::is_newer_than_stored.
    #[test]
    fn test_registration_hold_newest_only_replacement() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO);
        let keys = Keys::generate();
        let bucket = alias_for(7);
        let e2 = registration_like(&keys, &bucket, 200);

        index.add_registration(e2.clone());
        // Older edition, same bucket: id-only dropped — the hold keeps e2,
        // and the older id IS skip-set tracked (no refetch churn).
        let e1 = registration_like(&keys, &bucket, 100);
        index.add_registration(e1.clone());
        assert!(index.contains(&e1.id), "older-or-equal is id-only dropped");

        // Strictly newer edition, e2 STILL HELD: replaces e2 in the hold;
        // the displaced e2 keeps an id-only skip-set entry (TTL'd).
        let e3 = registration_like(&keys, &bucket, 300);
        index.add_registration(e3.clone());
        assert!(index.contains(&e2.id), "the displaced edition is id-only");
        let drain = index.drain_registrations(Instant::now(), 64);
        assert_eq!(drain.events.len(), 1);
        assert_eq!(drain.events[0].id, e3.id, "the hold must carry the newest");

        // Equal created_at: the LOWER id is newer (NIP-01 tie-break).
        let low_id = EventBuilder::new(Kind::Custom(30640u16), "tie-lo")
            .tag(Tag::custom("d", ["a".repeat(32)]))
            .custom_created_at(Timestamp::from_secs(400))
            .finalize(&keys)
            .expect("sign");
        let high_id = EventBuilder::new(Kind::Custom(30640u16), "tie-hi")
            .tag(Tag::custom("d", ["a".repeat(32)]))
            .custom_created_at(Timestamp::from_secs(400))
            .finalize(&keys)
            .expect("sign");
        let (newer_tie, older_tie) = if low_id.id < high_id.id {
            (low_id, high_id)
        } else {
            (high_id, low_id)
        };
        index.add_registration(older_tie.clone());
        index.add_registration(newer_tie.clone());
        let drain = index.drain_registrations(Instant::now(), 64);
        assert_eq!(drain.events.len(), 1);
        assert_eq!(
            drain.events[0].id, newer_tie.id,
            "equal created_at must resolve to the lower id"
        );
    }

    /// R2-1(b): the drain skips not-yet-eligible registrations; they become
    /// eligible one jittered refill period after being held (jitter stays
    /// within ±20%, so +130% of the period is a guaranteed drain).
    #[test]
    fn test_registration_drain_eligibility_gate() {
        use nostr_sdk::prelude::*;

        let period = Duration::from_secs(60);
        let index = PrivateRejectedIndex::new(Duration::from_secs(3600), period);
        let keys = Keys::generate();
        let event = registration_like(&keys, &alias_for(2), 100);
        let id = event.id;
        let t0 = Instant::now();
        index.add_registration(event);

        for wait in [0, 30] {
            let drain = index.drain_registrations(t0 + Duration::from_secs(wait), 64);
            assert!(
                drain.events.is_empty(),
                "t+{wait}s must be before the earliest eligibility (0.8x period)"
            );
            assert_eq!(drain.remaining, 1);
            assert!(
                index.contains(&id),
                "a skipped entry stays skip-set tracked"
            );
        }
        // 80s > 1.2 x 60s: past the latest possible jittered eligibility.
        let drain = index.drain_registrations(t0 + Duration::from_secs(80), 64);
        assert_eq!(drain.events.len(), 1);
        assert_eq!(drain.events[0].id, id);
    }

    /// R2-1(c): the per-tick drain cap is FIFO by insertion; entries beyond
    /// the cap keep their eligibility and drain first next tick.
    #[test]
    fn test_registration_drain_cap_fifo() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO);
        let keys = Keys::generate();
        let mut want_order = Vec::new();
        for i in 0..100u64 {
            // Distinct (tenant, alias) buckets: alias varies per event.
            let event = registration_like(&keys, &alias_for(i), 100);
            want_order.push(event.id);
            index.add_registration(event);
        }
        let drain = index.drain_registrations(Instant::now(), MAX_REGISTRATION_RETRIES_PER_TICK);
        assert_eq!(drain.events.len(), MAX_REGISTRATION_RETRIES_PER_TICK);
        assert_eq!(drain.remaining, 100 - MAX_REGISTRATION_RETRIES_PER_TICK);
        let got: Vec<_> = drain.events.iter().map(|e| e.id).collect();
        assert_eq!(
            got,
            want_order[..MAX_REGISTRATION_RETRIES_PER_TICK],
            "the drain must be FIFO by insertion"
        );
        let drain = index.drain_registrations(Instant::now(), MAX_REGISTRATION_RETRIES_PER_TICK);
        assert_eq!(drain.events.len(), 100 - MAX_REGISTRATION_RETRIES_PER_TICK);
        assert_eq!(drain.remaining, 0);
        let got: Vec<_> = drain.events.iter().map(|e| e.id).collect();
        assert_eq!(got, want_order[MAX_REGISTRATION_RETRIES_PER_TICK..]);
    }

    /// R2-1: the registrations sub-cap keeps dependency holds their share
    /// of MAX_HELD_EVENTS — a new bucket past the sub-cap is dropped
    /// WITHOUT poisoning the skip-set, while a replacement of an existing
    /// bucket (no growth) is still accepted at the sub-cap.
    #[test]
    fn test_registration_sub_cap_does_not_poison_skip_set() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO);
        let keys = Keys::generate();
        let first = registration_like(&keys, &alias_for(0), 100);
        index.add_registration(first);
        for i in 1..MAX_HELD_REGISTRATIONS as u64 {
            index.add_registration(registration_like(&keys, &alias_for(i), 100));
        }

        // A NEW bucket at the sub-cap: dropped, and NOT skip-set tracked.
        let over = registration_like(&keys, &alias_for(MAX_HELD_REGISTRATIONS as u64), 100);
        let over_id = over.id;
        index.add_registration(over);
        assert!(!index.contains(&over_id));
        assert!(!index.all_event_ids().contains(&over_id));

        // A strictly-newer replacement for an existing bucket (no growth)
        // is still held at the sub-cap.
        let newer_first = registration_like(&keys, &alias_for(0), 110);
        let newer_id = newer_first.id;
        index.add_registration(newer_first);
        assert!(index.contains(&newer_id));

        // Dependency holds (30641) still have MAX_HELD_EVENTS -
        // MAX_HELD_REGISTRATIONS slots: the registrations sub-cap leaves
        // 3072 for them.
        let held_state = EventBuilder::text_note("30641-like")
            .finalize(&keys)
            .expect("sign");
        index.add_state_root("some-alias".into(), held_state.clone());
        assert!(index.contains(&held_state.id));
    }

    /// R2-1(b): the retry period maps the refill knob to the per-token
    /// period, clamped [60s, 1h] outside NGIT_TEST (the lib test process
    /// never sets NGIT_TEST — TestRelay exports it to the spawned relay).
    #[test]
    fn test_registration_retry_period_mapping() {
        assert_eq!(registration_retry_period(4), Duration::from_secs(900));
        assert_eq!(registration_retry_period(1), Duration::from_secs(3600));
        assert_eq!(
            registration_retry_period(3600),
            Duration::from_secs(60),
            "the clamp floor is 60s"
        );
        assert_eq!(
            registration_retry_period(0),
            Duration::from_secs(3600),
            "0 refill (limiter disabled) maps to the ceiling"
        );
    }

    /// FS-4 (review L3-F5): the negentropy exclusion set filters
    /// TTL-expired ids LAZILY (same idiom as `contains`) instead of
    /// waiting for the periodic physical cleanup.
    #[test]
    fn test_all_event_ids_filters_expired_lazily() {
        use nostr_sdk::prelude::*;

        let keys = Keys::generate();
        let event = EventBuilder::text_note("x")
            .finalize(&keys)
            .expect("sign");
        let id = event.id;

        // Within TTL: excluded (both the REQ-path check and the set).
        let index = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO);
        index.add_id_only(id);
        assert!(index.all_event_ids().contains(&id));

        // Past TTL (zero-TTL index): lazily absent from the exclusion set
        // even though no cleanup pass has run — the entry is still
        // physically present until cleanup_expired.
        let expired = PrivateRejectedIndex::new(Duration::ZERO, Duration::ZERO);
        expired.add_id_only(id);
        assert!(
            !expired.all_event_ids().contains(&id),
            "TTL-expired ids must leave the negentropy exclusion lazily"
        );
        assert!(
            !expired.contains(&id),
            "the REQ-path pre-filter already honored the TTL"
        );
    }
}
