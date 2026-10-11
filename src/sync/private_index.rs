//! GRASP-P Phase 2 sync-side indexes.
//!
//! Two small additive structures, both inert unless
//! `NGIT_GRASP_P_REPOS_ENABLE=true`:
//!
//! - [`PrivateSyncIndex`]: alias → {w+aux keys, relay URLs, server URLs},
//!   rebuilt from the relay DB's accepted kind-30640 registrations. Parallel
//!   to `RepoSyncIndex`; drives the derived 30641/stream-wrap sync filters. The
//!   private peer-relay set is NOT derived from it — outbound sync peers
//!   come only from the operator allowlist
//!   ([`configured_peer_relay_urls`]).
//! - [`PrivateRejectedIndex`]: a dedicated hot cache for 30641/stream-wrap
//!   events rejected because their authorizing 30640 has not arrived yet
//!   (out-of-order sync), bounded by count and by bytes. What enters it is
//!   decided by `PrivateService::note_rejected`; this index only keeps,
//!   accounts and releases. Keyed by target alias (30641) and outer author
//!   pubkey (stream wraps) — wraps have an ephemeral pubkey and no `d` tag,
//!   so the existing (pubkey, d-tag) `RejectedEventsIndex` keying cannot
//!   apply. The author keying is deliberately KIND-AGNOSTIC: the 1059 ->
//!   3359 wire-kind migration needs no change here, and a write key whose
//!   registration lands late releases its held wraps of both kinds at once.

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
        let old_keys: HashSet<&String> =
            self.entries.values().flat_map(|e| e.keys.iter()).collect();
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
/// operator-configured allowlist (`NGIT_GRASP_P_SYNC_PEER_URLS`), minus the
/// entries that name this node. `own_service` is the node's service address:
/// its domain, and its mount path when it is served under one. Tenant 30640
/// `relays` tags deliberately do NOT contribute — deriving outbound
/// connections from tenant input would let a
/// single registration point the node at internal infrastructure or an
/// attacker relay and leak the entire private-repo membership map through
/// the derived sync filters. Empty allowlist ⇒ empty set (no connections).
pub fn configured_peer_relay_urls(allowlist: &[String], own_service: &str) -> HashSet<String> {
    allowlist
        .iter()
        // Normalize FIRST (bare host[:port] -> wss://) so the exclusion
        // below also recognizes scheme-less self entries.
        .filter_map(|v| normalize_relay_url(v))
        // Drop the entries that name this node: same host and port (so
        // loopback test pairs stay distinct and look-alike hosts do not
        // match), and, for a node under a mount path, the same path. A relay
        // on the same host under another path is a different service and
        // stays a peer.
        .filter(|v| !crate::grasp_p::host::url_denotes_service(v, own_service))
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
/// registration-hold flood cannot crowd out the 30641/stream-wrap dependency
/// holds. Newest-only replacement (below) bounds the hold by the live
/// (tenant, alias) universe in practice; this cap is the flood backstop.
const MAX_HELD_REGISTRATIONS: usize = 1024;

/// Cap on the ids the index remembers in total: the ids of held events plus
/// the ids kept without their event. Without it a peer, or anyone it relays
/// for, could grow the id map without limit by sending rejected events of
/// distinct ids faster than the TTL retires them.
const MAX_SKIP_SET_IDS: usize = 65_536;

/// The part of [`MAX_SKIP_SET_IDS`] open to ids kept WITHOUT their event. The
/// rest is reserved for the ids of held events, so a full skip-set can never
/// be the reason a dependency hold is refused.
const MAX_ID_ONLY_IDS: usize = MAX_SKIP_SET_IDS - MAX_HELD_EVENTS;

/// Floor of the hold's byte budget.
pub const MIN_HOLD_BUDGET_BYTES: usize = 32 * 1024 * 1024;

/// The budget is never less than this many times the largest size admission
/// lets through, however large that size is configured. That is room for
/// about this many such events: one built from many tiny tags is charged
/// more than its serialized size (see [`event_bytes`]).
const HOLD_BUDGET_MAX_SIZE_EVENTS: u64 = 64;

/// Held registrations may use at most one part in this many of the byte
/// budget: the same quarter [`MAX_HELD_REGISTRATIONS`] is of
/// [`MAX_HELD_EVENTS`].
const REGISTRATION_BUDGET_DIVISOR: usize = MAX_HELD_EVENTS / MAX_HELD_REGISTRATIONS;

/// Byte budget of the hold for a node whose GRASP-P event size limit is
/// `max_event_bytes`: 32 MiB, or 64 times the largest admissible size when
/// that is more. Derived, not a setting: the hold changes when an
/// out-of-order event is retried, never whether it is finally accepted.
pub fn hold_budget_bytes(max_event_bytes: u64) -> usize {
    let scaled = max_event_bytes.saturating_mul(HOLD_BUDGET_MAX_SIZE_EVENTS);
    usize::try_from(scaled)
        .unwrap_or(usize::MAX)
        .max(MIN_HOLD_BUDGET_BYTES)
}

/// What a held event costs against the byte budget: its serialized length
/// plus the memory its tag list takes beyond that text. A tag costs a vector
/// header and one string header per element however short its text is, so an
/// event made of thousands of one-character tags would otherwise occupy
/// about ten times what it is charged.
pub(crate) fn event_bytes(event: &Event) -> usize {
    let tag_headers: usize = event
        .tags
        .iter()
        .map(|tag| {
            std::mem::size_of::<nostr_sdk::prelude::Tag>()
                + tag.len() * std::mem::size_of::<String>()
        })
        .sum();
    event.as_json().len().saturating_add(tag_headers)
}

/// Why the index did not keep what it was offered. Also the fixed label set
/// of `ngit_private_hold_dropped_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldDropReason {
    /// The hold already carries its maximum number of events.
    CountCap,
    /// Keeping the event would exceed the hold's byte budget.
    ByteBudget,
    /// The rejection is not one a later registration can turn into an
    /// acceptance, so the event itself was never offered to the hold.
    NotHoldable,
    /// The id could not be remembered: the skip-set is full.
    SkipSetFull,
}

impl HoldDropReason {
    /// Metric label value.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::CountCap => "count_cap",
            Self::ByteBudget => "byte_budget",
            Self::NotHoldable => "not_holdable",
            Self::SkipSetFull => "skip_set_full",
        }
    }
}

/// What the index did with a rejected event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldOutcome {
    /// The full event is held for a later retry and its id is skipped.
    Held,
    /// Only the id is remembered, so the event is not fetched again before
    /// the TTL lapses.
    IdOnly,
    /// The id was already held or remembered. Nothing new was kept; at most
    /// the time the id was last seen rejected was refreshed.
    AlreadyTracked,
    /// Nothing was kept, not even the id, so the event stays fetchable.
    Dropped(HoldDropReason),
}

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
    /// What this entry was charged against the byte budget when it entered,
    /// kept so leaving the hold returns exactly that amount.
    bytes: usize,
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
    /// As [`HeldEvent::bytes`].
    bytes: usize,
}

#[derive(Debug, Default)]
struct PrivateRejectedInner {
    /// 30641 rejections keyed by target alias (`d` tag).
    by_alias: HashMap<String, Vec<HeldEvent>>,
    /// Stream-wrap rejections keyed by outer author pubkey hex (kind-agnostic).
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
    /// and the ids of 30641/stream-wrap holds) with their rejection time — drives
    /// the sync pre-filter skip and the negentropy exclusion set.
    ids: HashMap<EventId, Instant>,
    /// Held full events of every sort: 30641s, stream wraps, registrations.
    held_count: usize,
    /// Bytes charged by every held full event, registrations included.
    held_bytes: usize,
    /// The part of `held_bytes` charged by held registrations.
    registration_bytes: usize,
}

impl PrivateRejectedInner {
    /// How many ids are remembered WITHOUT their event. Every held 30641 and
    /// stream wrap has its id in `ids` for as long as it is held (both are
    /// stamped with one instant and expire together), so the rest of `ids`
    /// is id-only. Held registrations keep their ids in `registration_ids`.
    fn id_only_len(&self) -> usize {
        let held_in_ids = self.held_count.saturating_sub(self.registrations.len());
        self.ids.len().saturating_sub(held_in_ids)
    }

    /// Remember `id` without its event, or refresh the time it was last seen
    /// rejected.
    ///
    /// A full skip-set REFUSES a new id; it does not evict an old one. The
    /// skip-set exists so a rejected event is not fetched and validated again
    /// on every delivery. When ids arrive faster than the TTL retires them,
    /// some rejected events will be validated again whichever policy is
    /// used: eviction lets the flood push out the entries of other senders
    /// and needs an ordered structure to find the oldest, while refusal is
    /// constant time, leaves every existing entry its full TTL, and frees
    /// room by itself as those entries expire.
    fn remember_id(&mut self, id: EventId, now: Instant) -> HoldOutcome {
        if let Some(at) = self.ids.get_mut(&id) {
            // The id may belong to an event that is still held, so this is
            // not reported as an event reduced to its id.
            *at = now;
            return HoldOutcome::AlreadyTracked;
        }
        if self.id_only_len() >= MAX_ID_ONLY_IDS {
            return HoldOutcome::Dropped(HoldDropReason::SkipSetFull);
        }
        self.ids.insert(id, now);
        HoldOutcome::IdOnly
    }

    fn uncharge(&mut self, bytes: usize) {
        self.held_count = self.held_count.saturating_sub(1);
        self.held_bytes = self.held_bytes.saturating_sub(bytes);
    }

    fn uncharge_registration(&mut self, bytes: usize) {
        self.uncharge(bytes);
        self.registration_bytes = self.registration_bytes.saturating_sub(bytes);
    }
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
///
/// Bounded three ways: by the number of held events, by their bytes, and by
/// the number of ids remembered. Over the count cap or the byte budget a new
/// event is dropped and existing entries are left alone.
#[derive(Debug)]
pub struct PrivateRejectedIndex {
    inner: parking_lot::Mutex<PrivateRejectedInner>,
    ttl: Duration,
    /// R2-1(b): per-token refill period of the (tenant, alias) replacement
    /// cadence bucket, from [`registration_retry_period`]; per-hold ±20%
    /// jitter is sampled in [`Self::insert_registration`].
    registration_retry_period: Duration,
    /// Byte budget for every held full event (see [`hold_budget_bytes`]).
    max_bytes: usize,
}

impl PrivateRejectedIndex {
    pub fn new(ttl: Duration, registration_retry_period: Duration, max_bytes: usize) -> Self {
        Self {
            inner: parking_lot::Mutex::new(PrivateRejectedInner::default()),
            ttl,
            registration_retry_period,
            max_bytes,
        }
    }

    /// The share of the byte budget held registrations may use.
    fn max_registration_bytes(&self) -> usize {
        self.max_bytes / REGISTRATION_BUDGET_DIVISOR
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

    /// Remember a rejected event by id only, for the TTL. Refused when the
    /// skip-set is full (see [`PrivateRejectedInner::remember_id`]).
    pub fn add_id_only(&self, id: EventId) -> HoldOutcome {
        self.inner.lock().remember_id(id, Instant::now())
    }

    /// Hold a rejected 30641 keyed by its target alias.
    pub fn add_state_root(&self, alias: String, event: Event) -> HoldOutcome {
        let mut inner = self.inner.lock();
        Self::add_held(&mut inner, self.max_bytes, event, |inner, held| {
            inner.by_alias.entry(alias).or_default().push(held);
        })
    }

    /// Hold a rejected stream wrap keyed by its outer author pubkey. The
    /// wire kind is irrelevant to the hold: legacy 1059 and 3359 wraps
    /// share the author bucket and are released by the same 30640.
    pub fn add_wrap(&self, author_hex: String, event: Event) -> HoldOutcome {
        let mut inner = self.inner.lock();
        Self::add_held(&mut inner, self.max_bytes, event, |inner, held| {
            inner.by_author.entry(author_hex).or_default().push(held);
        })
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
    ///   edition keeps only an id-only skip-set entry (TTL'd). The
    ///   replacement is charged the DIFFERENCE in bytes; if that difference
    ///   does not fit the budget the newer edition is dropped and the held
    ///   one stays;
    /// - an older-or-equal edition for the same bucket is id-only dropped;
    /// - a NEW bucket is subject to the registrations sub-cap
    ///   ([`MAX_HELD_REGISTRATIONS`], so dependency holds keep their share
    ///   of [`MAX_HELD_EVENTS`]), the global hold cap, the registrations'
    ///   quarter of the byte budget and the budget itself — overflow drops
    ///   WITHOUT poisoning the skip-set, exactly like [`Self::add_held`].
    ///
    /// While held, the event id keeps the pre-filter skip and negentropy
    /// exclusion out of refetch loops (no TTL — the refill-aware
    /// eligibility can sit up to 1h past the 120s default TTL). The event
    /// leaves the hold on accept, on expiry (TTL past its eligibility —
    /// the hourly full re-issue is the backstop healer), or on sub-cap
    /// overflow.
    pub fn add_registration(&self, event: Event) -> HoldOutcome {
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
            return self.add_id_only(event.id);
        };
        let bytes = event_bytes(&event);
        let max_bytes = self.max_bytes;
        let max_registration_bytes = self.max_registration_bytes();
        let mut inner = self.inner.lock();
        if inner.registration_ids.contains(&event.id) || inner.ids.contains_key(&event.id) {
            // Already tracked (held, or id-only from an older-or-equal
            // drop) — don't hold duplicates.
            return HoldOutcome::AlreadyTracked;
        }
        let key = (tenant_hex, alias);
        let held_edition = inner.registrations.get(&key).map(|held| {
            let newer = event.created_at.as_secs() > held.event.created_at.as_secs()
                || (event.created_at == held.event.created_at && event.id < held.event.id);
            (newer, held.bytes)
        });
        if let Some((newer, old_bytes)) = held_edition {
            if !newer {
                // Older-or-equal: id-only drop (it would be absorbed by the
                // accept-no-op anchor repair anyway).
                return inner.remember_id(event.id, Instant::now());
            }
            // Strictly newer: the count does not change, the bytes may, so
            // the budget is checked against the totals as they would be
            // with the held edition gone and the newer one in its place.
            let registration_bytes_after =
                inner.registration_bytes.saturating_sub(old_bytes) + bytes;
            let held_bytes_after = inner.held_bytes.saturating_sub(old_bytes) + bytes;
            if registration_bytes_after > max_registration_bytes || held_bytes_after > max_bytes {
                // Over budget: drop the newcomer, keep what is held, and
                // leave the skip-set alone so the newer edition can be
                // fetched again once there is room.
                return HoldOutcome::Dropped(HoldDropReason::ByteBudget);
            }
            let old = inner.registrations.remove(&key).expect("checked above");
            inner.registration_ids.remove(&old.event.id);
            inner.uncharge_registration(old.bytes);
            // The displaced id is skipped for the TTL when the skip-set has
            // room; when it does not, the worst case is one more fetch and
            // validation of an edition the held one supersedes.
            let _ = inner.remember_id(old.event.id, Instant::now());
            Self::insert_registration(
                &mut inner,
                key,
                event,
                bytes,
                self.registration_retry_period,
            );
            return HoldOutcome::Held;
        }
        if inner.registrations.len() >= MAX_HELD_REGISTRATIONS {
            // Sub-cap overflow: drop WITHOUT touching the skip-set.
            return HoldOutcome::Dropped(HoldDropReason::CountCap);
        }
        if inner.held_count >= MAX_HELD_EVENTS {
            // Global memory bound: same no-poison discipline as add_held.
            return HoldOutcome::Dropped(HoldDropReason::CountCap);
        }
        if inner.registration_bytes.saturating_add(bytes) > max_registration_bytes
            || inner.held_bytes.saturating_add(bytes) > max_bytes
        {
            // Byte budget (the registrations' quarter, or the whole): the
            // same no-poison discipline again.
            return HoldOutcome::Dropped(HoldDropReason::ByteBudget);
        }
        Self::insert_registration(
            &mut inner,
            key,
            event,
            bytes,
            self.registration_retry_period,
        );
        HoldOutcome::Held
    }

    fn insert_registration(
        inner: &mut PrivateRejectedInner,
        key: (String, String),
        event: Event,
        bytes: usize,
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
        inner.held_bytes += bytes;
        inner.registration_bytes += bytes;
        inner.registrations.insert(
            key,
            HeldRegistration {
                event,
                next_eligible: now + period.mul_f64(jitter),
                seq,
                bytes,
            },
        );
    }

    fn add_held(
        inner: &mut PrivateRejectedInner,
        max_bytes: usize,
        event: Event,
        insert: impl FnOnce(&mut PrivateRejectedInner, HeldEvent),
    ) -> HoldOutcome {
        if inner.ids.contains_key(&event.id) {
            // Already tracked (skip-set or held) — don't hold duplicates.
            return HoldOutcome::AlreadyTracked;
        }
        if inner.held_count >= MAX_HELD_EVENTS {
            // Memory bound: drop the event WITHOUT touching the skip-set —
            // a skip-set entry for an event we are not actually holding
            // would block it from ever being refetched/replayed until TTL
            // expiry, letting a hold-cap flood starve legitimate events.
            return HoldOutcome::Dropped(HoldDropReason::CountCap);
        }
        let bytes = event_bytes(&event);
        if inner.held_bytes.saturating_add(bytes) > max_bytes {
            // The count cap alone lets a few thousand maximum-size events
            // pin memory; the byte budget is the bound that scales with
            // what was sent. Same discipline: nothing enters the skip-set.
            return HoldOutcome::Dropped(HoldDropReason::ByteBudget);
        }
        // One instant for the id and the event, so they expire in the same
        // cleanup pass and `id_only_len` stays exact.
        let now = Instant::now();
        inner.ids.insert(event.id, now);
        inner.held_count += 1;
        inner.held_bytes += bytes;
        insert(
            inner,
            HeldEvent {
                event,
                held_at: now,
                bytes,
            },
        );
        HoldOutcome::Held
    }

    /// Remove and return all held events for `alias` (30641s), clearing
    /// their skip-set entries so re-processing is not pre-filtered.
    pub fn take_for_alias(&self, alias: &str) -> Vec<Event> {
        let mut inner = self.inner.lock();
        let held = inner.by_alias.remove(alias).unwrap_or_default();
        Self::release(&mut inner, held)
    }

    /// Remove and return all held events authored by any of `authors`
    /// (stream wraps of any accepted kind), clearing their skip-set entries.
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
                inner.uncharge_registration(h.bytes);
                events.push(h.event);
            }
        }
        RegistrationDrain {
            events,
            remaining: inner.registrations.len(),
        }
    }

    fn release(inner: &mut PrivateRejectedInner, held: Vec<HeldEvent>) -> Vec<Event> {
        held.into_iter()
            .map(|h| {
                inner.ids.remove(&h.event.id);
                inner.uncharge(h.bytes);
                h.event
            })
            .collect()
    }

    /// Drop entries older than the TTL, returning their bytes to the
    /// budget. Returns how many held events were removed.
    pub fn cleanup_expired(&self) -> usize {
        let ttl = self.ttl;
        // One reading of the clock for the whole pass: a held event and its
        // id carry the same instant and must be judged against the same now.
        let now = Instant::now();
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let mut removed = 0_usize;
        let mut freed = 0_usize;

        for map in [&mut inner.by_alias, &mut inner.by_author] {
            for events in map.values_mut() {
                events.retain(|h| {
                    let keep = now.saturating_duration_since(h.held_at) < ttl;
                    if !keep {
                        removed += 1;
                        freed += h.bytes;
                    }
                    keep
                });
            }
            map.retain(|_, v| !v.is_empty());
        }

        // Registrations expire TTL past their ELIGIBILITY, not past
        // insertion: the refill-aware eligibility can sit up to 1h out
        // (vs the 120s default TTL) and the entry must survive to its
        // first retry. (The saturating difference is zero for a future
        // next_eligible.)
        let mut expired_ids = Vec::new();
        let mut freed_registrations = 0_usize;
        inner.registrations.retain(|_, h| {
            let keep = now.saturating_duration_since(h.next_eligible) < ttl;
            if !keep {
                expired_ids.push(h.event.id);
                freed_registrations += h.bytes;
            }
            keep
        });
        removed += expired_ids.len();
        freed += freed_registrations;
        for id in expired_ids {
            inner.registration_ids.remove(&id);
        }

        inner.held_count = inner.held_count.saturating_sub(removed);
        inner.held_bytes = inner.held_bytes.saturating_sub(freed);
        inner.registration_bytes = inner.registration_bytes.saturating_sub(freed_registrations);

        // Expire skip-set ids on the same TTL. A held event's id was
        // stamped with the event's own instant (or refreshed later), so it
        // never expires before the event; held REGISTRATION ids live in
        // `registration_ids` (dropped above with their hold entry) and
        // never in `ids`.
        inner
            .ids
            .retain(|_, at| now.saturating_duration_since(*at) < ttl);
        removed
    }

    /// Bytes currently charged against the budget.
    #[cfg(test)]
    pub(crate) fn held_bytes(&self) -> usize {
        self.inner.lock().held_bytes
    }

    /// Held full events of every sort.
    #[cfg(test)]
    pub(crate) fn held_len(&self) -> usize {
        self.inner.lock().held_count
    }

    /// Recompute the count and both byte totals from the entries and check
    /// them against the running totals, and check every bound. Tests call
    /// this after each step, so an insert, take, expiry, replacement or drop
    /// that forgets its half of the accounting fails where it happens.
    #[cfg(test)]
    pub(crate) fn assert_accounting(&self) {
        let inner = self.inner.lock();
        let dependents: Vec<&HeldEvent> = inner
            .by_alias
            .values()
            .chain(inner.by_author.values())
            .flatten()
            .collect();
        let dependent_bytes: usize = dependents.iter().map(|h| h.bytes).sum();
        let registration_bytes: usize = inner.registrations.values().map(|h| h.bytes).sum();

        for h in &dependents {
            assert_eq!(h.bytes, event_bytes(&h.event), "charge is the event's size");
            assert!(
                inner.ids.contains_key(&h.event.id),
                "a held event's id is in the skip-set"
            );
        }
        for h in inner.registrations.values() {
            assert_eq!(h.bytes, event_bytes(&h.event), "charge is the event's size");
            assert!(inner.registration_ids.contains(&h.event.id));
        }
        assert_eq!(inner.registration_ids.len(), inner.registrations.len());
        assert_eq!(
            inner.held_count,
            dependents.len() + inner.registrations.len(),
            "held_count matches the entries"
        );
        assert_eq!(
            inner.held_bytes,
            dependent_bytes + registration_bytes,
            "held_bytes matches the entries"
        );
        assert_eq!(
            inner.registration_bytes, registration_bytes,
            "registration_bytes matches the entries"
        );
        assert_eq!(
            inner.id_only_len(),
            inner.ids.len() - dependents.len(),
            "the id-only count is the ids that have no held event"
        );

        assert!(inner.held_count <= MAX_HELD_EVENTS);
        assert!(inner.registrations.len() <= MAX_HELD_REGISTRATIONS);
        assert!(inner.held_bytes <= self.max_bytes);
        assert!(inner.registration_bytes <= self.max_registration_bytes());
        assert!(inner.id_only_len() <= MAX_ID_ONLY_IDS);
        assert!(inner.ids.len() + inner.registration_ids.len() <= MAX_SKIP_SET_IDS);
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
    fn same_host_peer_under_another_mount_is_not_self() {
        let allowlist: Vec<String> = vec![
            "wss://h.example/a".into(),
            "wss://h.example/a/".into(),
            "h.example/a".into(),
            "wss://h.example/b".into(),
            "wss://h.example".into(),
            "wss://other.example/a".into(),
        ];
        // A node mounted at /a drops every spelling of itself and keeps the
        // relay next door, the bare host and the same path on another host.
        let peers = configured_peer_relay_urls(&allowlist, "h.example/a");
        assert_eq!(
            peers,
            HashSet::from([
                "wss://h.example/b".to_string(),
                "wss://h.example".to_string(),
                "wss://other.example/a".to_string(),
            ])
        );
        // A node at the root of the host is every path on it, as before.
        let peers = configured_peer_relay_urls(&allowlist, "h.example");
        assert_eq!(peers, HashSet::from(["wss://other.example/a".to_string()]));
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
        assert_eq!(peers, HashSet::from(["wss://peer.example.com".to_string()]));
        assert!(!peers.contains("ws://169.254.169.254"));
        assert!(!peers.contains("wss://attacker.example.com"));
    }

    #[test]
    fn test_rejected_index_hold_and_take() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "x")
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
        index.assert_accounting();
        let taken = index.take_for_authors(&[keys.public_key().to_hex()]);
        assert_eq!(taken.len(), 1);
        assert!(!index.contains(&id));
        index.assert_accounting();
        assert_eq!(index.held_bytes(), 0);
    }

    /// The hold's kind-AGNOSTIC author keying — the contract
    /// `PrivateService::note_rejected` depends on across the 1059 -> 3359
    /// migration: wraps of BOTH wire
    /// kinds from one write key share a bucket and are released together by
    /// the single 30640 that registers that key, with the skip-set cleared
    /// so the reprocess is not pre-filtered.
    ///
    /// Coverage note: this pins the INDEX. The decision that sends a
    /// rejected wrap here is pinned by
    /// `grasp_p::tests::dependency_rejections_are_held_on_both_paths`. A
    /// synced wrap that precedes its own registration is still a race the
    /// two-node harness cannot order.
    #[test]
    fn test_wrap_hold_is_kind_agnostic_per_author() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
        let writer = Keys::generate();
        let author = writer.public_key().to_hex();

        let wrap_of = |kind: u16| {
            EventBuilder::new(Kind::Custom(kind), "opaque-ciphertext-stand-in")
                .finalize(&writer)
                .expect("sign")
        };
        let legacy = wrap_of(crate::grasp_p::KIND_WRAP);
        let modern = wrap_of(crate::grasp_p::KIND_STREAM_WRAP);
        assert_ne!(legacy.id, modern.id, "distinct wire kinds, distinct ids");

        index.add_wrap(author.clone(), legacy.clone());
        index.add_wrap(author.clone(), modern.clone());
        assert!(index.contains(&legacy.id) && index.contains(&modern.id));

        // A different author's registration releases neither.
        let stranger = Keys::generate().public_key().to_hex();
        assert!(index.take_for_authors(&[stranger]).is_empty());
        assert!(index.contains(&legacy.id) && index.contains(&modern.id));

        // The registering author's 30640 releases BOTH at once.
        let taken = index.take_for_authors(&[author]);
        assert_eq!(taken.len(), 2, "both wire kinds must release together");
        let ids: HashSet<EventId> = taken.iter().map(|e| e.id).collect();
        assert!(ids.contains(&legacy.id) && ids.contains(&modern.id));
        assert!(
            !index.contains(&legacy.id) && !index.contains(&modern.id),
            "the take must clear the skip-set entries"
        );
        assert!(index.all_event_ids().is_empty());
    }

    #[test]
    fn test_held_cap_overflow_does_not_poison_skip_set() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
        let keys = Keys::generate();

        // Flood to the cap with bogus held events.
        for i in 0..MAX_HELD_EVENTS {
            let event = EventBuilder::new(Kind::TextNote, format!("flood {i}"))
                .finalize(&keys)
                .expect("sign");
            index.add_state_root(format!("flood-alias-{i}"), event);
        }

        // A legitimate event arriving over the cap is dropped...
        let legit = EventBuilder::new(Kind::TextNote, "legit")
            .finalize(&keys)
            .expect("sign");
        let id = legit.id;
        assert_eq!(
            index.add_state_root("legit-alias".into(), legit.clone()),
            HoldOutcome::Dropped(HoldDropReason::CountCap)
        );
        index.assert_accounting();
        assert!(index.take_for_alias("legit-alias").is_empty());
        // ...but must NOT be poisoned into the skip-set (it has to stay
        // refetchable — pre-filter skip and negentropy exclusion both key
        // off these ids).
        assert!(!index.contains(&id));
        assert!(!index.all_event_ids().contains(&id));

        // Once capacity frees up, the same event holds normally.
        assert_eq!(index.take_for_alias("flood-alias-0").len(), 1);
        assert_eq!(
            index.add_state_root("legit-alias".into(), legit),
            HoldOutcome::Held
        );
        assert!(index.contains(&id));
        assert_eq!(index.take_for_alias("legit-alias").len(), 1);
        index.assert_accounting();
    }

    /// FS-2 + R2-1: cadence-rejected 30640 replacements are held (not
    /// id-only), drained by the sync timer's retry once ELIGIBLE, deduped
    /// by id, expired TTL past their eligibility, and bounded by the
    /// registrations sub-cap. (Period ZERO => immediately eligible.)
    #[test]
    fn test_registration_hold_take_and_expiry() {
        use nostr_sdk::prelude::*;

        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
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
        let expiring =
            PrivateRejectedIndex::new(Duration::ZERO, Duration::ZERO, MIN_HOLD_BUDGET_BYTES);
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

        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
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
        index.assert_accounting();
        assert_eq!(index.held_bytes(), 0, "every drained edition gave back");
    }

    /// R2-1(b): the drain skips not-yet-eligible registrations; they become
    /// eligible one jittered refill period after being held (jitter stays
    /// within ±20%, so +130% of the period is a guaranteed drain).
    #[test]
    fn test_registration_drain_eligibility_gate() {
        use nostr_sdk::prelude::*;

        let period = Duration::from_secs(60);
        let index =
            PrivateRejectedIndex::new(Duration::from_secs(3600), period, MIN_HOLD_BUDGET_BYTES);
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

        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
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

        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
        let keys = Keys::generate();
        let first = registration_like(&keys, &alias_for(0), 100);
        index.add_registration(first);
        for i in 1..MAX_HELD_REGISTRATIONS as u64 {
            index.add_registration(registration_like(&keys, &alias_for(i), 100));
        }

        // A NEW bucket at the sub-cap: dropped, and NOT skip-set tracked.
        let over = registration_like(&keys, &alias_for(MAX_HELD_REGISTRATIONS as u64), 100);
        let over_id = over.id;
        assert_eq!(
            index.add_registration(over),
            HoldOutcome::Dropped(HoldDropReason::CountCap)
        );
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
        let held_state = EventBuilder::new(Kind::TextNote, "30641-like")
            .finalize(&keys)
            .expect("sign");
        index.add_state_root("some-alias".into(), held_state.clone());
        assert!(index.contains(&held_state.id));
        index.assert_accounting();
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
        let event = EventBuilder::new(Kind::TextNote, "x")
            .finalize(&keys)
            .expect("sign");
        let id = event.id;

        // Within TTL: excluded (both the REQ-path check and the set).
        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
        index.add_id_only(id);
        assert!(index.all_event_ids().contains(&id));

        // Past TTL (zero-TTL index): lazily absent from the exclusion set
        // even though no cleanup pass has run — the entry is still
        // physically present until cleanup_expired.
        let expired =
            PrivateRejectedIndex::new(Duration::ZERO, Duration::ZERO, MIN_HOLD_BUDGET_BYTES);
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

    /// A text note of `content_len` content bytes: a stand-in for a held
    /// 30641 or stream wrap whose serialized size is the same for every
    /// call with the same length (ids, keys and signatures are fixed-width
    /// hex), so byte budgets can be written in multiples of it. A counter
    /// in a fixed-width tag keeps the ids distinct.
    fn sized_event(keys: &nostr_sdk::prelude::Keys, content_len: usize) -> Event {
        use nostr_sdk::prelude::*;
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        EventBuilder::new(Kind::TextNote, "x".repeat(content_len))
            .custom_created_at(Timestamp::from_secs(1_700_000_000))
            .tag(Tag::custom("n", [format!("{n:016x}")]))
            .finalize(keys)
            .expect("sign")
    }

    /// A 30640-shaped event with a chosen content, for registrations of
    /// different sizes in one (tenant, alias) bucket.
    fn registration_sized(
        keys: &nostr_sdk::prelude::Keys,
        alias: &str,
        created_at: u64,
        content_len: usize,
    ) -> Event {
        use nostr_sdk::prelude::*;
        EventBuilder::new(Kind::Custom(30640u16), "r".repeat(content_len))
            .tag(Tag::custom("d", [alias.to_string()]))
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .expect("sign")
    }

    /// The budget is 32 MiB, or 64 events of the largest admissible size
    /// when that is more, and never overflows.
    #[test]
    fn hold_budget_scales_with_the_event_size_limit() {
        assert_eq!(hold_budget_bytes(131_072), MIN_HOLD_BUDGET_BYTES);
        assert_eq!(hold_budget_bytes(0), MIN_HOLD_BUDGET_BYTES);
        assert_eq!(hold_budget_bytes(524_288), MIN_HOLD_BUDGET_BYTES);
        assert_eq!(hold_budget_bytes(1 << 20), 64 << 20);
        assert_eq!(hold_budget_bytes(u64::MAX), usize::MAX);
        assert_eq!(REGISTRATION_BUDGET_DIVISOR, 4);
    }

    /// The label values of the drop counter are a fixed set.
    #[test]
    fn hold_drop_reason_labels_are_fixed() {
        let labels: Vec<&str> = [
            HoldDropReason::CountCap,
            HoldDropReason::ByteBudget,
            HoldDropReason::NotHoldable,
            HoldDropReason::SkipSetFull,
        ]
        .iter()
        .map(|reason| reason.as_label())
        .collect();
        assert_eq!(
            labels,
            ["count_cap", "byte_budget", "not_holdable", "skip_set_full"]
        );
    }

    /// The hold is bounded by bytes as well as by count: an event past the
    /// budget is dropped without entering the skip-set and without
    /// disturbing what is held, a smaller one that fits is still taken, and
    /// a take or an expiry returns exactly the bytes it was charged.
    #[test]
    fn hold_is_bounded_by_bytes() {
        use nostr_sdk::prelude::*;

        let keys = Keys::generate();
        let big = event_bytes(&sized_event(&keys, 1000));
        let small = event_bytes(&sized_event(&keys, 0));
        assert!(small < big / 2, "the small event fits the slack below");

        // Room for three big events and a half.
        let budget = 3 * big + big / 2;
        let index = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO, budget);
        let mut held = Vec::new();
        for i in 0..3 {
            let event = sized_event(&keys, 1000);
            assert_eq!(event_bytes(&event), big, "same length, same size");
            assert_eq!(
                index.add_state_root(format!("alias-{i}"), event.clone()),
                HoldOutcome::Held
            );
            held.push(event);
            index.assert_accounting();
        }
        assert_eq!(index.held_bytes(), 3 * big);

        // The fourth does not fit: dropped, and refetchable.
        let over = sized_event(&keys, 1000);
        assert_eq!(
            index.add_wrap(keys.public_key().to_hex(), over.clone()),
            HoldOutcome::Dropped(HoldDropReason::ByteBudget)
        );
        assert!(!index.contains(&over.id));
        assert!(!index.all_event_ids().contains(&over.id));
        assert_eq!(index.held_bytes(), 3 * big, "existing entries untouched");
        assert_eq!(index.held_len(), 3);
        for event in &held {
            assert!(index.contains(&event.id));
        }
        index.assert_accounting();

        // The limit is bytes, not a count: a small event still fits.
        let little = sized_event(&keys, 0);
        assert_eq!(
            index.add_wrap(keys.public_key().to_hex(), little),
            HoldOutcome::Held
        );
        assert_eq!(index.held_bytes(), 3 * big + small);
        index.assert_accounting();

        // A take returns its bytes, and the dropped event then fits.
        assert_eq!(index.take_for_alias("alias-0").len(), 1);
        assert_eq!(index.held_bytes(), 2 * big + small);
        index.assert_accounting();
        assert_eq!(
            index.add_state_root("alias-0".into(), over),
            HoldOutcome::Held
        );
        assert_eq!(index.held_bytes(), 3 * big + small);
        index.assert_accounting();

        // Taking everything returns the budget to zero.
        for alias in ["alias-0", "alias-1", "alias-2"] {
            assert_eq!(index.take_for_alias(alias).len(), 1);
        }
        assert_eq!(
            index.take_for_authors(&[keys.public_key().to_hex()]).len(),
            1
        );
        assert_eq!(index.held_bytes(), 0);
        assert_eq!(index.held_len(), 0);
        assert!(index.all_event_ids().is_empty());
        index.assert_accounting();

        // Expiry returns bytes too (a zero TTL is past at once).
        let expiring = PrivateRejectedIndex::new(Duration::ZERO, Duration::ZERO, budget);
        expiring.add_state_root("a".into(), sized_event(&keys, 1000));
        expiring.add_wrap(keys.public_key().to_hex(), sized_event(&keys, 1000));
        expiring.add_registration(registration_like(&keys, &alias_for(1), 100));
        assert!(expiring.held_bytes() > 2 * big);
        expiring.assert_accounting();
        assert_eq!(expiring.cleanup_expired(), 3);
        assert_eq!(expiring.held_bytes(), 0);
        assert_eq!(expiring.held_len(), 0);
        expiring.assert_accounting();
    }

    /// Held registrations may use a quarter of the byte budget and no more,
    /// so a flood of them cannot take the room 30641s and stream wraps need;
    /// and they are also bound by the whole budget when the others fill it.
    #[test]
    fn registration_hold_has_its_own_byte_share() {
        use nostr_sdk::prelude::*;

        let keys = Keys::generate();
        let size = event_bytes(&registration_like(&keys, &alias_for(0), 100));
        let budget = 8 * size;
        let index = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO, budget);

        // The quarter holds two.
        for i in 0..2u64 {
            let event = registration_like(&keys, &alias_for(i), 100);
            assert_eq!(event_bytes(&event), size, "same shape, same size");
            assert_eq!(index.add_registration(event), HoldOutcome::Held);
            index.assert_accounting();
        }
        let third = registration_like(&keys, &alias_for(2), 100);
        assert_eq!(
            index.add_registration(third.clone()),
            HoldOutcome::Dropped(HoldDropReason::ByteBudget)
        );
        assert!(
            !index.contains(&third.id),
            "dropped without entering the skip-set"
        );
        assert_eq!(index.held_bytes(), 2 * size);
        index.assert_accounting();

        // The other three quarters are still there for dependents.
        for i in 0..6u64 {
            let event = registration_like(&keys, &alias_for(100 + i), 100);
            assert_eq!(
                index.add_state_root(format!("dependent-{i}"), event),
                HoldOutcome::Held,
                "dependent {i} must fit beside a full registration share"
            );
        }
        assert_eq!(index.held_bytes(), budget);
        index.assert_accounting();
        let one_more = registration_like(&keys, &alias_for(200), 100);
        assert_eq!(
            index.add_state_root("dependent-over".into(), one_more),
            HoldOutcome::Dropped(HoldDropReason::ByteBudget)
        );
        index.assert_accounting();

        // Draining the registrations frees their share and nothing else.
        let drain = index.drain_registrations(Instant::now(), 64);
        assert_eq!(drain.events.len(), 2);
        assert_eq!(index.held_bytes(), 6 * size);
        index.assert_accounting();

        // When dependents fill the whole budget a registration is refused
        // by the total, with its own share empty.
        let full = PrivateRejectedIndex::new(Duration::from_secs(120), Duration::ZERO, budget);
        for i in 0..8u64 {
            let event = registration_like(&keys, &alias_for(300 + i), 100);
            assert_eq!(
                full.add_wrap(keys.public_key().to_hex(), event),
                HoldOutcome::Held
            );
        }
        assert_eq!(
            full.add_registration(registration_like(&keys, &alias_for(400), 100)),
            HoldOutcome::Dropped(HoldDropReason::ByteBudget)
        );
        full.assert_accounting();
    }

    /// Replacing a held registration by a newer edition charges the
    /// difference, not the sum; a replacement whose difference does not fit
    /// is dropped and the held edition stays.
    #[test]
    fn replacing_a_held_registration_nets_its_bytes() {
        use nostr_sdk::prelude::*;

        let keys = Keys::generate();
        let bucket = alias_for(9);
        let small = registration_sized(&keys, &bucket, 100, 8);
        let large = registration_sized(&keys, &bucket, 200, 2000);
        let smaller_again = registration_sized(&keys, &bucket, 300, 40);
        let (small_bytes, large_bytes, again_bytes) = (
            event_bytes(&small),
            event_bytes(&large),
            event_bytes(&smaller_again),
        );

        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
        assert_eq!(index.add_registration(small.clone()), HoldOutcome::Held);
        assert_eq!(index.held_bytes(), small_bytes);
        index.assert_accounting();

        // Grows: the total is the new edition's size alone.
        assert_eq!(index.add_registration(large.clone()), HoldOutcome::Held);
        assert_eq!(index.held_len(), 1);
        assert_eq!(index.held_bytes(), large_bytes);
        assert!(index.contains(&small.id), "the displaced id is skipped");
        index.assert_accounting();

        // Shrinks: the difference is returned.
        assert_eq!(
            index.add_registration(smaller_again.clone()),
            HoldOutcome::Held
        );
        assert_eq!(index.held_len(), 1);
        assert_eq!(index.held_bytes(), again_bytes);
        index.assert_accounting();

        let drain = index.drain_registrations(Instant::now(), 64);
        assert_eq!(drain.events.len(), 1);
        assert_eq!(drain.events[0].id, smaller_again.id);
        assert_eq!(index.held_bytes(), 0);
        index.assert_accounting();

        // A registration share that fits the small edition but not the
        // large one: the larger, newer edition is dropped, stays fetchable,
        // and the held edition is untouched.
        let tight = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            REGISTRATION_BUDGET_DIVISOR * (small_bytes + 16),
        );
        assert!(large_bytes > small_bytes + 16);
        assert_eq!(tight.add_registration(small.clone()), HoldOutcome::Held);
        assert_eq!(
            tight.add_registration(large.clone()),
            HoldOutcome::Dropped(HoldDropReason::ByteBudget)
        );
        assert!(!tight.contains(&large.id));
        assert!(tight.contains(&small.id));
        assert_eq!(tight.held_bytes(), small_bytes);
        tight.assert_accounting();

        // A newer edition of the same size fits only when the held one's
        // bytes are netted off before the share is checked.
        let same_size = registration_sized(&keys, &bucket, 400, 8);
        assert_eq!(event_bytes(&same_size), small_bytes);
        assert_eq!(tight.add_registration(same_size.clone()), HoldOutcome::Held);
        assert_eq!(tight.held_len(), 1);
        assert_eq!(tight.held_bytes(), small_bytes);
        tight.assert_accounting();

        let drain = tight.drain_registrations(Instant::now(), 64);
        assert_eq!(drain.events.len(), 1);
        assert_eq!(drain.events[0].id, same_size.id);
        tight.assert_accounting();
    }

    /// The skip-set refuses a new id-only entry when full, keeps the ones it
    /// has, always has room for the id of a held event, and takes new ids
    /// again once entries expire.
    #[test]
    fn skip_set_is_capped() {
        use nostr_sdk::prelude::*;

        let id_for = |n: u64| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&n.to_be_bytes());
            EventId::from_byte_array(bytes)
        };

        let index = PrivateRejectedIndex::new(
            Duration::from_secs(120),
            Duration::ZERO,
            MIN_HOLD_BUDGET_BYTES,
        );
        for n in 0..MAX_ID_ONLY_IDS as u64 {
            assert_eq!(index.add_id_only(id_for(n)), HoldOutcome::IdOnly);
        }
        index.assert_accounting();

        // Full: a new id is refused and stays fetchable.
        let refused = id_for(MAX_ID_ONLY_IDS as u64);
        assert_eq!(
            index.add_id_only(refused),
            HoldOutcome::Dropped(HoldDropReason::SkipSetFull)
        );
        assert!(!index.contains(&refused));
        // An id already there is refreshed, not refused, and none was evicted.
        assert_eq!(index.add_id_only(id_for(0)), HoldOutcome::AlreadyTracked);
        assert!(index.contains(&id_for(0)));
        assert!(index.contains(&id_for(MAX_ID_ONLY_IDS as u64 - 1)));

        // A dependency hold is never refused for lack of skip-set room.
        let keys = Keys::generate();
        let held = sized_event(&keys, 10);
        assert_eq!(
            index.add_state_root("alias".into(), held.clone()),
            HoldOutcome::Held
        );
        assert!(index.contains(&held.id));
        assert_eq!(index.all_event_ids().len(), MAX_ID_ONLY_IDS + 1);
        index.assert_accounting();

        // A held registration displaced while the skip-set is full loses
        // its id rather than its replacement.
        let bucket = alias_for(3);
        let older = registration_like(&keys, &bucket, 100);
        let newer = registration_like(&keys, &bucket, 200);
        assert_eq!(index.add_registration(older.clone()), HoldOutcome::Held);
        assert_eq!(index.add_registration(newer.clone()), HoldOutcome::Held);
        assert!(index.contains(&newer.id));
        assert!(!index.contains(&older.id));
        index.assert_accounting();

        // Expiry makes room (a zero TTL is past at once).
        let expiring = PrivateRejectedIndex::new(Duration::ZERO, Duration::ZERO, 1 << 20);
        for n in 0..MAX_ID_ONLY_IDS as u64 {
            expiring.add_id_only(id_for(n));
        }
        assert_eq!(
            expiring.add_id_only(refused),
            HoldOutcome::Dropped(HoldDropReason::SkipSetFull)
        );
        assert_eq!(expiring.cleanup_expired(), 0, "ids are not held events");
        assert_eq!(expiring.add_id_only(refused), HoldOutcome::IdOnly);
        expiring.assert_accounting();
    }
}
