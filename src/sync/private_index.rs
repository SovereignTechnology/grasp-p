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
    let own = own_domain.trim_end_matches('/');
    allowlist
        .iter()
        .filter(|v| !v.trim_end_matches('/').contains(own))
        .filter_map(|v| normalize_relay_url(v))
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

#[derive(Debug)]
struct HeldEvent {
    event: Event,
    held_at: Instant,
}

#[derive(Debug, Default)]
struct PrivateRejectedInner {
    /// 30641 rejections keyed by target alias (`d` tag).
    by_alias: HashMap<String, Vec<HeldEvent>>,
    /// 1059 rejections keyed by outer author pubkey hex.
    by_author: HashMap<String, Vec<HeldEvent>>,
    /// All known-rejected private event ids (incl. id-only 30640 rejections)
    /// with their rejection time — drives the sync pre-filter skip and the
    /// negentropy exclusion set.
    ids: HashMap<EventId, Instant>,
    held_count: usize,
}

/// Dedicated hot cache for rejected private-repo events awaiting their
/// authorizing kind-30640 registration. TTL matches the existing rejected
/// hot-cache duration (default 120s); raise
/// `--rejected-hot-cache-duration-secs` if 30640/dependent ordering is slow.
#[derive(Debug)]
pub struct PrivateRejectedIndex {
    inner: parking_lot::Mutex<PrivateRejectedInner>,
    ttl: Duration,
}

impl PrivateRejectedIndex {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: parking_lot::Mutex::new(PrivateRejectedInner::default()),
            ttl,
        }
    }

    /// Is this event id known-rejected (still within TTL)?
    pub fn contains(&self, id: &EventId) -> bool {
        let inner = self.inner.lock();
        match inner.ids.get(id) {
            Some(at) => at.elapsed() < self.ttl,
            None => false,
        }
    }

    /// All known-rejected ids (for negentropy exclusion).
    pub fn all_event_ids(&self) -> HashSet<EventId> {
        self.inner.lock().ids.keys().copied().collect()
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
        inner.held_count = inner.held_count.saturating_sub(removed);

        // Expire skip-set ids on the same TTL. Held events keep their ids
        // alive because both were inserted at the same instant.
        inner.ids.retain(|_, at| at.elapsed() < ttl);
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let index = PrivateRejectedIndex::new(Duration::from_secs(120));
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

        let index = PrivateRejectedIndex::new(Duration::from_secs(120));
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
}
