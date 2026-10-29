//! GRASP-P seams in the sync manager.
//!
//! Everything here is inert unless `NGIT_GRASP_P_REPOS_ENABLE=true`. The sync
//! manager calls in at a handful of points:
//!
//! - its filter builders ([`SyncManager::grasp_p_filters_for`]): for a
//!   configured peer, the Layer-1 kind-30640 registration filter, the
//!   filter for offboard requests (kind 5 with `#k` 30640), and the
//!   30641/stream-wrap and vanish filters derived from the registrations
//!   this node holds, so connect-time sync, quick reconnects and
//!   consolidations all carry them; for any other relay, nothing;
//! - two timers ([`spawn_timers`]): the registration index rebuild (which also
//!   reprocesses held out-of-order events, retries cadence-held 30640
//!   replacements, expires holds and connects the operator's peers) and the
//!   periodic full re-issue, both to configured peers only;
//! - the event pipeline: refuse a GRASP-P event that relay sync brought from
//!   a relay that is not a peer ([`SyncManager::grasp_p_gate`]), skip
//!   events GRASP-P already refused, reprocess held events after a 30640 is
//!   accepted, and hand rejected private events to the hold's decision
//!   point;
//! - negentropy: a requested GRASP-P event that this node holds or refused
//!   counts as delivered ([`SyncManager::grasp_p_settled_ids`]);
//! - the relay lifecycle of a configured peer: it carries no public
//!   repository, so the empty-relay heuristic must not drop it, a session
//!   that ends must not retire it, the naughty list must not mute it, it
//!   may be given a dial policy of its own, and only its connection
//!   forwards duplicates (see "Configured peers" below).
//!
//! # Configured peers
//!
//! A configured peer is a relay the operator named as a node this one
//! replicates private repositories with: an entry of
//! `NGIT_GRASP_P_SYNC_PEER_URLS` that does not name this node. The set is
//! built once, held by the service (`PrivateService::sync_peer_relays`) and
//! read through [`SyncManager::grasp_p_peer_relays`] and
//! [`SyncManager::grasp_p_is_peer`] by everything below, so no two of them
//! can disagree about a relay. It is also the set the scrape gives an alias
//! to (`src/grasp_p/relay_labels.rs`). Nothing else is a peer: not a relay
//! that tenant events name, and not the relay in
//! `NGIT_SYNC_BOOTSTRAP_RELAY_URL` unless the list names it too. A
//! bootstrap relay that is not listed is a public-sync relay under
//! upstream's rules, with no GRASP-P traffic and none of what follows.
//!
//! GRASP-P events travel only on a peer's connection, in both directions:
//! only a peer is sent the private filters, which name every alias and key
//! this node holds, and a GRASP-P event that relay sync brings from any
//! other relay is refused before admission. Relay and server tags in
//! registrations never choose a relay to sync with.
//!
//! Upstream treats every relay as one it may give up on: a session that ends
//! retires a relay no repository names, and a relay whose dial failed over
//! TLS or DNS is not dialled for twelve hours. That is right for a relay an
//! event named. The link to a configured peer is the only way private
//! repositories reach the other node, so for a peer:
//!
//! - an ended session leaves it tracked and disconnected, under upstream's
//!   health backoff ([`SyncManager::grasp_p_peer_needs`]);
//! - a naughty-list entry is still recorded but does not stop a dial
//!   ([`SyncManager::grasp_p_naughty_mute_applies`]);
//! - while it is disconnected it is dialled at least once per
//!   [`PEER_REDIAL_INTERVAL`], whatever upstream's backoff has grown to
//!   ([`SyncManager::grasp_p_redial_peers`]);
//! - when the operator has said the pair's link is private
//!   (`NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS`), its connection, and no
//!   other, is exempt from the outbound target policy
//!   ([`SyncManager::grasp_p_peer_policy`]).

use super::*;

/// FS-3 (review L2-F4): per-peer min-interval floor between private
/// sync-filter re-issues. Both re-issue triggers (an index change and the
/// periodic full re-issue) share this floor per peer, so a churning
/// derived-filter set cannot re-issue to a peer on every dirty tick.
#[derive(Debug, Default)]
struct ReissueFloor {
    /// peer relay URL → when it last received a re-issue.
    last_sent: HashMap<String, Instant>,
}

impl ReissueFloor {
    /// True (recording the send) when `relay_url` may be re-issued under
    /// `floor`; false while the previous send is inside the interval. A zero
    /// floor disables gating. Entries older than the floor are pruned on each
    /// call so the map stays bounded by the recently-seen peer set.
    fn admit(&mut self, relay_url: &str, floor: Duration, now: Instant) -> bool {
        if floor.is_zero() {
            return true;
        }
        self.last_sent
            .retain(|_, at| now.duration_since(*at) < floor);
        if let Some(at) = self.last_sent.get(relay_url) {
            if now.duration_since(*at) < floor {
                return false;
            }
        }
        self.last_sent.insert(relay_url.to_string(), now);
        true
    }
}

/// Result of a private filter re-issue round (FS-3/FS-8): how many live peers
/// were actually re-issued vs skipped by the floor.
#[derive(Debug, Default, Clone, Copy)]
struct ReissueOutcome {
    sent: usize,
    floor_skipped: usize,
}

/// GRASP-P state owned by the sync manager.
#[derive(Debug, Default)]
pub(super) struct GraspPSyncState {
    /// alias → registration sync needs, rebuilt from the relay DB's
    /// kind-30640 events. Drives the derived 30641/stream-wrap filters.
    index: private_index::PrivateSyncIndex,
    reissue_floor: ReissueFloor,
    /// Retries a floor-skipped index-change re-issue on a later tick.
    reissue_pending: bool,
    /// Configured peers that could not be registered, and when to try each
    /// again. Without it a peer that stays refused is vetted (a DNS lookup,
    /// under the manager lock) and logged on every tick.
    peer_retry_after: HashMap<String, Instant>,
    /// When the bounded redial last dialled each disconnected peer.
    peer_redial: PeerRedial,
}

/// The longest a configured peer stays disconnected without a dial.
///
/// Upstream's backoff doubles up to an hour, drops to one dial a day after
/// 24 hours of failures, and does not dial a naughty-listed relay at all.
/// Each is too long for the one link private repositories replicate over.
/// Five minutes is short enough that a peer which came back is found soon,
/// and long enough that a peer which stays down costs one dial in that time.
const PEER_REDIAL_INTERVAL: Duration = Duration::from_secs(300);

/// [`PEER_REDIAL_INTERVAL`] under `NGIT_TEST=1`.
const PEER_REDIAL_INTERVAL_TEST: Duration = Duration::from_secs(2);

fn peer_redial_interval() -> Duration {
    if test_mode() {
        PEER_REDIAL_INTERVAL_TEST
    } else {
        PEER_REDIAL_INTERVAL
    }
}

/// Decides when the bounded redial may dial a disconnected peer.
///
/// It keeps its own record of the dials it issued, beside the health
/// tracker's record of attempts: an attempt is only recorded there once the
/// dial worker has a slot, and a call that upstream turns down is recorded
/// nowhere. Without the record such a peer would be offered again on every
/// tick.
#[derive(Debug, Default)]
struct PeerRedial {
    /// peer relay key → when this redial last dialled it.
    issued: HashMap<String, Instant>,
}

impl PeerRedial {
    /// True, recording the dial, when `peer` may be dialled at `now`: neither
    /// this redial nor anything else has dialled it, or seen it fail, within
    /// `interval`. `last_activity` is the health tracker's latest attempt or
    /// failure for the peer.
    fn admit(
        &mut self,
        peer: &str,
        last_activity: Option<Instant>,
        now: Instant,
        interval: Duration,
    ) -> bool {
        let latest = self.issued.get(peer).copied().max(last_activity);
        if latest.is_some_and(|at| now.saturating_duration_since(at) < interval) {
            return false;
        }
        self.issued.insert(peer.to_string(), now);
        true
    }

    /// Forget every relay that is not in `peers`, so the map never outgrows
    /// the configured set.
    fn retain(&mut self, peers: &HashSet<String>) {
        self.issued.retain(|peer, _| peers.contains(peer));
    }
}

/// `NGIT_TEST=1` shortens every GRASP-P timer so integration tests can
/// observe them.
fn test_mode() -> bool {
    std::env::var("NGIT_TEST").as_deref() == Ok("1")
}

/// The first value of every tag named `name`.
fn tag_values<'a>(event: &'a Event, name: &'a str) -> impl Iterator<Item = &'a String> + 'a {
    event.tags.iter().filter_map(move |tag| {
        let v = tag.as_slice();
        (v.len() >= 2 && v[0] == name).then(|| &v[1])
    })
}

/// GRASP-P offboard requests: every kind 5 that deletes a registration.
///
/// On a GRASP-P node only the account key deletes, and only through its
/// registration, with a request that must carry `["k", "30640"]`
/// (`grasp_p::offboard`), so this one tag selects every kind 5 that can
/// delete anything private. It is not scoped by author: a node takes a
/// request even before it holds the registration, and then refuses that
/// registration when it arrives. Like the registration filter it does not
/// depend on the index, and like every GRASP-P filter it goes to configured
/// peers only.
fn build_private_offboard_filter(since: Option<Timestamp>) -> Filter {
    let filter = Filter::new().kind(Kind::EventDeletion).custom_tag(
        SingleLetterTag::LOWERCASE_K,
        crate::grasp_p::KIND_REGISTRATION.to_string(),
    );
    match since {
        Some(ts) => filter.since(ts),
        None => filter,
    }
}

/// GRASP-P account closures: the NIP-62 vanish requests of the accounts
/// that hold registrations here, 100 authors per filter.
///
/// # Arguments
/// * `tenants` - account keys (lowercase hex) from accepted registrations;
///   values that do not parse are skipped
/// * `since` - Optional timestamp for incremental sync
fn build_private_vanish_filters(tenants: &[String], since: Option<Timestamp>) -> Vec<Filter> {
    let mut authors: Vec<PublicKey> = tenants
        .iter()
        .filter_map(|tenant| PublicKey::from_hex(tenant).ok())
        .collect();
    authors.sort();
    authors.dedup();
    authors
        .chunks(100)
        .map(|chunk| {
            let filter = Filter::new()
                .kind(Kind::RequestToVanish)
                .authors(chunk.iter().copied());
            match since {
                Some(ts) => filter.since(ts),
                None => filter,
            }
        })
        .collect()
}

/// Spawn the GRASP-P sync timers. Does nothing when GRASP-P is disabled.
pub(super) async fn spawn_timers(
    sync_manager: &Arc<Mutex<SyncManager>>,
    shutdown_tx: &broadcast::Sender<()>,
) {
    if !sync_manager.lock().await.config.private_repos_enable {
        return;
    }
    let manager = Arc::clone(sync_manager);
    let shutdown = shutdown_tx.subscribe();
    tokio::spawn(run_registration_sync(manager, shutdown));
    let manager = Arc::clone(sync_manager);
    let shutdown = shutdown_tx.subscribe();
    tokio::spawn(run_full_reissue_timer(manager, shutdown));
}

/// Rebuild the private index from the relay DB's kind-30640 events every 5s
/// (200ms under `NGIT_TEST=1`). This is the single registration path into the
/// index and covers client-pushed and synced 30640s alike, since both live in
/// the relay DB.
async fn run_registration_sync(
    sync_manager: Arc<Mutex<SyncManager>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let interval = if test_mode() {
        Duration::from_millis(200)
    } else {
        Duration::from_secs(5)
    };
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let mut manager = sync_manager.lock().await;
                manager.grasp_p_sync_registrations().await;
                manager
                    .grasp_p_redial_peers(Instant::now(), peer_redial_interval())
                    .await;
            }
            _ = shutdown_rx.recv() => {
                tracing::debug!("Private registration sync timer received shutdown signal");
                break;
            }
        }
    }
}

/// Phase-4b B1: periodic since=None full re-issue of the private sync filters
/// to every live peer, every `NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS` (0
/// disables it; clamped to 2s under `NGIT_TEST=1`). It bounds the wait for
/// gaps live delivery cannot heal (expired holds, negentropy blind spots,
/// cadence-limited 30640 rejections that rely on redelivery). Each sleep is
/// jittered ±10% so paired nodes do not re-issue in lockstep.
async fn run_full_reissue_timer(
    sync_manager: Arc<Mutex<SyncManager>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    use ::rand::RngExt;

    let base_secs = {
        let secs = sync_manager
            .lock()
            .await
            .config
            .private_full_reissue_interval_secs;
        if test_mode() {
            secs.min(2)
        } else {
            secs
        }
    };
    if base_secs == 0 {
        tracing::debug!("Private full re-issue timer disabled (interval 0)");
        return;
    }
    tracing::info!(
        interval_secs = base_secs,
        "Private full re-issue timer started"
    );
    loop {
        let jitter = 0.9 + ::rand::rng().random::<f64>() * 0.2;
        let interval = Duration::from_secs_f64(base_secs as f64 * jitter);
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let mut manager = sync_manager.lock().await;
                manager.grasp_p_reissue_full().await;
            }
            _ = shutdown_rx.recv() => {
                tracing::debug!("Private full re-issue timer received shutdown signal");
                break;
            }
        }
    }
}

impl SyncManager {
    /// The GRASP-P filters the subscription set of `relay_url` carries: the
    /// whole set for a configured peer, nothing for any other relay. The
    /// filters name every alias and write key this node holds, so they go
    /// where GRASP-P events may come from and nowhere else.
    pub(super) fn grasp_p_filters_for(&self, relay_url: &str) -> Vec<Filter> {
        if !self.grasp_p_is_peer(relay_url) {
            return Vec::new();
        }
        self.grasp_p_filter_set()
    }

    /// The Layer-1 kind-30640 filter, the offboard-request filter, and the
    /// filters derived from the current index, whoever they are for.
    fn grasp_p_filter_set(&self) -> Vec<Filter> {
        let mut filters = vec![
            filters::build_private_registration_filter(None),
            build_private_offboard_filter(None),
        ];
        filters.extend(self.grasp_p_index_filters());
        filters
    }

    /// The filters that change with the index: state roots by alias, stream
    /// wraps by key, and the vanish requests of the accounts. An index
    /// change re-issues these alone; the two that never change ride every
    /// connect and the periodic full re-issue.
    fn grasp_p_index_filters(&self) -> Vec<Filter> {
        let mut filters = filters::build_private_derived_filters(
            &self.grasp_p.index.derived_inputs(),
            None,
            self.config.private_accept_legacy_wrap_kind,
        );
        filters.extend(build_private_vanish_filters(
            &self.grasp_p.index.tenants(),
            None,
        ));
        filters
    }

    /// The configured peers, as sync relay keys: the set the service holds
    /// (`PrivateService::sync_peer_relays`). Empty when GRASP-P is disabled.
    pub(super) fn grasp_p_peer_relays(&self) -> HashSet<String> {
        self.write_policy
            .grasp_p()
            .map(|service| service.sync_peer_relays().clone())
            .unwrap_or_default()
    }

    /// Whether `relay_url`, in any spelling the sync code files under the
    /// same key, is a configured peer. False for every relay when GRASP-P
    /// is disabled.
    pub(super) fn grasp_p_is_peer(&self, relay_url: &str) -> bool {
        self.write_policy
            .grasp_p()
            .is_some_and(|service| service.is_sync_peer(relay_url))
    }

    /// What a configured peer is wanted for when its session ends: nothing
    /// that upstream counts, which is still a reason to keep it. `None` for
    /// any other relay, and for every relay when GRASP-P is disabled.
    pub(super) fn grasp_p_peer_needs(&self, relay_url: &str) -> Option<RelaySyncNeeds> {
        self.grasp_p_is_peer(relay_url)
            .then(RelaySyncNeeds::default)
    }

    /// Whether a naughty-list entry may stop a dial of `relay_url`. It may
    /// for every relay but a configured peer: twelve hours without a dial
    /// after, say, a certificate that has since been renewed would stop
    /// replication without a word. The entry itself is upstream's and stays,
    /// with its warning and its metric.
    pub(super) fn grasp_p_naughty_mute_applies(&self, relay_url: &str) -> bool {
        !self.grasp_p_is_peer(relay_url)
    }

    /// The outbound target policy of the connection to `relay_url` when it
    /// is not the node's own: a permissive one, for a configured peer, when
    /// the operator has said the pair's link is private
    /// (`NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS`). `None` for every other
    /// relay, which keeps the node's policy.
    ///
    /// This is what lets a pair on a private network leave upstream's guard
    /// on for the relays that customers' events name.
    pub(super) fn grasp_p_peer_policy(&self, relay_url: &str) -> Option<OutboundTargetPolicy> {
        let private_link = self.config.private_mirror_allow_private_ips;
        (private_link && self.grasp_p_is_peer(relay_url)).then_some(OutboundTargetPolicy {
            allow_non_global: true,
        })
    }

    /// Whether `relay_url` may be registered as an event-directed relay, as
    /// far as GRASP-P is concerned: over `wss://` only on a GRASP-P node,
    /// unless it is a configured peer on a link the operator declared
    /// private, the peer [`Self::grasp_p_peer_policy`] exempts, or
    /// `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS` is on (`grasp_p::egress`).
    /// The bootstrap relay always passes. Always `Ok` when GRASP-P is
    /// disabled.
    pub(super) fn grasp_p_event_relay_allowed(&self, relay_url: &str) -> Result<(), String> {
        // Once the bootstrap relay's session has ended, upstream registers
        // it again as event-directed; it is still the operator's own target,
        // and keeps the scheme it was given.
        let is_bootstrap = self
            .bootstrap_relay_url
            .as_deref()
            .and_then(|url| canonical_relay_key(url).ok())
            .is_some_and(|bootstrap| bootstrap == relay_url);
        if is_bootstrap {
            return Ok(());
        }
        crate::grasp_p::egress::DialSettings::from_config(&self.config)
            .event_relay_allowed(relay_url, self.grasp_p_is_peer(relay_url))
    }

    /// Whether NIP-65 discovery passes over `source` when it picks the one
    /// new source a pass dials: a source the `wss://` rule has refused, and
    /// `register_relay` has logged and remembered. It never connects, so it
    /// never backs off, and a `ws://` key sorts before every `wss://` one: it
    /// would be picked on every pass and no other new source would ever be
    /// dialled. The other callers already skip what that memo holds. A
    /// source refused by upstream's policy alone is left to upstream. Always
    /// false when GRASP-P is disabled.
    pub(super) fn grasp_p_discovery_source_refused(&self, source: &str) -> bool {
        self.rejected_relay_targets.contains(source)
            && self.grasp_p_event_relay_allowed(source).is_err()
    }

    /// Dial every configured peer that has been disconnected, with no dial
    /// and no failure, for `interval`.
    ///
    /// Upstream's reconnect loop stays the first to redial a peer, with its
    /// own backoff. This only bounds the wait once that backoff has grown
    /// past `interval`, and it is the one redial of a peer on the naughty
    /// list, which upstream does not dial. A peer whose dial is queued or
    /// running is left alone, and the dial itself runs in upstream's worker,
    /// not here.
    pub(super) async fn grasp_p_redial_peers(&mut self, now: Instant, interval: Duration) {
        let peers = self.grasp_p_peer_relays();
        self.grasp_p.peer_redial.retain(&peers);
        let disconnected: Vec<String> = {
            let index = self.relay_sync_index.read().await;
            peers
                .into_iter()
                .filter(|peer| {
                    index.get(peer).is_some_and(|state| {
                        state.connection_status == ConnectionStatus::Disconnected
                    })
                })
                .collect()
        };
        for peer in disconnected {
            if self.in_flight_connect_attempts.contains_key(&peer) {
                continue;
            }
            let last_activity = self
                .health_tracker
                .get_health(&peer)
                .and_then(|health| health.last_attempt_time.max(health.last_failure_time));
            if !self
                .grasp_p
                .peer_redial
                .admit(&peer, last_activity, now, interval)
            {
                continue;
            }
            tracing::info!(relay = %peer, "Redialling private-repo peer relay");
            self.schedule_connect_relay(&peer).await;
        }
    }

    /// Rebuild the index from the relay DB's 30640s, reprocess held events
    /// for newly available registrations, retry cadence-held 30640s, expire
    /// holds and, on change, re-issue derived filters to live peers and
    /// connect newly configured peers.
    async fn grasp_p_sync_registrations(&mut self) {
        let Some(service) = self.write_policy.grasp_p().cloned() else {
            return;
        };

        let filter = Filter::new().kind(Kind::Custom(crate::grasp_p::KIND_REGISTRATION));
        let events = match self.database.query(filter).await {
            Ok(events) => events,
            Err(error) => {
                tracing::warn!("private registration index query failed: {error}");
                return;
            }
        };

        let mut entries: HashMap<String, private_index::PrivateRepoEntry> = HashMap::new();
        for event in events.into_iter() {
            let Some(alias) = tag_values(&event, "d").next().cloned() else {
                continue;
            };
            // Key tags are [name, pubkey, pop-signature]; only the pubkey
            // matters for filters.
            let mut keys: Vec<String> = tag_values(&event, "w")
                .chain(tag_values(&event, "aux"))
                .cloned()
                .collect();
            keys.sort();
            keys.dedup();
            let mut relay_urls = Vec::new();
            let mut server_urls = Vec::new();
            for tag in event.tags.iter() {
                let v = tag.as_slice();
                match v.first().map(String::as_str) {
                    Some("relays") => relay_urls.extend(v[1..].iter().cloned()),
                    Some("server") => server_urls.extend(v[1..].iter().cloned()),
                    _ => {}
                }
            }
            entries.insert(
                alias,
                private_index::PrivateRepoEntry {
                    tenant_hex: event.pubkey.to_hex(),
                    keys,
                    relay_urls,
                    server_urls,
                },
            );
        }

        let diff = self.grasp_p.index.replace_all(entries);

        // Out-of-order reprocess (design 1.4): held 30641s keyed by a newly
        // registered alias and held stream wraps by a newly claimed key. The
        // sync path also reprocesses inline on 30640 accept; this covers
        // registrations that arrived by client push.
        if !diff.added_aliases.is_empty() || !diff.added_keys.is_empty() {
            let mut held: Vec<Event> = Vec::new();
            for alias in &diff.added_aliases {
                held.extend(service.sync_rejected().take_for_alias(alias));
            }
            held.extend(service.sync_rejected().take_for_authors(&diff.added_keys));
            let mut seen: HashSet<EventId> = HashSet::new();
            held.retain(|e| seen.insert(e.id));
            for event in held {
                let result = Box::pin(Self::process_event_static(
                    &event,
                    "grasp-p-30640-reprocess",
                    &self.database,
                    &self.write_policy,
                    &self.local_relay,
                    &self.rejected_events_index,
                    crate::nostr::persistence::SaveContext::HotCacheReprocess,
                ))
                .await;
                tracing::info!(
                    event_id = %event.id,
                    kind = %event.kind.as_u16(),
                    result = ?result,
                    "Re-processed held private event after 30640 registration"
                );
            }
        }

        // FS-2 + R2-1: retry held cadence-rejected 30640 replacements on
        // every tick, bounded by per-entry refill-aware eligibility,
        // newest-only holds and a per-tick drain cap. A retry still over
        // cadence is re-held by the rejection path.
        let drain = service.sync_rejected().drain_registrations(
            Instant::now(),
            private_index::MAX_REGISTRATION_RETRIES_PER_TICK,
        );
        let retried = drain.events.len();
        for event in drain.events {
            let result = Box::pin(Self::process_event_static(
                &event,
                "grasp-p-cadence-retry",
                &self.database,
                &self.write_policy,
                &self.local_relay,
                &self.rejected_events_index,
                crate::nostr::persistence::SaveContext::HotCacheReprocess,
            ))
            .await;
            tracing::debug!(
                event_id = %event.id,
                result = ?result,
                "Re-processed held cadence-rejected 30640 replacement"
            );
        }
        if retried > 0 || drain.remaining > 0 {
            tracing::info!(
                retried,
                held_remaining = drain.remaining,
                "Private cadence-rejected 30640 retry drain"
            );
        }

        // Physical expiry of held events (the TTL is also applied lazily).
        let expired = service.sync_rejected().cleanup_expired();
        if expired > 0 {
            tracing::debug!(expired, "Cleaned up expired held private events");
        }

        // Connect operator-allowlisted peers not yet registered. Their
        // filters arrive on connect through the generic filter set.
        // A peer that cannot be registered is tried again after a pause and
        // reported once, not on every tick. A peer that is also the
        // bootstrap relay is already registered, by upstream, at startup.
        let now = Instant::now();
        let peer_retry_delay = Duration::from_secs(if test_mode() { 1 } else { 60 });
        let unknown_peers: Vec<String> = {
            let index = self.relay_sync_index.read().await;
            self.grasp_p_peer_relays()
                .into_iter()
                .filter(|url| !index.contains_key(url))
                .filter(|url| {
                    self.grasp_p
                        .peer_retry_after
                        .get(url)
                        .is_none_or(|retry_at| now >= *retry_at)
                })
                .collect()
        };
        for url in unknown_peers {
            let first_attempt = !self.grasp_p.peer_retry_after.contains_key(&url);
            if !crate::grasp_p::mirror::relay_peer_allowed(
                &url,
                self.config.private_mirror_allow_private_ips,
            )
            .await
            {
                if first_attempt {
                    tracing::warn!(relay = %url, "Skipping private-repo peer relay: SSRF guard rejected URL");
                }
                self.grasp_p
                    .peer_retry_after
                    .insert(url, now + peer_retry_delay);
                continue;
            }
            if first_attempt {
                tracing::info!(relay = %url, "Registering private-repo peer relay");
            }
            if self.register_relay(url.clone(), false, false).await {
                self.grasp_p.peer_retry_after.remove(&url);
                self.schedule_connect_relay(&url).await;
            } else {
                self.grasp_p
                    .peer_retry_after
                    .insert(url, now + peer_retry_delay);
            }
        }

        // FS-3: a re-issue is due when the index changed or a previous one
        // was floor-skipped. Skipped re-issues are deferred, never dropped.
        if !(diff.changed || self.grasp_p.reissue_pending) {
            return;
        }
        let derived = self.grasp_p_index_filters();
        if derived.is_empty() {
            // No aliases means nothing to re-issue; a peer that connects
            // later gets the current (empty) derived set at connect time.
            self.grasp_p.reissue_pending = false;
            return;
        }
        let outcome = self.grasp_p_reissue_to_live_relays(derived).await;
        self.grasp_p.reissue_pending = outcome.floor_skipped > 0;
    }

    /// The configured peers whose live subscriptions are open now: where a
    /// re-issue goes. Any other live relay was never sent the private
    /// filters and is sent none here.
    async fn grasp_p_live_peers(&self) -> Vec<String> {
        let peers = self.grasp_p_peer_relays();
        let index = self.relay_sync_index.read().await;
        peers
            .into_iter()
            .filter(|peer| {
                index
                    .get(peer)
                    .is_some_and(|state| state.connection_status.is_live_sync_active())
            })
            .collect()
    }

    /// Re-issue private sync filters to every live peer: extend the live
    /// subscription set (falling back to upstream's consolidation when the
    /// minimal extension does not fit) and run a since=None historic sync.
    /// Each peer is gated by the `NGIT_GRASP_P_REISSUE_MIN_INTERVAL_SECS`
    /// floor (clamped to 1s under `NGIT_TEST=1`); paused relays are skipped,
    /// their recovery is the health tracker's.
    async fn grasp_p_reissue_to_live_relays(&mut self, filters: Vec<Filter>) -> ReissueOutcome {
        let floor_secs = self.config.private_reissue_min_interval_secs;
        let floor = Duration::from_secs(if test_mode() {
            floor_secs.min(1)
        } else {
            floor_secs
        });
        let now = Instant::now();
        let live_relays = self.grasp_p_live_peers().await;
        let mut outcome = ReissueOutcome::default();
        for relay_url in live_relays {
            if self.health_tracker.is_subscription_paused(&relay_url) {
                continue;
            }
            if !self.grasp_p.reissue_floor.admit(&relay_url, floor, now) {
                outcome.floor_skipped += 1;
                continue;
            }
            if let Err(error) = self.sync_live(&relay_url, &filters).await {
                tracing::warn!(
                    relay = %relay_url,
                    %error,
                    "GRASP-P live coverage could not be extended; continuing historic sync"
                );
                if error.starts_with("Minimum-churn live extension needs")
                    || error.starts_with("Minimum-churn live extension exceeds")
                {
                    let has_pending_batches = self.has_pending_batches(&relay_url).await;
                    if self
                        .deferred_consolidations
                        .request(&relay_url, has_pending_batches)
                    {
                        let _ = self.consolidate(&relay_url).await;
                    }
                }
            }
            self.historic_sync(&relay_url, filters.clone(), PendingItems::default(), None)
                .await;
            outcome.sent += 1;
        }
        outcome
    }

    /// Phase-4b B1: the periodic full re-issue. Same delivery as the
    /// index-change path but not gated on a diff; with an empty index the bare
    /// 30640 filter is still re-issued. Public subscriptions are left alone.
    async fn grasp_p_reissue_full(&mut self) {
        if self.write_policy.grasp_p().is_none() {
            return;
        }
        let filters = self.grasp_p_filter_set();
        let outcome = self.grasp_p_reissue_to_live_relays(filters).await;
        // FS-8: count a round only when at least one peer was re-issued, so a
        // chronically skipped peer is visible.
        if outcome.sent > 0 {
            crate::metrics::record_private_full_reissue();
        } else {
            crate::metrics::record_private_full_reissue_skipped();
        }
    }

    /// Whether `event` is one GRASP-P already refused and remembers by id,
    /// so the event pipeline can skip it (refetch-loop protection). That is
    /// a GRASP-P kind, or a synced event of another kind that admission
    /// refused for good: a deletion request, a reference to private
    /// content, a report on it. Negentropy leaves out the same ids
    /// (`grasp_p_rejected_ids`).
    pub(super) fn grasp_p_previously_rejected(
        write_policy: &Nip34WritePolicy,
        event: &Event,
    ) -> bool {
        let Some(service) = write_policy.grasp_p() else {
            return false;
        };
        service.sync_rejected().contains(&event.id)
    }

    /// The answer for a GRASP-P event that relay sync brought from a relay
    /// that is not a configured peer: refused as blocked, before admission.
    /// Nothing of the event is applied, held or remembered by id, so the
    /// same event from a peer or a client is admitted as ever. Blocked is a
    /// final answer, so a batch or a recovery fetch on that relay completes
    /// instead of asking again.
    ///
    /// `None`, and the event goes on, for every other case: an event of
    /// another kind, one from a peer, every event when GRASP-P is disabled,
    /// and every event that relay sync did not bring just now. A held event
    /// that is tried again came from a peer or a client before it was held,
    /// and an event from a client never passes here.
    pub(super) fn grasp_p_gate(
        write_policy: &Nip34WritePolicy,
        event: &Event,
        relay_url: &str,
        save_context: crate::nostr::persistence::SaveContext,
    ) -> Option<ProcessResult> {
        if save_context != crate::nostr::persistence::SaveContext::RelaySync {
            return None;
        }
        let service = write_policy.grasp_p()?;
        if !service.admits_kind(event.kind.as_u16()) || service.is_sync_peer(relay_url) {
            return None;
        }
        if service.note_foreign_sync_source(relay_url) {
            tracing::warn!(
                relay = %relay_url,
                event_id = %event.id,
                kind = event.kind.as_u16(),
                "Refusing GRASP-P events from a relay that is not a configured sync peer"
            );
        }
        Some(ProcessResult::Rejected(PolicyRejection::Blocked))
    }

    /// The ids among `requested` that GRASP-P has already settled: held
    /// until a registration arrives, or refused and remembered by id. Each
    /// reached the node, so a negentropy batch that asked for it needs no
    /// other copy. Without this, a batch that holds one completes only on
    /// the SDK's second copy of the event, which duplicate forwarding skips,
    /// and so takes a second round. Empty when GRASP-P is disabled.
    pub(super) fn grasp_p_settled_ids(&self, requested: &HashSet<EventId>) -> Vec<EventId> {
        let Some(service) = self.write_policy.grasp_p() else {
            return Vec::new();
        };
        requested
            .iter()
            .copied()
            .filter(|id| service.sync_rejected().contains(id))
            .collect()
    }

    /// Event ids negentropy should not fetch again: known-rejected GRASP-P
    /// events. Empty when GRASP-P is disabled.
    pub(super) fn grasp_p_rejected_ids(
        service: Option<&Arc<crate::grasp_p::PrivateService>>,
    ) -> HashSet<EventId> {
        service
            .map(|service| service.sync_rejected().all_event_ids())
            .unwrap_or_default()
    }

    /// Design 1.4: after a synced 30640 is accepted, reprocess held 30641s
    /// targeting its alias and held stream wraps authored by its w/aux keys.
    pub(super) async fn grasp_p_after_saved(
        event: &Event,
        relay_url: &str,
        database: &SharedDatabase,
        write_policy: &Nip34WritePolicy,
        local_relay: &LocalRelay,
        rejected_events_index: &Arc<RejectedEventsIndex>,
    ) {
        if event.kind.as_u16() != crate::grasp_p::KIND_REGISTRATION {
            return;
        }
        let Some(service) = write_policy.grasp_p() else {
            return;
        };
        let alias = tag_values(event, "d").next().cloned();
        let keys: Vec<String> = tag_values(event, "w")
            .chain(tag_values(event, "aux"))
            .cloned()
            .collect();

        let mut held: Vec<Event> = Vec::new();
        if let Some(ref alias) = alias {
            held.extend(service.sync_rejected().take_for_alias(alias));
        }
        held.extend(service.sync_rejected().take_for_authors(&keys));
        let mut seen: HashSet<EventId> = HashSet::new();
        held.retain(|e| seen.insert(e.id));

        for held_event in held {
            // Safe recursion: the event left the hold before this call, and
            // a second rejection re-holds it without looping.
            let result = Box::pin(Self::process_event_static(
                &held_event,
                relay_url,
                database,
                write_policy,
                local_relay,
                rejected_events_index,
                crate::nostr::persistence::SaveContext::HotCacheReprocess,
            ))
            .await;
            tracing::info!(
                event_id = %held_event.id,
                kind = %held_event.kind.as_u16(),
                alias = ?alias,
                result = ?result,
                "Re-processed held private event after synced 30640 accept"
            );
        }
    }

    /// Design 1.4: record a rejected synced GRASP-P event in the dedicated
    /// index. Upstream's (pubkey, d-tag) index does not fit these kinds:
    /// stream wraps have no `d` tag, so 30641s are keyed by target alias and
    /// stream wraps by their outer author.
    ///
    /// What is kept is decided in one place, `PrivateService::note_rejected`:
    /// the whole event when a later registration can make it acceptable,
    /// otherwise its id, so it is not fetched again on every delivery.
    pub(super) fn grasp_p_after_rejected(
        write_policy: &Nip34WritePolicy,
        event: &Event,
        message: &str,
    ) {
        if let Some(service) = write_policy.grasp_p() {
            service.note_rejected(event, message, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FS-3: back-to-back dirty ticks produce at most one re-issue per peer
    /// per min-interval; a skipped re-issue is deferred, never dropped; the
    /// floor is per-peer and zero disables it; the map self-prunes.
    #[test]
    fn reissue_floor_gates_and_defers() {
        let mut floor = ReissueFloor::default();
        let t0 = Instant::now();
        let f = Duration::from_secs(30);

        assert!(floor.admit("wss://a", f, t0));
        assert!(!floor.admit("wss://a", f, t0 + Duration::from_secs(5)));

        assert!(floor.admit("wss://b", f, t0 + Duration::from_secs(6)));

        assert!(floor.admit("wss://a", f, t0 + Duration::from_secs(31)));
        assert!(!floor.admit("wss://a", f, t0 + Duration::from_secs(32)));

        assert!(floor.admit("wss://a", Duration::ZERO, t0 + Duration::from_secs(33)));

        assert!(floor.admit("wss://c", f, t0 + Duration::from_secs(62)));
        assert!(
            floor.last_sent.len() <= 2,
            "stale entries must be pruned: {:?}",
            floor.last_sent.keys()
        );
    }

    // ------------------------------------------------------------------
    // Configured peers: one set, kept, not muted, redialled, a dial policy,
    // and the only relays GRASP-P events travel to and from
    // ------------------------------------------------------------------

    use crate::nostr::persistence::SaveContext;

    const INTERVAL: Duration = Duration::from_secs(300);
    /// A loopback peer, a second one, and a relay no setting names.
    const PEER: &str = "ws://127.0.0.1:1";
    const OTHER_PEER: &str = "ws://127.0.0.1:3";
    const STRANGER: &str = "ws://127.0.0.1:2";
    /// The address the test nodes serve under.
    const SERVICE: &str = "service.example";

    /// A sync manager with GRASP-P enabled and upstream's target policy
    /// permissive, as changed by `configure`, and `bootstrap` as its
    /// bootstrap relay. The relay and its GRASP-P service are built from
    /// the final settings, as at startup, so the service, and the peer set
    /// it holds, exists exactly when `configure` leaves GRASP-P on.
    ///
    /// No dial ever starts: the dial workers are given no slot, so a
    /// scheduled dial stays queued (`Connecting`) until the test reports its
    /// outcome with [`fail_dial`]. Nothing here opens a socket.
    async fn peer_test_manager(
        bootstrap: Option<&str>,
        configure: impl FnOnce(&mut Config),
    ) -> (SyncManager, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::for_testing();
        config.domain = SERVICE.to_string();
        config.git_data_path = directory.path().join("git").to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        config.private_repos_enable = true;
        config.sync_allow_non_global_targets = true;
        config.sync_bootstrap_relay_url = bootstrap.map(str::to_string);
        configure(&mut config);
        let git_path = PathBuf::from(&config.git_data_path);
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_path.clone()));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            runtime.write_policy.grasp_p().is_some(),
            config.private_repos_enable,
            "the service exists exactly when GRASP-P is on"
        );
        let mut manager = SyncManager::new(
            config.sync_bootstrap_relay_url.clone(),
            config.service_address(),
            runtime.stores.database.clone(),
            runtime.write_policy,
            runtime.relay,
            &config,
            git_path,
            None,
            None,
            None,
        );
        manager.connect_attempt_semaphore = Arc::new(Semaphore::new(0));
        let (result_tx, _result_rx) = tokio::sync::mpsc::channel(8);
        manager.connect_attempt_result_tx = Some(result_tx);
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);
        manager.shutdown_tx = Some(shutdown_tx);
        (manager, directory)
    }

    fn key(url: &str) -> String {
        canonical_relay_key(url).unwrap()
    }

    async fn status(manager: &SyncManager, relay: &str) -> Option<ConnectionStatus> {
        manager
            .relay_sync_index
            .read()
            .await
            .get(relay)
            .map(|state| state.connection_status)
    }

    async fn set_status(manager: &SyncManager, relay: &str, status: ConnectionStatus) {
        manager
            .relay_sync_index
            .write()
            .await
            .get_mut(relay)
            .expect("the relay is tracked")
            .connection_status = status;
    }

    /// Report the queued dial of `relay` as failed with `error`, the way the
    /// dial worker would.
    async fn fail_dial(manager: &mut SyncManager, relay: &str, error: &str) {
        let token = *manager
            .in_flight_connect_attempts
            .get(relay)
            .expect("a dial of the relay is queued");
        manager
            .handle_connect_attempt_result(ConnectAttemptResult {
                relay_url: relay.to_string(),
                token,
                outcome: ConnectAttemptOutcome::Failed(error.to_string()),
            })
            .await;
    }

    /// A stored stream wrap from a key no registration holds: admission
    /// refuses it with a rejection a later registration can cure, so a
    /// peer's copy is held. The counter keeps every id distinct.
    fn unregistered_wrap() -> Event {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        EventBuilder::new(
            Kind::Custom(crate::grasp_p::KIND_STREAM_WRAP),
            format!("ciphertext {n}"),
        )
        .finalize(&Keys::generate())
        .unwrap()
    }

    /// Hand `event` to the event pipeline as relay sync from `relay` would.
    async fn synced_from(
        manager: &SyncManager,
        event: &Event,
        relay: &str,
        context: SaveContext,
    ) -> ProcessResult {
        SyncManager::process_event_static(
            event,
            relay,
            &manager.database,
            &manager.write_policy,
            &manager.local_relay,
            &manager.rejected_events_index,
            context,
        )
        .await
    }

    fn is_held(manager: &SyncManager, event: &Event) -> bool {
        manager
            .write_policy
            .grasp_p()
            .expect("GRASP-P is on")
            .sync_rejected()
            .contains(&event.id)
    }

    /// Whether `filters` hold any filter that asks for a GRASP-P kind.
    fn asks_for_grasp_p(filters: &[Filter]) -> bool {
        let grasp_p_kinds = [
            crate::grasp_p::KIND_REGISTRATION,
            crate::grasp_p::KIND_STATE_ROOT,
            crate::grasp_p::KIND_STREAM_WRAP,
            crate::grasp_p::KIND_WRAP,
        ];
        filters.iter().any(|filter| {
            filter.kinds.as_ref().is_some_and(|kinds| {
                kinds
                    .iter()
                    .any(|kind| grasp_p_kinds.contains(&kind.as_u16()))
            })
        })
    }

    /// C3, the rule alone: one dial per interval per peer, counted from the
    /// latest of this redial's own dial and anybody's attempt or failure.
    #[test]
    fn peer_redial_admits_one_dial_per_interval() {
        let mut redial = PeerRedial::default();
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);

        // Never dialled and never failed: due at once, and then not again.
        assert!(redial.admit("a", None, at(0), INTERVAL));
        assert!(!redial.admit("a", None, at(1), INTERVAL));
        assert!(!redial.admit("a", None, at(299), INTERVAL));
        assert!(redial.admit("a", None, at(300), INTERVAL));
        assert!(!redial.admit("a", None, at(301), INTERVAL));

        // Each peer has its own clock.
        assert!(redial.admit("b", None, at(301), INTERVAL));

        // Upstream dialled, or saw a failure, at 700: the interval starts
        // again there, although this redial's own dial is long ago.
        assert!(!redial.admit("a", Some(at(700)), at(900), INTERVAL));
        assert!(redial.admit("a", Some(at(700)), at(1000), INTERVAL));
        // An activity older than this redial's own dial does not shorten it.
        assert!(!redial.admit("a", Some(at(700)), at(1299), INTERVAL));
        assert!(redial.admit("a", Some(at(700)), at(1300), INTERVAL));

        // A clock reading behind the record is "not yet", never a panic.
        assert!(!redial.admit("a", Some(at(5000)), at(1301), INTERVAL));

        // A relay that is no longer a peer is forgotten.
        redial.retain(&HashSet::from(["a".to_string()]));
        assert_eq!(redial.issued.len(), 1);
        assert!(redial.issued.contains_key("a"));
    }

    /// The one set C1 to C4, the filters and the ingress gate work on: the
    /// listed peers, held by the service, compared in any spelling the sync
    /// code files under the same key. Never this node, never a bootstrap
    /// relay the list does not name, and nothing with GRASP-P off.
    #[tokio::test]
    async fn the_peer_set_is_the_list_alone() {
        // A bootstrap relay the list does not name is not a peer.
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(format!("{PEER}/, wss://{SERVICE}"));
        })
        .await;
        let service = manager.write_policy.grasp_p().expect("GRASP-P is on");
        assert_eq!(service.sync_peer_relays(), &HashSet::from([key(PEER)]));
        assert_eq!(manager.grasp_p_peer_relays(), HashSet::from([key(PEER)]));
        for spelling in [PEER, "ws://127.0.0.1:1/"] {
            assert!(manager.grasp_p_is_peer(spelling), "{spelling}");
        }
        let own = format!("wss://{SERVICE}");
        for not_a_peer in [OTHER_PEER, STRANGER, own.as_str()] {
            assert!(!manager.grasp_p_is_peer(not_a_peer), "{not_a_peer}");
            assert!(manager.grasp_p_peer_needs(not_a_peer).is_none());
            assert!(manager.grasp_p_naughty_mute_applies(not_a_peer));
        }
        manager.shutdown().await;

        // A bootstrap relay the list names is a peer like any listed one.
        let (mut manager, _directory) = peer_test_manager(Some(PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        assert_eq!(manager.grasp_p_peer_relays(), HashSet::from([key(PEER)]));
        manager.shutdown().await;

        // With GRASP-P off there is no service and no peer, whatever the
        // settings say.
        let (mut manager, _directory) = peer_test_manager(Some(PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
            config.private_mirror_allow_private_ips = true;
            config.private_repos_enable = false;
        })
        .await;
        assert!(manager.grasp_p_peer_relays().is_empty());
        assert!(!manager.grasp_p_is_peer(PEER));
        assert!(manager.grasp_p_peer_needs(&key(PEER)).is_none());
        assert!(manager.grasp_p_naughty_mute_applies(&key(PEER)));
        assert!(manager.grasp_p_peer_policy(&key(PEER)).is_none());
        assert!(manager.grasp_p_filters_for(PEER).is_empty());
        manager.shutdown().await;
    }

    /// C1: a session that ends leaves a configured peer tracked and
    /// disconnected, with its connection and its health record, also when
    /// the peer is the bootstrap relay as well. A bootstrap relay the list
    /// does not name is retired like any other relay, as in upstream.
    #[tokio::test]
    async fn configured_peer_survives_an_ended_session() {
        let both = format!("{PEER},{OTHER_PEER}");
        let cases: [(&str, &[&str], &[&str]); 2] = [
            // (peer list, kept, retired)
            (PEER, &[PEER], &[OTHER_PEER, STRANGER]),
            (both.as_str(), &[PEER, OTHER_PEER], &[STRANGER]),
        ];
        for (listed, kept, retired) in cases {
            let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
                config.private_sync_peer_urls = Some(listed.to_string());
            })
            .await;
            assert!(manager.register_relay(key(PEER), false, false).await);
            assert!(manager.register_relay(key(OTHER_PEER), true, false).await);
            assert!(manager.register_relay(key(STRANGER), false, false).await);

            for relay in [PEER, OTHER_PEER, STRANGER].map(key) {
                set_status(&manager, &relay, ConnectionStatus::Connected).await;
                manager.handle_disconnect(&relay).await;
            }

            for relay in kept.iter().copied().map(key) {
                assert_eq!(
                    status(&manager, &relay).await,
                    Some(ConnectionStatus::Disconnected),
                    "list {listed}: {relay} must stay tracked"
                );
                assert!(manager.connections.contains_key(&relay), "{relay}");
                assert_eq!(
                    manager.health_tracker.get_failure_count(&relay),
                    1,
                    "the ended session of {relay} is a failure upstream's backoff counts"
                );
            }
            for relay in retired.iter().copied().map(key) {
                assert_eq!(
                    status(&manager, &relay).await,
                    None,
                    "list {listed}: {relay}"
                );
                assert!(!manager.connections.contains_key(&relay), "{relay}");
            }
            manager.shutdown().await;
        }
    }

    /// C1 is GRASP-P's alone: with it off, the same settings keep nothing.
    #[tokio::test]
    async fn ended_session_retires_every_relay_with_grasp_p_off() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(format!("{PEER},{OTHER_PEER}"));
            config.private_repos_enable = false;
        })
        .await;
        let (peer, bootstrap) = (key(PEER), key(OTHER_PEER));
        assert!(manager.register_relay(peer.clone(), false, false).await);
        assert!(manager.register_relay(bootstrap.clone(), true, false).await);

        for relay in [&peer, &bootstrap] {
            set_status(&manager, relay, ConnectionStatus::Connected).await;
            manager.handle_disconnect(relay).await;
            assert_eq!(status(&manager, relay).await, None, "{relay}");
            assert!(!manager.connections.contains_key(relay), "{relay}");
        }
        manager.shutdown().await;
    }

    /// C1, the other way a relay is retired: the periodic check drops a
    /// disconnected relay that nothing wants. A configured peer is wanted.
    /// The bootstrap relay stays too, listed or not, by upstream's own rule:
    /// that check never drops it.
    #[tokio::test]
    async fn disconnected_configured_peer_survives_the_disconnect_check() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        let (peer, bootstrap, stranger) = (key(PEER), key(OTHER_PEER), key(STRANGER));
        assert!(manager.register_relay(peer.clone(), false, false).await);
        assert!(manager.register_relay(bootstrap.clone(), true, false).await);
        assert!(manager.register_relay(stranger.clone(), false, false).await);

        manager.check_disconnects().await;

        for kept in [&peer, &bootstrap] {
            assert_eq!(
                status(&manager, kept).await,
                Some(ConnectionStatus::Disconnected),
                "{kept}"
            );
            assert!(manager.connections.contains_key(kept), "{kept}");
        }
        assert_eq!(status(&manager, &stranger).await, None);
        manager.shutdown().await;
    }

    /// C1 on a live session: a connected peer whose history is synced and
    /// that carries no public repository is not an empty relay the check
    /// disconnects. Any other relay in that state is.
    #[tokio::test]
    async fn connected_peer_is_not_an_empty_relay_disconnect_candidate() {
        let (mut manager, _directory) = peer_test_manager(None, |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        let (peer, stranger) = (key(PEER), key(STRANGER));
        for relay in [&peer, &stranger] {
            assert!(manager.register_relay(relay.clone(), false, false).await);
            let mut index = manager.relay_sync_index.write().await;
            let state = index.get_mut(relay).expect("the relay is tracked");
            state.connection_status = ConnectionStatus::Connected;
            state.historic_sync_completed = true;
        }

        manager.check_disconnects().await;

        assert_eq!(
            status(&manager, &peer).await,
            Some(ConnectionStatus::Connected)
        );
        assert_eq!(
            status(&manager, &stranger).await,
            Some(ConnectionStatus::Disconnecting),
            "an empty relay that is not a peer is disconnected, as in upstream"
        );
        manager.shutdown().await;
    }

    /// The reconnect loop counts a configured peer as wanted, so a peer
    /// whose first dial failed is dialled again; it does that for the
    /// bootstrap relay only when the list names it. Upstream's loop does not
    /// count its own bootstrap relay as wanted, and a bootstrap relay that
    /// is not a peer keeps that rule.
    #[tokio::test]
    async fn failed_first_dial_of_the_bootstrap_relay_is_retried_only_when_listed() {
        // (GRASP-P, the list names the bootstrap relay, status after the loop)
        for (grasp_p, listed, expected) in [
            (true, true, ConnectionStatus::Connecting),
            (true, false, ConnectionStatus::Disconnected),
            // Upstream as it is. If upstream starts to redial its bootstrap
            // relay, these two rows change and nothing else does.
            (false, true, ConnectionStatus::Disconnected),
        ] {
            let (mut manager, _directory) = peer_test_manager(Some(PEER), |config| {
                config.private_repos_enable = grasp_p;
                config.private_sync_peer_urls = listed.then(|| PEER.to_string());
                // No wait between dials, so the loop is due at once.
                config.sync_max_backoff_secs = 0;
            })
            .await;
            let peer = key(PEER);
            assert!(manager.register_relay(peer.clone(), true, false).await);
            manager.schedule_connect_relay(&peer).await;
            fail_dial(&mut manager, &peer, "Connection refused").await;
            assert_eq!(
                status(&manager, &peer).await,
                Some(ConnectionStatus::Disconnected)
            );

            manager.retry_disconnected_relays().await;

            assert_eq!(
                status(&manager, &peer).await,
                Some(expected),
                "GRASP-P {grasp_p}, listed {listed}"
            );
            manager.shutdown().await;
        }
    }

    /// C2 and C3 together: a certificate failure puts a peer on the naughty
    /// list like any relay, upstream's loop then leaves it alone, and the
    /// bounded redial still dials it. A relay that is not a peer stays
    /// muted, the bootstrap relay included when the list does not name it.
    #[tokio::test]
    async fn naughty_list_does_not_mute_a_configured_peer() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
            config.sync_max_backoff_secs = 0;
        })
        .await;
        let (peer, bootstrap, stranger) = (key(PEER), key(OTHER_PEER), key(STRANGER));
        assert!(manager.register_relay(peer.clone(), false, false).await);
        assert!(manager.register_relay(bootstrap.clone(), true, false).await);
        assert!(manager.register_relay(stranger.clone(), false, false).await);
        let naughty = manager.health_tracker.naughty_list().unwrap();

        // The entry is recorded for a peer exactly as for any relay.
        manager.schedule_connect_relay(&peer).await;
        fail_dial(
            &mut manager,
            &peer,
            "Failed to connect to relay: invalid peer certificate: UnknownIssuer",
        )
        .await;
        assert!(naughty.is_naughty(&peer));
        assert_eq!(
            naughty.get_entry(&peer).map(|entry| entry.category),
            Some(crate::sync::naughty_list::NaughtyCategory::TlsCertificateInvalid)
        );
        for muted in [&stranger, &bootstrap] {
            naughty.record(
                muted,
                crate::sync::naughty_list::NaughtyCategory::TlsCertificateInvalid,
                "invalid peer certificate".to_string(),
            );
        }

        // Upstream's loop dials none of them while the entries stand.
        manager.retry_disconnected_relays().await;
        assert_eq!(
            status(&manager, &peer).await,
            Some(ConnectionStatus::Disconnected)
        );

        // A dial that is asked for goes through for the peer only.
        for muted in [&stranger, &bootstrap] {
            manager.schedule_connect_relay(muted).await;
            assert_eq!(
                status(&manager, muted).await,
                Some(ConnectionStatus::Disconnected),
                "{muted}"
            );
        }
        let later = Instant::now() + INTERVAL + Duration::from_secs(10);
        manager.grasp_p_redial_peers(later, INTERVAL).await;
        assert_eq!(
            status(&manager, &peer).await,
            Some(ConnectionStatus::Connecting)
        );
        for muted in [&stranger, &bootstrap] {
            assert_eq!(
                status(&manager, muted).await,
                Some(ConnectionStatus::Disconnected),
                "the redial is for configured peers only: {muted}"
            );
        }
        assert!(naughty.is_naughty(&peer), "the entry is not cleared");
        manager.shutdown().await;
    }

    /// C3 on the manager: a disconnected peer is dialled once per interval,
    /// counted from its last failure, and never while a dial of it is
    /// queued or running.
    #[tokio::test]
    async fn disconnected_peer_is_redialled_once_per_interval() {
        let (mut manager, _directory) = peer_test_manager(None, |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        let peer = key(PEER);
        assert!(manager.register_relay(peer.clone(), false, false).await);
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);

        // Never dialled: due at once.
        manager.grasp_p_redial_peers(at(0), INTERVAL).await;
        assert_eq!(
            status(&manager, &peer).await,
            Some(ConnectionStatus::Connecting)
        );
        // While that dial is queued nothing more is issued, however late.
        manager.grasp_p_redial_peers(at(10_000), INTERVAL).await;
        assert_eq!(manager.in_flight_connect_attempts.len(), 1);
        assert_eq!(manager.next_connect_attempt_token, 1);

        // The dial fails now, a moment after `t0` on the real clock.
        fail_dial(&mut manager, &peer, "Connection refused").await;
        assert_eq!(
            status(&manager, &peer).await,
            Some(ConnectionStatus::Disconnected)
        );
        for too_early in [10, 150, 299] {
            manager.grasp_p_redial_peers(at(too_early), INTERVAL).await;
            assert_eq!(
                status(&manager, &peer).await,
                Some(ConnectionStatus::Disconnected),
                "{too_early} s"
            );
        }
        // Well past the interval, so the moment between `t0` and the
        // failure does not decide the outcome.
        manager.grasp_p_redial_peers(at(330), INTERVAL).await;
        assert_eq!(
            status(&manager, &peer).await,
            Some(ConnectionStatus::Connecting)
        );

        // A session can end while a dial of the same relay is still queued.
        // The peer then reads as disconnected, and must still not get a
        // second dial.
        set_status(&manager, &peer, ConnectionStatus::Disconnected).await;
        manager.grasp_p_redial_peers(at(20_000), INTERVAL).await;
        assert_eq!(
            status(&manager, &peer).await,
            Some(ConnectionStatus::Disconnected)
        );
        assert_eq!(manager.next_connect_attempt_token, 2, "two dials in all");
        manager.shutdown().await;
    }

    /// C4: only a configured peer, and only when the operator has said the
    /// pair's link is private, is registered on an internal address with
    /// upstream's guard on. Everything else keeps the node's own policy, a
    /// bootstrap relay the list does not name included (it is upstream's
    /// operator-configured target, which no policy is asked about).
    #[tokio::test]
    async fn only_a_configured_peer_on_a_private_link_gets_a_permissive_policy() {
        const PRIVATE_PEER: &str = "ws://10.0.0.5:7777";
        const PRIVATE_STRANGER: &str = "ws://10.0.0.6:7777";
        const PRIVATE_BOOTSTRAP: &str = "ws://10.0.0.7:7777";

        // (GRASP-P, link declared private, the peer is registered)
        for (grasp_p, private_link, registered) in [
            (true, true, true),
            (true, false, false),
            (false, true, false),
        ] {
            let (mut manager, _directory) = peer_test_manager(Some(PRIVATE_BOOTSTRAP), |config| {
                config.sync_allow_non_global_targets = false;
                config.private_repos_enable = grasp_p;
                config.private_mirror_allow_private_ips = private_link;
                config.private_sync_peer_urls = Some(PRIVATE_PEER.to_string());
            })
            .await;
            let (peer, stranger) = (key(PRIVATE_PEER), key(PRIVATE_STRANGER));
            let case = format!("GRASP-P {grasp_p}, private link {private_link}");

            assert_eq!(
                manager
                    .grasp_p_peer_policy(&peer)
                    .map(|policy| policy.allow_non_global),
                registered.then_some(true),
                "{case}"
            );
            assert!(manager.grasp_p_peer_policy(&stranger).is_none(), "{case}");
            assert!(
                manager
                    .grasp_p_peer_policy(&key(PRIVATE_BOOTSTRAP))
                    .is_none(),
                "{case}"
            );

            assert_eq!(
                manager.register_relay(peer.clone(), false, false).await,
                registered,
                "{case}"
            );
            // A relay that an event names never shares the exception.
            assert!(
                !manager.register_relay(stranger.clone(), false, false).await,
                "{case}"
            );
            manager.shutdown().await;
        }
    }

    /// On a GRASP-P node a relay that an event names is registered over
    /// wss:// only, on the repository path and the NIP-65 path alike, and a
    /// ws:// one is refused through upstream's own branch: no connection,
    /// remembered as refused. A configured peer keeps ws:// only on a link
    /// declared private, and `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS` lifts the
    /// rule. The bootstrap relay is the operator's: registered as written in
    /// every case, an event that names exactly its URL shares its
    /// connection, and once its session has ended upstream registers it
    /// again as event-directed, still as written. With GRASP-P off every row
    /// is upstream's. The names are
    /// public, so upstream's policy passes all of them without a lookup:
    /// every refusal here is the scheme's.
    #[tokio::test]
    async fn a_relay_an_event_names_is_registered_over_wss_only() {
        const PLAIN: &str = "ws://relay.example.com";
        const PLAIN_OUTBOX: &str = "ws://outbox.example.com";
        const TLS: &str = "wss://relay.example.com";
        const PLAIN_PEER: &str = "ws://peer.example.com";
        const PLAIN_BOOTSTRAP: &str = "ws://bootstrap.example.com";

        // (GRASP-P, non-global targets allowed, link declared private) ->
        // whether a ws:// relay an event names, and the ws:// peer, register
        for (grasp_p, allow_non_global, private_link, stranger_registered, peer_registered) in [
            (true, false, false, false, false),
            (true, false, true, false, true),
            (true, true, false, true, true),
            (false, false, false, true, true),
        ] {
            let (mut manager, _directory) = peer_test_manager(Some(PLAIN_BOOTSTRAP), |config| {
                config.private_repos_enable = grasp_p;
                config.sync_allow_non_global_targets = allow_non_global;
                config.private_mirror_allow_private_ips = private_link;
                config.private_sync_peer_urls = Some(PLAIN_PEER.to_string());
            })
            .await;
            let case = format!(
                "GRASP-P {grasp_p}, non-global {allow_non_global}, private link {private_link}"
            );

            assert!(
                manager
                    .register_relay(key(PLAIN_BOOTSTRAP), true, false)
                    .await,
                "{case}"
            );
            assert!(
                manager
                    .register_relay(key(PLAIN_BOOTSTRAP), false, false)
                    .await,
                "{case}"
            );
            assert!(
                manager.register_relay(key(TLS), false, false).await,
                "{case}"
            );

            for (relay, nip65_discovery_only) in [(PLAIN, false), (PLAIN_OUTBOX, true)] {
                let relay = key(relay);
                assert_eq!(
                    manager
                        .register_relay(relay.clone(), false, nip65_discovery_only)
                        .await,
                    stranger_registered,
                    "{case}: {relay}"
                );
                assert_eq!(
                    manager.connections.contains_key(&relay),
                    stranger_registered,
                    "{case}: {relay}"
                );
                assert_eq!(
                    manager.rejected_relay_targets.contains(&relay),
                    !stranger_registered,
                    "{case}: {relay}"
                );
            }

            assert_eq!(
                manager.register_relay(key(PLAIN_PEER), false, false).await,
                peer_registered,
                "{case}"
            );
            assert!(
                !manager.rejected_relay_targets.contains(&key(TLS)),
                "{case}"
            );

            // Its session over and nothing owning it, the bootstrap relay
            // loses its connection; upstream's ways back register it as
            // event-directed.
            manager
                .complete_ended_session(&key(PLAIN_BOOTSTRAP), false)
                .await;
            assert!(
                !manager.connections.contains_key(&key(PLAIN_BOOTSTRAP)),
                "{case}"
            );
            assert!(
                manager
                    .register_relay(key(PLAIN_BOOTSTRAP), false, true)
                    .await,
                "{case}: the bootstrap relay keeps ws:// after its session ends"
            );
            assert!(
                !manager
                    .rejected_relay_targets
                    .contains(&key(PLAIN_BOOTSTRAP)),
                "{case}"
            );
            manager.shutdown().await;
        }
    }

    /// NIP-65 discovery dials one new source per pass, the lowest key it has
    /// no connection to, and a ws:// key sorts before every wss:// one. A
    /// source the wss:// rule refused never connects, so it must not be
    /// picked again: the first pass refuses it through upstream's branch
    /// (logged once and remembered), and the next dials the wss:// source.
    /// With GRASP-P off the ws:// source is dialled, as upstream picks it.
    #[tokio::test]
    async fn a_refused_discovery_source_does_not_hold_back_the_others() {
        let plain = key("ws://outbox.example.com");
        let tls = key("wss://outbox.example.com");
        for grasp_p in [true, false] {
            let (mut manager, _directory) = peer_test_manager(None, |config| {
                config.private_repos_enable = grasp_p;
                config.sync_allow_non_global_targets = false;
                config.sync_plus_enabled = true;
            })
            .await;
            // No inventory is due, so each pass works from these sources.
            manager.nip65_discovery.next_inventory_at =
                Some(Instant::now() + Duration::from_secs(3600));
            manager.nip65_discovery.author_sources.insert(
                Keys::generate().public_key(),
                HashSet::from([plain.clone(), tls.clone()]),
            );

            manager.schedule_nip65_discovery().await;
            assert_eq!(manager.connections.contains_key(&plain), !grasp_p);
            assert_eq!(manager.rejected_relay_targets.contains(&plain), grasp_p);
            assert!(!manager.connections.contains_key(&tls), "GRASP-P {grasp_p}");

            if grasp_p {
                manager.schedule_nip65_discovery().await;
                assert!(
                    manager.connections.contains_key(&tls),
                    "the wss:// source is dialled on the next pass"
                );
                assert!(!manager.connections.contains_key(&plain));
            }
            manager.shutdown().await;
        }
    }

    /// Egress: the private filters, which name every alias and key the node
    /// holds, are for a configured peer, in any spelling of its key, and for
    /// no other relay: not the bootstrap relay the list does not name, not a
    /// relay an event names, and none at all with GRASP-P off.
    #[tokio::test]
    async fn grasp_p_filters_go_only_to_configured_peers() {
        let registration = filters::build_private_registration_filter(None);
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        for spelling in [PEER, "ws://127.0.0.1:1/"] {
            assert!(
                manager
                    .grasp_p_filters_for(spelling)
                    .contains(&registration),
                "{spelling}"
            );
        }
        for not_a_peer in [OTHER_PEER, STRANGER] {
            assert!(
                manager.grasp_p_filters_for(not_a_peer).is_empty(),
                "{not_a_peer}"
            );
        }
        manager.shutdown().await;

        let (mut manager, _directory) = peer_test_manager(None, |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
            config.private_repos_enable = false;
        })
        .await;
        assert!(manager.grasp_p_filters_for(PEER).is_empty());
        manager.shutdown().await;
    }

    /// Egress through upstream's builder: the complete live coverage of a
    /// connection carries the private filters for a peer only. It fails
    /// when the seam in `complete_live_filters` goes.
    #[tokio::test]
    async fn complete_live_filters_carry_grasp_p_only_for_a_peer() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        assert!(manager.register_relay(key(PEER), false, false).await);
        assert!(manager.register_relay(key(OTHER_PEER), true, false).await);
        assert!(manager.register_relay(key(STRANGER), false, false).await);
        let announcements = filters::build_announcement_filter(None);
        let registration = filters::build_private_registration_filter(None);

        let peer = manager.complete_live_filters(&key(PEER), None).await;
        assert!(peer.contains(&announcements) && peer.contains(&registration));
        for not_a_peer in [OTHER_PEER, STRANGER] {
            let coverage = manager.complete_live_filters(&key(not_a_peer), None).await;
            assert!(coverage.contains(&announcements), "{not_a_peer}");
            assert!(
                !asks_for_grasp_p(&coverage),
                "{not_a_peer} must not be asked for GRASP-P events: {coverage:?}"
            );
        }
        manager.shutdown().await;
    }

    /// The pair sees the same deletion: the offboard filter selects every
    /// kind 5 that deletes a registration and nothing else, and the vanish
    /// filters select the vanishes of the accounts listed, each once, at
    /// most 100 to a filter.
    #[test]
    fn private_deletion_filters_ask_for_offboard_requests_and_account_vanishes() {
        let opts = MatchEventOptions::new();
        let account = Keys::generate();
        let stranger = Keys::generate();
        let request = |kind: Kind, tags: Vec<Tag>, keys: &Keys| {
            EventBuilder::new(kind, "")
                .tags(tags)
                .finalize(keys)
                .expect("sign")
        };
        let coordinate = Tag::custom(
            "a",
            vec![format!(
                "30640:{}:{}",
                account.public_key().to_hex(),
                "a".repeat(32)
            )],
        );
        let k = |kind: &str| Tag::custom("k", vec![kind.to_string()]);

        let offboard = build_private_offboard_filter(None);
        assert_eq!(offboard.since, None);
        let with_k = request(
            Kind::EventDeletion,
            vec![coordinate.clone(), k("30640")],
            &account,
        );
        assert!(offboard.match_event(&with_k, opts));
        for (what, event) in [
            (
                "no k tag",
                request(Kind::EventDeletion, vec![coordinate.clone()], &account),
            ),
            (
                "another k",
                request(Kind::EventDeletion, vec![k("1")], &stranger),
            ),
            (
                "a vanish",
                request(Kind::RequestToVanish, vec![k("30640")], &account),
            ),
        ] {
            assert!(!offboard.match_event(&event, opts), "{what}");
        }
        let since = Timestamp::from_secs(1_000);
        assert_eq!(
            build_private_offboard_filter(Some(since)).since,
            Some(since)
        );

        assert!(build_private_vanish_filters(&[], None).is_empty());
        let mut tenants: Vec<String> = (0..250)
            .map(|_| Keys::generate().public_key().to_hex())
            .collect();
        tenants.push(tenants[0].clone());
        tenants.push("not a key".to_string());
        tenants.push(account.public_key().to_hex());
        let vanish = build_private_vanish_filters(&tenants, None);
        assert_eq!(vanish.len(), 3);
        let mut listed = HashSet::new();
        for filter in &vanish {
            assert_eq!(
                filter
                    .kinds
                    .as_ref()
                    .expect("kinds")
                    .iter()
                    .collect::<Vec<_>>(),
                vec![&Kind::RequestToVanish]
            );
            let authors = filter.authors.as_ref().expect("authors");
            assert!(authors.len() <= 100);
            for author in authors {
                assert!(listed.insert(*author), "{author} listed twice");
            }
        }
        assert_eq!(listed.len(), 251);
        let by_account = request(Kind::RequestToVanish, vec![], &account);
        let by_stranger = request(Kind::RequestToVanish, vec![], &stranger);
        assert!(vanish.iter().any(|f| f.match_event(&by_account, opts)));
        assert!(!vanish.iter().any(|f| f.match_event(&by_stranger, opts)));
        assert!(!vanish.iter().any(|f| f.match_event(&with_k, opts)));
        assert!(build_private_vanish_filters(&tenants, Some(since))
            .iter()
            .all(|f| f.since == Some(since)));
    }

    /// The deletion filters ride a peer's set and no other relay's: the
    /// offboard-request filter always, and the vanish filter of every
    /// account the index holds, which the index-change set
    /// (`grasp_p_index_filters`) carries too. A relay that is not a peer is
    /// asked for neither, so a deletion reaches the other node of the pair
    /// and goes nowhere else.
    #[tokio::test]
    async fn deletion_filters_go_only_to_configured_peers() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        let tenant = Keys::generate().public_key().to_hex();
        let writer = Keys::generate().public_key().to_hex();
        manager.grasp_p.index.replace_all(HashMap::from([(
            "a".repeat(32),
            private_index::PrivateRepoEntry {
                tenant_hex: tenant.clone(),
                keys: vec![writer],
                ..Default::default()
            },
        )]));
        let offboard = build_private_offboard_filter(None);
        let vanish = build_private_vanish_filters(&[tenant], None);
        assert_eq!(vanish.len(), 1);

        let for_peer = manager.grasp_p_filters_for(PEER);
        assert!(for_peer.contains(&offboard) && for_peer.contains(&vanish[0]));
        let on_index_change = manager.grasp_p_index_filters();
        assert!(on_index_change.contains(&vanish[0]));
        for not_a_peer in [OTHER_PEER, STRANGER] {
            assert!(
                manager.grasp_p_filters_for(not_a_peer).is_empty(),
                "{not_a_peer}"
            );
        }

        // The whole live coverage of a connection, through upstream's
        // builder.
        assert!(manager.register_relay(key(PEER), false, false).await);
        assert!(manager.register_relay(key(OTHER_PEER), true, false).await);
        assert!(manager.register_relay(key(STRANGER), false, false).await);
        let coverage = manager.complete_live_filters(&key(PEER), None).await;
        assert!(coverage.contains(&offboard) && coverage.contains(&vanish[0]));
        for not_a_peer in [OTHER_PEER, STRANGER] {
            let coverage = manager.complete_live_filters(&key(not_a_peer), None).await;
            assert!(
                !coverage
                    .iter()
                    .any(|filter| filter.kinds.as_ref().is_some_and(|kinds| {
                        kinds.contains(&Kind::EventDeletion)
                            || kinds.contains(&Kind::RequestToVanish)
                    })),
                "{not_a_peer} must not be asked for deletion requests: {coverage:?}"
            );
        }
        manager.shutdown().await;
    }

    /// Egress on a re-issue: it goes to the peers whose live subscriptions
    /// are open, and to no other live relay. A non-peer that is syncing (a
    /// NIP-65 source, the bootstrap relay the list does not name) is left
    /// alone, and so is a peer that is down.
    #[tokio::test]
    async fn reissue_targets_only_live_configured_peers() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(format!("{PEER},ws://127.0.0.1:4"));
        })
        .await;
        let down_peer = key("ws://127.0.0.1:4");
        assert!(manager.register_relay(key(PEER), false, false).await);
        assert!(manager.register_relay(key(OTHER_PEER), true, false).await);
        assert!(manager.register_relay(key(STRANGER), false, false).await);
        assert!(
            manager
                .register_relay(down_peer.clone(), false, false)
                .await
        );
        for relay in [PEER, OTHER_PEER, STRANGER].map(key) {
            set_status(&manager, &relay, ConnectionStatus::Syncing).await;
        }
        assert_eq!(
            status(&manager, &down_peer).await,
            Some(ConnectionStatus::Disconnected)
        );

        assert_eq!(manager.grasp_p_live_peers().await, vec![key(PEER)]);

        // The re-issue itself goes to that set. Without a connection object
        // sync_live and historic_sync return at once, so nothing is dialled.
        for relay in [PEER, OTHER_PEER, STRANGER].map(key) {
            manager.connections.remove(&relay);
        }
        let outcome = manager
            .grasp_p_reissue_to_live_relays(vec![filters::build_private_registration_filter(None)])
            .await;
        assert_eq!(outcome.sent, 1);
        assert_eq!(
            manager
                .grasp_p
                .reissue_floor
                .last_sent
                .keys()
                .cloned()
                .collect::<HashSet<_>>(),
            HashSet::from([key(PEER)])
        );
        manager.shutdown().await;
    }

    /// Ingress: a GRASP-P event that relay sync brings from a relay that is
    /// not a peer is refused as blocked before admission. It is not held,
    /// not remembered by id and not stored, so the same event from the peer
    /// is admitted as ever: here, held for its registration. It fails when
    /// the seam in `process_event_static_inner` goes.
    #[tokio::test]
    async fn grasp_p_event_from_a_non_peer_is_refused_before_admission_and_not_held() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        let wrap = unregistered_wrap();

        for not_a_peer in [STRANGER, OTHER_PEER] {
            assert_eq!(
                synced_from(&manager, &wrap, not_a_peer, SaveContext::RelaySync).await,
                ProcessResult::Rejected(PolicyRejection::Blocked),
                "{not_a_peer}"
            );
            assert!(!is_held(&manager, &wrap), "{not_a_peer}");
            assert!(manager
                .database
                .event_by_id(&wrap.id)
                .await
                .unwrap()
                .is_none());
        }

        // The peer, under another spelling of its key: admission runs.
        assert_eq!(
            synced_from(&manager, &wrap, "ws://127.0.0.1:1/", SaveContext::RelaySync).await,
            ProcessResult::Rejected(PolicyRejection::Restricted)
        );
        assert!(is_held(&manager, &wrap));
        manager.shutdown().await;
    }

    /// The gate is for relay sync alone. A held event that is tried again
    /// (it came from a peer or a client before it was held) reaches
    /// admission whatever name its retry carries, an event a client sends
    /// never passes here, an event of a public kind passes, and with GRASP-P
    /// off nothing is gated.
    #[tokio::test]
    async fn only_relay_sync_of_a_grasp_p_kind_from_a_non_peer_is_gated() {
        let (mut manager, _directory) = peer_test_manager(None, |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        let wrap = unregistered_wrap();
        let gate = |event: &Event, relay: &str, context: SaveContext| {
            SyncManager::grasp_p_gate(&manager.write_policy, event, relay, context)
        };

        assert_eq!(
            gate(&wrap, STRANGER, SaveContext::RelaySync),
            Some(ProcessResult::Rejected(PolicyRejection::Blocked))
        );
        // Every kind admission claims, stored and ephemeral; the legacy
        // kinds too, which the test settings still accept.
        for kind in [
            crate::grasp_p::KIND_REGISTRATION,
            crate::grasp_p::KIND_STATE_ROOT,
            crate::grasp_p::KIND_STREAM_WRAP,
            crate::grasp_p::KIND_EPHEMERAL_STREAM_WRAP,
            crate::grasp_p::KIND_WRAP,
            crate::grasp_p::KIND_EPHEMERAL_WRAP,
        ] {
            let event = EventBuilder::new(Kind::Custom(kind), "")
                .finalize(&Keys::generate())
                .unwrap();
            assert_eq!(
                gate(&event, STRANGER, SaveContext::RelaySync),
                Some(ProcessResult::Rejected(PolicyRejection::Blocked)),
                "kind {kind}"
            );
        }
        assert_eq!(gate(&wrap, PEER, SaveContext::RelaySync), None);
        assert_eq!(
            gate(
                &wrap,
                "grasp-p-30640-reprocess",
                SaveContext::HotCacheReprocess
            ),
            None
        );
        assert_eq!(
            gate(&wrap, STRANGER, SaveContext::DirectWritePolicyAcceptance),
            None
        );
        let public = EventBuilder::new(Kind::TextNote, "public")
            .finalize(&Keys::generate())
            .unwrap();
        assert_eq!(gate(&public, STRANGER, SaveContext::RelaySync), None);

        // A held event retried through the pipeline reaches admission.
        let retried = unregistered_wrap();
        assert_eq!(
            synced_from(
                &manager,
                &retried,
                "grasp-p-30640-reprocess",
                SaveContext::HotCacheReprocess
            )
            .await,
            ProcessResult::Rejected(PolicyRejection::Restricted)
        );
        assert!(is_held(&manager, &retried));
        manager.shutdown().await;

        let (mut manager, _directory) = peer_test_manager(None, |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
            config.private_repos_enable = false;
        })
        .await;
        assert_eq!(
            SyncManager::grasp_p_gate(
                &manager.write_policy,
                &wrap,
                STRANGER,
                SaveContext::RelaySync
            ),
            None
        );
        manager.shutdown().await;
    }

    /// A synced event of another kind that admission refuses for a
    /// reference to private-repository content is kept by id, and the live
    /// sync path then skips it as it skips a refused GRASP-P event. Fails
    /// if `grasp_p_previously_rejected` goes back to GRASP-P kinds only.
    #[tokio::test]
    async fn a_refused_event_of_another_kind_is_skipped_when_it_comes_again() {
        let (mut manager, _directory) = peer_test_manager(None, |_| {}).await;
        let wrap = unregistered_wrap();
        manager.database.save_event(&wrap).await.unwrap();
        let note = EventBuilder::new(Kind::TextNote, "")
            .tags(vec![Tag::event(wrap.id)])
            .finalize(&Keys::generate())
            .unwrap();
        assert!(!SyncManager::grasp_p_previously_rejected(
            &manager.write_policy,
            &note
        ));
        assert_eq!(
            synced_from(&manager, &note, PEER, SaveContext::RelaySync).await,
            ProcessResult::Rejected(PolicyRejection::Restricted)
        );
        assert!(is_held(&manager, &note));
        assert!(SyncManager::grasp_p_previously_rejected(
            &manager.write_policy,
            &note
        ));
        manager.shutdown().await;
    }

    /// Duplicate forwarding is on for a peer's connection alone, so every
    /// other connection of the node syncs as upstream's; the stricter
    /// address check stays on all of them. It fails when the seam in
    /// `register_relay` goes.
    #[tokio::test]
    async fn only_a_peer_connection_forwards_duplicates() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        assert!(manager.register_relay(key(PEER), false, false).await);
        assert!(manager.register_relay(key(OTHER_PEER), true, false).await);
        assert!(manager.register_relay(key(STRANGER), false, false).await);
        for (relay, forwards) in [(PEER, true), (OTHER_PEER, false), (STRANGER, false)] {
            let connection = &manager.connections[&key(relay)];
            assert_eq!(connection.forward_duplicate_events, forwards, "{relay}");
            assert!(connection.grasp_p_node, "{relay}");
        }
        manager.shutdown().await;

        let (mut manager, _directory) = peer_test_manager(None, |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
            config.private_repos_enable = false;
        })
        .await;
        assert!(manager.register_relay(key(PEER), false, false).await);
        let connection = &manager.connections[&key(PEER)];
        assert!(!connection.forward_duplicate_events);
        assert!(!connection.grasp_p_node);
        manager.shutdown().await;
    }

    /// Negentropy: a requested event that GRASP-P holds counts as delivered,
    /// so the batch completes on its EOSE, with no second round and nothing
    /// left for missing-event recovery. It fails when the seam beside
    /// upstream's own dependency check in `handle_eose` goes.
    #[tokio::test]
    async fn negentropy_batch_counts_a_held_grasp_p_event_as_delivered() {
        let (mut manager, _directory) = peer_test_manager(None, |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        let peer = key(PEER);
        let wrap = unregistered_wrap();
        // Delivered once and held. Its second copy, which used to complete
        // the batch, is the one duplicate forwarding skips.
        assert_eq!(
            synced_from(&manager, &wrap, &peer, SaveContext::RelaySync).await,
            ProcessResult::Rejected(PolicyRejection::Restricted)
        );
        assert!(is_held(&manager, &wrap));
        let never_seen = unregistered_wrap();
        assert_eq!(
            manager.grasp_p_settled_ids(&HashSet::from([wrap.id, never_seen.id])),
            vec![wrap.id]
        );

        let sub = SubscriptionId::generate();
        manager.pending_sync_index.write().await.insert(
            peer.clone(),
            vec![PendingBatch {
                batch_id: 1,
                purpose: PendingBatchPurpose::Core,
                items: PendingItems::default(),
                outstanding_subs: HashSet::from([sub.clone()]),
                sync_method: SyncMethod::Negentropy,
                pagination_state: HashMap::new(),
                requested_event_ids: Some(HashSet::from([wrap.id])),
                received_event_ids: Some(HashSet::new()),
                initial_hydration_counts: None,
                retry_count: 0,
                failed: false,
            }],
        );
        tokio::time::timeout(Duration::from_secs(5), manager.handle_eose(&peer, sub))
            .await
            .unwrap();

        assert!(
            !manager.pending_sync_index.read().await.contains_key(&peer),
            "the batch must complete in its first round"
        );
        assert_eq!(
            manager
                .missing_event_recovery
                .lock()
                .unwrap()
                .pending_ids(&peer),
            None
        );
        manager.shutdown().await;
    }
}
