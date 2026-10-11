//! GRASP-P seams in the sync manager.
//!
//! Everything here is inert unless `NGIT_GRASP_P_REPOS_ENABLE=true`. The sync
//! manager calls in at a handful of points:
//!
//! - its filter builders ([`SyncManager::grasp_p_filters`]): the Layer-1
//!   kind-30640 registration filter plus the 30641/stream-wrap filters derived
//!   from the registrations this node holds, so connect-time sync, quick
//!   reconnects and consolidations all carry them;
//! - two timers ([`spawn_timers`]): the registration index rebuild (which also
//!   reprocesses held out-of-order events, retries cadence-held 30640
//!   replacements, expires holds and connects the operator's peers) and the
//!   periodic full re-issue;
//! - the event pipeline: skip known-rejected private events, reprocess held
//!   events after a 30640 is accepted, and hand rejected private events to
//!   the hold's decision point;
//! - the relay lifecycle of a configured peer: it carries no public
//!   repository, so the empty-relay heuristic must not drop it, a session
//!   that ends must not retire it, the naughty list must not mute it, and it
//!   may be given a dial policy of its own (see "Configured peers" below).
//!
//! # Configured peers
//!
//! A configured peer is a relay the operator named as a node this one
//! replicates private repositories with: an entry of
//! `NGIT_GRASP_P_SYNC_PEER_URLS`, or the relay in
//! `NGIT_SYNC_BOOTSTRAP_RELAY_URL` ([`SyncManager::grasp_p_peer_relays`]).
//! The bootstrap relay counts because a pair can be wired through it alone,
//! which is also why the scrape gives it a peer alias
//! (`src/grasp_p/relay_labels.rs`). Relay URLs inside tenant events never
//! make a peer and never trigger a connection.
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
    /// The GRASP-P filters every relay subscription set carries: the Layer-1
    /// kind-30640 filter and the filters derived from the current index.
    /// Empty when GRASP-P is disabled.
    pub(super) fn grasp_p_filters(&self) -> Vec<Filter> {
        if !self.config.private_repos_enable {
            return Vec::new();
        }
        let mut filters = vec![filters::build_private_registration_filter(None)];
        filters.extend(filters::build_private_derived_filters(
            &self.grasp_p.index.derived_inputs(),
            None,
            self.config.private_accept_legacy_wrap_kind,
        ));
        filters
    }

    /// The peers of `NGIT_GRASP_P_SYNC_PEER_URLS`, as canonical relay keys.
    /// These are the relays the tick registers and dials by itself. Empty
    /// when GRASP-P is disabled.
    fn grasp_p_listed_peers(&self) -> HashSet<String> {
        if !self.config.private_repos_enable {
            return HashSet::new();
        }
        private_index::configured_peer_relay_urls(
            &self.config.private_sync_peer_url_entries(),
            &self.service_domain,
        )
        .iter()
        .filter_map(|url| canonical_relay_key(url).ok())
        .collect()
    }

    /// The configured peers, as canonical relay keys: the listed peers and
    /// the bootstrap relay. Empty when GRASP-P is disabled.
    ///
    /// The bootstrap relay is one of them because a pair can be wired through
    /// it alone: upstream dials it at startup, it is sent the private filters
    /// like any relay, and `policy_fingerprint` takes the pair's other node
    /// from it. Upstream itself dials it a second time only for its public
    /// repositories, so without this a peer named by that setting alone was
    /// lost to the first failed dial or ended session until a restart. The set is the one
    /// `RelayLabels::from_config` gives an alias to.
    pub(super) fn grasp_p_peer_relays(&self) -> HashSet<String> {
        let mut peers = self.grasp_p_listed_peers();
        if self.config.private_repos_enable {
            peers.extend(
                self.bootstrap_relay_url
                    .as_deref()
                    .and_then(|url| canonical_relay_key(url).ok()),
            );
        }
        peers
    }

    /// What a configured peer is wanted for when its session ends: nothing
    /// that upstream counts, which is still a reason to keep it. `None` for
    /// any other relay, and for every relay when GRASP-P is disabled.
    pub(super) fn grasp_p_peer_needs(&self, relay_url: &str) -> Option<RelaySyncNeeds> {
        self.grasp_p_peer_relays()
            .contains(relay_url)
            .then(RelaySyncNeeds::default)
    }

    /// Whether a naughty-list entry may stop a dial of `relay_url`. It may
    /// for every relay but a configured peer: twelve hours without a dial
    /// after, say, a certificate that has since been renewed would stop
    /// replication without a word. The entry itself is upstream's and stays,
    /// with its warning and its metric.
    pub(super) fn grasp_p_naughty_mute_applies(&self, relay_url: &str) -> bool {
        !self.grasp_p_peer_relays().contains(relay_url)
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
        (self.config.private_mirror_allow_private_ips
            && self.grasp_p_peer_relays().contains(relay_url))
        .then_some(OutboundTargetPolicy {
            allow_non_global: true,
        })
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
    /// holds and, on change, re-issue derived filters to live relays and
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
        // reported once, not on every tick.
        let now = Instant::now();
        let peer_retry_delay = Duration::from_secs(if test_mode() { 1 } else { 60 });
        let unknown_peers: Vec<String> = {
            let index = self.relay_sync_index.read().await;
            self.grasp_p_listed_peers()
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
        let derived = filters::build_private_derived_filters(
            &self.grasp_p.index.derived_inputs(),
            None,
            self.config.private_accept_legacy_wrap_kind,
        );
        if derived.is_empty() {
            // No aliases means nothing to re-issue; a peer that connects
            // later gets the current (empty) derived set at connect time.
            self.grasp_p.reissue_pending = false;
            return;
        }
        let outcome = self.grasp_p_reissue_to_live_relays(derived).await;
        self.grasp_p.reissue_pending = outcome.floor_skipped > 0;
    }

    /// Re-issue private sync filters to every live relay: extend the live
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
        let live_relays: Vec<String> = {
            let index = self.relay_sync_index.read().await;
            index
                .iter()
                .filter(|(_, state)| state.connection_status.is_live_sync_active())
                .map(|(url, _)| url.clone())
                .collect()
        };
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
        let filters = self.grasp_p_filters();
        if filters.is_empty() {
            return;
        }
        let outcome = self.grasp_p_reissue_to_live_relays(filters).await;
        // FS-8: count a round only when at least one peer was re-issued, so a
        // chronically skipped peer is visible.
        if outcome.sent > 0 {
            crate::metrics::record_private_full_reissue();
        } else {
            crate::metrics::record_private_full_reissue_skipped();
        }
    }

    /// Whether `event` is a GRASP-P kind already known to be rejected, so the
    /// event pipeline can skip it (refetch-loop protection).
    pub(super) fn grasp_p_previously_rejected(
        write_policy: &Nip34WritePolicy,
        event: &Event,
    ) -> bool {
        let Some(service) = write_policy.grasp_p() else {
            return false;
        };
        let kind = event.kind.as_u16();
        let is_private_kind = kind == crate::grasp_p::KIND_REGISTRATION
            || kind == crate::grasp_p::KIND_STATE_ROOT
            || service.accepts_stream_wrap_kind(kind);
        is_private_kind && service.sync_rejected().contains(&event.id)
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
    // Configured peers: kept, not muted, redialled, and their dial policy
    // ------------------------------------------------------------------

    const INTERVAL: Duration = Duration::from_secs(300);
    /// A loopback peer, a second one, and a relay no setting names.
    const PEER: &str = "ws://127.0.0.1:1";
    const OTHER_PEER: &str = "ws://127.0.0.1:3";
    const STRANGER: &str = "ws://127.0.0.1:2";

    /// A sync manager with GRASP-P enabled and upstream's target policy
    /// permissive, as changed by `configure`.
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
        config.git_data_path = directory.path().join("git").to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let git_path = PathBuf::from(&config.git_data_path);
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_path.clone()));
        // The relay is built with GRASP-P off: these tests need the sync
        // manager's reading of the settings and no private store.
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .unwrap();
        config.private_repos_enable = true;
        config.sync_allow_non_global_targets = true;
        configure(&mut config);
        let mut manager = SyncManager::new(
            bootstrap.map(str::to_string),
            "service.example".into(),
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

    /// The set C1 to C4 work on: the listed peers and the bootstrap relay,
    /// never this node, and nothing with GRASP-P off.
    #[tokio::test]
    async fn configured_peers_are_the_list_and_the_bootstrap_relay() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(format!("{PEER}, wss://service.example"));
        })
        .await;

        assert_eq!(
            manager.grasp_p_peer_relays(),
            HashSet::from([key(PEER), key(OTHER_PEER)])
        );
        // The tick registers the listed peers only; upstream registers the
        // bootstrap relay.
        assert_eq!(manager.grasp_p_listed_peers(), HashSet::from([key(PEER)]));

        manager.config.private_repos_enable = false;
        assert!(manager.grasp_p_peer_relays().is_empty());
        assert!(manager.grasp_p_peer_needs(&key(PEER)).is_none());
        assert!(manager.grasp_p_naughty_mute_applies(&key(PEER)));
        assert!(manager.grasp_p_peer_policy(&key(PEER)).is_none());
        manager.shutdown().await;
    }

    /// C1: a session that ends leaves a configured peer tracked and
    /// disconnected, with its connection and its health record, whether the
    /// list or the bootstrap setting names it. Any other relay is retired,
    /// as in upstream.
    #[tokio::test]
    async fn configured_peer_survives_an_ended_session() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
        })
        .await;
        let (peer, bootstrap, stranger) = (key(PEER), key(OTHER_PEER), key(STRANGER));
        assert!(manager.register_relay(peer.clone(), false, false).await);
        assert!(manager.register_relay(bootstrap.clone(), true, false).await);
        assert!(manager.register_relay(stranger.clone(), false, false).await);

        for relay in [&peer, &bootstrap, &stranger] {
            set_status(&manager, relay, ConnectionStatus::Connected).await;
            manager.handle_disconnect(relay).await;
        }

        for kept in [&peer, &bootstrap] {
            assert_eq!(
                status(&manager, kept).await,
                Some(ConnectionStatus::Disconnected),
                "{kept} must stay tracked"
            );
            assert!(manager.connections.contains_key(kept), "{kept}");
            assert_eq!(
                manager.health_tracker.get_failure_count(kept),
                1,
                "the ended session of {kept} is a failure upstream's backoff counts"
            );
        }
        assert_eq!(status(&manager, &stranger).await, None);
        assert!(!manager.connections.contains_key(&stranger));
        manager.shutdown().await;
    }

    /// C1 is GRASP-P's alone: with it off, the same settings keep nothing.
    #[tokio::test]
    async fn ended_session_retires_every_relay_with_grasp_p_off() {
        let (mut manager, _directory) = peer_test_manager(Some(OTHER_PEER), |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
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

    /// A peer named by the bootstrap setting alone used to be dialled once:
    /// upstream's reconnect loop does not count its own bootstrap relay as
    /// wanted. It is a configured peer, so the loop dials it again.
    #[tokio::test]
    async fn failed_first_dial_of_a_bootstrap_only_peer_is_retried() {
        for grasp_p in [true, false] {
            let (mut manager, _directory) = peer_test_manager(Some(PEER), |config| {
                config.private_repos_enable = grasp_p;
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

            let expected = if grasp_p {
                ConnectionStatus::Connecting
            } else {
                // Upstream as it is. If upstream starts to redial its
                // bootstrap relay, this half goes and nothing else changes.
                ConnectionStatus::Disconnected
            };
            assert_eq!(
                status(&manager, &peer).await,
                Some(expected),
                "GRASP-P {grasp_p}"
            );
            manager.shutdown().await;
        }
    }

    /// C2 and C3 together: a certificate failure puts a peer on the naughty
    /// list like any relay, upstream's loop then leaves it alone, and the
    /// bounded redial still dials it. A relay that is not a peer stays
    /// muted.
    #[tokio::test]
    async fn naughty_list_does_not_mute_a_configured_peer() {
        let (mut manager, _directory) = peer_test_manager(None, |config| {
            config.private_sync_peer_urls = Some(PEER.to_string());
            config.sync_max_backoff_secs = 0;
        })
        .await;
        let (peer, stranger) = (key(PEER), key(STRANGER));
        assert!(manager.register_relay(peer.clone(), false, false).await);
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
        naughty.record(
            &stranger,
            crate::sync::naughty_list::NaughtyCategory::TlsCertificateInvalid,
            "invalid peer certificate".to_string(),
        );

        // Upstream's loop dials neither while the entry stands.
        manager.retry_disconnected_relays().await;
        assert_eq!(
            status(&manager, &peer).await,
            Some(ConnectionStatus::Disconnected)
        );

        // A dial that is asked for goes through for the peer only.
        manager.schedule_connect_relay(&stranger).await;
        assert_eq!(
            status(&manager, &stranger).await,
            Some(ConnectionStatus::Disconnected)
        );
        let later = Instant::now() + INTERVAL + Duration::from_secs(10);
        manager.grasp_p_redial_peers(later, INTERVAL).await;
        assert_eq!(
            status(&manager, &peer).await,
            Some(ConnectionStatus::Connecting)
        );
        assert_eq!(
            status(&manager, &stranger).await,
            Some(ConnectionStatus::Disconnected),
            "the redial is for configured peers only"
        );
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
    /// upstream's guard on. Everything else keeps the node's own policy.
    #[tokio::test]
    async fn only_a_configured_peer_on_a_private_link_gets_a_permissive_policy() {
        const PRIVATE_PEER: &str = "ws://10.0.0.5:7777";
        const PRIVATE_STRANGER: &str = "ws://10.0.0.6:7777";

        // (GRASP-P, link declared private, the peer is registered)
        for (grasp_p, private_link, registered) in [
            (true, true, true),
            (true, false, false),
            (false, true, false),
        ] {
            let (mut manager, _directory) = peer_test_manager(None, |config| {
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
}
