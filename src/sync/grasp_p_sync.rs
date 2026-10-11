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
//! - disconnect checks: configured peers carry no public repositories, so the
//!   empty-relay heuristic must not drop them.
//!
//! Peers come only from `NGIT_GRASP_P_SYNC_PEER_URLS`. Relay URLs inside tenant
//! events never trigger a connection.

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

    /// Operator-allowlisted GRASP-P peers, as canonical relay keys. Empty when
    /// GRASP-P is disabled.
    pub(super) fn grasp_p_peer_relays(&self) -> HashSet<String> {
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
}
