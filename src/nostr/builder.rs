/// Nostr Relay Builder Configuration
///
/// Wires nostr-relay-builder with NIP-34 admission/routing policy.
/// Deletion behaviour is owned by the `nostr::lifecycle` subsystem;
/// this module keeps top-level `admit_event`
/// dispatch and non-deletion admission/router policy logic.
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use nostr::nips::nip19::ToBech32;
use nostr_lmdb::NostrLmdb;
use nostr_memory::MemoryDatabase;
use nostr_relay_builder::prelude::*;

use crate::config::{Config, DatabaseBackend};
use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::lifecycle::{
    DeletionContext, DeletionRuntime, DeletionService, HoldingStore, ReplaceableHistoryStore,
    RepositoryLifecycle, Tombstones,
};
use crate::nostr::persistence::{EventPersistence, SaveContext};
use crate::nostr::policy::{
    accepted_purgatory, duplicate, reject_error, reject_invalid, reject_restricted,
    AnnouncementPolicy, AnnouncementResult, PolicyContext, PrEventPolicy, ReferenceResult,
    RelatedEventPolicy, StatePolicy, StateResult,
};
use crate::nostr::SharedDatabase;
use crate::purgatory::promotion_hooks::NostrPurgatoryPromotionHooks;

/// NIP-34 Write Policy — admission and routing for GRASP-01 events
///
/// Acts as the top-level admission gate and router.  Each incoming event is:
/// 1. Checked against the event blacklist.
/// 2. Passed through the deletion gate (`DeletionService::gate`).
/// 3. Dispatched to the appropriate sub-policy:
///    - `AnnouncementPolicy` — repository announcement validation
///    - `StatePolicy`        — state event validation + ref alignment
///    - `PrEventPolicy`      — PR / PR-Update validation
///    - `RelatedEventPolicy` — forward/backward reference checking
///    - `DeletionService`    — NIP-09 deletion and NIP-62 vanish handling
///
/// Deletion logic (cascade, holding, archive, recovery, startup passes) lives
/// entirely in `crate::nostr::lifecycle`.  This struct exposes a `deletion()`
/// accessor for callers that need to reach those operations directly.
#[derive(Clone)]
pub struct Nip34WritePolicy {
    ctx: PolicyContext,
    announcement_policy: AnnouncementPolicy,
    state_policy: StatePolicy,
    pr_event_policy: PrEventPolicy,
    related_event_policy: RelatedEventPolicy,
    deletion: DeletionService,
    /// GRASP-P private-repo subsystem. `None` unless
    /// `NGIT_PRIVATE_REPOS_ENABLE=true`; shared across clones (set once in
    /// `create_relay`, mirroring the `set_local_relay` pattern).
    private: Arc<std::sync::OnceLock<Arc<crate::private::PrivateService>>>,
}

impl std::fmt::Debug for Nip34WritePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nip34WritePolicy")
            .field("domain", &self.ctx.domain)
            .field("git_data_path", &self.ctx.git_data_path)
            .field("database", &"<database>")
            .finish()
    }
}

impl Nip34WritePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database: SharedDatabase,
        tombstones: Tombstones,
        holding: HoldingStore,
        lifecycle: RepositoryLifecycle,
        history: ReplaceableHistoryStore,
        git_data_path: impl Into<std::path::PathBuf>,
        purgatory: std::sync::Arc<crate::purgatory::Purgatory>,
        config: crate::config::Config,
        repo_init_locks: crate::grasp06::receive::RepoInitLocks,
    ) -> Self {
        let git_data_path = git_data_path.into();
        let domain = config.domain.clone();
        let deletion_ctx = DeletionContext::new(
            domain.clone(),
            database.clone(),
            tombstones.clone(),
            holding.clone(),
            lifecycle,
            history.clone(),
            git_data_path.clone(),
            purgatory.clone(),
            config.clone(),
            repo_init_locks.clone(),
        );

        let ctx = PolicyContext::new(domain, database, git_data_path, purgatory, config.clone());
        Self {
            announcement_policy: AnnouncementPolicy::new(ctx.clone(), config.clone()),
            state_policy: StatePolicy::new(ctx.clone()),
            pr_event_policy: PrEventPolicy::new(ctx.clone(), repo_init_locks),
            related_event_policy: RelatedEventPolicy::new(ctx.clone()),
            deletion: DeletionService::new(deletion_ctx),
            ctx,
            private: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Install the GRASP-P private-repo service. Must be called before the
    /// relay starts admitting events (done in `create_relay`); shared with all
    /// clones of this policy.
    pub fn set_private(&self, private: Arc<crate::private::PrivateService>) {
        let _ = self.private.set(private);
    }

    /// The private-repo service, when enabled.
    pub fn private(&self) -> Option<&Arc<crate::private::PrivateService>> {
        self.private.get()
    }

    /// Check if an event author is blacklisted
    ///
    /// Returns Some(reason) if blacklisted, None if not blacklisted.
    fn check_event_blacklist(&self, event: &Event) -> Option<String> {
        let event_blacklist = self.ctx.config.event_blacklist_config();
        if !event_blacklist.enabled() {
            return None;
        }

        let npub = event.pubkey.to_bech32().ok()?;
        event_blacklist.check(&npub)
    }

    /// Get a reference to the purgatory for read-only access
    pub fn purgatory(&self) -> &std::sync::Arc<crate::purgatory::Purgatory> {
        &self.ctx.purgatory
    }

    /// Get a reference to the holding store for retention cleanup orchestration.
    pub fn holding(&self) -> &HoldingStore {
        self.deletion.holding()
    }

    /// Get a reference to the replaceable-history store.
    pub fn history(&self) -> &ReplaceableHistoryStore {
        self.deletion.history()
    }

    pub fn tombstones(&self) -> &Tombstones {
        self.deletion.tombstones()
    }

    /// Set the local relay for purgatory notifications.
    ///
    /// This must be called after the relay is created since the relay depends
    /// on this policy, but purgatory sync needs the relay to notify subscribers.
    pub fn set_local_relay(&self, relay: nostr_relay_builder::LocalRelay) {
        self.ctx.set_local_relay(relay);
    }

    /// Access the deletion subsystem directly.
    ///
    /// Exposes startup passes and recovery without requiring delegation wrappers
    /// on this struct. Repository lifecycle coordination is exposed separately
    /// through [`RepositoryLifecycle`].
    pub fn deletion(&self) -> &DeletionService {
        &self.deletion
    }

    fn event_persistence(&self) -> EventPersistence<'_> {
        EventPersistence::new(&self.ctx.database)
    }

    /// Save an already-admitted event through the central accepted-event path.
    pub async fn save_accepted_event(
        &self,
        event: &Event,
        context: SaveContext,
    ) -> anyhow::Result<()> {
        self.event_persistence()
            .save_accepted_event(event, context)
            .await
    }

    /// Extract repository identifier from event's 'd' tag.
    ///
    /// Used for structured logging when parsing fails - we try to extract
    /// the identifier even if full parsing failed.
    fn extract_identifier_from_event(event: &Event) -> String {
        event
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Extract ALL repository identifiers from PR event's 'a' tags.
    ///
    /// PR events can reference multiple repositories via multiple 'a' tags
    /// (e.g., when there are multiple maintainers). Each tag has format
    /// `30617:<owner_pubkey>:<identifier>`.
    ///
    /// Returns a vector of unique identifiers, or `["unknown"]` if none found.
    fn extract_repos_from_pr_event(event: &Event) -> Vec<String> {
        let repos: Vec<String> = event
            .tags
            .iter()
            .filter_map(|tag| {
                let tag_vec = tag.clone().to_vec();
                if tag_vec.len() >= 2 && tag_vec[0] == "a" && tag_vec[1].starts_with("30617:") {
                    // Format: 30617:<owner_pubkey>:<identifier>
                    let parts: Vec<&str> = tag_vec[1].split(':').collect();
                    if parts.len() >= 3 {
                        Some(parts[2].to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Deduplicate while preserving order
        let mut seen = std::collections::HashSet::new();
        let unique_repos: Vec<String> = repos
            .into_iter()
            .filter(|r| seen.insert(r.clone()))
            .collect();

        if unique_repos.is_empty() {
            vec!["unknown".to_string()]
        } else {
            unique_repos
        }
    }

    /// Handle repository announcement event
    async fn handle_announcement(&self, event: &Event) -> WritePolicyResult {
        let event_id_str = event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex());

        let admission = self.announcement_policy.validate(event).await;
        let deletion_hooks = self.deletion.admission_hooks();
        let deletion_hook_result = deletion_hooks
            .on_announcement_admission(event, &admission)
            .await;

        match admission {
            AnnouncementResult::Accept | AnnouncementResult::AcceptArchive => {
                // Parse announcement to get repository details
                match RepositoryAnnouncement::from_event(event.clone()) {
                    Ok(announcement) => {
                        // Try to create bare repository if it doesn't exist
                        if let Err(e) = self
                            .announcement_policy
                            .ensure_bare_repository(&announcement)
                        {
                            tracing::warn!(
                                "Failed to create bare repository for {}: {}",
                                event_id_str,
                                e
                            );
                            // Note: We still accept the event even if repo creation fails
                        }

                        tracing::debug!("Accepted repository announcement: {}", event_id_str);

                        // Check purgatory for state events that might now be authorized
                        self.check_purgatory_state_events_for_identifier(&announcement.identifier)
                            .await;

                        WritePolicyResult::Accept
                    }
                    Err(e) => {
                        let npub = event
                            .pubkey
                            .to_bech32()
                            .unwrap_or_else(|_| event.pubkey.to_hex());
                        let event_id_short = &event.id.to_hex()[..12];
                        // Try to extract repo identifier from 'd' tag even if parsing failed
                        let repo = Self::extract_identifier_from_event(event);
                        // Structured log for migration scripts
                        tracing::warn!(
                            "[PARSE_FAIL] kind={} event_id={}... reason=\"{}\" repo={} npub={}",
                            event.kind.as_u16(),
                            event_id_short,
                            e,
                            repo,
                            npub
                        );
                        reject_invalid(format!("Failed to parse announcement: {}", e))
                    }
                }
            }
            AnnouncementResult::AcceptPurgatory => {
                let announcement = match RepositoryAnnouncement::from_event(event.clone()) {
                    Ok(announcement) => announcement,
                    Err(e) => {
                        return reject_invalid(format!("Failed to parse announcement: {}", e))
                    }
                };

                if deletion_hook_result.recovered_repository() {
                    tracing::info!(
                        identifier = %announcement.identifier,
                        event_id = %event_id_str,
                        "Accepted re-announcement with recovery"
                    );
                    if let Err(e) = self
                        .announcement_policy
                        .ensure_bare_repository(&announcement)
                    {
                        tracing::warn!(
                            "Failed to ensure bare repository after recovery for {}: {}",
                            event_id_str,
                            e
                        );
                    }
                    return WritePolicyResult::Accept;
                }

                // New announcement - add to purgatory
                match self.announcement_policy.add_to_purgatory(event) {
                    Ok(()) => {
                        tracing::info!(
                            "Accepted announcement to purgatory: {} (waiting for git data)",
                            event_id_str
                        );
                        accepted_purgatory("won't be served until git data arrives")
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to add announcement to purgatory {}: {}",
                            event_id_str,
                            e
                        );
                        reject_error(e)
                    }
                }
            }
            AnnouncementResult::AcceptMaintainer => {
                // Parse announcement to get details for logging
                match RepositoryAnnouncement::from_event(event.clone()) {
                    Ok(announcement) => {
                        tracing::info!(
                            "Accepted maintainer announcement {} (author {} is listed as maintainer for {})",
                            event_id_str,
                            event.pubkey.to_hex(),
                            announcement.identifier
                        );
                        // Don't create bare repository for external announcements

                        // Check purgatory for state events that might now be authorized
                        self.check_purgatory_state_events_for_identifier(&announcement.identifier)
                            .await;

                        WritePolicyResult::Accept
                    }
                    Err(e) => {
                        let npub = event
                            .pubkey
                            .to_bech32()
                            .unwrap_or_else(|_| event.pubkey.to_hex());
                        let event_id_short = &event.id.to_hex()[..12];
                        // Try to extract repo identifier from 'd' tag even if parsing failed
                        let repo = Self::extract_identifier_from_event(event);
                        // Structured log for migration scripts
                        tracing::warn!(
                            "[PARSE_FAIL] kind={} event_id={}... reason=\"{}\" repo={} npub={}",
                            event.kind.as_u16(),
                            event_id_short,
                            e,
                            repo,
                            npub
                        );
                        reject_invalid(format!("Failed to parse announcement: {}", e))
                    }
                }
            }
            AnnouncementResult::Reject(reason) => {
                tracing::warn!(
                    "Rejected repository announcement {}: {}",
                    event_id_str,
                    reason
                );
                reject_invalid(reason)
            }
        }
    }

    /// Handle repository state event
    ///
    /// # Arguments
    /// * `event` - The state event to validate
    /// * `is_synced` - True if this event came from proactive sync (vs user-submitted)
    async fn handle_state(&self, event: &Event, is_synced: bool) -> WritePolicyResult {
        match self.state_policy.validate(event) {
            StateResult::Accept => {
                let promotion_hooks = NostrPurgatoryPromotionHooks::recovery_only(self);

                // Process state alignment asynchronously
                match self
                    .state_policy
                    .process_state_event(event, is_synced, Some(&promotion_hooks))
                    .await
                {
                    Ok(policy_result) => {
                        self.deletion
                            .admission_hooks()
                            .on_state_admission(event, &policy_result)
                            .await;
                        policy_result
                    }
                    Err(e) => {
                        let npub = event
                            .pubkey
                            .to_bech32()
                            .unwrap_or_else(|_| event.pubkey.to_hex());
                        let event_id_short = &event.id.to_hex()[..12];
                        // Try to extract repo identifier from 'd' tag even if parsing failed
                        let repo = Self::extract_identifier_from_event(event);
                        // Structured log for migration scripts
                        tracing::warn!(
                            "[PARSE_FAIL] kind={} event_id={}... reason=\"{}\" repo={} npub={}",
                            event.kind.as_u16(),
                            event_id_short,
                            e,
                            repo,
                            npub
                        );
                        // reject if processing failed
                        reject_error(format!("{e}"))
                    }
                }
            }
            StateResult::Reject(reason) => {
                let npub = event
                    .pubkey
                    .to_bech32()
                    .unwrap_or_else(|_| event.pubkey.to_hex());
                let event_id_short = &event.id.to_hex()[..12];
                // Try to extract repo identifier from 'd' tag even if parsing failed
                let repo = Self::extract_identifier_from_event(event);
                // Structured log for migration scripts
                tracing::warn!(
                    "[PARSE_FAIL] kind={} event_id={}... reason=\"{}\" repo={} npub={}",
                    event.kind.as_u16(),
                    event_id_short,
                    reason,
                    repo,
                    npub
                );
                reject_invalid(reason)
            }
        }
    }

    /// Handle PR or PR Update event
    ///
    /// # Arguments
    /// * `event` - The PR event to validate
    /// * `is_synced` - True if this event came from proactive sync (vs user-submitted)
    async fn handle_pr_event(&self, event: &Event, is_synced: bool) -> WritePolicyResult {
        let event_id_str = event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex());

        // duplicate check in purgatory
        let in_purgatory = self
            .ctx
            .purgatory
            .find_pr(&event.id.to_hex())
            .is_some_and(|e| e.event.is_some());
        if in_purgatory {
            tracing::debug!(
                "processed PR event duplicate (already in purgatory): {}",
                event.id,
            );
            return duplicate("in purgatory");
        }

        // duplicate check in db
        //
        // Note: the database runs with `process_nip09(false)`, so `check_id`
        // only ever returns `Saved` / `NotExistent` here — re-submission of a
        // deleted PR is already rejected upstream by `DeletionService::gate`.
        match &self.ctx.database.check_id(&event.id).await {
            Ok(DatabaseEventStatus::Saved) => {
                return duplicate("already have this event");
            }
            Err(e) => {
                return reject_error(format!("internal error: {e}"));
            }
            _ => {} // continue
        }

        // Reject PRs unrelated to stored repositories / events.
        //
        // GRASP-06 (06.md lines 19–22) relaxes this: a PR / PR-Update event
        // whose `clone` tag names this relay's
        // `/prs/<signer-npub>/<d>.git` endpoint (and which carries a
        // matching `a` tag of the form `30617:<hex>:<d>`) MUST be accepted
        // even when no announcement for the target coord is on this relay.
        // Such events skip the related-event check and fall through to the
        // git-data-check + purgatory branch below.
        match self.handle_related_event(event, "PR").await {
            WritePolicyResult::Accept => {} // continue
            rejected => {
                if !crate::grasp06::policy::event_qualifies_for_pr_relaxation(
                    event,
                    &self.ctx.config,
                ) {
                    return rejected;
                }
                tracing::info!(
                    "Accepted orphan PR event {} under GRASP-06: clone tag names this relay's /prs/ endpoint",
                    event_id_str,
                );
            }
        }

        // Check if git data exists (delete any incorrect commits at refs/nostr/<event-id>, copies correct data to relivant repositories)
        match self.pr_event_policy.git_data_check(event).await {
            Ok(false) => {
                // Only reject expired events if they're from sync (not user-submitted)
                // User-submitted events should be allowed to retry in case git data became available
                if is_synced && self.ctx.purgatory.is_expired(&event.id) {
                    tracing::debug!(
                        event_id = %event_id_str,
                        "PR event previously expired from purgatory (synced), rejecting to prevent re-sync loop"
                    );
                    return reject_invalid("previously expired from purgatory without git data");
                }

                // No git data exists - add to purgatory
                let commit = event
                    .tags
                    .iter()
                    .find_map(|tag| {
                        let tag_vec = tag.clone().to_vec();
                        if tag_vec.len() >= 2 && tag_vec[0] == "c" {
                            Some(tag_vec[1].clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                tracing::info!(
                    "PR event {} added to purgatory: waiting for git push with commit {}",
                    event_id_str,
                    commit
                );

                // Add to purgatory
                self.ctx.purgatory.add_pr(
                    event.clone(),
                    event.id.to_hex(),
                    commit.clone(),
                    is_synced,
                );

                accepted_purgatory(format!(
                    "PR event stored, waiting for git push with commit {}",
                    commit
                ))
            }
            Ok(true) => {
                // Git data exists - proceed with normal validation
                tracing::debug!("Git data exists for PR event {}", event_id_str);
                WritePolicyResult::Accept
            }
            Err(e) => {
                // Error checking git data - reject event
                let npub = event
                    .pubkey
                    .to_bech32()
                    .unwrap_or_else(|_| event.pubkey.to_hex());
                let event_id_short = &event.id.to_hex()[..12];
                // Extract ALL repo identifiers from 'a' tags for PR events
                // (PR events can reference multiple repos when there are multiple maintainers)
                let repos = Self::extract_repos_from_pr_event(event);
                // Structured log for migration scripts - log once per repo
                for repo in &repos {
                    tracing::warn!(
                        "[PARSE_FAIL] kind={} event_id={}... reason=\"git data check failed: {}\" repo={} npub={}",
                        event.kind.as_u16(),
                        event_id_short,
                        e,
                        repo,
                        npub
                    );
                }
                reject_error(format!("Failed to check git data: {}", e))
            }
        }
    }

    /// Check purgatory for state events that might now be authorized by a new announcement
    ///
    /// When an announcement is accepted, state events in purgatory that were previously
    /// rejected due to missing announcements might now be authorized. This method:
    /// 1. Finds all state events in purgatory for the identifier
    /// 2. Re-evaluates authorization for each event
    /// 3. Processes authorized events (releases from purgatory)
    /// 4. Keeps unauthorized events in purgatory (will expire naturally)
    async fn check_purgatory_state_events_for_identifier(&self, identifier: &str) {
        let state_events = self.ctx.purgatory.find_state(identifier);

        if state_events.is_empty() {
            return;
        }

        tracing::debug!(
            identifier = %identifier,
            count = state_events.len(),
            "Checking purgatory state events after announcement acceptance"
        );

        for entry in state_events {
            let promotion_hooks = NostrPurgatoryPromotionHooks::recovery_only(self);

            // Re-evaluate authorization with the new announcement
            match self
                .state_policy
                .process_state_event(&entry.event, false, Some(&promotion_hooks))
                .await
            {
                Ok(WritePolicyResult::Accept) => {
                    tracing::info!(
                        event_id = %entry.event.id,
                        identifier = %identifier,
                        "State event in purgatory now authorized, will be processed"
                    );
                    // Event will be automatically removed from purgatory by process_state_event
                    // and broadcast to subscribers
                }
                Ok(WritePolicyResult::Reject { message, .. }) => {
                    if message.contains("not authorized") {
                        tracing::debug!(
                            event_id = %entry.event.id,
                            identifier = %identifier,
                            "State event in purgatory still not authorized, keeping in purgatory"
                        );
                        // Keep in purgatory - will expire naturally after 30 minutes
                    } else {
                        tracing::debug!(
                            event_id = %entry.event.id,
                            identifier = %identifier,
                            reason = %message,
                            "State event in purgatory rejected for other reason"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        event_id = %entry.event.id,
                        identifier = %identifier,
                        error = %e,
                        "Error re-evaluating state event in purgatory"
                    );
                }
            }
        }
    }

    /// Handle events that must reference accepted repositories or events
    async fn handle_related_event(&self, event: &Event, event_type: &str) -> WritePolicyResult {
        let event_id_str = event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex());

        match self.related_event_policy.check_references(event).await {
            Ok(ReferenceResult::ReferencesRepository(addr_ref)) => {
                tracing::debug!(
                    "Accepted {} event {}: references accepted repository {}",
                    event_type,
                    event_id_str,
                    addr_ref
                );
                WritePolicyResult::Accept
            }
            Ok(ReferenceResult::ReferencesEvent(event_ref)) => {
                tracing::debug!(
                    "Accepted {} event {}: references accepted event {}",
                    event_type,
                    event_id_str,
                    event_ref
                );
                WritePolicyResult::Accept
            }
            Ok(ReferenceResult::ReferencedByAccepted) => {
                tracing::debug!(
                    "Accepted {} event {}: referenced by accepted event",
                    event_type,
                    event_id_str
                );
                WritePolicyResult::Accept
            }
            Ok(ReferenceResult::Orphan) => {
                let (addressable_refs, event_refs) =
                    RelatedEventPolicy::extract_reference_tags(event);
                tracing::info!(
                    "Rejected orphan {} event {} (kind={}, pubkey={}): no references to accepted repos or events (checked {} addressable, {} event refs)",
                    event_type,
                    event.id.to_hex(),
                    event.kind.as_u16(),
                    event.pubkey.to_hex(),
                    addressable_refs.len(),
                    event_refs.len()
                );
                reject_restricted(format!(
                    "{} event must reference an accepted repository or accepted event",
                    event_type
                ))
            }
            Err(e) => {
                tracing::warn!(
                    "Database query failed for {} {}, rejecting (fail-secure): {}",
                    event_type,
                    event_id_str,
                    e
                );
                reject_error(format!("Database query failed: {}", e))
            }
        }
    }
}

impl WritePolicy for Nip34WritePolicy {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr_relay_builder::prelude::Event,
        addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, WritePolicyResult> {
        Box::pin(async move {
            // Check event blacklist FIRST - it overrides everything
            if let Some(reason) = self.check_event_blacklist(event) {
                tracing::debug!(
                    event_id = %event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex()),
                    author = %event.pubkey.to_hex(),
                    reason = %reason,
                    "Rejected event from blacklisted author"
                );
                return WritePolicyResult::reject(MachineReadablePrefix::Blocked, reason);
            }

            // Deletion / vanish gate.
            //
            // The relay-builder library has a `check_id` gate that runs *before*
            // this policy and used to reject re-submitted deleted events with
            // "this event is deleted" — but that gate is fed by the LMDB
            // backend's internal NIP-09/NIP-62 tables, which go silent now that
            // we run the backend with `process_nip09(false)` /
            // `process_nip62(false)`. We reproduce that rejection here from our
            // own persistent `Tombstones` store so deleted events (and events
            // from vanished pubkeys) stay rejected across restarts.
            if let Some(rejection) = self.deletion.gate(event).await {
                return rejection;
            }

            // Detect if this is a synced event (from proactive sync) vs user-submitted
            // Sync uses localhost:0 as a dummy address
            let is_synced = addr.ip().is_loopback() && addr.port() == 0;

            // GRASP-P private-repo kinds. Only routed when the subsystem is
            // enabled; otherwise every private kind falls through to the
            // existing dispatch below (zero behavior change with
            // enable=false). Which stream-wrap kinds route here is decided
            // in exactly one place (`accepts_*_stream_wrap_kind`), so the
            // dual-accept window (3359 + legacy 1059) can never diverge
            // from the sync filters or the NIP-11 advert; its complement
            // (`rejects_retired_wrap_kind`) refuses the legacy kinds
            // outright once the window closes, so they are never handed to
            // the weaker public related-event path. Synced events
            // (loopback:0) intentionally get identical handling — a synced
            // 30640/30641/stream wrap must apply under the same rules.
            let private = self.private.get();
            let result = match event.kind {
                k if private.is_some()
                    && k.as_u16() == crate::private::KIND_REGISTRATION =>
                {
                    let svc = private.unwrap();
                    let result = svc.handle_registration(event).await;
                    // FS-2 (review L3-F4): a cadence-rejected same-tenant
                    // replacement is held AND rejected to the client — the
                    // NIP-20 message still says retry-later, but
                    // convergence must not depend on the client actually
                    // retrying: the sync timer re-offers the held event
                    // after the bucket refills. Dedup by event id makes the
                    // sync path's own hold a no-op.
                    if let WritePolicyResult::Reject { ref message, .. } = result {
                        if message.contains(
                            crate::private::registration::REPLACE_CADENCE_REJECT_MESSAGE,
                        ) {
                            svc.sync_rejected().add_registration(event.clone());
                        }
                    }
                    result
                }
                k if private.is_some() && k.as_u16() == crate::private::KIND_STATE_ROOT => {
                    let svc = private.unwrap();
                    // Phase-4b A1: per-write-key token bucket — CLIENT
                    // submissions only. Synced events and SaveContext
                    // reprocess traffic arrive via the loopback:0 dummy
                    // address and bypass the bucket (node-local DoS knob,
                    // no convergence impact). A rate-limited 30641 is NOT
                    // added to the out-of-order hold: the client retries.
                    if !is_synced && !svc.client_write_allowed(&event.pubkey.to_hex()) {
                        crate::metrics::record_private_rate_limited("state_root");
                        crate::metrics::record_private_event_rejected(
                            crate::private::KIND_STATE_ROOT,
                        );
                        return reject_restricted("rate-limited; retry later");
                    }
                    let result = svc.handle_state_root(event).await;
                    // GRASP-P Phase 2 (design 1.4): a 30641 can be pushed
                    // BEFORE its authorizing 30640 is known here (client
                    // out-of-order push mirrors sync out-of-order arrival).
                    // Hold the rejection keyed by target alias so the 30640
                    // reprocess hook can resurrect it; dedup by event id
                    // makes the sync path's own hold a no-op.
                    if !matches!(result, WritePolicyResult::Accept) {
                        let alias = event.tags.iter().find_map(|tag| {
                            let v = tag.clone().to_vec();
                            if v.len() >= 2 && v[0] == "d" {
                                Some(v[1].clone())
                            } else {
                                None
                            }
                        });
                        if let Some(alias) = alias {
                            svc.sync_rejected().add_state_root(alias, event.clone());
                        }
                    }
                    result
                }
                k if private.is_some_and(|svc| svc.accepts_stream_wrap_kind(k.as_u16())) => {
                    let svc = private.unwrap();
                    // Phase-4b A1: per-write-key token bucket (client
                    // submissions only — see the 30641 arm). Charged wraps
                    // and never-charged spam both spend one token; a
                    // rate-limited wrap is rejected outright (no hold).
                    if !is_synced && !svc.client_write_allowed(&event.pubkey.to_hex()) {
                        crate::metrics::record_private_rate_limited("wrap");
                        crate::metrics::record_private_event_rejected(k.as_u16());
                        return reject_restricted("rate-limited; retry later");
                    }
                    match svc.try_handle_wrap(event, false).await {
                        Some(result) => result,
                        // Unregistered outer key: REJECT (never the public
                        // related-event path). §3.2 is normative here: a
                        // GRASP-P node admits stream wraps only for outer
                        // authors in w∪s of a live registration — accepting referenced
                        // wraps from unregistered keys made every deregistered
                        // rekey address permanently floodable (charged to
                        // nobody), defeating the client's epoch-scoped
                        // admission windows. The wrap is still held keyed by
                        // its outer author so a later 30640 registering that
                        // key reprocesses it (design 1.4, out-of-order sync).
                        None => {
                            svc.sync_rejected()
                                .add_wrap(event.pubkey.to_hex(), event.clone());
                            reject_restricted("unregistered key")
                        }
                    }
                }
                k if private
                    .is_some_and(|svc| svc.accepts_ephemeral_stream_wrap_kind(k.as_u16())) =>
                {
                    let svc = private.unwrap();
                    // Phase-4b A1: ephemeral wraps are never quota-charged,
                    // so this bucket is their ONLY cost — client submissions
                    // only (see the 30641 arm).
                    if !is_synced && !svc.client_write_allowed(&event.pubkey.to_hex()) {
                        crate::metrics::record_private_rate_limited("ewrap");
                        crate::metrics::record_private_event_rejected(k.as_u16());
                        return reject_restricted("rate-limited; retry later");
                    }
                    match svc.try_handle_wrap(event, true).await {
                        Some(result) => result,
                        // Ephemeral wraps are never stored, so there is no
                        // out-of-order hold — reject outright (§3.2: outer
                        // author must be registered).
                        None => reject_restricted("unregistered key"),
                    }
                }
                k if private.is_some_and(|svc| svc.rejects_retired_wrap_kind(k.as_u16())) => {
                    // NGIT_PRIVATE_ACCEPT_LEGACY_WRAP_KIND=false RETIRES
                    // 1059/21059 on a GRASP-P node: refuse them here rather
                    // than let them fall through to `handle_related_event`.
                    // Without this arm, closing the private arm RECLASSIFIES
                    // a legacy wrap onto the public related-event policy,
                    // which stores any `a`/`e`-tagged event referencing
                    // accepted content — from any key, ungated by §3.2,
                    // uncapped by private_max_event_bytes, uncharged to any
                    // private quota, and never swept by the private GC. That
                    // is MORE permissive than the default (legacy on, where
                    // an unregistered 1059 is rejected outright), so the
                    // "off" position of a migration knob would widen the
                    // accepted set. Nothing legitimate is lost: with the knob
                    // on, the private arm already claims every 1059 on this
                    // node, so no client can be relying on the public path
                    // for it, and genuine NIP-59 gift wraps go to inbox
                    // relays, never a git node. Nodes with private repos
                    // disabled never reach this arm (`private` is None) and
                    // keep vanilla 1059 handling (phase0 G3).
                    crate::metrics::record_private_event_rejected(k.as_u16());
                    reject_restricted("legacy stream-wrap kind is not accepted on this node")
                }
                Kind::GitRepoAnnouncement => self.handle_announcement(event).await,
                Kind::RepoState => self.handle_state(event, is_synced).await,
                Kind::GitPullRequest | Kind::GitPullRequestUpdate => {
                    self.handle_pr_event(event, is_synced).await
                }
                Kind::GitUserGraspList => {
                    // Accept all kind 10317 (User Grasp List) events
                    // for better GRASP repository discovery
                    tracing::debug!(
                        event_id = %event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex()),
                        author = %event.pubkey.to_hex(),
                        "Accepted kind 10317 user grasp list"
                    );
                    WritePolicyResult::Accept
                }
                Kind::EventDeletion => {
                    let result = self.deletion.handle_nip09(event).await;
                    // GRASP-P: when an author-valid deletion of a private
                    // 30640 is honored, free its key claims — claims must die
                    // with the registration or they wedge future rotations
                    // (dangling "write key already registered" conflicts).
                    if matches!(result, WritePolicyResult::Accept)
                        && self.deletion.actions_deletions()
                    {
                        if let Some(svc) = self.private.get() {
                            svc.free_claims_for_deleted_registrations(event);
                        }
                    }
                    result
                }
                Kind::RequestToVanish => {
                    let result = self.deletion.handle_vanish(event).await;
                    // GRASP-P: a vanish deletes every author event including
                    // 30640s — free their key claims too (dangling-claim
                    // wedge, same as the kind-5 path). Only when the vanish
                    // actually targets this relay and is actioned locally.
                    if matches!(result, WritePolicyResult::Accept)
                        && self.deletion.actions_deletions()
                        && self.deletion.vanish_targets_this_relay(event)
                    {
                        if let Some(svc) = self.private.get() {
                            svc.free_claims_for_vanished_author(event);
                        }
                    }
                    result
                }
                k if private.is_some() && k.as_u16() == crate::private::KIND_REPORT => {
                    // GRASP-P Phase-4b D3: NIP-56 report intake —
                    // observe-then-defer. Log the event id, the reporter,
                    // and any sha256-looking tag values (the takedown
                    // evidence an operator needs — e.g. `x` tags carrying
                    // blob digests); the event CONTENT is never logged.
                    // Admission then runs through the EXISTING related-event
                    // rules unchanged: reports referencing accepted content
                    // are stored as today, others are rejected as orphans as
                    // today. v1 takes no automatic action; v2 may auto-act
                    // on verified reports — until then the runbook documents
                    // the manual denylist workflow (Phase-4b D1).
                    let sha256_tags: Vec<String> = event
                        .tags
                        .iter()
                        .flat_map(|tag| tag.clone().to_vec())
                        .filter(|v| crate::private::blossom_auth::is_lower_hex_64(v))
                        .take(16)
                        .collect();
                    tracing::info!(
                        event_id = %event.id.to_hex(),
                        reporter = %event.pubkey.to_hex(),
                        sha256_tags = ?sha256_tags,
                        "NIP-56 report event received"
                    );
                    crate::metrics::record_private_report_event();
                    self.handle_related_event(event, "NIP-56 report").await
                }
                _ => self.handle_related_event(event, "Event").await,
            };

            result
        })
    }
}

/// Storage handles shared by the relay runtime and HTTP/runtime services.
pub struct RelayStores {
    /// Main relay database used for event queries and persistence.
    pub database: SharedDatabase,
    /// Persistent NIP-09/NIP-62 tombstone store.
    pub tombstones: Tombstones,
    /// Holding store used for deletion archival + expiry cleanup
    pub holding: HoldingStore,
    /// Replaceable-history store used for rollback history capture.
    pub history: ReplaceableHistoryStore,
}

/// Runtime components produced when constructing the local relay.
pub struct RelayRuntime {
    /// The local relay instance.
    pub relay: LocalRelay,
    /// The write policy used for event admission, routing, and persistence.
    pub write_policy: Nip34WritePolicy,
    /// Deletion service shared with write policy for NIP-09/NIP-62 operations.
    pub deletion: DeletionService,
    /// Runtime facade for deletion startup tasks and background cleanup.
    pub deletion_runtime: DeletionRuntime,
    /// Repository lifecycle locks shared by HTTP serving and deletion/recovery.
    pub lifecycle: RepositoryLifecycle,
    /// Storage handles used by the relay runtime.
    pub stores: RelayStores,
    /// GRASP-P private-repo service (Some only when
    /// `NGIT_PRIVATE_REPOS_ENABLE=true`).
    pub private: Option<Arc<crate::private::PrivateService>>,
}

/// Create a configured LocalRelay with full GRASP-01 validation
///
/// Returns a `RelayRuntime` struct containing the relay, write policy, deletion
/// runtime, lifecycle locks, and storage handles used by HTTP/runtime services.
pub async fn create_relay(
    config: &Config,
    purgatory: Arc<crate::purgatory::Purgatory>,
    repo_init_locks: crate::grasp06::receive::RepoInitLocks,
) -> Result<RelayRuntime> {
    tracing::info!("Configuring nostr relay with GRASP-01 validation...");

    // Determine database path
    let db_path = Path::new(&config.relay_data_path);

    // Create database based on configuration
    //
    // NIP-09 (deletion) and NIP-62 (request to vanish) auto-processing is
    // explicitly disabled on the main database: ngit-grasp owns this handling
    // (see the deletion subsystem facade + `Tombstones` store).
    // Leaving the backend defaults (`true`) would double-process: the backend
    // would silently hard-delete events and block re-submission via its own
    // internal tables that we cannot inspect, conflicting with our purgatory /
    // bare-repo bookkeeping.
    let (database, tombstones, holding, history): (
        SharedDatabase,
        Tombstones,
        HoldingStore,
        ReplaceableHistoryStore,
    ) = match config.database_backend {
        DatabaseBackend::Memory => {
            tracing::info!("Using in-memory database (no persistence)");
            // Disable the backend's built-in NIP-09 / NIP-62 auto-processing to
            // match the LMDB path: ngit-grasp owns this handling (deletion
            // subsystem + Tombstones store). Leaving the memory
            // backend's defaults (`true`) would silently suppress targeted events
            // at query time the moment a kind-5 is *stored* — which in particular
            // defeats `deletion_request_disrespector` (archival) mode, where the
            // kind-5 is intentionally stored but not acted upon.
            let db = MemoryDatabase::builder()
                .max_events(NonZeroUsize::new(100_000).unwrap())
                .process_nip09(false)
                .process_nip62(false)
                .build();
            (
                Arc::new(db),
                Tombstones::in_memory(),
                HoldingStore::in_memory(),
                ReplaceableHistoryStore::in_memory(),
            )
        }
        DatabaseBackend::Lmdb => {
            tracing::info!("Using LMDB backend at: {}", db_path.display());
            // Ensure the database directory exists
            std::fs::create_dir_all(db_path).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create LMDB directory {}: {}",
                    db_path.display(),
                    e
                )
            })?;
            let db = NostrLmdb::builder(db_path)
                .process_nip09(false)
                .process_nip62(false)
                .build()
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to open LMDB database at {}: {}",
                        db_path.display(),
                        e
                    )
                })?;
            let tombstones = Tombstones::open_lmdb(db_path).await?;
            let holding =
                HoldingStore::open_lmdb(db_path, Path::new(&config.effective_git_data_path()))
                    .await?;
            let history = ReplaceableHistoryStore::open_lmdb(db_path).await?;
            (Arc::new(db), tombstones, holding, history)
        }
    };

    // Build relay with GRASP-01 validation
    // Clone Arc for the write policy so both relay and policy can access the database
    let git_data_path = config.effective_git_data_path();

    // Log archive configuration (config.validate() must be called at startup)
    let archive_config = config.archive_config();
    if archive_config.enabled() {
        tracing::info!(
            "GRASP-05 archive mode enabled: archive_all={}, whitelist_entries={}, read_only={}",
            archive_config.archive_all,
            archive_config.whitelist.len(),
            archive_config.read_only
        );
    }

    // Log repository configuration
    let repository_config = config.repository_config();
    if repository_config.enabled() {
        tracing::info!(
            "Repository whitelist enabled: whitelist_entries={}",
            repository_config.whitelist.len()
        );
    }

    let lifecycle = match config.database_backend {
        DatabaseBackend::Memory => RepositoryLifecycle::in_memory(),
        DatabaseBackend::Lmdb => RepositoryLifecycle::for_git_data_path(Path::new(&git_data_path)),
    };

    // Create write policy with purgatory integration
    let write_policy = Nip34WritePolicy::new(
        database.clone(),
        tombstones.clone(),
        holding.clone(),
        lifecycle.clone(),
        history.clone(),
        &git_data_path,
        purgatory,
        config.clone(),
        repo_init_locks,
    );

    // GRASP-P private repositories: construct + install the service BEFORE the
    // relay builder clones the write policy so every admission path sees it.
    let private = if config.private_repos_enable {
        let service = crate::private::PrivateService::new(config, database.clone()).await?;
        write_policy.set_private(service.clone());
        Some(service)
    } else {
        None
    };

    let mut builder = LocalRelayBuilder::default()
        .database(database.clone())
        .write_policy(write_policy.clone())
        // Explicitly set rate limits (make defaults visible in code)
        // Per-connection limits: 500 max subscriptions, 60 events/min
        .rate_limit(RateLimit {
            max_reqs: 500,        // Max concurrent subscriptions per connection
            notes_per_minute: 60, // Max events per minute per connection
        });

    if let Some(max) = config.max_connections {
        builder = builder.max_connections(max);
    }

    let relay = builder.build();

    let deletion_runtime = DeletionRuntime::new(
        write_policy.deletion().clone(),
        holding.clone(),
        config.holding_retention(),
        config.holding_cleanup_interval(),
    );

    tracing::info!(
        "Relay configured with GRASP-01 validation for domain: {}",
        config.domain
    );

    let deletion = write_policy.deletion().clone();

    Ok(RelayRuntime {
        relay,
        write_policy,
        deletion,
        deletion_runtime,
        lifecycle,
        stores: RelayStores {
            database,
            tombstones,
            holding,
            history,
        },
        private,
    })
}
