/// Nostr Relay Builder Configuration
///
/// This module integrates nostr-relay-builder with NIP-34 validation logic
/// using modular sub-policies for each event type.
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::{collections::BTreeSet, fs::File, process::Command};

use flate2::read::GzDecoder;
use nostr::nips::nip19::ToBech32;
use nostr_lmdb::NostrLmdb;
use nostr_memory::MemoryDatabase;
use nostr_relay_builder::prelude::*;
use tar::Archive as TarArchive;

use crate::config::{Config, DatabaseBackend};
use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::history::ReplaceableHistoryStore;
use crate::nostr::holding::{DeletionSource, RecoveryMetadataRecord};
use crate::nostr::policy::{
    accepted_purgatory, duplicate, reject_error, reject_invalid, reject_restricted,
    AnnouncementPolicy, AnnouncementResult, DeletionPolicy, PolicyContext, PrEventPolicy,
    ReferenceResult, RelatedEventPolicy, StatePolicy, StateResult,
};

/// Type alias for the shared database used by the relay
pub type SharedDatabase = Arc<dyn NostrDatabase>;

/// NIP-34 Write Policy with Full GRASP-01 Event Validation
///
/// Validates all events according to GRASP-01 specification using modular sub-policies:
/// - `AnnouncementPolicy` - Repository announcement validation
/// - `StatePolicy` - State event validation + ref alignment
/// - `PrEventPolicy` - PR/PR Update validation
/// - `RelatedEventPolicy` - Forward/backward reference checking
/// - `DeletionPolicy` - NIP-09 event deletion request handling
///
/// Uses stateful database queries to check event relationships.
#[derive(Clone)]
pub struct Nip34WritePolicy {
    ctx: PolicyContext,
    announcement_policy: AnnouncementPolicy,
    state_policy: StatePolicy,
    pr_event_policy: PrEventPolicy,
    related_event_policy: RelatedEventPolicy,
    deletion_policy: DeletionPolicy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlacklistParityStats {
    pub scanned_announcements: usize,
    pub matched_announcements: usize,
    pub attempted_deletions: usize,
    pub successful_deletions: usize,
    pub failed_deletions: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WhitelistParityStats {
    pub scanned_announcements: usize,
    pub mismatched_announcements: usize,
    pub attempted_deletions: usize,
    pub successful_deletions: usize,
    pub failed_deletions: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlacklistRestoreStats {
    pub scanned_scopes: usize,
    pub attempted_restores: usize,
    pub successful_restores: usize,
    pub failed_restores: usize,
    pub skipped_scopes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WhitelistRestoreStats {
    pub scanned_scopes: usize,
    pub attempted_restores: usize,
    pub successful_restores: usize,
    pub failed_restores: usize,
    pub skipped_scopes: usize,
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
    pub fn new(
        database: SharedDatabase,
        tombstones: crate::nostr::tombstones::Tombstones,
        holding: crate::nostr::holding::HoldingStore,
        history: crate::nostr::history::ReplaceableHistoryStore,
        git_data_path: impl Into<std::path::PathBuf>,
        purgatory: std::sync::Arc<crate::purgatory::Purgatory>,
        config: crate::config::Config,
        repo_init_locks: crate::grasp06::receive::RepoInitLocks,
    ) -> Self {
        let ctx = PolicyContext::new(
            &config.domain,
            database,
            tombstones,
            holding,
            history,
            git_data_path,
            purgatory,
            config.clone(),
            repo_init_locks,
        );
        Self {
            announcement_policy: AnnouncementPolicy::new(ctx.clone(), config.clone()),
            state_policy: StatePolicy::new(ctx.clone()),
            pr_event_policy: PrEventPolicy::new(ctx.clone()),
            related_event_policy: RelatedEventPolicy::new(ctx.clone()),
            deletion_policy: DeletionPolicy::new(ctx.clone()),
            ctx,
        }
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
    pub fn holding(&self) -> &crate::nostr::holding::HoldingStore {
        &self.ctx.holding
    }

    /// Get a reference to the replaceable-history store.
    pub fn history(&self) -> &crate::nostr::history::ReplaceableHistoryStore {
        &self.ctx.history
    }

    pub fn tombstones(&self) -> &crate::nostr::tombstones::Tombstones {
        &self.ctx.tombstones
    }

    /// Startup-only blacklist parity pass.
    ///
    /// Scans already-stored kind-30617 announcements, identifies entries
    /// matching `repository_blacklist`, and applies the same deletion pipeline as
    /// NIP-09 (cascade + holding/archive) but with `DeletionSource::Blacklist`.
    pub async fn run_startup_blacklist_parity_pass(&self) -> BlacklistParityStats {
        let blacklist = self.ctx.config.blacklist_config();
        if !blacklist.enabled() {
            return BlacklistParityStats::default();
        }

        let announcements = match self
            .ctx
            .database
            .query(Filter::new().kind(Kind::GitRepoAnnouncement))
            .await
        {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(error = %e, "Blacklist startup parity scan failed to query announcements");
                return BlacklistParityStats::default();
            }
        };

        let mut stats = BlacklistParityStats {
            scanned_announcements: announcements.len(),
            ..BlacklistParityStats::default()
        };

        for announcement in announcements {
            let parsed = match RepositoryAnnouncement::from_event(announcement.clone()) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        event_id = %announcement.id.to_hex(),
                        error = %e,
                        "Blacklist startup parity: skipping unparseable announcement"
                    );
                    continue;
                }
            };

            let npub = announcement
                .pubkey
                .to_bech32()
                .expect("public key to bech32 should be infallible");

            let Some(reason) = blacklist.check(&npub, &parsed.identifier) else {
                continue;
            };

            stats.matched_announcements += 1;
            stats.attempted_deletions += 1;
            crate::metrics::record_blacklist_deletion_attempt("startup");

            match self
                .deletion_policy
                .apply_blacklist_deletion_for_announcement(&announcement)
                .await
            {
                Ok(()) => {
                    stats.successful_deletions += 1;
                    crate::metrics::record_blacklist_deletion_success("startup");
                    tracing::info!(
                        event_id = %announcement.id.to_hex(),
                        owner = %announcement.pubkey.to_hex(),
                        identifier = %parsed.identifier,
                        reason = %reason,
                        "Blacklist startup parity: deleted stored repository"
                    );
                }
                Err(e) => {
                    stats.failed_deletions += 1;
                    crate::metrics::record_blacklist_deletion_failure("startup");
                    tracing::error!(
                        event_id = %announcement.id.to_hex(),
                        owner = %announcement.pubkey.to_hex(),
                        identifier = %parsed.identifier,
                        reason = %reason,
                        error = %e,
                        "Blacklist startup parity: deletion failed"
                    );
                }
            }
        }

        stats
    }

    /// Startup-only whitelist parity pass.
    ///
    /// Scans already-stored kind-30617 announcements that list this relay's
    /// service domain and removes repositories that no longer match
    /// `repository_whitelist`, using the same cascade + holding/archive flow as
    /// NIP-09 but with `DeletionSource::Whitelist`.
    pub async fn run_startup_whitelist_parity_pass(&self) -> WhitelistParityStats {
        let whitelist = self.ctx.config.repository_config();
        if !whitelist.enabled() {
            return WhitelistParityStats::default();
        }

        let blacklist = self.ctx.config.blacklist_config();
        let announcements = match self
            .ctx
            .database
            .query(Filter::new().kind(Kind::GitRepoAnnouncement))
            .await
        {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(error = %e, "Whitelist startup parity scan failed to query announcements");
                return WhitelistParityStats::default();
            }
        };

        let mut stats = WhitelistParityStats {
            scanned_announcements: announcements.len(),
            ..WhitelistParityStats::default()
        };

        for announcement in announcements {
            let parsed = match RepositoryAnnouncement::from_event(announcement.clone()) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        event_id = %announcement.id.to_hex(),
                        error = %e,
                        "Whitelist startup parity: skipping unparseable announcement"
                    );
                    continue;
                }
            };

            if !parsed.lists_service(&self.ctx.domain) {
                continue;
            }

            let npub = announcement
                .pubkey
                .to_bech32()
                .expect("public key to bech32 should be infallible");

            // Blacklist precedence: if this repository is blacklisted, it belongs to
            // the blacklist parity path and should be attributed there.
            if blacklist.check(&npub, &parsed.identifier).is_some() {
                continue;
            }

            if whitelist.matches(&npub, &parsed.identifier) {
                continue;
            }

            stats.mismatched_announcements += 1;
            stats.attempted_deletions += 1;

            match self
                .deletion_policy
                .apply_whitelist_deletion_for_announcement(&announcement)
                .await
            {
                Ok(()) => {
                    stats.successful_deletions += 1;
                    tracing::info!(
                        event_id = %announcement.id.to_hex(),
                        owner = %announcement.pubkey.to_hex(),
                        identifier = %parsed.identifier,
                        "Whitelist startup parity: deleted stored repository"
                    );
                }
                Err(e) => {
                    stats.failed_deletions += 1;
                    tracing::error!(
                        event_id = %announcement.id.to_hex(),
                        owner = %announcement.pubkey.to_hex(),
                        identifier = %parsed.identifier,
                        error = %e,
                        "Whitelist startup parity: deletion failed"
                    );
                }
            }
        }

        stats
    }

    /// Startup-only blacklist restore pass.
    ///
    /// Scans holding metadata for scopes deleted by blacklist parity and restores
    /// owner+identifier scopes that are no longer blacklisted and still inside
    /// holding retention.
    pub async fn run_startup_blacklist_restore_pass(&self) -> BlacklistRestoreStats {
        if !self.ctx.config.blacklist_auto_restore {
            return BlacklistRestoreStats::default();
        }

        let now = Timestamp::now();
        let retention = self.ctx.config.holding_retention();
        let scopes = self
            .ctx
            .holding
            .eligible_recovery_scopes_by_source(DeletionSource::Blacklist, now, retention)
            .await;

        let blacklist = self.ctx.config.blacklist_config();
        let mut stats = BlacklistRestoreStats {
            scanned_scopes: scopes.len(),
            ..BlacklistRestoreStats::default()
        };

        for scope in scopes {
            let owner_pubkey = match PublicKey::from_hex(&scope.owner_pubkey_hex) {
                Ok(pubkey) => pubkey,
                Err(e) => {
                    stats.skipped_scopes += 1;
                    crate::metrics::record_blacklist_startup_restore_skipped("invalid_owner");
                    tracing::warn!(
                        owner = %scope.owner_pubkey_hex,
                        identifier = %scope.identifier,
                        reason = "invalid_owner",
                        error = %e,
                        "Blacklist startup restore: skipping scope"
                    );
                    continue;
                }
            };

            let owner_npub = match owner_pubkey.to_bech32() {
                Ok(npub) => npub,
                Err(e) => {
                    stats.skipped_scopes += 1;
                    crate::metrics::record_blacklist_startup_restore_skipped("owner_bech32_failed");
                    tracing::warn!(
                        owner = %scope.owner_pubkey_hex,
                        identifier = %scope.identifier,
                        reason = "owner_bech32_failed",
                        error = %e,
                        "Blacklist startup restore: skipping scope"
                    );
                    continue;
                }
            };

            if let Some(reason) = blacklist.check(&owner_npub, &scope.identifier) {
                stats.skipped_scopes += 1;
                crate::metrics::record_blacklist_startup_restore_skipped("still_blacklisted");
                tracing::info!(
                    owner = %scope.owner_pubkey_hex,
                    identifier = %scope.identifier,
                    reason = %reason,
                    "Blacklist startup restore: skipping scope still blacklisted"
                );
                continue;
            }

            stats.attempted_restores += 1;
            crate::metrics::record_blacklist_startup_restore_attempt();

            if self
                .maybe_recover_deleted_repository_for_scope(&owner_pubkey, &scope.identifier)
                .await
            {
                stats.successful_restores += 1;
                crate::metrics::record_blacklist_startup_restore_success();
                tracing::info!(
                    owner = %scope.owner_pubkey_hex,
                    identifier = %scope.identifier,
                    reason = "unblacklisted_within_retention",
                    "Blacklist startup restore: restored repository scope"
                );
            } else {
                stats.failed_restores += 1;
                crate::metrics::record_blacklist_startup_restore_failure();
                tracing::error!(
                    owner = %scope.owner_pubkey_hex,
                    identifier = %scope.identifier,
                    reason = "recovery_pipeline_failed",
                    "Blacklist startup restore: recovery pipeline failed"
                );
            }
        }

        stats
    }

    /// Startup-only whitelist restore pass.
    ///
    /// Scans holding metadata for scopes deleted by whitelist parity and restores
    /// owner+identifier scopes that now match `repository_whitelist`, are not
    /// blacklisted, and are still inside holding retention.
    pub async fn run_startup_whitelist_restore_pass(&self) -> WhitelistRestoreStats {
        let whitelist = self.ctx.config.repository_config();
        if !whitelist.enabled() {
            return WhitelistRestoreStats::default();
        }

        let now = Timestamp::now();
        let retention = self.ctx.config.holding_retention();
        let scopes = self
            .ctx
            .holding
            .eligible_recovery_scopes_by_source(DeletionSource::Whitelist, now, retention)
            .await;

        let blacklist = self.ctx.config.blacklist_config();
        let mut stats = WhitelistRestoreStats {
            scanned_scopes: scopes.len(),
            ..WhitelistRestoreStats::default()
        };

        for scope in scopes {
            let owner_pubkey = match PublicKey::from_hex(&scope.owner_pubkey_hex) {
                Ok(pubkey) => pubkey,
                Err(e) => {
                    stats.skipped_scopes += 1;
                    crate::metrics::record_whitelist_startup_restore_skipped("invalid_owner");
                    tracing::warn!(
                        owner = %scope.owner_pubkey_hex,
                        identifier = %scope.identifier,
                        reason = "invalid_owner",
                        error = %e,
                        "Whitelist startup restore: skipping scope"
                    );
                    continue;
                }
            };

            let owner_npub = match owner_pubkey.to_bech32() {
                Ok(npub) => npub,
                Err(e) => {
                    stats.skipped_scopes += 1;
                    crate::metrics::record_whitelist_startup_restore_skipped("owner_bech32_failed");
                    tracing::warn!(
                        owner = %scope.owner_pubkey_hex,
                        identifier = %scope.identifier,
                        reason = "owner_bech32_failed",
                        error = %e,
                        "Whitelist startup restore: skipping scope"
                    );
                    continue;
                }
            };

            if let Some(reason) = blacklist.check(&owner_npub, &scope.identifier) {
                stats.skipped_scopes += 1;
                crate::metrics::record_whitelist_startup_restore_skipped("still_blacklisted");
                tracing::info!(
                    owner = %scope.owner_pubkey_hex,
                    identifier = %scope.identifier,
                    reason = %reason,
                    "Whitelist startup restore: skipping scope still blacklisted"
                );
                continue;
            }

            if !whitelist.matches(&owner_npub, &scope.identifier) {
                stats.skipped_scopes += 1;
                crate::metrics::record_whitelist_startup_restore_skipped("not_whitelisted");
                tracing::info!(
                    owner = %scope.owner_pubkey_hex,
                    identifier = %scope.identifier,
                    reason = "not_whitelisted",
                    "Whitelist startup restore: skipping scope"
                );
                continue;
            }

            stats.attempted_restores += 1;
            crate::metrics::record_whitelist_startup_restore_attempt();

            if self
                .maybe_recover_deleted_repository_for_scope(&owner_pubkey, &scope.identifier)
                .await
            {
                stats.successful_restores += 1;
                crate::metrics::record_whitelist_startup_restore_success();
                tracing::info!(
                    owner = %scope.owner_pubkey_hex,
                    identifier = %scope.identifier,
                    reason = "now_whitelisted_within_retention",
                    "Whitelist startup restore: restored repository scope"
                );
            } else {
                stats.failed_restores += 1;
                crate::metrics::record_whitelist_startup_restore_failure();
                tracing::error!(
                    owner = %scope.owner_pubkey_hex,
                    identifier = %scope.identifier,
                    reason = "recovery_pipeline_failed",
                    "Whitelist startup restore: recovery pipeline failed"
                );
            }
        }

        stats
    }

    /// Set the local relay for purgatory notifications.
    ///
    /// This must be called after the relay is created since the relay depends
    /// on this policy, but purgatory sync needs the relay to notify subscribers.
    pub fn set_local_relay(&self, relay: nostr_relay_builder::LocalRelay) {
        self.ctx.set_local_relay(relay);
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

        match self.announcement_policy.validate(event).await {
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

                        // Phase 5 recovery trigger: accepted re-announcement for
                        // same owner+identifier can restore holding/archive state.
                        self.maybe_recover_deleted_repository(event, &announcement.identifier)
                            .await;

                        tracing::debug!("Accepted repository announcement: {}", event_id_str);

                        // Check purgatory for state events that might now be authorized
                        self.check_purgatory_state_events_for_identifier(&announcement.identifier)
                            .await;

                        self.capture_superseded_replaceable_history(event).await;

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

                // Phase 5 recovery trigger for deleted repos: if eligible holding
                // state exists, restore and accept immediately (no purgatory wait).
                let recovered = self
                    .maybe_recover_deleted_repository(event, &announcement.identifier)
                    .await;
                if recovered {
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
                    self.capture_superseded_replaceable_history(event).await;
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
                        // Phase 5 recovery trigger: any accepted announcement route
                        // (including maintainer acceptance) can restore eligible
                        // holding/archive state for this owner+identifier.
                        self.maybe_recover_deleted_repository(event, &announcement.identifier)
                            .await;

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

                        self.capture_superseded_replaceable_history(event).await;

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
                // Process state alignment asynchronously
                match self
                    .state_policy
                    .process_state_event(event, is_synced, Some(self))
                    .await
                {
                    Ok(policy_result) => {
                        if Self::event_persists_to_main_db(&policy_result) {
                            self.capture_superseded_replaceable_history(event).await;
                        }
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
        // deleted PR is already rejected upstream by `deletion_gate`.
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
        // GRASP-06 (06.md lines 21–24) relaxes this: a PR / PR-Update event
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
            // Re-evaluate authorization with the new announcement
            match self
                .state_policy
                .process_state_event(&entry.event, false, Some(self))
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

    /// Deletion / vanish gate run before kind-specific handling.
    ///
    /// Reproduces the rejection the relay-builder's `check_id` gate used to
    /// provide when the LMDB backend auto-processed NIP-09/NIP-62. Returns
    /// `Some(rejection)` if the event must be rejected, `None` to continue.
    ///
    /// Checks, in the same order the backend used:
    /// 1. author pubkey has requested to vanish from this relay
    /// 2. the event id was deleted by a recorded kind-5 (`e` tag)
    /// 3. the event's replaceable/addressable coordinate was deleted by a
    ///    recorded kind-5 (`a` tag) at or after this event's `created_at`
    ///
    /// Fresh kind-5 / kind-62 events pass this gate naturally: their tombstone
    /// is only recorded *after* successful handling, so they are not yet in the
    /// store when the gate runs.
    async fn deletion_gate(&self, event: &Event) -> Option<WritePolicyResult> {
        // 1. Vanished pubkey
        if self.ctx.tombstones.is_pubkey_vanished(&event.pubkey).await {
            tracing::debug!(
                event_id = %event.id.to_hex(),
                author = %event.pubkey.to_hex(),
                "Rejected event from vanished pubkey"
            );
            return Some(reject_invalid("this pubkey has requested to vanish"));
        }

        // 2. Deleted event id (author-bound: only the event's own author may
        //    have deleted it)
        if self
            .ctx
            .tombstones
            .is_event_deleted(&event.id, &event.pubkey)
            .await
        {
            tracing::debug!(
                event_id = %event.id.to_hex(),
                "Rejected re-submission of deleted event"
            );
            return Some(reject_invalid("this event is deleted"));
        }

        // 3. Deleted coordinate (replaceable / addressable events only)
        if event.kind.is_replaceable() || event.kind.is_addressable() {
            let coordinate = Self::event_coordinate(event);
            if let Some(coord) = coordinate {
                if self
                    .ctx
                    .tombstones
                    .is_coordinate_deleted(&coord, event.created_at)
                    .await
                {
                    tracing::debug!(
                        event_id = %event.id.to_hex(),
                        coordinate = %coord,
                        "Rejected event whose coordinate was deleted"
                    );
                    return Some(reject_invalid("this event is deleted"));
                }
            }
        }

        None
    }

    /// Build the NIP-01 addressable/replaceable coordinate string
    /// `<kind>:<pubkey-hex>:<d-identifier>` for an event, matching the format
    /// used in NIP-09 `a` tags. Returns `None` for non-(addressable/replaceable)
    /// events.
    fn event_coordinate(event: &Event) -> Option<String> {
        if !(event.kind.is_replaceable() || event.kind.is_addressable()) {
            return None;
        }
        let identifier = if event.kind.is_addressable() {
            event
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .unwrap_or("")
        } else {
            ""
        };
        Some(format!(
            "{}:{}:{}",
            event.kind.as_u16(),
            event.pubkey.to_hex(),
            identifier
        ))
    }

    fn extract_addressable_identifier(event: &Event) -> Option<String> {
        event.tags.iter().find_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == "d" {
                Some(v[1].clone())
            } else {
                None
            }
        })
    }

    fn should_capture_replaceable_history(kind: Kind) -> bool {
        kind == Kind::GitRepoAnnouncement || kind == Kind::RepoState
    }

    fn event_persists_to_main_db(result: &WritePolicyResult) -> bool {
        matches!(result, WritePolicyResult::Accept)
    }

    async fn capture_superseded_replaceable_history(&self, incoming: &Event) {
        if !Self::should_capture_replaceable_history(incoming.kind) {
            return;
        }

        let Some(coordinate) = Self::event_coordinate(incoming) else {
            return;
        };

        let Some(identifier) = Self::extract_addressable_identifier(incoming) else {
            tracing::warn!(
                event_id = %incoming.id.to_hex(),
                kind = incoming.kind.as_u16(),
                "Skipping history capture for addressable event without d tag"
            );
            return;
        };

        let filter = Filter::new()
            .kind(incoming.kind)
            .author(incoming.pubkey)
            .identifier(identifier);

        let existing = match self.ctx.database.query(filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    event_id = %incoming.id.to_hex(),
                    coordinate = %coordinate,
                    "Failed querying existing events for history capture"
                );
                return;
            }
        };

        for superseded in existing {
            if superseded.id == incoming.id || superseded.created_at >= incoming.created_at {
                continue;
            }

            if let Err(e) = self
                .ctx
                .history
                .archive_superseded_event(&superseded, incoming, &coordinate)
                .await
            {
                tracing::warn!(
                    error = %e,
                    superseded_event_id = %superseded.id.to_hex(),
                    replaced_by = %incoming.id.to_hex(),
                    coordinate = %coordinate,
                    "Failed to archive superseded replaceable/addressable event"
                );
            }
        }
    }

    /// Handle a NIP-62 request-to-vanish (kind 62).
    ///
    /// Reproduces the LMDB backend's vanish behaviour now that we run with
    /// `process_nip62(false)`:
    /// - record the vanish request in the persistent tombstone store so future
    ///   events from this pubkey are rejected (the [`deletion_gate`]),
    /// - hard-delete the author's events from the main database,
    /// - evict any of the author's purgatory entries and delete their bare repos.
    ///
    /// Only requests targeting this relay (or `ALL_RELAYS`) are honoured; the
    /// signer is implicitly the pubkey being vanished, so author validation is
    /// inherent.
    async fn handle_vanish(&self, event: &Event) -> WritePolicyResult {
        use nostr_relay_builder::prelude::nip62;

        // Only honour requests that target this relay (or all relays). We do not
        // configure a relay_url on the database, matching the historical
        // behaviour where only ALL_RELAYS requests were actioned; but we accept
        // (store) any well-formed kind-62 so clients get an OK.
        let targets_relay = nip62::is_valid_vanish_request_for_relay(event.tags.as_slice(), None);

        if !targets_relay {
            tracing::debug!(
                author = %event.pubkey.to_hex(),
                "kind-62 vanish request does not target this relay; storing without action"
            );
            return WritePolicyResult::Accept;
        }

        let author = event.pubkey;

        // 1. Record the vanish so re-submission of the author's events is blocked.
        if let Err(e) = self.ctx.tombstones.record_vanish(event).await {
            tracing::error!(error = %e, author = %author.to_hex(), "Failed to record vanish tombstone");
            return reject_error(format!("internal error recording vanish: {e}"));
        }

        // 2. Hard-delete the author's events from the main database.
        let filter = Filter::new().author(author);
        if let Err(e) = self.ctx.database.delete(filter).await {
            tracing::error!(error = %e, author = %author.to_hex(), "Failed to delete vanished author's events");
            return reject_error(format!("internal error processing vanish: {e}"));
        }

        // 3. Evict the author's purgatory entries (and their bare repos).
        self.evict_author_from_purgatory(&author);

        tracing::info!(
            author = %author.to_hex(),
            "Processed NIP-62 request to vanish: deleted author's events and purgatory entries"
        );

        WritePolicyResult::Accept
    }

    /// Remove all purgatory entries authored by `author` and delete any bare
    /// repositories backing purgatory announcements they owned.
    fn evict_author_from_purgatory(&self, author: &nostr_relay_builder::prelude::PublicKey) {
        // Announcements owned by this author.
        for (repo_id, _) in self.ctx.purgatory.announcements_for_sync() {
            // repo_id format: "30617:{pubkey_hex}:{identifier}"
            let parts: Vec<&str> = repo_id.splitn(3, ':').collect();
            if parts.len() != 3 || parts[1] != author.to_hex() {
                continue;
            }
            let identifier = parts[2];
            if let Some(entry) = self.ctx.purgatory.find_announcement(author, identifier) {
                if entry.repo_path.exists() {
                    if let Err(e) = std::fs::remove_dir_all(&entry.repo_path) {
                        tracing::warn!(
                            path = %entry.repo_path.display(),
                            error = %e,
                            "Failed to delete bare repository during vanish processing"
                        );
                    }
                }
            }
            self.ctx.purgatory.remove_announcement(author, identifier);
        }

        // State events authored by this author across all identifiers.
        for identifier in self.ctx.purgatory.get_all_identifiers() {
            for entry in self.ctx.purgatory.find_state(&identifier) {
                if entry.author == *author {
                    self.ctx
                        .purgatory
                        .remove_state_event(&identifier, &entry.event.id);
                }
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
            if let Some(rejection) = self.deletion_gate(event).await {
                return rejection;
            }

            // Detect if this is a synced event (from proactive sync) vs user-submitted
            // Sync uses localhost:0 as a dummy address
            let is_synced = addr.ip().is_loopback() && addr.port() == 0;

            match event.kind {
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
                Kind::EventDeletion => self.deletion_policy.handle(event).await,
                Kind::RequestToVanish => self.handle_vanish(event).await,
                _ => self.handle_related_event(event, "Event").await,
            }
        })
    }
}

/// Result of creating a relay - includes relay, database, and write policy
pub struct RelayWithDatabase {
    /// The local relay instance
    pub relay: LocalRelay,
    /// The database Arc that can be used for direct queries
    pub database: SharedDatabase,
    /// The write policy used for event validation
    pub write_policy: Nip34WritePolicy,
    /// Holding store used for deletion archival + expiry cleanup
    pub holding: crate::nostr::holding::HoldingStore,
    /// Replaceable-history store used for rollback history capture.
    pub history: crate::nostr::history::ReplaceableHistoryStore,
}

/// Create a configured LocalRelay with full GRASP-01 validation
///
/// Returns a `RelayWithDatabase` struct containing:
/// - The `LocalRelay` for handling WebSocket connections
/// - The `SharedDatabase` for direct database queries (e.g., push authorization)
pub async fn create_relay(
    config: &Config,
    purgatory: Arc<crate::purgatory::Purgatory>,
    repo_init_locks: crate::grasp06::receive::RepoInitLocks,
) -> Result<RelayWithDatabase> {
    tracing::info!("Configuring nostr relay with GRASP-01 validation...");

    // Determine database path
    let db_path = Path::new(&config.relay_data_path);

    // Create database based on configuration
    //
    // NIP-09 (deletion) and NIP-62 (request to vanish) auto-processing is
    // explicitly disabled on the main database: ngit-grasp owns this handling
    // (see `DeletionPolicy`, the kind-62 handler, and the `Tombstones` store).
    // Leaving the backend defaults (`true`) would double-process: the backend
    // would silently hard-delete events and block re-submission via its own
    // internal tables that we cannot inspect, conflicting with our purgatory /
    // bare-repo bookkeeping.
    let (database, tombstones, holding, history): (
        SharedDatabase,
        crate::nostr::tombstones::Tombstones,
        crate::nostr::holding::HoldingStore,
        ReplaceableHistoryStore,
    ) = match config.database_backend {
        DatabaseBackend::Memory => {
            tracing::info!("Using in-memory database (no persistence)");
            // Disable the backend's built-in NIP-09 / NIP-62 auto-processing to
            // match the LMDB path: ngit-grasp owns this handling (DeletionPolicy,
            // the kind-62 handler, and the Tombstones store). Leaving the memory
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
                crate::nostr::tombstones::Tombstones::in_memory(),
                crate::nostr::holding::HoldingStore::in_memory(),
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
            let tombstones = crate::nostr::tombstones::Tombstones::open_lmdb(db_path).await?;
            let holding = crate::nostr::holding::HoldingStore::open_lmdb(
                db_path,
                Path::new(&config.effective_git_data_path()),
            )
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

    // Create write policy with purgatory integration
    let write_policy = Nip34WritePolicy::new(
        database.clone(),
        tombstones,
        holding.clone(),
        history.clone(),
        &git_data_path,
        purgatory,
        config.clone(),
        repo_init_locks,
    );

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

    tracing::info!(
        "Relay configured with GRASP-01 validation for domain: {}",
        config.domain
    );

    Ok(RelayWithDatabase {
        relay,
        database,
        write_policy,
        holding,
        history,
    })
}

impl Nip34WritePolicy {
    fn owner_directory_component(pubkey: &PublicKey) -> String {
        pubkey.to_bech32().unwrap_or_else(|_| pubkey.to_hex())
    }

    fn repo_path_for_owner_and_identifier(
        &self,
        owner_path_component: &str,
        identifier: &str,
    ) -> PathBuf {
        self.ctx
            .git_data_path
            .join(owner_path_component)
            .join(format!("{}.git", identifier))
    }

    fn restore_git_archive_to_repo(
        &self,
        archive_path: &Path,
        owner_path_component: &str,
        identifier: &str,
    ) -> anyhow::Result<bool> {
        let target_repo = self.repo_path_for_owner_and_identifier(owner_path_component, identifier);

        let owner_dir = target_repo
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid repository path {}", target_repo.display()))?;
        std::fs::create_dir_all(owner_dir).map_err(|e| {
            anyhow::anyhow!(
                "failed to create owner directory {}: {}",
                owner_dir.display(),
                e
            )
        })?;

        let staging_dir = owner_dir.join(format!(
            ".restore-{}-{}",
            identifier,
            Timestamp::now().as_secs()
        ));
        if staging_dir.exists() {
            let _ = std::fs::remove_dir_all(&staging_dir);
        }
        std::fs::create_dir_all(&staging_dir).map_err(|e| {
            anyhow::anyhow!(
                "failed to create restore staging directory {}: {}",
                staging_dir.display(),
                e
            )
        })?;

        let result = (|| -> anyhow::Result<bool> {
            let archive_file = File::open(archive_path).map_err(|e| {
                anyhow::anyhow!("failed to open archive {}: {}", archive_path.display(), e)
            })?;
            let decoder = GzDecoder::new(archive_file);
            let mut tar = TarArchive::new(decoder);
            tar.unpack(&staging_dir).map_err(|e| {
                anyhow::anyhow!(
                    "failed to extract archive {} into {}: {}",
                    archive_path.display(),
                    staging_dir.display(),
                    e
                )
            })?;

            let extracted_repo = staging_dir.join(format!("{}.git", identifier));
            if !extracted_repo.is_dir() {
                return Err(anyhow::anyhow!(
                    "archive {} did not contain {}.git",
                    archive_path.display(),
                    identifier
                ));
            }

            if target_repo.is_dir() {
                return Self::restore_archived_nostr_refs(&extracted_repo, &target_repo);
            }

            std::fs::rename(&extracted_repo, &target_repo)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to move restored repository {} -> {}: {}",
                        extracted_repo.display(),
                        target_repo.display(),
                        e
                    )
                })
                .map(|_| true)
        })();

        let _ = std::fs::remove_dir_all(&staging_dir);
        result
    }

    fn restore_archived_nostr_refs(source_repo: &Path, target_repo: &Path) -> anyhow::Result<bool> {
        let source_repo_str = source_repo
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid source repo path {}", source_repo.display()))?;

        let list_output = Command::new("git")
            .args([
                "--git-dir",
                source_repo_str,
                "for-each-ref",
                "--format=%(objectname) %(refname)",
                "refs/nostr/",
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("failed to list archived refs/nostr: {e}"))?;

        if !list_output.status.success() {
            let stderr = String::from_utf8_lossy(&list_output.stderr);
            return Err(anyhow::anyhow!(
                "failed listing archived refs/nostr from {}: {}",
                source_repo.display(),
                stderr
            ));
        }

        let stdout = String::from_utf8_lossy(&list_output.stdout);
        let mut restored_any = false;

        for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
            let Some((oid, ref_name)) = line.split_once(' ') else {
                continue;
            };

            if !crate::git::oid_exists(target_repo, oid) {
                let fetch_output = Command::new("git")
                    .args(["fetch", source_repo_str, oid])
                    .current_dir(target_repo)
                    .output()
                    .map_err(|e| anyhow::anyhow!("failed to fetch archived OID {oid}: {e}"))?;
                if !fetch_output.status.success() {
                    let stderr = String::from_utf8_lossy(&fetch_output.stderr);
                    return Err(anyhow::anyhow!(
                        "failed fetching archived OID {} into {}: {}",
                        oid,
                        target_repo.display(),
                        stderr
                    ));
                }
            }

            crate::git::update_ref(target_repo, ref_name, oid).map_err(|e| {
                anyhow::anyhow!(
                    "failed to restore archived ref {} -> {} into {}: {}",
                    ref_name,
                    oid,
                    target_repo.display(),
                    e
                )
            })?;
            restored_any = true;
        }

        Ok(restored_any)
    }

    fn pr_event_commit(event: &Event) -> Option<String> {
        event.tags.iter().find_map(|tag| {
            let parts = tag.as_slice();
            if parts.len() >= 2 && parts[0] == "c" {
                Some(parts[1].clone())
            } else {
                None
            }
        })
    }

    fn pr_event_identifiers(event: &Event) -> BTreeSet<String> {
        event
            .tags
            .iter()
            .filter_map(|tag| {
                let parts = tag.as_slice();
                if parts.len() < 2 || parts[0] != "a" {
                    return None;
                }

                let coord: Vec<&str> = parts[1].splitn(3, ':').collect();
                if coord.len() != 3 || coord[0] != "30617" {
                    return None;
                }

                Some(coord[2].to_string())
            })
            .collect()
    }

    async fn pr_target_repo_paths_for_recovery(&self, event: &Event) -> BTreeSet<PathBuf> {
        let mut paths = BTreeSet::new();

        for identifier in Self::pr_event_identifiers(event) {
            let Ok(repo_data) =
                crate::git::authorization::fetch_repository_data_excluding_purgatory(
                    &self.ctx.database,
                    &identifier,
                )
                .await
            else {
                continue;
            };

            for announcement in &repo_data.announcements {
                paths.insert(self.ctx.git_data_path.join(announcement.repo_path()));
            }
        }

        for identifier in crate::grasp06::policy::prs_identifiers_named_by_event_clone_tags(
            event,
            &self.ctx.config.domain,
        ) {
            paths.insert(crate::grasp06::paths::prs_repo_path(
                &self.ctx.git_data_path,
                &event.pubkey.to_hex(),
                &identifier,
            ));
        }

        paths
    }

    async fn restore_pr_git_refs_for_recovered_event(&self, event: &Event) -> anyhow::Result<bool> {
        if !matches!(
            event.kind,
            Kind::GitPullRequest | Kind::GitPullRequestUpdate
        ) {
            return Ok(true);
        }

        let Some(commit) = Self::pr_event_commit(event) else {
            tracing::warn!(
                event_id = %event.id.to_hex(),
                "Recovery could not restore PR git ref: event missing c-tag"
            );
            return Ok(false);
        };

        let ref_name = format!("refs/nostr/{}", event.id.to_hex());
        let mut restored_any = false;
        let repo_paths = self.pr_target_repo_paths_for_recovery(event).await;

        for repo_path in repo_paths {
            if !repo_path.is_dir() {
                continue;
            }

            if !crate::git::commit_exists(&repo_path, &commit) {
                continue;
            }

            crate::git::update_ref(&repo_path, &ref_name, &commit).map_err(|e| {
                anyhow::anyhow!(
                    "failed to restore PR ref {} -> {} in {}: {}",
                    ref_name,
                    commit,
                    repo_path.display(),
                    e
                )
            })?;
            restored_any = true;
        }

        if !restored_any {
            tracing::warn!(
                event_id = %event.id.to_hex(),
                ref_name = %ref_name,
                commit = %commit,
                "Recovery did not find a repository with commit needed to restore PR ref"
            );
        }

        Ok(restored_any)
    }

    async fn restore_events_from_holding(
        &self,
        records: &[RecoveryMetadataRecord],
    ) -> (Vec<RecoveryMetadataRecord>, Vec<RecoveryMetadataRecord>) {
        let mut restorable = Vec::new();
        let mut blocked = Vec::new();

        for record in records {
            let Some(event_id) = record.archived_event_id else {
                // Metadata-only row (no payload) can be cleaned up.
                restorable.push(record.clone());
                continue;
            };

            match self.ctx.holding.archived_event(&event_id).await {
                Ok(Some(event)) => {
                    if self.recovery_blocked_by_tombstone(&event).await {
                        tracing::info!(
                            event_id = %event.id.to_hex(),
                            kind = event.kind.as_u16(),
                            author = %event.pubkey.to_hex(),
                            "Recovery skipped event blocked by tombstone semantics"
                        );
                        // Tombstoned entries are intentionally non-restorable; clean up
                        // their holding metadata to keep repeated recovery attempts idempotent.
                        restorable.push(record.clone());
                        continue;
                    }

                    let already_exists = match self.ctx.database.event_by_id(&event_id).await {
                        Ok(Some(_)) => true,
                        Ok(None) => false,
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                event_id = %event_id.to_hex(),
                                "Recovery failed while checking main DB event existence"
                            );
                            blocked.push(record.clone());
                            continue;
                        }
                    };

                    if !already_exists {
                        if let Err(e) = self.ctx.database.save_event(&event).await {
                            tracing::error!(
                                error = %e,
                                event_id = %event_id.to_hex(),
                                "Recovery failed to restore event payload into main DB"
                            );
                            blocked.push(record.clone());
                            continue;
                        }
                    }

                    if matches!(
                        event.kind,
                        Kind::GitPullRequest | Kind::GitPullRequestUpdate
                    ) {
                        match self.restore_pr_git_refs_for_recovered_event(&event).await {
                            Ok(true) => {}
                            Ok(false) => {
                                blocked.push(record.clone());
                                continue;
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    event_id = %event_id.to_hex(),
                                    "Recovery failed restoring PR git refs"
                                );
                                blocked.push(record.clone());
                                continue;
                            }
                        }
                    }

                    restorable.push(record.clone());
                }
                Ok(None) => {
                    // Stale metadata referencing missing payload: deterministic
                    // behavior is to keep recovery moving and clean this row.
                    tracing::warn!(
                        event_id = %event_id.to_hex(),
                        "Recovery metadata referenced missing holding payload event; cleaning metadata"
                    );
                    restorable.push(record.clone());
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        event_id = %event_id.to_hex(),
                        "Recovery failed to load holding payload event"
                    );
                    blocked.push(record.clone());
                }
            }
        }

        (restorable, blocked)
    }

    async fn recovery_blocked_by_tombstone(&self, event: &Event) -> bool {
        if self.ctx.tombstones.is_pubkey_vanished(&event.pubkey).await {
            return true;
        }

        if self
            .ctx
            .tombstones
            .is_event_deleted(&event.id, &event.pubkey)
            .await
        {
            return true;
        }

        if event.kind.is_replaceable() || event.kind.is_addressable() {
            if let Some(coord) = Self::event_coordinate(event) {
                if self
                    .ctx
                    .tombstones
                    .is_coordinate_deleted(&coord, event.created_at)
                    .await
                {
                    return true;
                }
            }
        }

        false
    }

    pub(crate) async fn maybe_recover_deleted_repository(
        &self,
        event: &Event,
        identifier: &str,
    ) -> bool {
        self.maybe_recover_deleted_repository_for_scope(&event.pubkey, identifier)
            .await
    }

    async fn maybe_recover_deleted_repository_for_scope(
        &self,
        owner_pubkey: &PublicKey,
        identifier: &str,
    ) -> bool {
        let owner_hex = owner_pubkey.to_hex();
        let records = self
            .ctx
            .holding
            .eligible_recovery_records(
                &owner_hex,
                identifier,
                Timestamp::now(),
                crate::nostr::holding::DEFAULT_RETENTION,
            )
            .await;

        if records.is_empty() {
            return false;
        }

        crate::metrics::record_recovery_attempt();

        let mut archive_paths = BTreeSet::new();
        for record in &records {
            if let Some(path) = &record.archive_relative_path {
                archive_paths.insert(path.clone());
            }
        }

        let selected_archive_rel = archive_paths.iter().next().cloned();
        if archive_paths.len() > 1 {
            tracing::warn!(
                owner = %owner_hex,
                identifier = %identifier,
                selected_archive = ?selected_archive_rel,
                archives = ?archive_paths,
                "Recovery found multiple archive paths; selecting lexicographically first path"
            );
        }

        let owner_component = Self::owner_directory_component(owner_pubkey);
        let mut git_ready = true;
        let mut archive_restored = false;
        let mut selected_archive_abs: Option<PathBuf> = None;
        if let Some(rel_path) = &selected_archive_rel {
            match self.ctx.holding.archive_absolute_path(rel_path) {
                Some(abs_path) => {
                    selected_archive_abs = Some(abs_path.clone());
                    if !abs_path.exists() {
                        tracing::warn!(
                            owner = %owner_hex,
                            identifier = %identifier,
                            archive = %abs_path.display(),
                            "Recovery archive file missing; continuing with events-only recovery"
                        );
                        git_ready = false;
                    } else {
                        match self.restore_git_archive_to_repo(
                            &abs_path,
                            &owner_component,
                            identifier,
                        ) {
                            Ok(restored) => {
                                archive_restored = restored;
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    owner = %owner_hex,
                                    identifier = %identifier,
                                    archive = %abs_path.display(),
                                    "Recovery failed restoring git archive; aborting recovery"
                                );
                                crate::metrics::record_recovery_failed();
                                return false;
                            }
                        }
                    }
                }
                None => {
                    tracing::warn!(
                        owner = %owner_hex,
                        identifier = %identifier,
                        archive_rel = %rel_path,
                        "Recovery archive path is invalid; continuing with events-only recovery"
                    );
                    git_ready = false;
                }
            }
        }

        let (cleanup_candidates, blocked_records) =
            self.restore_events_from_holding(&records).await;
        if cleanup_candidates.is_empty() && !git_ready {
            tracing::warn!(
                owner = %owner_hex,
                identifier = %identifier,
                "Recovery found only non-restorable state"
            );
            crate::metrics::record_recovery_failed();
            return false;
        }

        let mut cleaned = 0usize;
        for record in &cleanup_candidates {
            match self.ctx.holding.delete_recovery_record(record).await {
                Ok((metadata_deleted, _payload_deleted)) => {
                    if metadata_deleted {
                        cleaned += 1;
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        metadata_event_id = %record.metadata_event_id.to_hex(),
                        "Recovery failed to clean up holding record"
                    );
                }
            }
        }

        let all_records_cleared = blocked_records.is_empty() && cleaned == cleanup_candidates.len();
        if all_records_cleared && selected_archive_rel.is_some() {
            if let Some(abs_path) = selected_archive_abs {
                match std::fs::remove_file(&abs_path) {
                    Ok(()) => {
                        tracing::info!(
                            owner = %owner_hex,
                            identifier = %identifier,
                            archive = %abs_path.display(),
                            "Recovery removed consumed git archive"
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            owner = %owner_hex,
                            identifier = %identifier,
                            archive = %abs_path.display(),
                            "Recovery failed to delete consumed archive file"
                        );
                    }
                }
            }
        }

        tracing::info!(
            owner = %owner_hex,
            identifier = %identifier,
            records_considered = records.len(),
            records_cleaned = cleaned,
            records_blocked = blocked_records.len(),
            archive_tracked = selected_archive_rel.is_some(),
            archive_restored = archive_restored,
            git_ready = git_ready,
            "Recovery workflow completed"
        );

        let partial = !blocked_records.is_empty() || !git_ready;
        if partial {
            crate::metrics::record_recovery_partial();
        } else {
            crate::metrics::record_recovery_success();
        }

        true
    }
}
