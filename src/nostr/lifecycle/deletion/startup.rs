use nostr::nips::nip19::ToBech32;
use std::collections::HashMap;

use anyhow::Result;
use nostr_relay_builder::prelude::{Event, Filter, Kind, PublicKey, Timestamp};

use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::lifecycle::{DeletionSource, RequestClassification};

use super::DeletionService;

// ---------------------------------------------------------------------------
// Stats structs
// ---------------------------------------------------------------------------

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StartupReconciliationStats {
    pub request_lifecycle: RequestLifecycleStartupStats,
    pub blacklist_parity: BlacklistParityStats,
    pub blacklist_restore: BlacklistRestoreStats,
    pub whitelist_parity: WhitelistParityStats,
    pub whitelist_restore: WhitelistRestoreStats,
}

/// Startup migration and policy reconciliation counters for retained deletion
/// requests. A failure is returned to the caller rather than represented as a
/// successful zero-count pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestLifecycleStartupStats {
    pub main_payloads_scanned: usize,
    pub tombstone_payloads_scanned: usize,
    pub unique_requests_discovered: usize,
    pub requests_migrated: usize,
    pub valid_metadata_existing: usize,
    pub requests_reclassified: usize,
    pub disrespector_requests_newly_used: usize,
    pub main_requests_promoted: usize,
    pub main_requests_removed: usize,
    pub failures: usize,
}

// ---------------------------------------------------------------------------
// DeletionService startup pass implementations
// ---------------------------------------------------------------------------

impl DeletionService {
    /// Run all startup reconciliation passes in the required order.
    ///
    /// Ordering is intentionally owned here so relay startup only depends on a
    /// single facade while deletion internals decide sequencing:
    /// 1) deletion request lifecycle migration and reconciliation
    /// 2) blacklist parity delete
    /// 3) blacklist auto-restore
    /// 4) whitelist parity delete
    /// 5) whitelist restore
    pub async fn run_startup_reconciliation(&self) -> Result<StartupReconciliationStats> {
        let request_lifecycle = self
            .run_request_lifecycle_startup_reconciliation(Timestamp::now())
            .await?;
        let blacklist_parity = self.run_startup_blacklist_parity_pass().await;
        let blacklist_restore = self.run_startup_blacklist_restore_pass().await;
        let whitelist_parity = self.run_startup_whitelist_parity_pass().await;
        let whitelist_restore = self.run_startup_whitelist_restore_pass().await;

        Ok(StartupReconciliationStats {
            request_lifecycle,
            blacklist_parity,
            blacklist_restore,
            whitelist_parity,
            whitelist_restore,
        })
    }

    /// Migrate historical request payloads and reconcile their current-policy
    /// serving state. The timestamp is supplied for deterministic tests and is
    /// captured once by the production startup pass.
    pub(crate) async fn run_request_lifecycle_startup_reconciliation(
        &self,
        now: Timestamp,
    ) -> Result<RequestLifecycleStartupStats> {
        let main = self.request_payloads_from_main().await?;
        let tombstones = self.ctx.tombstones();
        // This bulk query resolves all payload/metadata pairs in one pass. Do
        // not call lifecycle_for_request_result once per request here: startup
        // runs before serving traffic and must remain linear in retained data.
        // Keep payloads lacking valid metadata in the migration set too.
        let tombstone_payloads = tombstones.request_payloads().await?;
        let tombstone_payloads_scanned = tombstone_payloads.len();
        let existing_lifecycles = tombstones
            .lifecycle_records_for_payloads_result(tombstone_payloads.clone())
            .await?;
        let mut existing_by_request: HashMap<_, _> = existing_lifecycles
            .into_iter()
            .map(|record| (record.request.id, record))
            .collect();
        let mut stats = RequestLifecycleStartupStats {
            main_payloads_scanned: main.len(),
            tombstone_payloads_scanned,
            ..Default::default()
        };
        let mut requests: HashMap<_, Event> = HashMap::new();
        for request in main.into_iter().chain(tombstone_payloads) {
            requests.entry(request.id).or_insert(request);
        }
        stats.unique_requests_discovered = requests.len();

        for request in requests.into_values() {
            let existing = existing_by_request.remove(&request.id);
            let mut record = match existing {
                Some(record) => {
                    stats.valid_metadata_existing += 1;
                    record
                }
                None => {
                    let classification = self.current_classification(&request);
                    let record = self
                        .ctx
                        .tombstones()
                        .record_request(&request, now, classification)
                        .await?;
                    self.promote_request(&request, &mut stats).await?;
                    stats.requests_migrated += 1;
                    record
                }
            };

            let desired = self.current_classification(&record.request);
            if record.classification != desired {
                record = self
                    .ctx
                    .tombstones()
                    .reclassify_request(&record.request.id, desired)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "lifecycle disappeared during reclassification: {}",
                            record.request.id
                        )
                    })?;
                stats.requests_reclassified += 1;
            }

            let targeting = record.request.kind == Kind::EventDeletion
                || self.vanish_targets_this_relay(&record.request);
            if self.ctx.config.deletion_request_disrespector
                && targeting
                && record.last_used_at.is_none()
                && !self.request_is_expired(&record, now)?
            {
                let would_use = if record.request.kind == Kind::EventDeletion {
                    self.would_delete_stored_target(&record.request).await?
                } else {
                    self.would_nip62_vanish_stored_data(&record.request).await?
                };
                if would_use {
                    record = self
                        .ctx
                        .tombstones()
                        .mark_request_used(&record.request.id, now)
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "lifecycle disappeared while marking used: {}",
                                record.request.id
                            )
                        })?;
                    stats.disrespector_requests_newly_used += 1;
                }
            }

            let serve_indefinitely = self.ctx.config.deletion_request_disrespector
                && targeting
                && record.last_used_at.is_some();
            if serve_indefinitely || self.request_is_served(&record, now)? {
                self.promote_request(&record.request, &mut stats).await?;
            } else {
                self.remove_request_from_main(&record.request, &mut stats)
                    .await?;
            }
        }
        tracing::info!(
            main_payloads_scanned = stats.main_payloads_scanned,
            tombstone_payloads_scanned = stats.tombstone_payloads_scanned,
            unique_requests = stats.unique_requests_discovered,
            migrated = stats.requests_migrated,
            existing_metadata = stats.valid_metadata_existing,
            reclassified = stats.requests_reclassified,
            disrespector_newly_used = stats.disrespector_requests_newly_used,
            promoted = stats.main_requests_promoted,
            removed = stats.main_requests_removed,
            failures = stats.failures,
            "Deletion-request startup lifecycle reconciliation completed"
        );
        Ok(stats)
    }

    async fn request_payloads_from_main(&self) -> Result<Vec<Event>> {
        let mut requests = Vec::new();
        for kind in [Kind::EventDeletion, Kind::RequestToVanish] {
            requests.extend(
                self.ctx
                    .database()
                    .query(Filter::new().kind(kind))
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to list main database deletion-request payloads: {e}"
                        )
                    })?,
            );
        }
        Ok(requests)
    }

    fn current_classification(&self, request: &Event) -> RequestClassification {
        if request.kind == Kind::RequestToVanish && !self.vanish_targets_this_relay(request) {
            RequestClassification::NonTargetingNip62
        } else if self.ctx.config.deletion_request_disrespector {
            RequestClassification::Disrespector
        } else {
            RequestClassification::LocallyActionable
        }
    }

    async fn promote_request(
        &self,
        request: &Event,
        stats: &mut RequestLifecycleStartupStats,
    ) -> Result<()> {
        let exists = self
            .ctx
            .database()
            .event_by_id(&request.id)
            .await?
            .is_some();
        if !exists {
            self.ctx.database().save_event(request).await?;
            stats.main_requests_promoted += 1;
        }
        Ok(())
    }

    async fn remove_request_from_main(
        &self,
        request: &Event,
        stats: &mut RequestLifecycleStartupStats,
    ) -> Result<()> {
        let exists = self
            .ctx
            .database()
            .event_by_id(&request.id)
            .await?
            .is_some();
        if exists {
            self.ctx
                .database()
                .delete(Filter::new().ids(vec![request.id]))
                .await?;
            stats.main_requests_removed += 1;
        }
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use nostr_relay_builder::prelude::{EventBuilder, FinalizeEvent, Keys, Tag};

    use super::super::DeletionContext;
    use super::*;
    use crate::grasp06::receive::new_repo_init_locks;
    use crate::nostr::lifecycle::{
        HoldingStore, ReplaceableHistoryStore, RepositoryLifecycle, Tombstones,
    };
    use crate::purgatory::Purgatory;

    fn service(disrespector: bool) -> DeletionService {
        let db = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let config = crate::config::Config {
            deletion_request_disrespector: disrespector,
            deletion_request_retention_unused_served_secs: 10,
            deletion_request_retention_unused_unserved_gating_additional_secs: 5,
            deletion_request_retention_used_served_after_last_used_secs: 20,
            ..crate::config::Config::for_testing()
        };
        DeletionService::new(DeletionContext::new(
            "test.example.com",
            db,
            Tombstones::in_memory(),
            HoldingStore::in_memory(),
            RepositoryLifecycle::in_memory(),
            ReplaceableHistoryStore::in_memory(),
            PathBuf::new(),
            Arc::new(Purgatory::new(PathBuf::new())),
            config,
            new_repo_init_locks(),
        ))
    }

    fn deletion(keys: &Keys) -> Event {
        EventBuilder::new(Kind::EventDeletion, "")
            .finalize(keys)
            .unwrap()
    }

    #[tokio::test]
    async fn migrates_main_only_request_with_fresh_probation_idempotently() {
        let service = service(false);
        let request = deletion(&Keys::generate());
        service.ctx.database.save_event(&request).await.unwrap();

        let stats = service
            .run_request_lifecycle_startup_reconciliation(Timestamp::from_secs(100))
            .await
            .unwrap();
        assert_eq!(stats.requests_migrated, 1);
        assert_eq!(stats.main_requests_promoted, 0);
        let record = service
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.first_seen_at, Timestamp::from_secs(100));
        assert_eq!(
            record.classification,
            RequestClassification::LocallyActionable
        );

        let rerun = service
            .run_request_lifecycle_startup_reconciliation(Timestamp::from_secs(200))
            .await
            .unwrap();
        assert_eq!(rerun.requests_migrated, 0);
        assert_eq!(
            service
                .ctx
                .tombstones()
                .lifecycle_for_request_result(&request.id)
                .await
                .unwrap()
                .unwrap()
                .first_seen_at,
            Timestamp::from_secs(100)
        );
    }

    #[tokio::test]
    async fn tombstone_only_request_is_migrated_and_promoted() {
        let service = service(false);
        let request = deletion(&Keys::generate());
        service
            .ctx
            .tombstones()
            .save_request_payload_without_metadata(&request)
            .await
            .unwrap();

        let stats = service
            .run_request_lifecycle_startup_reconciliation(Timestamp::from_secs(100))
            .await
            .unwrap();
        assert_eq!(stats.requests_migrated, 1);
        assert_eq!(stats.main_requests_promoted, 1);
        assert!(service
            .ctx
            .database
            .event_by_id(&request.id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn startup_reconciles_thousands_of_retained_lifecycles() {
        // Keep this large enough that a per-request full payload scan is a
        // visible regression (the former implementation inspected millions of
        // events), while remaining small enough for the unit-test suite.
        const REQUEST_COUNT: usize = 2_000;

        let service = service(false);
        let keys = Keys::generate();
        for sequence in 0..REQUEST_COUNT {
            let request = EventBuilder::new(Kind::EventDeletion, sequence.to_string())
                .finalize(&keys)
                .unwrap();
            service
                .ctx
                .tombstones()
                .record_request(
                    &request,
                    Timestamp::from_secs(100),
                    RequestClassification::LocallyActionable,
                )
                .await
                .unwrap();
        }

        let stats = service
            .run_request_lifecycle_startup_reconciliation(Timestamp::from_secs(101))
            .await
            .unwrap();

        assert_eq!(stats.tombstone_payloads_scanned, REQUEST_COUNT);
        assert_eq!(stats.unique_requests_discovered, REQUEST_COUNT);
        assert_eq!(stats.valid_metadata_existing, REQUEST_COUNT);
        assert_eq!(stats.requests_migrated, 0);
    }

    #[tokio::test]
    async fn reclassifies_used_request_without_erasing_timestamps() {
        let service = service(true);
        let request = deletion(&Keys::generate());
        service
            .ctx
            .tombstones()
            .record_request(
                &request,
                Timestamp::from_secs(10),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        service
            .ctx
            .tombstones()
            .mark_request_used(&request.id, Timestamp::from_secs(20))
            .await
            .unwrap();

        service
            .run_request_lifecycle_startup_reconciliation(Timestamp::from_secs(30))
            .await
            .unwrap();
        let record = service
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.first_seen_at, Timestamp::from_secs(10));
        assert_eq!(record.last_used_at, Some(Timestamp::from_secs(20)));
        assert_eq!(record.classification, RequestClassification::Disrespector);
        assert!(service
            .ctx
            .database
            .event_by_id(&request.id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn expired_unused_disrespector_request_is_not_credited_on_startup() {
        let service = service(true);
        let keys = Keys::generate();
        let target = EventBuilder::new(Kind::TextNote, "target")
            .finalize(&keys)
            .unwrap();
        let request = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target.id)])
            .finalize(&keys)
            .unwrap();
        service.ctx.database().save_event(&target).await.unwrap();
        service
            .ctx
            .tombstones()
            .record_request(
                &request,
                Timestamp::from_secs(0),
                RequestClassification::Disrespector,
            )
            .await
            .unwrap();

        let stats = service
            .run_request_lifecycle_startup_reconciliation(Timestamp::from_secs(15))
            .await
            .unwrap();
        assert_eq!(stats.disrespector_requests_newly_used, 0);
        let record = service
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .expect("startup reconciliation does not perform cleanup");
        assert_eq!(record.last_used_at, None);
        assert!(service
            .ctx
            .database()
            .event_by_id(&request.id)
            .await
            .unwrap()
            .is_none());

        service
            .cleanup_expired_requests(Timestamp::from_secs(15))
            .await
            .unwrap();
        assert!(service
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .is_none());
        assert!(service
            .ctx
            .database()
            .event_by_id(&target.id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn mode_round_trip_reclassifies_without_changing_lifecycle_timestamps() {
        let normal = service(false);
        let request = deletion(&Keys::generate());
        normal
            .ctx
            .tombstones()
            .record_request(
                &request,
                Timestamp::from_secs(10),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        normal
            .ctx
            .tombstones()
            .mark_request_used(&request.id, Timestamp::from_secs(20))
            .await
            .unwrap();

        let mut disrespector_context = normal.ctx.clone();
        disrespector_context.config.deletion_request_disrespector = true;
        let disrespector = DeletionService::new(disrespector_context);
        let entering = disrespector
            .run_request_lifecycle_startup_reconciliation(Timestamp::from_secs(30))
            .await
            .unwrap();
        assert_eq!(entering.requests_reclassified, 1);
        let entering_record = disrespector
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entering_record.first_seen_at, Timestamp::from_secs(10));
        assert_eq!(entering_record.last_used_at, Some(Timestamp::from_secs(20)));
        assert_eq!(
            entering_record.classification,
            RequestClassification::Disrespector
        );

        let leaving = normal
            .run_request_lifecycle_startup_reconciliation(Timestamp::from_secs(40))
            .await
            .unwrap();
        assert_eq!(leaving.requests_reclassified, 1);
        let leaving_record = normal
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(leaving_record.first_seen_at, Timestamp::from_secs(10));
        assert_eq!(leaving_record.last_used_at, Some(Timestamp::from_secs(20)));
        assert_eq!(
            leaving_record.classification,
            RequestClassification::LocallyActionable
        );
    }
}
