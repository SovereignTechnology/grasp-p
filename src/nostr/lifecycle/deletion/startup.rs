use nostr::nips::nip19::ToBech32;
use nostr_relay_builder::prelude::{Filter, Kind, PublicKey, Timestamp};

use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::lifecycle::DeletionSource;

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
    pub blacklist_parity: BlacklistParityStats,
    pub blacklist_restore: BlacklistRestoreStats,
    pub whitelist_parity: WhitelistParityStats,
    pub whitelist_restore: WhitelistRestoreStats,
}

// ---------------------------------------------------------------------------
// DeletionService startup pass implementations
// ---------------------------------------------------------------------------

impl DeletionService {
    /// Run all startup reconciliation passes in the required order.
    ///
    /// Ordering is intentionally owned here so relay startup only depends on a
    /// single facade while deletion internals decide sequencing:
    /// 1) blacklist parity delete
    /// 2) blacklist auto-restore
    /// 3) whitelist parity delete
    /// 4) whitelist restore
    pub async fn run_startup_reconciliation(&self) -> StartupReconciliationStats {
        let blacklist_parity = self.run_startup_blacklist_parity_pass().await;
        let blacklist_restore = self.run_startup_blacklist_restore_pass().await;
        let whitelist_parity = self.run_startup_whitelist_parity_pass().await;
        let whitelist_restore = self.run_startup_whitelist_restore_pass().await;

        StartupReconciliationStats {
            blacklist_parity,
            blacklist_restore,
            whitelist_parity,
            whitelist_restore,
        }
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
