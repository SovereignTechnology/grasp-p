use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use clap::Args;
use nostr_relay_builder::prelude::{PublicKey, Timestamp};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::nostr::lifecycle::HoldingStore;
use crate::nostr::lifecycle::RepositoryLifecycle;

use super::startup::{
    BlacklistParityStats, BlacklistRestoreStats, StartupReconciliationStats, WhitelistParityStats,
    WhitelistRestoreStats,
};
use super::{DeletionService, RequestCleanupStats};

#[derive(Debug, Args)]
pub struct HoldingEjectArgs {
    /// Owner pubkey (npub or hex) for the repository scope to eject.
    #[arg(long)]
    pub owner: String,

    /// Repository identifier (`d` tag value).
    #[arg(long)]
    pub identifier: String,

    /// Relay data path containing the holding LMDB directory.
    #[arg(long, env = "NGIT_RELAY_DATA_PATH", default_value = "./data/relay")]
    pub relay_data_path: String,

    /// Git data path containing the `.archive` subtree.
    #[arg(long, env = "NGIT_GIT_DATA_PATH", default_value = "./data/git")]
    pub git_data_path: String,
}

#[derive(Clone)]
pub struct DeletionRuntime {
    service: DeletionService,
    holding: HoldingStore,
    lifecycle: RepositoryLifecycle,
    holding_retention: Duration,
    holding_cleanup_interval: Duration,
}

impl DeletionRuntime {
    pub fn new(
        service: DeletionService,
        holding: HoldingStore,
        holding_retention: Duration,
        holding_cleanup_interval: Duration,
    ) -> Self {
        Self {
            lifecycle: service.lifecycle().clone(),
            service,
            holding,
            holding_retention,
            holding_cleanup_interval,
        }
    }

    /// Run deletion-owned startup tasks before the relay begins serving traffic.
    pub async fn run_startup_tasks(&self) -> Result<()> {
        log_startup_reconciliation(self.service.run_startup_reconciliation().await?);
        // Enumeration failure is fatal before serving traffic; individual record
        // failures are conservatively retained and retried by the timer.
        let request_stats = self
            .service
            .cleanup_expired_requests(Timestamp::now())
            .await?;
        log_request_cleanup("startup catch-up", request_stats);
        self.run_holding_startup_cleanup().await;
        Ok(())
    }

    /// Spawn deletion-owned background maintenance tasks.
    pub fn spawn_cleanup_task(&self) -> DeletionCleanupTask {
        let holding = self.holding.clone();
        let lifecycle = self.lifecycle.clone();
        let service = self.service.clone();
        let retention = self.holding_retention;
        let interval_duration = self.holding_cleanup_interval;
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + interval_duration,
                interval_duration,
            );

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match service.cleanup_expired_requests(Timestamp::now()).await {
                            Ok(stats) => log_request_cleanup("periodic pass", stats),
                            Err(error) => tracing::warn!(error = %error, "Deletion-request cleanup periodic pass failed"),
                        }
                        match holding.cleanup_expired_with_lifecycle(&lifecycle, Timestamp::now(), retention).await {
                            Ok(stats) => {
                                if stats.expired_records > 0 {
                                    tracing::info!(
                                        examined = stats.metadata_examined,
                                        expired = stats.expired_records,
                                        metadata_deleted = stats.metadata_deleted,
                                        archived_events_deleted = stats.archived_events_deleted,
                                        "Holding cleanup periodic pass completed"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "Holding cleanup periodic pass failed");
                            }
                        }
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            tracing::info!("Deletion lifecycle maintenance task received shutdown signal");
                            break;
                        }
                    }
                }
            }
        });

        tracing::info!(
            retention_secs = retention.as_secs(),
            interval_secs = interval_duration.as_secs(),
            "Deletion lifecycle maintenance task started"
        );

        DeletionCleanupTask {
            shutdown_tx,
            handle,
        }
    }

    async fn run_holding_startup_cleanup(&self) {
        match self
            .holding
            .cleanup_expired_with_lifecycle(
                &self.lifecycle,
                Timestamp::now(),
                self.holding_retention,
            )
            .await
        {
            Ok(stats) => {
                if stats.expired_records > 0 {
                    tracing::info!(
                        examined = stats.metadata_examined,
                        expired = stats.expired_records,
                        metadata_deleted = stats.metadata_deleted,
                        archived_events_deleted = stats.archived_events_deleted,
                        "Holding cleanup startup catch-up completed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Holding cleanup startup catch-up failed");
            }
        }
    }
}

pub struct DeletionCleanupTask {
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

impl DeletionCleanupTask {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        if let Err(e) = self.handle.await {
            tracing::warn!(error = %e, "Deletion lifecycle maintenance task join failed during shutdown");
        }
    }
}

pub async fn run_holding_eject(args: HoldingEjectArgs) -> Result<()> {
    let owner_hex = PublicKey::parse(&args.owner)
        .map(|pk| pk.to_hex())
        .map_err(|e| anyhow::anyhow!("invalid --owner pubkey '{}': {}", args.owner, e))?;

    let holding = HoldingStore::open_lmdb(
        Path::new(&args.relay_data_path),
        Path::new(&args.git_data_path),
    )
    .await?;
    let lifecycle = RepositoryLifecycle::for_git_data_path(Path::new(&args.git_data_path));

    let stats = holding
        .manual_eject_repository_with_lifecycle(&lifecycle, &owner_hex, &args.identifier)
        .await?;

    println!(
        "Holding ejection complete: owner={} identifier={} metadata_deleted={} payload_deleted={} archive_files_deleted={}",
        owner_hex,
        args.identifier,
        stats.metadata_deleted,
        stats.archived_events_deleted,
        stats.archive_files_deleted
    );

    Ok(())
}

fn log_startup_reconciliation(stats: StartupReconciliationStats) {
    log_blacklist_parity(stats.blacklist_parity);
    log_blacklist_restore(stats.blacklist_restore);
    log_whitelist_parity(stats.whitelist_parity);
    log_whitelist_restore(stats.whitelist_restore);
}

fn log_request_cleanup(phase: &str, stats: RequestCleanupStats) {
    crate::metrics::record_deletion_request_cleanup_run(
        stats.main_payloads_removed,
        stats.tombstone_payloads_removed,
        stats.metadata_rows_removed,
        stats.failures,
        stats.stale_or_concurrent_records_skipped,
    );
    tracing::info!(
        phase,
        examined = stats.canonical_records_examined,
        main_removed = stats.main_payloads_removed,
        tombstone_removed = stats.tombstone_payloads_removed,
        metadata_removed = stats.metadata_rows_removed,
        indefinitely_retained = stats.indefinitely_retained_disrespector_requests,
        skipped = stats.stale_or_concurrent_records_skipped,
        failures = stats.failures,
        "Deletion-request cleanup completed"
    );
}

fn log_blacklist_parity(stats: BlacklistParityStats) {
    if stats.scanned_announcements > 0 || stats.matched_announcements > 0 {
        tracing::info!(
            scanned = stats.scanned_announcements,
            matched = stats.matched_announcements,
            attempted = stats.attempted_deletions,
            succeeded = stats.successful_deletions,
            failed = stats.failed_deletions,
            "Startup blacklist parity pass completed"
        );
    }
}

fn log_blacklist_restore(stats: BlacklistRestoreStats) {
    if stats.scanned_scopes > 0 || stats.attempted_restores > 0 {
        tracing::info!(
            scanned_scopes = stats.scanned_scopes,
            attempted = stats.attempted_restores,
            succeeded = stats.successful_restores,
            failed = stats.failed_restores,
            skipped = stats.skipped_scopes,
            "Startup blacklist restore pass completed"
        );
    }
}

fn log_whitelist_parity(stats: WhitelistParityStats) {
    if stats.scanned_announcements > 0 || stats.mismatched_announcements > 0 {
        tracing::info!(
            scanned = stats.scanned_announcements,
            mismatched = stats.mismatched_announcements,
            attempted = stats.attempted_deletions,
            succeeded = stats.successful_deletions,
            failed = stats.failed_deletions,
            "Startup whitelist parity pass completed"
        );
    }
}

fn log_whitelist_restore(stats: WhitelistRestoreStats) {
    if stats.scanned_scopes > 0 || stats.attempted_restores > 0 {
        tracing::info!(
            scanned_scopes = stats.scanned_scopes,
            attempted = stats.attempted_restores,
            succeeded = stats.successful_restores,
            failed = stats.failed_restores,
            skipped = stats.skipped_scopes,
            "Startup whitelist restore pass completed"
        );
    }
}
