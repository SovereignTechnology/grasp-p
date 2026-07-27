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
            let mut first_pass = true;
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now(), interval_duration);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // The first pass is the startup catch-up. It deliberately
                        // runs here, after the relay and SyncManager are live:
                        // large retained request sets can take minutes to scan,
                        // but must not prevent fresh purgatory work from starting.
                        match service.cleanup_expired_requests(Timestamp::now()).await {
                            Ok(stats) => log_request_cleanup(
                                if first_pass { "startup catch-up" } else { "periodic pass" },
                                stats,
                            ),
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
                        first_pass = false;
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use nostr_memory::MemoryDatabase;
    use nostr_relay_builder::prelude::{
        EventBuilder, EventId, FinalizeEvent, Keys, Kind, NostrDatabase, Tag,
    };

    use super::*;
    use crate::grasp06::receive::new_repo_init_locks;
    use crate::nostr::lifecycle::{
        DeletionContext, HoldingStore, ReplaceableHistoryStore, RepositoryLifecycle,
        RequestClassification, Tombstones,
    };
    use crate::purgatory::Purgatory;

    #[tokio::test]
    async fn retained_request_cleanup_starts_after_blocking_startup_finishes() {
        let database = Arc::new(MemoryDatabase::unbounded());
        let tombstones = Tombstones::in_memory();
        let holding = HoldingStore::in_memory();
        let lifecycle = RepositoryLifecycle::in_memory();
        let config = crate::config::Config {
            deletion_request_retention_unused_served_secs: 1,
            deletion_request_retention_unused_unserved_gating_additional_secs: 1,
            ..crate::config::Config::for_testing()
        };
        let service = DeletionService::new(DeletionContext::new(
            "test.example.com",
            database.clone(),
            tombstones.clone(),
            holding.clone(),
            lifecycle.clone(),
            ReplaceableHistoryStore::in_memory(),
            PathBuf::new(),
            Arc::new(Purgatory::new(PathBuf::new())),
            config,
            new_repo_init_locks(),
        ));
        let runtime = DeletionRuntime::new(
            service,
            holding,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let request = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(EventId::all_zeros())])
            .finalize(&Keys::generate())
            .expect("deletion request should sign");

        tombstones
            .record_request(
                &request,
                Timestamp::from_secs(1),
                RequestClassification::LocallyActionable,
            )
            .await
            .expect("request lifecycle should be retained");
        database
            .save_event(&request)
            .await
            .expect("request payload should be served");

        runtime
            .run_startup_tasks()
            .await
            .expect("blocking startup reconciliation should complete");
        assert!(
            tombstones
                .lifecycle_for_request_result(&request.id)
                .await
                .expect("lifecycle lookup should succeed")
                .is_some(),
            "retention cleanup must not delay relay and SyncManager startup"
        );

        let cleanup = runtime.spawn_cleanup_task();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if tombstones
                    .lifecycle_for_request_result(&request.id)
                    .await
                    .expect("lifecycle lookup should succeed")
                    .is_none()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("background startup catch-up should run immediately");
        cleanup.shutdown().await;
    }
}
