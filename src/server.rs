//! In-process relay server lifecycle.
//!
//! [`RelayServer`] owns the full ngit-grasp runtime: it binds the TCP
//! listener (natively supporting `:0` for kernel-assigned ports), wires up
//! the nostr relay, purgatory, sync system, and background maintenance
//! tasks, then serves until a caller-supplied shutdown future resolves and
//! finally persists state to disk.
//!
//! The `ngit-grasp serve` binary (`src/main.rs`) drives this module,
//! supplying OS signal futures (SIGINT/SIGTERM) as the shutdown trigger;
//! `main.rs` itself only owns binary concerns (CLI/env config, tracing
//! subscriber, owner-key file, signal wiring).

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use nostr_sdk::local_relay::LocalRelay;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::{
    audit_cleanup,
    config::{Config, DatabaseBackend},
    git, grasp06, http,
    metrics::Metrics,
    nostr::{
        self, builder::Nip34WritePolicy, lifecycle::RepositoryLifecycle, relay_identity,
        SharedDatabase,
    },
    outbound::OutboundTargetPolicy,
    private::PrivateAccess,
    purgatory::{sync::RealSyncContext, sync::ThrottleManager, Purgatory},
    sync::{naughty_list::NaughtyListTracker, rejected_index::RejectedEventsIndex, SyncManager},
};

/// Limits recovery work lost to an abrupt process or machine stop without
/// turning every in-memory mutation into synchronous disk I/O.
const SYNC_STATE_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(60);

/// A fully-wired relay that has bound its listener but not yet started
/// accepting connections.
///
/// Construct with [`RelayServer::start`], inspect the actual bound address
/// with [`RelayServer::local_addr`], then drive it with
/// [`RelayServer::run_until`].
pub struct RelayServer {
    config: Config,
    listener: TcpListener,
    local_addr: SocketAddr,
    relay: LocalRelay,
    database: SharedDatabase,
    metrics: Option<Arc<Metrics>>,
    purgatory: Arc<Purgatory>,
    write_policy: Arc<Nip34WritePolicy>,
    lifecycle: Arc<RepositoryLifecycle>,
    rejected_events_index: Arc<RejectedEventsIndex>,
    repo_init_locks: crate::grasp06::receive::RepoInitLocks,
    private_access: Option<PrivateAccess>,
    deletion_cleanup: nostr::lifecycle::DeletionCleanupTask,
    /// Detached background loops (sync manager, purgatory cleanup, audit
    /// cleanup, purgatory sync loop). Aborted on shutdown so the host
    /// process does not leak tasks per relay instance.
    background_tasks: Vec<JoinHandle<()>>,
    git_data_path: String,
}

impl RelayServer {
    /// Validate the config, bind the listener, and wire up the full relay
    /// runtime. Does not accept connections yet — call
    /// [`RelayServer::run_until`] for that.
    ///
    /// `config.bind_address` may use port `0` for a kernel-assigned port;
    /// the resolved address is available via [`RelayServer::local_addr`]
    /// and is written back into `config.bind_address`. If `config.domain`
    /// is empty it is set to the resolved `host:port`.
    ///
    /// Expects `config.relay_owner_nsec` to be set (see [`Config::load`])
    /// and does **not** install a tracing subscriber — that is the
    /// caller's concern.
    pub async fn start(mut config: Config) -> Result<Self> {
        // Bind first so kernel-assigned ports are resolved before any
        // component captures the domain / bind address.
        let requested: SocketAddr = config
            .bind_address
            .parse()
            .with_context(|| format!("invalid bind address '{}'", config.bind_address))?;
        let listener = TcpListener::bind(&requested)
            .await
            .with_context(|| format!("failed to bind {}", requested))?;
        let local_addr = listener.local_addr()?;
        config.bind_address = local_addr.to_string();
        if config.domain.is_empty() {
            config.domain = local_addr.to_string();
        }

        // Validate configuration and fail fast on fatal errors.
        // Recoverable issues (e.g., malformed whitelist entries) are logged
        // as warnings.
        config.validate()?;
        let private_access = if config.private_mode {
            let access = PrivateAccess::new(config.parse_private_members()?);
            info!(
                "GRASP-08 private mode enabled for {} configured member(s)",
                access.len()
            );
            Some(access)
        } else {
            None
        };

        info!(
            "Configuration loaded and validated: {}",
            config.bind_address
        );
        info!("Public service: {}", config.service_address());
        info!("Relay name: {}", config.relay_name());
        info!("Git data directory: {}", config.effective_git_data_path());
        if config.database_backend != DatabaseBackend::Memory {
            info!("Relay data directory: {}", config.relay_data_path);
        }
        info!("Database backend: {}", config.database_backend);

        // Upgrade Git storage before any runtime component can inspect or
        // mutate repositories. Migration is resumable; each identifier
        // family's legacy backups are verified and retired before the next
        // family converts, so peak disk overhead is bounded by the family
        // currently in flight. Backups that cannot be verified are retained
        // as operator-managed rollback material.
        let git_storage = git::storage::LocalGitStorage::new(config.effective_git_data_path());
        let migration = git::migration::migrate_on_startup(&git_storage)
            .await
            .context("upgrade Git repositories to identifier-family storage")?;
        if !migration.already_current
            || migration.retired_backups > 0
            || migration.retained_backups > 0
        {
            info!(
                migrated_views = migration.migrated_views,
                recovered_views = migration.recovered_views,
                families_built = migration.families_built,
                retired_backups = migration.retired_backups,
                retained_backups = migration.retained_backups,
                "Git identifier-family storage migration completed"
            );
        }
        info!("Git object backend: local identifier families");

        // Initialize metrics if enabled
        let metrics = if config.metrics_enabled {
            info!("Metrics enabled on /metrics endpoint");
            let m = Arc::new(Metrics::new(
                config.metrics_connection_per_ip_abuse_threshold,
                Some(config.effective_git_data_path()),
            ));
            info!("Repository count will be updated on each metrics request");
            Some(m)
        } else {
            info!("Metrics disabled");
            None
        };

        // Create purgatory for event/git coordination
        let purgatory = Arc::new(Purgatory::new(PathBuf::from(
            config.effective_git_data_path(),
        )));
        info!("Purgatory initialized for event coordination");

        // Restore purgatory state from disk if available
        let purgatory_path =
            PathBuf::from(config.effective_git_data_path()).join("purgatory-state.json");

        if purgatory_path.exists() {
            match purgatory.restore_from_disk(&purgatory_path) {
                Ok(()) => {
                    info!("Restored purgatory state from disk");
                    // Re-queueing will happen later after sync system is created
                }
                Err(e) => {
                    warn!("Failed to restore purgatory state: {}, starting empty", e);
                }
            }
        }

        // Shared per-path state for the GRASP-06 `/prs/` endpoint (mutex +
        // in-flight counter, see [`grasp06::receive::PrsPathState`]). Lives
        // for the lifetime of the process so concurrent pushes to the same
        // `/prs/<submitter>/<id>.git` path — and policy / purgatory code
        // paths that may delete a `/prs/` bare repo — coordinate through
        // the same DashMap.
        let repo_init_locks = grasp06::receive::new_repo_init_locks();

        // Startup recovery for the GRASP-06 `/prs/` subtree: remove any
        // zero-ref bare repos and empty submitter dirs left behind by a
        // previous run (crashes mid-push, mid-cleanup, or shutdowns with
        // unresolved scoped placeholders). Inline cleanup paths only fire
        // while the process is running, so without this scan abandoned
        // dirs persist indefinitely — the `cleanup-empty-repos` CLI tool
        // explicitly skips `/prs/`. Gated on `grasp06_enable` so an
        // operator who has turned the feature off does not start removing
        // their existing `/prs/` data on the next restart. Runs before
        // anything that could write to `/prs/` so no locking is needed.
        if config.grasp06_enable {
            let git_data_path = PathBuf::from(config.effective_git_data_path());
            let (repos, dirs) = grasp06::cleanup::scan_on_startup(&git_data_path);
            if repos > 0 || dirs > 0 {
                info!(
                    "GRASP-06 /prs/ startup recovery: removed {} zero-ref repo(s), {} empty submitter dir(s)",
                    repos, dirs
                );
            }
        }

        // Create Nostr relay runtime with NIP-34 validation and shared stores.
        let relay_runtime = nostr::builder::create_relay(
            &config,
            purgatory.clone(),
            repo_init_locks.clone(),
            private_access.clone(),
        )
        .await
        .context("failed to create relay runtime")?;

        info!(
            "Relay created with NIP-34 validation for domain: {}",
            config.service_address()
        );

        // Set the local relay on the write policy for purgatory notifications
        // This must be done after relay creation since the relay depends on the policy
        relay_runtime
            .write_policy
            .set_local_relay(relay_runtime.relay.clone());

        let deletion_runtime = relay_runtime.deletion_runtime.clone();
        deletion_runtime
            .run_startup_tasks()
            .await
            .context("failed deletion lifecycle startup reconciliation")?;

        // Make the operator identity discoverable on this relay without
        // overwriting identity events the owner already published — locally
        // or on the configured user-index relays. Runs after deletion startup
        // reconciliation so seeding sees settled tombstones. Kinds with no
        // local copy are handed to the background publication task below,
        // which seeds them only once a user-index relay is reachable and
        // confirms no existing identity. Stored kinds pass the same gate:
        // nothing is published before at least one user-index relay has been
        // checked for the kind, and an identity found there is adopted
        // locally instead of overwritten, so transient network failure never
        // blocks relay startup and a wiped database cannot displace a
        // customized profile surviving on the indexes. In private mode the
        // identity stays local and is never published.
        let generated_identity = relay_identity::build(&config)
            .context("failed to build relay-owner identity events")?;
        let relay_identity_plan = relay_identity::prepare(
            &relay_runtime.relay,
            &relay_runtime.stores.database,
            &relay_runtime.deletion,
            &config,
            &generated_identity,
        )
        .await
        .context("failed to prepare relay-owner identity publication")?;

        // Wire the GRASP-06 `/prs/` filesystem cleanup context into
        // purgatory so the standard expiry sweep can delete dangling
        // refs/nostr/<event-id> refs (and zero-ref bare repos) when a
        // scoped placeholder expires without a matching PR event. Held
        // under the same per-path lock the receive handler uses so the
        // cleanup can never race with an in-flight push.
        purgatory.set_prs_cleanup_ctx(crate::purgatory::PrsCleanupCtx {
            git_data_path: PathBuf::from(config.effective_git_data_path()),
            repo_init_locks: repo_init_locks.clone(),
        });

        // Start SyncManager for proactive sync (Phase 2: multi-relay support, Phase 3: health tracking)
        // Even without bootstrap relay, SyncManager discovers relays from stored announcements
        // Pass the already-registered sync metrics from Metrics to avoid duplicate registration
        // GRASP-08 peer registry and credential signer exist only on private
        // instances: a public mirror never authenticates its Git fetches.
        let grasp08_peers = config
            .private_mode
            .then(crate::private::Grasp08Peers::default);
        let outbound_credential_keys = if config.private_mode {
            match config.relay_owner_keys() {
                Ok(keys) => Some(keys),
                Err(error) => {
                    warn!(
                        %error,
                        "Relay owner key unavailable; outbound GRASP-08 credentials disabled"
                    );
                    None
                }
            }
        } else {
            None
        };

        let sync_manager = SyncManager::new(
            config.sync_bootstrap_relay_url.clone(),
            config.service_address(),
            relay_runtime.stores.database.clone(),
            relay_runtime.write_policy.clone(),
            relay_runtime.relay.clone(),
            &config,
            PathBuf::from(config.effective_git_data_path()),
            metrics.as_ref().and_then(|m| m.sync_metrics().cloned()),
            private_access.clone(),
            grasp08_peers.clone(),
        );

        if config.sync_bootstrap_relay_url.is_some() {
            info!(
                "Starting proactive sync with bootstrap relay: {:?}",
                config.sync_bootstrap_relay_url
            );
        } else {
            info!("Proactive sync enabled (will discover relays from stored announcements)");
        }

        // Re-queue all restored purgatory repos for sync
        let restored_identifiers = purgatory.get_all_identifiers();
        if !restored_identifiers.is_empty() {
            info!(
                "Re-queueing {} restored repositories for sync",
                restored_identifiers.len()
            );
            for identifier in restored_identifiers {
                purgatory.enqueue_sync_immediate(&identifier);
            }
        }

        // Get a reference to the rejected events index for shutdown persistence
        // and for the HTTP server's git push path (hot-cache re-processing)
        let rejected_events_index = sync_manager.rejected_events_index();
        relay_runtime
            .write_policy
            .set_rejected_events_index(rejected_events_index.clone());

        let mut background_tasks = Vec::new();

        if let Some(task) = relay_identity::spawn_user_index_publication(
            &config,
            relay_identity_plan,
            relay_runtime.relay.clone(),
            relay_runtime.deletion.clone(),
        ) {
            background_tasks.push(task);
        }

        background_tasks.push(tokio::spawn(async move {
            sync_manager.run().await;
        }));

        // Retain a recent durable copy after startup. Restore deliberately
        // leaves the prior checkpoint in place, and these atomic replacements
        // bound any later crash loss to one interval.
        let checkpoint_purgatory = purgatory.clone();
        let checkpoint_rejected = rejected_events_index.clone();
        let checkpoint_root = PathBuf::from(config.effective_git_data_path());
        background_tasks.push(tokio::spawn(async move {
            let first = tokio::time::Instant::now() + SYNC_STATE_CHECKPOINT_INTERVAL;
            let mut interval = tokio::time::interval_at(first, SYNC_STATE_CHECKPOINT_INTERVAL);
            loop {
                interval.tick().await;
                let purgatory_path = checkpoint_root.join("purgatory-state.json");
                if let Err(error) = checkpoint_purgatory.save_to_disk(&purgatory_path) {
                    warn!(%error, "Failed to checkpoint purgatory state");
                }
                let rejected_path = checkpoint_root.join("rejected-events-cache.json");
                if let Err(error) = checkpoint_rejected.save_to_disk(&rejected_path) {
                    warn!(%error, "Failed to checkpoint rejected-events cache");
                }
            }
        }));
        info!(
            interval_secs = SYNC_STATE_CHECKPOINT_INTERVAL.as_secs(),
            "Crash-safe sync-state checkpoint task started"
        );

        // Spawn background cleanup task for purgatory entries (60s interval)
        let cleanup_purgatory = purgatory.clone();
        background_tasks.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let (announcement_removed, state_removed, pr_removed) = cleanup_purgatory.cleanup();
                if announcement_removed > 0 || state_removed > 0 || pr_removed > 0 {
                    info!(
                        "Purgatory cleanup: removed {} announcements, {} state events, {} PR events",
                        announcement_removed, state_removed, pr_removed
                    );
                }
            }
        }));
        info!("Purgatory cleanup task started (60s interval)");

        // Spawn daily cleanup task for old expired event records (prevent unbounded growth)
        let expired_cleanup_purgatory = purgatory.clone();
        background_tasks.push(tokio::spawn(async move {
            // Run immediately on startup, then every 24 hours
            let mut interval = tokio::time::interval(Duration::from_secs(24 * 3600));
            loop {
                interval.tick().await;
                // Remove expired event records older than 7 days
                let removed = expired_cleanup_purgatory
                    .cleanup_expired_events(Duration::from_secs(7 * 24 * 3600));
                if removed > 0 {
                    info!(
                        "Expired event cleanup: removed {} old expired event records (>7 days)",
                        removed
                    );
                }
            }
        }));
        info!("Expired event cleanup task started (24h interval, keeps 7 days)");

        // Spawn audit event cleanup task (30m interval, removes events >2h old)
        let audit_db = relay_runtime.stores.database.clone();
        let audit_git_path = PathBuf::from(config.effective_git_data_path());
        background_tasks.push(tokio::spawn(async move {
            audit_cleanup::run_audit_cleanup_loop(audit_db, audit_git_path).await;
        }));
        info!("Audit event cleanup task started (30m interval, removes events >2h old)");

        // Start purgatory sync loop for background git data fetching
        // Create naughty list tracker for git remote domains with persistent errors (12h expiration)
        let git_naughty_list = Arc::new(NaughtyListTracker::with_defaults());

        let sync_ctx = Arc::new(RealSyncContext::new(
            purgatory.clone(),
            relay_runtime.stores.database.clone(),
            PathBuf::from(config.effective_git_data_path()),
            Some(config.service_address()),
            Some(relay_runtime.relay.clone()),
            Some(relay_runtime.write_policy.clone()),
            git_naughty_list.clone(),
            OutboundTargetPolicy {
                allow_non_global: config.sync_allow_non_global_targets,
            },
            grasp08_peers,
            outbound_credential_keys,
        ));

        // Check the permanent identifier-family model after migration and
        // database initialization. The pass is intentionally non-blocking:
        // remote repair must not make availability depend on listed clone
        // servers. It also owns filesystem-queued operator requests so all
        // repair work remains inside the process holding family write leases.
        background_tasks.push(git::integrity::spawn_integrity_worker(
            git_storage,
            sync_ctx.clone(),
            config.startup_integrity_identifiers.clone(),
        ));
        info!("Git storage and authorization-integrity worker started");

        // Create throttle manager for rate limiting remote git servers
        // Default: 5 concurrent requests per domain, 60 requests per minute per domain
        let throttle_manager = Arc::new(ThrottleManager::new(5, 60));
        throttle_manager.set_context(sync_ctx.clone());
        throttle_manager.set_git_naughty_list(git_naughty_list.clone());

        // Start the sync loop
        background_tasks.push(purgatory.clone().start_sync_loop(
            sync_ctx,
            throttle_manager,
            git_naughty_list.clone(),
        ));
        info!("Purgatory sync loop started (1s interval)");

        let deletion_cleanup = deletion_runtime.spawn_cleanup_task();

        let git_data_path = config.effective_git_data_path();

        Ok(Self {
            relay: relay_runtime.relay,
            database: relay_runtime.stores.database,
            write_policy: Arc::new(relay_runtime.write_policy),
            lifecycle: Arc::new(relay_runtime.lifecycle),
            config,
            listener,
            local_addr,
            metrics,
            purgatory,
            rejected_events_index,
            repo_init_locks,
            private_access,
            deletion_cleanup,
            background_tasks,
            git_data_path,
        })
    }

    /// The actual bound socket address (with the kernel-assigned port when
    /// the configured bind address used port `0`).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The effective configuration (bind address and domain reflect the
    /// resolved listener address).
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Serve HTTP + relay traffic until `shutdown` resolves (or the server
    /// itself fails), then persist state and tear down background tasks.
    ///
    /// The shutdown sequence mirrors the binary's signal handling: stop the
    /// holding-cleanup task gracefully, stop background mutation, save
    /// purgatory state and the rejected-events cache to disk, and remove
    /// placeholder `refs/nostr/` refs.
    pub async fn run_until(self, shutdown: impl Future<Output = ()>) -> Result<()> {
        info!("Starting HTTP server on {}", self.config.bind_address);

        let serve = http::run_server_on_listener(
            self.listener,
            self.config,
            self.relay,
            self.database,
            self.metrics,
            self.purgatory.clone(),
            self.write_policy,
            self.lifecycle,
            self.rejected_events_index.clone(),
            self.repo_init_locks,
            self.private_access,
        );

        let result = tokio::select! {
            result = serve => result,
            _ = shutdown => {
                info!("Shutdown signal received, cleaning up...");
                Ok(())
            }
        };

        // Stop and join all state-mutating background loops before taking the
        // final snapshot. This also prevents an older periodic checkpoint from
        // racing and replacing the shutdown snapshot after it is written.
        for task in self.background_tasks {
            task.abort();
            let _ = task.await;
        }

        self.deletion_cleanup.shutdown().await;

        // Save purgatory state to disk
        let purgatory_save_path = PathBuf::from(&self.git_data_path).join("purgatory-state.json");
        if let Err(e) = self.purgatory.save_to_disk(&purgatory_save_path) {
            error!("Failed to save purgatory state: {}", e);
        } else {
            info!("Purgatory state saved to disk");
        }

        // Save rejected events cache to disk
        let rejected_cache_path =
            PathBuf::from(&self.git_data_path).join("rejected-events-cache.json");
        if let Err(e) = self
            .rejected_events_index
            .save_to_disk(&rejected_cache_path)
        {
            error!("Failed to save rejected events cache: {}", e);
        } else {
            info!("Rejected events cache saved to disk");
        }

        // Cleanup placeholder refs on shutdown
        let placeholder_ids = self.purgatory.get_placeholder_event_ids();
        if !placeholder_ids.is_empty() {
            info!(
                "Cleaning up {} placeholder refs/nostr/ refs on shutdown",
                placeholder_ids.len()
            );
            git::cleanup_placeholder_refs(&self.git_data_path, &placeholder_ids);
        }

        result
    }
}
