use std::time::Duration;
use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use ngit_grasp::{
    audit_cleanup, cleanup_empty_repos,
    config::{Config, DatabaseBackend},
    git, grasp06, http,
    metrics::Metrics,
    nostr,
    purgatory::{sync::RealSyncContext, sync::ThrottleManager, Purgatory},
    sync::{naughty_list::NaughtyListTracker, SyncManager},
};

/// Top-level CLI dispatcher.
///
/// With no subcommand the binary runs the relay (all relay flags apply).
/// With a subcommand it runs the requested maintenance tool instead.
#[derive(Debug, Parser)]
#[command(author, version, about = "ngit-grasp GRASP relay", long_about = None)]
#[command(propagate_version = true)]
enum Cli {
    /// Run the GRASP relay server (default when no subcommand is given).
    #[command(name = "serve")]
    Serve(Box<Config>),

    /// Remove kind 30617/30618 events whose bare git repository is empty or missing.
    ///
    /// Runs in dry-run mode by default. Pass --execute to make changes.
    /// Stop the relay service before running with --execute.
    CleanupEmptyRepos(cleanup_empty_repos::CleanupArgs),

    /// Unified maintenance operations for repository/event consistency.
    Maintenance(MaintenanceArgs),

    /// Permanently eject deleted repository data from holding/archive stores.
    ///
    /// This is an operator/admin maintenance command and is idempotent.
    HoldingEject(nostr::lifecycle::HoldingEjectArgs),
}

#[derive(Debug, clap::Args)]
struct MaintenanceArgs {
    #[command(subcommand)]
    command: MaintenanceCommand,
}

#[derive(Debug, Subcommand)]
enum MaintenanceCommand {
    /// Consolidated cleanup pipeline (dry-run by default).
    Cleanup(cleanup_empty_repos::MaintenanceCleanupArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file before clap parses, so env vars are available.
    dotenvy::dotenv().ok();

    // Peek at argv[1] to decide whether a subcommand was explicitly provided.
    // If not, prepend the implicit "serve" subcommand so that clap routes to Cli::Serve
    // and all relay flags are parsed normally (preserving backward compatibility).
    let mut args: Vec<String> = std::env::args().collect();
    let known_subcommands = [
        "serve",
        "cleanup-empty-repos",
        "maintenance",
        "holding-eject",
        "help",
    ];
    let has_subcommand = args.get(1).is_some_and(|a| {
        known_subcommands.contains(&a.as_str())
            || matches!(a.as_str(), "-h" | "--help" | "-V" | "--version")
    });
    if !has_subcommand {
        args.insert(1, "serve".to_string());
    }

    match Cli::parse_from(args) {
        Cli::CleanupEmptyRepos(cleanup_args) => cleanup_empty_repos::run(&cleanup_args).await,
        Cli::Maintenance(args) => match args.command {
            MaintenanceCommand::Cleanup(cleanup_args) => {
                cleanup_empty_repos::run_maintenance_cleanup(&cleanup_args).await
            }
        },
        Cli::HoldingEject(eject_args) => nostr::lifecycle::run_holding_eject(eject_args).await,
        Cli::Serve(config) => {
            let mut config = *config;
            // Finish initialising the Config (load relay owner key if not provided).
            if config.relay_owner_nsec.is_none() {
                config.relay_owner_nsec = Some(Config::load_or_generate_relay_owner_key()?);
            } else {
                config.relay_owner_nsec =
                    config.relay_owner_nsec.take().map(|s| s.trim().to_string());
            }
            run_relay(config).await
        }
    }
}

async fn run_relay(config: Config) -> Result<()> {
    // Initialize tracing with configured log level
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new(&config.log_level))
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting ngit-grasp with log level: {}", config.log_level);

    // Validate configuration and fail fast on fatal errors
    // Recoverable issues (e.g., malformed whitelist entries) are logged as warnings
    config.validate()?;

    info!(
        "Configuration loaded and validated: {}",
        config.bind_address
    );
    info!("Domain: {}", config.domain);
    info!("Relay name: {}", config.relay_name());
    info!("Git data directory: {}", config.effective_git_data_path());
    if config.database_backend != DatabaseBackend::Memory {
        info!("Relay data directory: {}", config.relay_data_path);
    }
    info!("Database backend: {}", config.database_backend);

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
    if let Ok(relay_runtime) =
        nostr::builder::create_relay(&config, purgatory.clone(), repo_init_locks.clone()).await
    {
        info!(
            "Relay created with NIP-34 validation for domain: {}",
            config.domain
        );

        // Set the local relay on the write policy for purgatory notifications
        // This must be done after relay creation since the relay depends on the policy
        relay_runtime
            .write_policy
            .set_local_relay(relay_runtime.relay.clone());

        let deletion_runtime = relay_runtime.deletion_runtime.clone();
        deletion_runtime.run_startup_tasks().await;

        // Wire the GRASP-06 `/prs/` filesystem cleanup context into
        // purgatory so the standard expiry sweep can delete dangling
        // refs/nostr/<event-id> refs (and zero-ref bare repos) when a
        // scoped placeholder expires without a matching PR event. Held
        // under the same per-path lock the receive handler uses so the
        // cleanup can never race with an in-flight push.
        purgatory.set_prs_cleanup_ctx(ngit_grasp::purgatory::PrsCleanupCtx {
            git_data_path: PathBuf::from(config.effective_git_data_path()),
            repo_init_locks: repo_init_locks.clone(),
        });

        // Start SyncManager for proactive sync (Phase 2: multi-relay support, Phase 3: health tracking)
        // Even without bootstrap relay, SyncManager discovers relays from stored announcements
        // Pass the already-registered sync metrics from Metrics to avoid duplicate registration
        let sync_manager = SyncManager::new(
            config.sync_bootstrap_relay_url.clone(),
            config.domain.clone(),
            relay_runtime.stores.database.clone(),
            relay_runtime.write_policy.clone(),
            relay_runtime.relay.clone(),
            &config,
            PathBuf::from(config.effective_git_data_path()),
            metrics.as_ref().and_then(|m| m.sync_metrics().cloned()),
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
        let shutdown_rejected_index = sync_manager.rejected_events_index();
        let http_rejected_index = shutdown_rejected_index.clone();

        tokio::spawn(async move {
            sync_manager.run().await;
        });

        // Spawn background cleanup task for purgatory entries (60s interval)
        let cleanup_purgatory = purgatory.clone();
        tokio::spawn(async move {
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
        });
        info!("Purgatory cleanup task started (60s interval)");

        // Spawn daily cleanup task for old expired event records (prevent unbounded growth)
        let expired_cleanup_purgatory = purgatory.clone();
        tokio::spawn(async move {
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
        });
        info!("Expired event cleanup task started (24h interval, keeps 7 days)");

        // Spawn audit event cleanup task (30m interval, removes events >2h old)
        let audit_db = relay_runtime.stores.database.clone();
        let audit_git_path = PathBuf::from(config.effective_git_data_path());
        tokio::spawn(async move {
            audit_cleanup::run_audit_cleanup_loop(audit_db, audit_git_path).await;
        });
        info!("Audit event cleanup task started (30m interval, removes events >2h old)");

        // Start purgatory sync loop for background git data fetching
        // Create naughty list tracker for git remote domains with persistent errors (12h expiration)
        let git_naughty_list = Arc::new(NaughtyListTracker::with_defaults());

        let sync_ctx = Arc::new(RealSyncContext::new(
            purgatory.clone(),
            relay_runtime.stores.database.clone(),
            PathBuf::from(config.effective_git_data_path()),
            Some(config.domain.clone()),
            Some(relay_runtime.relay.clone()),
            Some(relay_runtime.write_policy.clone()),
            git_naughty_list.clone(),
        ));

        // Create throttle manager for rate limiting remote git servers
        // Default: 5 concurrent requests per domain, 60 requests per minute per domain
        let throttle_manager = Arc::new(ThrottleManager::new(5, 60));
        throttle_manager.set_context(sync_ctx.clone());
        throttle_manager.set_git_naughty_list(git_naughty_list.clone());

        // Start the sync loop
        let _sync_loop_handle =
            purgatory
                .clone()
                .start_sync_loop(sync_ctx, throttle_manager, git_naughty_list.clone());
        info!("Purgatory sync loop started (1s interval)");

        // Setup shutdown handler for purgatory cleanup
        let shutdown_purgatory = purgatory.clone();
        let git_data_path = config.effective_git_data_path();

        // Start HTTP server with integrated relay and database
        info!("Starting HTTP server on {}", config.bind_address);

        let deletion_cleanup = deletion_runtime.spawn_cleanup_task();

        // Wrap write_policy in Arc for sharing between HTTP server connections
        let http_write_policy = Arc::new(relay_runtime.write_policy.clone());
        let http_lifecycle = Arc::new(relay_runtime.lifecycle.clone());

        // Run server until shutdown signal, then cleanup
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate())?;

            tokio::select! {
                result = http::run_server(
                    config,
                    relay_runtime.relay,
                    relay_runtime.stores.database,
                    metrics,
                    purgatory,
                    http_write_policy,
                    http_lifecycle,
                    http_rejected_index,
                    repo_init_locks,
                ) => {
                    result?
                }
                _ = signal::ctrl_c() => {
                    info!("Received SIGINT (Ctrl+C), cleaning up...");
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, cleaning up...");
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                result = http::run_server(
                    config,
                    relay_runtime.relay,
                    relay_runtime.stores.database,
                    metrics,
                    purgatory,
                    http_write_policy,
                    http_lifecycle,
                    http_rejected_index,
                    repo_init_locks,
                ) => {
                    result?
                }
                _ = signal::ctrl_c() => {
                    info!("Received SIGINT (Ctrl+C), cleaning up...");
                }
            }
        }

        deletion_cleanup.shutdown().await;

        // Save purgatory state to disk
        let purgatory_save_path = PathBuf::from(&git_data_path).join("purgatory-state.json");
        if let Err(e) = shutdown_purgatory.save_to_disk(&purgatory_save_path) {
            error!("Failed to save purgatory state: {}", e);
        } else {
            info!("Purgatory state saved to disk");
        }

        // Save rejected events cache to disk
        let rejected_cache_path = PathBuf::from(&git_data_path).join("rejected-events-cache.json");
        if let Err(e) = shutdown_rejected_index.save_to_disk(&rejected_cache_path) {
            error!("Failed to save rejected events cache: {}", e);
        } else {
            info!("Rejected events cache saved to disk");
        }

        // Cleanup placeholder refs on shutdown
        let placeholder_ids = shutdown_purgatory.get_placeholder_event_ids();
        if !placeholder_ids.is_empty() {
            info!(
                "Cleaning up {} placeholder refs/nostr/ refs on shutdown",
                placeholder_ids.len()
            );
            git::cleanup_placeholder_refs(&git_data_path, &placeholder_ids);
        }
    }

    Ok(())
}
