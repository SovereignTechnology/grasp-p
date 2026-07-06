use anyhow::Result;
use clap::Parser;
use tokio::signal;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use ngit_grasp::{
    cleanup_empty_repos, config::Config, nostr, repair_deletion_requests, server::RelayServer,
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

    /// Permanently eject deleted repository data from holding/archive stores.
    ///
    /// This is an operator/admin maintenance command and is idempotent.
    HoldingEject(nostr::lifecycle::HoldingEjectArgs),

    /// Temporarily repair historical redundant kind-5 deletion request rows.
    #[command(hide = true)]
    RepairDeletionRequests(repair_deletion_requests::RepairDeletionRequestsArgs),
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
        "holding-eject",
        "repair-deletion-requests",
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
        Cli::HoldingEject(eject_args) => nostr::lifecycle::run_holding_eject(eject_args).await,
        Cli::RepairDeletionRequests(repair_args) => {
            repair_deletion_requests::run(&repair_args).await
        }
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

/// Run the relay until an OS shutdown signal arrives.
///
/// All relay wiring lives in [`ngit_grasp::server::RelayServer`];
/// this function only owns concerns specific to the standalone binary:
/// the global tracing subscriber and signal handling.
async fn run_relay(config: Config) -> Result<()> {
    // Initialize tracing with configured log level
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new(&config.log_level))
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting ngit-grasp with log level: {}", config.log_level);

    let server = RelayServer::start(config).await?;

    server.run_until(shutdown_signal()).await
}

/// Resolves when the process receives SIGINT (Ctrl+C) or, on unix, SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal as unix_signal, SignalKind};
        let mut sigterm = match unix_signal(SignalKind::terminate()) {
            Ok(sigterm) => sigterm,
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
                // Fall back to Ctrl+C only.
                let _ = signal::ctrl_c().await;
                info!("Received SIGINT (Ctrl+C), cleaning up...");
                return;
            }
        };

        tokio::select! {
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
        let _ = signal::ctrl_c().await;
        info!("Received SIGINT (Ctrl+C), cleaning up...");
    }
}
