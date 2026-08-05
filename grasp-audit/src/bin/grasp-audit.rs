//! GRASP Audit CLI Tool

use clap::{Args, CommandFactory, Parser, Subcommand};
use grasp_audit::*;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "grasp-audit")]
#[command(about = "GRASP audit and compliance testing tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Args)]
struct KeyArgs {
    /// Secret key in nsec or hex format. Convenient for disposable keys, but
    /// visible in the process argument list; prefer --nsec-file or GRASP_AUDIT_NSEC.
    #[arg(long, conflicts_with = "nsec_file")]
    nsec: Option<String>,

    /// Read a secret key in nsec or hex format from this file.
    #[arg(long, value_name = "PATH", conflicts_with = "nsec")]
    nsec_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a probe/smoke test against a server
    Probe {
        /// Relay URL (e.g., wss://relay.ngit.dev)
        #[arg(short, long)]
        relay: Option<String>,

        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,

        /// Per-step timeout in seconds
        #[arg(long, default_value_t = 30)]
        timeout: u64,

        /// Re-run every N seconds (watch mode)
        #[arg(long)]
        watch: Option<u64>,

        #[command(flatten)]
        keys: KeyArgs,

        /// Create a test repo on the relay to verify the full write path
        /// (publish events, git push, verify refs match state).
        /// Requires write access; use --nsec for whitelisted relays.
        #[arg(long, default_value_t = false)]
        create_repo: bool,
    },

    /// Run audit tests against a server
    Audit {
        /// Relay URL (e.g., ws://localhost:7000)
        #[arg(short, long)]
        relay: String,

        /// Fixture mode: shared (default) or isolated
        ///
        /// - shared: Fixtures are cached and reused across tests (efficient for sequential test runs)
        /// - isolated: Each test creates fresh fixtures (for parallel tests like cargo test)
        #[arg(short, long, default_value = "shared")]
        mode: String,

        /// Spec to test (nip01-smoke, nip11, event-acceptance, cors, git-clone, git-filter, push-auth, repo-creation, purgatory, grasp06, all)
        #[arg(short, long, default_value = "all")]
        spec: String,

        /// Git data directory (required for cors, git-clone, push-auth, repo-creation specs)
        #[arg(short, long)]
        git_data_dir: Option<PathBuf>,

        #[command(flatten)]
        keys: KeyArgs,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Probe output is self-contained — library chatter (nostr_relay_pool etc.)
    // adds no value and clutters both human and JSON output.  Skip the tracing
    // subscriber entirely for the probe subcommand; initialise it normally for
    // audit subcommands where verbose output is expected.
    let is_probe = std::env::args().nth(1).as_deref() == Some("probe");
    if !is_probe {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Probe {
            relay,
            json,
            timeout,
            watch,
            keys,
            create_repo,
        } => {
            let relay = match relay {
                Some(r) => r,
                None => {
                    // Print probe-specific help and exit cleanly
                    let mut cmd = Cli::command();
                    let _ = cmd.find_subcommand_mut("probe").unwrap().print_help();
                    println!();
                    return Ok(());
                }
            };

            let keys = load_keys(&keys)?;

            // read_only is the default; --create-repo opts into the write path
            let read_only = !create_repo;

            // Overall probe timeout: min(20s, watch_interval) to prevent
            // overlapping runs under --watch or cron scheduling.
            let overall_secs = match watch {
                Some(interval) => interval.min(20),
                None => 20,
            };

            if let Some(interval) = watch {
                let mut run = 1u64;
                loop {
                    if !json {
                        println!("\n[Run {}]", run);
                    }
                    let report = grasp_audit::probe::run_probe(
                        &relay,
                        keys.clone(),
                        read_only,
                        timeout,
                        overall_secs,
                    )
                    .await;
                    if json {
                        report.print_json();
                    } else {
                        report.print_human();
                    }
                    run += 1;
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                }
            } else {
                let report =
                    grasp_audit::probe::run_probe(&relay, keys, read_only, timeout, overall_secs)
                        .await;
                if json {
                    report.print_json();
                } else {
                    report.print_human();
                }
                if !report.all_passed {
                    std::process::exit(1);
                }
            }
        }

        Commands::Audit {
            relay,
            mode,
            spec,
            git_data_dir,
            keys,
        } => {
            let keys = load_keys(&keys)?;
            let mut config = match mode.as_str() {
                "shared" => AuditConfig::shared(),
                "isolated" => AuditConfig::isolated(),
                // Backwards compatibility aliases
                "ci" => AuditConfig::isolated(),
                "production" => AuditConfig::shared(),
                _ => {
                    return Err(anyhow!(
                        "Invalid mode: {}. Use 'shared' or 'isolated'",
                        mode
                    ))
                }
            };

            // Audit needs to create events to test the relay, so disable read-only mode
            config.read_only = false;

            // Derive relay_domain from relay URL (e.g., "ws://localhost:8081" -> "localhost:8081")
            let relay_domain = relay
                .replace("ws://", "")
                .replace("wss://", "")
                .trim_end_matches('/')
                .to_string();

            println!("🔍 GRASP Audit Tool");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Relay:   {}", relay);
            println!("Mode:    {}", mode);
            println!("Spec:    {}", spec);
            println!("Run ID:  {}", config.run_id);
            if let Some(ref dir) = git_data_dir {
                println!("Git Dir: {}", dir.display());
            }
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();

            println!("Connecting to relay...");
            let client = match keys {
                Some(keys) => AuditClient::new_with_keys(&relay, config, keys).await,
                None => AuditClient::new(&relay, config).await,
            }
            .map_err(|e| anyhow!("Failed to connect to relay: {}", e))?;

            if !client.is_connected().await {
                return Err(anyhow!("Could not establish connection to relay"));
            }

            println!("✓ Connected\n");

            let results = match spec.as_str() {
                "nip01-smoke" => {
                    println!("Running NIP-01 smoke tests...\n");
                    specs::Nip01SmokeTests::run_all(&client).await
                }
                "nip11" => {
                    println!("Running NIP-11 document tests...\n");
                    specs::Nip11DocumentTests::run_all(&client).await
                }
                "event-acceptance" => {
                    println!("Running event acceptance policy tests...\n");
                    specs::EventAcceptancePolicyTests::run_all(&client).await
                }
                "cors" => {
                    println!("Running CORS tests...\n");
                    specs::CorsTests::run_all(&client, &relay_domain).await
                }
                "git-clone" => {
                    println!("Running Git clone tests...\n");
                    specs::GitCloneTests::run_all(&client, &relay_domain).await
                }
                "git-filter" => {
                    println!("Running Git filter capability tests...\n");
                    specs::GitFilterTests::run_all(&client, &relay_domain).await
                }
                "push-auth" => {
                    println!("Running push authorization tests...\n");
                    specs::PushAuthorizationTests::run_all(&client, &relay_domain).await
                }
                "repo-creation" => {
                    println!("Running repository creation tests...\n");
                    specs::RepositoryCreationTests::run_all(&client, &relay_domain).await
                }
                "purgatory" => {
                    println!("Running purgatory tests...\n");
                    specs::PurgatoryTests::run_all(&client).await
                }
                "grasp06" => {
                    println!("Running GRASP-06 tests...\n");
                    // GRASP-06 has its own report renderer (sections differ
                    // from GRASP-01). Print it directly and short-circuit the
                    // shared print_report path below.
                    let grasp06_results = specs::Grasp06Tests::run_all(&client).await;
                    specs::Grasp06Tests::print_report(&grasp06_results);
                    if !grasp06_results.all_passed() {
                        println!("❌ Some tests failed");
                        std::process::exit(1);
                    } else {
                        println!("✅ All tests passed!");
                    }
                    return Ok(());
                }
                "all" => {
                    println!("Running all tests...\n");
                    let mut all_results = AuditResult::new("All GRASP-01 Tests");

                    // NIP-01 smoke tests (stateless - no shared fixture dependencies)
                    println!("  → NIP-01 smoke tests...");
                    let nip01_results = specs::Nip01SmokeTests::run_all(&client).await;
                    all_results.merge(nip01_results);

                    // NIP-11 document tests (stateless)
                    println!("  → NIP-11 document tests...");
                    let nip11_results = specs::Nip11DocumentTests::run_all(&client).await;
                    all_results.merge(nip11_results);

                    // CORS tests (stateless HTTP checks)
                    println!("  → CORS tests...");
                    let cors_results = specs::CorsTests::run_all(&client, &relay_domain).await;
                    all_results.merge(cors_results);

                    // Repository creation tests (uses ValidRepoSent only - no state events)
                    println!("  → Repository creation tests...");
                    let repo_results = specs::RepositoryCreationTests::run_all(&client, &relay_domain).await;
                    all_results.merge(repo_results);

                    // Git clone tests (uses ValidRepoSent only - no state events)
                    println!("  → Git clone tests...");
                    let clone_results = specs::GitCloneTests::run_all(&client, &relay_domain).await;
                    all_results.merge(clone_results);

                    // Git filter capability tests (uses ValidRepoSent only - no state events)
                    println!("  → Git filter capability tests...");
                    let filter_results = specs::GitFilterTests::run_all(&client, &relay_domain).await;
                    all_results.merge(filter_results);

                    // Event acceptance policy tests (uses ValidRepoServed - no extra state events)
                    println!("  → Event acceptance policy tests...");
                    let event_results = specs::EventAcceptancePolicyTests::run_all(&client).await;
                    all_results.merge(event_results);

                    // Purgatory tests MUST run before push-auth.
                    // Push-auth sends new replaceable state events (kind 30618) for the same
                    // repo_id as OwnerStateDataPushed (e.g. test_head_set_after_git_push_with_required_oids
                    // sends a develop1 state event that displaces the original). If purgatory ran
                    // after push-auth, is_event_on_relay(original_id) would return false because
                    // the original state event has been replaced on the relay.
                    println!("  → Purgatory tests...");
                    let purgatory_results = specs::PurgatoryTests::run_all(&client).await;
                    all_results.merge(purgatory_results);

                    // Push authorization tests (mutates shared state - must run last among git specs)
                    println!("  → Push authorization tests...");
                    let push_results = specs::PushAuthorizationTests::run_all(&client, &relay_domain).await;
                    all_results.merge(push_results);

                    // GRASP-06 tests live in their own spec family with their
                    // own report renderer. Print the GRASP-01 block first
                    // (via the default `print_report` below), then the
                    // GRASP-06 block separately.
                    println!("  → GRASP-06 tests...");
                    let grasp06_results = specs::Grasp06Tests::run_all(&client).await;

                    println!();
                    all_results.print_report();
                    specs::Grasp06Tests::print_report(&grasp06_results);

                    let combined_ok =
                        all_results.all_passed() && grasp06_results.all_passed();
                    if !combined_ok {
                        println!("❌ Some tests failed");
                        std::process::exit(1);
                    } else {
                        println!("✅ All tests passed!");
                    }
                    return Ok(());
                }
                _ => {
                    return Err(anyhow!(
                        "Unknown spec: {}. Use 'nip01-smoke', 'nip11', 'event-acceptance', 'cors', 'git-clone', 'git-filter', 'push-auth', 'repo-creation', 'purgatory', 'grasp06', or 'all'",
                        spec
                    ))
                }
            };

            results.print_report();

            if !results.all_passed() {
                println!("❌ Some tests failed");
                std::process::exit(1);
            } else {
                println!("✅ All tests passed!");
            }
        }
    }

    Ok(())
}

fn load_keys(args: &KeyArgs) -> Result<Option<Keys>> {
    load_keys_with_env(args, std::env::var_os(GRASP_AUDIT_NSEC_ENV))
}

fn load_keys_with_env(args: &KeyArgs, env_value: Option<OsString>) -> Result<Option<Keys>> {
    let value = if let Some(value) = &args.nsec {
        Some((value.clone(), "--nsec".to_string()))
    } else if let Some(path) = &args.nsec_file {
        Some((
            std::fs::read_to_string(path)
                .map_err(|error| anyhow!("Failed to read {}: {error}", path.display()))?,
            format!("--nsec-file {}", path.display()),
        ))
    } else if let Some(value) = env_value {
        Some((
            value.into_string().map_err(|_| {
                anyhow!("Secret key from {GRASP_AUDIT_NSEC_ENV} is not valid UTF-8")
            })?,
            GRASP_AUDIT_NSEC_ENV.to_string(),
        ))
    } else {
        None
    };

    let Some((value, source)) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("Secret key source {source} is empty"));
    }

    Keys::parse(value)
        .map(Some)
        .map_err(|error| anyhow!("Invalid secret key from {source}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_args(nsec: Option<String>, nsec_file: Option<PathBuf>) -> KeyArgs {
        KeyArgs { nsec, nsec_file }
    }

    fn nsec(keys: &Keys) -> String {
        keys.secret_key().to_bech32().unwrap()
    }

    #[test]
    fn inline_key_takes_precedence_over_environment() {
        let inline = Keys::generate();
        let environment = Keys::generate();
        let loaded = load_keys_with_env(
            &key_args(Some(format!("  {}\n", nsec(&inline))), None),
            Some(nsec(&environment).into()),
        )
        .unwrap()
        .unwrap();

        assert_eq!(loaded.public_key(), inline.public_key());
    }

    #[test]
    fn file_key_takes_precedence_over_environment_and_is_trimmed() {
        let file_keys = Keys::generate();
        let environment = Keys::generate();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), format!("\n {} \n", nsec(&file_keys))).unwrap();

        let loaded = load_keys_with_env(
            &key_args(None, Some(file.path().to_path_buf())),
            Some(nsec(&environment).into()),
        )
        .unwrap()
        .unwrap();

        assert_eq!(loaded.public_key(), file_keys.public_key());
    }

    #[test]
    fn environment_key_is_used_and_trimmed() {
        let environment = Keys::generate();
        let loaded = load_keys_with_env(
            &key_args(None, None),
            Some(format!("\t{}\n", nsec(&environment)).into()),
        )
        .unwrap()
        .unwrap();

        assert_eq!(loaded.public_key(), environment.public_key());
    }

    #[test]
    fn hex_keys_are_supported() {
        let expected = Keys::generate();
        let hex = expected.secret_key().to_secret_hex();
        let loaded = load_keys_with_env(&key_args(Some(hex), None), None)
            .unwrap()
            .unwrap();

        assert_eq!(loaded.public_key(), expected.public_key());
    }

    #[test]
    fn no_key_source_preserves_generated_key_behavior() {
        assert!(load_keys_with_env(&key_args(None, None), None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn empty_and_invalid_key_sources_are_rejected() {
        let empty = load_keys_with_env(&key_args(Some(" \n".to_string()), None), None).unwrap_err();
        assert!(empty.to_string().contains("--nsec is empty"));

        let invalid =
            load_keys_with_env(&key_args(None, None), Some("not-a-key".into())).unwrap_err();
        assert!(invalid
            .to_string()
            .contains("Invalid secret key from GRASP_AUDIT_NSEC"));
    }

    #[test]
    fn empty_key_file_is_rejected_with_its_source() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let error =
            load_keys_with_env(&key_args(None, Some(file.path().to_path_buf())), None).unwrap_err();

        assert!(error.to_string().contains("--nsec-file"));
        assert!(error.to_string().contains("is empty"));
    }

    #[test]
    fn both_subcommands_expose_key_options_and_reject_cli_conflicts() {
        for subcommand in ["probe", "audit"] {
            let parsed = Cli::try_parse_from([
                "grasp-audit",
                subcommand,
                "--relay",
                "wss://example.com",
                "--nsec",
                "secret",
                "--nsec-file",
                "/tmp/secret",
            ]);
            assert!(
                parsed.is_err(),
                "{subcommand} accepted conflicting key sources"
            );
        }
    }
}
