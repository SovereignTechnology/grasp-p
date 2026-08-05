//! GRASP Audit CLI Tool

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use grasp_audit::*;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "grasp-audit", version)]
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AuditSelection {
    Nip01Smoke,
    Nip11,
    EventAcceptance,
    Cors,
    GitClone,
    GitFilter,
    PushAuth,
    RepoCreation,
    Purgatory,
    Grasp06,
    All,
}

impl std::fmt::Display for AuditSelection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self
            .to_possible_value()
            .expect("audit selection variants have possible values");
        formatter.write_str(value.get_name())
    }
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

        /// Restrict read-only probes to pinned public wss/https targets.
        #[arg(long, default_value_t = false)]
        harden_network: bool,
    },

    /// Run audit tests against a server
    Audit {
        /// Relay URL (e.g., ws://localhost:7000)
        #[arg(short, long)]
        relay: String,

        /// Fixture mode: shared (default) or isolated
        #[arg(short, long, default_value = "shared")]
        mode: String,

        /// Audit specification or suite to run.
        #[arg(short, long, value_enum, default_value_t = AuditSelection::All)]
        spec: AuditSelection,

        /// Git data directory (required for cors, git-clone, push-auth, repo-creation specs)
        #[arg(short, long)]
        git_data_dir: Option<PathBuf>,

        /// Output one stable machine-readable JSON document.
        #[arg(long, default_value_t = false)]
        json: bool,

        #[command(flatten)]
        keys: KeyArgs,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let is_probe = args.get(1).is_some_and(|arg| arg == "probe");
    if !is_probe {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();
    }

    let audit_json = audit_json_requested(&args);
    let parse_started_at = unix_timestamp();
    let parse_started = Instant::now();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            error.print()?;
            return Ok(());
        }
        Err(error) if audit_json => {
            let report = AuditReport::error(
                requested_relay(&args),
                "",
                parse_started_at,
                parse_started.elapsed(),
                format!("invalid command line ({:?})", error.kind()),
            );
            println!("{}", serde_json::to_string(&report)?);
            std::process::exit(2);
        }
        Err(error) => error.exit(),
    };

    match cli.command {
        Commands::Probe {
            relay,
            json,
            timeout,
            watch,
            keys,
            create_repo,
            harden_network,
        } => {
            let relay = match relay {
                Some(relay) => relay,
                None => {
                    let mut command = Cli::command();
                    let _ = command.find_subcommand_mut("probe").unwrap().print_help();
                    println!();
                    return Ok(());
                }
            };
            let keys = load_keys(&keys)?;
            let read_only = !create_repo;
            let overall_secs = watch.map_or(20, |interval| interval.min(20));
            let options = ProbeOptions { harden_network };

            if let Some(interval) = watch {
                let mut run = 1_u64;
                loop {
                    if !json {
                        println!("\n[Run {run}]");
                    }
                    let report = run_probe_with_options(
                        &relay,
                        keys.clone(),
                        read_only,
                        timeout,
                        overall_secs,
                        options,
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
                    run_probe_with_options(&relay, keys, read_only, timeout, overall_secs, options)
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
            json,
            keys,
        } => run_audit(relay, mode, spec, git_data_dir, json, keys).await?,
    }

    Ok(())
}

fn audit_json_requested(args: &[OsString]) -> bool {
    args.get(1).is_some_and(|arg| arg == "audit") && args.iter().skip(2).any(|arg| arg == "--json")
}

fn requested_relay(args: &[OsString]) -> String {
    for (index, arg) in args.iter().enumerate().skip(2) {
        if arg == "--relay" || arg == "-r" {
            return args
                .get(index + 1)
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_default();
        }
        if let Some(value) = arg.to_str().and_then(|arg| arg.strip_prefix("--relay=")) {
            return value.to_string();
        }
    }
    String::new()
}

async fn run_audit(
    relay: String,
    mode: String,
    spec: AuditSelection,
    git_data_dir: Option<PathBuf>,
    json: bool,
    key_args: KeyArgs,
) -> Result<()> {
    let started_at = unix_timestamp();
    let started = Instant::now();
    let mut config = match mode.as_str() {
        "shared" | "production" => AuditConfig::shared(),
        "isolated" | "ci" => AuditConfig::isolated(),
        _ => audit_runtime_error(
            json,
            &relay,
            "",
            started_at,
            started,
            anyhow!("Invalid mode: {mode}. Use 'shared' or 'isolated'"),
        ),
    };
    config.read_only = false;
    let run_id = config.run_id.clone();

    let keys = match load_keys(&key_args) {
        Ok(keys) => keys,
        Err(error) => audit_runtime_error(json, &relay, &run_id, started_at, started, error),
    };
    let relay_domain = relay
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .trim_end_matches('/')
        .to_string();

    if !json {
        println!("🔍 GRASP Audit Tool");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Relay:   {relay}");
        println!("Mode:    {mode}");
        println!("Spec:    {spec}");
        println!("Run ID:  {run_id}");
        if let Some(ref dir) = git_data_dir {
            println!("Git Dir: {}", dir.display());
        }
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        println!("Connecting to relay...");
    }

    let client_result = match keys {
        Some(keys) => AuditClient::new_with_keys(&relay, config, keys).await,
        None => AuditClient::new(&relay, config).await,
    };
    let client = match client_result {
        Ok(client) => client,
        Err(error) => audit_runtime_error(
            json,
            &relay,
            &run_id,
            started_at,
            started,
            anyhow!("Failed to connect to relay: {error}"),
        ),
    };
    if !client.is_connected().await {
        audit_runtime_error(
            json,
            &relay,
            &run_id,
            started_at,
            started,
            anyhow!("Could not establish connection to relay"),
        );
    }
    if !json {
        println!("✓ Connected\n");
    }

    let mut results = Vec::new();
    match spec {
        AuditSelection::Nip01Smoke => {
            status(json, "Running NIP-01 smoke tests...");
            results.push((
                AuditSuite::Nip01Smoke,
                specs::Nip01SmokeTests::run_all(&client).await,
            ));
        }
        AuditSelection::Nip11 => {
            status(json, "Running NIP-11 document tests...");
            results.push((
                AuditSuite::Nip11Document,
                specs::Nip11DocumentTests::run_all(&client).await,
            ));
        }
        AuditSelection::EventAcceptance => {
            status(json, "Running event acceptance policy tests...");
            results.push((
                AuditSuite::EventAcceptance,
                specs::EventAcceptancePolicyTests::run_all(&client).await,
            ));
        }
        AuditSelection::Cors => {
            status(json, "Running CORS tests...");
            results.push((
                AuditSuite::Cors,
                specs::CorsTests::run_all(&client, &relay_domain).await,
            ));
        }
        AuditSelection::GitClone => {
            status(json, "Running Git clone tests...");
            results.push((
                AuditSuite::GitClone,
                specs::GitCloneTests::run_all(&client, &relay_domain).await,
            ));
        }
        AuditSelection::GitFilter => {
            status(json, "Running Git filter capability tests...");
            results.push((
                AuditSuite::GitFilter,
                specs::GitFilterTests::run_all(&client, &relay_domain).await,
            ));
        }
        AuditSelection::PushAuth => {
            status(json, "Running push authorization tests...");
            results.push((
                AuditSuite::PushAuthorization,
                specs::PushAuthorizationTests::run_all(&client, &relay_domain).await,
            ));
        }
        AuditSelection::RepoCreation => {
            status(json, "Running repository creation tests...");
            results.push((
                AuditSuite::RepositoryCreation,
                specs::RepositoryCreationTests::run_all(&client, &relay_domain).await,
            ));
        }
        AuditSelection::Purgatory => {
            status(json, "Running purgatory tests...");
            results.push((
                AuditSuite::Purgatory,
                specs::PurgatoryTests::run_all(&client).await,
            ));
        }
        AuditSelection::Grasp06 => {
            status(json, "Running GRASP-06 tests...");
            results.push((
                AuditSuite::Grasp06All,
                specs::Grasp06Tests::run_all(&client).await,
            ));
        }
        AuditSelection::All => {
            status(json, "Running all tests...");
            let mut grasp01 = AuditResult::new("All GRASP-01 Tests");
            progress(json, "  → NIP-01 smoke tests...");
            grasp01.merge(specs::Nip01SmokeTests::run_all(&client).await);
            progress(json, "  → NIP-11 document tests...");
            grasp01.merge(specs::Nip11DocumentTests::run_all(&client).await);
            progress(json, "  → CORS tests...");
            grasp01.merge(specs::CorsTests::run_all(&client, &relay_domain).await);
            progress(json, "  → Repository creation tests...");
            grasp01.merge(specs::RepositoryCreationTests::run_all(&client, &relay_domain).await);
            progress(json, "  → Git clone tests...");
            grasp01.merge(specs::GitCloneTests::run_all(&client, &relay_domain).await);
            progress(json, "  → Git filter capability tests...");
            grasp01.merge(specs::GitFilterTests::run_all(&client, &relay_domain).await);
            progress(json, "  → Event acceptance policy tests...");
            grasp01.merge(specs::EventAcceptancePolicyTests::run_all(&client).await);
            // Purgatory must run before push authorization because the latter
            // replaces shared state events used by the purgatory assertions.
            progress(json, "  → Purgatory tests...");
            grasp01.merge(specs::PurgatoryTests::run_all(&client).await);
            progress(json, "  → Push authorization tests...");
            grasp01.merge(specs::PushAuthorizationTests::run_all(&client, &relay_domain).await);
            results.push((AuditSuite::Grasp01All, grasp01));
            progress(json, "  → GRASP-06 tests...");
            results.push((
                AuditSuite::Grasp06All,
                specs::Grasp06Tests::run_all(&client).await,
            ));
        }
    }

    let all_passed = results.iter().all(|(_, result)| result.all_passed());
    if json {
        let specs = results
            .iter()
            .map(|(suite, result)| SpecReport::from_result(*suite, result))
            .collect();
        let report = AuditReport::completed(&relay, &run_id, started_at, started.elapsed(), specs);
        println!("{}", serde_json::to_string(&report)?);
    } else {
        for (suite, result) in &results {
            if *suite == AuditSuite::Grasp06All {
                specs::Grasp06Tests::print_report(result);
            } else {
                result.print_report();
            }
        }
        if all_passed {
            println!("✅ All tests passed!");
        } else {
            println!("❌ Some tests failed");
        }
    }

    if !all_passed {
        std::process::exit(1);
    }
    Ok(())
}

fn status(json: bool, message: &str) {
    if !json {
        println!("{message}\n");
    }
}

fn progress(json: bool, message: &str) {
    if !json {
        println!("{message}");
    }
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

fn audit_runtime_error(
    json: bool,
    relay: &str,
    run_id: &str,
    started_at: u64,
    started: Instant,
    error: anyhow::Error,
) -> ! {
    if json {
        let report = AuditReport::error(
            relay,
            run_id,
            started_at,
            started.elapsed(),
            error.to_string(),
        );
        println!(
            "{}",
            serde_json::to_string(&report).expect("audit error report is serializable")
        );
    } else {
        eprintln!("{error:#}");
    }
    std::process::exit(2);
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

    #[test]
    fn audit_selection_is_validated_by_clap() {
        let parsed = Cli::try_parse_from([
            "grasp-audit",
            "audit",
            "--relay",
            "wss://example.com",
            "--spec",
            "not-an-audit",
        ]);

        assert!(parsed.is_err());
    }

    #[test]
    fn json_parse_error_helpers_detect_audit_and_relay() {
        let args: Vec<OsString> = [
            "grasp-audit",
            "audit",
            "--json",
            "--relay=wss://relay.example",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();

        assert!(audit_json_requested(&args));
        assert_eq!(requested_relay(&args), "wss://relay.example");
    }
}
