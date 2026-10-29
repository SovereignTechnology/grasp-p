//! Sync context abstraction for testability.
//!
//! This module provides the `SyncContext` trait which abstracts external dependencies
//! for sync operations. This allows unit testing of sync logic by mocking:
//! - Repository data fetching
//! - OID existence checks
//! - Git fetch operations
//! - Event processing
//!
//! The real implementation (`RealSyncContext`) connects to actual database, git,
//! and relay systems. The mock implementation (`MockSyncContext`) is used in tests.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitFetchRole {
    Primary,
    Hedge,
    Integrity,
}

impl GitFetchRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Hedge => "hedge",
            Self::Integrity => "integrity",
        }
    }
}

use crate::git::authorization::RepositoryData;
use crate::git::sync::PurgatoryPromotionHooks;
use crate::purgatory::promotion_hooks::NostrPurgatoryPromotionHooks;

/// Result of processing newly available git data.
///
/// This struct captures what happened when we tried to release events from
/// purgatory after new git data became available.
#[derive(Debug, Default, Clone)]
pub struct ProcessResult {
    /// Number of state events released from purgatory
    pub states_released: usize,
    /// Number of PR events released from purgatory
    pub prs_released: usize,
    /// Number of repositories synced (OIDs copied + refs aligned)
    pub repos_synced: usize,
    /// Number of refs created across all repos
    pub refs_created: usize,
    /// Number of refs updated across all repos
    pub refs_updated: usize,
    /// Number of refs deleted across all repos
    pub refs_deleted: usize,
    /// Errors encountered (non-fatal)
    pub errors: Vec<String>,
}

impl ProcessResult {
    /// Check if any events were released
    pub fn released_any(&self) -> bool {
        self.states_released > 0 || self.prs_released > 0
    }
}

/// Abstraction over external dependencies for sync operations.
///
/// This trait allows unit testing of sync logic by mocking:
/// - Repository data fetching
/// - OID existence checks
/// - Git fetch operations
/// - Event processing
///
/// # Implementation Notes
///
/// The real implementation (`RealSyncContext`) holds references to purgatory,
/// database, etc., and the `process_newly_available_git_data` method delegates
/// to the unified function. This keeps the sync logic functions
/// (`sync_identifier_next_url`, `sync_identifier_from_url`) clean and testable
/// with mocks.
#[async_trait]
pub trait SyncContext: Send + Sync {
    /// Collect clone URLs from PR events in purgatory for a given identifier.
    ///
    /// PR events (kind 1618) and PR Update events (kind 1619) can include `clone` tags
    /// specifying where the PR commits can be fetched from. This method extracts those
    /// URLs to supplement the clone URLs from repository announcements.
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier
    ///
    /// # Returns
    /// Set of clone URLs from PR events in purgatory for this identifier
    fn collect_pr_clone_urls(&self, identifier: &str) -> HashSet<String>;
    /// Get repository data (announcements, clone URLs, etc.) from the database and purgatory.
    ///
    /// Checks both the database (promoted announcements) and purgatory (announcements
    /// awaiting git data). This is necessary to obtain clone URLs when an announcement
    /// has not yet been promoted - without purgatory data, the sync loop would have no
    /// URLs to fetch from and the announcement could never be promoted (circular deadlock).
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier (d-tag value)
    ///
    /// # Returns
    /// Repository data including announcements and state events
    async fn fetch_repository_data_with_purgatory(
        &self,
        identifier: &str,
    ) -> Result<RepositoryData>;

    /// Get all OIDs needed for purgatory events with this identifier.
    ///
    /// This collects commit hashes from:
    /// - State events in purgatory (branch/tag commits)
    /// - PR events in purgatory (commit hash from c-tag)
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier
    ///
    /// # Returns
    /// Set of OID strings (commit hashes) that are still needed
    fn collect_needed_oids(&self, identifier: &str) -> HashSet<String>;

    /// Check if an OID exists locally in a repository.
    ///
    /// # Arguments
    /// * `repo_path` - Path to the git repository
    /// * `oid` - The object ID (commit hash) to check
    ///
    /// # Returns
    /// true if the OID exists in the repository
    fn oid_exists(&self, repo_path: &Path, oid: &str) -> bool;

    /// Fetch OIDs from a remote server.
    ///
    /// Attempts to fetch the specified OIDs from the given URL into the
    /// local repository.
    ///
    /// # Arguments
    /// * `repo_path` - Path to the local git repository
    /// * `url` - Remote URL to fetch from
    /// * `oids` - List of OIDs to fetch
    ///
    /// # Returns
    /// List of OIDs that were successfully fetched
    async fn fetch_oids(
        &self,
        repo_path: &Path,
        url: &str,
        oids: &[String],
    ) -> Result<Vec<String>> {
        self.fetch_oids_with_role(repo_path, url, oids, GitFetchRole::Primary)
            .await
    }

    async fn fetch_oids_with_role(
        &self,
        repo_path: &Path,
        url: &str,
        oids: &[String],
        role: GitFetchRole,
    ) -> Result<Vec<String>>;

    /// Process newly available git data.
    ///
    /// This is called after each successful OID fetch to check if any purgatory
    /// events can now be satisfied with the available git data.
    ///
    /// The function:
    /// 1. Discovers satisfiable events from purgatory
    /// 2. Syncs OIDs to authorized owner repos
    /// 3. Aligns refs (+ sets HEAD)
    /// 4. Saves events to database
    /// 5. Notifies WebSocket subscribers
    /// 6. Removes from purgatory
    ///
    /// # Arguments
    /// * `source_repo_path` - Path to the repository that has the new git data
    /// * `new_oids` - Set of OIDs that were just fetched
    ///
    /// # Returns
    /// Result describing what was processed
    async fn process_newly_available_git_data(
        &self,
        source_repo_path: &Path,
        new_oids: &HashSet<String>,
    ) -> Result<ProcessResult>;

    /// Check if there are still pending events for this identifier.
    ///
    /// Returns true if purgatory has state events or PR events for this identifier.
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier
    fn has_pending_events(&self, identifier: &str) -> bool;

    /// Find the best local repository to fetch into.
    ///
    /// Given repository data from the database, finds an existing local repository
    /// that can be used as the fetch target. Typically returns the first owner's
    /// repository that exists on disk.
    ///
    /// # Arguments
    /// * `db_repo_data` - Repository data from the database
    ///
    /// # Returns
    /// Path to the target repository, or None if no suitable repo exists
    fn find_target_repo(&self, db_repo_data: &RepositoryData) -> Option<PathBuf>;

    /// Get our domain (to exclude from clone URLs).
    ///
    /// When syncing, we don't want to fetch from ourselves. This returns our
    /// domain so it can be filtered out of clone URL lists.
    fn our_domain(&self) -> Option<&str>;
}

// =============================================================================
// Real Implementation
// =============================================================================

use nostr_sdk::local_relay::LocalRelay;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tracing::debug;

use crate::git::storage::{FamilyKey, LocalGitStorage, ObjectFormat};
use crate::nostr::builder::Nip34WritePolicy;
use crate::nostr::events::RepositoryState;
use crate::nostr::SharedDatabase;
use crate::outbound::{OutboundTargetKind, OutboundTargetPolicy, ResolvedTarget};
use crate::purgatory::Purgatory;
use crate::sync::naughty_list::NaughtyListTracker;

use super::functions::extract_domain;
use super::git_budget::{
    is_rate_limit_error, GitBudgetDeferred, GitCommandBudget, GitCommandReservation,
    SPECULATIVE_PER_PASS,
};

/// Real implementation of `SyncContext` that connects to actual systems.
///
/// This is the production implementation used by the sync loop. It:
/// - Queries the database for repository data
/// - Collects needed OIDs from purgatory state and PR events
/// - Uses git commands to check OID existence and fetch from remote servers
/// - Delegates to the unified `process_newly_available_git_data` function
pub struct RealSyncContext {
    /// Purgatory instance for checking pending events and collecting needed OIDs
    purgatory: Arc<Purgatory>,

    /// Database for querying repository data and saving events
    database: SharedDatabase,

    /// Base path for git repositories
    git_data_path: PathBuf,

    /// Our domain (to exclude from clone URLs when syncing)
    our_domain_value: Option<String>,

    /// Local relay for notifying WebSocket subscribers
    local_relay: Option<LocalRelay>,

    /// Write policy used for promotion-time recovery hooks.
    write_policy: Option<Nip34WritePolicy>,

    /// Naughty list tracker for git remote domains with persistent errors
    git_naughty_list: Arc<NaughtyListTracker>,

    /// OIDs each URL has already reported missing, scoped to its current
    /// advertised ref tips.
    miss_memo: Arc<Mutex<HashMap<String, RemoteMissMemo>>>,

    /// Counts individual Git commands across every URL, pass, and repair role.
    git_budget: GitCommandBudget,

    /// Outbound target policy applied before every event-directed git fetch
    outbound_policy: OutboundTargetPolicy,

    /// Confirmed GRASP-08 peers (by canonical `host:port`), fed by the sync
    /// manager's NIP-11 fetches. Only set for private instances.
    grasp08_peers: Option<crate::private::Grasp08Peers>,

    /// Keys signing outbound GRASP-08 repository credentials. Only set for
    /// private instances; fetches stay unauthenticated without them.
    credential_keys: Option<nostr_sdk::prelude::Keys>,
}

impl RealSyncContext {
    /// Create a new real sync context.
    ///
    /// # Arguments
    /// * `purgatory` - Purgatory instance for pending events
    /// * `database` - Database for queries and saves
    /// * `git_data_path` - Base path for git repositories
    /// * `our_domain` - Our domain to exclude from clone URLs
    /// * `local_relay` - Local relay for WebSocket notifications
    /// * `write_policy` - Write policy for promotion-time recovery hooks
    /// * `git_naughty_list` - Naughty list tracker for git remote domains
    /// * `outbound_policy` - Policy vetting event-directed git fetch targets
    /// * `grasp08_peers` - Confirmed GRASP-08 peer registry (private mode only)
    /// * `credential_keys` - Keys signing outbound GRASP-08 credentials
    ///   (private mode only)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        purgatory: Arc<Purgatory>,
        database: SharedDatabase,
        git_data_path: PathBuf,
        our_domain: Option<String>,
        local_relay: Option<LocalRelay>,
        write_policy: Option<Nip34WritePolicy>,
        git_naughty_list: Arc<NaughtyListTracker>,
        outbound_policy: OutboundTargetPolicy,
        grasp08_peers: Option<crate::private::Grasp08Peers>,
        credential_keys: Option<nostr_sdk::prelude::Keys>,
    ) -> Self {
        Self {
            purgatory,
            database,
            git_data_path,
            our_domain_value: our_domain,
            local_relay,
            write_policy,
            git_naughty_list,
            miss_memo: Arc::new(Mutex::new(HashMap::new())),
            git_budget: GitCommandBudget::default(),
            outbound_policy,
            grasp08_peers,
            credential_keys,
        }
    }

    /// Get reference to the git naughty list tracker
    pub fn git_naughty_list(&self) -> &Arc<NaughtyListTracker> {
        &self.git_naughty_list
    }

    /// Clone URLs from accepted repository announcements for one identifier.
    ///
    /// Integrity repair deliberately excludes purgatory URLs: it heals
    /// durable families only from repository sources already accepted into
    /// the relay database. The normal outbound policy is still applied at the
    /// point of each fetch.
    pub async fn accepted_repository_clone_urls(&self, identifier: &str) -> Result<Vec<String>> {
        let data = crate::git::authorization::fetch_repository_data_excluding_purgatory(
            &self.database,
            identifier,
        )
        .await?;
        let mut urls: Vec<_> = data
            .announcements
            .into_iter()
            .flat_map(|announcement| announcement.clone_urls)
            .filter(|url| {
                self.our_domain_value
                    .as_deref()
                    .is_none_or(|domain| !crate::outbound::url_matches_service_domain(url, domain))
            })
            .collect();
        urls.sort();
        urls.dedup();
        Ok(urls)
    }

    pub(crate) async fn accepted_repository_data_for_integrity(
        &self,
        identifier: &str,
    ) -> Result<RepositoryData> {
        crate::git::authorization::fetch_repository_data_excluding_purgatory(
            &self.database,
            identifier,
        )
        .await
    }

    /// Accepted PR and PR-update events used to reconstruct the authorized
    /// `refs/nostr/*` surface during the startup integrity pass.
    pub(crate) async fn accepted_pr_events_for_integrity(
        &self,
    ) -> Result<Vec<nostr_sdk::prelude::Event>> {
        use nostr_sdk::prelude::{Filter, Kind};

        self.database
            .query(Filter::new().kinds([Kind::GitPullRequest, Kind::GitPullRequestUpdate]))
            .await
            .map(|events| events.into_iter().collect())
            .map_err(|error| anyhow::anyhow!("Database query failed: {error}"))
    }

    /// Revalidate a bounded set of PR IDs immediately before ref mutation.
    /// Deleted events disappear from this result, preventing a long-running
    /// online pass from recreating refs from its older startup snapshot.
    pub(crate) async fn accepted_pr_events_by_id_for_integrity(
        &self,
        ids: &[nostr_sdk::prelude::EventId],
    ) -> Result<Vec<nostr_sdk::prelude::Event>> {
        use nostr_sdk::prelude::{Filter, Kind};

        if ids.is_empty() {
            return Ok(Vec::new());
        }
        self.database
            .query(
                Filter::new()
                    .ids(ids.iter().copied())
                    .kinds([Kind::GitPullRequest, Kind::GitPullRequestUpdate]),
            )
            .await
            .map(|events| events.into_iter().collect())
            .map_err(|error| anyhow::anyhow!("Database query failed: {error}"))
    }

    pub(crate) fn pending_pr_entries_for_integrity(
        &self,
    ) -> Vec<(String, crate::purgatory::PrPurgatoryEntry)> {
        self.purgatory.pr_entries_for_integrity()
    }

    pub(crate) fn pending_state_events_for_integrity(
        &self,
        identifier: &str,
    ) -> Vec<crate::purgatory::StatePurgatoryEntry> {
        self.purgatory.find_state(identifier)
    }

    pub(crate) fn service_address_for_integrity(&self) -> Option<&str> {
        self.our_domain_value.as_deref()
    }
}

const MISS_MEMO_TTL: Duration = Duration::from_secs(30 * 60);
const MISS_MEMO_MAX_URLS: usize = 1024;

#[derive(Debug)]
struct RemoteMissMemo {
    advert_fingerprint: u64,
    missing: HashSet<String>,
    last_touched: Instant,
}

fn advertised_oids_fingerprint(advertised: &HashSet<String>) -> u64 {
    let mut sorted: Vec<&str> = advertised.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut hasher = DefaultHasher::new();
    sorted.hash(&mut hasher);
    hasher.finish()
}

fn memoized_missing_for_url(
    memo: &mut HashMap<String, RemoteMissMemo>,
    url: &str,
    advert_fingerprint: u64,
    now: Instant,
) -> HashSet<String> {
    memo.retain(|_, entry| now.duration_since(entry.last_touched) < MISS_MEMO_TTL);

    if let Some(entry) = memo.get_mut(url) {
        entry.last_touched = now;
        if entry.advert_fingerprint == advert_fingerprint {
            return entry.missing.clone();
        }
        entry.advert_fingerprint = advert_fingerprint;
        entry.missing.clear();
        return HashSet::new();
    }

    if memo.len() >= MISS_MEMO_MAX_URLS {
        if let Some(oldest_url) = memo
            .iter()
            .min_by_key(|(_, entry)| entry.last_touched)
            .map(|(url, _)| url.clone())
        {
            memo.remove(&oldest_url);
        }
    }
    memo.insert(
        url.to_string(),
        RemoteMissMemo {
            advert_fingerprint,
            missing: HashSet::new(),
            last_touched: now,
        },
    );
    HashSet::new()
}

/// `http.curloptResolve` entry pinning the vetted DNS answers, when any.
///
/// Format is curl's `HOST:PORT:ADDRESS[,ADDRESS]`. Empty when the policy is
/// permissive and no vetting occurred (nothing to pin).
fn resolve_pin_entry(resolved: &ResolvedTarget) -> Option<String> {
    if resolved.addresses.is_empty() {
        return None;
    }
    let addresses = resolved
        .addresses
        .iter()
        .map(|address| match address {
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
            std::net::IpAddr::V4(v4) => v4.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",");
    Some(format!(
        "{}:{}:{}",
        resolved.target.host, resolved.target.port, addresses
    ))
}

/// Build a git command (fetch / ls-remote) that cannot escape the outbound
/// target policy.
///
/// The URL was authorized immediately before this call; these controls keep
/// the subprocess pointed at the vetted target:
/// - `GIT_ALLOW_PROTOCOL` confines git to smart HTTP, so no server-suggested
///   alternate transport (ssh, file, ext) can run;
/// - `http.followRedirects=false` stops HTTP redirects re-targeting the fetch;
/// - proxy configuration and environment are cleared so the connection goes to
///   the host that was vetted rather than through an ambient proxy;
/// - `credential.helper=` keeps any operator credentials on this machine out
///   of requests to event-directed servers;
/// - `http.curloptResolve` pins the vetted DNS answers so the fetch cannot be
///   re-bound to a different address between authorization and connection.
///
/// `auth_header` attaches an explicit `Authorization` header (the GRASP-08
/// repository credential for a confirmed private peer). This deliberately
/// does not conflict with the `credential.helper=` hardening: that control
/// keeps *ambient operator* credentials away from event-directed servers,
/// while this header is a peer-scoped credential minted for exactly this
/// fetch target.
fn hardened_git_command(
    repo_path: &Path,
    resolve_pin: Option<&str>,
    auth_header: Option<&str>,
    object_directory: Option<&Path>,
    negotiation_algorithm: Option<&str>,
    args: &[String],
) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-c")
        .arg("http.followRedirects=false")
        .arg("-c")
        .arg("http.proxy=")
        .arg("-c")
        .arg("credential.helper=");
    if let Some(algorithm) = negotiation_algorithm {
        command
            .arg("-c")
            .arg(format!("fetch.negotiationAlgorithm={algorithm}"));
    }
    if let Some(pin) = resolve_pin {
        command.arg("-c").arg(format!("http.curloptResolve={pin}"));
    }
    if let Some(header) = auth_header {
        command
            .arg("-c")
            .arg(format!("http.extraHeader=Authorization: {header}"));
    }
    command
        .args(args)
        .env("GIT_ALLOW_PROTOCOL", "http:https")
        .env_remove("http_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("all_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("GIT_PROXY_COMMAND")
        .env("LC_ALL", "C")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .current_dir(repo_path);
    if let Some(object_directory) = object_directory {
        command.env("GIT_OBJECT_DIRECTORY", object_directory);
    }
    command
}

const LS_REMOTE_STDOUT_CAPTURE_LIMIT: usize = 16 * 1024 * 1024;
const GIT_STDOUT_CAPTURE_LIMIT: usize = 1024 * 1024;
const GIT_STDERR_CAPTURE_LIMIT: usize = 4 * 1024 * 1024;
const GIT_LONG_RUNNING_AFTER: Duration = Duration::from_secs(60);
const GIT_LONG_RUNNING_REPEAT: Duration = Duration::from_secs(300);
const GIT_INACTIVITY_LIMIT: Duration = Duration::from_secs(5 * 60);
const GIT_TERMINATION_GRACE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
struct GitProcessPolicy {
    inactivity_limit: Duration,
    termination_grace: Duration,
}

impl Default for GitProcessPolicy {
    fn default() -> Self {
        Self {
            inactivity_limit: GIT_INACTIVITY_LIMIT,
            termination_grace: GIT_TERMINATION_GRACE,
        }
    }
}

#[derive(Default)]
struct GitActivity {
    last_millis: AtomicU64,
    stdout_bytes: AtomicU64,
    stderr_bytes: AtomicU64,
}

struct ObservedGitOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

struct ProcessGroupGuard {
    pgid: u32,
    armed: bool,
}

impl ProcessGroupGuard {
    fn new(pgid: u32) -> Self {
        Self { pgid, armed: true }
    }

    fn signal(&self, signal: libc::c_int) -> std::io::Result<()> {
        signal_process_group(self.pgid, signal)
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            // Cancellation drops this guard while the direct child still
            // anchors the process-group identity. Synchronous best-effort
            // cleanup prevents helpers outliving repository/domain permits.
            let _ = signal_process_group(self.pgid, libc::SIGKILL);
        }
    }
}

async fn drain_git_stream<R: AsyncRead + Unpin>(
    mut stream: R,
    capture_limit: usize,
    started: Instant,
    activity: Arc<GitActivity>,
    stdout: bool,
) -> std::io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        activity
            .last_millis
            .store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        let counter = if stdout {
            &activity.stdout_bytes
        } else {
            &activity.stderr_bytes
        };
        counter.fetch_add(read as u64, Ordering::Relaxed);
        let remaining = capture_limit.saturating_sub(captured.len());
        captured.extend_from_slice(&buffer[..read.min(remaining)]);
    }
    Ok(captured)
}

async fn run_budgeted_git_command(
    budget: &GitCommandBudget,
    reservation: Option<&mut GitCommandReservation<'_>>,
    command: Command,
    domain: &str,
    operation: &'static str,
    role: GitFetchRole,
) -> Result<ObservedGitOutput> {
    let admission = match reservation {
        Some(reservation) => reservation.admit(),
        None => budget.admit(
            domain,
            operation == "fetch_residual" && role != GitFetchRole::Integrity,
        ),
    };
    if let Err(reason) = admission {
        crate::metrics::record_purgatory_git_deferred(operation, reason);
        debug!(domain, operation, reason, "Outbound Git command deferred");
        return Err(GitBudgetDeferred {
            retry_after: budget.retry_after(domain),
            reason,
        }
        .into());
    }
    let output = run_observed_git_command(command, domain, operation, role).await?;
    if !output.status.success() && is_rate_limit_error(&String::from_utf8_lossy(&output.stderr)) {
        budget.rate_limited(domain);
        tracing::warn!(
            domain,
            operation,
            role = role.as_str(),
            cooldown_secs = 60,
            "Git server rate limited outbound requests; deferring this domain"
        );
    }
    Ok(output)
}

async fn run_observed_git_command(
    command: Command,
    domain: &str,
    operation: &'static str,
    role: GitFetchRole,
) -> Result<ObservedGitOutput> {
    run_observed_git_command_with_policy(
        command,
        domain,
        operation,
        role,
        GitProcessPolicy::default(),
    )
    .await
}

async fn run_observed_git_command_with_policy(
    mut command: Command,
    domain: &str,
    operation: &'static str,
    role: GitFetchRole,
    policy: GitProcessPolicy,
) -> Result<ObservedGitOutput> {
    let role = role.as_str();
    let mut metric = crate::metrics::start_purgatory_git_subprocess(operation, role);
    let started = Instant::now();
    let activity = Arc::new(GitActivity::default());
    // Give Git and every helper it creates (remote-http, credential helpers,
    // upload-pack transports) a private process group. Inactivity recovery
    // must not leave a descendant holding pipes, locks, or network sockets.
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            metric.finish(false);
            return Err(error.into());
        }
    };
    let mut process_group = ProcessGroupGuard::new(
        child
            .id()
            .ok_or_else(|| anyhow::anyhow!("git {operation} child had no process id"))?,
    );
    let Some(stdout) = child.stdout.take() else {
        metric.finish(false);
        return Err(anyhow::anyhow!("git {operation} stdout was not piped"));
    };
    let Some(stderr) = child.stderr.take() else {
        metric.finish(false);
        return Err(anyhow::anyhow!("git {operation} stderr was not piped"));
    };
    let stdout_reader = tokio::spawn(drain_git_stream(
        stdout,
        if operation == "ls_remote" {
            LS_REMOTE_STDOUT_CAPTURE_LIMIT
        } else {
            GIT_STDOUT_CAPTURE_LIMIT
        },
        started,
        activity.clone(),
        true,
    ));
    let stderr_reader = tokio::spawn(drain_git_stream(
        stderr,
        GIT_STDERR_CAPTURE_LIMIT,
        started,
        activity.clone(),
        false,
    ));

    let first_log = tokio::time::Instant::now() + GIT_LONG_RUNNING_AFTER;
    let mut long_running = tokio::time::interval_at(first_log, GIT_LONG_RUNNING_REPEAT);
    let mut inactivity_check =
        tokio::time::interval(policy.inactivity_limit.min(Duration::from_secs(1)));
    inactivity_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut stalled = false;
    let status = loop {
        tokio::select! {
            status = child.wait() => match status {
                Ok(status) => {
                    // A normal Git exit means it has joined its helpers. Do
                    // not retain an armed PGID after reaping the leader: that
                    // identity could subsequently be reused.
                    process_group.disarm();
                    break status;
                }
                Err(error) => {
                    metric.finish(false);
                    return Err(error.into());
                }
            },
            _ = long_running.tick() => {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                let last_millis = activity.last_millis.load(Ordering::Relaxed);
                tracing::warn!(
                    domain = %domain,
                    operation,
                    role,
                    elapsed_secs = elapsed_ms / 1000,
                    quiet_secs = elapsed_ms.saturating_sub(last_millis) / 1000,
                    stdout_bytes = activity.stdout_bytes.load(Ordering::Relaxed),
                    stderr_bytes = activity.stderr_bytes.load(Ordering::Relaxed),
                    "Outbound purgatory Git subprocess remains active"
                );
            }
            _ = inactivity_check.tick() => {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                let last_millis = activity.last_millis.load(Ordering::Relaxed);
                if Duration::from_millis(elapsed_ms.saturating_sub(last_millis))
                    < policy.inactivity_limit
                {
                    continue;
                }
                stalled = true;
                tracing::warn!(
                    domain = %domain,
                    operation,
                    role,
                    elapsed_secs = elapsed_ms / 1000,
                    quiet_secs = elapsed_ms.saturating_sub(last_millis) / 1000,
                    stdout_bytes = activity.stdout_bytes.load(Ordering::Relaxed),
                    stderr_bytes = activity.stderr_bytes.load(Ordering::Relaxed),
                    "Terminating inactive outbound purgatory Git process group"
                );
                process_group.signal(libc::SIGTERM)?;
                // Keep the unreaped leader anchoring the PGID throughout the
                // grace period. This avoids signalling a reused group id and
                // still gives every helper a bounded chance to exit cleanly.
                tokio::time::sleep(policy.termination_grace).await;
                tracing::warn!(
                    domain = %domain,
                    operation,
                    role,
                    "Completing inactive outbound purgatory Git process-group cleanup"
                );
                process_group.signal(libc::SIGKILL)?;
                let status = child.wait().await?;
                process_group.disarm();
                break status;
            }
        }
    };
    let stdout = match stdout_reader.await {
        Ok(Ok(stdout)) => stdout,
        Ok(Err(error)) => {
            metric.finish(false);
            return Err(error.into());
        }
        Err(error) => {
            metric.finish(false);
            return Err(error.into());
        }
    };
    let stderr = match stderr_reader.await {
        Ok(Ok(stderr)) => stderr,
        Ok(Err(error)) => {
            metric.finish(false);
            return Err(error.into());
        }
        Err(error) => {
            metric.finish(false);
            return Err(error.into());
        }
    };
    let stdout_bytes = activity.stdout_bytes.load(Ordering::Relaxed);
    let stderr_bytes = activity.stderr_bytes.load(Ordering::Relaxed);
    crate::metrics::record_purgatory_git_subprocess_output(operation, role, "stdout", stdout_bytes);
    crate::metrics::record_purgatory_git_subprocess_output(operation, role, "stderr", stderr_bytes);
    if stalled {
        metric.finish_with_outcome("stalled");
    } else if !status.success() && is_rate_limit_error(&String::from_utf8_lossy(&stderr)) {
        metric.finish_with_outcome("rate_limited");
    } else {
        metric.finish(status.success());
    }
    let stdout_truncated = stdout_bytes > stdout.len() as u64;
    let stderr_truncated = stderr_bytes > stderr.len() as u64;
    Ok(ObservedGitOutput {
        status,
        stdout,
        stderr,
        stdout_bytes,
        stderr_bytes,
        stdout_truncated,
        stderr_truncated,
    })
}

fn signal_process_group(pid: u32, signal: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `pid` is the live child id returned by Tokio, and the child was
    // placed into a process group whose id equals that pid before spawn.
    let result = unsafe { libc::kill(-(pid as libc::pid_t), signal) };
    if result == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        // The group may exit between the inactivity check and the signal.
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }
}

/// Parse `git ls-remote` output into the set of advertised object ids.
///
/// Each line has the form `<oid>\t<refname>`; peeled tag lines
/// (`refs/tags/x^{}`) are included since their OIDs are fetchable too.
fn parse_advertised_oids(stdout: &str) -> HashSet<String> {
    stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|oid| oid.len() == 40 && oid.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|oid| oid.to_string())
        .collect()
}

/// Whether a git fetch failure means the remote simply does not have (or
/// will not serve) the requested object — an expected per-OID outcome, not
/// a remote malfunction.
fn is_object_missing_error(stderr: &str) -> bool {
    // Server-side rejection of an unknown want, relayed by the client as
    // "fatal: remote error: upload-pack: not our ref <oid>".
    stderr.contains("not our ref")
        // Client-side refusal when the server does not advertise the
        // object and does not allow unadvertised wants (protocol v0).
        || stderr.contains("Server does not allow request for unadvertised object")
}

/// Integrity repair starts from a repository whose refs may name objects that
/// are already missing. Normal fetch negotiation walks those refs as local
/// "have" tips, which can make Git request no pack and then fail its own
/// connectivity check. Repair fetches therefore advertise no local haves and
/// ask the source for the complete requested object closure.
fn fetch_negotiation_algorithm(role: GitFetchRole) -> Option<&'static str> {
    (role == GitFetchRole::Integrity).then_some("noop")
}

/// Record a remote failure with the naughty list tracker (only error
/// categories the tracker classifies as persistent are recorded).
fn record_remote_failure(
    naughty_list: &NaughtyListTracker,
    url: &str,
    stderr: &str,
    operation: &str,
) {
    let Some(domain) = extract_domain(url) else {
        return;
    };
    let Some(category) = NaughtyListTracker::classify_error(stderr) else {
        return;
    };
    let is_new = naughty_list.record(&domain, category, stderr.to_string());

    if is_new {
        tracing::warn!(
            domain = %domain,
            category = %category,
            operation = %operation,
            error = %stderr,
            "Git remote domain added to naughty list"
        );
    } else {
        debug!(
            domain = %domain,
            category = %category,
            operation = %operation,
            error = %stderr,
            "Git remote operation failed (domain on naughty list)"
        );
    }
}

#[async_trait]
impl SyncContext for RealSyncContext {
    fn collect_pr_clone_urls(&self, identifier: &str) -> HashSet<String> {
        let mut urls = HashSet::new();

        for entry in self.purgatory.find_prs_for_identifier(identifier) {
            if let Some(ref event) = entry.event {
                for tag in event.tags.iter() {
                    let tag_vec = tag.clone().to_vec();
                    if tag_vec.len() >= 2 && tag_vec[0] == "clone" {
                        // Clone tags can have multiple URLs: ["clone", "url1", "url2", ...]
                        urls.extend(tag_vec[1..].iter().cloned());
                    }
                }
            }
        }

        debug!(
            identifier = %identifier,
            pr_clone_urls_count = urls.len(),
            "Collected clone URLs from PR events in purgatory"
        );

        urls
    }

    async fn fetch_repository_data_with_purgatory(
        &self,
        identifier: &str,
    ) -> Result<RepositoryData> {
        // Use the purgatory-aware variant so that clone URLs from announcements still
        // in purgatory (not yet promoted) are available. Without this, the sync loop
        // would find no URLs to fetch from and the announcement could never be promoted
        // (circular deadlock: can't promote without git data, can't get git data without URLs).
        crate::git::authorization::fetch_repository_data_with_purgatory(
            &self.database,
            &self.purgatory,
            identifier,
        )
        .await
    }

    fn collect_needed_oids(&self, identifier: &str) -> HashSet<String> {
        let mut needed_oids = HashSet::new();

        // Collect OIDs from state events in purgatory
        for entry in self.purgatory.find_state(identifier) {
            // Parse state event to extract branch/tag commits
            if let Ok(state) = RepositoryState::from_event(entry.event.clone()) {
                for branch in &state.branches {
                    // Skip symbolic refs (e.g., "ref: refs/heads/main")
                    if !branch.commit.starts_with("ref: ") {
                        needed_oids.insert(branch.commit.clone());
                    }
                }
                for tag in &state.tags {
                    if !tag.commit.starts_with("ref: ") {
                        needed_oids.insert(tag.commit.clone());
                    }
                }
            }
        }

        // Collect OIDs from PR events in purgatory
        for entry in self.purgatory.find_prs_for_identifier(identifier) {
            // PR events have a commit field (from c-tag)
            if !entry.commit.is_empty() {
                needed_oids.insert(entry.commit.clone());
            }
        }

        debug!(
            identifier = %identifier,
            needed_oids_count = needed_oids.len(),
            "Collected needed OIDs from purgatory"
        );

        needed_oids
    }

    fn oid_exists(&self, repo_path: &Path, oid: &str) -> bool {
        crate::git::oid_exists(repo_path, oid)
    }

    async fn fetch_oids_with_role(
        &self,
        repo_path: &Path,
        url: &str,
        oids: &[String],
        role: GitFetchRole,
    ) -> Result<Vec<String>> {
        if oids.is_empty() {
            return Ok(vec![]);
        }

        // Filter to only OIDs that don't already exist locally
        let missing: Vec<&String> = oids
            .iter()
            .filter(|oid| !self.oid_exists(repo_path, oid))
            .collect();

        if missing.is_empty() {
            debug!(
                url = %url,
                "All requested OIDs already exist locally"
            );
            return Ok(oids.to_vec());
        }

        debug!(
            url = %url,
            missing_count = missing.len(),
            "Fetching OIDs from remote server"
        );

        // Final authorization immediately before the outbound fetch. Clone
        // URLs come from untrusted announcement and PR events, so this is the
        // gate that keeps them off loopback/private/local targets. DNS is
        // vetted here and the answers pinned onto the git subprocess below.
        let resolved = match self
            .outbound_policy
            .authorize_resolved(OutboundTargetKind::EventGit, url)
            .await
        {
            Ok(resolved) => resolved,
            Err(reason) => {
                tracing::warn!(
                    url = %url,
                    reason = %reason,
                    "Rejecting event-directed git fetch target"
                );
                return Err(anyhow::anyhow!(
                    "outbound target policy rejected git fetch target {}: {}",
                    url,
                    reason
                ));
            }
        };
        let resolve_pin = resolve_pin_entry(&resolved);

        let storage = LocalGitStorage::new(&self.git_data_path);
        let family_key = family_key_for_view(repo_path, &self.git_data_path);
        let family_lease = match family_key.as_ref() {
            Some(key) if storage.is_thin_view(key, repo_path) => Some(
                storage
                    .write_lease(key)
                    .await
                    .map_err(|error| anyhow::anyhow!("open family for git fetch: {error}"))?,
            ),
            _ => None,
        };
        let family_objects = family_lease
            .as_ref()
            .map(|lease| lease.family_objects_path.as_path());

        let repo_path = repo_path.to_path_buf();
        let url = url.to_string();
        let domain = extract_domain(&url).unwrap_or_else(|| "unknown".to_string());
        let missing_oids: Vec<String> = missing.into_iter().cloned().collect();
        let naughty_list = self.git_naughty_list.clone();
        let miss_memo = self.miss_memo.clone();

        // GRASP-08: fetches from a confirmed private peer carry the
        // repository-root credential. The registry key is host:port derived
        // from the URL itself (`extract_domain` drops the port, which would
        // collide loopback services). Headers are minted fresh before each
        // subprocess: the peer's 60-second validity window must not expire
        // mid-pass on a long batch fetch.
        let credential_signer = self.credential_keys.clone().filter(|_| {
            self.grasp08_peers.as_ref().is_some_and(|peers| {
                crate::private::Grasp08Peers::peer_key(&url).is_some_and(|key| peers.contains(&key))
            })
        });
        let repository_root = credential_signer
            .as_ref()
            .and_then(|_| crate::private::nip98::repository_root_from_fetch_url(&url));
        let mut credential_warning_logged = false;
        let credential_url = url.clone();
        let mut fresh_auth_header = move || -> Option<String> {
            let keys = credential_signer.as_ref()?;
            let root = repository_root.as_deref()?;
            match crate::private::nip98::repository_credential_header(keys, root) {
                Ok(header) => Some(header),
                Err(error) => {
                    if !credential_warning_logged {
                        credential_warning_logged = true;
                        tracing::warn!(
                            url = %credential_url,
                            error = %error,
                            "Failed to sign GRASP-08 credential; fetching unauthenticated"
                        );
                    }
                    None
                }
            }
        };

        // Phase 1: compare the remote's advertised refs against our
        // needs. Most needed OIDs are ref tips declared by state events
        // (PR tips appear under `refs/nostr/<event-id>`), so the
        // advertisement tells us up front which OIDs the remote can
        // serve — instead of discovering each missing one through a
        // failed "not our ref" upload-pack round trip.
        let mut reservation = if role == GitFetchRole::Integrity {
            Some(self.git_budget.reserve_pair(&domain).map_err(|reason| {
                crate::metrics::record_purgatory_git_deferred("ls_remote", reason);
                GitBudgetDeferred {
                    retry_after: self.git_budget.retry_after(&domain),
                    reason,
                }
            })?)
        } else {
            None
        };
        let ls_remote_args = vec!["ls-remote".to_string(), url.clone()];
        let advertised = match run_budgeted_git_command(
            &self.git_budget,
            reservation.as_mut(),
            hardened_git_command(
                &repo_path,
                resolve_pin.as_deref(),
                fresh_auth_header().as_deref(),
                None,
                None,
                &ls_remote_args,
            ),
            &domain,
            "ls_remote",
            role,
        )
        .await
        {
            Ok(result) if result.status.success() => {
                if result.stdout_truncated {
                    tracing::warn!(
                        url = %url,
                        captured_bytes = result.stdout.len(),
                        total_bytes = result.stdout_bytes,
                        "Git advertisement exceeded capture bound; using residual fetch path"
                    );
                    HashSet::new()
                } else {
                    parse_advertised_oids(&String::from_utf8_lossy(&result.stdout))
                }
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                record_remote_failure(&naughty_list, &url, &stderr, "ls-remote");
                return Err(anyhow::anyhow!(
                    "git ls-remote failed for {}: {}",
                    url,
                    stderr
                ));
            }
            Err(e) => return Err(e.context(format!("git ls-remote command error for {url}"))),
        };
        let advert_fingerprint = advertised_oids_fingerprint(&advertised);
        let memoized_missing = {
            let mut memo = miss_memo
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            memoized_missing_for_url(&mut memo, &url, advert_fingerprint, Instant::now())
        };

        // Phase 2: batch-fetch the needed OIDs the remote actually
        // advertises. Advertised OIDs are always valid wants, so
        // "not our ref" cannot occur here and one batch cannot be
        // failed by an OID the remote never had.
        let advertised_tips: Vec<String> = missing_oids
            .iter()
            .filter(|oid| advertised.contains(*oid))
            .cloned()
            .collect();
        if !advertised_tips.is_empty() {
            let mut args = vec![
                "fetch".to_string(),
                "--no-write-fetch-head".to_string(),
                "--no-auto-maintenance".to_string(),
                "--progress".to_string(),
                url.clone(),
            ];
            args.extend(advertised_tips.iter().cloned());

            match run_budgeted_git_command(
                &self.git_budget,
                reservation.as_mut(),
                hardened_git_command(
                    &repo_path,
                    resolve_pin.as_deref(),
                    fresh_auth_header().as_deref(),
                    family_objects,
                    fetch_negotiation_algorithm(role),
                    &args,
                ),
                &domain,
                "fetch_batch",
                role,
            )
            .await
            {
                Ok(result) if result.status.success() => {}
                Ok(result) => {
                    if result.stderr_truncated {
                        debug!(url = %url, total_bytes = result.stderr_bytes, "Git fetch stderr was truncated");
                    }
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    if is_object_missing_error(&stderr) {
                        // The remote's refs changed between ls-remote and
                        // fetch. Fall through: every still-missing OID is
                        // retried individually below.
                        debug!(
                            url = %url,
                            error = %stderr,
                            "Advertised tip vanished between ls-remote and \
                             fetch - falling back to per-OID fetches"
                        );
                    } else {
                        record_remote_failure(&naughty_list, &url, &stderr, "fetch");
                        return Err(anyhow::anyhow!("git fetch failed for {}: {}", url, stderr));
                    }
                }
                Err(e) => return Err(e.context(format!("git fetch command error for {url}"))),
            }
        }

        // Phase 3: request residual OIDs that were not advertised and
        // did not arrive as ancestors of the fetched tips, one at a
        // time. Arbitrary-SHA1 wants may still be refused by some
        // servers, so a per-OID failure must cost exactly one small
        // round trip and must not abort the rest.
        let mut deferred = None;
        let mut residual_attempted = 0usize;
        let mut residual_missing = 0usize;
        let mut residual_skipped = 0usize;
        for oid in &missing_oids {
            if crate::git::oid_exists(&repo_path, oid) {
                continue;
            }
            if memoized_missing.contains(oid) {
                residual_skipped += 1;
                continue;
            }
            if role != GitFetchRole::Integrity && residual_attempted >= SPECULATIVE_PER_PASS {
                crate::metrics::record_purgatory_git_deferred("fetch_residual", "pass_budget");
                break;
            }

            let args = vec![
                "fetch".to_string(),
                "--no-write-fetch-head".to_string(),
                "--no-auto-maintenance".to_string(),
                "--progress".to_string(),
                url.clone(),
                oid.clone(),
            ];
            let result = run_budgeted_git_command(
                &self.git_budget,
                reservation.as_mut(),
                hardened_git_command(
                    &repo_path,
                    resolve_pin.as_deref(),
                    fresh_auth_header().as_deref(),
                    family_objects,
                    fetch_negotiation_algorithm(role),
                    &args,
                ),
                &domain,
                "fetch_residual",
                role,
            )
            .await;
            if result
                .as_ref()
                .is_err_and(|error| error.is::<GitBudgetDeferred>())
            {
                deferred = result.err();
                break;
            }
            residual_attempted += 1;
            match result {
                Ok(result) if result.status.success() => {}
                Ok(result) => {
                    if result.stderr_truncated {
                        debug!(url = %url, oid = %oid, total_bytes = result.stderr_bytes, "Git fetch stderr was truncated");
                    }
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    if is_object_missing_error(&stderr) {
                        residual_missing += 1;
                        let mut memo = miss_memo
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if let Some(entry) = memo.get_mut(&url) {
                            if entry.advert_fingerprint == advert_fingerprint {
                                entry.missing.insert(oid.clone());
                                entry.last_touched = Instant::now();
                            }
                        }
                        debug!(
                            url = %url,
                            oid = %oid,
                            "OID not available on remote"
                        );
                    } else {
                        // A genuine remote failure: record it and stop
                        // hammering the server, but keep what the batch
                        // already fetched.
                        record_remote_failure(&naughty_list, &url, &stderr, "fetch");
                        break;
                    }
                }
                Err(e) => {
                    debug!(url = %url, oid = %oid, error = %e, "git fetch command error");
                    break;
                }
            }
        }

        let fetched: Vec<String> = missing_oids
            .iter()
            .filter(|oid| crate::git::oid_exists(&repo_path, oid))
            .cloned()
            .collect();

        if let Some(key) = family_key.as_ref().filter(|_| family_lease.is_some()) {
            for oid in &fetched {
                if let Err(error) = storage.retain_tip(key, "purgatory-fetch", oid) {
                    tracing::warn!(
                        identifier = %key.identifier,
                        %oid,
                        %error,
                        "Failed to retain proactively fetched family tip"
                    );
                }
                if let Err(error) = storage.advertise_base_tip(key, "purgatory-fetch", oid) {
                    tracing::warn!(
                        identifier = %key.identifier,
                        %oid,
                        %error,
                        "Failed to advertise proactively fetched family tip"
                    );
                }
            }
        }

        // One summary line per outbound fetch pass: this is the
        // client-side visibility the drop-one-and-retry loop lacked
        // (it logged only at debug level, so a relay crawling a remote
        // was invisible in its own production logs).
        tracing::info!(
            url = %url,
            needed = missing_oids.len(),
            advertised_tips = advertised_tips.len(),
            residual_attempted = residual_attempted,
            residual_missing = residual_missing,
            residual_skipped = residual_skipped,
            fetched = fetched.len(),
            "Purgatory git fetch pass complete"
        );
        crate::metrics::record_purgatory_git_fetch_pass(
            advertised_tips.len(),
            residual_attempted,
            residual_missing,
            residual_skipped,
            fetched.len(),
        );

        if role == GitFetchRole::Integrity {
            if let Some(error) = deferred {
                return Err(error);
            }
        }
        Ok(fetched)
    }

    async fn process_newly_available_git_data(
        &self,
        source_repo_path: &Path,
        new_oids: &HashSet<String>,
    ) -> Result<ProcessResult> {
        // Delegate to the unified function from git::sync.
        // Pass configured deletion service for promotion-time recovery hooks.
        // Keep git-push reprocessing disabled: the purgatory sync path already
        // handles hot-cache re-processing via SyncManager::process_event_static.
        let promotion_hooks = self
            .write_policy
            .as_ref()
            .map(NostrPurgatoryPromotionHooks::recovery_only);
        let promotion_hooks = promotion_hooks
            .as_ref()
            .map(|hooks| hooks as &dyn PurgatoryPromotionHooks);

        let result = crate::git::sync::process_newly_available_git_data(
            source_repo_path,
            new_oids,
            &self.database,
            self.local_relay.as_ref(),
            &self.purgatory,
            &self.git_data_path,
            promotion_hooks,
        )
        .await?;

        // Convert from git::sync::ProcessResult to our ProcessResult
        Ok(ProcessResult {
            states_released: result.states_released,
            prs_released: result.prs_released,
            repos_synced: result.repos_synced,
            refs_created: result.refs_created,
            refs_updated: result.refs_updated,
            refs_deleted: result.refs_deleted,
            errors: result.errors,
        })
    }

    fn has_pending_events(&self, identifier: &str) -> bool {
        self.purgatory.has_pending_events(identifier)
    }

    fn find_target_repo(&self, db_repo_data: &RepositoryData) -> Option<PathBuf> {
        // Find the first owner repository that exists on disk
        for announcement in &db_repo_data.announcements {
            let repo_path = self.git_data_path.join(announcement.repo_path());
            if repo_path.exists() {
                debug!(
                    repo_path = %repo_path.display(),
                    "Found existing repository for sync target"
                );
                return Some(repo_path);
            }
        }

        debug!("No existing repository found for sync target");
        None
    }

    fn our_domain(&self) -> Option<&str> {
        self.our_domain_value.as_deref()
    }
}

fn family_key_for_view(repo_path: &Path, git_data_path: &Path) -> Option<FamilyKey> {
    let identifier = crate::git::sync::extract_identifier_from_repo_path(repo_path, git_data_path)?;
    let object_format = ObjectFormat::detect(repo_path).ok()?;
    FamilyKey::new(object_format, identifier).ok()
}

#[cfg(test)]
mod fetch_helper_tests {
    use super::*;

    #[test]
    fn family_key_for_view_preserves_the_repository_object_format() {
        let temp = tempfile::tempdir().unwrap();
        let git_data_path = temp.path().join("git");
        let storage = LocalGitStorage::new(&git_data_path);
        let expected = FamilyKey::new(ObjectFormat::Sha256, "shared").unwrap();
        let view = git_data_path.join("owner").join("shared.git");
        storage.create_thin_view(&expected, &view).unwrap();

        assert_eq!(family_key_for_view(&view, &git_data_path), Some(expected));
    }

    /// Hermetic git for these tests, immune to ambient git configuration
    /// such as hooks, signing, and templates.
    fn fixture_git() -> std::process::Command {
        grasp_audit::git_command()
    }

    /// True once the descendant with this pid no longer runs. A process-group
    /// kill leaves the orphaned descendant as an unreaped zombie whenever no
    /// reaping ancestor is present (CI containers lack a reaping PID 1), and
    /// `kill(pid, 0)` still succeeds for zombies, so an unreaped zombie must
    /// also count as terminated.
    fn descendant_terminated(pid: i32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            // The state field follows the parenthesised, possibly
            // space-containing command name.
            Ok(stat) => match stat.rsplit_once(") ") {
                Some((_, rest)) => rest.starts_with('Z'),
                None => false,
            },
        }
    }

    fn create_source_repo(root: &Path, name: &str, contents: &str) -> (PathBuf, String) {
        let path = root.join(name);
        assert!(fixture_git()
            .args(["init", "--quiet", path.to_str().unwrap()])
            .status()
            .unwrap()
            .success());
        assert!(fixture_git()
            .current_dir(&path)
            .args(["config", "user.name", "Test"])
            .status()
            .unwrap()
            .success());
        assert!(fixture_git()
            .current_dir(&path)
            .args(["config", "user.email", "test@example.com"])
            .status()
            .unwrap()
            .success());
        std::fs::write(path.join("payload"), contents).unwrap();
        assert!(fixture_git()
            .current_dir(&path)
            .args(["add", "payload"])
            .status()
            .unwrap()
            .success());
        assert!(fixture_git()
            .current_dir(&path)
            .args(["commit", "--quiet", "-m", "fixture"])
            .status()
            .unwrap()
            .success());
        let oid = fixture_git()
            .current_dir(&path)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        (
            path,
            String::from_utf8(oid.stdout).unwrap().trim().to_string(),
        )
    }

    #[tokio::test]
    async fn command_budget_covers_primary_hedge_and_integrity_and_observes_429() {
        fn command(script: &str) -> Command {
            let mut command = Command::new("sh");
            command
                .args(["-c", script])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            command
        }
        let budget = GitCommandBudget::default();
        for index in 0..60 {
            let role = [
                GitFetchRole::Primary,
                GitFetchRole::Hedge,
                GitFetchRole::Integrity,
            ][index % 3];
            let result = run_budgeted_git_command(
                &budget,
                None,
                command("exit 0"),
                "shared",
                "ls_remote",
                role,
            )
            .await
            .unwrap();
            assert!(result.status.success());
        }
        let denied = run_budgeted_git_command(
            &budget,
            None,
            command("exit 99"),
            "shared",
            "fetch_batch",
            GitFetchRole::Integrity,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(
            denied.downcast_ref::<GitBudgetDeferred>().unwrap().reason,
            "command_budget"
        );
        let rejected = run_budgeted_git_command(
            &budget,
            None,
            command("echo 'fatal: The requested URL returned error: 429' >&2; exit 1"),
            "limited",
            "fetch_batch",
            GitFetchRole::Primary,
        )
        .await
        .unwrap();
        assert!(!rejected.status.success());
        let cooled = run_budgeted_git_command(
            &budget,
            None,
            command("exit 99"),
            "limited",
            "ls_remote",
            GitFetchRole::Hedge,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(
            cooled.downcast_ref::<GitBudgetDeferred>().unwrap().reason,
            "remote_cooldown"
        );
        assert!(run_budgeted_git_command(
            &budget,
            None,
            command("exit 0"),
            "unrelated",
            "ls_remote",
            GitFetchRole::Primary
        )
        .await
        .unwrap()
        .status
        .success());
    }

    #[tokio::test]
    async fn stream_drain_bounds_capture_but_counts_all_activity() {
        let (mut writer, reader) = tokio::io::duplex(256);
        let activity = Arc::new(GitActivity::default());
        let reader_activity = activity.clone();
        let drain = tokio::spawn(async move {
            drain_git_stream(reader, 10, Instant::now(), reader_activity, true).await
        });
        tokio::io::AsyncWriteExt::write_all(&mut writer, &[b'x'; 100])
            .await
            .unwrap();
        drop(writer);
        let captured = drain.await.unwrap().unwrap();
        assert_eq!(captured, vec![b'x'; 10]);
        assert_eq!(activity.stdout_bytes.load(Ordering::Relaxed), 100);
        assert!(activity.last_millis.load(Ordering::Relaxed) <= 1_000);
    }

    #[tokio::test]
    async fn observed_runner_streams_both_outputs_and_preserves_exit_status() {
        let mut command = Command::new("sh");
        command
            .args(["-c", "printf stdout; printf stderr >&2; exit 7"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let output =
            run_observed_git_command(command, "test.example", "fetch_batch", GitFetchRole::Hedge)
                .await
                .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
        assert_eq!(output.stdout_bytes, 6);
        assert_eq!(output.stderr_bytes, 6);
    }

    #[tokio::test]
    async fn continuing_output_prevents_inactivity_termination() {
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "for value in 1 2 3 4 5 6; do printf x; sleep 0.02; done",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let output = tokio::time::timeout(
            Duration::from_secs(2),
            run_observed_git_command_with_policy(
                command,
                "test.example",
                "fetch_batch",
                GitFetchRole::Primary,
                GitProcessPolicy {
                    inactivity_limit: Duration::from_millis(500),
                    termination_grace: Duration::from_millis(50),
                },
            ),
        )
        .await
        .expect("active fixture has a bounded completion")
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"xxxxxx");
    }

    #[tokio::test]
    async fn inactivity_terminates_the_whole_process_group() {
        let temp = tempfile::tempdir().unwrap();
        let pid_file = temp.path().join("descendant.pid");
        let script = format!(
            "trap '' TERM; sleep 30 & child=$!; printf %s $child > {}; wait",
            pid_file.display()
        );
        let mut command = Command::new("sh");
        command
            .args(["-c", &script])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let wait_for_pid = async {
            loop {
                if let Ok(pid) = std::fs::read_to_string(&pid_file) {
                    if !pid.is_empty() {
                        break pid;
                    }
                }
                tokio::task::yield_now().await;
            }
        };
        let run = run_observed_git_command_with_policy(
            command,
            "test.example",
            "fetch_batch",
            GitFetchRole::Primary,
            // SovTech seam: on a slow CI runner a 50 ms limit killed the group
            // before `sh` had recorded its descendant, so the pid never came
            // and the bound below expired instead of the assertion running.
            GitProcessPolicy {
                inactivity_limit: Duration::from_secs(1),
                termination_grace: Duration::from_millis(50),
            },
        );
        let (pid, output) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(wait_for_pid, run)
        })
        .await
        .expect("stalled fixture has bounded recovery");
        let output = output.unwrap();
        assert!(!output.status.success());

        let pid: i32 = pid.parse().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            if descendant_terminated(pid) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "descendant survived"
            );
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn cancelling_observed_command_reaps_descendants_before_follow_up_work() {
        let temp = tempfile::tempdir().unwrap();
        let pid_file = temp.path().join("cancelled-descendant.pid");
        let script = format!(
            "trap '' TERM; sleep 30 & child=$!; printf %s $child > {}; wait",
            pid_file.display()
        );
        let mut command = Command::new("sh");
        command
            .args(["-c", &script])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let task = tokio::spawn(run_observed_git_command_with_policy(
            command,
            "test.example",
            "fetch_batch",
            GitFetchRole::Primary,
            GitProcessPolicy {
                inactivity_limit: Duration::from_secs(30),
                termination_grace: Duration::from_millis(50),
            },
        ));

        let pid = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(pid) = std::fs::read_to_string(&pid_file) {
                    if !pid.is_empty() {
                        break pid.parse::<i32>().unwrap();
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fixture descendant should become observable");
        task.abort();
        let _ = task.await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if descendant_terminated(pid) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled command descendant should be reaped");

        let mut follow_up = Command::new("sh");
        follow_up
            .args(["-c", "printf ready"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let output = run_observed_git_command(
            follow_up,
            "test.example",
            "fetch_batch",
            GitFetchRole::Primary,
        )
        .await
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"ready");
    }

    #[tokio::test]
    async fn concurrent_object_only_fetches_leave_shared_bare_repo_consistent() {
        let temp = tempfile::tempdir().unwrap();
        let (first_source, first_oid) = create_source_repo(temp.path(), "first", "first");
        let (second_source, second_oid) = create_source_repo(temp.path(), "second", "second");
        let target = temp.path().join("target.git");
        assert!(fixture_git()
            .args(["init", "--bare", "--quiet", target.to_str().unwrap()])
            .status()
            .unwrap()
            .success());

        let fetch = |source: PathBuf, oid: String, role| {
            let mut command = Command::from(fixture_git());
            command
                .current_dir(&target)
                .args(["fetch", "--no-write-fetch-head", "--no-auto-maintenance"])
                .arg(source)
                .arg(oid)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            run_observed_git_command(command, "local.test", "fetch_batch", role)
        };
        let (first, second) = tokio::join!(
            fetch(first_source, first_oid.clone(), GitFetchRole::Primary),
            fetch(second_source, second_oid.clone(), GitFetchRole::Hedge)
        );
        assert!(first.unwrap().status.success());
        assert!(second.unwrap().status.success());
        assert!(!target.join("FETCH_HEAD").exists());
        let refs = fixture_git()
            .current_dir(&target)
            .args(["for-each-ref", "--format=%(refname)"])
            .output()
            .unwrap();
        assert!(refs.status.success());
        assert!(refs.stdout.is_empty(), "object fetch must not update refs");

        for oid in [first_oid, second_oid] {
            assert!(fixture_git()
                .current_dir(&target)
                .args(["cat-file", "-e", &format!("{oid}^{{commit}}")])
                .status()
                .unwrap()
                .success());
        }
        let fsck = fixture_git()
            .current_dir(&target)
            .args(["fsck", "--no-dangling"])
            .output()
            .unwrap();
        assert!(
            fsck.status.success(),
            "{}",
            String::from_utf8_lossy(&fsck.stderr)
        );
    }

    #[test]
    fn parse_advertised_oids_collects_ref_tips_and_peeled_tags() {
        let stdout = "6451bf9d83e64647ba714740e9a15e5327d28be1\tHEAD\n\
             6451bf9d83e64647ba714740e9a15e5327d28be1\trefs/heads/main\n\
             ace0a97f55e3b5343f312b1340717d34e2b4d2c6\trefs/tags/v1.0\n\
             beef000000000000000000000000000000000001\trefs/tags/v1.0^{}\n";
        let advertised = parse_advertised_oids(stdout);
        assert_eq!(advertised.len(), 3);
        assert!(advertised.contains("6451bf9d83e64647ba714740e9a15e5327d28be1"));
        assert!(advertised.contains("ace0a97f55e3b5343f312b1340717d34e2b4d2c6"));
        assert!(advertised.contains("beef000000000000000000000000000000000001"));
    }

    #[test]
    fn parse_advertised_oids_ignores_malformed_lines() {
        let stdout = "warning: something\nnot-an-oid\trefs/heads/x\n\n";
        assert!(parse_advertised_oids(stdout).is_empty());
    }

    #[test]
    fn object_missing_errors_are_recognised() {
        assert!(is_object_missing_error(
            "fatal: remote error: upload-pack: not our ref beef0000"
        ));
        assert!(is_object_missing_error(
            "error: Server does not allow request for unadvertised object beef0000"
        ));
        assert!(!is_object_missing_error(
            "fatal: unable to access 'https://x/': SSL certificate problem"
        ));
    }

    #[test]
    fn integrity_fetches_disable_local_have_negotiation() {
        assert_eq!(fetch_negotiation_algorithm(GitFetchRole::Primary), None);
        assert_eq!(fetch_negotiation_algorithm(GitFetchRole::Hedge), None);
        assert_eq!(
            fetch_negotiation_algorithm(GitFetchRole::Integrity),
            Some("noop")
        );
        assert_eq!(GitFetchRole::Integrity.as_str(), "integrity");
    }

    #[test]
    fn miss_memo_is_stable_order_independent_invalidated_and_bounded() {
        let first = HashSet::from(["b".to_string(), "a".to_string()]);
        let reordered = HashSet::from(["a".to_string(), "b".to_string()]);
        let changed = HashSet::from(["a".to_string(), "c".to_string()]);
        let first_fingerprint = advertised_oids_fingerprint(&first);
        assert_eq!(first_fingerprint, advertised_oids_fingerprint(&reordered));
        assert_ne!(first_fingerprint, advertised_oids_fingerprint(&changed));

        let now = Instant::now();
        let mut memo = HashMap::new();
        assert!(
            memoized_missing_for_url(&mut memo, "https://one", first_fingerprint, now).is_empty()
        );
        memo.get_mut("https://one")
            .unwrap()
            .missing
            .insert("missing".to_string());
        assert!(
            memoized_missing_for_url(&mut memo, "https://one", first_fingerprint, now)
                .contains("missing")
        );
        assert!(memoized_missing_for_url(
            &mut memo,
            "https://one",
            advertised_oids_fingerprint(&changed),
            now,
        )
        .is_empty());

        memo.get_mut("https://one").unwrap().last_touched = now - MISS_MEMO_TTL;
        memoized_missing_for_url(&mut memo, "https://two", first_fingerprint, now);
        assert!(!memo.contains_key("https://one"));

        for index in 0..=MISS_MEMO_MAX_URLS {
            memoized_missing_for_url(
                &mut memo,
                &format!("https://remote-{index}"),
                first_fingerprint,
                now,
            );
        }
        assert_eq!(memo.len(), MISS_MEMO_MAX_URLS);
    }
}

// =============================================================================
// Mock Implementation for Testing
// =============================================================================

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::RwLock;

    /// Mock context for testing sync logic without I/O.
    ///
    /// This mock allows tests to:
    /// - Configure repository data (URLs, announcements)
    /// - Specify which OIDs are needed
    /// - Configure which URLs provide which OIDs
    /// - Track fetch attempts for assertions
    /// - Control whether events are "pending"
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mock = MockSyncContext::new()
    ///     .with_urls(&["https://github.com/foo/bar.git", "https://gitlab.com/foo/bar.git"])
    ///     .with_needed_oids(&["abc123", "def456"])
    ///     .url_provides("https://github.com/foo/bar.git", &["abc123"]);
    ///
    /// // Use mock in tests...
    /// assert_eq!(mock.fetch_log(), vec!["https://github.com/foo/bar.git"]);
    /// ```
    pub struct MockSyncContext {
        /// Repository data to return from fetch_repository_data_with_purgatory
        repo_data: RwLock<Option<RepositoryData>>,

        /// Clone URLs available for the repository (from announcements)
        clone_urls: Vec<String>,

        /// Clone URLs from PR events in purgatory
        pr_clone_urls: HashSet<String>,

        /// OIDs still needed (decremented when "fetched")
        needed_oids: RwLock<HashSet<String>>,

        /// Which OIDs each URL can provide
        url_provides_oids: HashMap<String, HashSet<String>>,

        /// Track fetch attempts for assertions
        fetch_log: RwLock<Vec<String>>,

        /// Whether there are pending events
        has_pending: RwLock<bool>,

        /// Our domain (to exclude from clone URLs)
        our_domain: Option<String>,

        /// Path to return from find_target_repo
        target_repo_path: Option<PathBuf>,

        /// Whether fetch_oids should fail
        fetch_should_fail: RwLock<HashSet<String>>,

        /// Results from process_newly_available_git_data calls
        process_results: RwLock<Vec<ProcessResult>>,

        /// Deterministic fetch barriers used by coordinator tests.
        fetch_barriers: HashMap<String, Arc<tokio::sync::Semaphore>>,
        fetch_completion_barriers: HashMap<String, Arc<tokio::sync::Semaphore>>,
        urls_report_shared_objects: HashSet<String>,
        fetch_started: Arc<tokio::sync::Notify>,
        fetch_started_count: AtomicUsize,
    }

    impl Default for MockSyncContext {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockSyncContext {
        /// Create a new mock context with default settings.
        pub fn new() -> Self {
            Self {
                repo_data: RwLock::new(None),
                clone_urls: Vec::new(),
                pr_clone_urls: HashSet::new(),
                needed_oids: RwLock::new(HashSet::new()),
                url_provides_oids: HashMap::new(),
                fetch_log: RwLock::new(Vec::new()),
                has_pending: RwLock::new(true),
                our_domain: None,
                target_repo_path: Some(PathBuf::from("/tmp/test-repo")),
                fetch_should_fail: RwLock::new(HashSet::new()),
                process_results: RwLock::new(Vec::new()),
                fetch_barriers: HashMap::new(),
                fetch_completion_barriers: HashMap::new(),
                urls_report_shared_objects: HashSet::new(),
                fetch_started: Arc::new(tokio::sync::Notify::new()),
                fetch_started_count: AtomicUsize::new(0),
            }
        }

        /// Configure clone URLs for the repository (from announcements).
        pub fn with_urls(mut self, urls: &[&str]) -> Self {
            self.clone_urls = urls.iter().map(|s| s.to_string()).collect();
            self
        }

        /// Configure clone URLs from PR events in purgatory.
        pub fn with_pr_clone_urls(mut self, urls: &[&str]) -> Self {
            self.pr_clone_urls = urls.iter().map(|s| s.to_string()).collect();
            self
        }

        /// Configure OIDs that are still needed.
        pub fn with_needed_oids(self, oids: &[&str]) -> Self {
            *self.needed_oids.write().unwrap() = oids.iter().map(|s| s.to_string()).collect();
            self
        }

        /// Configure which OIDs a specific URL can provide.
        pub fn url_provides(mut self, url: &str, oids: &[&str]) -> Self {
            self.url_provides_oids.insert(
                url.to_string(),
                oids.iter().map(|s| s.to_string()).collect(),
            );
            self
        }

        /// Configure our domain (to be excluded from clone URLs).
        pub fn with_our_domain(mut self, domain: &str) -> Self {
            self.our_domain = Some(domain.to_string());
            self
        }

        /// Configure the target repo path.
        pub fn with_target_repo(mut self, path: &str) -> Self {
            self.target_repo_path = Some(PathBuf::from(path));
            self
        }

        /// Configure whether there are pending events.
        pub fn with_pending_events(self, has_pending: bool) -> Self {
            *self.has_pending.write().unwrap() = has_pending;
            self
        }

        /// Configure a URL to fail when fetched.
        pub fn url_should_fail(self, url: &str) -> Self {
            self.fetch_should_fail
                .write()
                .unwrap()
                .insert(url.to_string());
            self
        }

        /// Hold this URL's fetch until the test explicitly releases it.
        pub fn url_waits_for_release(mut self, url: &str) -> Self {
            self.fetch_barriers
                .insert(url.to_string(), Arc::new(tokio::sync::Semaphore::new(0)));
            self
        }

        /// Hold this URL after it has made its objects visible in the shared
        /// mock object database but before its fetch call returns.
        pub fn url_waits_after_fetch(mut self, url: &str) -> Self {
            self.fetch_completion_barriers
                .insert(url.to_string(), Arc::new(tokio::sync::Semaphore::new(0)));
            self
        }

        /// Model the real implementation's final shared-ODB scan: this URL
        /// reports requested objects installed by a concurrent command.
        pub fn url_reports_shared_objects(mut self, url: &str) -> Self {
            self.urls_report_shared_objects.insert(url.to_string());
            self
        }

        pub async fn wait_for_fetches(&self, count: usize) {
            while self.fetch_started_count.load(Ordering::SeqCst) < count {
                self.fetch_started.notified().await;
            }
        }

        pub fn release_fetch(&self, url: &str) {
            self.fetch_barriers
                .get(url)
                .or_else(|| self.fetch_completion_barriers.get(url))
                .expect("URL should have a configured fetch barrier")
                .add_permits(1);
        }

        /// Get the log of fetch attempts (URLs that were fetched from).
        pub fn fetch_log(&self) -> Vec<String> {
            self.fetch_log.read().unwrap().clone()
        }

        /// Clear the fetch log.
        pub fn clear_fetch_log(&self) {
            self.fetch_log.write().unwrap().clear();
        }

        /// Get the current set of needed OIDs.
        pub fn current_needed_oids(&self) -> HashSet<String> {
            self.needed_oids.read().unwrap().clone()
        }

        pub fn process_call_count(&self) -> usize {
            self.process_results.read().unwrap().len()
        }

        /// Set whether there are pending events (can be called during test).
        pub fn set_pending_events(&self, has_pending: bool) {
            *self.has_pending.write().unwrap() = has_pending;
        }

        /// Mark specific OIDs as no longer needed (simulates successful fetch).
        pub fn mark_oids_fetched(&self, oids: &[&str]) {
            let mut needed = self.needed_oids.write().unwrap();
            for oid in oids {
                needed.remove(*oid);
            }
        }
    }

    #[async_trait]
    impl SyncContext for MockSyncContext {
        fn collect_pr_clone_urls(&self, _identifier: &str) -> HashSet<String> {
            self.pr_clone_urls.clone()
        }

        async fn fetch_repository_data_with_purgatory(
            &self,
            _identifier: &str,
        ) -> Result<RepositoryData> {
            // Return stored repo_data or create a minimal one with clone URLs
            if let Some(data) = self.repo_data.read().unwrap().as_ref() {
                // Clone the data - this is a test mock so efficiency isn't critical
                Ok(RepositoryData {
                    announcements: data.announcements.clone(),
                    states: data.states.clone(),
                })
            } else {
                // Create minimal repo data with just clone URLs
                // In real tests, you'd set up proper announcements
                use crate::nostr::events::RepositoryAnnouncement;
                use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind};

                let keys = Keys::generate();
                let mut announcements = Vec::new();

                if !self.clone_urls.is_empty() {
                    // Create a minimal announcement with the clone URLs
                    let mut tags = vec![nostr_sdk::prelude::Tag::custom(
                        "d",
                        vec!["test-repo".to_string()],
                    )];

                    // Create a single clone tag with multiple values (NIP-34 format)
                    tags.push(nostr_sdk::prelude::Tag::custom(
                        "clone",
                        self.clone_urls.to_vec(),
                    ));

                    let event = EventBuilder::new(Kind::from(30617), "")
                        .tags(tags)
                        .finalize(&keys)
                        .unwrap();

                    if let Ok(ann) = RepositoryAnnouncement::from_event(event) {
                        announcements.push(ann);
                    }
                }

                Ok(RepositoryData {
                    announcements,
                    states: Vec::new(),
                })
            }
        }

        fn collect_needed_oids(&self, _identifier: &str) -> HashSet<String> {
            self.needed_oids.read().unwrap().clone()
        }

        fn oid_exists(&self, _repo_path: &Path, oid: &str) -> bool {
            // OID exists if it's NOT in the needed set
            !self.needed_oids.read().unwrap().contains(oid)
        }

        async fn fetch_oids_with_role(
            &self,
            _repo_path: &Path,
            url: &str,
            oids: &[String],
            _role: GitFetchRole,
        ) -> Result<Vec<String>> {
            // Log the fetch attempt
            self.fetch_log.write().unwrap().push(url.to_string());
            self.fetch_started_count.fetch_add(1, Ordering::SeqCst);
            self.fetch_started.notify_waiters();
            if let Some(barrier) = self.fetch_barriers.get(url) {
                barrier
                    .acquire()
                    .await
                    .expect("mock fetch barrier should remain open")
                    .forget();
            }

            // Check if this URL should fail
            if self.fetch_should_fail.read().unwrap().contains(url) {
                return Err(anyhow::anyhow!("Simulated fetch failure for {}", url));
            }

            // Get OIDs this URL can provide
            let provides = self.url_provides_oids.get(url).cloned().unwrap_or_default();

            // Find which requested OIDs this URL can provide
            let fetched: Vec<String> = if self.urls_report_shared_objects.contains(url) {
                let needed = self.needed_oids.read().unwrap();
                oids.iter()
                    .filter(|oid| !needed.contains(*oid))
                    .cloned()
                    .collect()
            } else {
                oids.iter()
                    .filter(|oid| provides.contains(*oid))
                    .cloned()
                    .collect()
            };

            // Remove fetched OIDs from needed set
            {
                let mut needed = self.needed_oids.write().unwrap();
                for oid in &fetched {
                    needed.remove(oid);
                }
            }

            if let Some(barrier) = self.fetch_completion_barriers.get(url) {
                barrier
                    .acquire()
                    .await
                    .expect("mock completion barrier should remain open")
                    .forget();
            }

            Ok(fetched)
        }

        async fn process_newly_available_git_data(
            &self,
            _source_repo_path: &Path,
            _new_oids: &HashSet<String>,
        ) -> Result<ProcessResult> {
            // Return a default result - tests can check if this was called
            let result = ProcessResult::default();
            self.process_results.write().unwrap().push(result.clone());
            Ok(result)
        }

        fn has_pending_events(&self, _identifier: &str) -> bool {
            *self.has_pending.read().unwrap()
        }

        fn find_target_repo(&self, _db_repo_data: &RepositoryData) -> Option<PathBuf> {
            self.target_repo_path.clone()
        }

        fn our_domain(&self) -> Option<&str> {
            self.our_domain.as_deref()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn mock_tracks_fetch_attempts() {
            let mock = MockSyncContext::new()
                .with_urls(&["https://github.com/foo/bar.git"])
                .with_needed_oids(&["abc123"]);

            // Fetch should log the URL
            let _ = mock
                .fetch_oids(
                    Path::new("/tmp"),
                    "https://github.com/foo/bar.git",
                    &["abc123".to_string()],
                )
                .await;

            assert_eq!(
                mock.fetch_log(),
                vec!["https://github.com/foo/bar.git".to_string()]
            );
        }

        #[tokio::test]
        async fn mock_provides_configured_oids() {
            let mock = MockSyncContext::new()
                .with_needed_oids(&["abc123", "def456"])
                .url_provides("https://github.com/foo/bar.git", &["abc123"]);

            let fetched = mock
                .fetch_oids(
                    Path::new("/tmp"),
                    "https://github.com/foo/bar.git",
                    &["abc123".to_string(), "def456".to_string()],
                )
                .await
                .unwrap();

            // Only abc123 should be fetched (it's what the URL provides)
            assert_eq!(fetched, vec!["abc123".to_string()]);

            // abc123 should no longer be needed
            let needed = mock.current_needed_oids();
            assert!(!needed.contains("abc123"));
            assert!(needed.contains("def456"));
        }

        #[tokio::test]
        async fn mock_url_failure() {
            let mock = MockSyncContext::new()
                .with_needed_oids(&["abc123"])
                .url_should_fail("https://bad-server.com/repo.git");

            let result = mock
                .fetch_oids(
                    Path::new("/tmp"),
                    "https://bad-server.com/repo.git",
                    &["abc123".to_string()],
                )
                .await;

            assert!(result.is_err());
        }

        #[test]
        fn mock_oid_exists_reflects_needed_state() {
            let mock = MockSyncContext::new().with_needed_oids(&["abc123"]);

            // abc123 is needed, so it doesn't exist
            assert!(!mock.oid_exists(Path::new("/tmp"), "abc123"));

            // def456 is not needed, so it "exists"
            assert!(mock.oid_exists(Path::new("/tmp"), "def456"));

            // Mark abc123 as fetched
            mock.mark_oids_fetched(&["abc123"]);

            // Now it exists
            assert!(mock.oid_exists(Path::new("/tmp"), "abc123"));
        }

        #[test]
        fn mock_pending_events_controllable() {
            let mock = MockSyncContext::new().with_pending_events(true);
            assert!(mock.has_pending_events("test-repo"));

            mock.set_pending_events(false);
            assert!(!mock.has_pending_events("test-repo"));
        }

        #[test]
        fn mock_collect_pr_clone_urls_returns_configured_urls() {
            let mock = MockSyncContext::new().with_pr_clone_urls(&[
                "https://fork-server.com/repo.git",
                "https://another-fork.com/repo.git",
            ]);

            let urls = mock.collect_pr_clone_urls("any-identifier");

            assert_eq!(urls.len(), 2);
            assert!(urls.contains("https://fork-server.com/repo.git"));
            assert!(urls.contains("https://another-fork.com/repo.git"));
        }

        #[test]
        fn mock_collect_pr_clone_urls_empty_by_default() {
            let mock = MockSyncContext::new();

            let urls = mock.collect_pr_clone_urls("any-identifier");

            assert!(urls.is_empty());
        }
    }
}
