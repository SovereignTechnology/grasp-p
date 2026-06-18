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
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::git::authorization::RepositoryData;

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
    async fn fetch_oids(&self, repo_path: &Path, url: &str, oids: &[String])
        -> Result<Vec<String>>;

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

use nostr_relay_builder::LocalRelay;
use std::process::Command;
use std::sync::Arc;
use tracing::debug;

use crate::nostr::builder::Nip34WritePolicy;
use crate::nostr::builder::SharedDatabase;
use crate::nostr::events::RepositoryState;
use crate::purgatory::Purgatory;
use crate::sync::naughty_list::NaughtyListTracker;

use super::functions::extract_domain;

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
    pub fn new(
        purgatory: Arc<Purgatory>,
        database: SharedDatabase,
        git_data_path: PathBuf,
        our_domain: Option<String>,
        local_relay: Option<LocalRelay>,
        write_policy: Option<Nip34WritePolicy>,
        git_naughty_list: Arc<NaughtyListTracker>,
    ) -> Self {
        Self {
            purgatory,
            database,
            git_data_path,
            our_domain_value: our_domain,
            local_relay,
            write_policy,
            git_naughty_list,
        }
    }

    /// Get reference to the git naughty list tracker
    pub fn git_naughty_list(&self) -> &Arc<NaughtyListTracker> {
        &self.git_naughty_list
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

    async fn fetch_oids(
        &self,
        repo_path: &Path,
        url: &str,
        oids: &[String],
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

        // Use tokio::task::spawn_blocking for the git fetch since it's blocking
        let repo_path = repo_path.to_path_buf();
        let url = url.to_string();
        let missing_oids: Vec<String> = missing.into_iter().cloned().collect();
        let naughty_list = self.git_naughty_list.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut remaining_oids = missing_oids.clone();
            let mut missing_from_remote: Vec<String> = Vec::new();

            // Retry loop: keep fetching until success or no OIDs left
            loop {
                if remaining_oids.is_empty() {
                    // All OIDs were missing from remote
                    debug!(
                        url = %url,
                        missing_count = missing_from_remote.len(),
                        "All requested OIDs missing from remote"
                    );
                    return Ok(vec![]);
                }

                // git fetch <remote> <sha1> <sha2> ... - fetch all OIDs with full history
                let mut args = vec!["fetch".to_string(), url.clone()];
                args.extend(remaining_oids.iter().cloned());

                let output = Command::new("git")
                    .args(&args)
                    .current_dir(&repo_path)
                    .output();

                match output {
                    Ok(result) if result.status.success() => {
                        // Fetch succeeded - count how many OIDs we now have
                        let fetched: Vec<String> = missing_oids
                            .iter()
                            .filter(|oid| crate::git::oid_exists(&repo_path, oid))
                            .cloned()
                            .collect();

                        if !missing_from_remote.is_empty() {
                            debug!(
                                url = %url,
                                fetched_count = fetched.len(),
                                missing_count = missing_from_remote.len(),
                                missing_oids = ?missing_from_remote,
                                "Fetch completed after retries - some OIDs were missing from remote"
                            );
                        } else {
                            debug!(url = %url, fetched_count = fetched.len(), "Successfully fetched OIDs");
                        }

                        return Ok(fetched);
                    }
                    Ok(result) => {
                        let stderr = String::from_utf8_lossy(&result.stderr);

                        // Check for "not our ref" error - this is retryable
                        if stderr.contains("upload-pack: not our ref") {
                            // Parse out the missing OID from stderr
                            let missing_oid = stderr.lines().find_map(|line| {
                                if line.contains("not our ref") {
                                    // Extract the OID from lines like:
                                    // "fatal: remote error: upload-pack: not our ref <oid>"
                                    line.split("not our ref")
                                        .nth(1)
                                        .map(|s| s.trim().to_string())
                                } else {
                                    None
                                }
                            });

                            if let Some(ref oid) = missing_oid {
                                // Remove the missing OID and retry with remaining
                                remaining_oids.retain(|o| o != oid);
                                missing_from_remote.push(oid.clone());

                                debug!(
                                    url = %url,
                                    missing_oid = %oid,
                                    remaining_count = remaining_oids.len(),
                                    "OID not found on remote, retrying with remaining OIDs"
                                );

                                continue; // Retry with remaining OIDs
                            }
                        }

                        // Non-retryable error - record to naughty list and return error
                        if let Some(domain) = extract_domain(&url) {
                            if let Some(category) = NaughtyListTracker::classify_error(&stderr) {
                                let is_new =
                                    naughty_list.record(&domain, category, stderr.to_string());

                                if is_new {
                                    tracing::warn!(
                                        domain = %domain,
                                        category = %category,
                                        error = %stderr,
                                        "Git remote domain added to naughty list"
                                    );
                                } else {
                                    debug!(
                                        domain = %domain,
                                        category = %category,
                                        error = %stderr,
                                        "Git fetch failed (domain on naughty list)"
                                    );
                                }
                            }
                        }

                        return Err(anyhow::anyhow!("git fetch failed for {}: {}", url, stderr));
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "git fetch command error for {}: {}",
                            url,
                            e
                        ))
                    }
                }
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to spawn blocking task: {}", e))?
    }

    async fn process_newly_available_git_data(
        &self,
        source_repo_path: &Path,
        new_oids: &HashSet<String>,
    ) -> Result<ProcessResult> {
        // Delegate to the unified function from git::sync.
        // Pass configured write_policy for promotion-time recovery hooks.
        // Keep rejected_events_index as None: the purgatory sync path already handles
        // hot-cache re-processing via SyncManager::process_event_static.
        let result = crate::git::sync::process_newly_available_git_data(
            source_repo_path,
            new_oids,
            &self.database,
            self.local_relay.as_ref(),
            &self.purgatory,
            &self.git_data_path,
            self.write_policy.as_ref(),
            None,
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

// =============================================================================
// Mock Implementation for Testing
// =============================================================================

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
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

        async fn fetch_oids(
            &self,
            _repo_path: &Path,
            url: &str,
            oids: &[String],
        ) -> Result<Vec<String>> {
            // Log the fetch attempt
            self.fetch_log.write().unwrap().push(url.to_string());

            // Check if this URL should fail
            if self.fetch_should_fail.read().unwrap().contains(url) {
                return Err(anyhow::anyhow!("Simulated fetch failure for {}", url));
            }

            // Get OIDs this URL can provide
            let provides = self.url_provides_oids.get(url).cloned().unwrap_or_default();

            // Find which requested OIDs this URL can provide
            let fetched: Vec<String> = oids
                .iter()
                .filter(|oid| provides.contains(*oid))
                .cloned()
                .collect();

            // Remove fetched OIDs from needed set
            {
                let mut needed = self.needed_oids.write().unwrap();
                for oid in &fetched {
                    needed.remove(oid);
                }
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
