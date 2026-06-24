//! Git Data Synchronization Across Owner Repositories
//!
//! This module provides functions to sync git data across multiple owner repositories
//! that are authorized by the same state event. This is used when:
//!
//! 1. A push is received that satisfies a state event - the git data needs to be
//!    copied to other owner repos that authorize the same state
//! 2. Purgatory sync fetches git data from remote - needs to distribute to all
//!    authorized owner repos
//! 3. A push to refs/nostr/<event-id> (PR data) is received - needs to be synced
//!    to all other owner repos that share maintainers
//!
//! ## Architecture
//!
//! The key insight is that multiple owners can have announcements for the same
//! repository identifier, and they may share maintainers. When a state event
//! authorizes a push, that push should be reflected in ALL owner repositories
//! that would authorize the same state.
//!
//! ## Unified Processing
//!
//! The `process_newly_available_git_data` function provides unified processing
//! for newly available git data, regardless of how it arrived (git push or
//! purgatory sync). This ensures consistent behavior for:
//! - Discovering satisfiable events from purgatory
//! - Syncing OIDs to authorized owner repos
//! - Aligning refs (+ setting HEAD)
//! - Saving events to database
//! - Notifying WebSocket subscribers
//! - Removing from purgatory

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};

use async_trait::async_trait;
use nostr_sdk::prelude::Event;

use crate::git::authorization::{
    collect_authorized_maintainers, fetch_repository_data_excluding_purgatory,
    fetch_repository_data_with_purgatory, RepositoryData,
};
use crate::git::{self, oid_exists};
use crate::nostr::events::RepositoryState;
use crate::nostr::SharedDatabase;
use crate::purgatory::{can_apply_state, Purgatory};

/// Result of processing newly available git data.
///
/// This struct captures what happened when we tried to release events from
/// purgatory after new git data became available (whether from a git push
/// or from purgatory sync fetching OIDs from remote servers).
#[derive(Debug, Default, Clone)]
pub struct ProcessResult {
    /// Number of announcements released from purgatory
    pub announcements_released: usize,
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
        self.announcements_released > 0 || self.states_released > 0 || self.prs_released > 0
    }

    /// Merge another ProcessResult into this one
    pub fn merge(&mut self, other: ProcessResult) {
        self.announcements_released += other.announcements_released;
        self.states_released += other.states_released;
        self.prs_released += other.prs_released;
        self.repos_synced += other.repos_synced;
        self.refs_created += other.refs_created;
        self.refs_updated += other.refs_updated;
        self.refs_deleted += other.refs_deleted;
        self.errors.extend(other.errors);
    }
}

/// Result of syncing git data to owner repositories
#[derive(Debug, Default)]
pub struct SyncResult {
    /// Number of repositories synced
    pub repos_synced: usize,
    /// Number of refs created across all repos
    pub refs_created: usize,
    /// Number of refs updated across all repos
    pub refs_updated: usize,
    /// Number of refs deleted across all repos
    pub refs_deleted: usize,
    /// Number of repositories where HEAD was set
    pub heads_set: usize,
    /// Errors encountered (repo path -> error message)
    pub errors: Vec<(String, String)>,
}

/// Result of aligning a single repository with state
#[derive(Debug, Default)]
pub struct AlignmentResult {
    /// Number of refs created
    pub refs_created: usize,
    /// Number of refs updated
    pub refs_updated: usize,
    /// Number of refs deleted
    pub refs_deleted: usize,
    /// Whether HEAD was set
    pub head_set: bool,
}

/// Result of syncing PR refs to owner repositories
#[derive(Debug, Default)]
pub struct PrSyncResult {
    /// Number of repositories synced
    pub repos_synced: usize,
    /// Number of refs created across all repos
    pub refs_created: usize,
    /// Errors encountered (repo path -> error message)
    pub errors: Vec<(String, String)>,
}

/// Extract owner pubkeys from PR events' `a` tags.
///
/// PR events reference repositories via `a` tags with format `30617:<owner_pubkey>:<identifier>`.
/// This function extracts all unique owner pubkeys from these tags.
///
/// # Arguments
/// * `pr_events` - List of PR events to extract owner pubkeys from
///
/// # Returns
/// A HashSet of owner pubkeys (hex strings) referenced by the PR events
pub fn extract_tagged_owners_from_pr_events(pr_events: &[Event]) -> HashSet<String> {
    let mut owners = HashSet::new();

    for event in pr_events {
        for tag in event.tags.iter() {
            let tag_vec = tag.clone().to_vec();
            if tag_vec.len() >= 2 && tag_vec[0] == "a" && tag_vec[1].starts_with("30617:") {
                // Format: 30617:<owner_pubkey>:<identifier>
                let parts: Vec<&str> = tag_vec[1].split(':').collect();
                if parts.len() >= 2 {
                    owners.insert(parts[1].to_string());
                }
            }
        }
    }

    owners
}

/// Sync PR data (refs/nostr/<event-id>) from a source repository to owner
/// repositories that list any of the tagged owners as a maintainer.
///
/// This function is used when PR events from purgatory have been authorized.
/// It extracts the owner pubkeys from the PR events' `a` tags and syncs to
/// any owner repo that lists any of those owners as a maintainer.
///
/// # Arguments
/// * `source_repo_path` - Path to the repository that has the PR git data
/// * `pr_refs` - List of (event_id, commit_hash) tuples for PR refs that were pushed
/// * `purgatory_pr_events` - PR events from purgatory that authorized this push
/// * `db_repo_data` - Repository data from database (announcements + states)
/// * `git_data_path` - Base path for git repositories
/// * `source_owner_pubkey` - The owner pubkey of the source repository (to skip)
///
/// # Returns
/// A `PrSyncResult` with statistics about what was synced
pub fn sync_pr_refs_to_tagged_owner_repos(
    source_repo_path: &Path,
    pr_refs: &[(String, String)], // (event_id, commit_hash)
    purgatory_pr_events: &[Event],
    db_repo_data: &RepositoryData,
    git_data_path: &Path,
    source_owner_pubkey: &str,
) -> PrSyncResult {
    let mut result = PrSyncResult::default();

    if pr_refs.is_empty() {
        return result;
    }

    // Extract owner pubkeys from PR events' `a` tags
    let tagged_owners = extract_tagged_owners_from_pr_events(purgatory_pr_events);

    if tagged_owners.is_empty() {
        debug!("No tagged owners found in PR events");
        return result;
    }

    debug!(
        tagged_owners = ?tagged_owners,
        pr_refs_count = pr_refs.len(),
        "Syncing PR refs to owner repositories that list tagged owners as maintainers"
    );

    // Collect authorized maintainers per owner
    let by_owner = collect_authorized_maintainers(&db_repo_data.announcements);

    for (owner, maintainers) in &by_owner {
        // Skip the source owner - we already have the data there
        if owner == source_owner_pubkey {
            continue;
        }

        // Check if this owner's maintainer set includes any of the tagged owners
        let has_tagged_owner_as_maintainer = maintainers.iter().any(|m| tagged_owners.contains(m));

        if !has_tagged_owner_as_maintainer {
            debug!(
                owner = %owner,
                "Skipping owner - does not list any tagged owner as maintainer"
            );
            continue;
        }

        // Find the announcement for this owner
        let announcement = db_repo_data
            .announcements
            .iter()
            .find(|a| a.event.pubkey.to_hex() == *owner);

        let Some(announcement) = announcement else {
            continue;
        };

        let target_repo_path = git_data_path.join(announcement.repo_path());

        if !target_repo_path.exists() {
            debug!(
                owner = %owner,
                repo_path = %target_repo_path.display(),
                "Skipping owner - repository doesn't exist"
            );
            continue;
        }

        // Sync each PR ref
        let mut refs_created_for_owner = 0;
        for (event_id, commit_hash) in pr_refs {
            // Copy the commit if missing
            if !oid_exists(&target_repo_path, commit_hash) {
                if let Err(e) = copy_single_commit_between_repos(
                    source_repo_path,
                    &target_repo_path,
                    commit_hash,
                ) {
                    warn!(
                        event_id = %event_id,
                        source = %source_repo_path.display(),
                        target = %target_repo_path.display(),
                        error = %e,
                        "Failed to copy PR commit between repos"
                    );
                    result
                        .errors
                        .push((target_repo_path.display().to_string(), e));
                    continue;
                }
            }

            // Create the refs/nostr/<event-id> ref
            let ref_name = format!("refs/nostr/{}", event_id);
            match git::update_ref(&target_repo_path, &ref_name, commit_hash) {
                Ok(()) => {
                    info!(
                        event_id = %event_id,
                        commit = %commit_hash,
                        target = %target_repo_path.display(),
                        "Created PR ref in target repository (via tagged owner)"
                    );
                    refs_created_for_owner += 1;
                }
                Err(e) => {
                    warn!(
                        event_id = %event_id,
                        target = %target_repo_path.display(),
                        error = %e,
                        "Failed to create PR ref in target repository"
                    );
                    result
                        .errors
                        .push((target_repo_path.display().to_string(), e));
                }
            }
        }

        if refs_created_for_owner > 0 {
            result.repos_synced += 1;
            result.refs_created += refs_created_for_owner;

            info!(
                owner = %owner,
                repo_path = %target_repo_path.display(),
                refs_created = refs_created_for_owner,
                "Synced PR refs to owner repository (via tagged owner)"
            );
        }
    }

    info!(
        repos_synced = result.repos_synced,
        refs_created = result.refs_created,
        errors = result.errors.len(),
        tagged_owners = tagged_owners.len(),
        "Completed PR ref sync to owner repositories via tagged owners"
    );

    result
}

/// Copy a single commit from source repository to target repository
pub(crate) fn copy_single_commit_between_repos(
    source_repo: &Path,
    target_repo: &Path,
    commit_hash: &str,
) -> Result<(), String> {
    debug!(
        "Copying commit {} from {} to {}",
        commit_hash,
        source_repo.display(),
        target_repo.display()
    );

    let output = Command::new("git")
        .args([
            "fetch",
            source_repo.to_str().ok_or("Invalid source path")?,
            commit_hash,
        ])
        .current_dir(target_repo)
        .output()
        .map_err(|e| format!("Failed to execute git fetch: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "git fetch failed for commit {}: {}",
            commit_hash, stderr
        ));
    }

    debug!("Copied commit {} to {}", commit_hash, target_repo.display());
    Ok(())
}

/// Sync git data from a source repository to all other owner repositories
/// that authorize the given state event.
///
/// This function:
/// 1. Collects all authorized maintainers per owner from announcements
/// 2. For each owner whose maintainer set authorizes the state author:
///    - Skips if a newer state already exists for that owner
///    - Copies missing OIDs from source repo to target repo
///    - Aligns refs with the state
///
/// # Arguments
/// * `source_repo_path` - Path to the repository that has the git data
/// * `state` - The repository state event that authorized the push
/// * `db_repo_data` - Repository data from database (announcements + states)
/// * `git_data_path` - Base path for git repositories
///
/// # Returns
/// A `SyncResult` with statistics about what was synced
pub fn sync_to_owner_repos(
    source_repo_path: &Path,
    state: &RepositoryState,
    db_repo_data: &RepositoryData,
    git_data_path: &Path,
) -> SyncResult {
    let mut result = SyncResult::default();

    // Collect authorized maintainers per owner
    let by_owner = collect_authorized_maintainers(&db_repo_data.announcements);
    let state_author = state.event.pubkey.to_hex();

    debug!(
        identifier = %state.identifier,
        owners = by_owner.len(),
        "Syncing git data to owner repositories"
    );

    for (owner, maintainers) in &by_owner {
        // Check if this state's author is authorized for this owner
        if !maintainers.contains(&state_author) {
            debug!(
                identifier = %state.identifier,
                owner = %owner,
                "Skipping owner - state author not in maintainer set"
            );
            continue;
        }

        // Find the previous latest state for this owner's maintainer set
        let previous_state = db_repo_data
            .states
            .iter()
            .filter(|s| maintainers.contains(&s.event.pubkey.to_hex()))
            .max_by_key(|s| s.event.created_at);

        // Only update if this state is newer than any existing state
        // TODO: in event of a tie, the event with the biggest event id wins
        if let Some(prev) = previous_state {
            if state.event.created_at <= prev.event.created_at {
                debug!(
                    identifier = %state.identifier,
                    owner = %owner,
                    "Skipping owner - existing state is newer or equal"
                );
                continue;
            }
        }

        // Find the announcement for this owner
        let announcement = db_repo_data
            .announcements
            .iter()
            .find(|a| a.event.pubkey.to_hex() == *owner);

        let Some(announcement) = announcement else {
            continue;
        };

        let target_repo_path = git_data_path.join(announcement.repo_path());

        if !target_repo_path.exists() {
            // Repository doesn't exist (e.g., announcement doesn't list this service)
            debug!(
                identifier = %state.identifier,
                owner = %owner,
                repo_path = %target_repo_path.display(),
                "Skipping owner - repository doesn't exist"
            );
            continue;
        }

        // Copy missing OIDs from source repo to target repo if different
        if target_repo_path != source_repo_path {
            if let Err(e) =
                copy_missing_oids_between_repos(source_repo_path, &target_repo_path, state)
            {
                warn!(
                    identifier = %state.identifier,
                    source = %source_repo_path.display(),
                    target = %target_repo_path.display(),
                    error = %e,
                    "Failed to copy OIDs between repos"
                );
                result
                    .errors
                    .push((target_repo_path.display().to_string(), e));
                // Continue anyway - we'll try to align what we can
            }
        }

        // Align refs with state
        let align_result = align_repository_with_state(&target_repo_path, state);
        result.repos_synced += 1;
        result.refs_created += align_result.refs_created;
        result.refs_updated += align_result.refs_updated;
        result.refs_deleted += align_result.refs_deleted;
        if align_result.head_set {
            result.heads_set += 1;
        }

        info!(
            identifier = %state.identifier,
            owner = %owner,
            repo_path = %target_repo_path.display(),
            refs_created = align_result.refs_created,
            refs_updated = align_result.refs_updated,
            refs_deleted = align_result.refs_deleted,
            head_set = align_result.head_set,
            "Aligned repository with state"
        );
    }

    info!(
        identifier = %state.identifier,
        repos_synced = result.repos_synced,
        refs_created = result.refs_created,
        refs_updated = result.refs_updated,
        refs_deleted = result.refs_deleted,
        heads_set = result.heads_set,
        "Completed git data sync to owner repositories"
    );

    result
}

/// Copy missing OIDs from a source repository to a target repository.
///
/// Identifies commits referenced in the state that are missing from the target
/// repository and copies them from the source repository using git fetch.
pub fn copy_missing_oids_between_repos(
    source_repo: &Path,
    target_repo: &Path,
    state: &RepositoryState,
) -> Result<(), String> {
    // Collect all commits referenced in the state
    let mut commits_to_check = Vec::new();

    for branch in &state.branches {
        if !branch.commit.starts_with("ref: ") {
            commits_to_check.push(&branch.commit);
        }
    }

    for tag in &state.tags {
        if !tag.commit.starts_with("ref: ") {
            commits_to_check.push(&tag.commit);
        }
    }

    // Identify missing commits
    let mut missing_commits = Vec::new();
    for commit in commits_to_check {
        if !oid_exists(target_repo, commit) {
            missing_commits.push(commit);
        }
    }

    if missing_commits.is_empty() {
        debug!(
            "No missing commits to copy from {} to {}",
            source_repo.display(),
            target_repo.display()
        );
        return Ok(());
    }

    info!(
        "Copying {} missing commits from {} to {}",
        missing_commits.len(),
        source_repo.display(),
        target_repo.display()
    );

    // Fetch each missing commit from source to target
    for commit in &missing_commits {
        let output = Command::new("git")
            .args([
                "fetch",
                source_repo.to_str().ok_or("Invalid source path")?,
                commit,
            ])
            .current_dir(target_repo)
            .output()
            .map_err(|e| format!("Failed to execute git fetch: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "git fetch failed for commit {}: {}",
                commit, stderr
            ));
        }

        debug!("Copied commit {} to {}", commit, target_repo.display());
    }

    Ok(())
}

/// Align a repository's refs with the authorized state.
///
/// This function:
/// 1. Deletes refs that are in the repo but not in the state (for refs/heads/ and refs/tags/)
/// 2. Updates refs that exist in state if we have the commit
/// 3. Sets HEAD if the HEAD branch's commit is available
pub fn align_repository_with_state(repo_path: &Path, state: &RepositoryState) -> AlignmentResult {
    let mut result = AlignmentResult::default();

    // Check if repository exists
    if !repo_path.exists() {
        debug!(
            "Repository not found at {}, cannot align with state",
            repo_path.display()
        );
        return result;
    }

    // Get current refs from the repository
    let current_refs = match git::list_refs(repo_path) {
        Ok(refs) => refs,
        Err(e) => {
            warn!("Failed to list refs in {}: {}", repo_path.display(), e);
            return result;
        }
    };

    // Build expected refs from state
    let mut expected_refs: HashMap<String, String> = HashMap::new();

    for branch in &state.branches {
        let ref_name = format!("refs/heads/{}", branch.name);
        expected_refs.insert(ref_name, branch.commit.clone());
    }

    for tag in &state.tags {
        let ref_name = format!("refs/tags/{}", tag.name);
        expected_refs.insert(ref_name, tag.commit.clone());
    }

    // Delete refs that exist in repo but not in state (only for refs/heads/ and refs/tags/)
    for (ref_name, _current_commit) in &current_refs {
        if (ref_name.starts_with("refs/heads/") || ref_name.starts_with("refs/tags/"))
            && !expected_refs.contains_key(ref_name)
        {
            match git::delete_ref(repo_path, ref_name) {
                Ok(()) => {
                    info!(
                        "Deleted {} from {} (not in state)",
                        ref_name,
                        repo_path.display()
                    );
                    result.refs_deleted += 1;
                }
                Err(e) => {
                    warn!(
                        "Failed to delete {} from {}: {}",
                        ref_name,
                        repo_path.display(),
                        e
                    );
                }
            }
        }
    }

    // Update refs that exist in state (if we have the commit)
    for (ref_name, expected_commit) in &expected_refs {
        // Skip symbolic refs
        if expected_commit.starts_with("ref: ") {
            continue;
        }

        // Check if we have the commit
        if !git::oid_exists(repo_path, expected_commit) {
            debug!(
                "Commit {} not available for {} in {}",
                expected_commit,
                ref_name,
                repo_path.display()
            );
            continue;
        }

        // Check current value
        let current_commit = current_refs
            .iter()
            .find(|(r, _)| r == ref_name)
            .map(|(_, c)| c.as_str());

        if current_commit == Some(expected_commit.as_str()) {
            // Already correct
            continue;
        }

        // Update or create the ref
        match git::update_ref(repo_path, ref_name, expected_commit) {
            Ok(()) => {
                if current_commit.is_some() {
                    debug!(
                        "Updated {} to {} in {}",
                        ref_name,
                        expected_commit,
                        repo_path.display()
                    );
                    result.refs_updated += 1;
                } else {
                    debug!(
                        "Created {} at {} in {}",
                        ref_name,
                        expected_commit,
                        repo_path.display()
                    );
                    result.refs_created += 1;
                }
            }
            Err(e) => {
                warn!(
                    "Failed to update {} in {}: {}",
                    ref_name,
                    repo_path.display(),
                    e
                );
            }
        }
    }

    // Set HEAD if specified in state
    if let Some(head_ref) = &state.head {
        if let Some(branch_name) = state.get_head_branch() {
            if let Some(head_commit) = state.get_branch_commit(branch_name) {
                match git::try_set_head_if_available(repo_path, head_ref, head_commit) {
                    Ok(true) => {
                        debug!("Set HEAD to {} in {}", head_ref, repo_path.display());
                        result.head_set = true;
                    }
                    Ok(false) => {
                        debug!(
                            "HEAD commit {} not available yet in {}",
                            head_commit,
                            repo_path.display()
                        );
                    }
                    Err(e) => {
                        warn!("Failed to set HEAD in {}: {}", repo_path.display(), e);
                    }
                }
            }
        }
    }

    result
}

// =============================================================================
// Unified Git Data Processing
// =============================================================================

/// Extract repository identifier from a repository path.
///
/// Supports two on-disk layouts:
///
/// - Standard endpoint: `{git_data_path}/{npub}/{identifier}.git` — two
///   components after `git_data_path`. The identifier is the last
///   component minus the `.git` suffix.
/// - GRASP-06 `/prs/` endpoint (06.md line 14): the `/prs/`
///   contributor-submission subtree at
///   `{git_data_path}/prs/{submitter-hex}/{identifier}.git` — three
///   components, where the leading `prs` is the namespace marker (see
///   [`crate::grasp06::paths`]). The identifier is again the last
///   component minus `.git`.
///
/// Any other shape returns `None`.
///
/// # Arguments
/// * `repo_path` - Full path to the git repository
/// * `git_data_path` - Base path for git repositories
pub fn extract_identifier_from_repo_path(repo_path: &Path, git_data_path: &Path) -> Option<String> {
    // Get the relative path from git_data_path
    let relative = repo_path.strip_prefix(git_data_path).ok()?;

    let components: Vec<_> = relative.components().collect();

    // Standard layout: <npub>/<id>.git
    // /prs/ layout (06.md): prs/<submitter-hex>/<id>.git
    let repo_name = match components.len() {
        2 => components[1].as_os_str().to_str()?,
        3 if components[0].as_os_str().to_str() == Some(crate::grasp06::paths::PRS_DISK_PREFIX) => {
            components[2].as_os_str().to_str()?
        }
        _ => return None,
    };

    // Strip the .git suffix
    repo_name.strip_suffix(".git").map(|s| s.to_string())
}

/// Extract repository identifier from a PR event.
///
/// PR events reference repositories via `a` tags with format `30617:<owner_pubkey>:<identifier>`.
/// This function extracts the identifier from the first matching `a` tag.
///
/// # Arguments
/// * `event` - The PR event (kind 1617 or 1618)
///
/// # Returns
/// The identifier if found, None otherwise
pub fn extract_identifier_from_pr_event(event: &Event) -> Option<String> {
    for tag in event.tags.iter() {
        let tag_vec = tag.clone().to_vec();
        if tag_vec.len() >= 2 && tag_vec[0] == "a" && tag_vec[1].starts_with("30617:") {
            // Format: 30617:<owner_pubkey>:<identifier>
            let parts: Vec<&str> = tag_vec[1].split(':').collect();
            if parts.len() >= 3 {
                return Some(parts[2].to_string());
            }
        }
    }
    None
}

/// Unified processing of newly available git data.
///
/// This function is called whenever git data becomes available, whether from:
/// - A successful `git push` (handle_receive_pack)
/// - Purgatory sync fetching OIDs from remote servers
///
/// It handles all post-git-data-available processing:
/// 1. Discovers satisfiable events from purgatory (state events and PR events)
/// 2. For each satisfiable state event:
///    - Syncs OIDs to authorized owner repos
///    - Aligns refs (+ sets HEAD)
///    - Saves event to database
///    - Notifies WebSocket subscribers
///    - Removes from purgatory
/// 3. For each satisfiable PR event:
///    - Syncs commit to owner repos
///    - Creates refs/nostr/<event-id> refs
///    - Saves event to database
///    - Notifies WebSocket subscribers
///    - Removes from purgatory
///
/// # Arguments
/// * `source_repo_path` - Path to the repository that has the new git data
/// * `new_oids` - Set of OIDs that were just made available (used for logging/debugging)
/// * `database` - Database for saving events and querying repository data
/// * `local_relay` - Local relay for notifying WebSocket subscribers (optional)
/// * `purgatory` - Purgatory instance to check for satisfiable events
/// * `git_data_path` - Base path for git repositories
///
/// # Returns
/// A `ProcessResult` describing what was processed
/// Neutral lifecycle hooks for purgatory promotion.
///
/// This trait is owned by `git::sync` so this module can report promotion
/// lifecycle events without depending on Nostr write policy, deletion recovery,
/// or hot-cache internals. Higher layers may implement these hooks to react to
/// git/purgatory lifecycle events.
#[async_trait]
pub trait PurgatoryPromotionHooks: Send + Sync {
    /// Called immediately before an accepted purgatory event is saved to the
    /// main database.
    async fn before_event_saved(&self, _event: &Event, _context: PurgatorySaveContext) {}

    /// Called immediately before a purgatory announcement is promoted.
    async fn before_announcement_promote(&self, _event: &Event, _identifier: &str) {}

    /// Called after an announcement has been saved to the main database.
    async fn after_announcement_saved(&self, _event: &Event) {}

    /// Called after a state event has been saved to the main database.
    async fn after_state_saved(&self, _event: &Event) {}

    /// Called after a PR event has been saved to the main database.
    async fn after_pr_saved(&self, _event: &Event) {}
}

/// Neutral save context for purgatory events promoted by git sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgatorySaveContext {
    State,
    Announcement,
    Pr,
}

async fn save_promoted_event(
    database: &SharedDatabase,
    event: &Event,
    context: PurgatorySaveContext,
    promotion_hooks: Option<&dyn PurgatoryPromotionHooks>,
) -> anyhow::Result<()> {
    if let Some(hooks) = promotion_hooks {
        hooks.before_event_saved(event, context).await;
    }

    database
        .save_event(event)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Failed to save promoted event {}: {e}", event.id))
}

#[allow(clippy::too_many_arguments)]
pub async fn process_newly_available_git_data(
    source_repo_path: &Path,
    new_oids: &HashSet<String>,
    database: &SharedDatabase,
    local_relay: Option<&nostr_relay_builder::LocalRelay>,
    purgatory: &Purgatory,
    git_data_path: &Path,
    promotion_hooks: Option<&dyn PurgatoryPromotionHooks>,
) -> anyhow::Result<ProcessResult> {
    let mut result = ProcessResult::default();

    // Extract identifier from repo path
    let identifier = match extract_identifier_from_repo_path(source_repo_path, git_data_path) {
        Some(id) => id,
        None => {
            debug!(
                repo_path = %source_repo_path.display(),
                "Could not extract identifier from repo path"
            );
            return Ok(result);
        }
    };

    debug!(
        identifier = %identifier,
        new_oids_count = new_oids.len(),
        "Processing newly available git data"
    );

    // Process announcements from purgatory
    let announcement_result = process_purgatory_announcements(
        &identifier,
        source_repo_path,
        database,
        local_relay,
        purgatory,
        git_data_path,
        promotion_hooks,
    )
    .await;
    result.merge(announcement_result);

    // Process state events from purgatory
    let state_result = process_purgatory_state_events(
        &identifier,
        source_repo_path,
        database,
        local_relay,
        purgatory,
        git_data_path,
        promotion_hooks,
    )
    .await;
    result.merge(state_result);

    // Process PR events from purgatory
    let pr_outcome = process_purgatory_pr_events(
        &identifier,
        source_repo_path,
        database,
        local_relay,
        purgatory,
        git_data_path,
        promotion_hooks,
    )
    .await;
    result.merge(pr_outcome.result);

    // Cross-service mirror (design doc:
    // docs/explanation/grasp-06-contributor-pr-submission.md, "Cross-service
    // mirror" section). When the source repo lives under the `/prs/`
    // subtree (06.md line 14), refs released from purgatory by this push
    // must be copied into any matching announced repo on this relay so the
    // PR is fetchable at the maintainer's canonical URL. The reverse
    // direction is NOT supported — a push to `<owner>/<id>.git` must never
    // write under `/prs/*`, so this branch is gated on the `/prs/` source
    // check.
    if crate::grasp06::paths::is_prs_repo_path(source_repo_path, git_data_path) {
        for (event, commit) in &pr_outcome.released {
            mirror_prs_pr_to_announced_repos(
                source_repo_path,
                event,
                commit,
                database,
                git_data_path,
                &mut result,
            )
            .await;
        }
    }

    if result.released_any() {
        info!(
            identifier = %identifier,
            announcements_released = result.announcements_released,
            states_released = result.states_released,
            prs_released = result.prs_released,
            repos_synced = result.repos_synced,
            "Released events from purgatory after git data became available"
        );
    }

    Ok(result)
}

/// Process purgatory promotions for owner repos populated by state-event OID copies.
///
/// [`crate::git::process::process_state_with_git_data`] copies OIDs from the
/// source repo to other authorized owner repos for the same identifier. Those
/// target repos may now satisfy purgatory announcements even though no direct
/// push or fetch happened for the target repo path. This helper runs the normal
/// newly-available-git-data pipeline for each populated target repo so promotion
/// behavior stays centralized in this module.
pub async fn process_repos_populated_by_state_copy(
    source_repo_path: &Path,
    repo_data: &RepositoryData,
    database: &SharedDatabase,
    local_relay: Option<&nostr_relay_builder::LocalRelay>,
    purgatory: &Purgatory,
    git_data_path: &Path,
    promotion_hooks: Option<&dyn PurgatoryPromotionHooks>,
) -> ProcessResult {
    let empty_oids: HashSet<String> = HashSet::new();
    let mut aggregate = ProcessResult::default();

    for announcement in &repo_data.announcements {
        let target_repo_path = git_data_path.join(announcement.repo_path());
        if target_repo_path == source_repo_path {
            continue;
        }

        match process_newly_available_git_data(
            &target_repo_path,
            &empty_oids,
            database,
            local_relay,
            purgatory,
            git_data_path,
            promotion_hooks,
        )
        .await
        {
            Ok(result) => aggregate.merge(result),
            Err(e) => {
                aggregate.errors.push(format!(
                    "Failed to process purgatory announcements for repo {}: {}",
                    target_repo_path.display(),
                    e
                ));
            }
        }
    }

    aggregate
}

/// Process state events from purgatory that can now be applied.
///
/// This checks if we have all the git OIDs needed to apply each state event.
/// Unlike push authorization (which uses `can_satisfy_state` to check if a push
/// would transform refs correctly), this uses `can_apply_state` to simply check
/// if the required git data is available.
async fn process_purgatory_state_events(
    identifier: &str,
    source_repo_path: &Path,
    database: &SharedDatabase,
    local_relay: Option<&nostr_relay_builder::LocalRelay>,
    purgatory: &Purgatory,
    git_data_path: &Path,
    promotion_hooks: Option<&dyn PurgatoryPromotionHooks>,
) -> ProcessResult {
    let mut result = ProcessResult::default();

    // Find state events in purgatory for this identifier
    let mut purgatory_states = purgatory.find_state(identifier);
    if purgatory_states.is_empty() {
        return result;
    }

    // Sort by created_at (oldest first) so we process events in chronological order.
    // This ensures that when multiple state events are in purgatory, older ones
    // get processed first, allowing newer ones to correctly supersede them.
    purgatory_states.sort_by_key(|entry| entry.event.created_at);

    debug!(
        identifier = %identifier,
        purgatory_states_count = purgatory_states.len(),
        "Checking purgatory state events for available git data (processing oldest first)"
    );

    // Fetch repository data once for all state events
    // IMPORTANT: Use fetch_repository_data_with_purgatory to include announcements
    // that may still be in purgatory (not yet promoted). This ensures authorization
    // works correctly even if the announcement promotion happens in the same batch.
    let mut db_repo_data =
        match fetch_repository_data_with_purgatory(database, purgatory, identifier).await {
            Ok(data) => data,
            Err(e) => {
                warn!(
                    identifier = %identifier,
                    error = %e,
                    "Failed to fetch repository data for purgatory state events"
                );
                result
                    .errors
                    .push(format!("Failed to fetch repo data: {}", e));
                return result;
            }
        };

    // Process each state event in chronological order
    for entry in &purgatory_states {
        // Check if we have all the git data needed to apply this state event
        if !can_apply_state(&entry.event, source_repo_path) {
            debug!(
                identifier = %identifier,
                event_id = %entry.event.id,
                "State event cannot be applied - missing git OIDs in source repo"
            );
            continue;
        }

        // Parse the state event
        let state = match RepositoryState::from_event(entry.event.clone()) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    identifier = %identifier,
                    event_id = %entry.event.id,
                    error = %e,
                    "Failed to parse state event from purgatory"
                );
                result
                    .errors
                    .push(format!("Failed to parse state event: {}", e));
                continue;
            }
        };

        // CRITICAL: Check authorization before processing
        // State events MUST be rejected if author is not in maintainer set
        let authorized_owners = crate::git::authorization::pubkey_authorised_for_repo_owners(
            &entry.event.pubkey,
            &db_repo_data,
        );

        if authorized_owners.is_empty() {
            warn!(
                identifier = %identifier,
                event_id = %entry.event.id,
                author = %entry.event.pubkey.to_hex(),
                "Rejecting state event from purgatory: author not in maintainer set"
            );
            // Remove from purgatory - this event will never be authorized
            purgatory.remove_state_event(identifier, &entry.event.id);
            result.errors.push(format!(
                "State event {} rejected: author {} not in maintainer set",
                entry.event.id,
                entry.event.pubkey.to_hex()
            ));
            continue;
        }

        debug!(
            identifier = %identifier,
            event_id = %entry.event.id,
            author = %entry.event.pubkey.to_hex(),
            authorized_for_owners = ?authorized_owners,
            "State event author authorized via maintainer set"
        );

        // Use unified processing function
        let process_result = crate::git::process::process_state_with_git_data(
            &state,
            source_repo_path,
            &db_repo_data,
            git_data_path,
        );

        result.repos_synced += process_result.repos_synced;
        result.refs_created += process_result.refs_created;
        result.refs_updated += process_result.refs_updated;
        result.refs_deleted += process_result.refs_deleted;
        result.errors.extend(process_result.errors);

        // Check if there's a newer state from the same author in the database
        let has_newer_from_same_author = db_repo_data.states.iter().any(|s| {
            s.event.pubkey == state.event.pubkey
                && (s.event.created_at > state.event.created_at
                    || (s.event.created_at == state.event.created_at
                        && s.event.id > state.event.id))
        });

        if has_newer_from_same_author {
            // Just remove from purgatory without saving - a newer event from same author exists
            purgatory.remove_state_event(identifier, &entry.event.id);
            result.states_released += 1;

            debug!(
                identifier = %identifier,
                event_id = %entry.event.id,
                "Removed older state event from purgatory - newer event from same author exists in DB"
            );
        } else {
            // Save to database
            match save_promoted_event(
                database,
                &entry.event,
                PurgatorySaveContext::State,
                promotion_hooks,
            )
            .await
            {
                Ok(_) => {
                    info!(
                        identifier = %identifier,
                        event_id = %entry.event.id,
                        repos_synced = process_result.repos_synced,
                        "Saved purgatory state event to database"
                    );

                    if let Some(hooks) = promotion_hooks {
                        hooks.after_state_saved(&entry.event).await;
                    }

                    // Notify WebSocket subscribers
                    if let Some(relay) = local_relay {
                        if relay.notify_event(entry.event.clone()) {
                            debug!(
                                identifier = %identifier,
                                event_id = %entry.event.id,
                                "Broadcast state event to WebSocket listeners"
                            );
                        }
                    }

                    // Remove from purgatory
                    purgatory.remove_state_event(identifier, &entry.event.id);
                    result.states_released += 1;

                    // Add the newly saved state to db_repo_data so subsequent iterations
                    // can correctly determine if they're the latest
                    db_repo_data.states.push(state.clone());

                    info!(
                        identifier = %identifier,
                        event_id = %entry.event.id,
                        "Released state event from purgatory"
                    );

                    // Promote purgatory announcements for repos that received OIDs via
                    // the state event copy above.
                    //
                    // process_state_with_git_data copies OIDs from source_repo_path to every
                    // other owner repo listed in db_repo_data.announcements.  When an
                    // announcement for one of those owners is still in purgatory (e.g. the
                    // meshman announcement waiting while c03rad0's state event triggered the
                    // copy), the announcement would never be promoted because
                    // process_purgatory_announcements only promotes the owner derived from
                    // source_repo_path.  Without this promotion the purgatory expiry timer
                    // keeps running and eventually deletes the bare repo even though the
                    // announcement was effectively satisfied.
                    for announcement in &db_repo_data.announcements {
                        let target_repo_path = git_data_path.join(announcement.repo_path());
                        if target_repo_path == source_repo_path {
                            // This is the source repo — already handled by
                            // process_purgatory_announcements called before us.
                            continue;
                        }
                        let owner = &announcement.event.pubkey;
                        if let (Some(hooks), Some(entry)) = (
                            promotion_hooks,
                            purgatory.find_announcement(owner, identifier),
                        ) {
                            hooks
                                .before_announcement_promote(&entry.event, identifier)
                                .await;
                        }

                        if let Some(ann_event) = purgatory.promote_announcement(owner, identifier) {
                            match save_promoted_event(
                                database,
                                &ann_event,
                                PurgatorySaveContext::Announcement,
                                promotion_hooks,
                            )
                            .await
                            {
                                Ok(_) => {
                                    info!(
                                        identifier = %identifier,
                                        owner = %owner,
                                        event_id = %ann_event.id,
                                        "Promoted purgatory announcement for owner whose repo received OIDs via state event copy"
                                    );
                                    if let Some(hooks) = promotion_hooks {
                                        hooks.after_announcement_saved(&ann_event).await;
                                    }
                                    if let Some(relay) = local_relay {
                                        relay.notify_event(ann_event.clone());
                                    }
                                    result.announcements_released += 1;
                                }
                                Err(e) => {
                                    warn!(
                                        identifier = %identifier,
                                        owner = %owner,
                                        event_id = %ann_event.id,
                                        error = %e,
                                        "Failed to save promoted announcement to database"
                                    );
                                    result.errors.push(format!(
                                        "Failed to save promoted announcement for owner {}: {}",
                                        owner, e
                                    ));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        identifier = %identifier,
                        event_id = %entry.event.id,
                        error = %e,
                        "Failed to save state event to database"
                    );
                    result
                        .errors
                        .push(format!("Failed to save state event: {}", e));
                }
            }
        }
    }

    result
}

/// Check if a state event is the latest authorized state for a given maintainer set.
///
/// Only considers states already in the database, not other purgatory states.
///
/// # Arguments
/// * `state` - The state event to check
/// * `maintainers` - The set of authorized maintainers for the owner
/// * `db_states` - State events from the database
///
/// # Returns
/// true if this state is the latest (or equal latest) among all authorized states in the DB
fn is_latest_authorized_state(
    state: &RepositoryState,
    maintainers: &[String],
    db_states: &[RepositoryState],
) -> bool {
    // Find the latest authorized state from database
    let latest_db_state = db_states
        .iter()
        .filter(|s| maintainers.contains(&s.event.pubkey.to_hex()))
        .max_by(|a, b| {
            // Compare by created_at, then by event id for tie-breaking
            a.event
                .created_at
                .cmp(&b.event.created_at)
                .then_with(|| a.event.id.cmp(&b.event.id))
        });

    match latest_db_state {
        None => true, // No other states exist in DB, this is the latest
        Some(latest) => {
            // This state is latest if it's newer, or if equal timestamp with larger event id
            state.event.created_at > latest.event.created_at
                || (state.event.created_at == latest.event.created_at
                    && state.event.id >= latest.event.id)
        }
    }
}

/// Check if a state event is the latest authorized state for a given maintainer set.
///
/// Only considers states already in the database, not other purgatory states.
///
/// # Arguments
/// * `state` - The state event to check
/// * `maintainers` - The set of authorized maintainers for the owner
/// * `db_states` - State events from the database
///
/// # Returns
/// true if this state is the latest (or equal latest) among all authorized states in the DB
pub fn is_latest_authorized_state_public(
    state: &RepositoryState,
    maintainers: &[String],
    db_states: &[RepositoryState],
) -> bool {
    is_latest_authorized_state(state, maintainers, db_states)
}

/// Result of `process_purgatory_pr_events` — counts plus the list of
/// (event, commit) pairs that were actually released from purgatory.
///
/// The released list is consumed by the cross-service mirror branch in
/// [`process_newly_available_git_data`] so it can copy refs from a `/prs/`
/// source into matching announced repos. Standard-endpoint callers can
/// ignore the released list.
struct PrProcessingOutcome {
    result: ProcessResult,
    /// Events that were saved to the DB and removed from purgatory in this
    /// call, paired with their `c`-tag commit. Other entries (still
    /// waiting, errored, or placeholders) are not included.
    released: Vec<(Event, String)>,
}

/// Process PR events from purgatory that can now be satisfied.
async fn process_purgatory_pr_events(
    identifier: &str,
    source_repo_path: &Path,
    database: &SharedDatabase,
    local_relay: Option<&nostr_relay_builder::LocalRelay>,
    purgatory: &Purgatory,
    git_data_path: &Path,
    promotion_hooks: Option<&dyn PurgatoryPromotionHooks>,
) -> PrProcessingOutcome {
    let mut result = ProcessResult::default();
    let mut released: Vec<(Event, String)> = Vec::new();

    // Find PR events in purgatory for this identifier
    let purgatory_prs = purgatory.find_prs_for_identifier(identifier);
    if purgatory_prs.is_empty() {
        return PrProcessingOutcome { result, released };
    }

    debug!(
        identifier = %identifier,
        purgatory_prs_count = purgatory_prs.len(),
        "Checking purgatory PR events for satisfaction"
    );

    // Fetch repository data for syncing
    // NOTE: Only fetch from database, NOT purgatory. PR events should only be
    // released from purgatory when the announcement has been promoted (validated).
    // This ensures we don't accept PR events for announcements that fail validation.
    let db_repo_data = match fetch_repository_data_excluding_purgatory(database, identifier).await {
        Ok(data) => data,
        Err(e) => {
            warn!(
                identifier = %identifier,
                error = %e,
                "Failed to fetch repository data for PR events"
            );
            result
                .errors
                .push(format!("Failed to fetch repo data: {}", e));
            return PrProcessingOutcome { result, released };
        }
    };

    for entry in purgatory_prs {
        // Only process entries that have actual events (not placeholders)
        let event = match &entry.event {
            Some(e) => e,
            None => continue,
        };

        // Check if the commit exists in the source repo
        if !oid_exists(source_repo_path, &entry.commit) {
            debug!(
                identifier = %identifier,
                event_id = %event.id,
                commit = %entry.commit,
                "PR commit not available yet"
            );
            continue;
        }

        // Extract owner pubkey. For `/prs/` sources this returns None — the
        // submitter in the URL is the contributor, not a maintainer of any
        // announced repo. We pass an empty string so the tagged-owner sync
        // loop doesn't accidentally skip a real owner.
        let owner_pubkey =
            extract_owner_from_repo_path(source_repo_path, git_data_path).unwrap_or_default();

        // Use unified processing function
        let process_result = crate::git::process::process_pr_with_git_data(
            event,
            &entry.commit,
            source_repo_path,
            &db_repo_data,
            git_data_path,
            &owner_pubkey,
        );

        result.repos_synced += process_result.repos_synced;
        result.refs_created += process_result.refs_created;
        result.errors.extend(process_result.errors);

        // Save event to database
        match save_promoted_event(database, event, PurgatorySaveContext::Pr, promotion_hooks).await
        {
            Ok(_) => {
                info!(
                    identifier = %identifier,
                    event_id = %event.id,
                    "Saved purgatory PR event to database"
                );

                if let Some(hooks) = promotion_hooks {
                    hooks.after_pr_saved(event).await;
                }

                // Notify WebSocket subscribers
                if let Some(relay) = local_relay {
                    if relay.notify_event(event.clone()) {
                        debug!(
                            identifier = %identifier,
                            event_id = %event.id,
                            "Broadcast PR event to WebSocket listeners"
                        );
                    }
                }

                // Remove from purgatory
                let event_id_hex = event.id.to_hex();
                purgatory.remove_pr(&event_id_hex);
                result.prs_released += 1;
                released.push((event.clone(), entry.commit.clone()));

                info!(
                    identifier = %identifier,
                    event_id = %event.id,
                    "Released PR event from purgatory"
                );
            }
            Err(e) => {
                warn!(
                    identifier = %identifier,
                    event_id = %event.id,
                    error = %e,
                    "Failed to save PR event to database"
                );
                result
                    .errors
                    .push(format!("Failed to save PR event: {}", e));
            }
        }
    }

    PrProcessingOutcome { result, released }
}

/// Process announcements from purgatory that can now be promoted.
///
/// When git data arrives for a repository, any announcements in purgatory
/// for that repository should be promoted to the database and served to clients.
///
#[allow(clippy::too_many_arguments)]
async fn process_purgatory_announcements(
    identifier: &str,
    source_repo_path: &Path,
    database: &SharedDatabase,
    local_relay: Option<&nostr_relay_builder::LocalRelay>,
    purgatory: &Purgatory,
    git_data_path: &Path,
    promotion_hooks: Option<&dyn PurgatoryPromotionHooks>,
) -> ProcessResult {
    let mut result = ProcessResult::default();

    // Extract owner pubkey from the source repo path
    let owner_pubkey = match extract_owner_from_repo_path(source_repo_path, git_data_path) {
        Some(npub) => npub,
        None => {
            debug!(
                identifier = %identifier,
                "Could not extract owner from repo path"
            );
            return result;
        }
    };

    // Parse the npub back to PublicKey
    let owner = match nostr_sdk::prelude::PublicKey::parse(&owner_pubkey) {
        Ok(pk) => pk,
        Err(e) => {
            warn!(
                identifier = %identifier,
                owner_pubkey = %owner_pubkey,
                error = %e,
                "Failed to parse owner pubkey"
            );
            result
                .errors
                .push(format!("Failed to parse owner pubkey: {}", e));
            return result;
        }
    };

    if let (Some(hooks), Some(entry)) = (
        promotion_hooks,
        purgatory.find_announcement(&owner, identifier),
    ) {
        hooks
            .before_announcement_promote(&entry.event, identifier)
            .await;
    }

    // Check if there's an announcement in purgatory for this owner and identifier
    let announcement_event = purgatory.promote_announcement(&owner, identifier);

    if let Some(event) = announcement_event {
        // Save to database
        match save_promoted_event(
            database,
            &event,
            PurgatorySaveContext::Announcement,
            promotion_hooks,
        )
        .await
        {
            Ok(_) => {
                info!(
                    identifier = %identifier,
                    event_id = %event.id,
                    "Promoted announcement from purgatory to database"
                );

                if let Some(hooks) = promotion_hooks {
                    hooks.after_announcement_saved(&event).await;
                }

                // Notify WebSocket subscribers
                if let Some(relay) = local_relay {
                    if relay.notify_event(event.clone()) {
                        debug!(
                            identifier = %identifier,
                            event_id = %event.id,
                            "Broadcast announcement event to WebSocket listeners"
                        );
                    }
                }

                result.announcements_released += 1;
            }
            Err(e) => {
                warn!(
                    identifier = %identifier,
                    event_id = %event.id,
                    error = %e,
                    "Failed to save announcement to database"
                );
                result
                    .errors
                    .push(format!("Failed to save announcement: {}", e));
            }
        }
    }

    result
}

/// Mirror a PR event's `refs/nostr/<event-id>` (and reachable objects)
/// from a GRASP-06 `/prs/` source repo into every announced repo on this
/// relay whose coord appears in the event's `a` tags.
///
/// Triggered both by [`process_newly_available_git_data`] (event-first
/// ordering: push releases an event already waiting in purgatory) and by
/// [`crate::nostr::policy::pr_event::PrEventPolicy::git_data_check`]
/// (git-first ordering: event arrives matching a scoped placeholder that
/// an earlier `/prs/` push created). Both call sites require the source
/// repo to live under [`crate::grasp06::paths::prs_base_path`]. The
/// destination repo must (a) exist on disk and (b) have an accepted
/// announcement in the database for that coord. Absent either, nothing
/// is mirrored — the PR stays fetchable via the `clone` tag at `/prs/`.
/// See the design doc `docs/explanation/grasp-06-contributor-pr-submission.md`,
/// "Cross-service mirror" section.
///
/// Back-fill on a later announcement (i.e. an announcement accepted
/// *after* a `/prs/` push) is intentionally not handled here; the design
/// doc lists it as a follow-up.
pub(crate) async fn mirror_prs_pr_to_announced_repos(
    source_repo_path: &Path,
    event: &Event,
    commit: &str,
    database: &SharedDatabase,
    git_data_path: &Path,
    result: &mut ProcessResult,
) {
    let event_id = event.id.to_hex();
    let ref_name = format!("refs/nostr/{}", event_id);

    for tag in event.tags.iter() {
        let tag_vec = tag.clone().to_vec();
        if tag_vec.len() < 2 || tag_vec[0] != "a" || !tag_vec[1].starts_with("30617:") {
            continue;
        }
        let parts: Vec<&str> = tag_vec[1].splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let maintainer_hex = parts[1];
        let identifier = parts[2];

        let maintainer = match nostr_sdk::prelude::PublicKey::parse(maintainer_hex) {
            Ok(pk) => pk,
            Err(e) => {
                debug!(
                    event_id = %event_id,
                    a_tag = %tag_vec[1],
                    error = %e,
                    "Skipping a-tag for /prs/ mirror — maintainer pubkey unparseable"
                );
                continue;
            }
        };

        // Require an accepted announcement (DB, not purgatory) at this
        // coord. Without it we have no authoritative repo to mirror into.
        let db_data = match fetch_repository_data_excluding_purgatory(database, identifier).await {
            Ok(d) => d,
            Err(e) => {
                debug!(
                    event_id = %event_id,
                    identifier = %identifier,
                    error = %e,
                    "Skipping /prs/ mirror coord — failed to fetch announcement data"
                );
                continue;
            }
        };
        let announcement = match db_data
            .announcements
            .iter()
            .find(|a| a.event.pubkey == maintainer)
        {
            Some(a) => a,
            None => {
                debug!(
                    event_id = %event_id,
                    identifier = %identifier,
                    maintainer = %maintainer.to_hex(),
                    "No accepted announcement for /prs/ mirror coord — leaving PR at /prs/ only"
                );
                continue;
            }
        };

        let target_repo_path = git_data_path.join(announcement.repo_path());
        if !target_repo_path.exists() {
            debug!(
                event_id = %event_id,
                target = %target_repo_path.display(),
                "Announced repo path missing on disk — skipping /prs/ mirror"
            );
            continue;
        }

        if !oid_exists(&target_repo_path, commit) {
            if let Err(e) =
                copy_single_commit_between_repos(source_repo_path, &target_repo_path, commit)
            {
                warn!(
                    event_id = %event_id,
                    source = %source_repo_path.display(),
                    target = %target_repo_path.display(),
                    error = %e,
                    "Failed to copy PR commit from /prs/ to announced repo"
                );
                result.errors.push(e);
                continue;
            }
        }

        match git::update_ref(&target_repo_path, &ref_name, commit) {
            Ok(()) => {
                info!(
                    event_id = %event_id,
                    commit = %commit,
                    target = %target_repo_path.display(),
                    "Mirrored /prs/ PR ref into announced repo"
                );
                result.repos_synced += 1;
                result.refs_created += 1;
            }
            Err(e) => {
                warn!(
                    event_id = %event_id,
                    target = %target_repo_path.display(),
                    error = %e,
                    "Failed to write mirrored /prs/ PR ref into announced repo"
                );
                result.errors.push(e);
            }
        }
    }
}

///
/// For the standard endpoint layout (`{git_data_path}/{npub}/{identifier}.git`)
/// this returns the npub (as a string).
///
/// For the GRASP-06 `/prs/` layout
/// (`{git_data_path}/prs/{submitter-hex}/{identifier}.git`) there is no
/// "owner" in the announcement sense — the submitter is the contributor,
/// not a maintainer of the announced repo. `None` is returned so callers
/// can branch explicitly rather than treating the literal `"prs"` as a
/// pubkey.
pub fn extract_owner_from_repo_path(repo_path: &Path, git_data_path: &Path) -> Option<String> {
    let relative = repo_path.strip_prefix(git_data_path).ok()?;
    let components: Vec<_> = relative.components().collect();
    let first = components.first()?.as_os_str().to_str()?;
    if first == crate::grasp06::paths::PRS_DISK_PREFIX {
        // /prs/ has no owner-in-the-announcement-sense; callers must
        // handle this case explicitly.
        return None;
    }
    Some(first.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::Keys;

    #[test]
    fn test_process_result_default() {
        let result = ProcessResult::default();
        assert_eq!(result.announcements_released, 0);
        assert_eq!(result.states_released, 0);
        assert_eq!(result.prs_released, 0);
        assert_eq!(result.repos_synced, 0);
        assert!(!result.released_any());
    }

    #[test]
    fn test_process_result_released_any() {
        let mut result = ProcessResult::default();
        assert!(!result.released_any());

        result.announcements_released = 1;
        assert!(result.released_any());

        result.announcements_released = 0;
        result.states_released = 1;
        assert!(result.released_any());

        result.states_released = 0;
        result.prs_released = 1;
        assert!(result.released_any());
    }

    #[test]
    fn test_process_result_merge() {
        let mut result1 = ProcessResult {
            announcements_released: 0,
            states_released: 1,
            prs_released: 2,
            repos_synced: 3,
            refs_created: 4,
            refs_updated: 5,
            refs_deleted: 6,
            errors: vec!["error1".to_string()],
        };

        let result2 = ProcessResult {
            announcements_released: 5,
            states_released: 10,
            prs_released: 20,
            repos_synced: 30,
            refs_created: 40,
            refs_updated: 50,
            refs_deleted: 60,
            errors: vec!["error2".to_string()],
        };

        result1.merge(result2);

        assert_eq!(result1.announcements_released, 5);
        assert_eq!(result1.states_released, 11);
        assert_eq!(result1.prs_released, 22);
        assert_eq!(result1.repos_synced, 33);
        assert_eq!(result1.refs_created, 44);
        assert_eq!(result1.refs_updated, 55);
        assert_eq!(result1.refs_deleted, 66);
        assert_eq!(result1.errors.len(), 2);
    }

    #[test]
    fn test_extract_identifier_from_repo_path_valid() {
        use std::path::PathBuf;

        let git_data_path = PathBuf::from("/data/git");
        let repo_path = PathBuf::from("/data/git/npub1abc123/my-repo.git");

        let result = extract_identifier_from_repo_path(&repo_path, &git_data_path);
        assert_eq!(result, Some("my-repo".to_string()));
    }

    #[test]
    fn test_extract_identifier_from_repo_path_nested() {
        use std::path::PathBuf;

        let git_data_path = PathBuf::from("/var/lib/ngit/git");
        let repo_path = PathBuf::from("/var/lib/ngit/git/npub1xyz/ngit-grasp.git");

        let result = extract_identifier_from_repo_path(&repo_path, &git_data_path);
        assert_eq!(result, Some("ngit-grasp".to_string()));
    }

    #[test]
    fn test_extract_identifier_from_repo_path_invalid_no_git_suffix() {
        use std::path::PathBuf;

        let git_data_path = PathBuf::from("/data/git");
        let repo_path = PathBuf::from("/data/git/npub1abc123/my-repo");

        let result = extract_identifier_from_repo_path(&repo_path, &git_data_path);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_identifier_from_repo_path_invalid_wrong_depth() {
        use std::path::PathBuf;

        let git_data_path = PathBuf::from("/data/git");
        let repo_path = PathBuf::from("/data/git/my-repo.git"); // Missing npub level

        let result = extract_identifier_from_repo_path(&repo_path, &git_data_path);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_identifier_from_pr_event_valid() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

        let keys = Keys::generate();
        let tags = vec![Tag::custom(
            "a",
            vec!["30617:abc123def456:test-repo".to_string()],
        )];

        let event = EventBuilder::new(Kind::from(1618), "PR content")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let result = extract_identifier_from_pr_event(&event);
        assert_eq!(result, Some("test-repo".to_string()));
    }

    #[test]
    fn test_extract_identifier_from_pr_event_missing_tag() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

        let keys = Keys::generate();
        let tags = vec![Tag::custom("c", vec!["commit123".to_string()])];

        let event = EventBuilder::new(Kind::from(1618), "PR content")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let result = extract_identifier_from_pr_event(&event);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_identifier_from_pr_event_wrong_kind_a_tag() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

        let keys = Keys::generate();
        let tags = vec![Tag::custom(
            "a",
            vec!["30618:abc123:test-repo".to_string()], // 30618 not 30617
        )];

        let event = EventBuilder::new(Kind::from(1618), "PR content")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let result = extract_identifier_from_pr_event(&event);
        assert_eq!(result, None);
    }

    #[test]
    fn test_sync_result_default() {
        let result = SyncResult::default();
        assert_eq!(result.repos_synced, 0);
        assert_eq!(result.refs_created, 0);
        assert_eq!(result.refs_updated, 0);
        assert_eq!(result.refs_deleted, 0);
        assert_eq!(result.heads_set, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_alignment_result_default() {
        let result = AlignmentResult::default();
        assert_eq!(result.refs_created, 0);
        assert_eq!(result.refs_updated, 0);
        assert_eq!(result.refs_deleted, 0);
        assert!(!result.head_set);
    }

    #[test]
    fn test_pr_sync_result_default() {
        let result = PrSyncResult::default();
        assert_eq!(result.repos_synced, 0);
        assert_eq!(result.refs_created, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_extract_tagged_owners_from_pr_events_empty() {
        let events: Vec<Event> = vec![];
        let owners = extract_tagged_owners_from_pr_events(&events);
        assert!(owners.is_empty());
    }

    #[test]
    fn test_extract_tagged_owners_from_pr_events_with_a_tags() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

        let keys = Keys::generate();

        // Create a PR event with `a` tags referencing repos
        let tags = vec![
            Tag::custom("a", vec!["30617:abc123def456:test-repo".to_string()]),
            Tag::custom("a", vec!["30617:789xyz000111:another-repo".to_string()]),
            Tag::custom("c", vec!["commit123".to_string()]),
        ];

        let event = EventBuilder::new(Kind::from(1618), "PR content")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let owners = extract_tagged_owners_from_pr_events(&[event]);
        assert_eq!(owners.len(), 2);
        assert!(owners.contains("abc123def456"));
        assert!(owners.contains("789xyz000111"));
    }

    #[test]
    fn test_extract_tagged_owners_from_pr_events_deduplicates() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

        let keys = Keys::generate();

        // Create two events with overlapping owners
        let tags1 = vec![Tag::custom("a", vec!["30617:same_owner:repo1".to_string()])];

        let tags2 = vec![Tag::custom("a", vec!["30617:same_owner:repo2".to_string()])];

        let event1 = EventBuilder::new(Kind::from(1618), "PR 1")
            .tags(tags1)
            .finalize(&keys)
            .unwrap();

        let event2 = EventBuilder::new(Kind::from(1618), "PR 2")
            .tags(tags2)
            .finalize(&keys)
            .unwrap();

        let owners = extract_tagged_owners_from_pr_events(&[event1, event2]);
        assert_eq!(owners.len(), 1);
        assert!(owners.contains("same_owner"));
    }

    #[test]
    fn test_extract_tagged_owners_ignores_non_30617_a_tags() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

        let keys = Keys::generate();

        // Create a PR event with a non-30617 `a` tag
        let tags = vec![
            Tag::custom("a", vec!["30617:valid_owner:test-repo".to_string()]),
            Tag::custom(
                "a",
                vec!["30618:state_event:test-repo".to_string()], // Not 30617
            ),
        ];

        let event = EventBuilder::new(Kind::from(1618), "PR content")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let owners = extract_tagged_owners_from_pr_events(&[event]);
        assert_eq!(owners.len(), 1);
        assert!(owners.contains("valid_owner"));
    }

    // Helper function to create a test state event with specific timestamp
    // The `nonce` parameter ensures different events have different IDs even with same timestamp
    fn create_test_state_event_with_nonce(
        keys: &Keys,
        identifier: &str,
        created_at: u64,
        nonce: &str,
    ) -> RepositoryState {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Kind, Tag, Timestamp};

        let tags = vec![
            Tag::custom("d", vec![identifier.to_string()]),
            Tag::custom("refs/heads/main", vec![format!("abc123{}", nonce)]),
        ];

        let event = EventBuilder::new(Kind::from(30618), nonce)
            .tags(tags)
            .custom_created_at(Timestamp::from(created_at))
            .finalize(keys)
            .unwrap();

        RepositoryState::from_event(event).unwrap()
    }

    // Helper function to create a test state event with specific timestamp
    fn create_test_state_event(keys: &Keys, identifier: &str, created_at: u64) -> RepositoryState {
        create_test_state_event_with_nonce(keys, identifier, created_at, "")
    }

    #[test]
    fn test_is_latest_authorized_state_no_other_states() {
        let keys = Keys::generate();
        let state = create_test_state_event(&keys, "test-repo", 1000);
        let maintainers = vec![keys.public_key().to_hex()];

        // No other states - should be latest
        let result = is_latest_authorized_state(&state, &maintainers, &[]);
        assert!(result);
    }

    #[test]
    fn test_is_latest_authorized_state_newer_than_db() {
        let keys = Keys::generate();
        let old_state = create_test_state_event(&keys, "test-repo", 1000);
        let new_state = create_test_state_event(&keys, "test-repo", 2000);
        let maintainers = vec![keys.public_key().to_hex()];

        // new_state is newer than old_state in db
        let result = is_latest_authorized_state(&new_state, &maintainers, &[old_state]);
        assert!(result);
    }

    #[test]
    fn test_is_latest_authorized_state_older_than_db() {
        let keys = Keys::generate();
        let old_state = create_test_state_event(&keys, "test-repo", 1000);
        let new_state = create_test_state_event(&keys, "test-repo", 2000);
        let maintainers = vec![keys.public_key().to_hex()];

        // old_state is older than new_state in db
        let result = is_latest_authorized_state(&old_state, &maintainers, &[new_state]);
        assert!(!result);
    }

    #[test]
    fn test_is_latest_authorized_state_ignores_unauthorized_states() {
        let keys1 = Keys::generate();
        let keys2 = Keys::generate();

        let state1 = create_test_state_event(&keys1, "test-repo", 1000);
        let state2 = create_test_state_event(&keys2, "test-repo", 2000);

        // Only keys1 is authorized
        let maintainers = vec![keys1.public_key().to_hex()];

        // state1 should be latest because state2 is not authorized
        let result = is_latest_authorized_state(&state1, &maintainers, &[state2]);
        assert!(result);
    }

    #[test]
    fn test_is_latest_authorized_state_same_timestamp_uses_event_id() {
        let keys = Keys::generate();

        // Create two states with same timestamp but different content (different event IDs)
        let state1 = create_test_state_event_with_nonce(&keys, "test-repo", 1000, "nonce1");
        let state2 = create_test_state_event_with_nonce(&keys, "test-repo", 1000, "nonce2");

        let maintainers = vec![keys.public_key().to_hex()];

        // The one with larger event ID should be considered latest
        let (latest, older) = if state1.event.id > state2.event.id {
            (state1, state2)
        } else {
            (state2, state1)
        };

        // latest should be considered latest
        let result =
            is_latest_authorized_state(&latest, &maintainers, std::slice::from_ref(&older));
        assert!(result);

        // older should not be considered latest
        let result = is_latest_authorized_state(&older, &maintainers, &[latest]);
        assert!(!result);
    }

    #[test]
    fn test_is_latest_authorized_state_same_event_is_latest() {
        let keys = Keys::generate();
        let state = create_test_state_event(&keys, "test-repo", 1000);
        let maintainers = vec![keys.public_key().to_hex()];

        // When the state being checked is also in the db_states, it should be considered latest
        let result = is_latest_authorized_state(&state, &maintainers, std::slice::from_ref(&state));
        assert!(result);
    }
}
