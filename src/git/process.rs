//! Event Processing - Unified logic for processing state and PR events with git data
//!
//! This module provides the core processing logic used when events have git data available.
//! These functions are used in multiple scenarios:
//! - When events arrive with git data already available (policy handlers)
//! - When events are released from purgatory (purgatory sync)
//! - When git pushes trigger purgatory releases (receive-pack handler)

use crate::git;
use crate::git::authorization::{collect_authorized_maintainers, RepositoryData};
use crate::git::sync::{
    align_repository_with_state, copy_missing_oids_between_repos,
    sync_pr_refs_to_tagged_owner_repos,
};
use crate::nostr::events::RepositoryState;
use nostr_sdk::prelude::Event;
use std::path::Path;

/// Result of processing a state event with git data
#[derive(Debug, Default, Clone)]
pub struct ProcessStateResult {
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

/// Result of processing a PR event with git data
#[derive(Debug, Default, Clone)]
pub struct ProcessPrResult {
    /// Number of repositories synced
    pub repos_synced: usize,
    /// Number of refs created across all repos
    pub refs_created: usize,
    /// Errors encountered (non-fatal)
    pub errors: Vec<String>,
}

/// Process a single state event that has git data available.
///
/// This is the core processing logic used when:
/// - A state event arrives with git data already available
/// - A state event is released from purgatory
///
/// Does NOT save to database or notify subscribers - caller handles that.
///
/// # Processing Steps
/// 1. Identify owner repos where state author is an authorized maintainer
/// 2. For each owner repo, check if this state is the latest authorized
/// 3. Copy missing OIDs from source repo to target repo
/// 4. Align refs (branches, tags, HEAD) with the state
///
/// # Arguments
/// * `state` - The state event to process
/// * `source_repo_path` - Path to repo that has the git data
/// * `db_repo_data` - Repository data from database (announcements + states)
/// * `git_data_path` - Base path for git repositories
///
/// # Returns
/// ProcessStateResult with statistics
pub fn process_state_with_git_data(
    state: &RepositoryState,
    source_repo_path: &Path,
    db_repo_data: &RepositoryData,
    git_data_path: &Path,
) -> ProcessStateResult {
    let mut result = ProcessStateResult::default();

    let state_author = state.event.pubkey.to_hex();

    // Collect authorized maintainers per owner
    let by_owner = collect_authorized_maintainers(&db_repo_data.announcements);

    // Step 1: Identify owner repos that the state event author is maintainer for
    let authorized_owners: Vec<&String> = by_owner
        .iter()
        .filter(|(_, maintainers)| maintainers.contains(&state_author))
        .map(|(owner, _)| owner)
        .collect();

    if authorized_owners.is_empty() {
        tracing::debug!(
            identifier = %state.identifier,
            author = %state_author,
            "State event author not authorized for any owner"
        );
        return result;
    }

    // Process each owner repo that authorizes this state event author
    for owner in &authorized_owners {
        let maintainers = by_owner.get(*owner).unwrap();

        // Step 2: Check if this state event is the latest authorized for this owner
        let is_latest = crate::git::sync::is_latest_authorized_state_public(
            state,
            maintainers,
            &db_repo_data.states,
        );

        if !is_latest {
            tracing::debug!(
                identifier = %state.identifier,
                owner = %owner,
                "Skipping owner - newer authorized state exists"
            );
            continue;
        }

        // Find the announcement for this owner
        let Some(announcement) = db_repo_data
            .announcements
            .iter()
            .find(|a| a.event.pubkey.to_hex() == **owner)
        else {
            continue;
        };

        let target_repo_path = git_data_path.join(announcement.repo_path());

        // Step 3: Check git repo exists for that owner
        if !target_repo_path.exists() {
            tracing::debug!(
                identifier = %state.identifier,
                owner = %owner,
                repo_path = %target_repo_path.display(),
                "Skipping owner - repository doesn't exist"
            );
            continue;
        }

        // Step 4: Copy all required OIDs to that repo (unless it's source_repo_path)
        if target_repo_path != source_repo_path {
            if let Err(e) =
                copy_missing_oids_between_repos(source_repo_path, &target_repo_path, state)
            {
                tracing::warn!(
                    identifier = %state.identifier,
                    source = %source_repo_path.display(),
                    target = %target_repo_path.display(),
                    error = %e,
                    "Failed to copy OIDs between repos"
                );
                result.errors.push(e);
                continue; // Skip this owner repo
            }
        }

        // Step 5: Reset the git state in that repo to match the state event
        let align_result = align_repository_with_state(&target_repo_path, state);
        result.repos_synced += 1;
        result.refs_created += align_result.refs_created;
        result.refs_updated += align_result.refs_updated;
        result.refs_deleted += align_result.refs_deleted;

        tracing::info!(
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

    result
}

/// Process a single PR event that has git data available.
///
/// This is the core processing logic used when:
/// - A PR event arrives with git data already available
/// - A PR event is released from purgatory
///
/// Does NOT save to database or notify subscribers - caller handles that.
///
/// # Processing Steps
/// 1. Sync PR commit to owner repos using tagged maintainer logic
/// 2. Create refs/nostr/<event-id> ref in source repo (if missing)
/// 3. Create refs/nostr/<event-id> refs in all synced repos
///
/// # Arguments
/// * `event` - The PR event to process
/// * `commit` - The commit hash from the PR event
/// * `source_repo_path` - Path to repo that has the commit
/// * `db_repo_data` - Repository data from database (announcements + states)
/// * `git_data_path` - Base path for git repositories
/// * `source_owner_pubkey` - Owner pubkey of source repo (to skip)
///
/// # Returns
/// ProcessPrResult with statistics
pub fn process_pr_with_git_data(
    event: &Event,
    commit: &str,
    source_repo_path: &Path,
    db_repo_data: &RepositoryData,
    git_data_path: &Path,
    source_owner_pubkey: &str,
) -> ProcessPrResult {
    let mut result = ProcessPrResult::default();

    let event_id = event.id.to_hex();

    // Sync PR ref to owner repos using tagged maintainer logic
    let pr_refs = vec![(event_id.clone(), commit.to_string())];
    let pr_events = vec![event.clone()];

    let sync_result = sync_pr_refs_to_tagged_owner_repos(
        source_repo_path,
        &pr_refs,
        &pr_events,
        db_repo_data,
        git_data_path,
        source_owner_pubkey,
    );
    result.repos_synced += sync_result.repos_synced;
    result.refs_created += sync_result.refs_created;
    result
        .errors
        .extend(sync_result.errors.into_iter().map(|(_, e)| e));

    // Create the ref in the source repo if it doesn't exist
    let ref_name = format!("refs/nostr/{}", event_id);
    if git::get_ref_commit(source_repo_path, &ref_name).is_none() {
        if let Err(e) = git::update_ref(source_repo_path, &ref_name, commit) {
            tracing::warn!(
                event_id = %event_id,
                repo = %source_repo_path.display(),
                error = %e,
                "Failed to create PR ref in source repo"
            );
            result.errors.push(e);
        } else {
            result.refs_created += 1;
            tracing::info!(
                event_id = %event_id,
                commit = %commit,
                repo = %source_repo_path.display(),
                "Created PR ref in source repo"
            );
        }
    }

    result
}
