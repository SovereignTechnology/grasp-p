use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nostr_relay_builder::builder::WritePolicyResult;
/// State Policy - State event validation + ref alignment
///
/// Handles validation of NIP-34 repository state events (kind 30618)
/// and aligns git refs with authorized state according to GRASP-01.
use nostr_relay_builder::prelude::Event;

use super::{accepted_purgatory, duplicate, reject_invalid, reject_restricted, PolicyContext};
use crate::git;
use crate::git::authorization::fetch_repository_data_with_purgatory;
use crate::nostr::events::{validate_state, RepositoryAnnouncement, RepositoryState};

/// Result of state policy evaluation
#[derive(Debug)]
pub enum StateResult {
    /// Accept: Event passes validation
    Accept,
    /// Reject: Event fails validation with reason
    Reject(String),
}

/// Policy for validating repository state events and aligning refs
#[derive(Clone)]
pub struct StatePolicy {
    ctx: PolicyContext,
}

impl StatePolicy {
    pub fn new(ctx: PolicyContext) -> Self {
        Self { ctx }
    }

    /// Validate a repository state event
    pub fn validate(&self, event: &Event) -> StateResult {
        match validate_state(event) {
            Ok(_) => StateResult::Accept,
            Err(e) => StateResult::Reject(e.to_string()),
        }
    }

    /// Process a state event: validate and align owner repositories
    ///
    /// # Arguments
    /// * `event` - The state event to process
    /// * `is_synced` - True if this event came from proactive sync (vs user-submitted)
    ///
    /// Returns the true if git data already availale or false if added to purgatory
    pub async fn process_state_event(
        &self,
        event: &Event,
        is_synced: bool,
    ) -> Result<WritePolicyResult> {
        // Parse state to get HEAD and branch info
        let state =
            RepositoryState::from_event(event.clone()).context("Failed to parse state event")?;

        // Duplicate check in purgatory
        if self
            .ctx
            .purgatory
            .find_state(&state.identifier)
            .iter()
            .any(|e| e.event.id.eq(&event.id))
        {
            tracing::debug!(
                "processed state event duplicate (already in purgatory): {}",
                event.id,
            );
            return Ok(duplicate("in purgatory"));
        }

        // Get all repositories and state events from db with identifier
        // Include purgatory announcements for authorization
        let db_repo_data = fetch_repository_data_with_purgatory(
            &self.ctx.database,
            &self.ctx.purgatory,
            &state.identifier,
        )
        .await?;

        // CRITICAL: Check if author is authorized via maintainer set
        // State events MUST be rejected if author is not in maintainer set of any accepted announcement
        if db_repo_data.announcements.is_empty() {
            if is_synced {
                tracing::debug!(
                    event_id = %event.id,
                    identifier = %state.identifier,
                    author = %event.pubkey.to_hex(),
                    "Rejecting state event: no announcement exists for this repository"
                );
            } else {
                tracing::warn!(
                    event_id = %event.id,
                    identifier = %state.identifier,
                    author = %event.pubkey.to_hex(),
                    "Rejecting state event: no announcement exists for this repository"
                );
            }
            return Ok(reject_invalid("no announcement exists for this repository"));
        }

        let authorized_owners = crate::git::authorization::pubkey_authorised_for_repo_owners(
            &event.pubkey,
            &db_repo_data,
        );

        if authorized_owners.is_empty() {
            if is_synced {
                tracing::debug!(
                    event_id = %event.id,
                    identifier = %state.identifier,
                    author = %event.pubkey.to_hex(),
                    announcements_count = db_repo_data.announcements.len(),
                    "Rejecting state event: author not in maintainer set of any announcement"
                );
            } else {
                tracing::warn!(
                    event_id = %event.id,
                    identifier = %state.identifier,
                    author = %event.pubkey.to_hex(),
                    announcements_count = db_repo_data.announcements.len(),
                    "Rejecting state event: author not in maintainer set of any announcement"
                );
            }
            return Ok(reject_restricted("author not authorized for this repository"));
        }

        tracing::debug!(
            event_id = %event.id,
            identifier = %state.identifier,
            author = %event.pubkey.to_hex(),
            authorized_for_owners = ?authorized_owners,
            "State event author authorized via maintainer set"
        );

        // Extend expiry for any purgatory announcements for this identifier.
        //
        // Per design doc decision #4: state event arrival extends the purgatory
        // announcement's expiry (reset the 30-minute protocol timer). This prevents
        // premature expiry during slow sync operations — the repo is actively receiving
        // metadata so it should stay alive.
        //
        // We extend for all owners that authorized this state event, since the state
        // event proves the repo is active regardless of which owner's announcement
        // authorized it.
        for owner_hex in &authorized_owners {
            if let Ok(owner_pk) = nostr_sdk::prelude::PublicKey::from_hex(owner_hex) {
                if self
                    .ctx
                    .purgatory
                    .has_purgatory_announcement(&owner_pk, &state.identifier)
                {
                    self.ctx.purgatory.extend_announcement_expiry(
                        &owner_pk,
                        &state.identifier,
                        std::time::Duration::from_secs(1800),
                    );
                    tracing::debug!(
                        event_id = %event.id,
                        identifier = %state.identifier,
                        owner = %owner_hex,
                        "Extended purgatory announcement expiry due to state event arrival"
                    );
                }
            }
        }

        // Duplicate check in db
        if db_repo_data.states.iter().any(|e| e.event.id.eq(&event.id)) {
            tracing::debug!("processed state event duplicate (in db): {}", event.id);
            return Ok(duplicate("already have this event"));
        }

        // Check if git data is available
        if let Some(repo_with_git_data) =
            find_repo_with_git_data(&db_repo_data.announcements, &state, &self.ctx.git_data_path)
        {
            tracing::debug!(
                "processing state event as git data already available: {}",
                event.id,
            );

            // Use unified processing function
            let result = crate::git::process::process_state_with_git_data(
                &state,
                &repo_with_git_data,
                &db_repo_data,
                &self.ctx.git_data_path,
            );

            tracing::info!(
                identifier = %state.identifier,
                event_id = %event.id,
                repos_synced = result.repos_synced,
                refs_created = result.refs_created,
                refs_updated = result.refs_updated,
                refs_deleted = result.refs_deleted,
                "Processed state event with git data already available"
            );

            if !result.errors.is_empty() {
                for error in &result.errors {
                    tracing::warn!(
                        identifier = %state.identifier,
                        event_id = %event.id,
                        error = %error,
                        "Error processing state event"
                    );
                }
            }

            // After copying OIDs to other owner repos, promote any purgatory announcements
            // for those repos. This handles the case where two maintainers push to the same
            // identifier on the same relay with identical commit hashes: the second maintainer's
            // announcement sits in purgatory, and when their state event arrives the relay copies
            // commits from the first maintainer's repo — but without this call the announcement
            // would stay in purgatory indefinitely.
            let local_relay = self.ctx.get_local_relay();
            let empty_oids: HashSet<String> = HashSet::new();
            for announcement in &db_repo_data.announcements {
                let target_repo_path = self.ctx.git_data_path.join(announcement.repo_path());
                if target_repo_path != repo_with_git_data {
                    // OIDs were copied to this repo by process_state_with_git_data;
                    // check if there's a purgatory announcement waiting for it.
                    if let Err(e) = crate::git::sync::process_newly_available_git_data(
                        &target_repo_path,
                        &empty_oids,
                        &self.ctx.database,
                        local_relay.as_ref(),
                        &self.ctx.purgatory,
                        &self.ctx.git_data_path,
                        None,
                        None,
                    )
                    .await
                    {
                        tracing::warn!(
                            identifier = %state.identifier,
                            event_id = %event.id,
                            repo_path = %target_repo_path.display(),
                            error = %e,
                            "Failed to process purgatory announcements for target repo after git sync copy"
                        );
                    }
                }
            }

            // Event will be saved and broadcast by relay builder
            Ok(WritePolicyResult::Accept)
        } else {
            // Only reject expired events if they're from sync (not user-submitted)
            // User-submitted events should be allowed to retry in case git data became available
            if is_synced && self.ctx.purgatory.is_expired(&event.id) {
                tracing::debug!(
                    event_id = %event.id,
                    identifier = %state.identifier,
                    "State event previously expired from purgatory (synced), rejecting to prevent re-sync loop"
                );
                return Ok(reject_invalid(
                    "previously expired from purgatory without git data",
                ));
            }

            // If no git data - add to purgatory
            // (add_state automatically enqueues for background sync)
            self.ctx.purgatory.add_state(
                event.clone(),
                state.identifier.clone(),
                event.pubkey,
                is_synced,
            );

            tracing::info!(
                "state event added to purgatory: eventid: {}, identifier: {}",
                state.event.id,
                state.identifier,
            );
            Ok(accepted_purgatory("won't be served until git data arrives"))
        }
    }
}

fn find_repo_with_git_data(
    announcements: &[RepositoryAnnouncement],
    state: &RepositoryState,
    git_data_path: &Path,
) -> Option<PathBuf> {
    for announcement in announcements {
        let repo_path = git_data_path.join(announcement.repo_path().clone());
        if state.branches.iter().all(|branch_state| {
            if branch_state.commit.starts_with("ref: ") {
                true // ignore symlinks
            } else {
                git::oid_exists(&repo_path, &branch_state.commit)
            }
        }) && state
            .tags
            .iter()
            .all(|tag_state| git::oid_exists(&repo_path, &tag_state.commit))
        {
            return Some(repo_path);
        }
    }
    None
}
