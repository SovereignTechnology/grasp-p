/// PR Event Policy - PR/PR Update validation
///
/// Handles validation of NIP-34 PR events (kind 1618) and PR Update events (kind 1619)
/// according to GRASP-01 specification.
use anyhow::{bail, Result};
use nostr_sdk::prelude::Event;

use super::PolicyContext;
use crate::git;
use crate::git::authorization::{
    collect_state_maintainers_by_coordinate, fetch_repository_data_excluding_purgatory,
};
use crate::grasp06::receive::RepoInitLocks;

/// Policy for validating PR and PR Update events
#[derive(Clone)]
pub struct PrEventPolicy {
    ctx: PolicyContext,
    /// Per-path locks shared with the GRASP-06 `/prs/` receive handler for the
    /// scoped-placeholder cleanup path. This is intentionally a narrow PR-policy
    /// capability rather than part of the shared policy context.
    repo_init_locks: RepoInitLocks,
}

impl PrEventPolicy {
    pub fn new(ctx: PolicyContext, repo_init_locks: RepoInitLocks) -> Self {
        Self {
            ctx,
            repo_init_locks,
        }
    }

    /// Extract required commit metadata separately from fallible Git I/O.
    pub(crate) fn commit(event: &Event) -> Option<String> {
        event.tags.iter().find_map(|tag| {
            let values = tag.as_slice();
            (values.first().map(String::as_str) == Some("c"))
                .then(|| values.get(1).cloned())
                .flatten()
        })
    }

    /// Check if git data exists for a PR event
    ///
    /// This unified method checks for git data existence and handles:
    /// 1. Placeholder validation (git-data-first scenario)
    /// 2. Commit existence in referenced repositories
    /// 3. Deletion of incorrect refs/nostr/<event-id> refs
    /// 4. Deletion of incorrect placeholders
    /// 5. Processing PR event with unified function
    ///
    /// # Returns
    /// - `Ok(true)` if git data ready (commit exists and is synced to all repos)
    /// - `Ok(false)` if git data missing (should add to purgatory)
    /// - `Err(msg)` on errors
    pub async fn git_data_check(&self, event: &Event) -> Result<bool> {
        let event_id = event.id.to_hex();

        let commit = Self::commit(event);

        let commit = match commit {
            Some(c) => c,
            None => {
                bail!(format!("PR event {} has no 'c' tag", event_id));
            }
        };

        // A crash may happen after Git installs the ref but before the
        // purgatory checkpoint. Recover the /prs/ scope only from a signed,
        // service-local clone URL for this signer and an exact event-id/OID ref.
        let mut placeholder = self
            .ctx
            .purgatory
            .find_pr_placeholder(&event_id)
            .map(|commit| {
                let scope = self
                    .ctx
                    .purgatory
                    .find_pr(&event_id)
                    .and_then(|entry| entry.prs_scope);
                (commit, scope)
            });
        if placeholder.is_none() && self.ctx.config.grasp06_enable {
            for identifier in crate::grasp06::policy::prs_identifiers_named_by_event_clone_tags(
                event,
                &self.ctx.config.service_address(),
            ) {
                if !git::validate_repository_identifier(&identifier) {
                    continue;
                }
                let path = crate::grasp06::paths::prs_repo_path(
                    &self.ctx.git_data_path,
                    &event.pubkey.to_hex(),
                    &identifier,
                );
                if git::get_ref_commit(&path, &format!("refs/nostr/{event_id}")).as_deref()
                    == Some(commit.as_str())
                {
                    placeholder = Some((
                        commit.clone(),
                        Some(crate::purgatory::PrsPlaceholderScope {
                            submitter: event.pubkey,
                            identifier,
                        }),
                    ));
                    break;
                }
            }
        }
        if let Some((placeholder_commit, prs_scope)) = placeholder {
            if let Some(scope) = prs_scope {
                // The placeholder was created by a /prs/<submitter>/<id>.git
                // push (06.md line 12). The arriving event MUST be signed by
                // the URL submitter AND carry an `a` tag with d-tag equal to
                // the URL identifier — otherwise this event was published by
                // someone else and merely shares an id with a ref the
                // submitter pre-staged. Discarding the placeholder + ref
                // here is the security boundary; the event itself is left
                // to continue through the normal acceptance flow (which may
                // still legitimately accept it via the GRASP-06 relaxation
                // in `src/nostr/builder.rs` or, if announced, the standard
                // GRASP-01 path).
                let event_d_tags: std::collections::HashSet<String> = event
                    .tags
                    .iter()
                    .filter_map(|tag| {
                        let tag_vec = tag.clone().to_vec();
                        if tag_vec.len() >= 2
                            && tag_vec[0] == "a"
                            && tag_vec[1].starts_with("30617:")
                        {
                            let parts: Vec<&str> = tag_vec[1].splitn(3, ':').collect();
                            if parts.len() == 3 {
                                return Some(parts[2].to_string());
                            }
                        }
                        None
                    })
                    .collect();

                let signer_matches = event.pubkey == scope.submitter;
                let identifier_matches = event_d_tags.contains(&scope.identifier);
                let commit_matches = placeholder_commit == commit;

                if !signer_matches || !identifier_matches || !commit_matches {
                    tracing::warn!(
                        event_id = %event_id,
                        signer_matches,
                        identifier_matches,
                        commit_matches,
                        submitter = %scope.submitter.to_hex(),
                        identifier = %scope.identifier,
                        "Discarding scoped /prs/ PR placeholder — incoming event does not match URL submitter + identifier",
                    );

                    // Delete the ref the original /prs/ push wrote, and if
                    // that leaves the bare repo with zero refs *and no
                    // push is in flight to this path*, delete the
                    // directory too. The per-path mutex is held only for
                    // the brief delete-and-check window — concurrent
                    // pushes increment `in_flight` under the same mutex,
                    // so seeing `in_flight == 0` while holding the lock
                    // is a safe signal that no push is mid-receive.
                    let prs_repo = crate::grasp06::paths::prs_repo_path(
                        &self.ctx.git_data_path,
                        &scope.submitter.to_hex(),
                        &scope.identifier,
                    );
                    let ref_name = format!("refs/nostr/{}", event_id);
                    if prs_repo.exists() {
                        let state =
                            crate::grasp06::receive::path_state(&self.repo_init_locks, &prs_repo);
                        let _guard = state.mu.lock().expect("prs path mutex poisoned");

                        if let Err(e) = crate::git::delete_ref(&prs_repo, &ref_name) {
                            tracing::warn!(
                                event_id = %event_id,
                                repo = %prs_repo.display(),
                                error = %e,
                                "Failed to delete /prs/ ref while discarding scoped placeholder",
                            );
                        } else if state.in_flight.load(std::sync::atomic::Ordering::Relaxed) == 0
                            && matches!(
                                crate::git::list_refs(&prs_repo),
                                Ok(refs) if refs.is_empty()
                            )
                        {
                            // No refs left and no push in flight — the
                            // repo is now an empty husk. Drop the bare
                            // dir so /prs/ doesn't accumulate abandoned
                            // repos. Equivalent to the cleanup the
                            // receive handler does on push completion.
                            if let Err(e) = std::fs::remove_dir_all(&prs_repo) {
                                tracing::warn!(
                                    repo = %prs_repo.display(),
                                    error = %e,
                                    "Failed to remove zero-ref /prs/ repo after discarding scoped placeholder",
                                );
                            } else {
                                tracing::debug!(
                                    repo = %prs_repo.display(),
                                    "Removed zero-ref /prs/ repo after discarding scoped placeholder",
                                );
                            }
                        }
                    }
                    self.ctx.purgatory.remove_pr(&event_id);

                    // Fall through: this arriving event was NOT served by
                    // the placeholder. The standard processing below treats
                    // it like any other PR event (find_relevant_repo_paths,
                    // commit lookup, etc).
                } else {
                    // Scope match. The /prs/ push's ref is locked by the
                    // signed event, and the event must be promoted now —
                    // not re-purgatorised — so subscribers see it
                    // immediately and the cross-service mirror fires
                    // while the source repo is still on disk.
                    //
                    // This branch is the git-first counterpart to the
                    // promotion that `process_newly_available_git_data`
                    // performs on the event-first ordering (called from
                    // [`crate::grasp06::receive::handle_prs_receive_pack`]).
                    // Both code paths must converge on the same observable
                    // outcome: event saved to the DB, broadcast to
                    // subscribers, and `refs/nostr/<event-id>` mirrored
                    // into every accepted announcement on this relay
                    // whose coord appears in the event's `a` tags.
                    let prs_repo = crate::grasp06::paths::prs_repo_path(
                        &self.ctx.git_data_path,
                        &scope.submitter.to_hex(),
                        &scope.identifier,
                    );

                    // `process_pr_with_git_data` handles the tagged-owner
                    // sync path (a `/prs/` contributor who *also* happens
                    // to be a tagged maintainer of some other announced
                    // repo on this relay). For typical contributor pushes
                    // this is a no-op; we run it for symmetry with the
                    // event-first path in `process_newly_available_git_data`.
                    let db_repo_data = fetch_repository_data_excluding_purgatory(
                        &self.ctx.database,
                        &scope.identifier,
                    )
                    .await?;

                    let process_result = crate::git::process::process_pr_with_git_data(
                        event,
                        &commit,
                        &prs_repo,
                        &db_repo_data,
                        &self.ctx.git_data_path,
                        // /prs/ has no owner-in-the-maintainer-sense; pass
                        // empty so the tagged-owner sync doesn't skip a
                        // real maintainer by accident (see
                        // [`crate::git::sync::extract_owner_from_repo_path`]
                        // which returns None for /prs/).
                        "",
                    );

                    // GRASP-06 cross-service mirror: copy the ref + commit
                    // into every accepted-announcement repo whose coord
                    // appears in the event's `a` tags. No-op when no such
                    // announcement exists locally — the PR is then served
                    // only from `/prs/`, which the spec allows.
                    let mut mirror_result = crate::git::sync::ProcessResult::default();
                    crate::git::sync::mirror_prs_pr_to_announced_repos(
                        &prs_repo,
                        event,
                        &commit,
                        &self.ctx.database,
                        &self.ctx.git_data_path,
                        &mut mirror_result,
                    )
                    .await;

                    self.ctx.purgatory.remove_pr(&event_id);

                    tracing::info!(
                        event_id = %event_id,
                        commit = %commit,
                        submitter = %scope.submitter.to_hex(),
                        identifier = %scope.identifier,
                        tagged_repos_synced = process_result.repos_synced,
                        mirrored_to_announced_repos = mirror_result.repos_synced,
                        "Promoted GRASP-06 PR event matching scoped /prs/ placeholder (git-first)",
                    );

                    // Ok(true) makes the write policy Accept this event,
                    // which routes through the nostr-relay-builder
                    // framework's normal save+broadcast path. We do not
                    // re-add the event to purgatory.
                    return Ok(true);
                }
            } else if placeholder_commit == commit {
                // Standard endpoint placeholder, matching commit — original
                // behaviour.
                tracing::debug!(
                    "Found matching placeholder for PR event {} with commit {}",
                    event_id,
                    commit
                );
                self.ctx.purgatory.remove_pr(&event_id);
            } else {
                // Standard endpoint placeholder, mismatched commit — original
                // behaviour: incoming event supersedes.
                tracing::info!(
                    "PR event {} supersedes placeholder: event expects commit {}, placeholder has {}",
                    event_id,
                    commit,
                    placeholder_commit
                );
                self.ctx.purgatory.remove_pr(&event_id);
                // Delete incorrect git data (refs/nostr/<event-id>) will be handled below
            }
        }

        let repo_paths = self.find_relevant_repo_paths(event).await?;

        if repo_paths.is_empty() {
            tracing::debug!("No repository paths found for PR event {}", event_id);
            return Ok(false);
        }

        // Delete incorrect refs/nostr/<event-id>
        for repo_path in &repo_paths {
            match git::validate_nostr_ref(repo_path, &event_id, &commit) {
                Ok(true) => {
                    tracing::info!(
                        "Deleted mismatched refs/nostr/{} in {}",
                        event_id,
                        repo_path.display()
                    );
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(
                        "Failed to validate refs/nostr/{} in {}: {}",
                        event_id,
                        repo_path.display(),
                        e
                    );
                }
            }
        }

        // Find location of correct git data (if exists)
        let mut source_repo: Option<std::path::PathBuf> = None;
        for repo_path in &repo_paths {
            if git::commit_exists(repo_path, &commit) {
                source_repo = Some(repo_path.clone());
                tracing::debug!(
                    "Found commit {} in repository {}",
                    commit,
                    repo_path.display()
                );
                break;
            }
        }

        if let Some(source_repo) = source_repo {
            // Extract identifier
            let identifier = crate::git::sync::extract_identifier_from_pr_event(event)
                .ok_or_else(|| anyhow::anyhow!("No identifier in PR event"))?;

            // Fetch repository data
            // NOTE: Only fetch from database, NOT purgatory. Incoming PR events should
            // only be accepted for announcements that have been promoted (validated).
            // If the announcement is still in purgatory, the PR event should also go
            // to purgatory and wait for the announcement to be promoted.
            let db_repo_data =
                fetch_repository_data_excluding_purgatory(&self.ctx.database, &identifier).await?;

            // Extract owner pubkey from source repo path
            let owner_pubkey = crate::git::sync::extract_owner_from_repo_path(
                &source_repo,
                &self.ctx.git_data_path,
            )
            .unwrap_or_default();

            // Use unified processing function
            let result = crate::git::process::process_pr_with_git_data(
                event,
                &commit,
                &source_repo,
                &db_repo_data,
                &self.ctx.git_data_path,
                &owner_pubkey,
            );

            tracing::info!(
                identifier = %identifier,
                event_id = %event_id,
                repos_synced = result.repos_synced,
                refs_created = result.refs_created,
                "Processed PR event with git data already available"
            );

            if !result.errors.is_empty() {
                for error in &result.errors {
                    tracing::warn!(
                        identifier = %identifier,
                        event_id = %event_id,
                        error = %error,
                        "Error processing PR event"
                    );
                }
            }

            Ok(true)
        } else {
            tracing::debug!(
                "No git data found for PR event {} with commit {}",
                event_id,
                commit
            );
            Ok(false)
        }
    }

    async fn find_relevant_repo_paths(&self, event: &Event) -> Result<Vec<std::path::PathBuf>> {
        // Extract ALL `a` tags (repository references) from the PR event
        let repo_refs: Vec<String> = event
            .tags
            .iter()
            .filter_map(|tag| {
                let tag_vec = tag.clone().to_vec();
                if tag_vec.len() >= 2 && tag_vec[0] == "a" && tag_vec[1].starts_with("30617:") {
                    Some(tag_vec[1].clone())
                } else {
                    None
                }
            })
            .collect();

        if repo_refs.is_empty() {
            return Ok(Vec::new());
        }

        // 1. Find identifier from first a tag starting with "30617:"
        let parts: Vec<&str> = repo_refs[0].split(':').collect();
        if parts.len() < 3 {
            return Err(anyhow::anyhow!("Invalid repository reference format"));
        }
        let identifier = parts[2];

        // 2. Fetch repo data
        // NOTE: Only fetch from database, NOT purgatory. Incoming PR events should
        // only be accepted for announcements that have been promoted (validated).
        // If the announcement is still in purgatory, the PR event should also go
        // to purgatory and wait for the announcement to be promoted.
        let db_repo_data =
            fetch_repository_data_excluding_purgatory(&self.ctx.database, identifier).await?;

        // 3. Extract list of maintainers from "a 30617:<maintainer>:<identifier>" tags
        let mut maintainer_pubkeys = std::collections::HashSet::new();
        for repo_ref in &repo_refs {
            let parts: Vec<&str> = repo_ref.split(':').collect();
            if parts.len() >= 2 {
                maintainer_pubkeys.insert(parts[1].to_string());
            }
        }

        // 4. Identify owner repos that list any of the maintainers using this function
        let by_owner = collect_state_maintainers_by_coordinate(&db_repo_data.announcements);

        // 5. Return the repo_path for each owner whose authorized maintainers include any of our maintainers
        let mut repo_paths = Vec::new();
        for announcement in &db_repo_data.announcements {
            let owner_pubkey = announcement.event.pubkey.to_hex();

            // Check if this owner's authorized maintainers overlap with our maintainer list
            if let Some(authorized_maintainers) = by_owner.get(&owner_pubkey) {
                let has_overlap = authorized_maintainers
                    .iter()
                    .any(|m| maintainer_pubkeys.contains(m));

                if has_overlap {
                    let repo_path = self.ctx.git_data_path.join(announcement.repo_path());
                    repo_paths.push(repo_path);
                }
            }
        }

        Ok(repo_paths)
    }
}
