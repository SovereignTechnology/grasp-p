/// Deletion Recovery - repository and event restoration from holding/archive
///
/// Owns all logic for recovering a deleted repository scope back into the live
/// relay state:
/// - git archive extraction and staging
/// - archived nostr-ref restoration into an existing bare repository
/// - PR git-ref restoration and cleanup
/// - event payload restoration from the holding DB into the main DB
/// - tombstone-blocked event detection
/// - holding metadata cleanup after successful recovery
use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::read::GzDecoder;
use nostr_relay_builder::prelude::{Event, Kind, PublicKey, Timestamp};
use tar::Archive as TarArchive;

use super::DeletionService;
use crate::nostr::holding::RecoveryMetadataRecord;

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

impl DeletionService {
    pub(crate) fn owner_directory_component(pubkey: &PublicKey) -> String {
        use nostr::nips::nip19::ToBech32;
        pubkey.to_bech32().unwrap_or_else(|_| pubkey.to_hex())
    }

    pub(crate) fn repo_path_for_owner_and_identifier(
        &self,
        owner_path_component: &str,
        identifier: &str,
    ) -> PathBuf {
        self.ctx
            .git_data_path
            .join(owner_path_component)
            .join(format!("{}.git", identifier))
    }
}

// ---------------------------------------------------------------------------
// Git archive restoration
// ---------------------------------------------------------------------------

impl DeletionService {
    pub(crate) fn restore_git_archive_to_repo(
        &self,
        archive_path: &Path,
        owner_path_component: &str,
        identifier: &str,
    ) -> anyhow::Result<bool> {
        let target_repo = self.repo_path_for_owner_and_identifier(owner_path_component, identifier);

        let owner_dir = target_repo
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid repository path {}", target_repo.display()))?;
        std::fs::create_dir_all(owner_dir).map_err(|e| {
            anyhow::anyhow!(
                "failed to create owner directory {}: {}",
                owner_dir.display(),
                e
            )
        })?;

        let staging_dir = owner_dir.join(format!(
            ".restore-{}-{}",
            identifier,
            Timestamp::now().as_secs()
        ));
        if staging_dir.exists() {
            let _ = std::fs::remove_dir_all(&staging_dir);
        }
        std::fs::create_dir_all(&staging_dir).map_err(|e| {
            anyhow::anyhow!(
                "failed to create restore staging directory {}: {}",
                staging_dir.display(),
                e
            )
        })?;

        let result = (|| -> anyhow::Result<bool> {
            let archive_file = File::open(archive_path).map_err(|e| {
                anyhow::anyhow!("failed to open archive {}: {}", archive_path.display(), e)
            })?;
            let decoder = GzDecoder::new(archive_file);
            let mut tar = TarArchive::new(decoder);
            tar.unpack(&staging_dir).map_err(|e| {
                anyhow::anyhow!(
                    "failed to extract archive {} into {}: {}",
                    archive_path.display(),
                    staging_dir.display(),
                    e
                )
            })?;

            let extracted_repo = staging_dir.join(format!("{}.git", identifier));
            if !extracted_repo.is_dir() {
                return Err(anyhow::anyhow!(
                    "archive {} did not contain {}.git",
                    archive_path.display(),
                    identifier
                ));
            }

            if target_repo.is_dir() {
                return Self::restore_archived_nostr_refs(&extracted_repo, &target_repo);
            }

            std::fs::rename(&extracted_repo, &target_repo)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to move restored repository {} -> {}: {}",
                        extracted_repo.display(),
                        target_repo.display(),
                        e
                    )
                })
                .map(|_| true)
        })();

        let _ = std::fs::remove_dir_all(&staging_dir);
        result
    }

    fn restore_archived_nostr_refs(source_repo: &Path, target_repo: &Path) -> anyhow::Result<bool> {
        let source_repo_str = source_repo
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid source repo path {}", source_repo.display()))?;

        let list_output = Command::new("git")
            .args([
                "--git-dir",
                source_repo_str,
                "for-each-ref",
                "--format=%(objectname) %(refname)",
                "refs/nostr/",
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("failed to list archived refs/nostr: {e}"))?;

        if !list_output.status.success() {
            let stderr = String::from_utf8_lossy(&list_output.stderr);
            return Err(anyhow::anyhow!(
                "failed listing archived refs/nostr from {}: {}",
                source_repo.display(),
                stderr
            ));
        }

        let stdout = String::from_utf8_lossy(&list_output.stdout);
        let mut restored_any = false;

        for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
            let Some((oid, ref_name)) = line.split_once(' ') else {
                continue;
            };

            if !crate::git::oid_exists(target_repo, oid) {
                let fetch_output = Command::new("git")
                    .args(["fetch", source_repo_str, oid])
                    .current_dir(target_repo)
                    .output()
                    .map_err(|e| anyhow::anyhow!("failed to fetch archived OID {oid}: {e}"))?;
                if !fetch_output.status.success() {
                    let stderr = String::from_utf8_lossy(&fetch_output.stderr);
                    return Err(anyhow::anyhow!(
                        "failed fetching archived OID {} into {}: {}",
                        oid,
                        target_repo.display(),
                        stderr
                    ));
                }
            }

            crate::git::update_ref(target_repo, ref_name, oid).map_err(|e| {
                anyhow::anyhow!(
                    "failed to restore archived ref {} -> {} into {}: {}",
                    ref_name,
                    oid,
                    target_repo.display(),
                    e
                )
            })?;
            restored_any = true;
        }

        Ok(restored_any)
    }
}

// ---------------------------------------------------------------------------
// PR git-ref helpers
// ---------------------------------------------------------------------------

impl DeletionService {
    fn pr_event_commit(event: &Event) -> Option<String> {
        event.tags.iter().find_map(|tag| {
            let parts = tag.as_slice();
            if parts.len() >= 2 && parts[0] == "c" {
                Some(parts[1].clone())
            } else {
                None
            }
        })
    }

    fn pr_event_identifiers(event: &Event) -> BTreeSet<String> {
        Self::pr_event_announcement_scopes(event)
            .into_iter()
            .map(|(_, identifier)| identifier)
            .collect()
    }

    fn pr_event_announcement_scopes(event: &Event) -> BTreeSet<(PublicKey, String)> {
        event
            .tags
            .iter()
            .filter_map(|tag| {
                let parts = tag.as_slice();
                if parts.len() < 2 || parts[0] != "a" {
                    return None;
                }

                let coord: Vec<&str> = parts[1].splitn(3, ':').collect();
                if coord.len() != 3 || coord[0] != "30617" {
                    return None;
                }

                let owner = PublicKey::from_hex(coord[1]).ok()?;
                Some((owner, coord[2].to_string()))
            })
            .collect()
    }

    async fn pr_target_repo_paths_for_recovery(&self, event: &Event) -> BTreeSet<PathBuf> {
        let mut paths = BTreeSet::new();

        for (owner, identifier) in Self::pr_event_announcement_scopes(event) {
            paths.insert(self.repo_path_for_owner_and_identifier(
                &Self::owner_directory_component(&owner),
                &identifier,
            ));
        }

        for identifier in Self::pr_event_identifiers(event) {
            let Ok(repo_data) =
                crate::git::authorization::fetch_repository_data_excluding_purgatory(
                    &self.ctx.database,
                    &identifier,
                )
                .await
            else {
                continue;
            };

            for announcement in &repo_data.announcements {
                paths.insert(self.ctx.git_data_path.join(announcement.repo_path()));
            }
        }

        for identifier in crate::grasp06::policy::prs_identifiers_named_by_event_clone_tags(
            event,
            &self.ctx.config.domain,
        ) {
            paths.insert(crate::grasp06::paths::prs_repo_path(
                &self.ctx.git_data_path,
                &event.pubkey.to_hex(),
                &identifier,
            ));
        }

        paths
    }

    pub(crate) async fn restore_pr_git_refs_for_recovered_event(
        &self,
        event: &Event,
    ) -> anyhow::Result<bool> {
        if !matches!(
            event.kind,
            Kind::GitPullRequest | Kind::GitPullRequestUpdate
        ) {
            return Ok(true);
        }

        let Some(commit) = Self::pr_event_commit(event) else {
            tracing::warn!(
                event_id = %event.id.to_hex(),
                "Recovery could not restore PR git ref: event missing c-tag"
            );
            return Ok(false);
        };

        let ref_name = format!("refs/nostr/{}", event.id.to_hex());
        let mut restored_any = false;
        let repo_paths = self.pr_target_repo_paths_for_recovery(event).await;

        for repo_path in repo_paths {
            if !repo_path.is_dir() {
                continue;
            }

            if !crate::git::commit_exists(&repo_path, &commit) {
                continue;
            }

            crate::git::update_ref(&repo_path, &ref_name, &commit).map_err(|e| {
                anyhow::anyhow!(
                    "failed to restore PR ref {} -> {} in {}: {}",
                    ref_name,
                    commit,
                    repo_path.display(),
                    e
                )
            })?;
            restored_any = true;
        }

        if !restored_any {
            tracing::warn!(
                event_id = %event.id.to_hex(),
                ref_name = %ref_name,
                commit = %commit,
                "Recovery did not find a repository with commit needed to restore PR ref"
            );
        }

        Ok(restored_any)
    }

    pub(crate) async fn cleanup_pr_git_refs_for_tombstoned_event(&self, event: &Event) {
        if !matches!(
            event.kind,
            Kind::GitPullRequest | Kind::GitPullRequestUpdate
        ) {
            return;
        }

        let ref_name = format!("refs/nostr/{}", event.id.to_hex());
        let repo_paths = self.pr_target_repo_paths_for_recovery(event).await;

        for repo_path in repo_paths {
            if !repo_path.is_dir() {
                continue;
            }

            if let Err(e) = crate::git::delete_ref(&repo_path, &ref_name) {
                tracing::debug!(
                    event_id = %event.id.to_hex(),
                    repo = %repo_path.display(),
                    ref_name = %ref_name,
                    error = %e,
                    "Recovery tombstone cleanup: PR git ref not deleted for this repository"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core recovery pipeline
// ---------------------------------------------------------------------------

impl DeletionService {
    pub(crate) async fn recovery_blocked_by_tombstone(&self, event: &Event) -> bool {
        self.gate(event).await.is_some()
    }

    pub(crate) async fn restore_events_from_holding(
        &self,
        records: &[RecoveryMetadataRecord],
    ) -> (Vec<RecoveryMetadataRecord>, Vec<RecoveryMetadataRecord>) {
        let mut restorable = Vec::new();
        let mut blocked = Vec::new();

        for record in records {
            let Some(event_id) = record.archived_event_id else {
                // Metadata-only row (no payload) can be cleaned up.
                restorable.push(record.clone());
                continue;
            };

            match self.holding().archived_event(&event_id).await {
                Ok(Some(event)) => {
                    if self.recovery_blocked_by_tombstone(&event).await {
                        self.cleanup_pr_git_refs_for_tombstoned_event(&event).await;
                        tracing::info!(
                            event_id = %event.id.to_hex(),
                            kind = event.kind.as_u16(),
                            author = %event.pubkey.to_hex(),
                            "Recovery skipped event blocked by tombstone semantics"
                        );
                        // Tombstoned entries are intentionally non-restorable; clean up
                        // their holding metadata to keep repeated recovery attempts idempotent.
                        restorable.push(record.clone());
                        continue;
                    }

                    let already_exists = match self.ctx.database.event_by_id(&event_id).await {
                        Ok(Some(_)) => true,
                        Ok(None) => false,
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                event_id = %event_id.to_hex(),
                                "Recovery failed while checking main DB event existence"
                            );
                            blocked.push(record.clone());
                            continue;
                        }
                    };

                    if !already_exists {
                        if let Err(e) = self.ctx.database.save_event(&event).await {
                            tracing::error!(
                                error = %e,
                                event_id = %event_id.to_hex(),
                                "Recovery failed to restore event payload into main DB"
                            );
                            blocked.push(record.clone());
                            continue;
                        }
                    }

                    if matches!(
                        event.kind,
                        Kind::GitPullRequest | Kind::GitPullRequestUpdate
                    ) {
                        match self.restore_pr_git_refs_for_recovered_event(&event).await {
                            Ok(true) => {}
                            Ok(false) => {
                                blocked.push(record.clone());
                                continue;
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    event_id = %event_id.to_hex(),
                                    "Recovery failed restoring PR git refs"
                                );
                                blocked.push(record.clone());
                                continue;
                            }
                        }
                    }

                    restorable.push(record.clone());
                }
                Ok(None) => {
                    // Stale metadata referencing missing payload: deterministic
                    // behavior is to keep recovery moving and clean this row.
                    tracing::warn!(
                        event_id = %event_id.to_hex(),
                        "Recovery metadata referenced missing holding payload event; cleaning metadata"
                    );
                    restorable.push(record.clone());
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        event_id = %event_id.to_hex(),
                        "Recovery failed to load holding payload event"
                    );
                    blocked.push(record.clone());
                }
            }
        }

        (restorable, blocked)
    }

    /// Trigger recovery for a repository scope identified by the announcement event.
    ///
    /// Convenience wrapper used by the write-policy announcement handlers.
    pub(crate) async fn maybe_recover_deleted_repository(
        &self,
        event: &Event,
        identifier: &str,
    ) -> bool {
        self.maybe_recover_deleted_repository_for_scope(&event.pubkey, identifier)
            .await
    }

    /// Core recovery pipeline for a `(owner_pubkey, identifier)` scope.
    ///
    /// Acquires the exclusive lifecycle lock, checks for eligible holding
    /// records, restores the git archive and/or event payloads, cleans up
    /// consumed holding metadata, and emits metrics.
    pub async fn maybe_recover_deleted_repository_for_scope(
        &self,
        owner_pubkey: &PublicKey,
        identifier: &str,
    ) -> bool {
        let owner_hex = owner_pubkey.to_hex();
        let _lifecycle_guard = self
            .write_repository_lifecycle(&owner_hex, identifier)
            .await;
        let records = self
            .holding()
            .eligible_recovery_records(
                &owner_hex,
                identifier,
                Timestamp::now(),
                self.ctx.config.holding_retention(),
            )
            .await;

        if records.is_empty() {
            return false;
        }

        crate::metrics::record_recovery_attempt();

        let mut archive_paths = BTreeSet::new();
        for record in &records {
            if let Some(path) = &record.archive_relative_path {
                archive_paths.insert(path.clone());
            }
        }

        let selected_archive_rel = archive_paths.iter().next().cloned();
        if archive_paths.len() > 1 {
            tracing::warn!(
                owner = %owner_hex,
                identifier = %identifier,
                selected_archive = ?selected_archive_rel,
                archives = ?archive_paths,
                "Recovery found multiple archive paths; selecting lexicographically first path"
            );
        }

        let owner_component = Self::owner_directory_component(owner_pubkey);
        let mut git_ready = true;
        let mut archive_restored = false;
        let mut selected_archive_abs: Option<PathBuf> = None;
        if let Some(rel_path) = &selected_archive_rel {
            match self.holding().archive_absolute_path(rel_path) {
                Some(abs_path) => {
                    selected_archive_abs = Some(abs_path.clone());
                    if !abs_path.exists() {
                        tracing::warn!(
                            owner = %owner_hex,
                            identifier = %identifier,
                            archive = %abs_path.display(),
                            "Recovery archive file missing; continuing with events-only recovery"
                        );
                        git_ready = false;
                    } else {
                        match self.restore_git_archive_to_repo(
                            &abs_path,
                            &owner_component,
                            identifier,
                        ) {
                            Ok(restored) => {
                                archive_restored = restored;
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    owner = %owner_hex,
                                    identifier = %identifier,
                                    archive = %abs_path.display(),
                                    "Recovery failed restoring git archive; aborting recovery"
                                );
                                crate::metrics::record_recovery_failed();
                                return false;
                            }
                        }
                    }
                }
                None => {
                    tracing::warn!(
                        owner = %owner_hex,
                        identifier = %identifier,
                        archive_rel = %rel_path,
                        "Recovery archive path is invalid; continuing with events-only recovery"
                    );
                    git_ready = false;
                }
            }
        }

        let (cleanup_candidates, blocked_records) =
            self.restore_events_from_holding(&records).await;
        if cleanup_candidates.is_empty() && !git_ready {
            tracing::warn!(
                owner = %owner_hex,
                identifier = %identifier,
                "Recovery found only non-restorable state"
            );
            crate::metrics::record_recovery_failed();
            return false;
        }

        let mut cleaned = 0usize;
        for record in &cleanup_candidates {
            match self.holding().delete_recovery_record(record).await {
                Ok((metadata_deleted, _payload_deleted)) => {
                    if metadata_deleted {
                        cleaned += 1;
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        metadata_event_id = %record.metadata_event_id.to_hex(),
                        "Recovery failed to clean up holding record"
                    );
                }
            }
        }

        let all_records_cleared = blocked_records.is_empty() && cleaned == cleanup_candidates.len();
        if all_records_cleared && selected_archive_rel.is_some() {
            if let Some(abs_path) = selected_archive_abs {
                match std::fs::remove_file(&abs_path) {
                    Ok(()) => {
                        tracing::info!(
                            owner = %owner_hex,
                            identifier = %identifier,
                            archive = %abs_path.display(),
                            "Recovery removed consumed git archive"
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            owner = %owner_hex,
                            identifier = %identifier,
                            archive = %abs_path.display(),
                            "Recovery failed to delete consumed archive file"
                        );
                    }
                }
            }
        }

        tracing::info!(
            owner = %owner_hex,
            identifier = %identifier,
            records_considered = records.len(),
            records_cleaned = cleaned,
            records_blocked = blocked_records.len(),
            archive_tracked = selected_archive_rel.is_some(),
            archive_restored = archive_restored,
            git_ready = git_ready,
            "Recovery workflow completed"
        );

        let partial = !blocked_records.is_empty() || !git_ready;
        if partial {
            crate::metrics::record_recovery_partial();
        } else {
            crate::metrics::record_recovery_success();
        }

        true
    }
}
