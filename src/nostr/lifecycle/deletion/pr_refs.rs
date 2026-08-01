use std::collections::BTreeSet;
use std::path::PathBuf;

use nostr_sdk::prelude::{Event, Kind};

use super::policy::{owner_directory_component, DeletionPolicy};
use crate::git;
use crate::git::authorization::fetch_repository_data_excluding_purgatory;

impl DeletionPolicy {
    pub(super) fn pr_event_primary_announcement_scope(
        event: &Event,
    ) -> Option<(String, String, String)> {
        for coordinate in Self::a_tag_coordinates(event) {
            let Some((kind, owner, identifier)) = Self::parse_coordinate(&coordinate) else {
                continue;
            };
            if kind != Kind::GitRepoAnnouncement {
                continue;
            }

            return Some((
                format!("30617:{}:{}", owner.to_hex(), identifier),
                owner.to_hex(),
                identifier,
            ));
        }

        None
    }

    fn pr_identifiers_from_a_tags(event: &Event) -> BTreeSet<String> {
        let mut identifiers = BTreeSet::new();
        for coordinate in Self::a_tag_coordinates(event) {
            let Some((kind, _, identifier)) = Self::parse_coordinate(&coordinate) else {
                continue;
            };
            if kind == Kind::GitRepoAnnouncement {
                identifiers.insert(identifier);
            }
        }
        identifiers
    }

    async fn collect_normal_repo_paths_for_pr_event(&self, event: &Event) -> BTreeSet<PathBuf> {
        let mut paths = BTreeSet::new();

        for coordinate in Self::a_tag_coordinates(event) {
            let Some((kind, owner, identifier)) = Self::parse_coordinate(&coordinate) else {
                continue;
            };
            if kind != Kind::GitRepoAnnouncement {
                continue;
            }

            paths.insert(self.repo_path_for_owner_and_identifier(
                &owner_directory_component(&owner),
                &identifier,
            ));
        }

        for identifier in Self::pr_identifiers_from_a_tags(event) {
            let Ok(repo_data) =
                fetch_repository_data_excluding_purgatory(&self.ctx.database, &identifier).await
            else {
                continue;
            };

            for announcement in &repo_data.announcements {
                paths.insert(self.ctx.git_data_path.join(announcement.repo_path()));
            }
        }

        paths
    }

    pub(super) fn collect_grasp06_repo_paths_for_pr_event(
        &self,
        event: &Event,
    ) -> BTreeSet<PathBuf> {
        crate::grasp06::policy::prs_identifiers_named_by_event_clone_tags(
            event,
            &self.ctx.config.domain,
        )
        .into_iter()
        .map(|identifier| {
            crate::grasp06::paths::prs_repo_path(
                &self.ctx.git_data_path,
                &event.pubkey.to_hex(),
                &identifier,
            )
        })
        .collect()
    }

    fn cleanup_zero_ref_grasp06_repo_if_idle(&self, repo_path: &PathBuf) {
        if !crate::grasp06::paths::is_prs_repo_path(repo_path, &self.ctx.git_data_path) {
            return;
        }

        let state = crate::grasp06::receive::path_state(&self.ctx.repo_init_locks, repo_path);
        let _guard = state.mu.lock().expect("prs path mutex poisoned");

        if state.in_flight.load(std::sync::atomic::Ordering::Relaxed) != 0 {
            return;
        }

        let is_zero_ref = matches!(git::list_refs(repo_path), Ok(refs) if refs.is_empty());
        if !is_zero_ref {
            return;
        }

        if let Err(e) = std::fs::remove_dir_all(repo_path) {
            tracing::warn!(
                repo = %repo_path.display(),
                error = %e,
                "Failed to remove zero-ref /prs/ repo while processing deletion request"
            );
            return;
        }

        if let Some(parent) = repo_path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    pub(super) async fn delete_pr_event_git_refs(&self, event: &Event) {
        let ref_name = format!("refs/nostr/{}", event.id.to_hex());
        let mut repo_paths = self.collect_normal_repo_paths_for_pr_event(event).await;
        repo_paths.extend(self.collect_grasp06_repo_paths_for_pr_event(event));

        for repo_path in repo_paths {
            if !repo_path.is_dir() {
                continue;
            }

            match git::delete_ref(&repo_path, &ref_name) {
                Ok(()) => {
                    tracing::info!(
                        event_id = %event.id.to_hex(),
                        repo = %repo_path.display(),
                        ref_name = %ref_name,
                        "Deleted PR git ref for deletion-requested event"
                    );
                    self.cleanup_zero_ref_grasp06_repo_if_idle(&repo_path);
                }
                Err(e) => {
                    tracing::debug!(
                        event_id = %event.id.to_hex(),
                        repo = %repo_path.display(),
                        ref_name = %ref_name,
                        error = %e,
                        "PR git ref not deleted for this repository"
                    );
                }
            }
        }
    }
}
