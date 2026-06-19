use std::collections::{BTreeSet, HashSet};

use nostr_relay_builder::prelude::{
    Alphabet, Event, EventId, Filter, Kind, PublicKey, SingleLetterTag, Timestamp,
};

use super::policy::{identifier_from_event, DeletionPolicy};
use crate::git;
use crate::git::authorization::{
    collect_authorized_maintainers, fetch_repository_data_excluding_purgatory,
};
use crate::git::process;
use crate::nostr::events::RepositoryState;
use crate::nostr::holding::RecoveryScope;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ReplaceableRollbackPlan {
    pub(super) kind: u16,
    coordinate: String,
    pub(super) identifier: String,
    deleted_event_id: EventId,
    cutoff: Timestamp,
}

impl DeletionPolicy {
    pub(super) async fn collect_replaceable_rollback_plans(
        &self,
        deletion: &Event,
    ) -> Vec<ReplaceableRollbackPlan> {
        let mut plans = Vec::new();

        for target_id in Self::e_tag_ids(deletion) {
            let Ok(Some(target)) = self.ctx.database.event_by_id(&target_id).await else {
                continue;
            };

            if target.pubkey != deletion.pubkey {
                continue;
            }

            if target.kind != Kind::RepoState && target.kind != Kind::GitRepoAnnouncement {
                continue;
            }

            let Some(identifier) = identifier_from_event(&target) else {
                continue;
            };

            let Some(active) = self
                .latest_event_for_coordinate(target.kind, &target.pubkey, &identifier, None)
                .await
            else {
                continue;
            };

            if active.id != target.id {
                continue;
            }

            plans.push(ReplaceableRollbackPlan {
                kind: target.kind.as_u16(),
                coordinate: format!(
                    "{}:{}:{}",
                    target.kind.as_u16(),
                    target.pubkey.to_hex(),
                    identifier
                ),
                identifier,
                deleted_event_id: target.id,
                cutoff: target.created_at,
            });
        }

        plans
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    pub(super) fn state_a_tag_identifiers_for_author(event: &Event) -> HashSet<String> {
        Self::a_tag_coordinates(event)
            .into_iter()
            .filter_map(|coordinate| {
                let (kind, coord_pubkey, identifier) = Self::parse_coordinate(&coordinate)?;

                if kind == Kind::RepoState && coord_pubkey == event.pubkey {
                    Some(identifier)
                } else {
                    None
                }
            })
            .collect()
    }

    pub(super) fn a_tag_coordinates(event: &Event) -> Vec<String> {
        event
            .tags
            .iter()
            .filter_map(|tag| {
                let v = tag.as_slice();
                if v.len() >= 2 && v[0] == "a" {
                    Some(v[1].clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub(super) fn parse_coordinate(coordinate: &str) -> Option<(Kind, PublicKey, String)> {
        let parts: Vec<&str> = coordinate.splitn(3, ':').collect();
        if parts.len() != 3 {
            return None;
        }
        let kind_num = parts[0].parse::<u16>().ok()?;
        let pubkey = PublicKey::from_hex(parts[1]).ok()?;
        Some((Kind::from(kind_num), pubkey, parts[2].to_string()))
    }

    pub(super) async fn deletion_recovery_scopes(&self, event: &Event) -> Vec<RecoveryScope> {
        let mut scopes = BTreeSet::new();

        for coordinate in Self::a_tag_coordinates(event) {
            let Some((kind, owner, identifier)) = Self::parse_coordinate(&coordinate) else {
                continue;
            };
            if owner != event.pubkey {
                continue;
            }
            if matches!(kind, Kind::GitRepoAnnouncement | Kind::RepoState) {
                scopes.insert(RecoveryScope {
                    owner_pubkey_hex: owner.to_hex(),
                    identifier,
                });
            }
        }

        for id in Self::e_tag_ids(event) {
            if let Ok(Some(target)) = self.ctx.database.event_by_id(&id).await {
                if target.pubkey == event.pubkey {
                    if let Some(identifier) = identifier_from_event(&target) {
                        scopes.insert(RecoveryScope {
                            owner_pubkey_hex: target.pubkey.to_hex(),
                            identifier,
                        });
                    }
                }
            }
        }

        scopes.into_iter().collect()
    }

    async fn latest_event_for_coordinate(
        &self,
        kind: Kind,
        author: &PublicKey,
        identifier: &str,
        until: Option<Timestamp>,
    ) -> Option<Event> {
        let mut filter = Filter::new().kind(kind).author(*author);
        if kind.is_addressable() {
            filter = filter.custom_tag(
                SingleLetterTag::lowercase(Alphabet::D),
                identifier.to_string(),
            );
        }
        if let Some(cutoff) = until {
            filter = filter.until(cutoff);
        }

        let Ok(events) = self.ctx.database.query(filter).await else {
            return None;
        };

        events.into_iter().max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        })
    }

    pub(super) async fn rollback_deleted_active_replaceable(&self, plan: &ReplaceableRollbackPlan) {
        match Kind::from(plan.kind) {
            Kind::RepoState => self.rollback_deleted_active_state(plan).await,
            Kind::GitRepoAnnouncement => self.rollback_deleted_active_announcement(plan).await,
            _ => {}
        }
    }

    async fn rollback_deleted_active_state(&self, plan: &ReplaceableRollbackPlan) {
        let Some(record) = self
            .ctx
            .history
            .latest_superseded_before(&plan.coordinate, plan.cutoff)
            .await
        else {
            tracing::info!(
                coordinate = %plan.coordinate,
                deleted_event_id = %plan.deleted_event_id.to_hex(),
                cutoff = plan.cutoff.as_secs(),
                "No rollback candidate in history; entering no-active-state path"
            );
            return;
        };

        let Some(candidate_id) = record.superseded_event_id else {
            tracing::warn!(
                coordinate = %plan.coordinate,
                metadata_event_id = %record.metadata_event_id.to_hex(),
                "History record missing superseded event id; cannot rollback"
            );
            return;
        };

        let candidate = match self.ctx.history.event_by_id(&candidate_id).await {
            Ok(Some(event)) => event,
            Ok(None) => {
                tracing::warn!(
                    coordinate = %plan.coordinate,
                    candidate_id = %candidate_id.to_hex(),
                    "History payload missing for rollback candidate"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    coordinate = %plan.coordinate,
                    candidate_id = %candidate_id.to_hex(),
                    error = %e,
                    "History lookup failed for rollback candidate"
                );
                return;
            }
        };

        let Ok(candidate_state) = RepositoryState::from_event(candidate.clone()) else {
            tracing::warn!(
                coordinate = %plan.coordinate,
                candidate_id = %candidate.id.to_hex(),
                "Rollback candidate is not a valid state event"
            );
            return;
        };

        let repo_data = match fetch_repository_data_excluding_purgatory(
            &self.ctx.database,
            &candidate_state.identifier,
        )
        .await
        {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!(
                    coordinate = %plan.coordinate,
                    error = %e,
                    "Failed to load repository data before rollback"
                );
                return;
            }
        };

        if crate::git::authorization::pubkey_authorised_for_repo_owners(
            &candidate.pubkey,
            &repo_data,
        )
        .is_empty()
        {
            tracing::warn!(
                coordinate = %plan.coordinate,
                candidate_id = %candidate.id.to_hex(),
                author = %candidate.pubkey.to_hex(),
                "Rollback candidate author is no longer authorized; skipping restore"
            );
            return;
        }

        if let Err(e) = self.ctx.database.save_event(&candidate).await {
            tracing::warn!(
                coordinate = %plan.coordinate,
                candidate_id = %candidate.id.to_hex(),
                error = %e,
                "Failed to restore rollback candidate into main DB"
            );
            return;
        }

        tracing::info!(
            coordinate = %plan.coordinate,
            deleted_event_id = %plan.deleted_event_id.to_hex(),
            restored_event_id = %candidate.id.to_hex(),
            "Restored deleted active state from replaceable history"
        );
    }

    async fn rollback_deleted_active_announcement(&self, plan: &ReplaceableRollbackPlan) {
        let Some(record) = self
            .ctx
            .history
            .latest_superseded_before(&plan.coordinate, plan.cutoff)
            .await
        else {
            tracing::info!(
                coordinate = %plan.coordinate,
                deleted_event_id = %plan.deleted_event_id.to_hex(),
                cutoff = plan.cutoff.as_secs(),
                "No announcement rollback candidate in history"
            );
            return;
        };

        let Some(candidate_id) = record.superseded_event_id else {
            tracing::warn!(
                coordinate = %plan.coordinate,
                metadata_event_id = %record.metadata_event_id.to_hex(),
                "History record missing superseded announcement event id; cannot rollback"
            );
            return;
        };

        let candidate = match self.ctx.history.event_by_id(&candidate_id).await {
            Ok(Some(event)) => event,
            Ok(None) => {
                tracing::warn!(
                    coordinate = %plan.coordinate,
                    candidate_id = %candidate_id.to_hex(),
                    "History payload missing for announcement rollback candidate"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    coordinate = %plan.coordinate,
                    candidate_id = %candidate_id.to_hex(),
                    error = %e,
                    "History lookup failed for announcement rollback candidate"
                );
                return;
            }
        };

        if candidate.kind != Kind::GitRepoAnnouncement {
            tracing::warn!(
                coordinate = %plan.coordinate,
                candidate_id = %candidate.id.to_hex(),
                kind = candidate.kind.as_u16(),
                "Rollback candidate is not an announcement"
            );
            return;
        }

        let Some((_kind, coord_pubkey, coord_identifier)) =
            Self::parse_coordinate(&plan.coordinate)
        else {
            tracing::warn!(
                coordinate = %plan.coordinate,
                "Invalid rollback coordinate while restoring announcement"
            );
            return;
        };

        if candidate.pubkey != coord_pubkey {
            tracing::warn!(
                coordinate = %plan.coordinate,
                candidate_id = %candidate.id.to_hex(),
                "Announcement rollback candidate author does not match coordinate"
            );
            return;
        }

        if identifier_from_event(&candidate).as_deref() != Some(coord_identifier.as_str()) {
            tracing::warn!(
                coordinate = %plan.coordinate,
                candidate_id = %candidate.id.to_hex(),
                expected_identifier = %coord_identifier,
                "Announcement rollback candidate identifier mismatch"
            );
            return;
        }

        if let Err(e) = self.ctx.database.save_event(&candidate).await {
            tracing::warn!(
                coordinate = %plan.coordinate,
                candidate_id = %candidate.id.to_hex(),
                error = %e,
                "Failed to restore announcement rollback candidate into main DB"
            );
            return;
        }

        tracing::info!(
            coordinate = %plan.coordinate,
            deleted_event_id = %plan.deleted_event_id.to_hex(),
            restored_event_id = %candidate.id.to_hex(),
            "Restored deleted active announcement from replaceable history"
        );
    }

    pub(super) async fn realign_identifier_state(&self, identifier: &str) {
        let repo_data =
            match fetch_repository_data_excluding_purgatory(&self.ctx.database, identifier).await {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!(
                        identifier = %identifier,
                        error = %e,
                        "Failed to reload repository data for post-deletion state alignment"
                    );
                    return;
                }
            };

        if repo_data.announcements.is_empty() {
            return;
        }

        let by_owner = collect_authorized_maintainers(&repo_data.announcements);

        for announcement in &repo_data.announcements {
            let owner_hex = announcement.event.pubkey.to_hex();
            let Some(maintainers) = by_owner.get(&owner_hex) else {
                continue;
            };

            let target_repo_path = self.ctx.git_data_path.join(announcement.repo_path());
            if !target_repo_path.is_dir() {
                continue;
            }

            let latest_state = repo_data
                .states
                .iter()
                .filter(|state| maintainers.contains(&state.event.pubkey.to_hex()))
                .max_by(|a, b| {
                    a.event
                        .created_at
                        .cmp(&b.event.created_at)
                        .then_with(|| a.event.id.cmp(&b.event.id))
                });

            match latest_state {
                Some(state) => {
                    let source_repo_path =
                        repo_data
                            .announcements
                            .iter()
                            .find_map(|candidate_announcement| {
                                let candidate_path = self
                                    .ctx
                                    .git_data_path
                                    .join(candidate_announcement.repo_path());
                                if candidate_path.is_dir()
                                    && state.branches.iter().all(|branch| {
                                        branch.commit.starts_with("ref: ")
                                            || git::oid_exists(&candidate_path, &branch.commit)
                                    })
                                    && state
                                        .tags
                                        .iter()
                                        .all(|tag| git::oid_exists(&candidate_path, &tag.commit))
                                {
                                    Some(candidate_path)
                                } else {
                                    None
                                }
                            });

                    if let Some(source_repo_path) = source_repo_path {
                        let result = process::process_state_with_git_data(
                            state,
                            &source_repo_path,
                            &repo_data,
                            &self.ctx.git_data_path,
                        );
                        tracing::info!(
                            identifier = %identifier,
                            owner = %owner_hex,
                            state_event_id = %state.event.id.to_hex(),
                            repos_synced = result.repos_synced,
                            refs_created = result.refs_created,
                            refs_updated = result.refs_updated,
                            refs_deleted = result.refs_deleted,
                            "Realigned git refs after state deletion/rollback"
                        );
                    }
                }
                None => {
                    let refs = match git::list_refs(&target_repo_path) {
                        Ok(refs) => refs,
                        Err(e) => {
                            tracing::warn!(
                                identifier = %identifier,
                                owner = %owner_hex,
                                repo = %target_repo_path.display(),
                                error = %e,
                                "Failed to list refs for no-active-state cleanup"
                            );
                            continue;
                        }
                    };

                    let mut deleted_refs = 0usize;
                    for (ref_name, _) in refs {
                        if (ref_name.starts_with("refs/heads/")
                            || ref_name.starts_with("refs/tags/"))
                            && git::delete_ref(&target_repo_path, &ref_name).is_ok()
                        {
                            deleted_refs += 1;
                        }
                    }

                    tracing::info!(
                        identifier = %identifier,
                        owner = %owner_hex,
                        repo = %target_repo_path.display(),
                        deleted_refs,
                        "No active authorized state remains; cleared managed refs"
                    );
                }
            }
        }
    }
}
