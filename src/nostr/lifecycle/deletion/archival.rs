use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;

use flate2::write::GzEncoder;
use flate2::Compression;
use nostr_sdk::prelude::{Event, EventId, Filter, Kind, PublicKey, SingleLetterTag, Timestamp};
use tar::Builder as TarBuilder;

use super::{
    policy::{identifier_from_event, owner_directory_component, DeletionPolicy},
    DeletionOutcome,
};
use crate::nostr::lifecycle::{DeletionSource, GitArchiveMetadata, HoldingMetadata};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeletedAnnouncementRepoScope {
    owner: PublicKey,
    owner_path_component: String,
    identifier: String,
}

impl DeletionPolicy {
    /// Read-only normal-policy evaluation for a targeting NIP-62 request in
    /// disrespector mode. This deliberately does not invoke archive, cascade,
    /// holding, rollback, repository, or purgatory mutation helpers.
    pub(super) async fn would_nip62_vanish_stored_data(
        &self,
        event: &Event,
    ) -> anyhow::Result<bool> {
        // The request has already been recorded and may be persisted before an
        // exact replay reaches this handler. It is not evidence that the
        // request had an effect; only a distinct event by this author is.
        if self
            .ctx
            .database
            .query(Filter::new().author(event.pubkey))
            .await?
            .into_iter()
            .any(|stored| stored.id != event.id)
        {
            return Ok(true);
        }

        let author = event.pubkey;
        if self
            .ctx
            .purgatory
            .announcements_for_sync()
            .into_iter()
            .any(|(repository_id, _)| {
                let parts: Vec<_> = repository_id.splitn(3, ':').collect();
                parts.len() == 3 && parts[1] == author.to_hex()
            })
        {
            return Ok(true);
        }

        Ok(self
            .ctx
            .purgatory
            .get_all_identifiers()
            .into_iter()
            .flat_map(|identifier| self.ctx.purgatory.find_state(&identifier))
            .any(|entry| entry.author == author))
    }

    /// Move all currently served data authored by a targeted NIP-62 vanish
    /// request through the same holding/archive deletion lifecycle used for
    /// NIP-09 announcement deletion.
    ///
    /// Kind-30617 announcements are processed first via the graph cascade path
    /// so dependent events that become orphaned are moved to holding with the
    /// repository archive linkage. Any remaining author events are then moved to
    /// holding before main-DB deletion. The caller is responsible for recording
    /// the vanish tombstone before invoking this method.
    pub(super) async fn apply_nip62_vanish(
        &self,
        event: &Event,
    ) -> anyhow::Result<DeletionOutcome> {
        let mut outcome = DeletionOutcome::default();
        let author = event.pubkey;
        let deleted_at = event.created_at;

        let announcement_filter = Filter::new().kind(Kind::GitRepoAnnouncement).author(author);
        let announcements = self
            .ctx
            .database
            .query(announcement_filter)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to query vanished author's announcements: {e}"))?;

        let scopes = announcements
            .iter()
            .filter_map(|announcement| {
                identifier_from_event(announcement).map(|identifier| {
                    crate::nostr::lifecycle::RecoveryScope {
                        owner_pubkey_hex: author.to_hex(),
                        identifier,
                    }
                })
            })
            .collect::<Vec<_>>();
        let _lifecycle_guards = self.ctx.lifecycle.write_repositories(scopes).await;

        for announcement in announcements {
            let Some(identifier) = identifier_from_event(&announcement) else {
                tracing::warn!(
                    event_id = %announcement.id.to_hex(),
                    author = %author.to_hex(),
                    "NIP-62 vanish: announcement missing identifier; it will be handled by remaining author-event deletion"
                );
                continue;
            };
            let coordinate = format!("30617:{}:{}", author.to_hex(), identifier);
            outcome.merge(
                self.cascade_delete_announcement(
                    &author,
                    &coordinate,
                    deleted_at,
                    DeletionSource::Nip62,
                )
                .await,
            );
        }

        let mut moved_ids = HashSet::new();
        let metadata = HoldingMetadata {
            deleted_at,
            source: DeletionSource::Nip62,
            coordinate: None,
            identifier: None,
            owner_pubkey: Some(author.to_hex()),
            git_archive: None,
        };

        // Exclude the incoming request itself. On an exact replay it may
        // already be stored in Main; deleting it would falsely turn a no-op
        // request into a used request and extend its retention lifecycle.
        let remaining_ids = self
            .ctx
            .database
            .query(Filter::new().author(author))
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to query vanished author's remaining events: {e}")
            })?
            .into_iter()
            .filter(|stored| stored.id != event.id)
            .map(|stored| stored.id)
            .collect::<Vec<_>>();
        if !remaining_ids.is_empty() {
            outcome.merge(
                self.archive_and_delete_filter(
                    Filter::new().ids(remaining_ids),
                    &metadata,
                    &mut moved_ids,
                    "NIP-62 vanish remaining author-event deletion",
                )
                .await,
            );
        }

        Ok(outcome)
    }

    /// Hard-delete the targeted events from the main database.
    ///
    /// Handles both `e`-tag (by event id) and `a`-tag (by coordinate) targets.
    /// Authorship for `e`-tag targets was validated in [`handle`]; `a`-tag
    /// coordinates carry their own pubkey which is matched against the deleter.
    pub(super) async fn delete_main_db_targets(
        &self,
        event: &Event,
        moved_ids: &mut HashSet<EventId>,
    ) -> DeletionOutcome {
        let mut outcome = DeletionOutcome::default();
        // `e` tags: delete by event id.
        let ids = Self::e_tag_ids(event);
        if !ids.is_empty() {
            let filter = Filter::new().ids(ids);
            let metadata = HoldingMetadata {
                deleted_at: event.created_at,
                source: DeletionSource::Nip09,
                coordinate: None,
                identifier: None,
                owner_pubkey: None,
                git_archive: None,
            };
            outcome.merge(
                self.archive_and_delete_filter(
                    filter,
                    &metadata,
                    moved_ids,
                    "NIP-09 e-tag deletion",
                )
                .await,
            );
        }

        // `a` tags: delete matching addressable/replaceable events up to the
        // deletion's created_at.
        //
        // A kind-30617 announcement coordinate authored by the deletion author
        // triggers the graph-based cascade: the announcement is deleted AND
        // every dependent event that becomes orphaned (no longer reachable from
        // a surviving maintainer's announcement) is hard-deleted too. Every
        // other coordinate keeps the simple "delete this coordinate" behaviour.
        for tag in event.tags.iter() {
            let v = tag.as_slice();
            if v.len() < 2 || v[0] != "a" {
                continue;
            }
            if Self::is_announcement_coordinate_for_author(&v[1], &event.pubkey) {
                outcome.merge(
                    self.cascade_delete_announcement(
                        &event.pubkey,
                        &v[1],
                        event.created_at,
                        DeletionSource::Nip09,
                    )
                    .await,
                );
            } else {
                outcome.merge(
                    self.delete_coordinate_from_main_db(
                        &event.pubkey,
                        &v[1],
                        event.created_at,
                        moved_ids,
                        DeletionSource::Nip09,
                    )
                    .await,
                );
            }
        }
        outcome
    }

    /// Whether `coordinate` is a kind-30617 announcement coordinate whose
    /// pubkey matches `author`.
    ///
    /// Only such coordinates trigger the graph-based cascade path; everything
    /// else (other kinds, or a 30617 coordinate naming a different pubkey)
    /// stays on the simple deletion path.
    fn is_announcement_coordinate_for_author(coordinate: &str, author: &PublicKey) -> bool {
        let parts: Vec<&str> = coordinate.splitn(3, ':').collect();
        parts.len() == 3 && parts[0] == "30617" && parts[1] == author.to_hex()
    }

    /// Delete events matching an `a`-tag coordinate from the main database.
    pub(super) async fn delete_coordinate_from_main_db(
        &self,
        author: &PublicKey,
        coordinate: &str,
        deletion_created_at: nostr_sdk::prelude::Timestamp,
        moved_ids: &mut HashSet<EventId>,
        source: DeletionSource,
    ) -> DeletionOutcome {
        // coordinate: `<kind>:<pubkey>:<d-identifier>`
        let parts: Vec<&str> = coordinate.splitn(3, ':').collect();
        if parts.len() != 3 {
            return DeletionOutcome::default();
        }
        let Ok(kind_num) = parts[0].parse::<u16>() else {
            return DeletionOutcome::default();
        };
        let coord_pubkey_hex = parts[1];
        let identifier = parts[2];

        // The coordinate pubkey must match the deletion author.
        if coord_pubkey_hex != author.to_hex() {
            return DeletionOutcome::default();
        }

        let kind = Kind::from(kind_num);
        let mut filter = Filter::new().kind(kind).author(*author);
        if kind.is_addressable() {
            filter = filter.custom_tag(SingleLetterTag::LOWERCASE_D, identifier.to_string());
        }
        // Per NIP-09, only versions up to the deletion's created_at are deleted.
        filter = filter.until(deletion_created_at);

        let metadata = HoldingMetadata {
            deleted_at: deletion_created_at,
            source,
            coordinate: Some(coordinate.to_string()),
            identifier: Some(identifier.to_string()),
            owner_pubkey: Some(author.to_hex()),
            git_archive: if kind == Kind::GitRepoAnnouncement {
                self.ensure_repo_archive(
                    &owner_directory_component(author),
                    identifier,
                    deletion_created_at,
                )
                .await
            } else {
                None
            },
        };

        // Fail-safe preservation policy: when deleting an announcement, if git
        // archival was required but failed, skip the destructive event delete.
        if kind == Kind::GitRepoAnnouncement
            && self.repo_exists_for_owner_and_identifier(
                &owner_directory_component(author),
                identifier,
            )
            && metadata.git_archive.is_none()
        {
            tracing::warn!(
                author = %author.to_hex(),
                identifier = %identifier,
                op = "coordinate deletion",
                "Skipping announcement deletion because git archival failed (fail-safe preservation)"
            );
            return DeletionOutcome {
                skipped: 1,
                ..Default::default()
            };
        }

        self.archive_and_delete_filter(filter, &metadata, moved_ids, "coordinate deletion")
            .await
    }

    pub(super) async fn archive_and_delete_filter(
        &self,
        filter: Filter,
        metadata: &HoldingMetadata,
        moved_ids: &mut HashSet<EventId>,
        context: &str,
    ) -> DeletionOutcome {
        let matches = match self.ctx.database.query(filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!(error = %e, op = %context, "Failed to query deletion targets");
                return DeletionOutcome {
                    failures: 1,
                    ..Default::default()
                };
            }
        };

        if matches.is_empty() {
            return DeletionOutcome::default();
        }

        let mut deletable = HashSet::with_capacity(matches.len());
        let mut outcome = DeletionOutcome::default();
        let mut deleted_announcement_repo_scopes = HashSet::new();
        for event in matches {
            let mut event_metadata = metadata.clone();

            if matches!(
                event.kind,
                Kind::GitPullRequest | Kind::GitPullRequestUpdate
            ) {
                if let Some((coord, owner_hex, identifier)) =
                    Self::pr_event_primary_announcement_scope(&event)
                {
                    if event_metadata.coordinate.is_none() {
                        event_metadata.coordinate = Some(coord);
                    }
                    if event_metadata.identifier.is_none() {
                        event_metadata.identifier = Some(identifier);
                    }
                    if event_metadata.owner_pubkey.is_none() {
                        event_metadata.owner_pubkey = Some(owner_hex);
                    }
                }
            }

            if event.kind == Kind::GitRepoAnnouncement {
                let owner_hex = event.pubkey.to_hex();
                let owner_dir = owner_directory_component(&event.pubkey);
                if let Some(identifier) = identifier_from_event(&event) {
                    event_metadata.identifier = Some(identifier.clone());
                    event_metadata.owner_pubkey = Some(owner_hex.clone());

                    if event_metadata.git_archive.is_none() {
                        event_metadata.git_archive = self
                            .ensure_repo_archive(&owner_dir, &identifier, metadata.deleted_at)
                            .await;
                    }

                    // Fail-safe policy applies here too: if this announcement has
                    // on-disk git data but we couldn't archive it, skip delete.
                    if self.repo_exists_for_owner_and_identifier(&owner_dir, &identifier)
                        && event_metadata.git_archive.is_none()
                    {
                        tracing::warn!(
                            event_id = %event.id.to_hex(),
                            owner = %owner_hex,
                            identifier = %identifier,
                            op = %context,
                            "Skipping announcement deletion because git archival failed (fail-safe preservation)"
                        );
                        outcome.skipped = outcome.skipped.saturating_add(1);
                        continue;
                    }

                    if event_metadata.git_archive.is_some() {
                        deleted_announcement_repo_scopes.insert(DeletedAnnouncementRepoScope {
                            owner: event.pubkey,
                            owner_path_component: owner_dir,
                            identifier,
                        });
                    }
                }
            }

            if !moved_ids.contains(&event.id) {
                if let Err(e) = self
                    .ctx
                    .holding
                    .archive_event(&event, &event_metadata)
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        event_id = %event.id.to_hex(),
                        op = %context,
                        "Skipping main-DB deletion because holding archival failed"
                    );
                    outcome.skipped = outcome.skipped.saturating_add(1);
                    continue;
                }
                moved_ids.insert(event.id);

                if matches!(
                    event.kind,
                    Kind::GitPullRequest | Kind::GitPullRequestUpdate
                ) {
                    self.delete_pr_event_git_refs(&event).await;
                }
            }
            deletable.insert(event.id);
        }

        if deletable.is_empty() {
            return outcome;
        }

        // NostrDatabase::delete does not return a per-event removed count. Two
        // concurrently processed requests can therefore both have observed one
        // target and both receive use credit after successful delete calls. This
        // narrow over-credit race is accepted: avoiding it would require broad
        // target-level serialization, it cannot affect deletion correctness,
        // and any extra credited request still follows bounded used retention.
        // Deterministic single-winner attribution remains strict for the more
        // important case of one later admission matching many pending requests.
        let deleted_count = deletable.len();
        let delete_filter = Filter::new().ids(deletable);
        if let Err(e) = self.ctx.database.delete(delete_filter).await {
            tracing::warn!(error = %e, op = %context, "Failed to delete events from main DB");
            outcome.failures = outcome.failures.saturating_add(1);
            return outcome;
        }
        for scope in deleted_announcement_repo_scopes {
            self.remove_live_repo_if_announcement_scope_unserved(scope, context)
                .await;
        }
        outcome.main_db_deleted = outcome.main_db_deleted.saturating_add(deleted_count);
        outcome
    }

    async fn remove_live_repo_if_announcement_scope_unserved(
        &self,
        scope: DeletedAnnouncementRepoScope,
        context: &str,
    ) {
        let remaining_filter = Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(scope.owner)
            .custom_tag(SingleLetterTag::LOWERCASE_D, scope.identifier.clone());

        match self.ctx.database.query(remaining_filter).await {
            Ok(remaining) if !remaining.is_empty() => {
                tracing::debug!(
                    owner = %scope.owner.to_hex(),
                    identifier = %scope.identifier,
                    remaining = remaining.len(),
                    op = %context,
                    "Preserving live git repository because announcement scope is still served"
                );
                return;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    owner = %scope.owner.to_hex(),
                    identifier = %scope.identifier,
                    error = %e,
                    op = %context,
                    "Could not verify announcement scope deletion; preserving live git repository"
                );
                return;
            }
        }

        let repo_path =
            self.repo_path_for_owner_and_identifier(&scope.owner_path_component, &scope.identifier);
        if !repo_path.exists() {
            return;
        }

        if let Err(e) = std::fs::remove_dir_all(&repo_path) {
            tracing::warn!(
                owner = %scope.owner.to_hex(),
                identifier = %scope.identifier,
                repo = %repo_path.display(),
                error = %e,
                op = %context,
                "Failed to remove live git repository after announcement deletion"
            );
            return;
        }

        if let Some(parent) = repo_path.parent() {
            if let Err(e) = std::fs::remove_dir(parent) {
                if e.kind() != std::io::ErrorKind::NotFound
                    && e.kind() != std::io::ErrorKind::DirectoryNotEmpty
                {
                    tracing::debug!(
                        owner = %scope.owner.to_hex(),
                        identifier = %scope.identifier,
                        parent = %parent.display(),
                        error = %e,
                        op = %context,
                        "Could not remove empty repository owner directory"
                    );
                }
            }
        }

        tracing::info!(
            owner = %scope.owner.to_hex(),
            identifier = %scope.identifier,
            repo = %repo_path.display(),
            op = %context,
            "Removed live git repository after announcement deletion"
        );
    }

    fn archive_output_path(
        &self,
        owner_path_component: &str,
        identifier: &str,
        deleted_at: Timestamp,
    ) -> PathBuf {
        self.ctx
            .git_data_path
            .join(".archive")
            .join(owner_path_component)
            .join(format!("{}-{}.tar.gz", identifier, deleted_at.as_secs()))
    }

    pub(super) fn repo_path_for_owner_and_identifier(
        &self,
        owner_path_component: &str,
        identifier: &str,
    ) -> PathBuf {
        self.ctx
            .git_data_path
            .join(owner_path_component)
            .join(format!("{}.git", identifier))
    }

    pub(super) fn repo_exists_for_owner_and_identifier(
        &self,
        owner_path_component: &str,
        identifier: &str,
    ) -> bool {
        self.repo_path_for_owner_and_identifier(owner_path_component, identifier)
            .is_dir()
    }

    pub(super) async fn ensure_repo_archive(
        &self,
        owner_path_component: &str,
        identifier: &str,
        deleted_at: Timestamp,
    ) -> Option<GitArchiveMetadata> {
        let repo_path = self.repo_path_for_owner_and_identifier(owner_path_component, identifier);
        if !repo_path.is_dir() {
            tracing::debug!(
                owner = %owner_path_component,
                identifier = %identifier,
                path = %repo_path.display(),
                "No on-disk git repository found for announcement deletion; skipping archive creation"
            );
            return None;
        }

        let archive_path = self.archive_output_path(owner_path_component, identifier, deleted_at);
        let relative_path = format!(
            "{}/{}-{}.tar.gz",
            owner_path_component,
            identifier,
            deleted_at.as_secs()
        );

        if archive_path.exists() {
            return Some(GitArchiveMetadata {
                relative_path,
                created_at: Timestamp::now(),
            });
        }

        if let Some(parent) = archive_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!(
                    owner = %owner_path_component,
                    identifier = %identifier,
                    path = %parent.display(),
                    error = %e,
                    "Failed to create archive directory"
                );
                return None;
            }
        }

        let tmp_path = archive_path.with_extension("tar.gz.tmp");
        let result = (|| -> anyhow::Result<()> {
            let archive_file = File::create(&tmp_path)?;
            let encoder = GzEncoder::new(archive_file, Compression::default());
            let mut tar = TarBuilder::new(encoder);
            tar.append_dir_all(format!("{}.git", identifier), &repo_path)?;
            let encoder = tar.into_inner()?;
            encoder.finish()?;
            std::fs::rename(&tmp_path, &archive_path)?;
            Ok(())
        })();

        if let Err(e) = result {
            let _ = std::fs::remove_file(&tmp_path);
            tracing::warn!(
                owner = %owner_path_component,
                identifier = %identifier,
                repo = %repo_path.display(),
                archive = %archive_path.display(),
                error = %e,
                "Failed to archive git repository for deletion"
            );
            return None;
        }

        Some(GitArchiveMetadata {
            relative_path,
            created_at: Timestamp::now(),
        })
    }
}
