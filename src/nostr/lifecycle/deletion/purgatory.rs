use std::collections::HashSet;
use std::process::Command;

use nostr_relay_builder::prelude::{Event, Kind, Timestamp};

use super::{policy::DeletionPolicy, DeletionOutcome};
use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::lifecycle::DeletionSource;

impl DeletionPolicy {
    /// Move a served announcement scope out of the main DB and back into
    /// purgatory when deleting state leaves that scope without any valid active
    /// 30618. This preserves the served-state/git-refs invariant: the stale
    /// announcement is not served, its current git data is archived using the
    /// normal announcement deletion path, the live bare repository is replaced
    /// with an empty purgatory repo, and future promotion must arrive through the
    /// standard state+git purgatory pipeline.
    pub(super) async fn transition_announcement_scope_to_purgatory(
        &self,
        announcement: &RepositoryAnnouncement,
        deleted_at: Timestamp,
    ) {
        let owner = announcement.event.pubkey;
        let identifier = announcement.identifier.clone();
        let coordinate = format!(
            "{}:{}:{}",
            Kind::GitRepoAnnouncement.as_u16(),
            owner.to_hex(),
            identifier
        );
        let repo_path = self.ctx.git_data_path.join(announcement.repo_path());
        let relays: HashSet<String> = announcement.relays.iter().cloned().collect();

        self.cascade_delete_announcement(&owner, &coordinate, deleted_at, DeletionSource::Nip09)
            .await;

        match self.ctx.database.event_by_id(&announcement.event.id).await {
            Ok(Some(_)) => {
                tracing::warn!(
                    owner = %owner.to_hex(),
                    identifier = %identifier,
                    event_id = %announcement.event.id.to_hex(),
                    "No-active-state transition left announcement in main DB; preserving live repository"
                );
                return;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    owner = %owner.to_hex(),
                    identifier = %identifier,
                    event_id = %announcement.event.id.to_hex(),
                    error = %e,
                    "No-active-state transition could not verify announcement deletion"
                );
                return;
            }
        }

        if let Err(e) = Self::replace_live_repo_with_empty_purgatory_repo(&repo_path) {
            tracing::warn!(
                owner = %owner.to_hex(),
                identifier = %identifier,
                repo = %repo_path.display(),
                error = %e,
                "No-active-state transition could not create empty purgatory repository"
            );
            return;
        }

        self.ctx.purgatory.add_announcement(
            announcement.event.clone(),
            identifier.clone(),
            owner,
            repo_path,
            relays,
        );

        tracing::info!(
            owner = %owner.to_hex(),
            identifier = %identifier,
            "No active authorized state remains; moved announcement scope to purgatory"
        );
    }

    fn replace_live_repo_with_empty_purgatory_repo(
        repo_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        if repo_path.exists() {
            std::fs::remove_dir_all(repo_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to remove live bare repository {}: {}",
                    repo_path.display(),
                    e
                )
            })?;
        }

        let parent = repo_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid repository path {}", repo_path.display()))?;
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "failed to create repository parent {}: {}",
                parent.display(),
                e
            )
        })?;

        let output = Command::new("git")
            .args([
                "init",
                "--bare",
                repo_path.to_str().ok_or_else(|| {
                    anyhow::anyhow!("non-utf8 repository path {}", repo_path.display())
                })?,
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("failed to execute git init: {}", e))?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "git init failed for {}: {}",
                repo_path.display(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    /// Remove any purgatory entries targeted by this deletion event.
    ///
    /// Handles both reference styles from NIP-09:
    /// - `e` tags: event ID references — match against announcement or state event IDs
    /// - `a` tags: addressable coordinate references — `30617:…` or `30618:…`
    ///
    /// Only removes entries where the purgatory entry's author matches the deletion
    /// event's pubkey (enforces author-only deletion).
    pub(super) fn remove_purgatory_targets(&self, event: &Event) -> DeletionOutcome {
        let author = &event.pubkey;
        let mut outcome = DeletionOutcome::default();
        let mut removed_ids = HashSet::new();

        for tag in event.tags.iter() {
            let tag_vec = tag.as_slice();
            if tag_vec.len() < 2 {
                continue;
            }

            match tag_vec[0].as_str() {
                "e" => {
                    // Event ID reference: find purgatory announcement with this event ID
                    let target_id = &tag_vec[1];
                    outcome.merge(self.remove_by_event_id(
                        author,
                        target_id,
                        event.created_at.as_secs(),
                        &mut removed_ids,
                    ));
                }
                "a" => {
                    // Addressable coordinate reference: `<kind>:<pubkey>:<d-identifier>`
                    let coord = &tag_vec[1];
                    outcome.merge(self.remove_by_coordinate(
                        author,
                        coord,
                        event.created_at.as_secs(),
                        &mut removed_ids,
                    ));
                }
                _ => {}
            }
        }
        outcome
    }

    /// Remove a purgatory entry (announcement, state event, or PR event) matched by event ID.
    ///
    /// Checks in order: announcements (30617), state events (30618), PR/PR-update events.
    /// Only removes entries whose author matches `author`.
    fn remove_by_event_id(
        &self,
        author: &nostr_relay_builder::prelude::PublicKey,
        target_id_hex: &str,
        _deletion_created_at: u64,
        removed_ids: &mut HashSet<nostr_relay_builder::prelude::EventId>,
    ) -> DeletionOutcome {
        // --- Check PR events (kind 1617/1618) first — O(1) direct lookup ---
        // PR purgatory is keyed by event ID hex, so this is the cheapest check.
        // Only remove if the entry has an actual event (not a placeholder) and the
        // event's author matches the deletion request author.
        if let Some(entry) = self.ctx.purgatory.find_pr(target_id_hex) {
            if let Some(ref event) = entry.event {
                if event.pubkey == *author {
                    tracing::info!(
                        event_id = %target_id_hex,
                        author = %author.to_hex(),
                        "Deletion request: removing purgatory PR event by event ID"
                    );
                    self.ctx.purgatory.remove_pr(target_id_hex);
                    return DeletionOutcome {
                        purgatory_removed: usize::from(removed_ids.insert(event.id)),
                        ..Default::default()
                    };
                }
            }
            // Entry exists but is a placeholder or wrong author — don't remove
            return DeletionOutcome::default();
        }

        // --- Check announcements (kind 30617) ---
        // The DashMap doesn't expose a direct "find by event ID" method, so we use
        // the announcements_for_sync snapshot to enumerate all (repo_id, _) pairs.
        let all = self.ctx.purgatory.announcements_for_sync();
        for (repo_id, _) in all {
            // repo_id format: "30617:{pubkey_hex}:{identifier}"
            let parts: Vec<&str> = repo_id.splitn(3, ':').collect();
            if parts.len() != 3 {
                continue;
            }
            let entry_pubkey_hex = parts[1];
            let identifier = parts[2];

            if entry_pubkey_hex != author.to_hex() {
                continue;
            }

            if let Some(entry) = self.ctx.purgatory.find_announcement(author, identifier) {
                if entry.event.id.to_hex() == target_id_hex {
                    tracing::info!(
                        event_id = %target_id_hex,
                        identifier = %identifier,
                        author = %author.to_hex(),
                        "Deletion request: removing purgatory announcement by event ID"
                    );
                    return self.evict_purgatory_entry(author, identifier, removed_ids);
                }
            }
        }

        // --- Check state events (kind 30618) ---
        // State events are keyed by identifier; scan all identifiers for a match.
        let state_identifiers = self.ctx.purgatory.get_all_identifiers();
        for identifier in state_identifiers {
            let entries = self.ctx.purgatory.find_state(&identifier);
            for entry in entries {
                if entry.author == *author && entry.event.id.to_hex() == target_id_hex {
                    tracing::info!(
                        event_id = %target_id_hex,
                        identifier = %identifier,
                        author = %author.to_hex(),
                        "Deletion request: removing purgatory state event by event ID"
                    );
                    self.ctx
                        .purgatory
                        .remove_state_event(&identifier, &entry.event.id);
                    return DeletionOutcome {
                        purgatory_removed: usize::from(removed_ids.insert(entry.event.id)),
                        ..Default::default()
                    };
                }
            }
        }
        DeletionOutcome::default()
    }

    /// Remove a purgatory entry matched by addressable coordinate.
    ///
    /// The coordinate format is `<kind>:<pubkey>:<d-identifier>`.
    /// Handles kind 30617 (announcements) and kind 30618 (state events).
    ///
    /// Per NIP-09, all versions up to `deletion_created_at` are considered deleted.
    fn remove_by_coordinate(
        &self,
        author: &nostr_relay_builder::prelude::PublicKey,
        coordinate: &str,
        deletion_created_at: u64,
        removed_ids: &mut HashSet<nostr_relay_builder::prelude::EventId>,
    ) -> DeletionOutcome {
        let mut outcome = DeletionOutcome::default();
        // Parse coordinate: `<kind>:<pubkey>:<d-identifier>`
        let parts: Vec<&str> = coordinate.splitn(3, ':').collect();
        if parts.len() != 3 {
            return DeletionOutcome::default();
        }

        let kind_str = parts[0];
        let coord_pubkey_hex = parts[1];
        let identifier = parts[2];

        // The coordinate pubkey must match the deletion event author
        if coord_pubkey_hex != author.to_hex() {
            tracing::debug!(
                coord_pubkey = %coord_pubkey_hex,
                deletion_author = %author.to_hex(),
                "Ignoring deletion: coordinate pubkey does not match deletion author"
            );
            return DeletionOutcome::default();
        }

        match kind_str {
            "30617" => {
                // Announcement purgatory entry
                if let Some(entry) = self.ctx.purgatory.find_announcement(author, identifier) {
                    if entry.event.created_at.as_secs() <= deletion_created_at {
                        tracing::info!(
                            identifier = %identifier,
                            author = %author.to_hex(),
                            "Deletion request: removing purgatory announcement by coordinate"
                        );
                        return self.evict_purgatory_entry(author, identifier, removed_ids);
                    } else {
                        tracing::debug!(
                            identifier = %identifier,
                            author = %author.to_hex(),
                            "Ignoring deletion: purgatory announcement is newer than deletion request"
                        );
                    }
                }
            }
            "30618" => {
                // State event purgatory entries for this (author, identifier).
                // Remove all entries authored by `author` with created_at ≤ deletion_created_at.
                let entries = self.ctx.purgatory.find_state(identifier);
                let mut removed = 0usize;
                for entry in entries {
                    if entry.author == *author
                        && entry.event.created_at.as_secs() <= deletion_created_at
                    {
                        self.ctx
                            .purgatory
                            .remove_state_event(identifier, &entry.event.id);
                        let counted = usize::from(removed_ids.insert(entry.event.id));
                        removed += counted;
                        outcome.purgatory_removed =
                            outcome.purgatory_removed.saturating_add(counted);
                    }
                }
                if removed > 0 {
                    tracing::info!(
                        identifier = %identifier,
                        author = %author.to_hex(),
                        removed = %removed,
                        "Deletion request: removed purgatory state event(s) by coordinate"
                    );
                }
            }
            _ => {
                // Other kinds not handled
            }
        }
        outcome
    }

    /// Remove a purgatory announcement and delete its bare repository from disk.
    fn evict_purgatory_entry(
        &self,
        author: &nostr_relay_builder::prelude::PublicKey,
        identifier: &str,
        removed_ids: &mut HashSet<nostr_relay_builder::prelude::EventId>,
    ) -> DeletionOutcome {
        let mut outcome = DeletionOutcome::default();
        // Get repo path before removing
        if let Some(entry) = self.ctx.purgatory.find_announcement(author, identifier) {
            if entry.repo_path.exists() {
                if let Err(e) = std::fs::remove_dir_all(&entry.repo_path) {
                    tracing::warn!(
                        path = %entry.repo_path.display(),
                        error = %e,
                        "Failed to delete bare repository during deletion request processing"
                    );
                    outcome.failures = outcome.failures.saturating_add(1);
                } else {
                    tracing::info!(
                        path = %entry.repo_path.display(),
                        "Deleted bare repository for deletion-requested purgatory announcement"
                    );
                }
            }
        }

        if let Some(entry) = self.ctx.purgatory.find_announcement(author, identifier) {
            outcome.purgatory_removed = outcome
                .purgatory_removed
                .saturating_add(usize::from(removed_ids.insert(entry.event.id)));
        }
        self.ctx.purgatory.remove_announcement(author, identifier);

        // Remove state events for this identifier only if no other owner's
        // announcement remains in purgatory (state events are keyed by identifier alone)
        let other_owners_remain = !self
            .ctx
            .purgatory
            .get_announcements_by_identifier(identifier)
            .is_empty();

        if !other_owners_remain {
            for entry in self.ctx.purgatory.find_state(identifier) {
                outcome.purgatory_removed = outcome
                    .purgatory_removed
                    .saturating_add(usize::from(removed_ids.insert(entry.event.id)));
            }
            self.ctx.purgatory.remove_state(identifier);
        }
        outcome
    }
}
