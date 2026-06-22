use std::collections::{HashMap, HashSet};

use nostr_relay_builder::prelude::{
    Alphabet, Event, EventId, Filter, Kind, PublicKey, SingleLetterTag, Timestamp,
};

use super::super::policy::{
    announcement_address_of, identifier_from_event, owner_directory_component, DeletionPolicy,
};
use super::{
    build_event_graph, reevaluate_events_without_announcement, traverse_and_mark_deletions,
    RetentionReason,
};
use crate::nostr::lifecycle::{DeletionSource, HoldingMetadata};

/// NIP-34 event kinds (other than the kind-30617 announcement and kind-30618
/// state event) that participate in the repository dependency graph. These are
/// the events that can become orphaned when an announcement is deleted.
const GRAPH_DEPENDENT_KINDS: &[u16] = &[
    1111, // NIP-22 comment
    1617, // patch
    1618, // pull request
    1619, // PR update
    1621, // issue
    1630, // issue status
    1631, // PR status
    1632, // patch status
    1633, // repository status
];

const MAX_CASCADE_CANDIDATE_EVENTS: usize = 50_000;
const MAX_CASCADE_ORPHAN_DELETES: usize = 20_000;

impl DeletionPolicy {
    /// Graph-based cascade deletion of a repository announcement.
    ///
    /// Mirrors the algorithm order of the multi-maintainer deletion design:
    ///
    /// 1. Query the candidate event set (the announcement's siblings + all
    ///    NIP-34 dependent events) and build the dependency graph via
    ///    [`crate::nostr::lifecycle::deletion::build_event_graph`] (a/e/q tag edges).
    /// 2. Re-evaluate the candidate events WITHOUT the deleted announcement but
    ///    WITH every OTHER maintainer's announcement for the same identifier via
    ///    [`crate::nostr::lifecycle::deletion::reevaluate_events_without_announcement`], yielding the
    ///    kept/deleted split (multi-maintainer retention).
    /// 3. Add every surviving announcement (a different identifier, or the same
    ///    identifier authored by a different maintainer) to the kept set so the
    ///    traversal keeps everything still anchored to a live announcement.
    /// 4. Traverse the graph from the kept announcements via
    ///    [`crate::nostr::lifecycle::deletion::traverse_and_mark_deletions`] to compute the final orphan
    ///    set (events unreachable from any surviving announcement).
    /// 5. Hard-delete the orphaned event ids plus the announcement coordinate
    ///    itself from the main DB.
    ///
    /// Holding orchestration is active in this cascade path via
    /// [`Self::archive_and_delete_filter`]: every deleted orphan/coordinate
    /// target is moved into holding before main-DB deletion, and announcement
    /// deletions include git archive metadata linkage for cleanup lifecycle.
    /// Recovery orchestration lives in `crate::nostr::lifecycle::deletion::recovery`.
    pub(in crate::nostr::lifecycle::deletion) async fn cascade_delete_announcement(
        &self,
        author: &PublicKey,
        announcement_addr: &str,
        deletion_created_at: Timestamp,
        source: DeletionSource,
    ) {
        let mut moved_ids = HashSet::new();

        // Parse `30617:<pubkey>:<identifier>` (already validated as a 30617
        // coordinate for this author, but re-parse defensively).
        let parts: Vec<&str> = announcement_addr.splitn(3, ':').collect();
        if parts.len() != 3 {
            return;
        }
        let identifier = parts[2];

        // Step 1: candidate event set — all announcements (to know which other
        // maintainers survive) plus all NIP-34 dependent events.
        let candidates = match self.query_cascade_candidates().await {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!(error = %e, "Cascade deletion: failed to query candidate events; falling back to simple coordinate deletion");
                self.delete_coordinate_from_main_db(
                    author,
                    announcement_addr,
                    deletion_created_at,
                    &mut moved_ids,
                    source,
                )
                .await;
                return;
            }
        };

        if candidates.len() > MAX_CASCADE_CANDIDATE_EVENTS {
            tracing::warn!(
                announcement = %announcement_addr,
                candidates = candidates.len(),
                max = MAX_CASCADE_CANDIDATE_EVENTS,
                "Cascade deletion candidate set exceeds limit; falling back to coordinate-only deletion"
            );
            self.delete_coordinate_from_main_db(
                author,
                announcement_addr,
                deletion_created_at,
                &mut moved_ids,
                source,
            )
            .await;
            return;
        }

        let graph = build_event_graph(&candidates);

        // The set of candidate event ids we feed into re-evaluation. The
        // re-evaluation engine queries each one back from the DB; passing the
        // full candidate set lets it decide retention for every dependent.
        let candidate_ids: HashSet<EventId> = candidates.iter().map(|e| e.id).collect();

        // Step 2: re-evaluate dependents WITHOUT the deleted announcement but
        // WITH any other surviving maintainers' announcements.
        let reeval = match reevaluate_events_without_announcement(
            &self.ctx.database,
            announcement_addr,
            &candidate_ids,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(error = %e, "Cascade deletion: re-evaluation failed; falling back to simple coordinate deletion");
                self.delete_coordinate_from_main_db(
                    author,
                    announcement_addr,
                    deletion_created_at,
                    &mut moved_ids,
                    source,
                )
                .await;
                return;
            }
        };

        let mut kept_events: HashMap<EventId, RetentionReason> = reeval.keep;

        // Step 3: any announcement that is NOT the one being deleted is a
        // surviving anchor. Add it to the kept set (with a Repository
        // Announcement retention reason) so the traversal starts from it. This
        // covers both "different identifier" and "same identifier, different
        // maintainer" survivors.
        for event in &candidates {
            if event.kind != Kind::GitRepoAnnouncement {
                continue;
            }
            let event_addr = announcement_address_of(event);
            if event_addr == announcement_addr {
                // This is the announcement being deleted — do not keep it.
                continue;
            }
            kept_events
                .entry(event.id)
                .or_insert_with(|| RetentionReason {
                    event_id: event.id,
                    valid_announcements: vec![event_addr],
                    event_type: "Repository Announcement".to_string(),
                });
        }

        // Step 4: traverse from kept announcements to find the final orphans.
        let deleted_announcement_id = candidates
            .iter()
            .find(|e| {
                e.kind == Kind::GitRepoAnnouncement
                    && announcement_address_of(e) == announcement_addr
            })
            .map(|e| e.id)
            .unwrap_or_else(EventId::all_zeros);

        let traversal = traverse_and_mark_deletions(&graph, &kept_events, deleted_announcement_id);

        tracing::info!(
            announcement = %announcement_addr,
            kept = traversal.keep.len(),
            deleted = traversal.delete.len(),
            circular = traversal.circular_dependencies.len(),
            "Announcement cascade deletion: graph traversal complete"
        );
        for circular in &traversal.circular_dependencies {
            tracing::debug!(
                events = ?circular.events,
                anchored = circular.anchored,
                "Cascade deletion: circular dependency"
            );
        }

        // Step 5a: hard-delete the orphaned dependent events by id.
        let orphan_ids: Vec<EventId> = traversal.delete.into_iter().collect();
        if orphan_ids.len() > MAX_CASCADE_ORPHAN_DELETES {
            tracing::warn!(
                announcement = %announcement_addr,
                orphan_deletes = orphan_ids.len(),
                max = MAX_CASCADE_ORPHAN_DELETES,
                "Cascade deletion orphan set exceeds limit; deleting announcement coordinate only"
            );
            self.delete_coordinate_from_main_db(
                author,
                announcement_addr,
                deletion_created_at,
                &mut moved_ids,
                source,
            )
            .await;
            return;
        }
        if !orphan_ids.is_empty() {
            tracing::debug!(
                count = orphan_ids.len(),
                "Cascade deletion: hard-deleting orphaned events"
            );
            let filter = Filter::new().ids(orphan_ids);
            let metadata = HoldingMetadata {
                deleted_at: deletion_created_at,
                source,
                coordinate: Some(announcement_addr.to_string()),
                identifier: Some(identifier.to_string()),
                owner_pubkey: Some(author.to_hex()),
                git_archive: self
                    .ensure_repo_archive(
                        &owner_directory_component(author),
                        identifier,
                        deletion_created_at,
                    )
                    .await,
            };
            self.archive_and_delete_filter(
                filter,
                &metadata,
                &mut moved_ids,
                "cascade orphan deletion",
            )
            .await;
        }

        // Step 5b: hard-delete the announcement coordinate itself (up to the
        // deletion's created_at, per NIP-09), exactly as the simple path does.
        self.delete_coordinate_from_main_db(
            author,
            announcement_addr,
            deletion_created_at,
            &mut moved_ids,
            source,
        )
        .await;

        // Step 5c: repository state (30618) is keyed by identifier, not by
        // graph edges. After deleting this announcement coordinate, delete
        // state events for the identifier only when no announcement for that
        // identifier remains in the main DB.
        self.delete_repo_state_if_identifier_is_unanchored(
            identifier,
            deletion_created_at,
            &mut moved_ids,
            source,
        )
        .await;
    }

    /// Apply operator-driven blacklist deletion for a stored kind-30617
    /// announcement.
    ///
    /// This path intentionally bypasses `deletion_request_disrespector` and uses
    /// the same cascade + holding/archive flow as user NIP-09 deletions, but
    /// marks holding metadata with `DeletionSource::Blacklist`.
    pub async fn apply_blacklist_deletion_for_announcement(
        &self,
        announcement: &Event,
    ) -> anyhow::Result<()> {
        if announcement.kind != Kind::GitRepoAnnouncement {
            return Err(anyhow::anyhow!(
                "blacklist deletion requires kind 30617 announcement, got {}",
                announcement.kind.as_u16()
            ));
        }

        let Some(identifier) = identifier_from_event(announcement) else {
            return Err(anyhow::anyhow!(
                "announcement {} missing identifier tag",
                announcement.id.to_hex()
            ));
        };

        let coordinate = format!("30617:{}:{}", announcement.pubkey.to_hex(), identifier);
        self.cascade_delete_announcement(
            &announcement.pubkey,
            &coordinate,
            Timestamp::now(),
            DeletionSource::Blacklist,
        )
        .await;

        Ok(())
    }

    /// Apply operator-driven whitelist deletion for a stored kind-30617
    /// announcement.
    ///
    /// Uses the same cascade + holding/archive flow as NIP-09 deletions, but
    /// marks holding metadata with `DeletionSource::Whitelist`.
    pub async fn apply_whitelist_deletion_for_announcement(
        &self,
        announcement: &Event,
    ) -> anyhow::Result<()> {
        if announcement.kind != Kind::GitRepoAnnouncement {
            return Err(anyhow::anyhow!(
                "whitelist deletion requires kind 30617 announcement, got {}",
                announcement.kind.as_u16()
            ));
        }

        let Some(identifier) = identifier_from_event(announcement) else {
            return Err(anyhow::anyhow!(
                "announcement {} missing identifier tag",
                announcement.id.to_hex()
            ));
        };

        let coordinate = format!("30617:{}:{}", announcement.pubkey.to_hex(), identifier);
        self.cascade_delete_announcement(
            &announcement.pubkey,
            &coordinate,
            Timestamp::now(),
            DeletionSource::Whitelist,
        )
        .await;

        Ok(())
    }

    /// Delete kind-30618 state events for `identifier` when the repository is
    /// now unanchored (no surviving kind-30617 announcement with that `d` tag).
    ///
    /// This is separate from graph traversal because state events are keyed by
    /// identifier rather than `a`/`e`/`q` relationships.
    async fn delete_repo_state_if_identifier_is_unanchored(
        &self,
        identifier: &str,
        deletion_created_at: Timestamp,
        moved_ids: &mut HashSet<EventId>,
        source: DeletionSource,
    ) {
        let announcement_filter = Filter::new().kind(Kind::GitRepoAnnouncement).custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            identifier.to_string(),
        );

        let remaining_announcements = match self.ctx.database.query(announcement_filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    identifier = %identifier,
                    "Cascade deletion: failed to check remaining announcements for identifier"
                );
                return;
            }
        };

        if !remaining_announcements.is_empty() {
            return;
        }

        let state_filter = Filter::new().kind(Kind::RepoState).custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            identifier.to_string(),
        );

        let metadata = HoldingMetadata {
            deleted_at: deletion_created_at,
            source,
            coordinate: None,
            identifier: Some(identifier.to_string()),
            owner_pubkey: None,
            git_archive: None,
        };
        self.archive_and_delete_filter(
            state_filter,
            &metadata,
            moved_ids,
            "unanchored state deletion",
        )
        .await;
    }

    /// Query the candidate event set for the cascade graph: every repository
    /// announcement (so surviving maintainers can be identified) plus every
    /// NIP-34 dependent event kind.
    async fn query_cascade_candidates(&self) -> Result<Vec<Event>, String> {
        let mut events = Vec::new();

        // All announcements.
        let ann_filter = Filter::new().kind(Kind::GitRepoAnnouncement);
        events.extend(
            self.ctx
                .database
                .query(ann_filter)
                .await
                .map_err(|e| format!("query announcements failed: {e}"))?,
        );

        // All dependent kinds.
        for kind_num in GRAPH_DEPENDENT_KINDS {
            let filter = Filter::new().kind(Kind::from(*kind_num));
            events.extend(
                self.ctx
                    .database
                    .query(filter)
                    .await
                    .map_err(|e| format!("query kind {kind_num} failed: {e}"))?,
            );
        }

        // Exclude GRASP-06 PR / PR-update subgraphs from cascade deletion.
        //
        // These events can intentionally target this relay's `/prs/` endpoint
        // via clone tags and should not be treated as regular announcement-
        // anchored dependents for announcement cascade deletion.
        let excluded_roots: HashSet<EventId> = events
            .iter()
            .filter(|event| {
                crate::grasp06::policy::event_names_relays_prs_endpoint(
                    event,
                    &self.ctx.config.domain,
                )
            })
            .map(|event| event.id)
            .collect();

        if !excluded_roots.is_empty() {
            let graph = build_event_graph(&events);
            let mut excluded_ids = excluded_roots.clone();
            for root in &excluded_roots {
                excluded_ids.extend(graph.get_transitive_dependents(root));
            }

            let total_before = events.len();
            events.retain(|event| !excluded_ids.contains(&event.id));

            tracing::debug!(
                total_before,
                excluded_roots = excluded_roots.len(),
                excluded_related = excluded_ids.len().saturating_sub(excluded_roots.len()),
                total_after = events.len(),
                "Cascade deletion: excluded GRASP-06 PR candidate subgraphs"
            );
        }

        Ok(events)
    }
}
