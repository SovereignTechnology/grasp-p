/// Deletion Policy - NIP-09 event deletion request handling
///
/// Handles kind 5 (EventDeletion) events that request removal of purgatory entries
/// for repository announcements (kind 30617) and state events (kind 30618).
///
/// ## NIP-09 Rules Enforced
///
/// - Only the event author can delete their own events (pubkey must match)
/// - `e` tags reference specific event IDs to delete
/// - `a` tags reference addressable events by coordinate (`<kind>:<pubkey>:<d-identifier>`)
/// - When an `a` tag is used, all versions up to `created_at` of the deletion request
///   are considered deleted
///
/// ## Purgatory Interaction
///
/// - Kind 30617 (announcement) in purgatory: entry removed, bare repo deleted from disk
/// - Kind 30618 (state event) in purgatory: matching state event(s) removed by event ID
///   or by (author, identifier) coordinate
/// ## Main-database interaction
///
/// Because the relay now runs the LMDB backend with `process_nip09(false)`,
/// ngit-grasp owns NIP-09 entirely. In addition to evicting purgatory entries,
/// the handler:
/// - hard-deletes the targeted events from the main database (the backend used
///   to do this for us), and
/// - records the deletion request in the persistent [`Tombstones`] store so
///   re-submission of the deleted event/coordinate stays rejected across
///   restarts (the resubmission gate in `builder.rs` consults this store).
///
/// Author ownership is enforced before any main-DB deletion or tombstone
/// recording: only the original author may delete their event.
use nostr_relay_builder::prelude::{
    Alphabet, Event, EventId, Filter, Kind, PublicKey, SingleLetterTag, WritePolicyResult,
};

use super::PolicyContext;
use crate::nostr::policy::reject_invalid;

/// Policy for handling NIP-09 event deletion requests
#[derive(Clone)]
pub struct DeletionPolicy {
    ctx: PolicyContext,
}

impl DeletionPolicy {
    pub fn new(ctx: PolicyContext) -> Self {
        Self { ctx }
    }

    /// Process a kind 5 (EventDeletion) event.
    ///
    /// Removes any targeted purgatory entries, hard-deletes targeted events from
    /// the main database, and records the deletion in the persistent tombstone
    /// store so the deletion survives restarts and re-submission is blocked.
    ///
    /// The deletion event itself is accepted (and therefore stored) per NIP-09 —
    /// unless it is an *invalid* delete (it references an event owned by a
    /// different author), in which case it is rejected, matching the LMDB
    /// backend's historical `InvalidDelete` behaviour.
    ///
    /// Only the event author can delete their own events. Authorship is checked
    /// per-target: `e`-tag targets must be authored by the deleter, and `a`-tag
    /// coordinates must carry the deleter's pubkey.
    ///
    /// ## Disrespector mode
    ///
    /// When `deletion_request_disrespector` is enabled the relay acts as an
    /// archival server: the kind-5 event is still accepted (and stored in the
    /// main database) so clients see an OK and the request is preserved, but it
    /// is NOT acted upon — no purgatory eviction, no main-DB deletion, and no
    /// tombstone recording. The targeted events therefore remain fully
    /// accessible. This only affects NIP-09 user-initiated deletions; it does
    /// not influence blacklist-triggered deletions.
    pub async fn handle(&self, event: &Event) -> WritePolicyResult {
        // Archival mode: store the deletion request but do not process it.
        if self.ctx.config.deletion_request_disrespector {
            tracing::info!(
                event_id = %event.id.to_hex(),
                author = %event.pubkey.to_hex(),
                "Disrespector mode: storing NIP-09 deletion request without acting on it"
            );
            return WritePolicyResult::Accept;
        }

        // Validate authorship of all targets first. If any `e`-tag target exists
        // in the main DB and is owned by someone else, the whole deletion is
        // invalid (mirrors the backend's `handle_deletion_event` returning
        // `invalid`). `a`-tag author mismatches are simply ignored (the
        // coordinate pubkey is part of the tag, so a mismatch is a no-op rather
        // than an attack signal).
        for id in Self::e_tag_ids(event) {
            match self.ctx.database.event_by_id(&id).await {
                Ok(Some(target)) if target.pubkey != event.pubkey => {
                    tracing::warn!(
                        deleter = %event.pubkey.to_hex(),
                        target_author = %target.pubkey.to_hex(),
                        target_id = %id.to_hex(),
                        "Rejected invalid NIP-09 deletion: target authored by another pubkey"
                    );
                    return reject_invalid("cannot delete event authored by another pubkey");
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "Database lookup failed during deletion validation");
                    return super::reject_error(format!("internal error: {e}"));
                }
            }
        }

        // Process purgatory removals (synchronous, in-memory).
        self.remove_purgatory_targets(event);

        // Hard-delete targeted events from the main database.
        self.delete_main_db_targets(event).await;

        // Record the deletion so future re-submission is rejected.
        if let Err(e) = self.ctx.tombstones.record_deletion(event).await {
            tracing::error!(error = %e, "Failed to record deletion tombstone");
            return super::reject_error(format!("internal error recording deletion: {e}"));
        }

        // Accept the deletion event itself so it is stored.
        WritePolicyResult::Accept
    }

    /// Extract all event-id (`e` tag) targets from a deletion event.
    fn e_tag_ids(event: &Event) -> Vec<EventId> {
        event
            .tags
            .iter()
            .filter_map(|tag| {
                let v = tag.as_slice();
                if v.len() >= 2 && v[0] == "e" {
                    EventId::from_hex(&v[1]).ok()
                } else {
                    None
                }
            })
            .collect()
    }

    /// Hard-delete the targeted events from the main database.
    ///
    /// Handles both `e`-tag (by event id) and `a`-tag (by coordinate) targets.
    /// Authorship for `e`-tag targets was validated in [`handle`]; `a`-tag
    /// coordinates carry their own pubkey which is matched against the deleter.
    async fn delete_main_db_targets(&self, event: &Event) {
        // `e` tags: delete by event id.
        let ids = Self::e_tag_ids(event);
        if !ids.is_empty() {
            let filter = Filter::new().ids(ids);
            if let Err(e) = self.ctx.database.delete(filter).await {
                tracing::warn!(error = %e, "Failed to delete events by id during NIP-09 deletion");
            }
        }

        // `a` tags: delete matching addressable/replaceable events up to the
        // deletion's created_at.
        for tag in event.tags.iter() {
            let v = tag.as_slice();
            if v.len() < 2 || v[0] != "a" {
                continue;
            }
            self.delete_coordinate_from_main_db(&event.pubkey, &v[1], event.created_at)
                .await;
        }
    }

    /// Delete events matching an `a`-tag coordinate from the main database.
    async fn delete_coordinate_from_main_db(
        &self,
        author: &PublicKey,
        coordinate: &str,
        deletion_created_at: nostr_relay_builder::prelude::Timestamp,
    ) {
        // coordinate: `<kind>:<pubkey>:<d-identifier>`
        let parts: Vec<&str> = coordinate.splitn(3, ':').collect();
        if parts.len() != 3 {
            return;
        }
        let Ok(kind_num) = parts[0].parse::<u16>() else {
            return;
        };
        let coord_pubkey_hex = parts[1];
        let identifier = parts[2];

        // The coordinate pubkey must match the deletion author.
        if coord_pubkey_hex != author.to_hex() {
            return;
        }

        let kind = Kind::from(kind_num);
        let mut filter = Filter::new().kind(kind).author(*author);
        if kind.is_addressable() {
            filter = filter.custom_tag(
                SingleLetterTag::lowercase(Alphabet::D),
                identifier.to_string(),
            );
        }
        // Per NIP-09, only versions up to the deletion's created_at are deleted.
        filter = filter.until(deletion_created_at);

        if let Err(e) = self.ctx.database.delete(filter).await {
            tracing::warn!(
                error = %e,
                coordinate = %coordinate,
                "Failed to delete events by coordinate during NIP-09 deletion"
            );
        }
    }

    /// Remove any purgatory entries targeted by this deletion event.
    ///
    /// Handles both reference styles from NIP-09:
    /// - `e` tags: event ID references — match against announcement or state event IDs
    /// - `a` tags: addressable coordinate references — `30617:…` or `30618:…`
    ///
    /// Only removes entries where the purgatory entry's author matches the deletion
    /// event's pubkey (enforces author-only deletion).
    fn remove_purgatory_targets(&self, event: &Event) {
        let author = &event.pubkey;

        for tag in event.tags.iter() {
            let tag_vec = tag.as_slice();
            if tag_vec.len() < 2 {
                continue;
            }

            match tag_vec[0].as_str() {
                "e" => {
                    // Event ID reference: find purgatory announcement with this event ID
                    let target_id = &tag_vec[1];
                    self.remove_by_event_id(author, target_id, event.created_at.as_secs());
                }
                "a" => {
                    // Addressable coordinate reference: `<kind>:<pubkey>:<d-identifier>`
                    let coord = &tag_vec[1];
                    self.remove_by_coordinate(author, coord, event.created_at.as_secs());
                }
                _ => {}
            }
        }
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
    ) {
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
                    return;
                }
            }
            // Entry exists but is a placeholder or wrong author — don't remove
            return;
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
                    self.evict_purgatory_entry(author, identifier);
                    return; // event IDs are unique
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
                    return; // event IDs are unique
                }
            }
        }
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
    ) {
        // Parse coordinate: `<kind>:<pubkey>:<d-identifier>`
        let parts: Vec<&str> = coordinate.splitn(3, ':').collect();
        if parts.len() != 3 {
            return;
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
            return;
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
                        self.evict_purgatory_entry(author, identifier);
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
                        removed += 1;
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
    }

    /// Remove a purgatory announcement and delete its bare repository from disk.
    fn evict_purgatory_entry(
        &self,
        author: &nostr_relay_builder::prelude::PublicKey,
        identifier: &str,
    ) {
        // Get repo path before removing
        if let Some(entry) = self.ctx.purgatory.find_announcement(author, identifier) {
            if entry.repo_path.exists() {
                if let Err(e) = std::fs::remove_dir_all(&entry.repo_path) {
                    tracing::warn!(
                        path = %entry.repo_path.display(),
                        error = %e,
                        "Failed to delete bare repository during deletion request processing"
                    );
                } else {
                    tracing::info!(
                        path = %entry.repo_path.display(),
                        "Deleted bare repository for deletion-requested purgatory announcement"
                    );
                }
            }
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
            self.ctx.purgatory.remove_state(identifier);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::policy::PolicyContext;
    use crate::purgatory::Purgatory;
    use nostr_relay_builder::prelude::*;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn make_context() -> PolicyContext {
        let db = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let purgatory = Arc::new(Purgatory::new(PathBuf::new()));
        let config = crate::config::Config::for_testing();
        PolicyContext::new_for_test("test.example.com", db, PathBuf::new(), purgatory, config)
    }

    fn make_disrespector_context() -> PolicyContext {
        let db = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let purgatory = Arc::new(Purgatory::new(PathBuf::new()));
        let config = crate::config::Config {
            deletion_request_disrespector: true,
            ..crate::config::Config::for_testing()
        };
        PolicyContext::new_for_test("test.example.com", db, PathBuf::new(), purgatory, config)
    }

    fn make_announcement_event(keys: &Keys, identifier: &str) -> Event {
        EventBuilder::new(Kind::GitRepoAnnouncement, "")
            .tags(vec![
                Tag::identifier(identifier),
                Tag::custom("clone", vec!["https://example.com/repo.git"]),
            ])
            .finalize(keys)
            .unwrap()
    }

    fn add_to_purgatory(ctx: &PolicyContext, event: &Event, identifier: &str) {
        ctx.purgatory.add_announcement(
            event.clone(),
            identifier.to_string(),
            event.pubkey,
            PathBuf::new(),
            HashSet::new(),
        );
    }

    #[tokio::test]
    async fn test_deletion_by_event_id_removes_purgatory_entry() {
        let ctx = make_context();
        let keys = Keys::generate();
        let identifier = "my-repo";

        let announcement = make_announcement_event(&keys, identifier);
        add_to_purgatory(&ctx, &announcement, identifier);

        assert!(ctx
            .purgatory
            .has_purgatory_announcement(&keys.public_key(), identifier));

        // Build kind 5 deletion event referencing the announcement by event ID
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![
                Tag::event(announcement.id),
                Tag::custom("k", vec!["30617"]),
            ])
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        let result = policy.handle(&deletion).await;

        assert!(matches!(result, WritePolicyResult::Accept));
        assert!(
            !ctx.purgatory
                .has_purgatory_announcement(&keys.public_key(), identifier),
            "Purgatory entry should have been removed"
        );
    }

    #[tokio::test]
    async fn test_deletion_by_coordinate_removes_purgatory_entry() {
        let ctx = make_context();
        let keys = Keys::generate();
        let identifier = "my-repo";

        let announcement = make_announcement_event(&keys, identifier);
        add_to_purgatory(&ctx, &announcement, identifier);

        assert!(ctx
            .purgatory
            .has_purgatory_announcement(&keys.public_key(), identifier));

        // Build kind 5 deletion event referencing the announcement by coordinate
        let coord = format!("30617:{}:{}", keys.public_key().to_hex(), identifier);
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![
                Tag::custom("a", vec![coord]),
                Tag::custom("k", vec!["30617"]),
            ])
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        let result = policy.handle(&deletion).await;

        assert!(matches!(result, WritePolicyResult::Accept));
        assert!(
            !ctx.purgatory
                .has_purgatory_announcement(&keys.public_key(), identifier),
            "Purgatory entry should have been removed"
        );
    }

    #[tokio::test]
    async fn test_deletion_by_wrong_author_does_not_remove() {
        let ctx = make_context();
        let owner_keys = Keys::generate();
        let attacker_keys = Keys::generate();
        let identifier = "my-repo";

        let announcement = make_announcement_event(&owner_keys, identifier);
        add_to_purgatory(&ctx, &announcement, identifier);

        // Attacker tries to delete by event ID
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![
                Tag::event(announcement.id),
                Tag::custom("k", vec!["30617"]),
            ])
            .finalize(&attacker_keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        let result = policy.handle(&deletion).await;

        assert!(matches!(result, WritePolicyResult::Accept));
        assert!(
            ctx.purgatory
                .has_purgatory_announcement(&owner_keys.public_key(), identifier),
            "Purgatory entry should NOT have been removed by wrong author"
        );
    }

    #[tokio::test]
    async fn test_deletion_by_coordinate_wrong_author_does_not_remove() {
        let ctx = make_context();
        let owner_keys = Keys::generate();
        let attacker_keys = Keys::generate();
        let identifier = "my-repo";

        let announcement = make_announcement_event(&owner_keys, identifier);
        add_to_purgatory(&ctx, &announcement, identifier);

        // Attacker tries to delete by coordinate using owner's pubkey in coord
        // but signs with their own key — coord pubkey != deletion author
        let coord = format!("30617:{}:{}", owner_keys.public_key().to_hex(), identifier);
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![
                Tag::custom("a", vec![coord]),
                Tag::custom("k", vec!["30617"]),
            ])
            .finalize(&attacker_keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        let result = policy.handle(&deletion).await;

        assert!(matches!(result, WritePolicyResult::Accept));
        assert!(
            ctx.purgatory
                .has_purgatory_announcement(&owner_keys.public_key(), identifier),
            "Purgatory entry should NOT have been removed by wrong author"
        );
    }

    #[tokio::test]
    async fn test_deletion_of_nonexistent_entry_is_accepted() {
        let ctx = make_context();
        let keys = Keys::generate();

        // No purgatory entry exists — deletion should still be accepted
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom(
                "a",
                vec![format!("30617:{}:nonexistent", keys.public_key().to_hex())],
            )])
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        let result = policy.handle(&deletion).await;

        assert!(matches!(result, WritePolicyResult::Accept));
    }

    #[tokio::test]
    async fn test_deletion_by_coordinate_respects_created_at() {
        let ctx = make_context();
        let keys = Keys::generate();
        let identifier = "my-repo";

        // Create announcement with a future timestamp
        let future_ts = Timestamp::now().as_secs() + 3600; // 1 hour in the future
        let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
            .tags(vec![Tag::identifier(identifier)])
            .custom_created_at(Timestamp::from(future_ts))
            .finalize(&keys)
            .unwrap();
        add_to_purgatory(&ctx, &announcement, identifier);

        // Deletion event with current timestamp (older than announcement)
        let coord = format!("30617:{}:{}", keys.public_key().to_hex(), identifier);
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord])])
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        let result = policy.handle(&deletion).await;

        assert!(matches!(result, WritePolicyResult::Accept));
        assert!(
            ctx.purgatory
                .has_purgatory_announcement(&keys.public_key(), identifier),
            "Purgatory entry should NOT be removed: entry is newer than deletion request"
        );
    }

    #[tokio::test]
    async fn test_disrespector_accepts_but_does_not_remove_purgatory_entry() {
        let ctx = make_disrespector_context();
        let keys = Keys::generate();
        let identifier = "my-repo";

        let announcement = make_announcement_event(&keys, identifier);
        add_to_purgatory(&ctx, &announcement, identifier);

        assert!(ctx
            .purgatory
            .has_purgatory_announcement(&keys.public_key(), identifier));

        // Deletion event the author is allowed to make.
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![
                Tag::event(announcement.id),
                Tag::custom("k", vec!["30617"]),
            ])
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        let result = policy.handle(&deletion).await;

        // The deletion request is accepted (stored) ...
        assert!(matches!(result, WritePolicyResult::Accept));
        // ... but NOT acted upon: the purgatory entry remains.
        assert!(
            ctx.purgatory
                .has_purgatory_announcement(&keys.public_key(), identifier),
            "Disrespector mode must NOT remove the purgatory entry"
        );
    }

    #[tokio::test]
    async fn test_disrespector_does_not_record_tombstone() {
        let ctx = make_disrespector_context();
        let keys = Keys::generate();
        let target = EventId::all_zeros();

        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target)])
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        let result = policy.handle(&deletion).await;

        assert!(matches!(result, WritePolicyResult::Accept));
        // No tombstone recorded -> re-submission of the target is NOT blocked.
        assert!(
            !ctx.tombstones.is_event_deleted(&target).await,
            "Disrespector mode must NOT record a deletion tombstone"
        );
    }

    #[tokio::test]
    async fn test_disrespector_does_not_delete_target_from_main_db() {
        let ctx = make_disrespector_context();
        let keys = Keys::generate();

        // Store a target event in the main DB.
        let target = make_announcement_event(&keys, "keep-me");
        ctx.database.save_event(&target).await.unwrap();

        // Author requests its deletion.
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target.id)])
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        let result = policy.handle(&deletion).await;

        assert!(matches!(result, WritePolicyResult::Accept));
        // Target must still be present in the main database.
        let still_there = ctx.database.event_by_id(&target.id).await.unwrap();
        assert!(
            still_there.is_some(),
            "Disrespector mode must NOT delete the target from the main DB"
        );
    }
}
