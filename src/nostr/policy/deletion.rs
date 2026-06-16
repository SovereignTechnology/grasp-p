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
use nostr_relay_builder::prelude::{Event, WritePolicyResult};

use super::PolicyContext;

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
    /// Checks whether the deletion request targets any purgatory announcements
    /// and removes them if so. The deletion event itself is always accepted
    /// (relays should store deletion requests per NIP-09).
    ///
    /// Only the event author can delete their own events — this is enforced by
    /// checking that the purgatory entry's owner matches `event.pubkey`.
    pub async fn handle(&self, event: &Event) -> WritePolicyResult {
        // Process purgatory removals synchronously (no async needed)
        self.remove_purgatory_targets(event);

        // Always accept the deletion event itself so it is stored and
        // can prevent re-acceptance of the deleted event in the future.
        WritePolicyResult::Accept
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
}
