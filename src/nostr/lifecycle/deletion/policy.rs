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
///   restarts (the deletion gate in [`DeletionService`](super::DeletionService)
///   consults this store).
///
/// Author ownership is enforced before any main-DB deletion or tombstone
/// recording: only the original author may delete their event.
use std::collections::HashSet;

use nostr::nips::nip19::ToBech32;
use nostr_relay_builder::prelude::{Event, EventId, Kind, PublicKey, WritePolicyResult};

use super::DeletionContext;
use crate::nostr::policy::{reject_error, reject_invalid};

const MAX_DELETION_TARGET_TAGS: usize = 2048;
/// Policy for handling NIP-09 event deletion requests
#[derive(Clone)]
pub struct DeletionPolicy {
    pub(super) ctx: DeletionContext,
}

impl DeletionPolicy {
    pub fn new(ctx: impl Into<DeletionContext>) -> Self {
        let ctx = ctx.into();
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
    /// accessible. The same archival-mode contract is applied to NIP-62 vanish
    /// requests in [`DeletionService::handle_vanish`](super::service::DeletionService::handle_vanish).
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

        let target_tag_count = event
            .tags
            .iter()
            .filter(|tag| {
                let v = tag.as_slice();
                v.len() >= 2 && (v[0] == "e" || v[0] == "a")
            })
            .count();
        if target_tag_count > MAX_DELETION_TARGET_TAGS {
            tracing::warn!(
                event_id = %event.id.to_hex(),
                target_tag_count,
                max = MAX_DELETION_TARGET_TAGS,
                "Rejected NIP-09 deletion with too many targets"
            );
            return reject_invalid("too many deletion targets");
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
                    return reject_error(format!("internal error: {e}"));
                }
            }
        }

        // Lifecycle lock discipline: acquire per `(owner, identifier)` locks
        // before mutating tombstones, main DB, holding DB, archives, repository
        // directories, or purgatory. Git Smart HTTP fetch/info-refs and push
        // handlers take shared read locks for the served repository, so
        // delete/archive/restore cannot remove or replace a bare repo while Git
        // is using it.
        let _lifecycle_guards = self
            .ctx
            .lifecycle()
            .write_repositories(self.deletion_recovery_scopes(event).await)
            .await;

        // Record the deletion before destructive work so a tombstone write
        // failure rejects the deletion request without already having removed
        // targets from purgatory/main DB/holding/archive state. Subsequent
        // destructive steps are best-effort and log their own failures; the
        // tombstone is the durable operation marker and resubmission gate source.
        if let Err(e) = self.ctx.tombstones.record_deletion(event).await {
            tracing::error!(error = %e, "Failed to record deletion tombstone");
            return reject_error(format!("internal error recording deletion: {e}"));
        }

        let rollback_plans = self.collect_replaceable_rollback_plans(event).await;
        let mut identifiers_to_realign = Self::state_a_tag_identifiers_for_author(event);

        // Process purgatory removals (synchronous, in-memory).
        self.remove_purgatory_targets(event);

        // Move targeted events into holding DB, then delete from main DB.
        let mut moved_ids = HashSet::new();
        self.delete_main_db_targets(event, &mut moved_ids).await;

        for plan in &rollback_plans {
            self.rollback_deleted_active_replaceable(plan).await;
            if plan.kind == Kind::RepoState.as_u16() {
                identifiers_to_realign.insert(plan.identifier.clone());
            }
        }

        for identifier in identifiers_to_realign {
            self.realign_identifier_state(&identifier).await;
        }

        // Accept the deletion event itself so it is stored.
        WritePolicyResult::Accept
    }

    /// Extract all event-id (`e` tag) targets from a deletion event.
    pub(super) fn e_tag_ids(event: &Event) -> Vec<EventId> {
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
}

/// Build the `30617:<pubkey>:<identifier>` coordinate string for a kind-30617
/// announcement event (the identifier comes from its `d` tag).
pub(super) fn announcement_address_of(event: &Event) -> String {
    let identifier = event
        .tags
        .iter()
        .find_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == "d" {
                Some(v[1].clone())
            } else {
                None
            }
        })
        .unwrap_or_default();
    format!("30617:{}:{}", event.pubkey.to_hex(), identifier)
}

pub(super) fn identifier_from_event(event: &Event) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.as_slice();
        if v.len() >= 2 && v[0] == "d" {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

pub(super) fn owner_directory_component(pubkey: &PublicKey) -> String {
    pubkey.to_bech32().unwrap_or_else(|_| pubkey.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grasp06::receive::new_repo_init_locks;
    use crate::nostr::lifecycle::HoldingStore;
    use crate::nostr::lifecycle::ReplaceableHistoryStore;
    use crate::nostr::lifecycle::RepositoryLifecycle;
    use crate::nostr::lifecycle::Tombstones;
    use crate::purgatory::Purgatory;
    use nostr_relay_builder::prelude::*;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn make_context() -> DeletionContext {
        let db = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let purgatory = Arc::new(Purgatory::new(PathBuf::new()));
        let config = crate::config::Config::for_testing();
        let holding = HoldingStore::in_memory();
        DeletionContext::new(
            "test.example.com",
            db,
            Tombstones::in_memory(),
            holding.clone(),
            RepositoryLifecycle::in_memory(),
            ReplaceableHistoryStore::in_memory(),
            PathBuf::new(),
            purgatory,
            config,
            new_repo_init_locks(),
        )
    }

    fn make_disrespector_context() -> DeletionContext {
        let db = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let purgatory = Arc::new(Purgatory::new(PathBuf::new()));
        let config = crate::config::Config {
            deletion_request_disrespector: true,
            ..crate::config::Config::for_testing()
        };
        let holding = HoldingStore::in_memory();
        DeletionContext::new(
            "test.example.com",
            db,
            Tombstones::in_memory(),
            holding.clone(),
            RepositoryLifecycle::in_memory(),
            ReplaceableHistoryStore::in_memory(),
            PathBuf::new(),
            purgatory,
            config,
            new_repo_init_locks(),
        )
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

    fn add_to_purgatory(ctx: &DeletionContext, event: &Event, identifier: &str) {
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
        assert!(
            ctx.tombstones
                .is_event_deleted(&announcement.id, &keys.public_key())
                .await,
            "accepted deletion must persist a tombstone as the durable operation marker"
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
    async fn deletion_with_excessive_target_tags_is_rejected() {
        let ctx = make_context();
        let keys = Keys::generate();
        let tags = (0..=MAX_DELETION_TARGET_TAGS)
            .map(|i| {
                Tag::custom(
                    "a",
                    vec![format!("30617:{}:repo-{i}", keys.public_key().to_hex())],
                )
            })
            .collect::<Vec<_>>();

        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx);
        let result = policy.handle(&deletion).await;

        assert!(matches!(result, WritePolicyResult::Reject { .. }));
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
            !ctx.tombstones
                .is_event_deleted(&target, &keys.public_key())
                .await,
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

    #[test]
    fn test_grasp06_pr_clone_tags_map_to_prs_repo_paths() {
        let db = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let purgatory = Arc::new(Purgatory::new(PathBuf::new()));
        let git_data_path = PathBuf::from("/tmp/ngit-grasp-test-git");
        let config = crate::config::Config {
            domain: "test.example.com".to_string(),
            ..crate::config::Config::for_testing()
        };
        let holding = HoldingStore::in_memory();
        let ctx = DeletionContext::new(
            "test.example.com",
            db,
            Tombstones::in_memory(),
            holding.clone(),
            RepositoryLifecycle::in_memory(),
            ReplaceableHistoryStore::in_memory(),
            git_data_path.clone(),
            purgatory,
            config,
            new_repo_init_locks(),
        );

        let signer = Keys::generate();
        let target = Keys::generate();
        let npub = signer.public_key().to_bech32().expect("pubkey to bech32");
        let event = EventBuilder::new(Kind::GitPullRequest, "prs clone test")
            .tags(vec![
                Tag::custom(
                    "a",
                    vec![format!(
                        "30617:{}:{}",
                        target.public_key().to_hex(),
                        "my-repo"
                    )],
                ),
                Tag::custom(
                    "clone",
                    vec![format!(
                        "http://test.example.com/prs/{}/{}.git",
                        npub, "my-repo"
                    )],
                ),
                Tag::custom("c", vec!["0".repeat(40)]),
            ])
            .finalize(&signer)
            .expect("build pr event");

        let policy = DeletionPolicy::new(ctx.clone());
        let paths = policy.collect_grasp06_repo_paths_for_pr_event(&event);
        let expected = crate::grasp06::paths::prs_repo_path(
            &git_data_path,
            &signer.public_key().to_hex(),
            "my-repo",
        );

        assert!(
            paths.contains(&expected),
            "expected /prs/ repo path derived from clone tag"
        );
    }
}
