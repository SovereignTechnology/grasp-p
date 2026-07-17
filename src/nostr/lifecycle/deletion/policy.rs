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
use nostr_relay_builder::prelude::{
    Alphabet, Event, EventId, Filter, Kind, PublicKey, SingleLetterTag, Timestamp,
    WritePolicyResult,
};

use super::service::{request_is_served_with_config, UNSERVED_REPLAY_MESSAGE};
use super::DeletionContext;
use crate::nostr::lifecycle::RequestClassification;
use crate::nostr::policy::{duplicate, reject_error, reject_invalid};

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
    /// main database) so clients see an OK and the request is preserved. It
    /// receives disrespector lifecycle metadata and is evaluated read-only to
    /// determine whether it would delete stored data under normal policy, but
    /// it never installs a local gate or mutates targets. Distinct signed
    /// kind-5 requests receive independent lifecycle records even when their
    /// targets overlap. The same archival-mode contract is applied to NIP-62
    /// vanish requests in
    /// [`DeletionService::handle_vanish`](super::service::DeletionService::handle_vanish).
    pub async fn handle(&self, event: &Event) -> WritePolicyResult {
        if let Err(result) = self.validate_request(event).await {
            return result;
        }

        let classification = if self.ctx.config.deletion_request_disrespector {
            RequestClassification::Disrespector
        } else {
            RequestClassification::LocallyActionable
        };
        // Hold the lifecycle lock through the admission decision so cleanup
        // cannot race an exact replay back into Main after its served deadline.
        let tombstones = &self.ctx.tombstones;
        let record_result = {
            let _lifecycle_guard = tombstones.lock_lifecycle().await;
            let existing = match tombstones.lifecycle_for_request_result(&event.id).await {
                Ok(record) => record,
                Err(error) => {
                    tracing::error!(event_id = %event.id.to_hex(), error = %error, "Failed to read NIP-09 deletion lifecycle");
                    return reject_error(format!(
                        "internal error reading deletion lifecycle: {error}"
                    ));
                }
            };
            if let Some(record) = existing {
                match request_is_served_with_config(&self.ctx, &record, Timestamp::now()) {
                    Ok(false) => return duplicate(UNSERVED_REPLAY_MESSAGE),
                    Ok(true) => {}
                    Err(error) => {
                        tracing::error!(event_id = %event.id.to_hex(), error = %error, "Failed to evaluate NIP-09 deletion lifecycle retention");
                        return reject_error(format!(
                            "internal error evaluating deletion lifecycle retention: {error}"
                        ));
                    }
                }
            }
            tombstones
                .record_request_locked(event, Timestamp::now(), classification)
                .await
        };
        if let Err(e) = record_result {
            tracing::error!(event_id = %event.id.to_hex(), error = %e, "Failed to record NIP-09 deletion lifecycle");
            return reject_error(format!("internal error recording deletion lifecycle: {e}"));
        }

        // Archival mode: retain and classify the deletion request without
        // invoking any destructive lifecycle paths.
        if self.ctx.config.deletion_request_disrespector {
            let would_delete = match self.would_delete_stored_target(event).await {
                Ok(would_delete) => would_delete,
                Err(e) => {
                    tracing::error!(event_id = %event.id.to_hex(), error = %e, "Failed to evaluate disrespector NIP-09 request");
                    return reject_error(format!(
                        "internal error evaluating deletion request: {e}"
                    ));
                }
            };
            if would_delete {
                if let Err(result) = self.mark_request_used(event).await {
                    return result;
                }
            }
            tracing::info!(
                event_id = %event.id.to_hex(),
                author = %event.pubkey.to_hex(),
                would_delete,
                "Disrespector mode: stored and read-only evaluated NIP-09 deletion request"
            );
            return WritePolicyResult::Accept;
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

        let rollback_plans = self.collect_replaceable_rollback_plans(event).await;
        let mut identifiers_to_realign = Self::state_a_tag_identifiers_for_author(event);

        // Process purgatory removals (synchronous, in-memory).
        let mut outcome = self.remove_purgatory_targets(event);

        // Move targeted events into holding DB, then delete from main DB.
        let mut moved_ids = HashSet::new();
        outcome.merge(self.delete_main_db_targets(event, &mut moved_ids).await);

        for plan in &rollback_plans {
            self.rollback_deleted_active_replaceable(plan).await;
            if plan.kind == Kind::RepoState.as_u16() {
                identifiers_to_realign.insert(plan.identifier.clone());
            }
        }

        for identifier in identifiers_to_realign {
            self.realign_identifier_state(&identifier).await;
        }

        if outcome.used() {
            if let Err(result) = self.mark_request_used(event).await {
                return result;
            }
        }
        tracing::info!(event_id = %event.id.to_hex(), main_db_deleted = outcome.main_db_deleted, purgatory_removed = outcome.purgatory_removed, skipped = outcome.skipped, failures = outcome.failures, "Processed NIP-09 deletion outcome");

        // Accept the deletion event itself so it is stored.
        WritePolicyResult::Accept
    }

    /// Validate all admission inputs before lifecycle persistence or target work.
    async fn validate_request(&self, event: &Event) -> Result<(), WritePolicyResult> {
        let target_tag_count = event
            .tags
            .iter()
            .filter(|tag| {
                let v = tag.as_slice();
                v.len() >= 2 && (v[0] == "e" || v[0] == "a")
            })
            .count();
        if target_tag_count > MAX_DELETION_TARGET_TAGS {
            tracing::warn!(event_id = %event.id.to_hex(), target_tag_count, max = MAX_DELETION_TARGET_TAGS, "Rejected NIP-09 deletion with too many targets");
            return Err(reject_invalid("too many deletion targets"));
        }

        // An existing cross-author `e` target invalidates the entire request.
        // Foreign and malformed `a` coordinates remain NIP-09 no-ops.
        for id in Self::e_tag_ids(event) {
            match self.ctx.database.event_by_id(&id).await {
                Ok(Some(target)) if target.pubkey != event.pubkey => {
                    tracing::warn!(deleter = %event.pubkey.to_hex(), target_author = %target.pubkey.to_hex(), target_id = %id.to_hex(), "Rejected invalid NIP-09 deletion: target authored by another pubkey");
                    return Err(reject_invalid(
                        "cannot delete event authored by another pubkey",
                    ));
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "Database lookup failed during deletion validation");
                    return Err(reject_error(format!("internal error: {e}")));
                }
            }
        }
        Ok(())
    }

    async fn mark_request_used(&self, event: &Event) -> Result<(), WritePolicyResult> {
        match self
            .ctx
            .tombstones
            .mark_request_used(&event.id, Timestamp::now())
            .await
        {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(reject_error(
                "internal error updating deletion lifecycle: missing metadata",
            )),
            Err(e) => {
                tracing::error!(event_id = %event.id.to_hex(), error = %e, "Failed to mark used NIP-09 deletion request after target processing");
                Err(reject_error(format!(
                    "internal error updating deletion lifecycle: {e}"
                )))
            }
        }
    }

    /// Read-only normal-policy target evaluation for disrespector mode.
    /// This intentionally only queries the main database and purgatory snapshots;
    /// it must not call deletion, holding, archive, rollback, or cascade helpers.
    pub(super) async fn would_delete_stored_target(&self, event: &Event) -> anyhow::Result<bool> {
        for id in Self::e_tag_ids(event) {
            if self.ctx.database.event_by_id(&id).await?.is_some() {
                return Ok(true);
            }
        }

        for coordinate in Self::a_tag_coordinates(event) {
            let Some((kind, owner, identifier)) = Self::parse_coordinate(&coordinate) else {
                continue;
            };
            if owner != event.pubkey {
                continue;
            }
            let mut filter = Filter::new()
                .kind(kind)
                .author(owner)
                .until(event.created_at);
            if kind.is_addressable() {
                filter =
                    filter.custom_tag(SingleLetterTag::lowercase(Alphabet::D), identifier.clone());
            }
            if !self.ctx.database.query(filter).await?.is_empty() {
                return Ok(true);
            }
        }

        Ok(self.purgatory_target_would_be_removed(event))
    }

    fn purgatory_target_would_be_removed(&self, event: &Event) -> bool {
        for id in Self::e_tag_ids(event) {
            for (repository_id, _) in self.ctx.purgatory.announcements_for_sync() {
                let parts: Vec<_> = repository_id.splitn(3, ':').collect();
                if parts.len() == 3
                    && parts[1] == event.pubkey.to_hex()
                    && self
                        .ctx
                        .purgatory
                        .find_announcement(&event.pubkey, parts[2])
                        .is_some_and(|entry| entry.event.id == id)
                {
                    return true;
                }
            }
            if self
                .ctx
                .purgatory
                .get_all_identifiers()
                .into_iter()
                .any(|identifier| {
                    self.ctx
                        .purgatory
                        .find_state(&identifier)
                        .into_iter()
                        .any(|entry| entry.author == event.pubkey && entry.event.id == id)
                })
            {
                return true;
            }
        }

        for coordinate in Self::a_tag_coordinates(event) {
            let Some((kind, owner, identifier)) = Self::parse_coordinate(&coordinate) else {
                continue;
            };
            if owner != event.pubkey {
                continue;
            }
            let covered = |created_at: Timestamp| created_at <= event.created_at;
            match kind {
                Kind::GitRepoAnnouncement => {
                    if self
                        .ctx
                        .purgatory
                        .find_announcement(&owner, &identifier)
                        .is_some_and(|entry| covered(entry.event.created_at))
                    {
                        return true;
                    }
                }
                Kind::RepoState
                    if self
                        .ctx
                        .purgatory
                        .find_state(&identifier)
                        .into_iter()
                        .any(|entry| entry.author == owner && covered(entry.event.created_at)) =>
                {
                    return true;
                }
                _ => {}
            }
        }
        false
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
    use crate::nostr::lifecycle::DeletionService;
    use crate::nostr::lifecycle::HoldingStore;
    use crate::nostr::lifecycle::ReplaceableHistoryStore;
    use crate::nostr::lifecycle::RepositoryLifecycle;
    use crate::nostr::lifecycle::RequestLifecycleRecord;
    use crate::nostr::lifecycle::Tombstones;
    use crate::purgatory::Purgatory;
    use nostr_relay_builder::prelude::*;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;

    trait TombstoneTestExt {
        async fn lifecycle_for_request(
            &self,
            request_id: &EventId,
        ) -> Option<RequestLifecycleRecord>;
        async fn is_event_deleted(&self, id: &EventId, author: &PublicKey) -> bool;
    }

    impl TombstoneTestExt for Tombstones {
        async fn lifecycle_for_request(
            &self,
            request_id: &EventId,
        ) -> Option<RequestLifecycleRecord> {
            self.lifecycle_for_request_result(request_id).await.unwrap()
        }

        async fn is_event_deleted(&self, id: &EventId, author: &PublicKey) -> bool {
            !self
                .event_deletion_candidates(id, author)
                .await
                .unwrap()
                .is_empty()
        }
    }

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
        assert_eq!(
            ctx.tombstones
                .event_deletion_candidates(&announcement.id, &keys.public_key())
                .await
                .unwrap()
                .len(),
            1,
            "accepted deletion must persist a lifecycle-backed tombstone"
        );
    }

    #[tokio::test]
    async fn distinct_overlapping_deletion_requests_are_independently_accepted() {
        let ctx = make_context();
        let keys = Keys::generate();
        let target = EventId::all_zeros();

        let first = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target)])
            .custom_created_at(Timestamp::from_secs(1000))
            .finalize(&keys)
            .unwrap();
        let overlapping = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target)])
            .custom_created_at(Timestamp::from_secs(1001))
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx);
        let first_result = policy.handle(&first).await;
        assert!(matches!(first_result, WritePolicyResult::Accept));

        assert!(matches!(
            policy.handle(&overlapping).await,
            WritePolicyResult::Accept
        ));
        let records = policy
            .ctx
            .tombstones
            .lifecycle_records_result()
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|record| record.request.id == first.id));
        assert!(records
            .iter()
            .any(|record| record.request.id == overlapping.id));
    }

    #[tokio::test]
    async fn nip09_marks_request_used_only_after_successful_removal() {
        let ctx = make_context();
        let keys = Keys::generate();
        let target = EventBuilder::new(Kind::TextNote, "target")
            .finalize(&keys)
            .unwrap();
        ctx.database.save_event(&target).await.unwrap();
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target.id)])
            .finalize(&keys)
            .unwrap();

        assert!(matches!(
            DeletionPolicy::new(ctx.clone()).handle(&deletion).await,
            WritePolicyResult::Accept
        ));
        let record = ctx
            .tombstones
            .lifecycle_records_result()
            .await
            .unwrap()
            .into_iter()
            .find(|record| record.request.id == deletion.id)
            .unwrap();
        assert_eq!(
            record.classification,
            RequestClassification::LocallyActionable
        );
        assert!(record.last_used_at.is_some());
    }

    #[tokio::test]
    async fn nip09_noop_leaves_request_lifecycle_unused() {
        let ctx = make_context();
        let keys = Keys::generate();
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(EventId::all_zeros())])
            .finalize(&keys)
            .unwrap();

        assert!(matches!(
            DeletionPolicy::new(ctx.clone()).handle(&deletion).await,
            WritePolicyResult::Accept
        ));
        let record = ctx
            .tombstones
            .lifecycle_records_result()
            .await
            .unwrap()
            .into_iter()
            .find(|record| record.request.id == deletion.id)
            .unwrap();
        assert_eq!(record.last_used_at, None);
    }

    #[tokio::test]
    async fn nip09_failed_archive_preserves_target_and_leaves_request_unused() {
        let mut ctx = make_context();
        let directory = tempfile::tempdir().unwrap();
        ctx.git_data_path = directory.path().to_path_buf();
        let keys = Keys::generate();
        let target = make_announcement_event(&keys, "archive-failure");
        let owner = owner_directory_component(&keys.public_key());
        std::fs::create_dir_all(directory.path().join(&owner).join("archive-failure.git")).unwrap();
        // A file where the archive directory belongs makes the archival attempt
        // fail, so the fail-safe path must not award deletion-use credit.
        std::fs::write(directory.path().join(".archive"), "not a directory").unwrap();
        ctx.database.save_event(&target).await.unwrap();
        let request = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target.id)])
            .finalize(&keys)
            .unwrap();

        assert!(matches!(
            DeletionPolicy::new(ctx.clone()).handle(&request).await,
            WritePolicyResult::Accept
        ));
        assert!(ctx
            .database
            .event_by_id(&target.id)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            ctx.tombstones
                .lifecycle_for_request(&request.id)
                .await
                .unwrap()
                .last_used_at,
            None
        );
    }

    #[tokio::test]
    async fn coordinate_deletion_requests_with_different_cutoffs_coexist() {
        let ctx = make_context();
        let keys = Keys::generate();
        let coord = format!("30618:{}:my-repo", keys.public_key().to_hex());

        let older = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord.clone()])])
            .custom_created_at(Timestamp::from_secs(1000))
            .finalize(&keys)
            .unwrap();
        let newer = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord])])
            .custom_created_at(Timestamp::from_secs(1100))
            .finalize(&keys)
            .unwrap();

        let policy = DeletionPolicy::new(ctx.clone());
        assert!(matches!(
            policy.handle(&older).await,
            WritePolicyResult::Accept
        ));

        // Simulate relay-builder's post-policy persistence of accepted events.
        ctx.database.save_event(&older).await.unwrap();
        assert!(ctx.database.event_by_id(&older.id).await.unwrap().is_some());

        assert!(matches!(
            policy.handle(&newer).await,
            WritePolicyResult::Accept
        ));

        ctx.database.save_event(&newer).await.unwrap();
        for request in [&older, &newer] {
            assert!(ctx
                .database
                .event_by_id(&request.id)
                .await
                .unwrap()
                .is_some());
            assert!(ctx
                .tombstones
                .lifecycle_for_request_result(&request.id)
                .await
                .unwrap()
                .is_some());
        }
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
        assert!(ctx
            .tombstones
            .lifecycle_for_request_result(&deletion.id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn preemptive_multi_target_foreign_event_keeps_request_and_valid_target_effective() {
        let ctx = make_context();
        let attacker_keys = Keys::generate();
        let victim_keys = Keys::generate();

        let foreign_target = EventBuilder::text_note("real event from victim")
            .finalize(&victim_keys)
            .unwrap();
        let valid_target = EventBuilder::text_note("real event from deleter")
            .finalize(&attacker_keys)
            .unwrap();
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![
                Tag::event(foreign_target.id),
                Tag::event(valid_target.id),
            ])
            .finalize(&attacker_keys)
            .unwrap();

        assert!(matches!(
            DeletionPolicy::new(ctx.clone()).handle(&deletion).await,
            WritePolicyResult::Accept
        ));
        ctx.database.save_event(&deletion).await.unwrap();

        let service = DeletionService::new(ctx.clone());
        assert!(service.gate(&foreign_target).await.is_none());
        assert!(
            ctx.database
                .event_by_id(&deletion.id)
                .await
                .unwrap()
                .is_some(),
            "foreign target discovery must not remove the entire signed request"
        );
        assert!(ctx
            .tombstones
            .lifecycle_for_request_result(&deletion.id)
            .await
            .unwrap()
            .unwrap()
            .last_used_at
            .is_none());
        assert!(service.gate(&valid_target).await.is_some());
        assert!(ctx
            .tombstones
            .lifecycle_for_request_result(&deletion.id)
            .await
            .unwrap()
            .unwrap()
            .last_used_at
            .is_some());
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

        for ctx in [make_context(), make_disrespector_context()] {
            let result = DeletionPolicy::new(ctx.clone()).handle(&deletion).await;
            assert!(matches!(result, WritePolicyResult::Reject { .. }));
            assert!(ctx
                .tombstones
                .lifecycle_for_request(&deletion.id)
                .await
                .is_none());
        }
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
    async fn disrespector_records_unused_lifecycle_without_enforcing_a_gate() {
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
        let record = ctx
            .tombstones
            .lifecycle_for_request(&deletion.id)
            .await
            .expect("disrespector request lifecycle should be recorded");
        assert_eq!(record.classification, RequestClassification::Disrespector);
        assert_eq!(record.last_used_at, None);
        // Disrespector metadata does not install a gate.
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
        assert!(ctx
            .tombstones
            .lifecycle_for_request(&deletion.id)
            .await
            .is_some_and(|record| record.last_used_at.is_some()));
    }

    #[tokio::test]
    async fn disrespector_marks_covered_coordinate_used_without_mutating_target() {
        let ctx = make_disrespector_context();
        let keys = Keys::generate();
        let target = make_announcement_event(&keys, "keep-coordinate");
        ctx.database.save_event(&target).await.unwrap();
        let coordinate = format!("30617:{}:keep-coordinate", keys.public_key().to_hex());
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coordinate])])
            .finalize(&keys)
            .unwrap();

        assert!(matches!(
            DeletionPolicy::new(ctx.clone()).handle(&deletion).await,
            WritePolicyResult::Accept
        ));
        assert!(ctx
            .database
            .event_by_id(&target.id)
            .await
            .unwrap()
            .is_some());
        assert!(ctx
            .tombstones
            .lifecycle_for_request(&deletion.id)
            .await
            .unwrap()
            .last_used_at
            .is_some());
    }

    #[tokio::test]
    async fn disrespector_marks_matching_purgatory_target_used_without_removing_it() {
        let ctx = make_disrespector_context();
        let keys = Keys::generate();
        let announcement = make_announcement_event(&keys, "keep-purgatory");
        add_to_purgatory(&ctx, &announcement, "keep-purgatory");
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(announcement.id)])
            .finalize(&keys)
            .unwrap();

        assert!(matches!(
            DeletionPolicy::new(ctx.clone()).handle(&deletion).await,
            WritePolicyResult::Accept
        ));
        assert!(ctx
            .purgatory
            .has_purgatory_announcement(&keys.public_key(), "keep-purgatory"));
        assert!(ctx
            .tombstones
            .lifecycle_for_request(&deletion.id)
            .await
            .unwrap()
            .last_used_at
            .is_some());
    }

    #[tokio::test]
    async fn cross_author_existing_target_is_rejected_without_lifecycle_record() {
        let ctx = make_disrespector_context();
        let owner = Keys::generate();
        let attacker = Keys::generate();
        let target = EventBuilder::new(Kind::TextNote, "owned")
            .finalize(&owner)
            .unwrap();
        ctx.database.save_event(&target).await.unwrap();
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target.id)])
            .finalize(&attacker)
            .unwrap();

        assert!(matches!(
            DeletionPolicy::new(ctx.clone()).handle(&deletion).await,
            WritePolicyResult::Reject { .. }
        ));
        assert!(ctx
            .tombstones
            .lifecycle_for_request(&deletion.id)
            .await
            .is_none());
        assert!(ctx
            .database
            .event_by_id(&target.id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn disrespector_foreign_coordinate_is_unused() {
        let ctx = make_disrespector_context();
        let owner = Keys::generate();
        let attacker = Keys::generate();
        let target = make_announcement_event(&owner, "foreign-coordinate");
        ctx.database.save_event(&target).await.unwrap();
        let coordinate = format!("30617:{}:foreign-coordinate", owner.public_key().to_hex());
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coordinate])])
            .finalize(&attacker)
            .unwrap();

        assert!(matches!(
            DeletionPolicy::new(ctx.clone()).handle(&deletion).await,
            WritePolicyResult::Accept
        ));
        assert!(ctx
            .database
            .event_by_id(&target.id)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            ctx.tombstones
                .lifecycle_for_request(&deletion.id)
                .await
                .unwrap()
                .last_used_at,
            None
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
