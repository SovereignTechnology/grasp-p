use anyhow::Result;
use nostr_relay_builder::prelude::{
    nip62, Alphabet, Event, Filter, Kind, PublicKey, RelayUrl, SingleLetterTag, Timestamp,
    WritePolicyResult,
};

use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::lifecycle::RequestLifecycleRecord;
use crate::nostr::policy::{reject_error, reject_invalid, AnnouncementResult};

use super::{DeletionContext, DeletionOutcome, DeletionPolicy};

#[derive(Clone)]
pub struct DeletionService {
    pub(super) ctx: DeletionContext,
    policy: DeletionPolicy,
}

impl DeletionService {
    pub fn new(ctx: DeletionContext) -> Self {
        let policy = DeletionPolicy::new(ctx.clone());
        Self { ctx, policy }
    }

    pub async fn gate(&self, event: &Event) -> Option<WritePolicyResult> {
        // The operator's current archival-mode policy governs every retained
        // request, regardless of how it was classified when received.
        if self.ctx.config.deletion_request_disrespector {
            return None;
        }

        let mut candidates = Vec::new();
        let tombstones = self.ctx.tombstones();
        match tombstones.vanish_candidates(&event.pubkey).await {
            Ok(records) => candidates.extend(records.into_iter().map(|record| (record, "vanish"))),
            Err(error) => return Some(Self::gate_error("querying vanish candidates", error)),
        }
        match tombstones
            .event_deletion_candidates(&event.id, &event.pubkey)
            .await
        {
            Ok(records) => {
                candidates.extend(records.into_iter().map(|record| (record, "event-id")))
            }
            Err(error) => {
                return Some(Self::gate_error(
                    "querying event deletion candidates",
                    error,
                ))
            }
        }

        // Deleted coordinate (replaceable / addressable events only).
        if event.kind.is_replaceable() || event.kind.is_addressable() {
            if let Some(coord) = Self::event_coordinate(event) {
                match tombstones
                    .coordinate_deletion_candidates(&coord, event.created_at)
                    .await
                {
                    Ok(records) => {
                        candidates.extend(records.into_iter().map(|record| (record, "coordinate")))
                    }
                    Err(error) => {
                        return Some(Self::gate_error(
                            "querying coordinate deletion candidates",
                            error,
                        ));
                    }
                }
            }
        }

        let now = Timestamp::now();
        let mut eligible = std::collections::HashMap::new();
        for (record, category) in candidates {
            match self.request_is_expired(&record, now) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    return Some(Self::gate_error(
                        "evaluating deletion-request retention",
                        error,
                    ));
                }
            }
            eligible
                .entry(record.request.id)
                .or_insert((record, category));
        }

        let candidate_count = eligible.len();
        let (winner, category) = eligible
            .into_values()
            .min_by(|(left, _), (right, _)| Self::winner_order(left, right))?;

        let previous_last_used_at = winner.last_used_at;
        if let Err(error) = self.ctx.database().save_event(&winner.request).await {
            return Some(Self::gate_error("promoting deletion request", error));
        }
        let used_at = Timestamp::now();
        let updated = match tombstones
            .mark_request_used(&winner.request.id, used_at)
            .await
        {
            Ok(Some(record)) if record.last_used_at >= Some(used_at) => record,
            Ok(Some(record)) => {
                return Some(Self::gate_error(
                    "verifying deletion-request lifecycle update",
                    anyhow::anyhow!(
                        "request {} retained an older last_used_at {:?}",
                        record.request.id,
                        record.last_used_at
                    ),
                ));
            }
            Ok(None) => {
                return Some(Self::gate_error(
                    "updating deletion-request lifecycle",
                    anyhow::anyhow!(
                        "request {} no longer has lifecycle metadata",
                        winner.request.id
                    ),
                ));
            }
            Err(error) => {
                return Some(Self::gate_error(
                    "updating deletion-request lifecycle",
                    error,
                ))
            }
        };

        tracing::debug!(
            incoming_event_id = %event.id.to_hex(),
            winning_request_id = %winner.request.id.to_hex(),
            request_kind = winner.request.kind.as_u16(),
            first_seen_at = winner.first_seen_at.as_secs(),
            previous_last_used_at = ?previous_last_used_at.map(|timestamp| timestamp.as_secs()),
            new_last_used_at = ?updated.last_used_at.map(|timestamp| timestamp.as_secs()),
            candidate_count,
            match_category = category,
            "Rejected event through attributed deletion-request gate"
        );

        Some(if winner.request.kind == Kind::RequestToVanish {
            reject_invalid("this pubkey has requested to vanish")
        } else {
            reject_invalid("this event is deleted")
        })
    }

    fn request_is_expired(&self, record: &RequestLifecycleRecord, now: Timestamp) -> Result<bool> {
        let (anchor, served, additional) = match record.last_used_at {
            Some(last_used_at) => (
                last_used_at,
                self.ctx
                    .config
                    .deletion_request_retention_used_served_after_last_used(),
                self.ctx
                    .config
                    .deletion_request_retention_used_unserved_gating_additional(),
            ),
            None => (
                record.first_seen_at,
                self.ctx.config.deletion_request_retention_unused_served(),
                self.ctx
                    .config
                    .deletion_request_retention_unused_unserved_gating_additional(),
            ),
        };
        let lifetime = served
            .as_secs()
            .checked_add(additional.as_secs())
            .ok_or_else(|| anyhow::anyhow!("deletion-request retention duration overflow"))?;
        let deadline = anchor
            .as_secs()
            .checked_add(lifetime)
            .ok_or_else(|| anyhow::anyhow!("deletion-request retention deadline overflow"))?;
        if now.as_secs() >= deadline {
            return Ok(true);
        }
        Ok(false)
    }

    fn winner_order(
        left: &RequestLifecycleRecord,
        right: &RequestLifecycleRecord,
    ) -> std::cmp::Ordering {
        right
            .last_used_at
            .is_some()
            .cmp(&left.last_used_at.is_some())
            .then_with(|| left.first_seen_at.cmp(&right.first_seen_at))
            .then_with(|| left.request.id.to_hex().cmp(&right.request.id.to_hex()))
    }

    fn gate_error(context: &str, error: impl std::fmt::Display) -> WritePolicyResult {
        tracing::error!(error = %error, "Deletion-request admission gate failed while {context}");
        reject_error(format!("internal error {context}: {error}"))
    }

    /// Remove stale out-of-order kind-5 requests that targeted this event ID but
    /// were authored by a different pubkey.
    ///
    /// Main-DB validation rejects cross-author `e` deletes when the target is
    /// already known. For pre-emptive deletes, ownership is unknowable until the
    /// target arrives. Once an accepted event establishes the real author, any
    /// stored deletion requests from other authors are retroactively invalid and
    /// should be removed from both the internal tombstone store and the served
    /// deletion-request event stream.
    pub async fn remove_stale_cross_author_event_deletions(&self, event: &Event) {
        let target_id = event.id;
        let author = event.pubkey;

        match self
            .ctx
            .tombstones()
            .remove_event_deletions_by_other_authors(&target_id, &author)
            .await
        {
            Ok(removed) if removed > 0 => tracing::info!(
                target_id = %target_id.to_hex(),
                author = %author.to_hex(),
                removed,
                "Removed stale cross-author deletion tombstone(s) after target arrival"
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!(
                target_id = %target_id.to_hex(),
                author = %author.to_hex(),
                error = %e,
                "Failed to remove stale cross-author deletion tombstones"
            ),
        }

        let filter = Filter::new()
            .kind(Kind::EventDeletion)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::E), target_id.to_hex());

        let stale_ids = match self.ctx.database().query(filter).await {
            Ok(events) => events
                .into_iter()
                .filter(|deletion| deletion.pubkey != author)
                .map(|deletion| deletion.id)
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::warn!(
                    target_id = %target_id.to_hex(),
                    author = %author.to_hex(),
                    error = %e,
                    "Failed to query stale cross-author deletion requests in main DB"
                );
                return;
            }
        };

        if stale_ids.is_empty() {
            return;
        }

        let removed = stale_ids.len();
        if let Err(e) = self
            .ctx
            .database()
            .delete(Filter::new().ids(stale_ids))
            .await
        {
            tracing::warn!(
                target_id = %target_id.to_hex(),
                author = %author.to_hex(),
                error = %e,
                "Failed to remove stale cross-author deletion requests from main DB"
            );
            return;
        }

        tracing::info!(
            target_id = %target_id.to_hex(),
            author = %author.to_hex(),
            removed,
            "Removed stale cross-author deletion request(s) from main DB after target arrival"
        );
    }

    pub async fn handle_nip09(&self, event: &Event) -> WritePolicyResult {
        self.policy.handle(event).await
    }

    pub async fn handle_vanish(&self, event: &Event) -> WritePolicyResult {
        // Archival mode: store the vanish request but do not process it.
        if self.ctx.config.deletion_request_disrespector {
            tracing::info!(
                event_id = %event.id.to_hex(),
                author = %event.pubkey.to_hex(),
                "Disrespector mode: storing NIP-62 vanish request without acting on it"
            );
            return WritePolicyResult::Accept;
        }

        // Only honour requests that target this relay (or all relays). `domain`
        // is configured as an authority for GRASP matching, so derive both
        // `wss://` and `ws://` relay URL candidates when no scheme is present.
        // We still accept (store) well-formed kind-62 requests that target other
        // relays so clients get an OK for their event.
        let targets_relay = self.vanish_targets_this_relay(event);

        if !targets_relay {
            tracing::debug!(
                author = %event.pubkey.to_hex(),
                "kind-62 vanish request does not target this relay; storing without action"
            );
            return WritePolicyResult::Accept;
        }

        let author = event.pubkey;

        // 1. Record the vanish so re-submission of the author's events is blocked.
        if let Err(e) = self.ctx.tombstones().record_vanish(event).await {
            tracing::error!(error = %e, author = %author.to_hex(), "Failed to record vanish tombstone");
            return reject_error(format!("internal error recording vanish: {e}"));
        }

        let mut outcome = match self.policy.apply_nip62_vanish(event).await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!(error = %e, author = %author.to_hex(), "Failed to process vanished author's lifecycle deletion");
                return reject_error(format!("internal error processing vanish: {e}"));
            }
        };

        // Evict the author's purgatory entries (and their bare repos). Served
        // data has already gone through the holding/archive lifecycle above;
        // purgatory entries are not live served data.
        outcome.merge(self.evict_author_from_purgatory(&author));

        if outcome.used() {
            match self
                .ctx
                .tombstones()
                .mark_request_used(&event.id, Timestamp::now())
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return reject_error(
                        "internal error updating vanish lifecycle: missing metadata",
                    )
                }
                Err(e) => {
                    tracing::error!(event_id = %event.id.to_hex(), error = %e, "Failed to mark used NIP-62 vanish request");
                    return reject_error(format!("internal error updating vanish lifecycle: {e}"));
                }
            }
        }

        tracing::info!(
            author = %author.to_hex(),
            main_db_deleted = outcome.main_db_deleted,
            purgatory_removed = outcome.purgatory_removed,
            skipped = outcome.skipped,
            failures = outcome.failures,
            "Processed NIP-62 request to vanish through deletion lifecycle"
        );

        WritePolicyResult::Accept
    }

    pub(crate) fn admission_hooks(&self) -> DeletionAdmissionHooks<'_> {
        DeletionAdmissionHooks { deletion: self }
    }

    fn vanish_targets_this_relay(&self, event: &Event) -> bool {
        let relay_urls = Self::relay_url_candidates(self.ctx.domain());

        if relay_urls.is_empty() {
            // Fall back to historical ALL_RELAYS-only matching when the relay's
            // configured domain cannot be converted into a NIP-62 RelayUrl.
            return nip62::is_valid_vanish_request_for_relay(event.tags.as_slice(), None);
        }

        relay_urls.iter().any(|relay_url| {
            nip62::is_valid_vanish_request_for_relay(event.tags.as_slice(), Some(relay_url))
        })
    }

    fn relay_url_candidates(domain: &str) -> Vec<RelayUrl> {
        let domain = domain.trim().trim_end_matches('/');
        if domain.is_empty() {
            return Vec::new();
        }

        let candidate_strings = if domain.contains("://") {
            vec![domain.to_owned()]
        } else {
            vec![format!("wss://{domain}"), format!("ws://{domain}")]
        };

        let mut candidates = Vec::new();
        for candidate in candidate_strings {
            match RelayUrl::parse(&candidate) {
                Ok(relay_url) if !candidates.contains(&relay_url) => candidates.push(relay_url),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    domain = %domain,
                    candidate = %candidate,
                    error = %e,
                    "Unable to derive NIP-62 relay URL candidate from configured domain"
                ),
            }
        }

        candidates
    }

    /// Runtime de-list parity path for already-served repositories.
    ///
    /// When a newer replacement announcement for the same owner+identifier no
    /// longer lists this relay's service, trigger the normal cascade
    /// delete->holding/archive flow for the currently served announcement.
    ///
    /// This mirrors startup whitelist/blacklist parity behavior, but runs at
    /// write time so service removals are enforced immediately.
    pub async fn maybe_apply_runtime_delist_deletion(&self, incoming: &Event) {
        let incoming_announcement = match RepositoryAnnouncement::from_event(incoming.clone()) {
            Ok(announcement) => announcement,
            Err(_) => return,
        };

        // This path is only for announcements that REMOVE this relay listing.
        if incoming_announcement.lists_service(self.ctx.domain()) {
            return;
        }

        let filter = Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(incoming.pubkey)
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::D),
                incoming_announcement.identifier.clone(),
            );

        let current = match self.ctx.database().query(filter).await {
            Ok(events) => events.into_iter().max_by_key(|event| event.created_at),
            Err(e) => {
                tracing::warn!(
                    owner = %incoming.pubkey.to_hex(),
                    identifier = %incoming_announcement.identifier,
                    error = %e,
                    "Runtime de-list parity: failed querying existing announcement"
                );
                None
            }
        };

        let Some(current) = current else {
            return;
        };

        // Not newer than what we already serve -> no runtime parity action.
        if incoming.created_at <= current.created_at {
            return;
        }

        let current_announcement = match RepositoryAnnouncement::from_event(current.clone()) {
            Ok(announcement) => announcement,
            Err(e) => {
                tracing::warn!(
                    event_id = %current.id.to_hex(),
                    owner = %incoming.pubkey.to_hex(),
                    identifier = %incoming_announcement.identifier,
                    error = %e,
                    "Runtime de-list parity: failed parsing current announcement"
                );
                return;
            }
        };

        // Safety guard: only run cascade when the currently served announcement
        // actually lists this relay.
        if !current_announcement.lists_service(self.ctx.domain()) {
            return;
        }

        match self
            .apply_whitelist_deletion_for_announcement(&current)
            .await
        {
            Ok(()) => {
                tracing::info!(
                    owner = %incoming.pubkey.to_hex(),
                    identifier = %incoming_announcement.identifier,
                    replaced_announcement = %current.id.to_hex(),
                    replacement = %incoming.id.to_hex(),
                    "Runtime de-list parity: deleted previously served repository"
                );
            }
            Err(e) => {
                tracing::error!(
                    owner = %incoming.pubkey.to_hex(),
                    identifier = %incoming_announcement.identifier,
                    replaced_announcement = %current.id.to_hex(),
                    replacement = %incoming.id.to_hex(),
                    error = %e,
                    "Runtime de-list parity: deletion flow failed"
                );
            }
        }
    }

    pub async fn capture_superseded_replaceable_history(&self, incoming: &Event) {
        if !Self::should_capture_replaceable_history(incoming.kind) {
            return;
        }

        let Some(coordinate) = Self::event_coordinate(incoming) else {
            return;
        };

        let Some(identifier) = Self::extract_addressable_identifier(incoming) else {
            tracing::warn!(
                event_id = %incoming.id.to_hex(),
                kind = incoming.kind.as_u16(),
                "Skipping history capture for addressable event without d tag"
            );
            return;
        };

        let filter = Filter::new()
            .kind(incoming.kind)
            .author(incoming.pubkey)
            .identifier(identifier);

        let existing = match self.ctx.database().query(filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    event_id = %incoming.id.to_hex(),
                    coordinate = %coordinate,
                    "Failed querying existing events for history capture"
                );
                return;
            }
        };

        for superseded in existing {
            if superseded.id == incoming.id || superseded.created_at >= incoming.created_at {
                continue;
            }

            if let Err(e) = self
                .history()
                .archive_superseded_event(&superseded, incoming, &coordinate)
                .await
            {
                tracing::warn!(
                    error = %e,
                    superseded_event_id = %superseded.id.to_hex(),
                    replaced_by = %incoming.id.to_hex(),
                    coordinate = %coordinate,
                    "Failed to archive superseded replaceable/addressable event"
                );
            }
        }
    }

    pub fn holding(&self) -> &crate::nostr::lifecycle::HoldingStore {
        self.ctx.holding()
    }

    pub fn lifecycle(&self) -> &crate::nostr::lifecycle::RepositoryLifecycle {
        self.ctx.lifecycle()
    }

    pub fn history(&self) -> &crate::nostr::lifecycle::ReplaceableHistoryStore {
        self.ctx.history()
    }

    pub fn tombstones(&self) -> &crate::nostr::lifecycle::Tombstones {
        self.ctx.tombstones()
    }

    pub async fn apply_blacklist_deletion_for_announcement(
        &self,
        announcement: &Event,
    ) -> Result<()> {
        self.policy
            .apply_blacklist_deletion_for_announcement(announcement)
            .await
    }

    pub async fn apply_whitelist_deletion_for_announcement(
        &self,
        announcement: &Event,
    ) -> Result<()> {
        self.policy
            .apply_whitelist_deletion_for_announcement(announcement)
            .await
    }

    fn event_coordinate(event: &Event) -> Option<String> {
        if !(event.kind.is_replaceable() || event.kind.is_addressable()) {
            return None;
        }
        let identifier = if event.kind.is_addressable() {
            event
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .unwrap_or("")
        } else {
            ""
        };
        Some(format!(
            "{}:{}:{}",
            event.kind.as_u16(),
            event.pubkey.to_hex(),
            identifier
        ))
    }

    fn extract_addressable_identifier(event: &Event) -> Option<String> {
        event.tags.iter().find_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == "d" {
                Some(v[1].clone())
            } else {
                None
            }
        })
    }

    fn should_capture_replaceable_history(kind: Kind) -> bool {
        kind == Kind::GitRepoAnnouncement || kind == Kind::RepoState
    }

    fn evict_author_from_purgatory(&self, author: &PublicKey) -> DeletionOutcome {
        let mut outcome = DeletionOutcome::default();
        let mut removed_ids = std::collections::HashSet::new();
        // Announcements owned by this author.
        for (repo_id, _) in self.ctx.purgatory().announcements_for_sync() {
            // repo_id format: "30617:{pubkey_hex}:{identifier}"
            let parts: Vec<&str> = repo_id.splitn(3, ':').collect();
            if parts.len() != 3 || parts[1] != author.to_hex() {
                continue;
            }
            let identifier = parts[2];
            if let Some(entry) = self.ctx.purgatory().find_announcement(author, identifier) {
                if entry.repo_path.exists() {
                    if let Err(e) = std::fs::remove_dir_all(&entry.repo_path) {
                        tracing::warn!(
                            path = %entry.repo_path.display(),
                            error = %e,
                            "Failed to delete bare repository during vanish processing"
                        );
                        outcome.failures = outcome.failures.saturating_add(1);
                    }
                }
            }
            if let Some(entry) = self.ctx.purgatory().find_announcement(author, identifier) {
                outcome.purgatory_removed = outcome
                    .purgatory_removed
                    .saturating_add(usize::from(removed_ids.insert(entry.event.id)));
            }
            self.ctx.purgatory().remove_announcement(author, identifier);
        }

        // State events authored by this author across all identifiers.
        for identifier in self.ctx.purgatory().get_all_identifiers() {
            for entry in self.ctx.purgatory().find_state(&identifier) {
                if entry.author == *author {
                    outcome.purgatory_removed = outcome
                        .purgatory_removed
                        .saturating_add(usize::from(removed_ids.insert(entry.event.id)));
                    self.ctx
                        .purgatory()
                        .remove_state_event(&identifier, &entry.event.id);
                }
            }
        }
        outcome
    }
}

pub(crate) struct DeletionAdmissionHooks<'a> {
    deletion: &'a DeletionService,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AnnouncementAdmissionHookResult {
    recovered_repository: bool,
}

impl AnnouncementAdmissionHookResult {
    pub(crate) fn recovered_repository(&self) -> bool {
        self.recovered_repository
    }
}

impl DeletionAdmissionHooks<'_> {
    /// Run deletion-owned side effects caused by announcement admission.
    ///
    /// The write policy decides routing/admission; this hook keeps runtime
    /// de-list parity, deleted-repository recovery, and replaceable history
    /// capture in the deletion facade.
    pub(crate) async fn on_announcement_admission(
        &self,
        event: &Event,
        result: &AnnouncementResult,
    ) -> AnnouncementAdmissionHookResult {
        let mut hook_result = AnnouncementAdmissionHookResult::default();

        match result {
            AnnouncementResult::Accept
            | AnnouncementResult::AcceptArchive
            | AnnouncementResult::AcceptMaintainer => {
                self.deletion
                    .maybe_apply_runtime_delist_deletion(event)
                    .await;

                if let Ok(announcement) = RepositoryAnnouncement::from_event(event.clone()) {
                    hook_result.recovered_repository = self
                        .deletion
                        .maybe_recover_deleted_repository(event, &announcement.identifier)
                        .await;

                    self.deletion
                        .capture_superseded_replaceable_history(event)
                        .await;
                }
            }
            AnnouncementResult::AcceptPurgatory => {
                if let Ok(announcement) = RepositoryAnnouncement::from_event(event.clone()) {
                    hook_result.recovered_repository = self
                        .deletion
                        .maybe_recover_deleted_repository(event, &announcement.identifier)
                        .await;

                    if hook_result.recovered_repository {
                        self.deletion
                            .capture_superseded_replaceable_history(event)
                            .await;
                    }
                }
            }
            AnnouncementResult::Reject(_) => {
                self.deletion
                    .maybe_apply_runtime_delist_deletion(event)
                    .await;
            }
        }

        hook_result
    }

    /// Run deletion-owned side effects caused by state admission.
    pub(crate) async fn on_state_admission(&self, event: &Event, result: &WritePolicyResult) {
        if matches!(result, WritePolicyResult::Accept) {
            self.deletion
                .capture_superseded_replaceable_history(event)
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grasp06::receive::new_repo_init_locks;
    use crate::nostr::lifecycle::{
        HoldingStore, ReplaceableHistoryStore, RepositoryLifecycle, Tombstones,
    };
    use crate::purgatory::Purgatory;
    use nostr_relay_builder::prelude::{EventBuilder, EventId, FinalizeEvent, Keys, Tag};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn context(config: crate::config::Config) -> DeletionContext {
        DeletionContext::new(
            "test.example.com",
            Arc::new(nostr_memory::MemoryDatabase::unbounded()),
            Tombstones::in_memory(),
            HoldingStore::in_memory(),
            RepositoryLifecycle::in_memory(),
            ReplaceableHistoryStore::in_memory(),
            PathBuf::new(),
            Arc::new(Purgatory::new(PathBuf::new())),
            config,
            new_repo_init_locks(),
        )
    }

    fn deletion(keys: &Keys, target: EventId) -> Event {
        EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target)])
            .finalize(keys)
            .unwrap()
    }

    #[test]
    fn retention_expiry_uses_exact_deadline_boundary() {
        let service = DeletionService::new(context(crate::config::Config {
            deletion_request_retention_unused_served_secs: 2,
            deletion_request_retention_unused_unserved_gating_additional_secs: 3,
            deletion_request_retention_used_served_after_last_used_secs: 2,
            deletion_request_retention_used_unserved_gating_additional_secs: 3,
            ..crate::config::Config::for_testing()
        }));
        let request = deletion(&Keys::generate(), EventId::all_zeros());
        let unused = RequestLifecycleRecord {
            metadata_event_id: EventId::all_zeros(),
            request: request.clone(),
            first_seen_at: Timestamp::from_secs(10),
            last_used_at: None,
            classification: crate::nostr::lifecycle::RequestClassification::LocallyActionable,
        };
        assert!(!service
            .request_is_expired(&unused, Timestamp::from_secs(14))
            .unwrap());
        assert!(service
            .request_is_expired(&unused, Timestamp::from_secs(15))
            .unwrap());
        let used = RequestLifecycleRecord {
            last_used_at: Some(Timestamp::from_secs(20)),
            ..unused
        };
        assert!(!service
            .request_is_expired(&used, Timestamp::from_secs(24))
            .unwrap());
        assert!(service
            .request_is_expired(&used, Timestamp::from_secs(25))
            .unwrap());
    }

    #[test]
    fn winner_order_prefers_used_then_first_seen_then_event_id() {
        let keys = Keys::generate();
        let first_request = EventBuilder::new(Kind::EventDeletion, "first")
            .tags(vec![Tag::event(EventId::all_zeros())])
            .finalize(&keys)
            .unwrap();
        let second_request = EventBuilder::new(Kind::EventDeletion, "second")
            .tags(vec![Tag::event(EventId::all_zeros())])
            .finalize(&keys)
            .unwrap();
        let record = |request: Event, first_seen_at: u64, last_used_at: Option<u64>| {
            RequestLifecycleRecord {
                metadata_event_id: EventId::all_zeros(),
                request,
                first_seen_at: Timestamp::from_secs(first_seen_at),
                last_used_at: last_used_at.map(Timestamp::from_secs),
                classification: crate::nostr::lifecycle::RequestClassification::LocallyActionable,
            }
        };
        let unused_early = record(first_request.clone(), 10, None);
        let unused_late = record(second_request.clone(), 20, None);
        let used_late = record(second_request.clone(), 20, Some(21));
        assert_eq!(
            DeletionService::winner_order(&used_late, &unused_early),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            DeletionService::winner_order(&unused_early, &unused_late),
            std::cmp::Ordering::Less
        );
        let same_time_left = record(first_request, 10, None);
        let same_time_right = record(second_request, 10, None);
        assert_eq!(
            DeletionService::winner_order(&same_time_left, &same_time_right),
            same_time_left
                .request
                .id
                .to_hex()
                .cmp(&same_time_right.request.id.to_hex())
        );
    }

    #[tokio::test]
    async fn gate_deduplicates_matches_promotes_winner_and_updates_only_it() {
        let ctx = context(crate::config::Config::for_testing());
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let incoming = EventBuilder::new(Kind::TextNote, "target")
            .finalize(&keys)
            .unwrap();
        let older = deletion(&keys, incoming.id);
        let newer = EventBuilder::new(Kind::EventDeletion, "newer")
            .tags(vec![Tag::event(incoming.id)])
            .finalize(&keys)
            .unwrap();
        let now = Timestamp::now().as_secs();
        ctx.tombstones
            .record_request(
                &older,
                Timestamp::from_secs(now - 2),
                crate::nostr::lifecycle::RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        ctx.tombstones
            .record_request(
                &newer,
                Timestamp::from_secs(now - 1),
                crate::nostr::lifecycle::RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();

        assert!(service.gate(&incoming).await.is_some());
        assert!(ctx
            .database
            .query(Filter::new().id(older.id))
            .await
            .unwrap()
            .iter()
            .any(|event| event.id == older.id));
        assert!(ctx
            .tombstones
            .lifecycle_for_request(&older.id)
            .await
            .unwrap()
            .last_used_at
            .is_some());
        assert_eq!(
            ctx.tombstones
                .lifecycle_for_request(&newer.id)
                .await
                .unwrap()
                .last_used_at,
            None
        );
    }

    #[tokio::test]
    async fn disrespector_mode_bypasses_all_deletion_gates() {
        let ctx = context(crate::config::Config {
            deletion_request_disrespector: true,
            ..crate::config::Config::for_testing()
        });
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "target")
            .finalize(&keys)
            .unwrap();
        let request = deletion(&keys, event.id);
        ctx.tombstones
            .record_request(
                &request,
                Timestamp::now(),
                crate::nostr::lifecycle::RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        assert!(service.gate(&event).await.is_none());
        assert_eq!(
            ctx.tombstones
                .lifecycle_for_request(&request.id)
                .await
                .unwrap()
                .last_used_at,
            None
        );
    }
}
