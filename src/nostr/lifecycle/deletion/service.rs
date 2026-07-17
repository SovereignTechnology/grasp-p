use anyhow::Result;
use nostr_relay_builder::prelude::{
    nip62, Alphabet, Event, Filter, Kind, PublicKey, RelayUrl, SingleLetterTag, Timestamp,
    WritePolicyResult,
};

use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::lifecycle::{RequestClassification, RequestLifecycleRecord};
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

        let tombstones = self.ctx.tombstones();

        // Candidate discovery, expiry evaluation, promotion, and last-used
        // attribution are one lifecycle transition. In particular, selecting a
        // winner before waiting for this lock can leave a later, still-live
        // candidate unchecked when that winner expires while waiting. Hold the
        // lock through discovery so cleanup cannot change the candidate set or
        // expiry state between selection and attribution.
        let _lifecycle_guard = tombstones.lock_lifecycle().await;

        let mut candidates = Vec::new();
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

        // Cleanup uses this same lock, so it cannot remove the Main copy
        // selected by this admission while it is being promoted.
        let Some(winner) = (match tombstones
            .lifecycle_for_request_result(&winner.request.id)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                return Some(Self::gate_error(
                    "re-reading deletion-request lifecycle",
                    error,
                ))
            }
        }) else {
            return Some(Self::gate_error(
                "re-reading deletion-request lifecycle",
                anyhow::anyhow!("request {} disappeared", winner.request.id),
            ));
        };
        match self.request_is_expired(&winner, Timestamp::now()) {
            Ok(true) => return None,
            Ok(false) => {}
            Err(error) => {
                return Some(Self::gate_error(
                    "evaluating deletion-request retention",
                    error,
                ))
            }
        }
        let previous_last_used_at = winner.last_used_at;
        if let Err(error) = self.ctx.database().save_event(&winner.request).await {
            return Some(Self::gate_error("promoting deletion request", error));
        }
        let used_at = Timestamp::now();
        let updated = match tombstones
            .mark_request_used_locked(&winner.request.id, used_at)
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

    pub(crate) fn request_is_expired(
        &self,
        record: &RequestLifecycleRecord,
        now: Timestamp,
    ) -> Result<bool> {
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

    pub async fn handle_nip09(&self, event: &Event) -> WritePolicyResult {
        self.policy.handle(event).await
    }

    pub async fn handle_vanish(&self, event: &Event) -> WritePolicyResult {
        // Only honour requests that target this relay (or all relays). `domain`
        // is configured as an authority for GRASP matching, so derive both
        // `wss://` and `ws://` relay URL candidates when no scheme is present.
        // We still accept (store) well-formed kind-62 requests that target other
        // relays so clients get an OK for their event.
        let targets_relay = self.vanish_targets_this_relay(event);
        let classification = if !targets_relay {
            RequestClassification::NonTargetingNip62
        } else if self.ctx.config.deletion_request_disrespector {
            RequestClassification::Disrespector
        } else {
            RequestClassification::LocallyActionable
        };

        // Persist every accepted NIP-62 request before accepting it or doing
        // destructive work. `record_request` preserves receipt time and
        // classification on an exact replay.
        if let Err(error) = self
            .ctx
            .tombstones()
            .record_request(event, Timestamp::now(), classification)
            .await
        {
            tracing::error!(event_id = %event.id.to_hex(), error = %error, "Failed to record NIP-62 vanish lifecycle");
            return reject_error(format!(
                "internal error recording vanish lifecycle: {error}"
            ));
        }

        if !targets_relay {
            tracing::debug!(
                author = %event.pubkey.to_hex(),
                "kind-62 vanish request does not target this relay; storing without action"
            );
            return WritePolicyResult::Accept;
        }

        let author = event.pubkey;

        if self.ctx.config.deletion_request_disrespector {
            let would_vanish = match self.policy.would_nip62_vanish_stored_data(event).await {
                Ok(would_vanish) => would_vanish,
                Err(error) => {
                    tracing::error!(event_id = %event.id.to_hex(), error = %error, "Failed to read-only evaluate NIP-62 vanish request");
                    return reject_error(format!(
                        "internal error evaluating vanish request: {error}"
                    ));
                }
            };
            if would_vanish {
                if let Err(result) = self.mark_vanish_request_used(event).await {
                    return result;
                }
            }
            tracing::info!(
                event_id = %event.id.to_hex(),
                author = %author.to_hex(),
                would_vanish,
                "Disrespector mode: stored and read-only evaluated NIP-62 vanish request"
            );
            return WritePolicyResult::Accept;
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
            if let Err(result) = self.mark_vanish_request_used(event).await {
                return result;
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

    async fn mark_vanish_request_used(
        &self,
        event: &Event,
    ) -> std::result::Result<(), WritePolicyResult> {
        match self
            .ctx
            .tombstones()
            .mark_request_used(&event.id, Timestamp::now())
            .await
        {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(reject_error(
                "internal error updating vanish lifecycle: missing metadata",
            )),
            Err(error) => {
                tracing::error!(event_id = %event.id.to_hex(), error = %error, "Failed to mark used NIP-62 vanish request");
                Err(reject_error(format!(
                    "internal error updating vanish lifecycle: {error}"
                )))
            }
        }
    }

    pub(crate) fn admission_hooks(&self) -> DeletionAdmissionHooks<'_> {
        DeletionAdmissionHooks { deletion: self }
    }

    pub(crate) fn vanish_targets_this_relay(&self, event: &Event) -> bool {
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

    pub(crate) async fn would_delete_stored_target(&self, event: &Event) -> anyhow::Result<bool> {
        self.policy.would_delete_stored_target(event).await
    }

    pub(crate) async fn would_nip62_vanish_stored_data(
        &self,
        event: &Event,
    ) -> anyhow::Result<bool> {
        self.policy.would_nip62_vanish_stored_data(event).await
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

    trait TombstoneTestExt {
        async fn lifecycle_for_request(
            &self,
            request_id: &EventId,
        ) -> Option<RequestLifecycleRecord>;
    }

    impl TombstoneTestExt for Tombstones {
        async fn lifecycle_for_request(
            &self,
            request_id: &EventId,
        ) -> Option<RequestLifecycleRecord> {
            self.lifecycle_for_request_result(request_id).await.unwrap()
        }
    }
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

    fn vanish(keys: &Keys, content: &str) -> Event {
        EventBuilder::new(Kind::RequestToVanish, content)
            .tags(vec![nostr_relay_builder::prelude::Tag::custom(
                "relay",
                vec!["ALL_RELAYS".to_string()],
            )])
            .finalize(keys)
            .unwrap()
    }

    fn non_targeting_vanish(keys: &Keys) -> Event {
        EventBuilder::new(Kind::RequestToVanish, "non-targeting")
            .tags(vec![nostr_relay_builder::prelude::Tag::custom(
                "relay",
                vec!["wss://other.example".to_string()],
            )])
            .finalize(keys)
            .unwrap()
    }

    #[test]
    fn all_relays_vanish_target_takes_precedence_over_relay_specific_target() {
        let service = DeletionService::new(context(crate::config::Config::for_testing()));
        let request = EventBuilder::new(Kind::RequestToVanish, "multiple targets")
            .tags(vec![
                Tag::custom("relay", vec!["wss://other.example".to_string()]),
                Tag::custom("relay", vec!["ALL_RELAYS".to_string()]),
            ])
            .finalize(&Keys::generate())
            .unwrap();

        assert!(
            service.vanish_targets_this_relay(&request),
            "ALL_RELAYS must target this relay even when a relay-specific tag does not"
        );
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
    async fn gate_uses_a_live_later_request_when_an_earlier_request_has_expired() {
        let ctx = context(crate::config::Config {
            deletion_request_retention_unused_served_secs: 1,
            deletion_request_retention_unused_unserved_gating_additional_secs: 1,
            ..crate::config::Config::for_testing()
        });
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let incoming = EventBuilder::new(Kind::TextNote, "target")
            .finalize(&keys)
            .unwrap();
        let expired = deletion(&keys, incoming.id);
        let live = EventBuilder::new(Kind::EventDeletion, "live fallback")
            .tags(vec![Tag::event(incoming.id)])
            .finalize(&keys)
            .unwrap();
        let now = Timestamp::now().as_secs();
        for (request, first_seen_at) in [(&expired, now - 3), (&live, now)] {
            ctx.tombstones
                .record_request(
                    request,
                    Timestamp::from_secs(first_seen_at),
                    RequestClassification::LocallyActionable,
                )
                .await
                .unwrap();
        }

        assert!(service.gate(&incoming).await.is_some());
        assert_eq!(
            ctx.tombstones
                .lifecycle_for_request(&expired.id)
                .await
                .unwrap()
                .last_used_at,
            None,
            "expired requests must not receive gate-use credit"
        );
        assert!(
            ctx.tombstones
                .lifecycle_for_request(&live.id)
                .await
                .unwrap()
                .last_used_at
                .is_some(),
            "a later live request must still reject the incoming event"
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

    #[tokio::test]
    async fn targeted_vanish_without_stored_data_is_actionable_and_unused() {
        let ctx = context(crate::config::Config::for_testing());
        let service = DeletionService::new(ctx.clone());
        let request = vanish(&Keys::generate(), "empty");

        assert!(matches!(
            service.handle_vanish(&request).await,
            WritePolicyResult::Accept
        ));
        let record = ctx
            .tombstones
            .lifecycle_for_request(&request.id)
            .await
            .unwrap();
        assert_eq!(
            record.classification,
            RequestClassification::LocallyActionable
        );
        assert_eq!(record.last_used_at, None);
    }

    #[tokio::test]
    async fn targeted_vanish_marks_used_after_main_database_removal() {
        let ctx = context(crate::config::Config::for_testing());
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let target = EventBuilder::new(Kind::TextNote, "vanish me")
            .finalize(&keys)
            .unwrap();
        ctx.database.save_event(&target).await.unwrap();
        let request = vanish(&keys, "main-db");

        assert!(matches!(
            service.handle_vanish(&request).await,
            WritePolicyResult::Accept
        ));
        assert!(ctx
            .database
            .event_by_id(&target.id)
            .await
            .unwrap()
            .is_none());
        assert!(ctx
            .tombstones
            .lifecycle_for_request(&request.id)
            .await
            .unwrap()
            .last_used_at
            .is_some());
    }

    #[tokio::test]
    async fn targeted_vanish_marks_used_after_purgatory_only_removal() {
        let ctx = context(crate::config::Config::for_testing());
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let state = EventBuilder::new(Kind::RepoState, "")
            .tags(vec![nostr_relay_builder::prelude::Tag::identifier(
                "purgatory-only",
            )])
            .finalize(&keys)
            .unwrap();
        ctx.purgatory.add_state(
            state.clone(),
            "purgatory-only".to_string(),
            keys.public_key(),
            false,
        );
        let request = vanish(&keys, "purgatory-only");

        assert!(matches!(
            service.handle_vanish(&request).await,
            WritePolicyResult::Accept
        ));
        assert!(ctx.purgatory.find_state("purgatory-only").is_empty());
        assert!(ctx
            .tombstones
            .lifecycle_for_request(&request.id)
            .await
            .unwrap()
            .last_used_at
            .is_some());
    }

    #[tokio::test]
    async fn non_targeting_vanish_is_unused_and_never_gates() {
        let ctx = context(crate::config::Config::for_testing());
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let target = EventBuilder::new(Kind::TextNote, "keep me")
            .finalize(&keys)
            .unwrap();
        ctx.database.save_event(&target).await.unwrap();
        let request = non_targeting_vanish(&keys);

        assert!(matches!(
            service.handle_vanish(&request).await,
            WritePolicyResult::Accept
        ));
        assert!(ctx
            .database
            .event_by_id(&target.id)
            .await
            .unwrap()
            .is_some());
        let record = ctx
            .tombstones
            .lifecycle_for_request(&request.id)
            .await
            .unwrap();
        assert_eq!(
            record.classification,
            RequestClassification::NonTargetingNip62
        );
        assert_eq!(record.last_used_at, None);
        let later = EventBuilder::new(Kind::TextNote, "allowed")
            .finalize(&keys)
            .unwrap();
        assert!(service.gate(&later).await.is_none());
    }

    #[tokio::test]
    async fn non_targeting_vanish_takes_precedence_over_disrespector_classification() {
        let ctx = context(crate::config::Config {
            deletion_request_disrespector: true,
            ..crate::config::Config::for_testing()
        });
        let service = DeletionService::new(ctx.clone());
        let request = non_targeting_vanish(&Keys::generate());

        assert!(matches!(
            service.handle_vanish(&request).await,
            WritePolicyResult::Accept
        ));
        assert_eq!(
            ctx.tombstones
                .lifecycle_for_request(&request.id)
                .await
                .unwrap()
                .classification,
            RequestClassification::NonTargetingNip62
        );
    }

    #[tokio::test]
    async fn disrespector_vanish_marks_main_database_and_purgatory_matches_used_without_mutating() {
        let ctx = context(crate::config::Config {
            deletion_request_disrespector: true,
            ..crate::config::Config::for_testing()
        });
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let target = EventBuilder::new(Kind::TextNote, "preserve me")
            .finalize(&keys)
            .unwrap();
        ctx.database.save_event(&target).await.unwrap();
        let state = EventBuilder::new(Kind::RepoState, "")
            .tags(vec![nostr_relay_builder::prelude::Tag::identifier(
                "preserve-purgatory",
            )])
            .finalize(&keys)
            .unwrap();
        ctx.purgatory.add_state(
            state.clone(),
            "preserve-purgatory".to_string(),
            keys.public_key(),
            false,
        );
        let request = vanish(&keys, "disrespector-data");

        assert!(matches!(
            service.handle_vanish(&request).await,
            WritePolicyResult::Accept
        ));
        assert!(ctx
            .database
            .event_by_id(&target.id)
            .await
            .unwrap()
            .is_some());
        assert!(ctx
            .purgatory
            .find_state("preserve-purgatory")
            .iter()
            .any(|entry| entry.event.id == state.id));
        let record = ctx
            .tombstones
            .lifecycle_for_request(&request.id)
            .await
            .unwrap();
        assert_eq!(record.classification, RequestClassification::Disrespector);
        assert!(record.last_used_at.is_some());
    }

    #[tokio::test]
    async fn disrespector_vanish_marks_purgatory_only_match_used_without_mutating() {
        let ctx = context(crate::config::Config {
            deletion_request_disrespector: true,
            ..crate::config::Config::for_testing()
        });
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let state = EventBuilder::new(Kind::RepoState, "")
            .tags(vec![nostr_relay_builder::prelude::Tag::identifier(
                "disrespector-purgatory",
            )])
            .finalize(&keys)
            .unwrap();
        ctx.purgatory.add_state(
            state.clone(),
            "disrespector-purgatory".to_string(),
            keys.public_key(),
            false,
        );
        let request = vanish(&keys, "disrespector-purgatory-only");

        assert!(matches!(
            service.handle_vanish(&request).await,
            WritePolicyResult::Accept
        ));
        assert!(ctx
            .purgatory
            .find_state("disrespector-purgatory")
            .iter()
            .any(|entry| entry.event.id == state.id));
        assert!(ctx
            .tombstones
            .lifecycle_for_request(&request.id)
            .await
            .unwrap()
            .last_used_at
            .is_some());
    }

    #[tokio::test]
    async fn disrespector_vanish_noop_remains_unused() {
        let ctx = context(crate::config::Config {
            deletion_request_disrespector: true,
            ..crate::config::Config::for_testing()
        });
        let service = DeletionService::new(ctx.clone());
        let request = vanish(&Keys::generate(), "disrespector-empty");

        assert!(matches!(
            service.handle_vanish(&request).await,
            WritePolicyResult::Accept
        ));
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
    async fn exact_vanish_replay_keeps_original_first_seen_at() {
        let ctx = context(crate::config::Config::for_testing());
        let service = DeletionService::new(ctx.clone());
        let request = vanish(&Keys::generate(), "replay");
        ctx.tombstones
            .record_request(
                &request,
                Timestamp::from_secs(10),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();

        assert!(matches!(
            service.handle_vanish(&request).await,
            WritePolicyResult::Accept
        ));
        assert_eq!(
            ctx.tombstones
                .lifecycle_for_request(&request.id)
                .await
                .unwrap()
                .first_seen_at,
            Timestamp::from_secs(10)
        );
    }

    #[tokio::test]
    async fn vanish_gate_promotes_and_updates_only_one_deterministic_request() {
        let ctx = context(crate::config::Config::for_testing());
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let older = vanish(&keys, "older");
        let newer = vanish(&keys, "newer");
        let now = Timestamp::now().as_secs();
        for (request, first_seen_at) in [(&older, now - 2), (&newer, now - 1)] {
            ctx.tombstones
                .record_request(
                    request,
                    Timestamp::from_secs(first_seen_at),
                    RequestClassification::LocallyActionable,
                )
                .await
                .unwrap();
        }
        let incoming = EventBuilder::new(Kind::TextNote, "blocked")
            .finalize(&keys)
            .unwrap();

        assert!(service.gate(&incoming).await.is_some());
        assert!(ctx.database.event_by_id(&older.id).await.unwrap().is_some());
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
    async fn coordinate_request_with_insufficient_cutoff_never_receives_use_credit() {
        let ctx = context(crate::config::Config::for_testing());
        let service = DeletionService::new(ctx.clone());
        let keys = Keys::generate();
        let coordinate = format!("30617:{}:repo", keys.public_key().to_hex());
        let request = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coordinate])])
            .custom_created_at(Timestamp::from_secs(100))
            .finalize(&keys)
            .unwrap();
        ctx.tombstones
            .record_request(
                &request,
                Timestamp::from_secs(10),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        let incoming = EventBuilder::new(Kind::GitRepoAnnouncement, "")
            .tags(vec![Tag::identifier("repo")])
            .custom_created_at(Timestamp::from_secs(101))
            .finalize(&keys)
            .unwrap();

        assert!(service.gate(&incoming).await.is_none());
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
