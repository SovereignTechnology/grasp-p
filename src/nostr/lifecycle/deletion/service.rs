use anyhow::Result;
use nostr_relay_builder::prelude::{
    nip62, Alphabet, Event, Filter, Kind, PublicKey, RelayUrl, SingleLetterTag, WritePolicyResult,
};

use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::policy::{reject_error, reject_invalid, AnnouncementResult};

use super::{DeletionContext, DeletionPolicy};

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
        // 1. Vanished pubkey
        if self
            .ctx
            .tombstones()
            .is_pubkey_vanished(&event.pubkey)
            .await
        {
            tracing::debug!(
                event_id = %event.id.to_hex(),
                author = %event.pubkey.to_hex(),
                "Rejected event from vanished pubkey"
            );
            return Some(reject_invalid("this pubkey has requested to vanish"));
        }

        // 2. Deleted event id (author-bound: only the event's own author may
        //    have deleted it)
        if self
            .ctx
            .tombstones()
            .is_event_deleted(&event.id, &event.pubkey)
            .await
        {
            tracing::debug!(
                event_id = %event.id.to_hex(),
                "Rejected re-submission of deleted event"
            );
            return Some(reject_invalid("this event is deleted"));
        }

        // 3. Deleted coordinate (replaceable / addressable events only)
        if event.kind.is_replaceable() || event.kind.is_addressable() {
            if let Some(coord) = Self::event_coordinate(event) {
                if self
                    .ctx
                    .tombstones()
                    .is_coordinate_deleted(&coord, event.created_at)
                    .await
                {
                    tracing::debug!(
                        event_id = %event.id.to_hex(),
                        coordinate = %coord,
                        "Rejected event whose coordinate was deleted"
                    );
                    return Some(reject_invalid("this event is deleted"));
                }
            }
        }

        None
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

        if let Err(e) = self.policy.apply_nip62_vanish(event).await {
            tracing::error!(error = %e, author = %author.to_hex(), "Failed to process vanished author's lifecycle deletion");
            return reject_error(format!("internal error processing vanish: {e}"));
        }

        // Evict the author's purgatory entries (and their bare repos). Served
        // data has already gone through the holding/archive lifecycle above;
        // purgatory entries are not live served data.
        self.evict_author_from_purgatory(&author);

        tracing::info!(
            author = %author.to_hex(),
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

    fn evict_author_from_purgatory(&self, author: &PublicKey) {
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
                    }
                }
            }
            self.ctx.purgatory().remove_announcement(author, identifier);
        }

        // State events authored by this author across all identifiers.
        for identifier in self.ctx.purgatory().get_all_identifiers() {
            for entry in self.ctx.purgatory().find_state(&identifier) {
                if entry.author == *author {
                    self.ctx
                        .purgatory()
                        .remove_state_event(&identifier, &entry.event.id);
                }
            }
        }
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
