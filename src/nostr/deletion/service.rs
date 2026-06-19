use anyhow::Result;
use nostr_relay_builder::prelude::{nip62, Event, PublicKey, WritePolicyResult};

use crate::nostr::holding::{LifecycleReadGuard, LifecycleWriteGuard};
use crate::nostr::policy::{reject_error, reject_invalid, DeletionPolicy};

use super::DeletionContext;

#[derive(Clone)]
pub struct DeletionService {
    ctx: DeletionContext,
    policy: DeletionPolicy,
}

impl DeletionService {
    pub fn new(ctx: DeletionContext) -> Self {
        let policy = DeletionPolicy::new(ctx.policy_context().clone());
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

    pub async fn handle_nip09(&self, event: &Event) -> WritePolicyResult {
        self.policy.handle(event).await
    }

    pub async fn handle_vanish(&self, event: &Event) -> WritePolicyResult {
        // Only honour requests that target this relay (or all relays). We do not
        // configure a relay_url on the database, matching the historical
        // behaviour where only ALL_RELAYS requests were actioned; but we accept
        // (store) any well-formed kind-62 so clients get an OK.
        let targets_relay = nip62::is_valid_vanish_request_for_relay(event.tags.as_slice(), None);

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

        // 2. Hard-delete the author's events from the main database.
        let filter = nostr_relay_builder::prelude::Filter::new().author(author);
        if let Err(e) = self.ctx.database().delete(filter).await {
            tracing::error!(error = %e, author = %author.to_hex(), "Failed to delete vanished author's events");
            return reject_error(format!("internal error processing vanish: {e}"));
        }

        // 3. Evict the author's purgatory entries (and their bare repos).
        self.evict_author_from_purgatory(&author);

        tracing::info!(
            author = %author.to_hex(),
            "Processed NIP-62 request to vanish: deleted author's events and purgatory entries"
        );

        WritePolicyResult::Accept
    }

    pub async fn read_repository_lifecycle(
        &self,
        owner_pubkey_hex: &str,
        identifier: &str,
    ) -> LifecycleReadGuard {
        self.ctx
            .holding()
            .read_recovery_scope(owner_pubkey_hex, identifier)
            .await
    }

    pub async fn write_repository_lifecycle(
        &self,
        owner_pubkey_hex: &str,
        identifier: &str,
    ) -> LifecycleWriteGuard {
        self.ctx
            .holding()
            .write_recovery_scope(owner_pubkey_hex, identifier)
            .await
    }

    pub fn holding(&self) -> &crate::nostr::holding::HoldingStore {
        self.ctx.holding()
    }

    pub fn history(&self) -> &crate::nostr::history::ReplaceableHistoryStore {
        self.ctx.history()
    }

    pub fn tombstones(&self) -> &crate::nostr::tombstones::Tombstones {
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
