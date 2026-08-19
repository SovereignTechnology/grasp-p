//! Nostr-facing reactions to git purgatory promotion lifecycle events.
//!
//! `git::sync` owns the neutral [`PurgatoryPromotionHooks`] trait and emits
//! lifecycle events. This module adapts those events to Nostr/deletion concerns
//! without making git sync depend upward on deletion recovery, write policy, or
//! rejected-event cache internals.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use nostr_sdk::local_relay::LocalRelay;
use nostr_sdk::prelude::PublicKey;
use nostr_sdk::prelude::{Event, WritePolicy, WritePolicyResult};
use tracing::{debug, info, warn};

use crate::git::sync::{PurgatoryPromotionHooks, PurgatorySaveContext};
use crate::nostr::builder::Nip34WritePolicy;
use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::lifecycle::DeletionService;
use crate::nostr::persistence::SaveContext;
use crate::sync::rejected_index::{EventType, RejectedEventsIndex};

pub struct NostrPurgatoryPromotionHooks {
    deletion: DeletionService,
    write_policy: Option<Arc<Nip34WritePolicy>>,
    rejected_events_index: Option<Arc<RejectedEventsIndex>>,
    local_relay: Option<LocalRelay>,
}

impl NostrPurgatoryPromotionHooks {
    /// Run deletion recovery and any configured rejected-event dependency hooks.
    pub fn recovery_only(write_policy: &Nip34WritePolicy) -> Self {
        Self {
            deletion: write_policy.deletion().clone(),
            write_policy: Some(Arc::new(write_policy.clone())),
            rejected_events_index: write_policy.rejected_events_index(),
            local_relay: write_policy.local_relay(),
        }
    }

    /// Git-push path: deletion recovery plus immediate hot-cache reprocessing.
    pub fn git_push(
        write_policy: Arc<Nip34WritePolicy>,
        rejected_events_index: Arc<RejectedEventsIndex>,
        local_relay: Option<LocalRelay>,
    ) -> Self {
        Self {
            deletion: write_policy.deletion().clone(),
            write_policy: Some(write_policy),
            rejected_events_index: Some(rejected_events_index),
            local_relay,
        }
    }

    async fn reprocess_state_dependencies(
        &self,
        write_policy: &Nip34WritePolicy,
        rejected_events_index: &RejectedEventsIndex,
        relay: &LocalRelay,
        author: &PublicKey,
        identifier: &str,
    ) {
        let (event_ids, hot_events) =
            rejected_events_index.dependency_candidates(author, identifier, Some(EventType::State));
        if !event_ids.is_empty() {
            info!(
                pubkey = %author,
                identifier = %identifier,
                dependency_event_count = event_ids.len(),
                hot_cache_events = hot_events.len(),
                "Found rejected state dependencies after purgatory announcement promotion"
            );
        }

        let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        for state in hot_events {
            info!(
                event_id = %state.id,
                pubkey = %author,
                identifier = %identifier,
                "Re-processing state event after purgatory announcement promotion"
            );

            match write_policy.admit_event(&state, &dummy_addr).await {
                WritePolicyResult::Accept => {
                    match write_policy
                        .save_accepted_event(&state, SaveContext::HotCacheReprocess)
                        .await
                    {
                        Ok(_) => {
                            rejected_events_index.remove(&state.id);
                            relay.notify_event(state.clone());
                        }
                        Err(e) => {
                            warn!(
                                event_id = %state.id,
                                error = %e,
                                "Failed to save re-processed state event"
                            );
                        }
                    }
                }
                WritePolicyResult::Reject { status: true, .. } => {
                    rejected_events_index.remove(&state.id);
                    write_policy.purgatory().enqueue_sync_immediate(identifier);
                }
                _ => {
                    warn!(
                        event_id = %state.id,
                        "State event still rejected after announcement promotion"
                    );
                }
            }
        }
    }
}

#[async_trait]
impl PurgatoryPromotionHooks for NostrPurgatoryPromotionHooks {
    async fn before_event_saved(&self, event: &Event, context: PurgatorySaveContext) {
        tracing::trace!(
            event_id = %event.id,
            kind = event.kind.as_u16(),
            ?context,
            "Preparing purgatory-promoted event for main database persistence"
        );

        self.deletion
            .capture_superseded_replaceable_history(event)
            .await;
    }

    async fn before_announcement_promote(&self, event: &Event, identifier: &str) {
        self.deletion
            .maybe_recover_deleted_repository(event, identifier)
            .await;
    }

    async fn after_announcement_saved(&self, event: &Event) {
        let (Some(write_policy), Some(rejected_events_index), Some(relay)) = (
            self.write_policy.as_deref(),
            self.rejected_events_index.as_ref(),
            self.local_relay.as_ref(),
        ) else {
            return;
        };

        let Ok(announcement) = RepositoryAnnouncement::from_event(event.clone()) else {
            return;
        };

        // Every currently-listed maintainer, including invited ones whose
        // announcements we still need to notice acceptance.
        let listed_maintainers = announcement.listed_maintainers();
        debug!(
            identifier = %announcement.identifier,
            event_id = %event.id,
            maintainer_count = listed_maintainers.len(),
            "Owner announcement promoted from purgatory, checking hot cache for rejected maintainer announcements"
        );

        for maintainer_hex in &listed_maintainers {
            match PublicKey::from_hex(maintainer_hex) {
                Ok(maintainer_pubkey) => {
                    let (event_ids, hot_events) = rejected_events_index.dependency_candidates(
                        &maintainer_pubkey,
                        &announcement.identifier,
                        Some(EventType::Announcement),
                    );

                    if !event_ids.is_empty() {
                        info!(
                            maintainer = %maintainer_hex,
                            identifier = %announcement.identifier,
                            dependency_event_count = event_ids.len(),
                            hot_cache_events = hot_events.len(),
                            "Found rejected maintainer dependencies after purgatory promotion"
                        );
                    }

                    let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
                    for hot_event in hot_events {
                        info!(
                            event_id = %hot_event.id,
                            maintainer = %maintainer_hex,
                            identifier = %announcement.identifier,
                            "Re-processing maintainer announcement from hot cache after purgatory promotion"
                        );

                        match write_policy.admit_event(&hot_event, &dummy_addr).await {
                            WritePolicyResult::Accept => {
                                match write_policy
                                    .save_accepted_event(&hot_event, SaveContext::HotCacheReprocess)
                                    .await
                                {
                                    Ok(_) => {
                                        rejected_events_index.remove(&hot_event.id);
                                        relay.notify_event(hot_event.clone());
                                        self.reprocess_state_dependencies(
                                            write_policy,
                                            rejected_events_index,
                                            relay,
                                            &hot_event.pubkey,
                                            &announcement.identifier,
                                        )
                                        .await;
                                        info!(
                                            event_id = %hot_event.id,
                                            "Maintainer announcement accepted and saved on re-processing"
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            event_id = %hot_event.id,
                                            error = %e,
                                            "Failed to save re-processed maintainer announcement"
                                        );
                                    }
                                }
                            }
                            _ => {
                                warn!(
                                    event_id = %hot_event.id,
                                    "Maintainer announcement still rejected on re-processing"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        maintainer_hex = %maintainer_hex,
                        error = %e,
                        "Invalid maintainer public key in promoted announcement"
                    );
                }
            }
        }

        self.reprocess_state_dependencies(
            write_policy,
            rejected_events_index,
            relay,
            &event.pubkey,
            &announcement.identifier,
        )
        .await;
    }
}
