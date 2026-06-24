//! Nostr-facing reactions to git purgatory promotion lifecycle events.
//!
//! `git::sync` owns the neutral [`PurgatoryPromotionHooks`] trait and emits
//! lifecycle events. This module adapts those events to Nostr/deletion concerns
//! without making git sync depend upward on deletion recovery, write policy, or
//! rejected-event cache internals.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use nostr_relay_builder::prelude::{Event, WritePolicy, WritePolicyResult};
use nostr_relay_builder::LocalRelay;
use nostr_sdk::prelude::PublicKey;
use tracing::{debug, info, warn};

use crate::git::sync::{PurgatoryPromotionHooks, PurgatorySaveContext};
use crate::nostr::builder::Nip34WritePolicy;
use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::lifecycle::DeletionService;
use crate::nostr::persistence::SaveContext;
use crate::sync::rejected_index::{EventType, RejectedEventsIndex};

pub struct NostrPurgatoryPromotionHooks<'a> {
    deletion: &'a DeletionService,
    write_policy: Option<&'a Nip34WritePolicy>,
    rejected_events_index: Option<&'a Arc<RejectedEventsIndex>>,
    local_relay: Option<&'a LocalRelay>,
}

impl<'a> NostrPurgatoryPromotionHooks<'a> {
    /// Run deletion recovery and accepted-event persistence hooks only.
    pub fn recovery_only(write_policy: &'a Nip34WritePolicy) -> Self {
        Self {
            deletion: write_policy.deletion(),
            write_policy: Some(write_policy),
            rejected_events_index: None,
            local_relay: None,
        }
    }

    /// Git-push path: deletion recovery plus immediate hot-cache reprocessing.
    pub fn git_push(
        write_policy: &'a Nip34WritePolicy,
        rejected_events_index: &'a Arc<RejectedEventsIndex>,
        local_relay: Option<&'a LocalRelay>,
    ) -> Self {
        Self {
            deletion: write_policy.deletion(),
            write_policy: Some(write_policy),
            rejected_events_index: Some(rejected_events_index),
            local_relay,
        }
    }
}

#[async_trait]
impl PurgatoryPromotionHooks for NostrPurgatoryPromotionHooks<'_> {
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
            self.write_policy,
            self.rejected_events_index,
            self.local_relay,
        ) else {
            return;
        };

        let Ok(announcement) = RepositoryAnnouncement::from_event(event.clone()) else {
            return;
        };

        if announcement.maintainers.is_empty() {
            return;
        }

        debug!(
            identifier = %announcement.identifier,
            event_id = %event.id,
            maintainer_count = announcement.maintainers.len(),
            "Owner announcement promoted via git push, checking hot cache for rejected maintainer announcements"
        );

        for maintainer_hex in &announcement.maintainers {
            match PublicKey::from_hex(maintainer_hex) {
                Ok(maintainer_pubkey) => {
                    let (removed, hot_events) = rejected_events_index.invalidate_and_get(
                        &maintainer_pubkey,
                        &announcement.identifier,
                        Some(EventType::Announcement),
                    );

                    if removed > 0 {
                        info!(
                            maintainer = %maintainer_hex,
                            identifier = %announcement.identifier,
                            removed_from_cold_index = removed,
                            hot_cache_events = hot_events.len(),
                            "Invalidated rejected maintainer announcements after git push promotion"
                        );
                    }

                    let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
                    for hot_event in hot_events {
                        info!(
                            event_id = %hot_event.id,
                            maintainer = %maintainer_hex,
                            identifier = %announcement.identifier,
                            "Re-processing maintainer announcement from hot cache after git push promotion"
                        );

                        match write_policy.admit_event(&hot_event, &dummy_addr).await {
                            WritePolicyResult::Accept => {
                                match write_policy
                                    .save_accepted_event(&hot_event, SaveContext::HotCacheReprocess)
                                    .await
                                {
                                    Ok(_) => {
                                        relay.notify_event(hot_event.clone());
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
    }
}
