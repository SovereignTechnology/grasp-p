//! Central persistence hooks for accepted GRASP events.
//!
//! The normal websocket write path is persisted by `nostr-relay-builder` after
//! `WritePolicyResult::Accept`, while sync/hot-cache paths save directly. This
//! module provides the direct accepted-event save facade for paths outside the
//! relay builder.

use nostr_sdk::prelude::{Event, RejectedReason, SaveEventStatus};

use crate::nostr::SharedDatabase;

/// Where an accepted event is being prepared/saved from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveContext {
    /// Websocket/local relay path. The database save happens outside this crate
    /// after the write policy returns `Accept`.
    DirectWritePolicyAcceptance,
    /// Event accepted while consuming a remote relay subscription.
    RelaySync,
    /// Event accepted during rejected hot-cache reprocessing.
    HotCacheReprocess,
}

/// Durable outcome of saving an event that already passed write policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptedEventSaveOutcome {
    /// The database inserted the event.
    Saved,
    /// The database already had this event or retained a newer replaceable event.
    Duplicate,
}

/// Nostr-owned facade for accepted-event persistence side effects.
pub struct EventPersistence<'a> {
    database: &'a SharedDatabase,
}

impl<'a> EventPersistence<'a> {
    pub fn new(database: &'a SharedDatabase) -> Self {
        Self { database }
    }

    /// Save an already-accepted event to the main database via the central
    /// persistence path.
    pub async fn save_accepted_event(
        &self,
        event: &Event,
        context: SaveContext,
    ) -> anyhow::Result<AcceptedEventSaveOutcome> {
        let status = self
            .database
            .save_event(event)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to save accepted event {}: {e}", event.id))?;

        let outcome = match status {
            SaveEventStatus::Success => AcceptedEventSaveOutcome::Saved,
            SaveEventStatus::Rejected(RejectedReason::Duplicate | RejectedReason::Replaced) => {
                AcceptedEventSaveOutcome::Duplicate
            }
            SaveEventStatus::Rejected(reason) => {
                return Err(anyhow::anyhow!(
                    "Database rejected accepted event {}: {reason:?}",
                    event.id
                ));
            }
        };

        tracing::trace!(
            event_id = %event.id,
            kind = event.kind.as_u16(),
            ?context,
            ?outcome,
            "Applied accepted event to main database"
        );

        Ok(outcome)
    }
}
