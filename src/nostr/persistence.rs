//! Central persistence hooks for accepted GRASP events.
//!
//! The normal websocket write path is persisted by `nostr-relay-builder` after
//! `WritePolicyResult::Accept`, while sync/purgatory paths save directly.  This
//! module keeps the pre-save side effects that must happen for every accepted
//! main-DB persistence path in one Nostr-owned facade.

use nostr_relay_builder::prelude::Event;

use crate::nostr::deletion::DeletionService;
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
    /// State event released from git purgatory into the main DB.
    PurgatoryStatePromotion,
    /// Announcement event released from git purgatory into the main DB.
    PurgatoryAnnouncementPromotion,
    /// PR/PR-update event released from git purgatory into the main DB.
    PurgatoryPrPromotion,
}

/// Nostr-owned facade for accepted-event persistence side effects.
pub struct EventPersistence<'a> {
    database: &'a SharedDatabase,
    deletion: &'a DeletionService,
}

impl<'a> EventPersistence<'a> {
    pub fn new(database: &'a SharedDatabase, deletion: &'a DeletionService) -> Self {
        Self { database, deletion }
    }

    /// Run side effects that must occur immediately before an accepted event is
    /// persisted to the main database.
    pub async fn before_accepted_event_persisted(&self, event: &Event, context: SaveContext) {
        tracing::trace!(
            event_id = %event.id,
            kind = event.kind.as_u16(),
            ?context,
            "Preparing accepted event for main database persistence"
        );

        self.deletion
            .capture_superseded_replaceable_history(event)
            .await;
    }

    /// Save an already-accepted event to the main database via the central
    /// persistence path.
    pub async fn save_accepted_event(
        &self,
        event: &Event,
        context: SaveContext,
    ) -> anyhow::Result<()> {
        self.before_accepted_event_persisted(event, context).await;

        self.database
            .save_event(event)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("Failed to save accepted event {}: {e}", event.id))?;

        tracing::trace!(
            event_id = %event.id,
            kind = event.kind.as_u16(),
            ?context,
            "Saved accepted event to main database"
        );

        Ok(())
    }
}
