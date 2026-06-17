//! Holding database for deleted events.
//!
//! Phase 2 foundation:
//! - copy/move deleted events out of the main DB into a dedicated holding DB,
//! - persist minimal per-event metadata for later retention/recovery phases.

use std::path::Path;
use std::sync::Arc;

use nostr_lmdb::NostrLmdb;
use nostr_memory::MemoryDatabase;
use nostr_relay_builder::prelude::{
    Alphabet, Event, EventBuilder, EventId, Filter, FinalizeEvent, Keys, Kind, NostrDatabase,
    SingleLetterTag, Tag, Timestamp,
};

/// Directory name (under `relay_data_path`) for the LMDB holding database.
pub const HOLDING_DIR: &str = "holding";

/// Internal metadata event kind stored alongside archived events.
pub const HOLDING_METADATA_KIND: u16 = 9905;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionSource {
    Nip09,
    Blacklist,
}

impl DeletionSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nip09 => "nip09",
            Self::Blacklist => "blacklist",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HoldingMetadata {
    pub deleted_at: Timestamp,
    pub source: DeletionSource,
    pub coordinate: Option<String>,
    pub identifier: Option<String>,
}

#[derive(Clone)]
pub struct HoldingStore {
    db: Arc<dyn NostrDatabase>,
    metadata_signer: Keys,
}

impl std::fmt::Debug for HoldingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoldingStore").finish_non_exhaustive()
    }
}

impl HoldingStore {
    pub async fn open_lmdb(relay_data_path: &Path) -> anyhow::Result<Self> {
        let path = relay_data_path.join(HOLDING_DIR);
        std::fs::create_dir_all(&path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create holding directory {}: {}",
                path.display(),
                e
            )
        })?;

        let db = NostrLmdb::builder(&path)
            .process_nip09(false)
            .process_nip62(false)
            .build()
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to open holding LMDB at {}: {}", path.display(), e)
            })?;

        Ok(Self {
            db: Arc::new(db),
            metadata_signer: Keys::generate(),
        })
    }

    pub fn in_memory() -> Self {
        Self {
            db: Arc::new(MemoryDatabase::unbounded()),
            metadata_signer: Keys::generate(),
        }
    }

    /// Archive one event in the holding DB and record minimal metadata.
    pub async fn archive_event(
        &self,
        event: &Event,
        metadata: &HoldingMetadata,
    ) -> anyhow::Result<()> {
        self.db.save_event(event).await.map_err(|e| {
            anyhow::anyhow!("Failed to store event {} in holding DB: {e}", event.id)
        })?;

        let mut tags = vec![
            Tag::event(event.id),
            Tag::custom("holding-source", vec![metadata.source.as_str().to_string()]),
            Tag::custom(
                "holding-deleted-at",
                vec![metadata.deleted_at.as_secs().to_string()],
            ),
        ];

        if let Some(coord) = &metadata.coordinate {
            tags.push(Tag::custom("a", vec![coord.clone()]));
        }
        if let Some(identifier) = &metadata.identifier {
            tags.push(Tag::custom("d", vec![identifier.clone()]));
        }

        let metadata_event = EventBuilder::new(Kind::from(HOLDING_METADATA_KIND), "")
            .tags(tags)
            .finalize(&self.metadata_signer)
            .map_err(|e| anyhow::anyhow!("Failed to build holding metadata event: {e}"))?;

        self.db.save_event(&metadata_event).await.map_err(|e| {
            anyhow::anyhow!("Failed to store holding metadata for {}: {e}", event.id)
        })?;

        Ok(())
    }

    pub async fn has_event(&self, id: &EventId) -> bool {
        match self.db.event_by_id(id).await {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                tracing::error!(error = %e, event_id = %id.to_hex(), "Holding DB lookup failed");
                false
            }
        }
    }

    pub async fn metadata_for_event(&self, id: &EventId) -> Vec<Event> {
        let filter = Filter::new()
            .kind(Kind::from(HOLDING_METADATA_KIND))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::E), id.to_hex());

        match self.db.query(filter).await {
            Ok(events) => events.into_iter().collect(),
            Err(e) => {
                tracing::error!(error = %e, event_id = %id.to_hex(), "Holding metadata query failed");
                Vec::new()
            }
        }
    }
}
