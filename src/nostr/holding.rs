//! Holding database for deleted events.
//!
//! Phase 2 foundation:
//! - copy/move deleted events out of the main DB into a dedicated holding DB,
//! - persist minimal per-event metadata for later retention/recovery phases.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

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

/// Default retention window for deleted events kept in the holding DB.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Default interval between background holding cleanup passes.
pub const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiredMetadataRecord {
    pub metadata_event_id: EventId,
    pub archived_event_id: Option<EventId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CleanupStats {
    pub metadata_examined: usize,
    pub expired_records: usize,
    pub metadata_deleted: usize,
    pub archived_events_deleted: usize,
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

    fn parse_holding_deleted_at(metadata_event: &Event) -> Option<Timestamp> {
        metadata_event.tags.iter().find_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == "holding-deleted-at" {
                v[1].parse::<u64>().ok().map(Timestamp::from_secs)
            } else {
                None
            }
        })
    }

    fn parse_archived_event_id(metadata_event: &Event) -> Option<EventId> {
        metadata_event.tags.iter().find_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == "e" {
                EventId::from_hex(&v[1]).ok()
            } else {
                None
            }
        })
    }

    /// Find expired metadata records in holding based on `holding-deleted-at`
    /// and a retention window.
    ///
    /// Metadata entries that are missing or have an invalid `holding-deleted-at`
    /// value are skipped (treated as non-expired) to keep cleanup fail-safe.
    pub async fn expired_records(
        &self,
        now: Timestamp,
        retention: Duration,
    ) -> Vec<ExpiredMetadataRecord> {
        let cutoff = now.as_secs().saturating_sub(retention.as_secs());
        let filter = Filter::new().kind(Kind::from(HOLDING_METADATA_KIND));

        let metadata_events = match self.db.query(filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(error = %e, "Holding cleanup failed to query metadata events");
                return Vec::new();
            }
        };

        metadata_events
            .into_iter()
            .filter_map(|metadata_event| {
                let deleted_at = Self::parse_holding_deleted_at(&metadata_event)?;
                if deleted_at.as_secs() <= cutoff {
                    Some(ExpiredMetadataRecord {
                        metadata_event_id: metadata_event.id,
                        archived_event_id: Self::parse_archived_event_id(&metadata_event),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Delete one expired metadata record plus its archived event (when present).
    ///
    /// This is idempotent: missing archived events and missing metadata rows are
    /// tolerated and do not error.
    pub async fn delete_expired_record(
        &self,
        record: ExpiredMetadataRecord,
    ) -> anyhow::Result<(bool, bool)> {
        let mut metadata_deleted = false;
        let mut event_deleted = false;

        if let Some(event_id) = record.archived_event_id {
            let exists = self.db.event_by_id(&event_id).await.map_err(|e| {
                anyhow::anyhow!("Failed to look up archived holding event {}: {e}", event_id)
            })?;
            if exists.is_some() {
                self.db
                    .delete(Filter::new().ids(vec![event_id]))
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to delete archived holding event {}: {e}", event_id)
                    })?;
                event_deleted = true;
            }
        }

        let metadata_exists = self
            .db
            .event_by_id(&record.metadata_event_id)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to look up holding metadata event {}: {e}",
                    record.metadata_event_id
                )
            })?;
        if metadata_exists.is_some() {
            self.db
                .delete(Filter::new().ids(vec![record.metadata_event_id]))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to delete holding metadata event {}: {e}",
                        record.metadata_event_id
                    )
                })?;
            metadata_deleted = true;
        }

        Ok((metadata_deleted, event_deleted))
    }

    /// Cleanup pass for expired holding records.
    ///
    /// - Computes expiry from `holding-deleted-at` metadata + `retention`.
    /// - Removes expired metadata rows and best-effort removes their archived
    ///   event payload.
    /// - Idempotent with missing metadata/events and safe to run repeatedly.
    pub async fn cleanup_expired(
        &self,
        now: Timestamp,
        retention: Duration,
    ) -> anyhow::Result<CleanupStats> {
        let filter = Filter::new().kind(Kind::from(HOLDING_METADATA_KIND));
        let metadata_examined = self
            .db
            .query(filter)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to query holding metadata for cleanup: {e}"))?
            .len();

        let expired = self.expired_records(now, retention).await;
        let mut stats = CleanupStats {
            metadata_examined,
            expired_records: expired.len(),
            ..CleanupStats::default()
        };

        for record in expired {
            let (metadata_deleted, event_deleted) = self.delete_expired_record(record).await?;
            if metadata_deleted {
                stats.metadata_deleted += 1;
            }
            if event_deleted {
                stats.archived_events_deleted += 1;
            }
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event(content: &str, created_at: Timestamp) -> Event {
        EventBuilder::new(Kind::TextNote, content)
            .custom_created_at(created_at)
            .finalize(&Keys::generate())
            .expect("build test event")
    }

    #[tokio::test]
    async fn cleanup_ignores_corrupt_metadata_deleted_at() {
        let store = HoldingStore::in_memory();
        let metadata = EventBuilder::new(Kind::from(HOLDING_METADATA_KIND), "")
            .tags(vec![
                Tag::custom("e", vec![EventId::all_zeros().to_hex()]),
                Tag::custom("holding-deleted-at", vec!["not-a-number".to_string()]),
            ])
            .finalize(&Keys::generate())
            .expect("build metadata event");

        store.db.save_event(&metadata).await.expect("save metadata");

        let stats = store
            .cleanup_expired(Timestamp::now(), Duration::from_secs(1))
            .await
            .expect("cleanup should succeed");

        assert_eq!(stats.expired_records, 0);
        assert_eq!(stats.metadata_deleted, 0);
    }

    #[tokio::test]
    async fn cleanup_deletes_metadata_even_if_archived_event_is_missing() {
        let store = HoldingStore::in_memory();
        let event = test_event("to archive", Timestamp::from_secs(10));
        let deleted_at = Timestamp::from_secs(11);

        store
            .archive_event(
                &event,
                &HoldingMetadata {
                    deleted_at,
                    source: DeletionSource::Nip09,
                    coordinate: None,
                    identifier: None,
                },
            )
            .await
            .expect("archive event");

        // Simulate partial/corrupt holding state: archived payload missing while
        // metadata still exists.
        store
            .db
            .delete(Filter::new().ids(vec![event.id]))
            .await
            .expect("delete archived payload directly");

        let stats = store
            .cleanup_expired(Timestamp::from_secs(10_000), Duration::from_secs(1))
            .await
            .expect("cleanup should succeed");

        assert_eq!(stats.expired_records, 1);
        assert_eq!(stats.archived_events_deleted, 0);
        assert_eq!(stats.metadata_deleted, 1);
        assert!(store.metadata_for_event(&event.id).await.is_empty());
    }
}
