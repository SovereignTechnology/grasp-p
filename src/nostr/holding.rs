//! Holding database for deleted events.
//!
//! Phase 2 foundation:
//! - copy/move deleted events out of the main DB into a dedicated holding DB,
//! - persist minimal per-event metadata for later retention/recovery phases.

use std::path::{Component, Path, PathBuf};
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
pub const HOLDING_ARCHIVE_PATH_TAG: &str = "holding-archive-path";
pub const HOLDING_ARCHIVE_CREATED_AT_TAG: &str = "holding-archive-created-at";
pub const HOLDING_OWNER_PUBKEY_TAG: &str = "holding-owner-pubkey";

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
    pub owner_pubkey: Option<String>,
    pub git_archive: Option<GitArchiveMetadata>,
}

#[derive(Debug, Clone)]
pub struct GitArchiveMetadata {
    pub relative_path: String,
    pub created_at: Timestamp,
}

#[derive(Clone)]
pub struct HoldingStore {
    db: Arc<dyn NostrDatabase>,
    metadata_signer: Keys,
    archive_root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredMetadataRecord {
    pub metadata_event_id: EventId,
    pub archived_event_id: Option<EventId>,
    pub archive_relative_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMetadataRecord {
    pub metadata_event_id: EventId,
    pub archived_event_id: Option<EventId>,
    pub archive_relative_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CleanupStats {
    pub metadata_examined: usize,
    pub expired_records: usize,
    pub metadata_deleted: usize,
    pub archived_events_deleted: usize,
    pub archive_files_deleted: usize,
}

impl std::fmt::Debug for HoldingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoldingStore").finish_non_exhaustive()
    }
}

impl HoldingStore {
    pub async fn open_lmdb(relay_data_path: &Path, git_data_path: &Path) -> anyhow::Result<Self> {
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
            archive_root: Some(git_data_path.join(".archive")),
        })
    }

    pub fn in_memory() -> Self {
        Self {
            db: Arc::new(MemoryDatabase::unbounded()),
            metadata_signer: Keys::generate(),
            archive_root: None,
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
        if let Some(owner_pubkey) = &metadata.owner_pubkey {
            tags.push(Tag::custom(
                HOLDING_OWNER_PUBKEY_TAG,
                vec![owner_pubkey.clone()],
            ));
        }
        if let Some(git_archive) = &metadata.git_archive {
            tags.push(Tag::custom(
                HOLDING_ARCHIVE_PATH_TAG,
                vec![git_archive.relative_path.clone()],
            ));
            tags.push(Tag::custom(
                HOLDING_ARCHIVE_CREATED_AT_TAG,
                vec![git_archive.created_at.as_secs().to_string()],
            ));
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

    fn parse_archive_relative_path(metadata_event: &Event) -> Option<String> {
        metadata_event.tags.iter().find_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == HOLDING_ARCHIVE_PATH_TAG {
                Some(v[1].clone())
            } else {
                None
            }
        })
    }

    fn parse_identifier(metadata_event: &Event) -> Option<String> {
        metadata_event.tags.iter().find_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == "d" {
                Some(v[1].clone())
            } else {
                None
            }
        })
    }

    fn parse_owner_pubkey(metadata_event: &Event) -> Option<String> {
        metadata_event.tags.iter().find_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == HOLDING_OWNER_PUBKEY_TAG {
                Some(v[1].clone())
            } else {
                None
            }
        })
    }

    fn parse_coordinate(metadata_event: &Event) -> Option<String> {
        metadata_event.tags.iter().find_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == "a" {
                Some(v[1].clone())
            } else {
                None
            }
        })
    }

    fn metadata_matches_recovery_scope(
        metadata_event: &Event,
        owner_pubkey_hex: &str,
        identifier: &str,
    ) -> bool {
        let expected_coord = format!("30617:{}:{}", owner_pubkey_hex, identifier);

        if Self::parse_coordinate(metadata_event).as_deref() == Some(expected_coord.as_str()) {
            return true;
        }

        let Some(meta_identifier) = Self::parse_identifier(metadata_event) else {
            return false;
        };

        if meta_identifier != identifier {
            return false;
        }

        match Self::parse_owner_pubkey(metadata_event) {
            Some(owner) => owner == owner_pubkey_hex,
            // Legacy/unanchored state metadata may not carry an owner pubkey.
            None => true,
        }
    }

    /// Find holding metadata records eligible for repository recovery.
    ///
    /// Eligibility requires all of:
    /// - metadata belongs to the same owner+identifier recovery scope,
    /// - metadata has a parseable `holding-deleted-at`,
    /// - metadata is within `retention` from `now`.
    pub async fn eligible_recovery_records(
        &self,
        owner_pubkey_hex: &str,
        identifier: &str,
        now: Timestamp,
        retention: Duration,
    ) -> Vec<RecoveryMetadataRecord> {
        let cutoff = now.as_secs().saturating_sub(retention.as_secs());
        let filter = Filter::new().kind(Kind::from(HOLDING_METADATA_KIND));

        let metadata_events = match self.db.query(filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(error = %e, "Holding recovery failed to query metadata events");
                return Vec::new();
            }
        };

        metadata_events
            .into_iter()
            .filter(|metadata_event| {
                Self::metadata_matches_recovery_scope(metadata_event, owner_pubkey_hex, identifier)
            })
            .filter_map(|metadata_event| {
                let deleted_at = Self::parse_holding_deleted_at(&metadata_event)?;
                if deleted_at.as_secs() <= cutoff {
                    return None;
                }

                Some(RecoveryMetadataRecord {
                    metadata_event_id: metadata_event.id,
                    archived_event_id: Self::parse_archived_event_id(&metadata_event),
                    archive_relative_path: Self::parse_archive_relative_path(&metadata_event),
                })
            })
            .collect()
    }

    /// Resolve an archive-relative path to an absolute path under `.archive`.
    pub fn archive_absolute_path(&self, relative_path: &str) -> Option<PathBuf> {
        self.resolve_archive_path(relative_path)
    }

    /// Load one archived payload event by id from the holding DB.
    pub async fn archived_event(&self, id: &EventId) -> anyhow::Result<Option<Event>> {
        self.db
            .event_by_id(id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to load archived holding event {}: {e}", id))
    }

    /// Delete one archived payload event by id (without touching metadata).
    ///
    /// Intended for corruption handling/tests that need to model stale metadata
    /// pointing at a missing payload event.
    pub async fn delete_archived_payload(&self, id: &EventId) -> anyhow::Result<bool> {
        let exists = self.db.event_by_id(id).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to look up archived holding payload event {}: {e}",
                id
            )
        })?;
        if exists.is_none() {
            return Ok(false);
        }

        self.db
            .delete(Filter::new().ids(vec![*id]))
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to delete archived holding payload event {}: {e}",
                    id
                )
            })?;

        Ok(true)
    }

    /// Remove one recovery metadata record and its archived payload (if present).
    ///
    /// Idempotent: missing payload/metadata rows are tolerated.
    pub async fn delete_recovery_record(
        &self,
        record: &RecoveryMetadataRecord,
    ) -> anyhow::Result<(bool, bool)> {
        let mut metadata_deleted = false;
        let mut payload_deleted = false;

        if let Some(event_id) = record.archived_event_id {
            let payload_exists = self.db.event_by_id(&event_id).await.map_err(|e| {
                anyhow::anyhow!("Failed to look up archived holding event {}: {e}", event_id)
            })?;
            if payload_exists.is_some() {
                self.db
                    .delete(Filter::new().ids(vec![event_id]))
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to delete recovered holding payload event {}: {e}",
                            event_id
                        )
                    })?;
                payload_deleted = true;
            }
        }

        let metadata_exists = self
            .db
            .event_by_id(&record.metadata_event_id)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to look up holding recovery metadata event {}: {e}",
                    record.metadata_event_id
                )
            })?;
        if metadata_exists.is_some() {
            self.db
                .delete(Filter::new().ids(vec![record.metadata_event_id]))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to delete holding recovery metadata event {}: {e}",
                        record.metadata_event_id
                    )
                })?;
            metadata_deleted = true;
        }

        Ok((metadata_deleted, payload_deleted))
    }

    fn resolve_archive_path(&self, relative_path: &str) -> Option<PathBuf> {
        let root = self.archive_root.as_ref()?;
        let rel = Path::new(relative_path);
        if rel.is_absolute() {
            tracing::warn!(path = %relative_path, "Ignoring absolute holding archive path");
            return None;
        }

        if rel.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            tracing::warn!(path = %relative_path, "Ignoring unsafe holding archive path");
            return None;
        }

        Some(root.join(rel))
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
                        archive_relative_path: Self::parse_archive_relative_path(&metadata_event),
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
    ) -> anyhow::Result<(bool, bool, bool)> {
        let mut metadata_deleted = false;
        let mut event_deleted = false;
        let mut archive_deleted = false;

        if let Some(relative_path) = record.archive_relative_path.as_deref() {
            if let Some(absolute_path) = self.resolve_archive_path(relative_path) {
                match std::fs::remove_file(&absolute_path) {
                    Ok(()) => {
                        archive_deleted = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        tracing::warn!(
                            path = %absolute_path.display(),
                            "Holding cleanup archive file missing; continuing"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %absolute_path.display(),
                            error = %e,
                            "Holding cleanup failed to delete archive file; continuing"
                        );
                    }
                }
            }
        }

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

        Ok((metadata_deleted, event_deleted, archive_deleted))
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
            let (metadata_deleted, event_deleted, archive_deleted) =
                self.delete_expired_record(record).await?;
            if metadata_deleted {
                stats.metadata_deleted += 1;
            }
            if event_deleted {
                stats.archived_events_deleted += 1;
            }
            if archive_deleted {
                stats.archive_files_deleted += 1;
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
                    owner_pubkey: None,
                    git_archive: None,
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

    #[tokio::test]
    async fn eligible_recovery_records_filters_by_scope_and_retention() {
        let store = HoldingStore::in_memory();
        let owner = Keys::generate();
        let owner_hex = owner.public_key().to_hex();
        let other_owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "repo-a";
        let now = Timestamp::from_secs(1_000);

        let in_scope_event = test_event("in-scope", Timestamp::from_secs(900));
        store
            .archive_event(
                &in_scope_event,
                &HoldingMetadata {
                    deleted_at: Timestamp::from_secs(980),
                    source: DeletionSource::Nip09,
                    coordinate: Some(format!("30617:{}:{}", owner_hex, identifier)),
                    identifier: Some(identifier.to_string()),
                    owner_pubkey: Some(owner_hex.clone()),
                    git_archive: None,
                },
            )
            .await
            .expect("archive in-scope event");

        let wrong_owner_event = test_event("wrong-owner", Timestamp::from_secs(900));
        store
            .archive_event(
                &wrong_owner_event,
                &HoldingMetadata {
                    deleted_at: Timestamp::from_secs(980),
                    source: DeletionSource::Nip09,
                    coordinate: Some(format!("30617:{}:{}", other_owner_hex, identifier)),
                    identifier: Some(identifier.to_string()),
                    owner_pubkey: Some(other_owner_hex),
                    git_archive: None,
                },
            )
            .await
            .expect("archive wrong-owner event");

        let expired_event = test_event("expired", Timestamp::from_secs(900));
        store
            .archive_event(
                &expired_event,
                &HoldingMetadata {
                    deleted_at: Timestamp::from_secs(100),
                    source: DeletionSource::Nip09,
                    coordinate: Some(format!("30617:{}:{}", owner_hex, identifier)),
                    identifier: Some(identifier.to_string()),
                    owner_pubkey: Some(owner_hex.clone()),
                    git_archive: None,
                },
            )
            .await
            .expect("archive expired event");

        let records = store
            .eligible_recovery_records(&owner_hex, identifier, now, Duration::from_secs(50))
            .await;

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].archived_event_id, Some(in_scope_event.id));
    }

    #[tokio::test]
    async fn delete_recovery_record_is_idempotent_for_missing_payload() {
        let store = HoldingStore::in_memory();
        let event = test_event("recover", Timestamp::from_secs(10));
        store
            .archive_event(
                &event,
                &HoldingMetadata {
                    deleted_at: Timestamp::from_secs(11),
                    source: DeletionSource::Nip09,
                    coordinate: Some("30617:owner:repo".to_string()),
                    identifier: Some("repo".to_string()),
                    owner_pubkey: Some("owner".to_string()),
                    git_archive: None,
                },
            )
            .await
            .expect("archive event");

        let records = store
            .eligible_recovery_records(
                "owner",
                "repo",
                Timestamp::from_secs(20),
                Duration::from_secs(100),
            )
            .await;
        assert_eq!(records.len(), 1);

        // Remove payload directly to simulate stale metadata.
        store
            .db
            .delete(Filter::new().ids(vec![event.id]))
            .await
            .expect("delete payload directly");

        let first = store
            .delete_recovery_record(&records[0])
            .await
            .expect("delete stale recovery record");
        assert_eq!(first, (true, false));

        let second = store
            .delete_recovery_record(&records[0])
            .await
            .expect("delete stale recovery record again");
        assert_eq!(second, (false, false));
    }
}
