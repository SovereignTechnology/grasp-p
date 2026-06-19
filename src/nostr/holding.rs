//! Holding database for deleted events.
//!
//! Phase 2 foundation:
//! - copy/move deleted events out of the main DB into a dedicated holding DB,
//! - persist minimal per-event metadata for later retention/recovery phases.

use std::hash::{Hash, Hasher};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{collections::BTreeSet, io::ErrorKind};

use dashmap::DashMap;
use nostr_lmdb::NostrLmdb;
use nostr_memory::MemoryDatabase;
use nostr_relay_builder::prelude::{
    Alphabet, Event, EventBuilder, EventId, Filter, FinalizeEvent, Keys, Kind, NostrDatabase,
    SingleLetterTag, Tag, Timestamp,
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock as AsyncRwLock};

/// Directory name (under `relay_data_path`) for the LMDB holding database.
pub const HOLDING_DIR: &str = "holding";

/// Internal metadata event kind stored alongside archived events.
pub const HOLDING_METADATA_KIND: u16 = 9905;
pub const HOLDING_SOURCE_TAG: &str = "holding-source";
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
    Whitelist,
}

impl DeletionSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nip09 => "nip09",
            Self::Blacklist => "blacklist",
            Self::Whitelist => "whitelist",
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
    /// Shared per-repository lifecycle read/write locks.
    ///
    /// Lock ordering invariant for deletion/recovery/cleanup paths: acquire all
    /// required `(owner_pubkey_hex, identifier)` lifecycle locks first (sorted
    /// lexicographically), then touch main DB / tombstones / holding DB /
    /// repository filesystem / archive filesystem. Never acquire a lifecycle
    /// lock while holding a lower-level lock or a purgatory map entry reference.
    /// A matching lock file under `.lifecycle-locks/` extends the invariant to
    /// short-lived CLI write operations such as `holding-eject`, which run in a
    /// separate process and cannot share this in-memory map. Read-side Git Smart
    /// HTTP operations share the in-memory read lock only, while write-side
    /// operations also take the lock file.
    lifecycle_locks: Arc<DashMap<RecoveryScope, Arc<AsyncRwLock<()>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredMetadataRecord {
    pub metadata_event_id: EventId,
    pub archived_event_id: Option<EventId>,
    pub archive_relative_path: Option<String>,
    pub recovery_scope: Option<RecoveryScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMetadataRecord {
    pub metadata_event_id: EventId,
    pub archived_event_id: Option<EventId>,
    pub archive_relative_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct RecoveryScope {
    pub owner_pubkey_hex: String,
    pub identifier: String,
}

pub struct LifecycleReadGuard {
    _memory_guard: OwnedRwLockReadGuard<()>,
}

pub struct LifecycleWriteGuard {
    _memory_guard: OwnedRwLockWriteGuard<()>,
    lock_path: Option<PathBuf>,
}

impl Drop for LifecycleWriteGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.lock_path {
            if let Err(e) = std::fs::remove_file(path) {
                if e.kind() != ErrorKind::NotFound {
                    tracing::warn!(path = %path.display(), error = %e, "Failed to remove lifecycle lock file");
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CleanupStats {
    pub metadata_examined: usize,
    pub expired_records: usize,
    pub metadata_deleted: usize,
    pub archived_events_deleted: usize,
    pub archive_files_deleted: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ManualEjectionStats {
    pub records_matched: usize,
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
            lifecycle_locks: Arc::new(DashMap::new()),
        })
    }

    pub fn in_memory() -> Self {
        Self {
            db: Arc::new(MemoryDatabase::unbounded()),
            metadata_signer: Keys::generate(),
            archive_root: None,
            lifecycle_locks: Arc::new(DashMap::new()),
        }
    }

    pub async fn read_recovery_scope(
        &self,
        owner_pubkey_hex: &str,
        identifier: &str,
    ) -> LifecycleReadGuard {
        let scope = RecoveryScope {
            owner_pubkey_hex: owner_pubkey_hex.to_string(),
            identifier: identifier.to_string(),
        };
        let lock = self
            .lifecycle_locks
            .entry(scope)
            .or_insert_with(|| Arc::new(AsyncRwLock::new(())))
            .value()
            .clone();
        LifecycleReadGuard {
            _memory_guard: lock.read_owned().await,
        }
    }

    pub async fn write_recovery_scope(
        &self,
        owner_pubkey_hex: &str,
        identifier: &str,
    ) -> LifecycleWriteGuard {
        self.write_recovery_scopes(vec![RecoveryScope {
            owner_pubkey_hex: owner_pubkey_hex.to_string(),
            identifier: identifier.to_string(),
        }])
        .await
        .pop()
        .expect("single lifecycle lock requested")
    }

    pub async fn write_recovery_scopes(
        &self,
        scopes: impl IntoIterator<Item = RecoveryScope>,
    ) -> Vec<LifecycleWriteGuard> {
        let mut scopes: Vec<_> = scopes.into_iter().collect();
        scopes.sort();
        scopes.dedup();

        let mut guards = Vec::with_capacity(scopes.len());
        for scope in scopes {
            let lock = self
                .lifecycle_locks
                .entry(scope.clone())
                .or_insert_with(|| Arc::new(AsyncRwLock::new(())))
                .value()
                .clone();
            let memory_guard = lock.write_owned().await;
            let lock_path = self.acquire_scope_file_lock(&scope).await;
            guards.push(LifecycleWriteGuard {
                _memory_guard: memory_guard,
                lock_path,
            });
        }
        guards
    }

    async fn acquire_scope_file_lock(&self, scope: &RecoveryScope) -> Option<PathBuf> {
        let root = self.archive_root.as_ref()?;
        let lock_dir = root
            .parent()
            .map(|parent| parent.join(".lifecycle-locks"))
            .unwrap_or_else(|| root.join(".lifecycle-locks"));
        if let Err(e) = std::fs::create_dir_all(&lock_dir) {
            tracing::warn!(path = %lock_dir.display(), error = %e, "Failed to create lifecycle lock directory");
            return None;
        }

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        scope.hash(&mut hasher);
        let lock_path = lock_dir.join(format!("{:016x}.lock", hasher.finish()));

        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => return Some(lock_path),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(e) => {
                    tracing::warn!(
                        owner = %scope.owner_pubkey_hex,
                        identifier = %scope.identifier,
                        path = %lock_path.display(),
                        error = %e,
                        "Failed to acquire lifecycle lock file; continuing with in-process lock only"
                    );
                    return None;
                }
            }
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
            Tag::custom(
                HOLDING_SOURCE_TAG,
                vec![metadata.source.as_str().to_string()],
            ),
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

    fn parse_holding_source(metadata_event: &Event) -> Option<DeletionSource> {
        metadata_event.tags.iter().find_map(|tag| {
            let v = tag.as_slice();
            if v.len() < 2 || v[0] != HOLDING_SOURCE_TAG {
                return None;
            }

            match v[1].as_str() {
                "nip09" => Some(DeletionSource::Nip09),
                "blacklist" => Some(DeletionSource::Blacklist),
                "whitelist" => Some(DeletionSource::Whitelist),
                _ => None,
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

    fn parse_scope_from_coordinate(metadata_event: &Event) -> Option<RecoveryScope> {
        let coordinate = Self::parse_coordinate(metadata_event)?;
        let mut parts = coordinate.splitn(3, ':');
        let kind = parts.next()?;
        let owner = parts.next()?;
        let identifier = parts.next()?;

        if kind != "30617" || owner.is_empty() || identifier.is_empty() {
            return None;
        }

        Some(RecoveryScope {
            owner_pubkey_hex: owner.to_string(),
            identifier: identifier.to_string(),
        })
    }

    fn parse_recovery_scope(metadata_event: &Event) -> Option<RecoveryScope> {
        if let Some(scope) = Self::parse_scope_from_coordinate(metadata_event) {
            return Some(scope);
        }

        let owner_pubkey_hex = Self::parse_owner_pubkey(metadata_event)?;
        let identifier = Self::parse_identifier(metadata_event)?;
        if owner_pubkey_hex.is_empty() || identifier.is_empty() {
            return None;
        }

        Some(RecoveryScope {
            owner_pubkey_hex,
            identifier,
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

    /// Find distinct owner+identifier scopes eligible for recovery from a
    /// specific deletion source.
    ///
    /// Eligibility requires all of:
    /// - metadata has the requested `holding-source`,
    /// - metadata has a parseable `holding-deleted-at`,
    /// - metadata is within `retention` from `now`,
    /// - metadata yields a parseable owner+identifier recovery scope.
    pub async fn eligible_recovery_scopes_by_source(
        &self,
        source: DeletionSource,
        now: Timestamp,
        retention: Duration,
    ) -> Vec<RecoveryScope> {
        let cutoff = now.as_secs().saturating_sub(retention.as_secs());
        let filter = Filter::new().kind(Kind::from(HOLDING_METADATA_KIND));

        let metadata_events = match self.db.query(filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(error = %e, "Holding recovery failed to query metadata scopes");
                return Vec::new();
            }
        };

        let mut scopes = BTreeSet::new();
        for metadata_event in metadata_events {
            if Self::parse_holding_source(&metadata_event) != Some(source) {
                continue;
            }

            let Some(deleted_at) = Self::parse_holding_deleted_at(&metadata_event) else {
                continue;
            };
            if deleted_at.as_secs() <= cutoff {
                continue;
            }

            let Some(scope) = Self::parse_recovery_scope(&metadata_event) else {
                continue;
            };

            scopes.insert(scope);
        }

        scopes.into_iter().collect()
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
                        recovery_scope: Self::parse_recovery_scope(&metadata_event),
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
            let _scope_guard = match &record.recovery_scope {
                Some(scope) => Some(
                    self.write_recovery_scope(&scope.owner_pubkey_hex, &scope.identifier)
                        .await,
                ),
                None => None,
            };
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

        crate::metrics::record_holding_cleanup_run(
            stats.metadata_deleted,
            stats.archived_events_deleted,
            stats.archive_files_deleted,
        );

        Ok(stats)
    }

    /// Permanently eject all holding/archive artifacts for one
    /// `(owner_pubkey_hex, identifier)` scope.
    ///
    /// This is an idempotent operator operation intended for manual moderation.
    /// Missing metadata/payload/archive files are tolerated.
    pub async fn manual_eject_repository(
        &self,
        owner_pubkey_hex: &str,
        identifier: &str,
    ) -> anyhow::Result<ManualEjectionStats> {
        let _scope_guard = self
            .write_recovery_scope(owner_pubkey_hex, identifier)
            .await;
        let filter = Filter::new().kind(Kind::from(HOLDING_METADATA_KIND));
        let metadata_events = self.db.query(filter).await.map_err(|e| {
            anyhow::anyhow!("Failed to query holding metadata for manual ejection: {e}")
        })?;

        let mut records = Vec::new();
        let mut archive_paths = BTreeSet::new();
        for metadata_event in metadata_events {
            if !Self::metadata_matches_recovery_scope(&metadata_event, owner_pubkey_hex, identifier)
            {
                continue;
            }

            let archive_relative_path = Self::parse_archive_relative_path(&metadata_event);
            if let Some(path) = &archive_relative_path {
                archive_paths.insert(path.clone());
            }

            records.push(RecoveryMetadataRecord {
                metadata_event_id: metadata_event.id,
                archived_event_id: Self::parse_archived_event_id(&metadata_event),
                archive_relative_path,
            });
        }

        let mut stats = ManualEjectionStats {
            records_matched: records.len(),
            ..ManualEjectionStats::default()
        };

        for record in &records {
            let (metadata_deleted, payload_deleted) = self.delete_recovery_record(record).await?;
            if metadata_deleted {
                stats.metadata_deleted += 1;
            }
            if payload_deleted {
                stats.archived_events_deleted += 1;
            }
        }

        for relative_path in archive_paths {
            let Some(absolute_path) = self.resolve_archive_path(&relative_path) else {
                tracing::warn!(
                    owner = %owner_pubkey_hex,
                    identifier = %identifier,
                    path = %relative_path,
                    "Manual ejection skipped invalid archive path"
                );
                continue;
            };

            match std::fs::remove_file(&absolute_path) {
                Ok(()) => {
                    stats.archive_files_deleted += 1;
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!(
                        owner = %owner_pubkey_hex,
                        identifier = %identifier,
                        path = %absolute_path.display(),
                        error = %e,
                        "Manual ejection failed deleting archive file"
                    );
                }
            }
        }

        tracing::info!(
            owner = %owner_pubkey_hex,
            identifier = %identifier,
            records_matched = stats.records_matched,
            metadata_deleted = stats.metadata_deleted,
            payload_deleted = stats.archived_events_deleted,
            archive_files_deleted = stats.archive_files_deleted,
            "Manual holding ejection completed"
        );

        crate::metrics::record_manual_ejection(
            stats.metadata_deleted,
            stats.archived_events_deleted,
            stats.archive_files_deleted,
        );

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
    async fn lifecycle_read_locks_can_be_held_concurrently() {
        let store = HoldingStore::in_memory();
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "popular-repo";

        let first_guard = store.read_recovery_scope(&owner_hex, identifier).await;
        let second_guard = tokio::time::timeout(
            Duration::from_millis(100),
            store.read_recovery_scope(&owner_hex, identifier),
        )
        .await
        .expect("second read lock should not wait behind first read lock");

        drop(second_guard);
        drop(first_guard);
    }

    #[tokio::test]
    async fn lifecycle_push_and_fetch_read_locks_can_overlap() {
        let store = HoldingStore::in_memory();
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "push-fetch-overlap";

        let push_guard = store.read_recovery_scope(&owner_hex, identifier).await;
        let fetch_guard = tokio::time::timeout(
            Duration::from_millis(100),
            store.read_recovery_scope(&owner_hex, identifier),
        )
        .await
        .expect("fetch lifecycle read lock should not wait behind push lifecycle read lock");

        drop(fetch_guard);
        drop(push_guard);
    }

    #[tokio::test]
    async fn lifecycle_write_lock_waits_for_active_read_lock() {
        let store = HoldingStore::in_memory();
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "read-before-delete";

        let read_guard = store.read_recovery_scope(&owner_hex, identifier).await;
        let writer_store = store.clone();
        let writer_owner = owner_hex.clone();
        let writer_identifier = identifier.to_string();
        let (writer_acquired_tx, writer_acquired_rx) = tokio::sync::oneshot::channel();

        let writer = tokio::spawn(async move {
            let guard = writer_store
                .write_recovery_scope(&writer_owner, &writer_identifier)
                .await;
            let _ = writer_acquired_tx.send(());
            guard
        });

        tokio::time::timeout(Duration::from_millis(100), writer_acquired_rx)
            .await
            .expect_err("write lock should wait while read lock is active");

        drop(read_guard);
        let write_guard = tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("write lock should acquire after read lock drops")
            .expect("writer task should join");
        drop(write_guard);
    }

    #[tokio::test]
    async fn lifecycle_queued_write_blocks_new_read_lock() {
        let store = HoldingStore::in_memory();
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "delete-waits-fairly";

        let first_read_guard = store.read_recovery_scope(&owner_hex, identifier).await;

        let writer_store = store.clone();
        let writer_owner = owner_hex.clone();
        let writer_identifier = identifier.to_string();
        let (writer_started_tx, writer_started_rx) = tokio::sync::oneshot::channel();
        let (writer_acquired_tx, writer_acquired_rx) = tokio::sync::oneshot::channel();
        let (release_writer_tx, release_writer_rx) = tokio::sync::oneshot::channel();

        let writer = tokio::spawn(async move {
            let _ = writer_started_tx.send(());
            let guard = writer_store
                .write_recovery_scope(&writer_owner, &writer_identifier)
                .await;
            let _ = writer_acquired_tx.send(());
            let _ = release_writer_rx.await;
            drop(guard);
        });

        writer_started_rx
            .await
            .expect("writer task should start before second reader");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let reader_store = store.clone();
        let reader_owner = owner_hex.clone();
        let reader_identifier = identifier.to_string();
        let (second_read_acquired_tx, second_read_acquired_rx) = tokio::sync::oneshot::channel();
        let second_reader = tokio::spawn(async move {
            let guard = reader_store
                .read_recovery_scope(&reader_owner, &reader_identifier)
                .await;
            let _ = second_read_acquired_tx.send(());
            guard
        });

        tokio::time::timeout(Duration::from_millis(100), second_read_acquired_rx)
            .await
            .expect_err("new read lock should wait behind queued writer");

        drop(first_read_guard);
        tokio::time::timeout(Duration::from_secs(1), writer_acquired_rx)
            .await
            .expect("writer should acquire after active reader drops")
            .expect("writer should report acquisition");

        let _ = release_writer_tx.send(());
        writer.await.expect("writer task should join");
        let second_read_guard = tokio::time::timeout(Duration::from_secs(1), second_reader)
            .await
            .expect("second read should acquire after writer releases")
            .expect("second reader task should join");
        drop(second_read_guard);
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

    #[tokio::test]
    async fn cleanup_and_manual_eject_same_scope_are_idempotent_under_contention() {
        let store = HoldingStore::in_memory();
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "contended-repo";

        for i in 0..2 {
            let event = test_event(&format!("expired-{i}"), Timestamp::from_secs(10 + i));
            store
                .archive_event(
                    &event,
                    &HoldingMetadata {
                        deleted_at: Timestamp::from_secs(20),
                        source: DeletionSource::Nip09,
                        coordinate: Some(format!("30617:{}:{}", owner_hex, identifier)),
                        identifier: Some(identifier.to_string()),
                        owner_pubkey: Some(owner_hex.clone()),
                        git_archive: None,
                    },
                )
                .await
                .expect("archive event");
        }

        let cleanup_store = store.clone();
        let eject_store = store.clone();
        let cleanup = tokio::spawn(async move {
            cleanup_store
                .cleanup_expired(Timestamp::from_secs(10_000), Duration::from_secs(1))
                .await
                .expect("cleanup succeeds")
        });
        let eject = tokio::spawn({
            let owner_hex = owner_hex.clone();
            let identifier = identifier.to_string();
            async move {
                eject_store
                    .manual_eject_repository(&owner_hex, &identifier)
                    .await
                    .expect("manual eject succeeds")
            }
        });

        let cleanup_stats = cleanup.await.expect("cleanup task joins");
        let eject_stats = eject.await.expect("eject task joins");

        assert_eq!(
            cleanup_stats.metadata_deleted + eject_stats.metadata_deleted,
            2
        );
        assert!(store
            .eligible_recovery_records(
                &owner_hex,
                identifier,
                Timestamp::from_secs(10_000),
                Duration::from_secs(10_000),
            )
            .await
            .is_empty());
    }
}
