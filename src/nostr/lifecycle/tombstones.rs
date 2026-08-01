//! Persistent tombstone store for NIP-09 (deletion) and NIP-62 (request to vanish).
//!
//! ## Why this exists
//!
//! Up to and including the move to rust-nostr 0.45, ngit-grasp relied on the
//! LMDB backend's *automatic* NIP-09 / NIP-62 processing
//! (`NostrLmdb` defaults `process_nip09 = true`, `process_nip62 = true`).
//! That backend behaviour did two things for us:
//!
//! 1. **Removed deleted/vanished events from the main DB** when a kind-5 or a
//!    valid kind-62 arrived.
//! 2. **Blocked re-submission** of a genuinely-deleted event (or an event from a
//!    vanished pubkey) — the relay-builder's `check_id` gate consulted the
//!    backend's internal `deleted-ids` / `deleted-coordinates` /
//!    `vanished-public-keys` LMDB tables and replied "this event is deleted".
//!
//! We disable the backend's automatic processing
//! (`process_nip09(false)`, `process_nip62(false)`) and implement NIP-09 /
//! NIP-62 ourselves, so we can apply our own customisations in the future. The
//! backend's internal tombstone tables are not part of the public
//! `NostrDatabase` API, so we cannot read or write them. Instead we keep our own
//! persistent record here.
//!
//! ## How it works
//!
//! Rather than inventing a bespoke key-value schema, we persist the **deletion
//! and vanish request events themselves** (kind 5 and kind 62), plus private
//! relay-generated lifecycle metadata, in a dedicated nostr database. Deleted /
//! vanished state is derived only from the original request payloads:
//!
//! - a kind-5 with an `e` tag → that event id is deleted
//! - a kind-5 with an `a` tag → that coordinate is deleted up to the kind-5's
//!   `created_at`
//! - a kind-62 by pubkey `P` → pubkey `P` is vanished
//!
//! The store uses the same backend family as the main relay database (a separate
//! [`NostrLmdb`] file for the LMDB backend, or [`MemoryDatabase`] for the memory
//! backend) so it survives restarts exactly like the main database did before.
//!
//! Author validation (only the event's author may delete it; only a pubkey may
//! request its own vanish) is enforced by the caller *before* recording, so any
//! request stored here is already authoritative.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use futures_util::future::join_all;
use tokio::sync::{Mutex, MutexGuard};

use nostr_lmdb::NostrLmdb;
use nostr_memory::MemoryDatabase;
use nostr_sdk::prelude::{
    Alphabet, Event, EventBuilder, EventId, Filter, FinalizeEvent, Keys, Kind, NostrDatabase,
    PublicKey, SingleLetterTag, Tag, Timestamp,
};

/// Directory name (under `relay_data_path`) for the LMDB tombstone database.
const TOMBSTONE_DIR: &str = "tombstones";

/// Internal metadata event kind stored alongside deletion-request payloads.
pub const TOMBSTONE_REQUEST_METADATA_KIND: u16 = 9907;
/// Tag containing the relay-observed first receipt time for a request.
pub const TOMBSTONE_FIRST_SEEN_AT_TAG: &str = "tombstone-first-seen-at";
/// Tag containing the most recent successful use time for a request.
pub const TOMBSTONE_LAST_USED_AT_TAG: &str = "tombstone-last-used-at";
/// Tag containing the relay's deletion-request classification.
pub const TOMBSTONE_REQUEST_CLASSIFICATION_TAG: &str = "tombstone-request-classification";

/// Bound the number of request IDs in a metadata `#e` query so a target with
/// many deletion requests cannot create an unbounded database filter.
const METADATA_REQUEST_ID_QUERY_CHUNK_SIZE: usize = 256;
/// Number of request lifecycles queued together during the one-time migration
/// from the main relay database. `nostr-lmdb` drains concurrent writes into a
/// single transaction, avoiding one fsync-heavy transaction per event.
const STARTUP_MIGRATION_CHUNK_SIZE: usize = 512;

/// Relay policy classification retained with a deletion request's lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClassification {
    LocallyActionable,
    NonTargetingNip62,
    Disrespector,
}

impl RequestClassification {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocallyActionable => "locally-actionable",
            Self::NonTargetingNip62 => "non-targeting-nip62",
            Self::Disrespector => "disrespector",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "locally-actionable" => Some(Self::LocallyActionable),
            "non-targeting-nip62" => Some(Self::NonTargetingNip62),
            "disrespector" => Some(Self::Disrespector),
            _ => None,
        }
    }
}

/// The canonical lifecycle state for one original kind-5 or kind-62 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLifecycleRecord {
    pub metadata_event_id: EventId,
    pub request: Event,
    pub first_seen_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub classification: RequestClassification,
}

/// Counts returned after permanently removing one request lifecycle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestLifecycleDeletionStats {
    pub payloads_deleted: usize,
    pub metadata_deleted: usize,
}

#[derive(Debug, Clone, Copy)]
struct ParsedMetadata {
    id: EventId,
    created_at: Timestamp,
    first_seen_at: Timestamp,
    last_used_at: Option<Timestamp>,
    classification: RequestClassification,
}

/// Persistent record of NIP-09 deletions and NIP-62 vanish requests.
///
/// Backed by its own nostr database so the deleted/vanished state survives
/// relay restarts. See the module docs for the rationale.
#[derive(Clone)]
pub struct Tombstones {
    db: Arc<dyn NostrDatabase>,
    metadata_signer: Keys,
    /// Serializes lifecycle metadata changes with Main-database transitions
    /// performed by `DeletionService`. This is intentionally one simple lock:
    /// request lifecycles are a small control plane and correctness matters more
    /// than parallel metadata writes.
    lifecycle_lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for Tombstones {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tombstones").finish_non_exhaustive()
    }
}

impl Tombstones {
    /// Open a persistent (LMDB) tombstone store under `relay_data_path`.
    ///
    /// The database lives at `<relay_data_path>/tombstones`. NIP-09 / NIP-62
    /// auto-processing is explicitly disabled on this database: requests and
    /// relay-private lifecycle metadata are interpreted explicitly by this store.
    pub async fn open_lmdb(relay_data_path: &Path) -> anyhow::Result<Self> {
        let path = relay_data_path.join(TOMBSTONE_DIR);
        std::fs::create_dir_all(&path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create tombstone directory {}: {}",
                path.display(),
                e
            )
        })?;

        let db = NostrLmdb::builder(&path)
            // We store deletion/vanish requests verbatim and interpret them
            // ourselves; the backend must not re-interpret them.
            .process_nip09(false)
            .process_nip62(false)
            .build()
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to open tombstone LMDB at {}: {}", path.display(), e)
            })?;

        Ok(Self {
            db: Arc::new(db),
            metadata_signer: Keys::generate(),
            lifecycle_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Create an in-memory tombstone store (used with the memory backend and in
    /// tests). Not persistent.
    pub fn in_memory() -> Self {
        Self {
            db: Arc::new(
                MemoryDatabase::builder()
                    .process_nip09(false)
                    .process_nip62(false)
                    .build(),
            ),
            metadata_signer: Keys::generate(),
            lifecycle_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Acquire the lifecycle transition lock. Callers that also transition the
    /// Main database must hold this across the Main operation and the matching
    /// metadata update/removal.
    pub(crate) async fn lock_lifecycle(&self) -> MutexGuard<'_, ()> {
        self.lifecycle_lock.lock().await
    }

    #[cfg(test)]
    pub(crate) async fn save_request_payload_without_metadata(
        &self,
        event: &Event,
    ) -> anyhow::Result<()> {
        self.db
            .save_event(event)
            .await
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("Failed to save test request payload: {error}"))
    }

    #[cfg(test)]
    pub(crate) async fn remove_request_payload_without_metadata(
        &self,
        request_id: EventId,
    ) -> anyhow::Result<()> {
        self.db
            .delete(Filter::new().ids(vec![request_id]))
            .await
            .map_err(|error| anyhow::anyhow!("Failed to remove test request payload: {error}"))
    }

    /// Persist a signed deletion/vanish request and relay-generated lifecycle
    /// metadata. Exact replays retain their original `first_seen_at`.
    pub async fn record_request(
        &self,
        event: &Event,
        first_seen_at: Timestamp,
        classification: RequestClassification,
    ) -> anyhow::Result<RequestLifecycleRecord> {
        let _guard = self.lock_lifecycle().await;
        self.record_request_locked(event, first_seen_at, classification)
            .await
    }

    pub(crate) async fn record_request_locked(
        &self,
        event: &Event,
        first_seen_at: Timestamp,
        classification: RequestClassification,
    ) -> anyhow::Result<RequestLifecycleRecord> {
        if !Self::is_request_kind(event.kind) {
            anyhow::bail!("Tombstone lifecycle accepts only kind-5 or kind-62 requests");
        }

        if let Some(record) = self.lifecycle_for_request_result(&event.id).await? {
            return Ok(record);
        }

        let payload_existed = self.request_payload(&event.id).await?.is_some();
        self.db.save_event(event).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to record deletion-request payload {}: {e}",
                event.id
            )
        })?;

        let metadata = self.build_metadata(event.id, first_seen_at, None, classification)?;
        if let Err(error) = self.db.save_event(&metadata).await {
            if !payload_existed {
                if let Err(rollback_error) = self.db.delete(Filter::new().ids(vec![event.id])).await
                {
                    tracing::error!(error = %rollback_error, request_id = %event.id, "Failed to roll back tombstone payload after metadata write failure");
                }
            }
            return Err(anyhow::anyhow!(
                "Failed to record lifecycle metadata for {}: {error}",
                event.id
            ));
        }

        Ok(RequestLifecycleRecord {
            metadata_event_id: metadata.id,
            request: event.clone(),
            first_seen_at,
            last_used_at: None,
            classification,
        })
    }

    /// Persist historical request lifecycles in write batches during startup.
    ///
    /// The caller has already enumerated canonical lifecycle metadata and only
    /// passes requests that lack a valid record. Startup remains unavailable
    /// until this completes, so a partial batch failure is safe to retry: a
    /// payload without metadata is not a valid lifecycle and will be included
    /// in the next migration pass.
    pub(crate) async fn record_requests_for_startup_migration(
        &self,
        requests: Vec<(Event, RequestClassification)>,
        first_seen_at: Timestamp,
    ) -> anyhow::Result<Vec<RequestLifecycleRecord>> {
        let _guard = self.lock_lifecycle().await;
        let mut records = Vec::with_capacity(requests.len());

        for chunk in requests.chunks(STARTUP_MIGRATION_CHUNK_SIZE) {
            let mut metadata = Vec::with_capacity(chunk.len());
            for (request, classification) in chunk {
                if !Self::is_request_kind(request.kind) {
                    anyhow::bail!("Tombstone lifecycle accepts only kind-5 or kind-62 requests");
                }
                metadata.push(self.build_metadata(
                    request.id,
                    first_seen_at,
                    None,
                    *classification,
                )?);
            }

            // Poll every save future together. The LMDB backend's ingester can
            // then drain these operations into a small number of transactions
            // instead of committing each payload and metadata event separately.
            let writes = chunk
                .iter()
                .map(|(request, _)| request)
                .chain(metadata.iter())
                .map(|event| self.db.save_event(event));
            for result in join_all(writes).await {
                result.map_err(|error| {
                    anyhow::anyhow!("Failed to batch-migrate deletion-request lifecycle: {error}")
                })?;
            }

            records.extend(chunk.iter().zip(metadata).map(
                |((request, classification), metadata)| RequestLifecycleRecord {
                    metadata_event_id: metadata.id,
                    request: request.clone(),
                    first_seen_at,
                    last_used_at: None,
                    classification: *classification,
                },
            ));
        }

        Ok(records)
    }

    /// Return the canonical lifecycle record, if both a valid payload and valid
    /// metadata exist. Multiple metadata rows are compacted lazily by updates.
    ///
    /// Canonical selection is deterministic: valid rows are required; the record
    /// preserves the earliest `first_seen_at` and greatest `last_used_at` across
    /// them, while its metadata ID is selected by greatest `last_used_at`, then
    /// earliest `first_seen_at`, newest metadata creation time, then lowest ID.
    /// Database failures are returned rather than treated as absent lifecycle
    /// metadata because callers use this result for admission and cleanup.
    pub async fn lifecycle_for_request_result(
        &self,
        request_id: &EventId,
    ) -> anyhow::Result<Option<RequestLifecycleRecord>> {
        let request = match self.request_payload(request_id).await? {
            Some(event) if Self::is_request_kind(event.kind) => event,
            Some(event) => {
                tracing::warn!(request_id = %request_id, kind = event.kind.as_u16(), "Tombstone lifecycle payload has invalid kind");
                return Ok(None);
            }
            None => {
                let orphaned_metadata = self.metadata_events_for_request_result(request_id).await?;
                if !orphaned_metadata.is_empty() {
                    tracing::warn!(
                        request_id = %request_id,
                        metadata_count = orphaned_metadata.len(),
                        "Ignoring orphan tombstone lifecycle metadata without a request payload"
                    );
                }
                return Ok(None);
            }
        };

        let metadata = self.metadata_events_for_request_result(request_id).await?;
        Ok(self.lifecycle_record_from_metadata(request, metadata))
    }

    /// Set `last_used_at`, never moving it backwards, then compact superseded
    /// metadata only after the replacement is durable.
    pub async fn mark_request_used(
        &self,
        request_id: &EventId,
        used_at: Timestamp,
    ) -> anyhow::Result<Option<RequestLifecycleRecord>> {
        let _guard = self.lock_lifecycle().await;
        self.mark_request_used_locked(request_id, used_at).await
    }

    pub(crate) async fn mark_request_used_locked(
        &self,
        request_id: &EventId,
        used_at: Timestamp,
    ) -> anyhow::Result<Option<RequestLifecycleRecord>> {
        let Some(existing) = self.lifecycle_for_request_result(request_id).await? else {
            return Ok(None);
        };
        let last_used_at = existing.last_used_at.max(Some(used_at));
        if last_used_at == existing.last_used_at {
            return Ok(Some(existing));
        }

        self.replace_lifecycle_metadata(
            request_id,
            existing.first_seen_at,
            last_used_at,
            existing.classification,
        )
        .await
    }

    /// Update a request's policy classification without changing its lifecycle
    /// timestamps. The replacement is durable before stale rows are compacted,
    /// so an interrupted update always leaves a readable lifecycle record.
    pub async fn reclassify_request(
        &self,
        request_id: &EventId,
        classification: RequestClassification,
    ) -> anyhow::Result<Option<RequestLifecycleRecord>> {
        let _guard = self.lock_lifecycle().await;
        self.reclassify_request_locked(request_id, classification)
            .await
    }

    pub(crate) async fn reclassify_request_locked(
        &self,
        request_id: &EventId,
        classification: RequestClassification,
    ) -> anyhow::Result<Option<RequestLifecycleRecord>> {
        let Some(existing) = self.lifecycle_for_request_result(request_id).await? else {
            return Ok(None);
        };
        if existing.classification == classification {
            return Ok(Some(existing));
        }
        self.replace_lifecycle_metadata(
            request_id,
            existing.first_seen_at,
            existing.last_used_at,
            classification,
        )
        .await
    }

    /// List canonical request lifecycles for migration and retention work.
    /// Private metadata is not returned, and database failures are propagated.
    pub async fn lifecycle_records_result(&self) -> anyhow::Result<Vec<RequestLifecycleRecord>> {
        let requests = self.request_payloads().await?;
        self.lifecycle_records_for_payloads_result(requests).await
    }

    /// Resolve lifecycle records for an already-enumerated payload set. This
    /// avoids reading payloads twice during startup reconciliation.
    pub(crate) async fn lifecycle_records_for_payloads_result(
        &self,
        requests: Vec<Event>,
    ) -> anyhow::Result<Vec<RequestLifecycleRecord>> {
        // Do not resolve metadata one request at a time. In particular, startup
        // calls this over the full retained request set, where per-request
        // lookups would turn an otherwise linear migration into thousands of
        // database reads. The metadata kind is small and indexed by LMDB, so
        // load it once and group its standard `e` references in memory.
        let metadata = self
            .db
            .query(Filter::new().kind(Kind::from(TOMBSTONE_REQUEST_METADATA_KIND)))
            .await
            .map_err(|error| anyhow::anyhow!("Failed to enumerate tombstone metadata: {error}"))?;
        let mut metadata_by_request: HashMap<EventId, Vec<Event>> = HashMap::new();
        for event in metadata {
            let Some(request_id) =
                Self::tag_value(&event, "e").and_then(|value| EventId::from_hex(value).ok())
            else {
                continue;
            };
            metadata_by_request
                .entry(request_id)
                .or_default()
                .push(event);
        }
        let mut records = Vec::new();
        for request in requests {
            let request_id = request.id;
            if let Some(record) = self.lifecycle_record_from_metadata(
                request,
                metadata_by_request.remove(&request_id).unwrap_or_default(),
            ) {
                records.push(record);
            }
        }
        records.sort_by_key(|record| record.request.id.to_hex());
        Ok(records)
    }

    /// Resolve lifecycle records for already-matched live-admission payloads.
    ///
    /// Unlike startup enumeration, this must never scan every metadata row.
    /// Query relay-private metadata through its indexed `#e` request reference,
    /// batching IDs to keep a heavily-targeted event's query bounded.
    async fn lifecycle_records_for_matched_payloads_result(
        &self,
        requests: Vec<Event>,
    ) -> anyhow::Result<Vec<RequestLifecycleRecord>> {
        let mut records = Vec::new();
        for request_batch in requests.chunks(METADATA_REQUEST_ID_QUERY_CHUNK_SIZE) {
            let request_ids: Vec<_> = request_batch.iter().map(|request| request.id).collect();
            let metadata = self
                .db
                .query(
                    Filter::new()
                        .kind(Kind::from(TOMBSTONE_REQUEST_METADATA_KIND))
                        .events(request_ids),
                )
                .await
                .map_err(|error| {
                    anyhow::anyhow!("Failed to query matched tombstone lifecycle metadata: {error}")
                })?;
            let mut metadata_by_request: HashMap<EventId, Vec<Event>> = HashMap::new();
            for event in metadata {
                let Some(request_id) =
                    Self::tag_value(&event, "e").and_then(|value| EventId::from_hex(value).ok())
                else {
                    continue;
                };
                metadata_by_request
                    .entry(request_id)
                    .or_default()
                    .push(event);
            }
            for request in request_batch {
                let request_id = request.id;
                if let Some(record) = self.lifecycle_record_from_metadata(
                    request.clone(),
                    metadata_by_request.remove(&request_id).unwrap_or_default(),
                ) {
                    records.push(record);
                }
            }
        }
        records.sort_by_key(|record| record.request.id.to_hex());
        Ok(records)
    }

    /// Remove one payload and every metadata row linked to it. This is
    /// idempotent when either side was already removed. The caller must hold
    /// `lock_lifecycle` and has already completed any required Main removal.
    pub(crate) async fn permanently_delete_request_locked(
        &self,
        request_id: &EventId,
    ) -> anyhow::Result<RequestLifecycleDeletionStats> {
        let payloads_deleted = usize::from(self.request_payload(request_id).await?.is_some());
        let metadata = self.metadata_events_for_request_result(request_id).await?;
        if payloads_deleted > 0 {
            self.db
                .delete(Filter::new().ids(vec![*request_id]))
                .await
                .map_err(|error| {
                    anyhow::anyhow!("Failed to remove tombstone request {request_id}: {error}")
                })?;
        }
        let metadata_deleted = metadata.len();
        if metadata_deleted > 0 {
            self.db
                .delete(Filter::new().ids(metadata.into_iter().map(|event| event.id)))
                .await
                .map_err(|error| {
                    anyhow::anyhow!("Failed to remove lifecycle metadata for {request_id}: {error}")
                })?;
        }
        Ok(RequestLifecycleDeletionStats {
            payloads_deleted,
            metadata_deleted,
        })
    }

    /// Remove metadata whose unambiguous `e` link has no retained request.
    /// This is deliberately separate from canonical enumeration: malformed
    /// metadata remains invisible to queries but is not guessed at.
    pub async fn remove_orphan_metadata(&self) -> anyhow::Result<usize> {
        let _guard = self.lock_lifecycle().await;
        let metadata = self
            .db
            .query(Filter::new().kind(Kind::from(TOMBSTONE_REQUEST_METADATA_KIND)))
            .await
            .map_err(|error| anyhow::anyhow!("Failed to enumerate tombstone metadata: {error}"))?;
        let mut stale = Vec::new();
        for event in metadata {
            let Some(request_id) =
                Self::tag_value(&event, "e").and_then(|value| EventId::from_hex(value).ok())
            else {
                continue;
            };
            if self.request_payload(&request_id).await?.is_none() {
                stale.push(event.id);
            }
        }
        let removed = stale.len();
        if removed > 0 {
            self.db
                .delete(Filter::new().ids(stale))
                .await
                .map_err(|error| {
                    anyhow::anyhow!("Failed to remove orphan lifecycle metadata: {error}")
                })?;
        }
        Ok(removed)
    }

    /// List the original kind-5 and kind-62 payloads retained by this store.
    /// This deliberately does not require lifecycle metadata, and never exposes
    /// relay-private metadata events to callers.
    pub async fn request_payloads(&self) -> anyhow::Result<Vec<Event>> {
        let mut requests = Vec::new();
        for kind in [Kind::EventDeletion, Kind::RequestToVanish] {
            let events = self
                .db
                .query(Filter::new().kind(kind))
                .await
                .map_err(|error| {
                    anyhow::anyhow!("Failed to list tombstone request payloads: {error}")
                })?;
            requests.extend(events);
        }
        requests.sort_by_key(|event| event.id.to_hex());
        requests.dedup_by_key(|event| event.id);
        Ok(requests)
    }

    fn is_request_kind(kind: Kind) -> bool {
        kind == Kind::EventDeletion || kind == Kind::RequestToVanish
    }

    async fn replace_lifecycle_metadata(
        &self,
        request_id: &EventId,
        first_seen_at: Timestamp,
        last_used_at: Option<Timestamp>,
        classification: RequestClassification,
    ) -> anyhow::Result<Option<RequestLifecycleRecord>> {
        // Metadata timestamps only order relay-private replacement rows. Ensure
        // this row is newer even when multiple updates happen in one wall-clock
        // second, otherwise canonical selection could retain the old class.
        let newest_existing = self
            .metadata_events_for_request_result(request_id)
            .await?
            .iter()
            .map(|event| event.created_at)
            .max();
        let replacement_created_at = match newest_existing {
            Some(existing) if existing >= Timestamp::now() => Timestamp::from_secs(
                existing
                    .as_secs()
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("lifecycle metadata timestamp overflow"))?,
            ),
            _ => Timestamp::now(),
        };
        let replacement = self.build_metadata_at(
            *request_id,
            first_seen_at,
            last_used_at,
            classification,
            replacement_created_at,
        )?;
        self.db.save_event(&replacement).await.map_err(|e| {
            anyhow::anyhow!("Failed to update lifecycle metadata for {request_id}: {e}")
        })?;
        let updated = self
            .lifecycle_for_request_result(request_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("Updated lifecycle metadata for {request_id} was not readable")
            })?;
        let stale_ids: Vec<_> = self
            .metadata_events_for_request_result(request_id)
            .await?
            .into_iter()
            .map(|event| event.id)
            .filter(|id| *id != updated.metadata_event_id)
            .collect();
        if !stale_ids.is_empty() {
            self.db
                .delete(Filter::new().ids(stale_ids))
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to compact lifecycle metadata for {request_id}: {e}")
                })?;
        }
        self.lifecycle_for_request_result(request_id).await
    }

    async fn request_payload(&self, request_id: &EventId) -> anyhow::Result<Option<Event>> {
        // `event_by_id` uses the database's primary event-ID index. Never scan
        // every kind-5 and kind-62 payload to find one request: this is called
        // in admission, cleanup, and startup reconciliation.
        self.db.event_by_id(request_id).await.map_err(|error| {
            anyhow::anyhow!("Failed to read tombstone request {request_id}: {error}")
        })
    }

    fn build_metadata(
        &self,
        request_id: EventId,
        first_seen_at: Timestamp,
        last_used_at: Option<Timestamp>,
        classification: RequestClassification,
    ) -> anyhow::Result<Event> {
        self.build_metadata_at(
            request_id,
            first_seen_at,
            last_used_at,
            classification,
            Timestamp::now(),
        )
    }

    fn build_metadata_at(
        &self,
        request_id: EventId,
        first_seen_at: Timestamp,
        last_used_at: Option<Timestamp>,
        classification: RequestClassification,
        created_at: Timestamp,
    ) -> anyhow::Result<Event> {
        let mut tags = vec![
            Tag::event(request_id),
            Tag::custom(
                TOMBSTONE_FIRST_SEEN_AT_TAG,
                vec![first_seen_at.as_secs().to_string()],
            ),
            Tag::custom(
                TOMBSTONE_REQUEST_CLASSIFICATION_TAG,
                vec![classification.as_str().to_string()],
            ),
        ];
        if let Some(last_used_at) = last_used_at {
            tags.push(Tag::custom(
                TOMBSTONE_LAST_USED_AT_TAG,
                vec![last_used_at.as_secs().to_string()],
            ));
        }
        EventBuilder::new(Kind::from(TOMBSTONE_REQUEST_METADATA_KIND), "")
            .tags(tags)
            .custom_created_at(created_at)
            .finalize(&self.metadata_signer)
            .map_err(|e| anyhow::anyhow!("Failed to build tombstone lifecycle metadata: {e}"))
    }

    #[cfg(test)]
    async fn metadata_events_for_request(&self, request_id: &EventId) -> Vec<Event> {
        match self.metadata_events_for_request_result(request_id).await {
            Ok(events) => events,
            Err(error) => {
                tracing::error!(error = %error, request_id = %request_id, "Failed to query tombstone lifecycle metadata");
                Vec::new()
            }
        }
    }

    async fn metadata_events_for_request_result(
        &self,
        request_id: &EventId,
    ) -> anyhow::Result<Vec<Event>> {
        let filter = Filter::new()
            .kind(Kind::from(TOMBSTONE_REQUEST_METADATA_KIND))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::E), request_id.to_hex());
        self.db
            .query(filter)
            .await
            .map(|events| events.into_iter().collect())
            .map_err(|error| {
                anyhow::anyhow!(
                    "Failed to query tombstone lifecycle metadata for {request_id}: {error}"
                )
            })
    }

    fn parse_metadata(&self, event: &Event, request_id: &EventId) -> Option<ParsedMetadata> {
        let linked = Self::tag_value(event, "e")
            .and_then(|value| EventId::from_hex(value).ok())
            .is_some_and(|id| id == *request_id);
        let first_seen_at = Self::tag_value(event, TOMBSTONE_FIRST_SEEN_AT_TAG)
            .and_then(|value| value.parse().ok())
            .map(Timestamp::from_secs);
        let classification = Self::tag_value(event, TOMBSTONE_REQUEST_CLASSIFICATION_TAG)
            .and_then(RequestClassification::parse);
        let last_used_at = Self::tag_value(event, TOMBSTONE_LAST_USED_AT_TAG)
            .and_then(|value| value.parse().ok())
            .map(Timestamp::from_secs);
        match (
            event.kind.as_u16() == TOMBSTONE_REQUEST_METADATA_KIND,
            linked,
            first_seen_at,
            classification,
        ) {
            (true, true, Some(first_seen_at), Some(classification)) => Some(ParsedMetadata {
                id: event.id,
                created_at: event.created_at,
                first_seen_at,
                last_used_at,
                classification,
            }),
            _ => {
                tracing::warn!(metadata_id = %event.id, request_id = %request_id, "Ignoring malformed tombstone lifecycle metadata");
                None
            }
        }
    }

    fn lifecycle_record_from_metadata(
        &self,
        request: Event,
        metadata: Vec<Event>,
    ) -> Option<RequestLifecycleRecord> {
        if !Self::is_request_kind(request.kind) {
            tracing::warn!(request_id = %request.id, kind = request.kind.as_u16(), "Tombstone lifecycle payload has invalid kind");
            return None;
        }
        let request_id = request.id;
        let mut valid: Vec<_> = metadata
            .into_iter()
            .filter_map(|event| self.parse_metadata(&event, &request_id))
            .collect();
        if valid.is_empty() {
            return None;
        }

        let first_seen_at = valid
            .iter()
            .map(|m| m.first_seen_at)
            .min()
            .expect("nonempty");
        let last_used_at = valid.iter().filter_map(|m| m.last_used_at).max();
        valid.sort_by(|left, right| {
            right
                .last_used_at
                .cmp(&left.last_used_at)
                .then_with(|| left.first_seen_at.cmp(&right.first_seen_at))
                .then_with(|| right.created_at.cmp(&left.created_at))
                .then_with(|| left.id.to_hex().cmp(&right.id.to_hex()))
        });
        let canonical = valid.remove(0);
        Some(RequestLifecycleRecord {
            metadata_event_id: canonical.id,
            request,
            first_seen_at,
            last_used_at,
            classification: canonical.classification,
        })
    }

    fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
        event.tags.iter().find_map(|tag| {
            let tag = tag.as_slice();
            (tag.len() >= 2 && tag[0] == name).then_some(tag[1].as_str())
        })
    }

    /// Return locally actionable, lifecycle-backed kind-5 requests that delete
    /// `id` on behalf of `author`.
    pub async fn event_deletion_candidates(
        &self,
        id: &EventId,
        author: &PublicKey,
    ) -> anyhow::Result<Vec<RequestLifecycleRecord>> {
        let filter = Filter::new()
            .kind(Kind::EventDeletion)
            .author(*author)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::E), id.to_hex());
        self.lifecycle_candidates(filter, |request| {
            request.kind == Kind::EventDeletion
                && request.pubkey == *author
                && request.tags.iter().any(|tag| {
                    tag.as_slice()
                        .get(0..2)
                        .is_some_and(|values| values[0] == "e" && values[1] == id.to_hex())
                })
        })
        .await
    }

    /// Return locally actionable, lifecycle-backed kind-5 requests that delete
    /// the coordinate at or after `event_created_at`.
    pub async fn coordinate_deletion_candidates(
        &self,
        coordinate: &str,
        event_created_at: Timestamp,
    ) -> anyhow::Result<Vec<RequestLifecycleRecord>> {
        // The coordinate owner (pubkey hex) is the only party allowed to delete
        // it. Extract it so we can require the kind-5 author to match.
        let coord_owner_hex = coordinate.split(':').nth(1);

        let filter = Filter::new().kind(Kind::EventDeletion).custom_tag(
            SingleLetterTag::lowercase(Alphabet::A),
            coordinate.to_string(),
        );
        self.lifecycle_candidates(filter, |request| {
            request.kind == Kind::EventDeletion
                && request.created_at >= event_created_at
                && coord_owner_hex
                    .map(|owner| owner == request.pubkey.to_hex())
                    .unwrap_or(false)
                && request.tags.iter().any(|tag| {
                    tag.as_slice()
                        .get(0..2)
                        .is_some_and(|values| values[0] == "a" && values[1] == coordinate)
                })
        })
        .await
    }

    /// Return locally actionable, lifecycle-backed kind-62 requests made by
    /// `pubkey`. Non-targeting and disrespector classifications never gate.
    pub async fn vanish_candidates(
        &self,
        pubkey: &PublicKey,
    ) -> anyhow::Result<Vec<RequestLifecycleRecord>> {
        let filter = Filter::new().kind(Kind::RequestToVanish).author(*pubkey);
        self.lifecycle_candidates(filter, |request| {
            request.kind == Kind::RequestToVanish && request.pubkey == *pubkey
        })
        .await
    }

    async fn lifecycle_candidates<F>(
        &self,
        filter: Filter,
        matches_request: F,
    ) -> anyhow::Result<Vec<RequestLifecycleRecord>>
    where
        F: Fn(&Event) -> bool,
    {
        let requests =
            self.db.query(filter).await.map_err(|error| {
                anyhow::anyhow!("Failed to query tombstone candidates: {error}")
            })?;
        // Queries are intentionally restricted to original kind-5/kind-62
        // payloads; private metadata can never enter this path. Resolve the
        // resulting payloads together through indexed metadata `#e` queries.
        // Startup uses full-table grouping, but using that strategy here would
        // scan all retained lifecycle metadata while the admission lock is held.
        let matching_requests = requests
            .into_iter()
            .filter(|request| Self::is_request_kind(request.kind) && matches_request(request))
            .collect();
        Ok(self
            .lifecycle_records_for_matched_payloads_result(matching_requests)
            .await?
            .into_iter()
            .filter(|record| record.classification == RequestClassification::LocallyActionable)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deletion_by_event(keys: &Keys, target: EventId) -> Event {
        EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target)])
            .finalize(keys)
            .unwrap()
    }

    fn vanish(keys: &Keys) -> Event {
        EventBuilder::new(Kind::RequestToVanish, "")
            .tags(vec![Tag::custom("relay", vec!["ALL_RELAYS".to_string()])])
            .finalize(keys)
            .unwrap()
    }

    async fn metadata_count(store: &Tombstones, request_id: EventId) -> usize {
        store.metadata_events_for_request(&request_id).await.len()
    }

    #[tokio::test]
    async fn lifecycle_round_trip_for_kind_five_preserves_relay_first_seen_at() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let request = deletion_by_event(&keys, EventId::all_zeros());
        let first_seen_at = Timestamp::from_secs(1234);

        store
            .record_request(
                &request,
                first_seen_at,
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        let lifecycle = store
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lifecycle.request, request);
        assert_eq!(lifecycle.first_seen_at, first_seen_at);
        assert_eq!(lifecycle.last_used_at, None);
        assert_eq!(
            lifecycle.classification,
            RequestClassification::LocallyActionable
        );
    }

    #[tokio::test]
    async fn lifecycle_round_trip_for_kind_sixty_two() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let request = vanish(&keys);

        store
            .record_request(
                &request,
                Timestamp::from_secs(2345),
                RequestClassification::NonTargetingNip62,
            )
            .await
            .unwrap();
        let lifecycle = store
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lifecycle.request, request);
        assert_eq!(
            lifecycle.classification,
            RequestClassification::NonTargetingNip62
        );
    }

    #[tokio::test]
    async fn exact_replay_does_not_reset_first_seen_at() {
        let store = Tombstones::in_memory();
        let request = deletion_by_event(&Keys::generate(), EventId::all_zeros());
        store
            .record_request(
                &request,
                Timestamp::from_secs(10),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        store
            .record_request(
                &request,
                Timestamp::from_secs(99),
                RequestClassification::Disrespector,
            )
            .await
            .unwrap();

        let lifecycle = store
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lifecycle.first_seen_at, Timestamp::from_secs(10));
        assert_eq!(
            lifecycle.classification,
            RequestClassification::LocallyActionable
        );
        assert_eq!(metadata_count(&store, request.id).await, 1);
    }

    #[tokio::test]
    async fn marking_request_used_advances_without_resetting_first_seen_at() {
        let store = Tombstones::in_memory();
        let request = deletion_by_event(&Keys::generate(), EventId::all_zeros());
        store
            .record_request(
                &request,
                Timestamp::from_secs(10),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();

        let first_use = store
            .mark_request_used(&request.id, Timestamp::from_secs(20))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_use.first_seen_at, Timestamp::from_secs(10));
        assert_eq!(first_use.last_used_at, Some(Timestamp::from_secs(20)));
        let later_use = store
            .mark_request_used(&request.id, Timestamp::from_secs(30))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(later_use.first_seen_at, Timestamp::from_secs(10));
        assert_eq!(later_use.last_used_at, Some(Timestamp::from_secs(30)));
        let older_use = store
            .mark_request_used(&request.id, Timestamp::from_secs(25))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(older_use.first_seen_at, Timestamp::from_secs(10));
        assert_eq!(older_use.last_used_at, Some(Timestamp::from_secs(30)));
        assert_eq!(metadata_count(&store, request.id).await, 1);
    }

    #[tokio::test]
    async fn canonical_metadata_selection_is_deterministic_and_compacted_on_update() {
        let store = Tombstones::in_memory();
        let request = deletion_by_event(&Keys::generate(), EventId::all_zeros());
        store
            .record_request(
                &request,
                Timestamp::from_secs(20),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        let older_first_seen = store
            .build_metadata(
                request.id,
                Timestamp::from_secs(10),
                Some(Timestamp::from_secs(40)),
                RequestClassification::Disrespector,
            )
            .unwrap();
        let newest_use = store
            .build_metadata(
                request.id,
                Timestamp::from_secs(30),
                Some(Timestamp::from_secs(50)),
                RequestClassification::NonTargetingNip62,
            )
            .unwrap();
        store.db.save_event(&older_first_seen).await.unwrap();
        store.db.save_event(&newest_use).await.unwrap();

        let lifecycle = store
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lifecycle.first_seen_at, Timestamp::from_secs(10));
        assert_eq!(lifecycle.last_used_at, Some(Timestamp::from_secs(50)));
        assert_eq!(lifecycle.metadata_event_id, newest_use.id);

        store
            .mark_request_used(&request.id, Timestamp::from_secs(60))
            .await
            .unwrap();
        assert_eq!(metadata_count(&store, request.id).await, 1);
    }

    #[tokio::test]
    async fn malformed_and_orphan_metadata_are_ignored_safely() {
        let store = Tombstones::in_memory();
        let request = deletion_by_event(&Keys::generate(), EventId::all_zeros());
        let malformed = EventBuilder::new(Kind::from(TOMBSTONE_REQUEST_METADATA_KIND), "")
            .tags(vec![Tag::event(request.id)])
            .finalize(&store.metadata_signer)
            .unwrap();
        store.db.save_event(&malformed).await.unwrap();
        assert!(store
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .is_none());

        let orphan_id = EventId::all_zeros();
        let orphan = store
            .build_metadata(
                orphan_id,
                Timestamp::from_secs(10),
                None,
                RequestClassification::LocallyActionable,
            )
            .unwrap();
        store.db.save_event(&orphan).await.unwrap();
        assert!(store
            .lifecycle_for_request_result(&orphan_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn metadata_events_do_not_affect_deletion_or_vanish_queries() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let target = EventId::all_zeros();
        let metadata = store
            .build_metadata(
                target,
                Timestamp::from_secs(10),
                None,
                RequestClassification::LocallyActionable,
            )
            .unwrap();
        store.db.save_event(&metadata).await.unwrap();

        assert!(store
            .event_deletion_candidates(&target, &keys.public_key())
            .await
            .unwrap()
            .is_empty());
        assert!(store
            .vanish_candidates(&keys.public_key())
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn event_deletion_candidates_are_author_bound_and_lifecycle_backed() {
        let store = Tombstones::in_memory();
        let owner = Keys::generate();
        let other = Keys::generate();
        let target = EventId::all_zeros();
        let request = deletion_by_event(&owner, target);
        store
            .record_request(
                &request,
                Timestamp::from_secs(10),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();

        let candidates = store
            .event_deletion_candidates(&target, &owner.public_key())
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].request.id, request.id);
        assert!(store
            .event_deletion_candidates(&target, &other.public_key())
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn event_deletion_candidates_resolve_duplicate_requests_together() {
        let store = Tombstones::in_memory();
        let owner = Keys::generate();
        let target = EventId::all_zeros();
        let mut actionable_ids = Vec::new();

        // A single event may have many valid deletion requests. Save their
        // payloads and metadata directly so this test isolates the candidate
        // resolution path from record_request's single-request replay check.
        for created_at in 1..=METADATA_REQUEST_ID_QUERY_CHUNK_SIZE as u64 + 1 {
            let request = EventBuilder::new(Kind::EventDeletion, "")
                .tags(vec![Tag::event(target)])
                .custom_created_at(Timestamp::from_secs(created_at))
                .finalize(&owner)
                .unwrap();
            let classification = if created_at % 2 == 0 {
                actionable_ids.push(request.id);
                RequestClassification::LocallyActionable
            } else {
                RequestClassification::Disrespector
            };
            store.db.save_event(&request).await.unwrap();
            let metadata = store
                .build_metadata(
                    request.id,
                    Timestamp::from_secs(created_at),
                    None,
                    classification,
                )
                .unwrap();
            store.db.save_event(&metadata).await.unwrap();
        }

        let candidate_ids = store
            .event_deletion_candidates(&target, &owner.public_key())
            .await
            .unwrap()
            .into_iter()
            .map(|record| record.request.id)
            .collect::<Vec<_>>();

        assert_eq!(candidate_ids.len(), actionable_ids.len());
        assert!(candidate_ids
            .iter()
            .all(|candidate_id| actionable_ids.contains(candidate_id)));
    }

    #[tokio::test]
    async fn coordinate_candidates_enforce_cutoff_and_coordinate_owner() {
        let store = Tombstones::in_memory();
        let owner = Keys::generate();
        let attacker = Keys::generate();
        let coordinate = format!("30618:{}:repo", owner.public_key().to_hex());
        let valid = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coordinate.clone()])])
            .custom_created_at(Timestamp::from_secs(100))
            .finalize(&owner)
            .unwrap();
        let invalid = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coordinate.clone()])])
            .custom_created_at(Timestamp::from_secs(100))
            .finalize(&attacker)
            .unwrap();
        for request in [&valid, &invalid] {
            store
                .record_request(
                    request,
                    Timestamp::from_secs(10),
                    RequestClassification::LocallyActionable,
                )
                .await
                .unwrap();
        }

        assert_eq!(
            store
                .coordinate_deletion_candidates(&coordinate, Timestamp::from_secs(100))
                .await
                .unwrap()
                .iter()
                .map(|record| record.request.id)
                .collect::<Vec<_>>(),
            vec![valid.id]
        );
        assert_eq!(
            store
                .coordinate_deletion_candidates(&coordinate, Timestamp::from_secs(99))
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .coordinate_deletion_candidates(&coordinate, Timestamp::from_secs(101))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn vanish_candidates_require_locally_actionable_classification() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let actionable = vanish(&keys);
        store
            .record_request(
                &actionable,
                Timestamp::from_secs(10),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .vanish_candidates(&keys.public_key())
                .await
                .unwrap()
                .len(),
            1
        );

        for classification in [
            RequestClassification::NonTargetingNip62,
            RequestClassification::Disrespector,
        ] {
            let store = Tombstones::in_memory();
            let request = vanish(&keys);
            store
                .record_request(&request, Timestamp::from_secs(10), classification)
                .await
                .unwrap();
            assert!(store
                .vanish_candidates(&keys.public_key())
                .await
                .unwrap()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn lifecycle_metadata_survives_lmdb_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let keys = Keys::generate();
        let request = deletion_by_event(&keys, EventId::all_zeros());
        let store = Tombstones::open_lmdb(directory.path()).await.unwrap();
        store
            .record_request(
                &request,
                Timestamp::from_secs(1234),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        drop(store);

        let reopened = Tombstones::open_lmdb(directory.path()).await.unwrap();
        let lifecycle = reopened
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lifecycle.first_seen_at, Timestamp::from_secs(1234));
        assert_eq!(lifecycle.request, request);
    }
}
