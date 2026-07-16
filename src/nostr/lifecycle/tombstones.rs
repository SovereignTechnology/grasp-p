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

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use nostr_lmdb::NostrLmdb;
use nostr_memory::MemoryDatabase;
use nostr_relay_builder::prelude::{
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

#[derive(Debug, Default)]
struct DeletionTargets {
    e_ids: HashSet<EventId>,
    a_coordinates: HashSet<String>,
}

#[derive(Debug, Clone, Copy)]
struct ParsedMetadata {
    id: EventId,
    created_at: Timestamp,
    first_seen_at: Timestamp,
    last_used_at: Option<Timestamp>,
    classification: RequestClassification,
}

impl DeletionTargets {
    fn is_empty(&self) -> bool {
        self.e_ids.is_empty() && self.a_coordinates.is_empty()
    }

    fn covers(
        &self,
        newer_created_at: Timestamp,
        older: &Self,
        older_created_at: Timestamp,
    ) -> bool {
        older.e_ids.is_subset(&self.e_ids)
            && older.a_coordinates.is_subset(&self.a_coordinates)
            && (older.a_coordinates.is_empty() || newer_created_at >= older_created_at)
    }
}

/// Persistent record of NIP-09 deletions and NIP-62 vanish requests.
///
/// Backed by its own nostr database so the deleted/vanished state survives
/// relay restarts. See the module docs for the rationale.
#[derive(Clone)]
pub struct Tombstones {
    db: Arc<dyn NostrDatabase>,
    metadata_signer: Keys,
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
        })
    }

    /// Create an in-memory tombstone store (used with the memory backend and in
    /// tests). Not persistent.
    pub fn in_memory() -> Self {
        Self {
            db: Arc::new(MemoryDatabase::unbounded()),
            metadata_signer: Keys::generate(),
        }
    }

    /// Persist a signed deletion/vanish request and relay-generated lifecycle
    /// metadata. Exact replays retain their original `first_seen_at`.
    pub async fn record_request(
        &self,
        event: &Event,
        first_seen_at: Timestamp,
        classification: RequestClassification,
    ) -> anyhow::Result<RequestLifecycleRecord> {
        if !Self::is_request_kind(event.kind) {
            anyhow::bail!("Tombstone lifecycle accepts only kind-5 or kind-62 requests");
        }

        if let Some(record) = self.lifecycle_for_request(&event.id).await {
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

    /// Return the canonical lifecycle record, if both a valid payload and valid
    /// metadata exist. Multiple metadata rows are compacted lazily by updates.
    ///
    /// Canonical selection is deterministic: valid rows are required; the record
    /// preserves the earliest `first_seen_at` and greatest `last_used_at` across
    /// them, while its metadata ID is selected by greatest `last_used_at`, then
    /// earliest `first_seen_at`, newest metadata creation time, then lowest ID.
    pub async fn lifecycle_for_request(
        &self,
        request_id: &EventId,
    ) -> Option<RequestLifecycleRecord> {
        match self.lifecycle_for_request_result(request_id).await {
            Ok(record) => record,
            Err(error) => {
                tracing::error!(error = %error, request_id = %request_id, "Failed to read tombstone lifecycle record");
                None
            }
        }
    }

    /// Fallible counterpart to [`Self::lifecycle_for_request`], for policy paths
    /// where an unreadable lifecycle must not be mistaken for an absent one.
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
        let mut valid: Vec<_> = metadata
            .into_iter()
            .filter_map(|event| self.parse_metadata(&event, request_id))
            .collect();
        if valid.is_empty() {
            return Ok(None);
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
        Ok(Some(RequestLifecycleRecord {
            metadata_event_id: canonical.id,
            request,
            first_seen_at,
            last_used_at,
            classification: canonical.classification,
        }))
    }

    /// Set `last_used_at`, never moving it backwards, then compact superseded
    /// metadata only after the replacement is durable.
    pub async fn mark_request_used(
        &self,
        request_id: &EventId,
        used_at: Timestamp,
    ) -> anyhow::Result<Option<RequestLifecycleRecord>> {
        let Some(existing) = self.lifecycle_for_request(request_id).await else {
            return Ok(None);
        };
        let last_used_at = existing.last_used_at.max(Some(used_at));
        if last_used_at == existing.last_used_at {
            return Ok(Some(existing));
        }

        let replacement = self.build_metadata(
            *request_id,
            existing.first_seen_at,
            last_used_at,
            existing.classification,
        )?;
        self.db.save_event(&replacement).await.map_err(|e| {
            anyhow::anyhow!("Failed to update lifecycle metadata for {request_id}: {e}")
        })?;
        let updated = self
            .lifecycle_for_request(request_id)
            .await
            .ok_or_else(|| {
                anyhow::anyhow!("Updated lifecycle metadata for {request_id} was not readable")
            })?;
        let stale_ids: Vec<_> = self
            .metadata_events_for_request(request_id)
            .await
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
        Ok(self.lifecycle_for_request(request_id).await)
    }

    /// List canonical request lifecycles for migration and retention work.
    /// Internal metadata events are never returned.
    pub async fn lifecycle_records(&self) -> Vec<RequestLifecycleRecord> {
        let mut requests = Vec::new();
        for kind in [Kind::EventDeletion, Kind::RequestToVanish] {
            match self.db.query(Filter::new().kind(kind)).await {
                Ok(events) => requests.extend(events),
                Err(error) => {
                    tracing::error!(error = %error, "Failed to list tombstone request payloads")
                }
            }
        }
        let mut records = Vec::new();
        for request in requests {
            if let Some(record) = self.lifecycle_for_request(&request.id).await {
                records.push(record);
            }
        }
        records.sort_by_key(|record| record.request.id.to_hex());
        records
    }

    fn is_request_kind(kind: Kind) -> bool {
        kind == Kind::EventDeletion || kind == Kind::RequestToVanish
    }

    async fn request_payload(&self, request_id: &EventId) -> anyhow::Result<Option<Event>> {
        for kind in [Kind::EventDeletion, Kind::RequestToVanish] {
            let events = self.db.query(Filter::new().kind(kind)).await.map_err(|e| {
                anyhow::anyhow!("Failed to read tombstone request {request_id}: {e}")
            })?;
            if let Some(event) = events.into_iter().find(|event| event.id == *request_id) {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    fn build_metadata(
        &self,
        request_id: EventId,
        first_seen_at: Timestamp,
        last_used_at: Option<Timestamp>,
        classification: RequestClassification,
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
            .finalize(&self.metadata_signer)
            .map_err(|e| anyhow::anyhow!("Failed to build tombstone lifecycle metadata: {e}"))
    }

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

    fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
        event.tags.iter().find_map(|tag| {
            let tag = tag.as_slice();
            (tag.len() >= 2 && tag[0] == name).then_some(tag[1].as_str())
        })
    }

    /// Record a NIP-09 deletion request (kind 5).
    ///
    /// The caller MUST have already validated author ownership of the targets.
    /// Storing the event makes the deletions durable and queryable.
    pub async fn record_deletion(&self, event: &Event) -> anyhow::Result<()> {
        debug_assert_eq!(event.kind, Kind::EventDeletion);
        self.record_request(
            event,
            Timestamp::now(),
            RequestClassification::LocallyActionable,
        )
        .await?;
        Ok(())
    }

    /// Return `true` when every actionable NIP-09 target in `event` is already
    /// covered by an existing same-author kind-5 request in this store.
    ///
    /// This is an idempotency helper for admission: a client may generate a new
    /// kind-5 event id by changing only `created_at` while tagging the same
    /// targets. Once the relay has already accepted a deletion request that
    /// covers those targets, accepting another equivalent request only pollutes
    /// the served deletion-request stream.
    ///
    /// Coverage is target-specific:
    /// - `e` targets are covered by any existing same-author kind-5 with that
    ///   event id.
    /// - `a` targets are covered only by an existing same-author kind-5 for the
    ///   same coordinate whose `created_at` is greater than or equal to the new
    ///   request's `created_at`, preserving NIP-09's "delete versions up to this
    ///   timestamp" semantics.
    ///
    /// Non-actionable targets (malformed tags, or `a` coordinates owned by a
    /// different pubkey than the event author) are ignored so this helper does
    /// not change existing no-op acceptance semantics for those events.
    pub async fn deletion_targets_already_covered(&self, event: &Event) -> anyhow::Result<bool> {
        debug_assert_eq!(event.kind, Kind::EventDeletion);

        let author = event.pubkey;
        let author_hex = author.to_hex();
        let mut actionable_targets = 0usize;

        for tag in event.tags.iter() {
            let v = tag.as_slice();
            if v.len() < 2 {
                continue;
            }

            match v[0].as_str() {
                "e" => {
                    let Ok(target_id) = EventId::from_hex(&v[1]) else {
                        continue;
                    };
                    actionable_targets += 1;

                    let filter = Filter::new()
                        .kind(Kind::EventDeletion)
                        .author(author)
                        .custom_tag(SingleLetterTag::lowercase(Alphabet::E), target_id.to_hex());
                    let covered = !self
                        .db
                        .query(filter)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to query deletion tombstones: {e}"))?
                        .is_empty();
                    if !covered {
                        return Ok(false);
                    }
                }
                "a" => {
                    let coordinate = &v[1];
                    let Some(coord_owner_hex) = coordinate.split(':').nth(1) else {
                        continue;
                    };
                    if coord_owner_hex != author_hex {
                        continue;
                    }
                    actionable_targets += 1;

                    let filter = Filter::new()
                        .kind(Kind::EventDeletion)
                        .author(author)
                        .custom_tag(SingleLetterTag::lowercase(Alphabet::A), coordinate.clone());
                    let covered = self
                        .db
                        .query(filter)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to query deletion tombstones: {e}"))?
                        .iter()
                        .any(|deletion| deletion.created_at >= event.created_at);
                    if !covered {
                        return Ok(false);
                    }
                }
                _ => {}
            }
        }

        Ok(actionable_targets > 0)
    }

    /// Return older same-author kind-5 request IDs whose actionable target set
    /// is fully subsumed by `event`.
    ///
    /// This supports deletion-request compaction. For example, if a client first
    /// publishes `kind:5` with `a=30617:<pubkey>:repo` at t=1000 and later
    /// publishes the same coordinate at t=2000, the t=2000 request preserves all
    /// deletion semantics of the older request and extends the coordinate cutoff.
    /// The older request can therefore be removed from both the tombstone store
    /// and the served deletion-request stream.
    pub async fn superseded_deletion_ids(&self, event: &Event) -> anyhow::Result<Vec<EventId>> {
        debug_assert_eq!(event.kind, Kind::EventDeletion);

        let newer_targets = Self::actionable_targets(event);
        if newer_targets.is_empty() {
            return Ok(Vec::new());
        }

        let candidates = self
            .db
            .query(Filter::new().kind(Kind::EventDeletion).author(event.pubkey))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to query deletion tombstones: {e}"))?;

        Ok(candidates
            .into_iter()
            .filter(|candidate| candidate.id != event.id)
            .filter(|candidate| {
                let older_targets = Self::actionable_targets(candidate);
                !older_targets.is_empty()
                    && newer_targets.covers(event.created_at, &older_targets, candidate.created_at)
            })
            .map(|candidate| candidate.id)
            .collect())
    }

    /// Remove deletion request records by event id from this tombstone store.
    pub async fn remove_deletions_by_ids(&self, ids: Vec<EventId>) -> anyhow::Result<usize> {
        let removed = ids.len();
        if removed > 0 {
            self.db
                .delete(Filter::new().ids(ids))
                .await
                .map_err(|e| anyhow::anyhow!("Failed to remove deletion tombstones: {e}"))?;
        }

        Ok(removed)
    }

    fn actionable_targets(event: &Event) -> DeletionTargets {
        let author_hex = event.pubkey.to_hex();
        let mut targets = DeletionTargets::default();

        for tag in event.tags.iter() {
            let v = tag.as_slice();
            if v.len() < 2 {
                continue;
            }

            match v[0].as_str() {
                "e" => {
                    if let Ok(target_id) = EventId::from_hex(&v[1]) {
                        targets.e_ids.insert(target_id);
                    }
                }
                "a" => {
                    let coordinate = &v[1];
                    if coordinate
                        .split(':')
                        .nth(1)
                        .map(|owner| owner == author_hex)
                        .unwrap_or(false)
                    {
                        targets.a_coordinates.insert(coordinate.clone());
                    }
                }
                _ => {}
            }
        }

        targets
    }

    /// Remove recorded kind-5 requests from other authors that targeted `id`.
    ///
    /// This handles out-of-order cross-author deletes. A relay may accept a
    /// pre-emptive `e` deletion before the target event exists, because it cannot
    /// yet validate ownership. When the real event later arrives from a different
    /// pubkey, the earlier deletion request is known to be invalid for that
    /// target and should no longer remain in the tombstone store.
    pub async fn remove_event_deletions_by_other_authors(
        &self,
        id: &EventId,
        author: &PublicKey,
    ) -> anyhow::Result<usize> {
        let filter = Filter::new()
            .kind(Kind::EventDeletion)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::E), id.to_hex());

        let stale_ids: Vec<EventId> = self
            .db
            .query(filter)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to query deletion tombstones: {e}"))?
            .into_iter()
            .filter(|deletion| deletion.pubkey != *author)
            .map(|deletion| deletion.id)
            .collect();

        let removed = stale_ids.len();
        if removed > 0 {
            self.db
                .delete(Filter::new().ids(stale_ids))
                .await
                .map_err(|e| anyhow::anyhow!("Failed to remove deletion tombstones: {e}"))?;
        }

        Ok(removed)
    }

    /// Record a NIP-62 vanish request (kind 62).
    ///
    /// The caller MUST have already validated that the request targets this relay
    /// and is signed by the pubkey being vanished.
    pub async fn record_vanish(&self, event: &Event) -> anyhow::Result<()> {
        debug_assert_eq!(event.kind, Kind::RequestToVanish);
        self.record_request(
            event,
            Timestamp::now(),
            RequestClassification::LocallyActionable,
        )
        .await?;
        Ok(())
    }

    /// Has this event id been deleted by a recorded kind-5 (`e` tag) authored by
    /// `author`?
    ///
    /// Mirrors the backend's `is_deleted` check that previously fed the
    /// relay-builder `check_id` gate, but with explicit author binding: only the
    /// event's own author may delete it (NIP-09). A deletion request signed by a
    /// different pubkey must NOT block (re-)submission of `author`'s event —
    /// otherwise any pubkey could pre-emptively censor another's events by
    /// racing a kind-5 ahead of the target (out-of-order delete).
    pub async fn is_event_deleted(&self, id: &EventId, author: &PublicKey) -> bool {
        match self.event_deletion_candidates(id, author).await {
            Ok(candidates) => !candidates.is_empty(),
            Err(error) => {
                tracing::error!(error = %error, "Tombstone query failed for is_event_deleted");
                false
            }
        }
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

    /// Has this addressable/replaceable coordinate been deleted at or after
    /// `event_created_at`?
    ///
    /// Per NIP-09, an `a`-tag deletion deletes all versions of the coordinate up
    /// to the deletion request's `created_at`. So a candidate event is blocked
    /// only if a recorded deletion for the same coordinate has
    /// `deletion.created_at >= event_created_at`.
    ///
    /// Author binding: a coordinate is `<kind>:<pubkey>:<d>`, so only the pubkey
    /// embedded in the coordinate may delete it. A kind-5 signed by a different
    /// pubkey referencing this coordinate is ignored, otherwise any pubkey could
    /// pre-emptively censor another's addressable events.
    pub async fn is_coordinate_deleted(
        &self,
        coordinate: &str,
        event_created_at: Timestamp,
    ) -> bool {
        match self
            .coordinate_deletion_candidates(coordinate, event_created_at)
            .await
        {
            Ok(candidates) => !candidates.is_empty(),
            Err(error) => {
                tracing::error!(error = %error, "Tombstone query failed for is_coordinate_deleted");
                false
            }
        }
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

    /// Has this pubkey requested to vanish from this relay (recorded kind-62)?
    ///
    /// Mirrors the backend's `is_pubkey_vanished` check.
    pub async fn is_pubkey_vanished(&self, pubkey: &PublicKey) -> bool {
        let filter = Filter::new().kind(Kind::RequestToVanish).author(*pubkey);
        match self
            .lifecycle_candidates(filter, |request| {
                request.kind == Kind::RequestToVanish && request.pubkey == *pubkey
            })
            .await
        {
            Ok(candidates) => !candidates.is_empty(),
            Err(error) => {
                tracing::error!(error = %error, "Tombstone query failed for is_pubkey_vanished");
                false
            }
        }
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
        let mut candidates = Vec::new();
        for request in requests {
            // Queries are intentionally restricted to original kind-5/kind-62
            // payloads; private metadata can never enter this path.
            if !Self::is_request_kind(request.kind) || !matches_request(&request) {
                continue;
            }
            let Some(record) = self.lifecycle_for_request_result(&request.id).await? else {
                // Requests without valid metadata await startup migration and do
                // not yet carry enough relay-observed state to gate admission.
                continue;
            };
            if record.classification == RequestClassification::LocallyActionable {
                candidates.push(record);
            }
        }
        Ok(candidates)
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
        let lifecycle = store.lifecycle_for_request(&request.id).await.unwrap();

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
        let lifecycle = store.lifecycle_for_request(&request.id).await.unwrap();

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

        let lifecycle = store.lifecycle_for_request(&request.id).await.unwrap();
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

        let lifecycle = store.lifecycle_for_request(&request.id).await.unwrap();
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
        assert!(store.lifecycle_for_request(&request.id).await.is_none());

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
        assert!(store.lifecycle_for_request(&orphan_id).await.is_none());
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

        assert!(!store.is_event_deleted(&target, &keys.public_key()).await);
        assert!(!store.is_pubkey_vanished(&keys.public_key()).await);
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
        let lifecycle = reopened.lifecycle_for_request(&request.id).await.unwrap();
        assert_eq!(lifecycle.first_seen_at, Timestamp::from_secs(1234));
        assert_eq!(lifecycle.request, request);
    }

    #[tokio::test]
    async fn records_and_detects_event_deletion() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let target = EventId::all_zeros();

        assert!(!store.is_event_deleted(&target, &keys.public_key()).await);

        let deletion = deletion_by_event(&keys, target);
        store.record_deletion(&deletion).await.unwrap();

        assert!(store.is_event_deleted(&target, &keys.public_key()).await);
    }

    #[tokio::test]
    async fn detects_already_covered_event_deletion_request() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let target = EventId::all_zeros();

        let first = deletion_by_event(&keys, target);
        store.record_deletion(&first).await.unwrap();

        let duplicate = deletion_by_event(&keys, target);

        assert!(store
            .deletion_targets_already_covered(&duplicate)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn coordinate_coverage_respects_deletion_created_at() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let coord = format!("30618:{}:my-repo", keys.public_key().to_hex());

        let first = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord.clone()])])
            .custom_created_at(Timestamp::from_secs(1000))
            .finalize(&keys)
            .unwrap();
        store.record_deletion(&first).await.unwrap();

        let older_or_equal = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord.clone()])])
            .custom_created_at(Timestamp::from_secs(900))
            .finalize(&keys)
            .unwrap();
        assert!(store
            .deletion_targets_already_covered(&older_or_equal)
            .await
            .unwrap());

        let newer = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord])])
            .custom_created_at(Timestamp::from_secs(1100))
            .finalize(&keys)
            .unwrap();
        assert!(!store
            .deletion_targets_already_covered(&newer)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn newer_coordinate_deletion_supersedes_older_request() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let coord = format!("30618:{}:my-repo", keys.public_key().to_hex());

        let older = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord.clone()])])
            .custom_created_at(Timestamp::from_secs(1000))
            .finalize(&keys)
            .unwrap();
        store.record_deletion(&older).await.unwrap();

        let newer = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord])])
            .custom_created_at(Timestamp::from_secs(1100))
            .finalize(&keys)
            .unwrap();
        store.record_deletion(&newer).await.unwrap();

        assert_eq!(
            store.superseded_deletion_ids(&newer).await.unwrap(),
            vec![older.id]
        );

        let removed = store.remove_deletions_by_ids(vec![older.id]).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            store.superseded_deletion_ids(&newer).await.unwrap(),
            Vec::new()
        );
    }

    #[tokio::test]
    async fn superseded_deletion_detection_requires_full_target_coverage() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let coord = format!("30618:{}:my-repo", keys.public_key().to_hex());
        let target = EventId::all_zeros();

        let older = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![
                Tag::event(target),
                Tag::custom("a", vec![coord.clone()]),
            ])
            .custom_created_at(Timestamp::from_secs(1000))
            .finalize(&keys)
            .unwrap();
        store.record_deletion(&older).await.unwrap();

        let newer = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord])])
            .custom_created_at(Timestamp::from_secs(1100))
            .finalize(&keys)
            .unwrap();
        store.record_deletion(&newer).await.unwrap();

        assert!(store
            .superseded_deletion_ids(&newer)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn deletion_does_not_block_a_different_authors_event() {
        // A kind-5 from pubkey B targeting an event id must NOT mark that id as
        // deleted for a different author A: only the event's own author may
        // delete it (NIP-09). Guards against pre-emptive cross-author censorship
        // when the deletion races ahead of the target (out-of-order delete).
        let store = Tombstones::in_memory();
        let attacker = Keys::generate();
        let victim = Keys::generate();
        let target = EventId::all_zeros();

        let deletion = deletion_by_event(&attacker, target);
        store.record_deletion(&deletion).await.unwrap();

        // The attacker "deleted" it for themselves...
        assert!(
            store
                .is_event_deleted(&target, &attacker.public_key())
                .await
        );
        // ...but the victim's identical id is NOT considered deleted.
        assert!(
            !store.is_event_deleted(&target, &victim.public_key()).await,
            "a deletion from another pubkey must not block the victim's event"
        );
    }

    #[tokio::test]
    async fn removes_deletion_requests_from_other_authors_when_target_author_is_known() {
        let store = Tombstones::in_memory();
        let attacker = Keys::generate();
        let victim = Keys::generate();
        let target = EventId::all_zeros();

        let deletion = deletion_by_event(&attacker, target);
        store.record_deletion(&deletion).await.unwrap();

        assert!(
            store
                .is_event_deleted(&target, &attacker.public_key())
                .await
        );

        let removed = store
            .remove_event_deletions_by_other_authors(&target, &victim.public_key())
            .await
            .unwrap();

        assert_eq!(removed, 1);
        assert!(
            !store
                .is_event_deleted(&target, &attacker.public_key())
                .await,
            "cross-author deletion request should be removed once the real author is known"
        );
    }

    #[tokio::test]
    async fn coordinate_deletion_respects_created_at() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let coord = format!("30618:{}:my-repo", keys.public_key().to_hex());

        // Deletion at t=1000
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord.clone()])])
            .custom_created_at(Timestamp::from_secs(1000))
            .finalize(&keys)
            .unwrap();
        store.record_deletion(&deletion).await.unwrap();

        // An event created at t<=1000 is deleted; t>1000 is not.
        assert!(
            store
                .is_coordinate_deleted(&coord, Timestamp::from_secs(1000))
                .await
        );
        assert!(
            store
                .is_coordinate_deleted(&coord, Timestamp::from_secs(500))
                .await
        );
        assert!(
            !store
                .is_coordinate_deleted(&coord, Timestamp::from_secs(1500))
                .await
        );
    }

    #[tokio::test]
    async fn coordinate_deletion_by_other_pubkey_is_ignored() {
        // A kind-5 from pubkey B carrying an `a` tag for a coordinate owned by
        // pubkey A must NOT mark that coordinate as deleted: only the pubkey
        // embedded in the coordinate may delete it.
        let store = Tombstones::in_memory();
        let victim = Keys::generate();
        let attacker = Keys::generate();
        let coord = format!("30618:{}:my-repo", victim.public_key().to_hex());

        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coord.clone()])])
            .custom_created_at(Timestamp::from_secs(1000))
            .finalize(&attacker)
            .unwrap();
        store.record_deletion(&deletion).await.unwrap();

        assert!(
            !store
                .is_coordinate_deleted(&coord, Timestamp::from_secs(1000))
                .await,
            "a coordinate deletion signed by a different pubkey must be ignored"
        );
    }

    #[tokio::test]
    async fn detects_pubkey_vanish() {
        let store = Tombstones::in_memory();
        let keys = Keys::generate();
        let other = Keys::generate();

        assert!(!store.is_pubkey_vanished(&keys.public_key()).await);

        let vanish = EventBuilder::new(Kind::RequestToVanish, "")
            .tags(vec![Tag::custom("relay", vec!["ALL_RELAYS".to_string()])])
            .finalize(&keys)
            .unwrap();
        store.record_vanish(&vanish).await.unwrap();

        assert!(store.is_pubkey_vanished(&keys.public_key()).await);
        assert!(!store.is_pubkey_vanished(&other.public_key()).await);
    }
}
