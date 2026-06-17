//! Durable history storage for superseded replaceable/addressable events.
//!
//! This store keeps prior versions of selected coordinates (currently kinds
//! 30617 + 30618) so rollback can be implemented later without depending on
//! backend-internal replaceable retention behavior.

use std::path::Path;
use std::sync::Arc;

use nostr_lmdb::NostrLmdb;
use nostr_memory::MemoryDatabase;
use nostr_relay_builder::prelude::{
    Alphabet, Event, EventBuilder, EventId, Filter, FinalizeEvent, Keys, Kind, NostrDatabase,
    SingleLetterTag, Tag, Timestamp,
};

/// Directory name (under `relay_data_path`) for LMDB replaceable history.
pub const HISTORY_DIR: &str = "replaceable-history";

/// Internal metadata event kind for history captures.
pub const HISTORY_METADATA_KIND: u16 = 9906;
pub const HISTORY_SUPERSEDED_AT_TAG: &str = "history-superseded-at";
pub const HISTORY_CAPTURED_AT_TAG: &str = "history-captured-at";
pub const HISTORY_REPLACED_BY_TAG: &str = "history-replaced-by";
pub const HISTORY_KIND_TAG: &str = "history-kind";
pub const HISTORY_AUTHOR_PUBKEY_TAG: &str = "history-author-pubkey";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersededRecord {
    pub metadata_event_id: EventId,
    pub superseded_event_id: Option<EventId>,
    pub coordinate: Option<String>,
    pub superseded_at: Option<Timestamp>,
    pub captured_at: Option<Timestamp>,
    pub replaced_by: Option<EventId>,
}

#[derive(Clone)]
pub struct ReplaceableHistoryStore {
    db: Arc<dyn NostrDatabase>,
    metadata_signer: Keys,
}

impl std::fmt::Debug for ReplaceableHistoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplaceableHistoryStore")
            .finish_non_exhaustive()
    }
}

impl ReplaceableHistoryStore {
    /// Open a persistent LMDB-backed history store.
    pub async fn open_lmdb(relay_data_path: &Path) -> anyhow::Result<Self> {
        let path = relay_data_path.join(HISTORY_DIR);
        std::fs::create_dir_all(&path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create replaceable-history directory {}: {}",
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
                anyhow::anyhow!(
                    "Failed to open replaceable-history LMDB at {}: {}",
                    path.display(),
                    e
                )
            })?;

        Ok(Self {
            db: Arc::new(db),
            metadata_signer: Keys::generate(),
        })
    }

    /// In-memory history store (non-persistent).
    pub fn in_memory() -> Self {
        Self {
            db: Arc::new(MemoryDatabase::unbounded()),
            metadata_signer: Keys::generate(),
        }
    }

    /// Persist one superseded event payload + metadata row for later rollback.
    pub async fn archive_superseded_event(
        &self,
        superseded: &Event,
        replaced_by: &Event,
        coordinate: &str,
    ) -> anyhow::Result<()> {
        self.db.save_event(superseded).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to store superseded event {} in history DB: {e}",
                superseded.id
            )
        })?;

        let captured_at = Timestamp::now();
        let mut tags = vec![
            Tag::event(superseded.id),
            Tag::custom("a", vec![coordinate.to_string()]),
            Tag::custom(
                HISTORY_SUPERSEDED_AT_TAG,
                vec![superseded.created_at.as_secs().to_string()],
            ),
            Tag::custom(
                HISTORY_CAPTURED_AT_TAG,
                vec![captured_at.as_secs().to_string()],
            ),
            Tag::custom(HISTORY_REPLACED_BY_TAG, vec![replaced_by.id.to_hex()]),
            Tag::custom(HISTORY_KIND_TAG, vec![superseded.kind.as_u16().to_string()]),
            Tag::custom(HISTORY_AUTHOR_PUBKEY_TAG, vec![superseded.pubkey.to_hex()]),
        ];

        if let Some(identifier) = extract_identifier(superseded) {
            tags.push(Tag::custom("d", vec![identifier]));
        }

        let metadata_event = EventBuilder::new(Kind::from(HISTORY_METADATA_KIND), "")
            .tags(tags)
            .custom_created_at(captured_at)
            .finalize(&self.metadata_signer)
            .map_err(|e| anyhow::anyhow!("Failed to build replaceable-history metadata: {e}"))?;

        self.db.save_event(&metadata_event).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to store replaceable-history metadata for {}: {e}",
                superseded.id
            )
        })?;

        Ok(())
    }

    pub async fn superseded_records_for_coordinate_before(
        &self,
        coordinate: &str,
        before_or_at: Timestamp,
    ) -> Vec<SupersededRecord> {
        let filter = Filter::new()
            .kind(Kind::from(HISTORY_METADATA_KIND))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::A),
                coordinate.to_string(),
            );

        let events = match self.db.query(filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    coordinate,
                    "History DB query failed"
                );
                return Vec::new();
            }
        };

        events
            .into_iter()
            .filter_map(|metadata| {
                let superseded_at = parse_timestamp_tag(&metadata, HISTORY_SUPERSEDED_AT_TAG)
                    .or_else(|| Some(metadata.created_at));
                if superseded_at.is_some_and(|ts| ts > before_or_at) {
                    return None;
                }

                Some(SupersededRecord {
                    metadata_event_id: metadata.id,
                    superseded_event_id: parse_event_id_tag(&metadata, "e"),
                    coordinate: parse_string_tag(&metadata, "a"),
                    superseded_at,
                    captured_at: parse_timestamp_tag(&metadata, HISTORY_CAPTURED_AT_TAG),
                    replaced_by: parse_event_id_tag(&metadata, HISTORY_REPLACED_BY_TAG),
                })
            })
            .collect()
    }

    pub async fn event_by_id(&self, id: &EventId) -> anyhow::Result<Option<Event>> {
        self.db
            .event_by_id(id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed history lookup for event {}: {e}", id))
    }
}

fn parse_string_tag(metadata: &Event, tag_name: &str) -> Option<String> {
    metadata.tags.iter().find_map(|tag| {
        let v = tag.as_slice();
        if v.len() >= 2 && v[0] == tag_name {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

fn parse_timestamp_tag(metadata: &Event, tag_name: &str) -> Option<Timestamp> {
    parse_string_tag(metadata, tag_name)
        .and_then(|v| v.parse::<u64>().ok())
        .map(Timestamp::from_secs)
}

fn parse_event_id_tag(metadata: &Event, tag_name: &str) -> Option<EventId> {
    parse_string_tag(metadata, tag_name).and_then(|v| EventId::from_hex(&v).ok())
}

fn extract_identifier(event: &Event) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.as_slice();
        if v.len() >= 2 && v[0] == "d" {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announcement(keys: &Keys, identifier: &str, created_at: u64, content: &str) -> Event {
        EventBuilder::new(Kind::GitRepoAnnouncement, content)
            .tags(vec![Tag::identifier(identifier)])
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .unwrap()
    }

    #[tokio::test]
    async fn archives_and_queries_superseded_records_by_coordinate_and_time() {
        let store = ReplaceableHistoryStore::in_memory();
        let keys = Keys::generate();

        let v1 = announcement(&keys, "repo", 100, "v1");
        let v2 = announcement(&keys, "repo", 200, "v2");
        let coord = format!("30617:{}:repo", keys.public_key().to_hex());

        store
            .archive_superseded_event(&v1, &v2, &coord)
            .await
            .expect("archive superseded event");

        let records = store
            .superseded_records_for_coordinate_before(&coord, Timestamp::from_secs(150))
            .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].superseded_event_id, Some(v1.id));
        assert_eq!(records[0].replaced_by, Some(v2.id));

        let payload = store
            .event_by_id(&v1.id)
            .await
            .expect("history payload lookup")
            .expect("payload exists");
        assert_eq!(payload.content, "v1");
    }

    #[tokio::test]
    async fn lmdb_history_survives_restart() {
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = Keys::generate();
        let coord = format!("30617:{}:repo", keys.public_key().to_hex());
        let v1 = announcement(&keys, "repo", 10, "old");
        let v2 = announcement(&keys, "repo", 20, "new");

        {
            let store = ReplaceableHistoryStore::open_lmdb(temp.path())
                .await
                .expect("open store");
            store
                .archive_superseded_event(&v1, &v2, &coord)
                .await
                .expect("archive");
        }

        let reopened = ReplaceableHistoryStore::open_lmdb(temp.path())
            .await
            .expect("reopen store");
        let records = reopened
            .superseded_records_for_coordinate_before(&coord, Timestamp::from_secs(999))
            .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].superseded_event_id, Some(v1.id));

        let payload = reopened
            .event_by_id(&v1.id)
            .await
            .expect("lookup")
            .expect("payload exists");
        assert_eq!(payload.id, v1.id);
    }
}
