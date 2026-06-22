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
//! and vanish request events themselves** (kind 5 and kind 62) in a dedicated
//! nostr database and derive the deleted/vanished state by querying it:
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

use std::path::Path;
use std::sync::Arc;

use nostr_lmdb::NostrLmdb;
use nostr_memory::MemoryDatabase;
use nostr_relay_builder::prelude::{
    Alphabet, Event, EventId, Filter, Kind, NostrDatabase, PublicKey, SingleLetterTag, Timestamp,
};

/// Directory name (under `relay_data_path`) for the LMDB tombstone database.
const TOMBSTONE_DIR: &str = "tombstones";

/// Persistent record of NIP-09 deletions and NIP-62 vanish requests.
///
/// Backed by its own nostr database so the deleted/vanished state survives
/// relay restarts. See the module docs for the rationale.
#[derive(Clone)]
pub struct Tombstones {
    db: Arc<dyn NostrDatabase>,
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
    /// auto-processing is explicitly disabled on this database: it is used purely
    /// as a raw, append-only record of deletion/vanish request events.
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

        Ok(Self { db: Arc::new(db) })
    }

    /// Create an in-memory tombstone store (used with the memory backend and in
    /// tests). Not persistent.
    pub fn in_memory() -> Self {
        Self {
            db: Arc::new(MemoryDatabase::unbounded()),
        }
    }

    /// Record a NIP-09 deletion request (kind 5).
    ///
    /// The caller MUST have already validated author ownership of the targets.
    /// Storing the event makes the deletions durable and queryable.
    pub async fn record_deletion(&self, event: &Event) -> anyhow::Result<()> {
        debug_assert_eq!(event.kind, Kind::EventDeletion);
        self.db
            .save_event(event)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to record deletion tombstone: {e}"))?;
        Ok(())
    }

    /// Record a NIP-62 vanish request (kind 62).
    ///
    /// The caller MUST have already validated that the request targets this relay
    /// and is signed by the pubkey being vanished.
    pub async fn record_vanish(&self, event: &Event) -> anyhow::Result<()> {
        debug_assert_eq!(event.kind, Kind::RequestToVanish);
        self.db
            .save_event(event)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to record vanish tombstone: {e}"))?;
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
        // A stored kind-5 authored by `author` carrying this id in an `e` tag
        // means `author` deleted their own event.
        let filter = Filter::new()
            .kind(Kind::EventDeletion)
            .author(*author)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::E), id.to_hex());
        match self.db.query(filter).await {
            Ok(events) => !events.is_empty(),
            Err(e) => {
                // Fail secure: if we cannot determine deletion status, do not
                // claim the event is deleted (so we don't reject legitimate
                // events), but log loudly.
                tracing::error!(error = %e, "Tombstone query failed for is_event_deleted");
                false
            }
        }
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
        // The coordinate owner (pubkey hex) is the only party allowed to delete
        // it. Extract it so we can require the kind-5 author to match.
        let coord_owner_hex = coordinate.split(':').nth(1);

        let filter = Filter::new().kind(Kind::EventDeletion).custom_tag(
            SingleLetterTag::lowercase(Alphabet::A),
            coordinate.to_string(),
        );
        match self.db.query(filter).await {
            Ok(events) => events.iter().any(|deletion| {
                deletion.created_at >= event_created_at
                    && coord_owner_hex
                        .map(|owner| owner == deletion.pubkey.to_hex())
                        .unwrap_or(false)
            }),
            Err(e) => {
                tracing::error!(error = %e, "Tombstone query failed for is_coordinate_deleted");
                false
            }
        }
    }

    /// Has this pubkey requested to vanish from this relay (recorded kind-62)?
    ///
    /// Mirrors the backend's `is_pubkey_vanished` check.
    pub async fn is_pubkey_vanished(&self, pubkey: &PublicKey) -> bool {
        let filter = Filter::new().kind(Kind::RequestToVanish).author(*pubkey);
        match self.db.query(filter).await {
            Ok(events) => !events.is_empty(),
            Err(e) => {
                tracing::error!(error = %e, "Tombstone query failed for is_pubkey_vanished");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_relay_builder::prelude::*;

    fn deletion_by_event(keys: &Keys, target: EventId) -> Event {
        EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target)])
            .finalize(keys)
            .unwrap()
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
