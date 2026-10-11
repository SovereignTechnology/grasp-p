//! GRASP-P private meta store: a dedicated heed (LMDB) environment holding the
//! registration index, key claims, quota ledger, blob claims, and the kind-30641
//! edition ring (G7 amendment).
//!
//! All tables are tiny per-entry; writes are serialized through a
//! `parking_lot::Mutex` so multi-table mutations stay atomic (single write txn)
//! and never race. No txn is ever held across an `.await`.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use heed::types::{SerdeJson, Str};
use heed::{Database, Env, EnvOpenOptions, RoTxn, RwTxn};
use nostr::prelude::Timestamp;
use parking_lot::{Mutex, MutexGuard};
use serde::{Deserialize, Serialize};

/// 4 GiB sparse map — private meta data is small (registrations, ledgers, and
/// up to N retained 30641 editions per alias at ≤128 KiB each).
const META_MAP_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// Ledger key for the whole private subsystem.
pub const LEDGER_GLOBAL_KEY: &str = "g:";

/// How long a charged kind-1059 wrap id is retained for charge idempotency.
/// The window only needs to cover the race between the async relay-DB
/// duplicate check and the save (older redeliveries are deduped by the relay
/// DB itself), so one hour is generous; pruning happens on each mark.
pub const CHARGED_WRAP_RETENTION_SECS: u64 = 3600;

/// A live (or tombstoned) alias registration derived from the latest accepted
/// kind-30640 event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRecord {
    /// Hosting tenant pubkey, lowercase hex.
    pub tenant_hex: String,
    /// Event id (hex) of the latest applied 30640 edition.
    pub event_id: String,
    /// created_at of the latest applied 30640 edition.
    pub created_at: u64,
    /// Registered write keys (64-lowercase-hex x-only pubkeys).
    pub w_keys: Vec<String>,
    /// Registered aux (stream/publish) keys.
    pub aux_keys: Vec<String>,
    /// `relays` tag values from the registration.
    pub relays: Vec<String>,
    /// `server` tag values from the registration.
    pub servers: Vec<String>,
    /// Opaque quota-class tag (recorded, unused in Phase 1).
    pub quota_class: Option<String>,
    /// Unix seconds when the alias was first registered on this node.
    pub registered_at: u64,
    /// Set when the alias has been offboarded (stub in Phase 1).
    pub tombstoned_at: Option<u64>,
    /// created_at of the FIRST registration edition for this seat — the §3.2
    /// conflict anchor (verify round 1, FA). Same-tenant replacement
    /// overwrites `created_at`/`event_id` with each new edition, so without
    /// this the seat's conflict priority DECAYS on every rotation: a squatter
    /// whose registration was created between edition 1 and edition N would
    /// start winning the deterministic merge after the rotation. `None` only
    /// for records written before this field existed (see [`Self::anchor`]).
    #[serde(default)]
    pub first_created_at: Option<Timestamp>,
    /// Event id (hex) of the first registration edition (see
    /// `first_created_at`).
    #[serde(default)]
    pub first_event_id: Option<String>,
}

impl RegistrationRecord {
    /// §3.2 conflict anchor: the FIRST edition's (created_at, event id) when
    /// recorded, else the latest edition's — the fallback for pre-existing
    /// records (first-edition history is unrecoverable there; accepted
    /// pre-multi-node-traffic). NEVER `registered_at` — that is node-local
    /// wall clock, and merge decisions must stay pure functions of
    /// event-intrinsic data + meta state.
    pub fn anchor(&self) -> (Timestamp, &str) {
        match (&self.first_created_at, &self.first_event_id) {
            (Some(created_at), Some(event_id)) => (*created_at, event_id.as_str()),
            _ => (
                Timestamp::from_secs(self.created_at),
                self.event_id.as_str(),
            ),
        }
    }
}

/// Byte ledger entry for a tenant (`t:<hex>`), alias (`r:<alias>`), or the
/// global scope (`g:`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub event_bytes: u64,
    pub blob_bytes: u64,
}

impl LedgerEntry {
    pub fn total(&self) -> u64 {
        self.event_bytes.saturating_add(self.blob_bytes)
    }
}

/// Speculative (pre-upload) ledger charge attached to a `stored = false`
/// blob claim: the declared bytes a 30641 charged to its (tenant, alias)
/// when it referenced a blob that was not yet stored (issue !12 — without
/// this, speculative claims accumulate unbilled and a tenant can grow the
/// shared meta LMDB at zero ledger cost). Released exactly once: when the
/// claim transitions to `stored` (the upload/mirror path takes over the
/// accounting) or when the claim is deleted by GC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecCharge {
    pub tenant: String,
    pub alias: String,
    pub bytes: u64,
}

/// Claim record for one stored (or referenced) blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobClaim {
    /// Size in bytes. For claims created by a 30641 before upload this is the
    /// declared size from the tag; replaced by the actual size at upload.
    pub size: u64,
    /// Aliases currently referencing this blob.
    pub aliases: Vec<String>,
    /// Unix seconds since the blob became unreferenced (GC grace anchor).
    pub unreferenced_since: Option<u64>,
    /// Whether the blob file has actually been stored (charged to the ledger).
    pub stored: bool,
    /// Scope the stored bytes were charged to (released on GC delete).
    pub charged_tenant: Option<String>,
    pub charged_alias: Option<String>,
    /// Speculative charge for a not-yet-stored declared blob (issue !12).
    /// `serde(default)` keeps records written before this field readable.
    #[serde(default)]
    pub spec_charge: Option<SpecCharge>,
    /// Unix seconds when THIS node first stored the bytes, whether a client
    /// uploaded them or the mirror fetched them. It is what `/list` and the
    /// upload descriptor report as `uploaded`, so the two nodes of a pair
    /// each report their own time for one blob. `None` while the blob is
    /// only declared. Claims are stored as JSON, so `serde(default)` reads
    /// a record written before this field existed as `None`.
    #[serde(default)]
    pub stored_at: Option<u64>,
}

struct MetaInner {
    env: Env,
    registrations: Database<Str, SerdeJson<RegistrationRecord>>,
    key_claims: Database<Str, Str>,
    tenant_aliases: Database<Str, SerdeJson<Vec<String>>>,
    ledger: Database<Str, SerdeJson<LedgerEntry>>,
    blob_claims: Database<Str, SerdeJson<BlobClaim>>,
    /// Per-alias claim index: `<alias>:<sha256>` → sha256. Kept in lockstep
    /// with `BlobClaim::aliases` inside the same write txn so tenant-scoped
    /// listings never scan the whole cross-tenant `blob_claims` table.
    alias_claims: Database<Str, Str>,
    state_ring: Database<Str, Str>,
    /// Set of kind-1059 wrap event ids (hex) whose bytes have already been
    /// charged to the ledger. Makes the per-event charge idempotent under
    /// concurrent deliveries of the SAME id (see `try_handle_wrap`), where the
    /// async relay-DB duplicate check can race two charges for one stored copy.
    charged_wraps: Database<Str, Str>,
    /// Time-ordered eviction index for `charged_wraps`:
    /// `<admitted_at:020>:<event_id_hex>` → "". Entries older than
    /// `CHARGED_WRAP_RETENTION_SECS` are pruned on each mark so the id set
    /// stays bounded — the idempotency window only needs to cover the narrow
    /// race between the async duplicate check and the save (older deliveries
    /// are caught by the relay DB's own duplicate check upstream).
    charged_wraps_gc: Database<Str, Str>,
    write_lock: Mutex<()>,
}

/// Cheaply cloneable handle to the private meta environment.
#[derive(Clone)]
pub struct MetaEnv {
    inner: Arc<MetaInner>,
}

impl std::fmt::Debug for MetaEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetaEnv").finish()
    }
}

impl MetaEnv {
    /// Open (creating if needed) the meta env at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)
            .with_context(|| format!("failed to create private meta dir {}", path.display()))?;
        // SAFETY: standard single-process open; no other process opens this env
        // with different options (mirrors nostr-lmdb usage).
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(META_MAP_SIZE)
                .max_dbs(10)
                .open(path)
                .with_context(|| format!("failed to open private meta env {}", path.display()))?
        };

        let mut wtxn = env.write_txn()?;
        let registrations = env.create_database(&mut wtxn, Some("registrations"))?;
        let key_claims = env.create_database(&mut wtxn, Some("key_claims"))?;
        let tenant_aliases = env.create_database(&mut wtxn, Some("tenant_aliases"))?;
        let ledger = env.create_database(&mut wtxn, Some("ledger"))?;
        let blob_claims = env.create_database(&mut wtxn, Some("blob_claims"))?;
        let alias_claims = env.create_database(&mut wtxn, Some("alias_claims"))?;
        let state_ring = env.create_database(&mut wtxn, Some("state_ring"))?;
        let charged_wraps = env.create_database(&mut wtxn, Some("charged_wraps"))?;
        let charged_wraps_gc = env.create_database(&mut wtxn, Some("charged_wraps_gc"))?;
        wtxn.commit()?;

        Ok(Self {
            inner: Arc::new(MetaInner {
                env,
                registrations,
                key_claims,
                tenant_aliases,
                ledger,
                blob_claims,
                alias_claims,
                state_ring,
                charged_wraps,
                charged_wraps_gc,
                write_lock: Mutex::new(()),
            }),
        })
    }

    /// Run `f` inside a single write transaction, serialized behind the write
    /// lock. Commits on `Ok`, aborts on `Err`.
    pub fn with_write<T>(&self, f: impl FnOnce(&Self, &mut RwTxn) -> Result<T>) -> Result<T> {
        let _guard: MutexGuard<'_, ()> = self.inner.write_lock.lock();
        let mut wtxn = self.inner.env.write_txn()?;
        match f(self, &mut wtxn) {
            Ok(value) => {
                wtxn.commit()?;
                Ok(value)
            }
            Err(e) => {
                wtxn.abort();
                Err(e)
            }
        }
    }

    /// Open a read transaction.
    pub fn read_txn(&self) -> Result<RoTxn<'_>> {
        Ok(self.inner.env.read_txn()?)
    }

    // ---- registrations ------------------------------------------------

    pub fn get_registration(&self, txn: &RoTxn, alias: &str) -> Result<Option<RegistrationRecord>> {
        Ok(self.inner.registrations.get(txn, alias)?)
    }

    pub fn put_registration(
        &self,
        txn: &mut RwTxn,
        alias: &str,
        record: &RegistrationRecord,
    ) -> Result<()> {
        Ok(self.inner.registrations.put(txn, alias, record)?)
    }

    pub fn delete_registration(&self, txn: &mut RwTxn, alias: &str) -> Result<()> {
        self.inner.registrations.delete(txn, alias)?;
        Ok(())
    }

    pub fn registrations_len(&self, txn: &RoTxn) -> Result<u64> {
        Ok(self.inner.registrations.len(txn)?)
    }

    pub fn registrations_is_empty(&self, txn: &RoTxn) -> Result<bool> {
        Ok(self.inner.registrations.is_empty(txn)?)
    }

    // ---- key claims ---------------------------------------------------

    pub fn get_key_claim(&self, txn: &RoTxn, pubkey_hex: &str) -> Result<Option<String>> {
        Ok(self
            .inner
            .key_claims
            .get(txn, pubkey_hex)?
            .map(|s| s.to_string()))
    }

    pub fn put_key_claim(&self, txn: &mut RwTxn, pubkey_hex: &str, alias: &str) -> Result<()> {
        Ok(self.inner.key_claims.put(txn, pubkey_hex, alias)?)
    }

    pub fn delete_key_claim(&self, txn: &mut RwTxn, pubkey_hex: &str) -> Result<()> {
        self.inner.key_claims.delete(txn, pubkey_hex)?;
        Ok(())
    }

    // ---- tenant aliases -----------------------------------------------

    pub fn get_tenant_aliases(&self, txn: &RoTxn, tenant_hex: &str) -> Result<Vec<String>> {
        Ok(self
            .inner
            .tenant_aliases
            .get(txn, tenant_hex)?
            .unwrap_or_default())
    }

    pub fn put_tenant_aliases(
        &self,
        txn: &mut RwTxn,
        tenant_hex: &str,
        aliases: &Vec<String>,
    ) -> Result<()> {
        Ok(self.inner.tenant_aliases.put(txn, tenant_hex, aliases)?)
    }

    // ---- ledger --------------------------------------------------------

    pub fn get_ledger_txn(&self, txn: &RoTxn, key: &str) -> Result<LedgerEntry> {
        Ok(self.inner.ledger.get(txn, key)?.unwrap_or_default())
    }

    pub fn put_ledger(&self, txn: &mut RwTxn, key: &str, entry: &LedgerEntry) -> Result<()> {
        Ok(self.inner.ledger.put(txn, key, entry)?)
    }

    // ---- blob claims ---------------------------------------------------

    pub fn get_blob_claim(&self, txn: &RoTxn, sha256: &str) -> Result<Option<BlobClaim>> {
        Ok(self.inner.blob_claims.get(txn, sha256)?)
    }

    pub fn put_blob_claim(&self, txn: &mut RwTxn, sha256: &str, claim: &BlobClaim) -> Result<()> {
        Ok(self.inner.blob_claims.put(txn, sha256, claim)?)
    }

    pub fn delete_blob_claim(&self, txn: &mut RwTxn, sha256: &str) -> Result<()> {
        self.inner.blob_claims.delete(txn, sha256)?;
        Ok(())
    }

    // ---- alias claim index ---------------------------------------------

    fn alias_claim_key(alias: &str, sha256: &str) -> String {
        format!("{alias}:{sha256}")
    }

    pub fn put_alias_claim(&self, txn: &mut RwTxn, alias: &str, sha256: &str) -> Result<()> {
        Ok(self
            .inner
            .alias_claims
            .put(txn, &Self::alias_claim_key(alias, sha256), sha256)?)
    }

    pub fn delete_alias_claim(&self, txn: &mut RwTxn, alias: &str, sha256: &str) -> Result<()> {
        self.inner
            .alias_claims
            .delete(txn, &Self::alias_claim_key(alias, sha256))?;
        Ok(())
    }

    /// All sha256es claimed by `alias` (prefix scan over the alias index —
    /// O(claims of this alias), never a cross-tenant table scan).
    pub fn alias_claim_shas(&self, txn: &RoTxn, alias: &str) -> Result<Vec<String>> {
        let prefix = format!("{alias}:");
        let mut out = Vec::new();
        for item in self.inner.alias_claims.prefix_iter(txn, &prefix)? {
            let (_, sha) = item?;
            out.push(sha.to_string());
        }
        Ok(out)
    }

    /// Snapshot of all blob claims (sha256 → claim).
    pub fn all_blob_claims(&self, txn: &RoTxn) -> Result<Vec<(String, BlobClaim)>> {
        let mut out = Vec::new();
        for item in self.inner.blob_claims.iter(txn)? {
            let (key, value) = item?;
            out.push((key.to_string(), value));
        }
        Ok(out)
    }

    // ---- state ring (30641 edition history, G7 amendment) --------------

    /// Ring key: `<alias>:<created_at:020>:<event_id_hex>` — lexicographic
    /// order == (created_at, id) order within an alias prefix.
    pub fn state_ring_key(alias: &str, created_at: u64, event_id_hex: &str) -> String {
        format!("{alias}:{created_at:020}:{event_id_hex}")
    }

    pub fn state_ring_contains(&self, txn: &RoTxn, key: &str) -> Result<bool> {
        Ok(self.inner.state_ring.get(txn, key)?.is_some())
    }

    pub fn put_state_ring(&self, txn: &mut RwTxn, key: &str, event_json: &str) -> Result<()> {
        Ok(self.inner.state_ring.put(txn, key, event_json)?)
    }

    pub fn delete_state_ring(&self, txn: &mut RwTxn, key: &str) -> Result<()> {
        self.inner.state_ring.delete(txn, key)?;
        Ok(())
    }

    /// All retained ring entries for an alias, oldest first: (key, event JSON).
    pub fn state_ring_for_alias(&self, txn: &RoTxn, alias: &str) -> Result<Vec<(String, String)>> {
        let prefix = format!("{alias}:");
        let mut out = Vec::new();
        for item in self.inner.state_ring.prefix_iter(txn, &prefix)? {
            let (key, value) = item?;
            out.push((key.to_string(), value.to_string()));
        }
        Ok(out)
    }

    // ---- charged wrap ids (per-id charge idempotency) ------------------

    /// True if this wrap event id (hex) has already been charged.
    pub fn is_wrap_charged(&self, txn: &RoTxn, event_id_hex: &str) -> Result<bool> {
        Ok(self.inner.charged_wraps.get(txn, event_id_hex)?.is_some())
    }

    /// Record that this wrap event id (hex) has been charged, pruning ids
    /// older than `CHARGED_WRAP_RETENTION_SECS` so the set stays bounded.
    pub fn mark_wrap_charged(&self, txn: &mut RwTxn, event_id_hex: &str) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.mark_wrap_charged_at(txn, event_id_hex, now)
    }

    /// `mark_wrap_charged` with an explicit admission time (tests).
    ///
    /// Callers must uphold the check-first invariant: an id is marked at most
    /// once while its entry lives (the production caller checks
    /// `is_wrap_charged` in the same serialized write txn). Marking the same
    /// id at two different times would create two GC keys, and expiry of the
    /// older key would prematurely drop the id from `charged_wraps`.
    pub fn mark_wrap_charged_at(
        &self,
        txn: &mut RwTxn,
        event_id_hex: &str,
        admitted_at: u64,
    ) -> Result<()> {
        self.inner.charged_wraps.put(txn, event_id_hex, "")?;
        self.inner.charged_wraps_gc.put(
            txn,
            &Self::charged_wrap_gc_key(admitted_at, event_id_hex),
            "",
        )?;

        // Evict expired entries. GC keys are zero-padded-time-ordered, so a
        // plain forward scan stops at the first unexpired key.
        let cutoff = admitted_at.saturating_sub(CHARGED_WRAP_RETENTION_SECS);
        let mut expired = Vec::new();
        for item in self.inner.charged_wraps_gc.iter(txn)? {
            let (key, _) = item?;
            let ts: u64 = key
                .get(..20)
                .and_then(|s| s.parse().ok())
                .unwrap_or(u64::MAX);
            if ts > cutoff {
                break;
            }
            expired.push(key.to_string());
        }
        for key in expired {
            self.inner.charged_wraps_gc.delete(txn, &key)?;
            if let Some(id) = key.get(21..) {
                self.inner.charged_wraps.delete(txn, id)?;
            }
        }
        Ok(())
    }

    fn charged_wrap_gc_key(admitted_at: u64, event_id_hex: &str) -> String {
        format!("{admitted_at:020}:{event_id_hex}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A claim written before `stored_at` existed has no such key. It must
    /// still read, as a blob whose storing time is unknown; a claim written
    /// now must carry the time.
    #[test]
    fn claim_written_before_stored_at_still_reads() {
        let old = r#"{"size":7,"aliases":["a"],"unreferenced_since":null,"stored":true,"charged_tenant":"t","charged_alias":"a","spec_charge":null}"#;
        let claim: BlobClaim = serde_json::from_str(old).expect("an old claim must read");
        assert!(claim.stored);
        assert_eq!(claim.stored_at, None);

        let dir = tempfile::tempdir().unwrap();
        let meta = MetaEnv::open(dir.path()).unwrap();
        let sha = "ab".repeat(32);
        let written = BlobClaim {
            stored_at: Some(1_700_000_000),
            ..claim
        };
        meta.with_write(|m, txn| m.put_blob_claim(txn, &sha, &written))
            .unwrap();
        let txn = meta.read_txn().unwrap();
        let read = meta.get_blob_claim(&txn, &sha).unwrap().unwrap();
        assert_eq!(read.stored_at, Some(1_700_000_000));
    }

    /// B3: charged wrap ids must be pruned once they age past the retention
    /// window so the table stays bounded; ids still inside the window and the
    /// just-marked id must survive.
    #[test]
    fn charged_wrap_ids_pruned_after_retention() {
        let dir = tempfile::tempdir().unwrap();
        let meta = MetaEnv::open(dir.path()).unwrap();
        let t0 = 1_000_000_u64;

        meta.with_write(|m, txn| {
            m.mark_wrap_charged_at(txn, "aa", t0)?;
            m.mark_wrap_charged_at(txn, "bb", t0 + CHARGED_WRAP_RETENTION_SECS - 1)
        })
        .unwrap();

        // Both marks are within the window of the latest one: nothing pruned.
        {
            let txn = meta.read_txn().unwrap();
            assert!(meta.is_wrap_charged(&txn, "aa").unwrap());
            assert!(meta.is_wrap_charged(&txn, "bb").unwrap());
        }

        // A mark just past the window must evict only the oldest id.
        meta.with_write(|m, txn| {
            m.mark_wrap_charged_at(txn, "cc", t0 + CHARGED_WRAP_RETENTION_SECS + 1)
        })
        .unwrap();

        let txn = meta.read_txn().unwrap();
        assert!(
            !meta.is_wrap_charged(&txn, "aa").unwrap(),
            "id older than retention must be pruned"
        );
        assert!(
            meta.is_wrap_charged(&txn, "bb").unwrap(),
            "id inside retention must survive"
        );
        assert!(meta.is_wrap_charged(&txn, "cc").unwrap());
        assert_eq!(
            meta.inner.charged_wraps_gc.len(&txn).unwrap(),
            2,
            "eviction index must shrink in lockstep with the id set"
        );
    }
}
