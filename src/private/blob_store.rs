//! Content-addressed private blob store.
//!
//! Layout: `<root>/<aa>/<bb>/<sha256>` (sharded by the first two hex byte
//! pairs) plus `<root>/tmp/` for in-flight streamed uploads. The store is
//! content-blind: bytes are opaque ciphertext; the only invariant is that the
//! filename equals the SHA-256 of the contents.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nostr::hashes::{sha256, Hash, HashEngine};
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use super::meta::{BlobClaim, MetaEnv};
use super::{quota, BlobError, PrivateConfig, UploadReservation};

/// BUD-01 style blob descriptor returned by upload and list routes.
#[derive(Debug, Clone, Serialize)]
pub struct BlobDescriptor {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub uploaded: u64,
}

/// Disk store handle (cheap to clone).
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root.join("tmp"))
            .with_context(|| format!("failed to create blob store at {}", root.display()))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Final sharded path for a (validated, 64-lowercase-hex) sha256.
    pub fn path_for(&self, sha256: &str) -> PathBuf {
        self.root.join(&sha256[0..2]).join(&sha256[2..4]).join(sha256)
    }

    pub fn exists(&self, sha256: &str) -> bool {
        self.path_for(sha256).is_file()
    }

    /// Size of a stored blob, if present.
    pub fn size_of(&self, sha256: &str) -> Option<u64> {
        std::fs::metadata(self.path_for(sha256)).ok().map(|m| m.len())
    }

    /// Remove a stored blob (idempotent).
    pub fn remove(&self, sha256: &str) -> std::io::Result<()> {
        match std::fs::remove_file(self.path_for(sha256)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn new_tmp_path(&self) -> PathBuf {
        self.root
            .join("tmp")
            .join(uuid::Uuid::new_v4().to_string())
    }
}

/// Best-effort removal of a blob file that `finish()` placed but whose claim
/// txn failed to commit. The claim check and the unlink run inside one meta
/// write txn so they are mutually exclusive with GC and with any concurrent
/// `finish()`: if another upload has since adopted the file (committed
/// `stored = true`), it is left in place; while no stored claim exists the
/// file is unreferenced on-disk garbage and is removed. A `stored = false`
/// claim (a 30641 pre-declaration) does not protect the file — such a claim
/// expects an upload, and a later upload simply re-places the bytes.
fn remove_placed_file(meta: &MetaEnv, store: &BlobStore, sha256: &str) -> Result<()> {
    meta.with_write(|m, txn| {
        let claimed = m
            .get_blob_claim(txn, sha256)?
            .map(|c| c.stored)
            .unwrap_or(false);
        if !claimed {
            store
                .remove(sha256)
                .map_err(|e| anyhow::anyhow!("orphan unlink failed: {e}"))?;
        }
        Ok(())
    })
}

/// Streaming upload sink: the HTTP layer feeds request-body frames in, the
/// sink hashes and counts while writing to a temp file, and `finish()`
/// verifies + renames + claims + charges. Dropping an unfinished sink removes
/// the temp file.
pub struct UploadSink {
    meta: MetaEnv,
    store: BlobStore,
    cfg: PrivateConfig,
    tenant_hex: String,
    alias: String,
    expected_sha: String,
    declared_len: u64,
    /// min(declared_len, max_blob_bytes) — overruns abort with 413.
    limit: u64,
    written: u64,
    engine: sha256::HashEngine,
    file: Option<tokio::fs::File>,
    tmp_path: PathBuf,
    finished: bool,
    /// Held for the lifetime of the sink: releases the in-flight
    /// byte/concurrency reservation on drop or finish.
    _reservation: UploadReservation,
}

impl UploadSink {
    pub(crate) async fn create(
        meta: MetaEnv,
        store: BlobStore,
        cfg: PrivateConfig,
        tenant_hex: String,
        alias: String,
        expected_sha: String,
        declared_len: u64,
        reservation: UploadReservation,
    ) -> Result<Self, BlobError> {
        let tmp_path = store.new_tmp_path();
        let file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| BlobError::Internal(format!("failed to create temp file: {e}")))?;
        let limit = declared_len.min(cfg.max_blob_bytes);
        Ok(Self {
            meta,
            store,
            cfg,
            tenant_hex,
            alias,
            expected_sha,
            declared_len,
            limit,
            written: 0,
            engine: sha256::Hash::engine(),
            file: Some(file),
            tmp_path,
            finished: false,
            _reservation: reservation,
        })
    }

    /// Total bytes accepted so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Feed one request-body chunk. Fails with `BlobError::TooLarge` (413) as
    /// soon as the stream overruns min(declared Content-Length, max blob size).
    pub async fn write_chunk(&mut self, data: &[u8]) -> Result<(), BlobError> {
        self.written = self.written.saturating_add(data.len() as u64);
        if self.written > self.limit {
            return Err(BlobError::TooLarge);
        }
        self.engine.input(data);
        match self.file.as_mut() {
            Some(file) => file
                .write_all(data)
                .await
                .map_err(|e| BlobError::Internal(format!("blob write failed: {e}"))),
            None => Err(BlobError::Internal("upload sink already closed".into())),
        }
    }

    /// Verify the streamed hash, move the temp file into place, and claim +
    /// charge atomically. Idempotent for blobs that already exist (adds the
    /// claim, no double-charge).
    pub async fn finish(mut self) -> Result<BlobDescriptor, BlobError> {
        // Actual bytes must match the declared Content-Length.
        if self.written != self.declared_len {
            self.cleanup();
            return Err(BlobError::BadRequest(format!(
                "body length {} does not match Content-Length {}",
                self.written, self.declared_len
            )));
        }

        let engine = std::mem::replace(&mut self.engine, sha256::Hash::engine());
        let actual = sha256::Hash::from_engine(engine).to_string();
        if actual != self.expected_sha {
            self.cleanup();
            return Err(BlobError::BadRequest(format!(
                "sha256 mismatch: body hashed to {actual}, auth committed to {}",
                self.expected_sha
            )));
        }

        // fsync before rename so a crash cannot leave a corrupt final blob.
        if let Some(file) = self.file.take() {
            file.sync_all()
                .await
                .map_err(|e| BlobError::Internal(format!("fsync failed: {e}")))?;
            drop(file);
        }

        let final_path = self.store.path_for(&self.expected_sha);
        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BlobError::Internal(format!("mkdir failed: {e}")))?;
        }

        let size = self.written;
        let sha = self.expected_sha.clone();
        let tenant = self.tenant_hex.clone();
        let alias = self.alias.clone();
        let cfg = self.cfg.clone();
        let tmp_path = self.tmp_path.clone();

        // Existence check, rename, and claim/charge ALL inside the one meta
        // write txn. GC unlinks blob files under the same write lock, so the
        // `file_present` decision cannot go stale between check and commit
        // (checking outside the lock was a TOCTOU: GC could delete the file
        // and claim after a `file_present = true` check, and this txn would
        // then commit a fresh `stored = true` claim for a file that no longer
        // exists — a live alias pointing at silent blob loss).
        //
        // The rename is the LAST fallible step in the closure: if it fails,
        // the txn aborts and the charge/claim roll back with it, so the ledger
        // never carries a phantom charge for bytes that were never placed.
        // Conversely, if the LMDB commit fails after a successful rename, the
        // error path below unlinks the file we just placed (`renamed` flag) so
        // no unclaimed orphan is left on disk.
        let renamed = std::cell::Cell::new(false);
        let charged = self.meta.with_write(|meta, txn| {
            let file_present = final_path.is_file();
            let mut claim = meta.get_blob_claim(txn, &sha)?.unwrap_or(BlobClaim {
                size,
                aliases: Vec::new(),
                unreferenced_since: None,
                stored: false,
                charged_tenant: None,
                charged_alias: None,
            });

            let mut charged = false;
            if !claim.stored && !file_present {
                if !quota::check(meta, txn, &cfg, &tenant, &alias, size)? {
                    return Err(anyhow::anyhow!("quota"));
                }
                quota::charge(meta, txn, &tenant, &alias, size, true)?;
                claim.stored = true;
                claim.size = size;
                claim.charged_tenant = Some(tenant.clone());
                claim.charged_alias = Some(alias.clone());
                charged = true;
            } else {
                claim.stored = true;
                claim.size = size;
            }
            if !claim.aliases.contains(&alias) {
                claim.aliases.push(alias.clone());
                meta.put_alias_claim(txn, &alias, &sha)?;
            }
            claim.unreferenced_since = None;
            meta.put_blob_claim(txn, &sha, &claim)?;
            // Last fallible step: place the bytes. Skip when the file is
            // already there (idempotent re-upload / adopt); when the claim
            // said stored but the file is gone (crash window), this restores
            // the bytes without a second charge.
            if !file_present {
                std::fs::rename(&tmp_path, &final_path)
                    .map_err(|e| anyhow::anyhow!("rename failed: {e}"))?;
                renamed.set(true);
            }
            Ok(charged)
        });

        match charged {
            Ok(charged) => {
                self.finished = true;
                if !renamed.get() {
                    // Blob was already present: discard our tmp copy.
                    self.cleanup();
                }
                if charged {
                    crate::metrics::record_private_blob_upload(size);
                }
                Ok(BlobDescriptor {
                    url: format!("https://{}/{}", self.cfg.domain, sha),
                    sha256: sha,
                    size,
                    uploaded: nostr::Timestamp::now().as_secs(),
                })
            }
            Err(e) => {
                // The txn aborted. If the rename inside it had already
                // succeeded (i.e. the LMDB commit itself failed), the file we
                // placed is an unclaimed orphan. Unlink it — but the check and
                // the unlink must run under the write lock: a concurrent
                // finish() may already have adopted the file with a committed
                // `stored = true` claim, and deleting it then would recreate
                // the exact silent-loss state this ordering exists to prevent.
                if renamed.get() {
                    let _ = remove_placed_file(&self.meta, &self.store, &sha);
                }
                self.cleanup();
                if e.to_string() == "quota" {
                    Err(BlobError::QuotaExceeded)
                } else {
                    Err(BlobError::Internal(format!("meta update failed: {e}")))
                }
            }
        }
    }

    fn cleanup(&mut self) {
        self.file.take();
        let _ = std::fs::remove_file(&self.tmp_path);
        self.finished = true;
    }
}

impl Drop for UploadSink {
    fn drop(&mut self) {
        if !self.finished {
            self.file.take();
            let _ = std::fs::remove_file(&self.tmp_path);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RegistrationMode;
    use crate::private::meta::LEDGER_GLOBAL_KEY;
    use crate::private::InflightUploads;
    use std::sync::Arc;

    fn test_cfg(quota_repo_bytes: u64) -> PrivateConfig {
        PrivateConfig {
            domain: "test.local".into(),
            registration_mode: RegistrationMode::Open,
            pow_bits: 0,
            tenant_whitelist: vec![],
            max_blob_bytes: 1 << 20,
            max_event_bytes: 1 << 20,
            quota_tenant_bytes: 1 << 20,
            quota_repo_bytes,
            global_budget_bytes: 1 << 20,
            max_aliases_per_tenant: 8,
            max_write_keys_per_alias: 8,
            state_history_editions: 3,
            gc_grace_secs: 3600,
            gc_interval_secs: 60,
            offboard_retention_secs: 0,
            accept_direct_invites: false,
            per_tenant_metrics: false,
            mirror_enable: false,
            mirror_peer_urls: None,
            mirror_max_concurrency: 1,
            mirror_fetch_timeout_secs: 5,
            mirror_allow_private_ips: false,
            policy_fingerprint: String::new(),
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        meta: MetaEnv,
        store: BlobStore,
        cfg: PrivateConfig,
    }

    impl Harness {
        fn new(quota_repo_bytes: u64) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let meta = MetaEnv::open(&dir.path().join("meta")).unwrap();
            let store = BlobStore::open(&dir.path().join("blobs")).unwrap();
            Self {
                _dir: dir,
                meta,
                store,
                cfg: test_cfg(quota_repo_bytes),
            }
        }

        /// One full streamed upload of `data` by tenant/alias ("tenant"/"alias").
        async fn upload(&self, data: &[u8]) -> Result<BlobDescriptor, BlobError> {
            let sha = sha256::Hash::hash(data).to_string();
            let reservation = UploadReservation {
                inflight: Arc::new(parking_lot::Mutex::new(InflightUploads::default())),
                bytes: 0,
            };
            let mut sink = UploadSink::create(
                self.meta.clone(),
                self.store.clone(),
                self.cfg.clone(),
                "tenant".to_string(),
                "alias".to_string(),
                sha,
                data.len() as u64,
                reservation,
            )
            .await?;
            sink.write_chunk(data).await?;
            sink.finish().await
        }

        /// (tenant, alias, global) blob-byte ledger totals.
        fn ledger_blob_bytes(&self) -> (u64, u64, u64) {
            let txn = self.meta.read_txn().unwrap();
            let t = self
                .meta
                .get_ledger_txn(&txn, &quota::tenant_key("tenant"))
                .unwrap()
                .blob_bytes;
            let r = self
                .meta
                .get_ledger_txn(&txn, &quota::alias_key("alias"))
                .unwrap()
                .blob_bytes;
            let g = self
                .meta
                .get_ledger_txn(&txn, LEDGER_GLOBAL_KEY)
                .unwrap()
                .blob_bytes;
            (t, r, g)
        }
    }

    #[tokio::test]
    async fn fresh_upload_places_file_charges_and_claims() {
        let h = Harness::new(1 << 20);
        let data = vec![7u8; 512];
        let sha = sha256::Hash::hash(&data).to_string();

        let d = h.upload(&data).await.unwrap();
        assert_eq!(d.size, 512);
        assert!(h.store.exists(&sha), "blob file must be placed");

        let claim = {
            let txn = h.meta.read_txn().unwrap();
            h.meta.get_blob_claim(&txn, &sha).unwrap().unwrap()
        };
        assert!(claim.stored);
        assert_eq!(claim.aliases, vec!["alias".to_string()]);
        assert_eq!(claim.charged_tenant.as_deref(), Some("tenant"));
        assert_eq!(claim.charged_alias.as_deref(), Some("alias"));
        assert_eq!(h.ledger_blob_bytes(), (512, 512, 512));
    }

    #[tokio::test]
    async fn reupload_present_blob_does_not_double_charge() {
        let h = Harness::new(1 << 20);
        let data = vec![9u8; 1024];
        let sha = sha256::Hash::hash(&data).to_string();

        h.upload(&data).await.unwrap();
        h.upload(&data).await.unwrap();

        assert!(h.store.exists(&sha));
        assert_eq!(
            h.ledger_blob_bytes(),
            (1024, 1024, 1024),
            "idempotent re-upload must not re-charge"
        );
        let claim = {
            let txn = h.meta.read_txn().unwrap();
            h.meta.get_blob_claim(&txn, &sha).unwrap().unwrap()
        };
        assert_eq!(claim.aliases.len(), 1, "alias must not be duplicated");
    }

    /// Regression pin for the finish()/GC TOCTOU: the store can legitimately
    /// reach "claim says stored, file gone" (GC unlinks file + claim under the
    /// write lock; a crash in that window, or an operator delete, lands here).
    /// A re-upload must restore the bytes WITHOUT a second charge, and finish
    /// must never commit `stored = true` while leaving no file on disk.
    #[tokio::test]
    async fn reupload_restores_missing_file_without_recharge() {
        let h = Harness::new(1 << 20);
        let data = vec![3u8; 256];
        let sha = sha256::Hash::hash(&data).to_string();

        h.upload(&data).await.unwrap();
        std::fs::remove_file(h.store.path_for(&sha)).unwrap();
        assert!(!h.store.exists(&sha));

        h.upload(&data).await.unwrap();
        assert!(h.store.exists(&sha), "re-upload must restore the bytes");
        assert_eq!(
            h.ledger_blob_bytes(),
            (256, 256, 256),
            "bytes were already charged; restore must not re-charge"
        );
        let stored = {
            let txn = h.meta.read_txn().unwrap();
            h.meta.get_blob_claim(&txn, &sha).unwrap().unwrap().stored
        };
        assert!(stored);
    }

    /// An orphaned file (present on disk, no claim — e.g. a crash between the
    /// rename and the LMDB commit) is adopted: claim committed `stored = true`
    /// with no charge, matching the pre-B2 policy for existing content.
    #[tokio::test]
    async fn orphan_file_is_adopted_without_charge() {
        let h = Harness::new(1 << 20);
        let data = vec![11u8; 128];
        let sha = sha256::Hash::hash(&data).to_string();

        let path = h.store.path_for(&sha);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &data).unwrap();

        h.upload(&data).await.unwrap();
        assert!(h.store.exists(&sha));
        assert_eq!(
            h.ledger_blob_bytes(),
            (0, 0, 0),
            "adopting an already-present file must not charge"
        );
        let claim = {
            let txn = h.meta.read_txn().unwrap();
            h.meta.get_blob_claim(&txn, &sha).unwrap().unwrap()
        };
        assert!(claim.stored);
        assert_eq!(claim.aliases, vec!["alias".to_string()]);
    }

    #[tokio::test]
    async fn quota_rejection_places_no_file_and_charges_nothing() {
        let h = Harness::new(100);
        let data = vec![5u8; 512];
        let sha = sha256::Hash::hash(&data).to_string();

        let err = h.upload(&data).await.unwrap_err();
        assert!(matches!(err, BlobError::QuotaExceeded));

        assert!(!h.store.exists(&sha), "rejected upload must leave no file");
        let no_stored_claim = {
            let txn = h.meta.read_txn().unwrap();
            h.meta
                .get_blob_claim(&txn, &sha)
                .unwrap()
                .map(|c| !c.stored)
                .unwrap_or(true)
        };
        assert!(no_stored_claim, "no stored claim may survive rejection");
        assert_eq!(h.ledger_blob_bytes(), (0, 0, 0));
    }

    /// Commit-failure cleanup (F1): the placed file is unlinked only while no
    /// stored claim references it. A concurrent finish() may have adopted the
    /// orphan between our failed commit and the cleanup — deleting it then
    /// would leave a committed `stored = true` claim pointing at nothing.
    #[tokio::test]
    async fn commit_failure_cleanup_preserves_adopted_file() {
        let h = Harness::new(1 << 20);
        let data = vec![13u8; 64];
        let sha = sha256::Hash::hash(&data).to_string();

        // Simulate: our rename succeeded, our commit failed (no claim), and a
        // concurrent upload then adopted the file (stored claim committed).
        let path = h.store.path_for(&sha);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &data).unwrap();
        h.upload(&data).await.unwrap(); // adopts the orphan -> stored = true

        remove_placed_file(&h.meta, &h.store, &sha).unwrap();
        assert!(h.store.exists(&sha), "an adopted file must survive the cleanup");
    }

    #[tokio::test]
    async fn commit_failure_cleanup_removes_unclaimed_orphan() {
        let h = Harness::new(1 << 20);
        let data = vec![15u8; 64];
        let sha = sha256::Hash::hash(&data).to_string();
        let path = h.store.path_for(&sha);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        // No claim at all: the file we placed is unreferenced garbage.
        std::fs::write(&path, &data).unwrap();
        remove_placed_file(&h.meta, &h.store, &sha).unwrap();
        assert!(!h.store.exists(&sha), "unclaimed orphan must be unlinked");

        // A stored=false claim (30641 pre-declaration) does not protect it,
        // and the claim itself must survive — only the file goes.
        std::fs::write(&path, &data).unwrap();
        h.meta
            .with_write(|m, txn| {
                m.put_blob_claim(
                    txn,
                    &sha,
                    &BlobClaim {
                        size: data.len() as u64,
                        aliases: vec!["alias".to_string()],
                        unreferenced_since: None,
                        stored: false,
                        charged_tenant: None,
                        charged_alias: None,
                    },
                )
            })
            .unwrap();
        remove_placed_file(&h.meta, &h.store, &sha).unwrap();
        assert!(
            !h.store.exists(&sha),
            "a pre-declared (unstored) claim must not protect the orphan"
        );
        let stored_claim_survives = {
            let txn = h.meta.read_txn().unwrap();
            h.meta.get_blob_claim(&txn, &sha).unwrap().is_some()
        };
        assert!(stored_claim_survives);
    }
}
