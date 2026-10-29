//! Content-addressed private blob store.
//!
//! Layout: `<root>/<aa>/<bb>/<sha256>` (sharded by the first two hex byte
//! pairs) plus `<root>/tmp/` for in-flight streamed uploads. The store is
//! content-blind: bytes are opaque ciphertext; the only invariant is that the
//! filename equals the SHA-256 of the contents.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bitcoin_hashes::{sha256, HashEngine};
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use super::claims;
use super::denylist::{self, SharedDenylist};
use super::meta::MetaEnv;
use super::{quota, BlobError, PrivateConfig, UploadOrigin, UploadReservation};

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
    /// Open the store, creating it if needed, and clear what earlier runs
    /// left in `<root>/tmp`.
    ///
    /// The sweep is safe only because nothing can be uploading yet: the
    /// service opens the store while it is being constructed, before the
    /// mirror task is spawned and before the HTTP listener serves a request,
    /// and one process owns a data directory. Opening a second handle on a
    /// store that is in use would delete uploads in flight. A `tmp` that is
    /// a link to some other directory is left unswept.
    pub fn open(root: &Path) -> Result<Self> {
        let tmp = root.join("tmp");
        std::fs::create_dir_all(&tmp)
            .with_context(|| format!("failed to create blob store at {}", root.display()))?;
        // The entries are judged without following links, and so is the
        // directory: a tmp that is a link leads somewhere this store does
        // not own.
        match std::fs::symlink_metadata(&tmp) {
            Ok(meta) if meta.file_type().is_dir() => {
                sweep_tmp(&tmp);
            }
            Ok(_) => tracing::warn!(
                "{} is not a plain directory; old temp files were not cleared",
                tmp.display()
            ),
            Err(e) => tracing::warn!("could not inspect {}: {e}", tmp.display()),
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Final sharded path for a (validated, 64-lowercase-hex) sha256.
    pub fn path_for(&self, sha256: &str) -> PathBuf {
        self.root
            .join(&sha256[0..2])
            .join(&sha256[2..4])
            .join(sha256)
    }

    pub fn exists(&self, sha256: &str) -> bool {
        self.path_for(sha256).is_file()
    }

    /// Size of a stored blob, if present.
    pub fn size_of(&self, sha256: &str) -> Option<u64> {
        std::fs::metadata(self.path_for(sha256))
            .ok()
            .map(|m| m.len())
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
        self.root.join("tmp").join(uuid::Uuid::new_v4().to_string())
    }
}

/// Remove the temp files of uploads that an earlier run never finished (a
/// crash or a kill leaves them behind, and nothing else ever deletes them).
///
/// Only the directory's own entries are judged, each by `symlink_metadata`:
/// a regular file or a symlink is unlinked, so a link is removed and never
/// followed, and a directory is left alone and never entered. A failure is
/// logged and the sweep moves on: leftover temp files must not stop a node
/// from starting. Returns the number of entries and bytes removed.
fn sweep_tmp(tmp: &Path) -> (u64, u64) {
    let entries = match std::fs::read_dir(tmp) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(
                "could not read {} to clear old temp files: {e}",
                tmp.display()
            );
            return (0, 0);
        }
    };
    let mut removed = 0_u64;
    let mut bytes = 0_u64;
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                tracing::warn!("could not read an entry of {}: {e}", tmp.display());
                continue;
            }
        };
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                tracing::warn!("could not inspect {}: {e}", path.display());
                continue;
            }
        };
        let kind = meta.file_type();
        if !(kind.is_file() || kind.is_symlink()) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                removed += 1;
                bytes = bytes.saturating_add(meta.len());
            }
            Err(e) => tracing::warn!("could not remove old temp file {}: {e}", path.display()),
        }
    }
    if removed > 0 {
        tracing::info!(
            entries = removed,
            bytes,
            "removed temp files left by earlier runs from {}",
            tmp.display()
        );
    }
    (removed, bytes)
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
///
/// A client's upload makes its repository a referrer of the blob; the
/// mirror's only stores bytes a referrer of this node already waits for
/// (`origin`).
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
    /// Node-local takedown list, re-checked inside finish()'s meta txn
    /// (Phase-4b D1): an upload whose hash became denylisted between PUT
    /// begin and finish must not land.
    denylist: SharedDenylist,
    /// Who is storing: a client's `PUT /upload` or the blob mirror.
    origin: UploadOrigin,
}

impl UploadSink {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create(
        meta: MetaEnv,
        store: BlobStore,
        cfg: PrivateConfig,
        tenant_hex: String,
        alias: String,
        expected_sha: String,
        declared_len: u64,
        reservation: UploadReservation,
        denylist: SharedDenylist,
        origin: UploadOrigin,
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
            denylist,
            origin,
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
    /// charge atomically. Idempotent for blobs that already exist: a
    /// repository that already references the blob is not charged again.
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
        let denylist = self.denylist.clone();
        let origin = self.origin;
        let now = nostr::prelude::Timestamp::now().as_secs();

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
        let outcome = self.meta.with_write(|meta, txn| {
            // R2-C (verify round 2): FIRST fallible statement — re-verify
            // the uploader's registration inside the charge txn, before the
            // file-existence check (so the rename stays the last fallible
            // step). The upload streamed between auth and finish; an
            // eviction or honored deletion in between must not let the
            // claim + charge commit against a dead scope. The bar here is
            // existence + same tenant (NOT the latest event id): an honest
            // same-tenant rotation mid-stream must not kill a legit upload.
            let live = meta
                .get_registration(txn, &alias)?
                .map(|r| r.tombstoned_at.is_none() && r.tenant_hex == tenant)
                .unwrap_or(false);
            if !live {
                return Err(anyhow::anyhow!("registration gone"));
            }
            // Phase-4b D1: denylist re-check inside the charge txn (R2-C
            // pattern). The body streamed between PUT begin and finish; a
            // denylist reload in between must not let the bytes land (they
            // would resurrect content the reload's purge-on-add just
            // removed). Like the registration re-verify this precedes the
            // file-existence check, keeping the rename the last fallible
            // step, and the abort takes the shared commit-failure cleanup
            // path below (tmp unlink + reservation drop; nothing placed).
            if denylist::read_set(&denylist).contains(&sha) {
                return Err(anyhow::anyhow!("denylisted"));
            }
            let file_present = final_path.is_file();
            let before = meta.get_blob_claim(txn, &sha)?;
            // The mirror adds no reference of its own: the pair's other node
            // would know nothing of it, and the repository it fetched for
            // may have stopped referencing the blob since. It stores only
            // what a referrer here still waits for, and the bytes then
            // settle that referrer's charge with every other one.
            if origin == UploadOrigin::Mirror
                && !before
                    .as_ref()
                    .is_some_and(|claim| claim.aliases.iter().any(|a| a == &alias))
            {
                return Err(anyhow::anyhow!("unreferenced"));
            }
            let newly_stored = !before.as_ref().is_some_and(|claim| claim.stored) && !file_present;
            let mut claim = before.clone().unwrap_or_else(|| claims::new_claim(size));

            // Decision D4: the bytes set every repository's charge to their
            // size, and a client's upload makes its repository pay for them
            // like any other referrer, also for bytes another account
            // stored or an earlier run left on disk. The uploader's own
            // declared charge is part of the moves, so a declare-then-upload
            // nets out. Another repository the stored size raises past its
            // own caps stops referencing the blob rather than being carried
            // over them; the uploader's scopes and the node's are judged
            // with every move.
            let mut moves = claims::settle_stored(&mut claim, size, now);
            if origin == UploadOrigin::Client {
                moves.extend(claims::attach(&mut claim, &tenant, &alias, size));
            }
            claims::detach_unaffordable(meta, txn, &cfg, &mut claim, &alias, &mut moves, now)?;
            if !quota::fits(meta, txn, &cfg, &tenant, &alias, 0, &moves)? {
                return Err(anyhow::anyhow!("quota"));
            }
            // Kept from the first time the bytes were stored here: a repeat
            // upload, or one that restores a lost file, reports that time
            // and does not move it.
            let stored_at = claim.stored_at.unwrap_or(now);
            claims::commit(meta, txn, &sha, before.as_ref(), Some(&claim), &moves)?;
            // Last fallible step: place the bytes. Skip when the file is
            // already there (idempotent re-upload / adopt); when the claim
            // said stored but the file is gone (crash window), this restores
            // the bytes without a second charge.
            if !file_present {
                std::fs::rename(&tmp_path, &final_path)
                    .map_err(|e| anyhow::anyhow!("rename failed: {e}"))?;
                renamed.set(true);
            }
            Ok((newly_stored, stored_at))
        });

        match outcome {
            Ok((newly_stored, stored_at)) => {
                self.finished = true;
                if !renamed.get() {
                    // Blob was already present: discard our tmp copy.
                    self.cleanup();
                }
                if newly_stored {
                    crate::metrics::record_private_blob_upload(size);
                }
                Ok(BlobDescriptor {
                    url: format!("https://{}/{}", self.cfg.service_address, sha),
                    sha256: sha,
                    size,
                    uploaded: stored_at,
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
                } else if e.to_string() == "registration gone" {
                    // R2-C: the registration died mid-stream. The re-check
                    // precedes the rename, so no file was placed on this
                    // path (the tmp unlink above + reservation drop are the
                    // whole cleanup); `remove_placed_file` stays exclusively
                    // for LMDB-commit failures after a successful rename.
                    Err(BlobError::Forbidden(
                        "attributed alias is not a live registration".into(),
                    ))
                } else if e.to_string() == "denylisted" {
                    // D1: the hash was denylisted mid-stream. Same cleanup
                    // shape as "registration gone" (re-check precedes the
                    // rename), but the status is the read path's 451.
                    Err(BlobError::Denylisted)
                } else if e.to_string() == "unreferenced" {
                    // The mirror's fetch outlived the reference it was for.
                    // Same cleanup shape: nothing was placed.
                    Err(BlobError::Forbidden(
                        "the blob is no longer referenced by this repository".into(),
                    ))
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
    use crate::grasp_p::meta::{BlobClaim, ClaimCharge, LEDGER_GLOBAL_KEY};

    fn charge(tenant: &str, alias: &str, bytes: u64) -> ClaimCharge {
        ClaimCharge {
            tenant: tenant.to_string(),
            alias: alias.to_string(),
            bytes,
        }
    }

    /// A blob `alias` of `tenant` declared at `declared` bytes and nobody
    /// stored, as a 30641 leaves it.
    fn declare(meta: &MetaEnv, sha: &str, tenant: &str, alias: &str, declared: u64) {
        meta.with_write(|m, txn| claims::attach_to(m, txn, sha, tenant, alias, declared))
            .unwrap();
    }

    fn test_cfg(quota_repo_bytes: u64) -> PrivateConfig {
        PrivateConfig {
            domain: "test.local".into(),
            service_address: "test.local/base".into(),
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
            accept_legacy_wrap_kind: true,
            mirror_enable: false,
            mirror_peer_urls: None,
            mirror_max_concurrency: 1,
            mirror_fetch_timeout_secs: 5,
            mirror_retry_base_secs: 1,
            mirror_retry_max_secs: 60,
            mirror_max_attempts_per_min: 0,
            mirror_allow_private_ips: false,
            sync_peer_relays: Default::default(),
            policy_fingerprint: String::new(),
            write_blacklist: Default::default(),
            write_rate_capacity: 0,
            write_rate_refill_per_min: 0,
            registration_replace_capacity: 0,
            registration_replace_refill_per_hour: 0,
            denylist_paths: vec![],
            denylist_reload_secs: 0,
            max_uploads_per_tenant: 0,
            upload_min_bytes_per_sec: 0,
        }
    }

    /// A live registration for the harness ("tenant", "alias") — finish()
    /// re-verifies it inside the charge txn (R2-C).
    fn test_registration(tenant: &str, event_id: &str) -> crate::grasp_p::meta::RegistrationRecord {
        crate::grasp_p::meta::RegistrationRecord {
            tenant_hex: tenant.to_string(),
            event_id: event_id.to_string(),
            created_at: 1,
            w_keys: vec![],
            aux_keys: vec![],
            relays: vec![],
            servers: vec![],
            quota_class: None,
            registered_at: 1,
            tombstoned_at: None,
            first_created_at: None,
            first_event_id: None,
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        meta: MetaEnv,
        store: BlobStore,
        cfg: PrivateConfig,
        denylist: SharedDenylist,
    }

    impl Harness {
        fn new(quota_repo_bytes: u64) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let meta = MetaEnv::open(&dir.path().join("meta")).unwrap();
            let store = BlobStore::open(&dir.path().join("blobs")).unwrap();
            meta.with_write(|m, txn| {
                m.put_registration(txn, "alias", &test_registration("tenant", "ed1"))
            })
            .unwrap();
            Self {
                _dir: dir,
                meta,
                store,
                cfg: test_cfg(quota_repo_bytes),
                denylist: std::sync::Arc::new(std::sync::RwLock::new(
                    std::collections::HashSet::new(),
                )),
            }
        }

        /// One full streamed upload of `data` by tenant/alias ("tenant"/"alias").
        async fn upload(&self, data: &[u8]) -> Result<BlobDescriptor, BlobError> {
            self.store_as("tenant", "alias", data, UploadOrigin::Client)
                .await
        }

        /// A live registration of `alias` under `tenant`, besides the
        /// harness's own.
        fn register(&self, tenant: &str, alias: &str) {
            self.meta
                .with_write(|m, txn| {
                    m.put_registration(txn, alias, &test_registration(tenant, "ed"))
                })
                .unwrap();
        }

        /// One full streamed store of `data` for tenant/alias by `origin`.
        async fn store_as(
            &self,
            tenant: &str,
            alias: &str,
            data: &[u8],
            origin: UploadOrigin,
        ) -> Result<BlobDescriptor, BlobError> {
            let sha = sha256::Hash::hash(data).to_string();
            let reservation = UploadReservation::detached();
            let mut sink = UploadSink::create(
                self.meta.clone(),
                self.store.clone(),
                self.cfg.clone(),
                tenant.to_string(),
                alias.to_string(),
                sha,
                data.len() as u64,
                reservation,
                self.denylist.clone(),
                origin,
            )
            .await?;
            sink.write_chunk(data).await?;
            sink.finish().await
        }

        /// (repository, account) blob-byte ledger totals of any pair.
        fn scope_bytes(&self, tenant: &str, alias: &str) -> (u64, u64) {
            let txn = self.meta.read_txn().unwrap();
            let r = self
                .meta
                .get_ledger_txn(&txn, &quota::alias_key(alias))
                .unwrap()
                .blob_bytes;
            let t = self
                .meta
                .get_ledger_txn(&txn, &quota::tenant_key(tenant))
                .unwrap()
                .blob_bytes;
            (r, t)
        }

        fn claim(&self, sha: &str) -> Option<BlobClaim> {
            let txn = self.meta.read_txn().unwrap();
            self.meta.get_blob_claim(&txn, sha).unwrap()
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
        // The descriptor is built from the service address (domain plus
        // mount path), not from the bare domain.
        assert_eq!(d.url, format!("https://test.local/base/{sha}"));
        assert!(h.store.exists(&sha), "blob file must be placed");

        let claim = {
            let txn = h.meta.read_txn().unwrap();
            h.meta.get_blob_claim(&txn, &sha).unwrap().unwrap()
        };
        assert!(claim.stored);
        assert_eq!(claim.aliases, vec!["alias".to_string()]);
        assert_eq!(claim.charges, vec![charge("tenant", "alias", 512)]);
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
    /// rename and the LMDB commit) is adopted, and the repository that
    /// uploads it pays for it like for any blob it references (decision D4):
    /// bytes already on disk are no free storage.
    #[tokio::test]
    async fn orphan_file_is_adopted_and_charged() {
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
            (128, 128, 128),
            "adopting an already-present file charges the uploader"
        );
        let claim = h.claim(&sha).unwrap();
        assert!(claim.stored);
        assert_eq!(claim.aliases, vec!["alias".to_string()]);
        assert_eq!(claim.charges, vec![charge("tenant", "alias", 128)]);
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
        assert!(
            h.store.exists(&sha),
            "an adopted file must survive the cleanup"
        );
    }

    /// A blob a 30641 declared at a size it does not have, then uploaded:
    /// the declarer's charge is set to the stored size, never doubled.
    #[tokio::test]
    async fn upload_sets_the_declared_charge_to_the_stored_size() {
        let h = Harness::new(1 << 20);
        let data = vec![21u8; 300];
        let sha = sha256::Hash::hash(&data).to_string();

        declare(&h.meta, &sha, "tenant", "alias", 500);
        assert_eq!(h.ledger_blob_bytes(), (500, 500, 500));

        h.upload(&data).await.unwrap();
        assert_eq!(
            h.ledger_blob_bytes(),
            (300, 300, 300),
            "the declared 500 becomes the stored 300: one charge"
        );
        let claim = h.claim(&sha).unwrap();
        assert!(claim.stored);
        assert_eq!(claim.charges, vec![charge("tenant", "alias", 300)]);
        assert_eq!(claim.size, 300);
    }

    /// FF (verify round 1): the uploader's own declared charge nets out of
    /// the quota decision. With the repo cap BETWEEN the stored size and
    /// declared + stored (cap 600, declared 500, stored 300), the upload
    /// passes only if the declared charge is counted as replaced, not
    /// added to.
    #[tokio::test]
    async fn upload_nets_the_uploaders_own_declared_charge() {
        let h = Harness::new(600);
        let data = vec![31u8; 300];
        let sha = sha256::Hash::hash(&data).to_string();
        declare(&h.meta, &sha, "tenant", "alias", 500);

        h.upload(&data)
            .await
            .expect("upload must pass: its own declared charge is replaced");
        assert_eq!(h.ledger_blob_bytes(), (300, 300, 300));
    }

    /// Adopting an already-present file keeps the declarer's charge, at the
    /// stored size.
    #[tokio::test]
    async fn declared_charge_is_kept_when_an_orphan_file_is_adopted() {
        let h = Harness::new(1 << 20);
        let data = vec![23u8; 128];
        let sha = sha256::Hash::hash(&data).to_string();

        let path = h.store.path_for(&sha);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &data).unwrap();
        declare(&h.meta, &sha, "tenant", "alias", 128);

        h.upload(&data).await.unwrap();
        assert_eq!(h.ledger_blob_bytes(), (128, 128, 128), "charged once");
        let claim = h.claim(&sha).unwrap();
        assert!(claim.stored);
        assert_eq!(claim.charges, vec![charge("tenant", "alias", 128)]);
    }

    /// Issue 5 at the upload: a repository that uploads bytes another
    /// account already stored pays for them like the first one, and is
    /// refused when it cannot afford them. Without the charge the second
    /// account would hold the bytes at no cost; without the check it could
    /// go past its quota.
    #[tokio::test]
    async fn uploading_another_accounts_stored_blob_charges_the_uploader() {
        let mut h = Harness::new(1 << 20);
        h.register("other-tenant", "other-alias");
        h.register("third-tenant", "third-alias");
        let data = vec![61u8; 400];
        let sha = sha256::Hash::hash(&data).to_string();
        h.upload(&data).await.unwrap();

        h.store_as("other-tenant", "other-alias", &data, UploadOrigin::Client)
            .await
            .unwrap();
        assert_eq!(h.scope_bytes("tenant", "alias"), (400, 400));
        assert_eq!(h.scope_bytes("other-tenant", "other-alias"), (400, 400));
        let claim = h.claim(&sha).unwrap();
        assert_eq!(claim.aliases.len(), 2);
        assert_eq!(claim.charges.len(), 2);

        // A third repository with room for 399 bytes is refused.
        h.cfg.quota_repo_bytes = 399;
        let err = h
            .store_as("third-tenant", "third-alias", &data, UploadOrigin::Client)
            .await
            .unwrap_err();
        assert!(matches!(err, BlobError::QuotaExceeded), "got {err:?}");
        assert_eq!(h.scope_bytes("third-tenant", "third-alias"), (0, 0));
        assert_eq!(h.claim(&sha).unwrap().aliases.len(), 2);
    }

    /// A repository that declared a blob at fewer bytes than were stored,
    /// and cannot afford the difference, stops referencing the blob when
    /// another account uploads it, instead of being carried over its own
    /// caps; the uploader still pays, also after it drops the blob as its
    /// last referrer. Without this one account declaring blobs at nothing
    /// and another uploading and dropping each would hold bytes no quota
    /// counts.
    #[tokio::test]
    async fn an_upload_never_carries_another_repository_over_its_caps() {
        let mut h = Harness::new(1 << 20);
        h.cfg.quota_repo_bytes = 1000;
        h.register("short-tenant", "short-alias");
        let data = vec![63u8; 400];
        let sha = sha256::Hash::hash(&data).to_string();
        h.meta
            .with_write(|m, txn| quota::charge(m, txn, "short-tenant", "short-alias", 999, true))
            .unwrap();
        declare(&h.meta, &sha, "short-tenant", "short-alias", 1);
        assert_eq!(h.scope_bytes("short-tenant", "short-alias"), (1000, 1000));

        h.upload(&data).await.unwrap();
        let claim = h.claim(&sha).unwrap();
        assert_eq!(claim.aliases, vec!["alias".to_string()]);
        assert_eq!(claim.charges, vec![charge("tenant", "alias", 400)]);
        assert_eq!(
            h.scope_bytes("short-tenant", "short-alias"),
            (999, 999),
            "its declared byte is released, and nothing more is charged"
        );
        assert_eq!(h.scope_bytes("tenant", "alias"), (400, 400));

        let now = nostr::prelude::Timestamp::now().as_secs();
        h.meta
            .with_write(|m, txn| claims::detach_from(m, txn, &sha, "alias", now))
            .unwrap();
        assert_eq!(
            h.scope_bytes("tenant", "alias"),
            (400, 400),
            "the uploader pays the grace charge"
        );
        assert_eq!(h.scope_bytes("short-tenant", "short-alias"), (999, 999));
    }

    /// A repository that declared fewer bytes than were stored and can
    /// afford them pays the stored size, like any other referrer.
    #[tokio::test]
    async fn an_upload_raises_a_short_declaration_that_fits() {
        let h = Harness::new(1 << 20);
        h.register("other-tenant", "other-alias");
        let data = vec![64u8; 400];
        let sha = sha256::Hash::hash(&data).to_string();
        declare(&h.meta, &sha, "other-tenant", "other-alias", 1);

        h.upload(&data).await.unwrap();
        let claim = h.claim(&sha).unwrap();
        assert_eq!(claim.aliases.len(), 2);
        assert_eq!(h.scope_bytes("other-tenant", "other-alias"), (400, 400));
        assert_eq!(h.scope_bytes("tenant", "alias"), (400, 400));
    }

    /// The mirror stores bytes only for a repository that references the
    /// blob here, and adds no reference: a fetch that outlived its
    /// reference stores nothing, and one for a referrer sets every charge
    /// to the stored size without a new one.
    #[tokio::test]
    async fn the_mirror_stores_for_a_referrer_and_adds_no_reference() {
        let h = Harness::new(1 << 20);
        h.register("other-tenant", "other-alias");
        let data = vec![62u8; 256];
        let sha = sha256::Hash::hash(&data).to_string();

        // Nobody references it here: refused, nothing placed or charged.
        let err = h
            .store_as("tenant", "alias", &data, UploadOrigin::Mirror)
            .await
            .unwrap_err();
        assert!(matches!(err, BlobError::Forbidden(_)), "got {err:?}");
        assert!(!h.store.exists(&sha));
        assert!(h.claim(&sha).is_none());

        // Another repository references it; the fetch was for this one.
        declare(&h.meta, &sha, "other-tenant", "other-alias", 300);
        h.store_as("tenant", "alias", &data, UploadOrigin::Mirror)
            .await
            .unwrap_err();
        assert!(!h.store.exists(&sha));

        // The fetch is for the referrer: stored, its charge set to the
        // stored size, and no reference added.
        h.store_as("other-tenant", "other-alias", &data, UploadOrigin::Mirror)
            .await
            .unwrap();
        assert!(h.store.exists(&sha));
        let claim = h.claim(&sha).unwrap();
        assert_eq!(claim.aliases, vec!["other-alias".to_string()]);
        assert_eq!(
            claim.charges,
            vec![charge("other-tenant", "other-alias", 256)]
        );
        assert_eq!(h.scope_bytes("other-tenant", "other-alias"), (256, 256));
        assert_eq!(
            h.ledger_blob_bytes().0,
            0,
            "the harness's repository pays nothing"
        );
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
                        charges: vec![charge("tenant", "alias", data.len() as u64)],
                        stored_at: None,
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

    /// R2-C (verify round 2): an eviction/deletion between auth and finish()
    /// must fail the upload WITHOUT placing the file, claiming, or charging —
    /// the re-check inside the charge txn (existence + same tenant, never the
    /// latest event id) is the last line of defense. An honest same-tenant
    /// ROTATION mid-stream must not kill the upload.
    #[tokio::test]
    async fn finish_rejects_when_registration_dies_mid_upload() {
        let h = Harness::new(1 << 20);
        let data = vec![41u8; 256];
        let sha = sha256::Hash::hash(&data).to_string();

        let new_sink = |h: &Harness| {
            let reservation = UploadReservation::detached();
            UploadSink::create(
                h.meta.clone(),
                h.store.clone(),
                h.cfg.clone(),
                "tenant".to_string(),
                "alias".to_string(),
                sha.clone(),
                data.len() as u64,
                reservation,
                h.denylist.clone(),
                UploadOrigin::Client,
            )
        };

        // The sink streams while the registration is live; it dies before
        // finish() (eviction/kind-5/vanish all take this path).
        let mut sink = new_sink(&h).await.unwrap();
        sink.write_chunk(&data).await.unwrap();
        h.meta
            .with_write(|m, txn| m.delete_registration(txn, "alias"))
            .unwrap();
        let err = sink.finish().await.unwrap_err();
        assert!(
            matches!(err, BlobError::Forbidden(_)),
            "death mid-upload must be a 403, got {err:?}"
        );
        assert!(!h.store.exists(&sha), "rejected finish must place no file");
        {
            let txn = h.meta.read_txn().unwrap();
            assert!(
                h.meta.get_blob_claim(&txn, &sha).unwrap().is_none(),
                "no claim may commit for a dead registration"
            );
        }
        assert_eq!(h.ledger_blob_bytes(), (0, 0, 0), "nothing may be charged");

        // A same-tenant ROTATION mid-stream (new event id, same tenant) must
        // NOT kill the upload.
        h.meta
            .with_write(|m, txn| {
                m.put_registration(txn, "alias", &test_registration("tenant", "ed2"))
            })
            .unwrap();
        let mut sink = new_sink(&h).await.unwrap();
        sink.write_chunk(&data).await.unwrap();
        h.meta
            .with_write(|m, txn| {
                m.put_registration(txn, "alias", &test_registration("tenant", "ed3"))
            })
            .unwrap();
        sink.finish()
            .await
            .expect("a same-tenant rotation must not kill the upload");
        assert!(h.store.exists(&sha));
        assert_eq!(h.ledger_blob_bytes(), (256, 256, 256));
    }

    /// Phase-4b D1: the finish() race — the hash is denylisted (by a
    /// reload) between PUT begin and finish. The in-txn re-check must fail
    /// the upload with 451 WITHOUT placing the file, claiming, or charging
    /// (same cleanup shape as the R2-C registration-gone path). A
    /// non-denylisted upload on the same denylist handle is unaffected.
    #[tokio::test]
    async fn finish_rejects_when_hash_denylisted_mid_upload() {
        let h = Harness::new(1 << 20);
        let data = vec![43u8; 256];
        let sha = sha256::Hash::hash(&data).to_string();

        let reservation = UploadReservation::detached();
        let mut sink = UploadSink::create(
            h.meta.clone(),
            h.store.clone(),
            h.cfg.clone(),
            "tenant".to_string(),
            "alias".to_string(),
            sha.clone(),
            data.len() as u64,
            reservation,
            h.denylist.clone(),
            UploadOrigin::Client,
        )
        .await
        .unwrap();
        sink.write_chunk(&data).await.unwrap();

        // The reload swaps the set between begin and finish.
        h.denylist.write().unwrap().insert(sha.clone());

        let err = sink.finish().await.unwrap_err();
        assert!(
            matches!(err, BlobError::Denylisted),
            "denylisted mid-upload must be a 451, got {err:?}"
        );
        assert!(!h.store.exists(&sha), "rejected finish must place no file");
        {
            let txn = h.meta.read_txn().unwrap();
            assert!(
                h.meta.get_blob_claim(&txn, &sha).unwrap().is_none(),
                "no claim may commit for denylisted bytes"
            );
        }
        assert_eq!(h.ledger_blob_bytes(), (0, 0, 0), "nothing may be charged");

        // Control: a different, non-denylisted hash still lands.
        let ok_data = vec![44u8; 128];
        h.upload(&ok_data)
            .await
            .expect("non-denylisted upload must succeed");
    }

    /// The descriptor's `uploaded` is the time this node first stored the
    /// bytes. It is written with the claim, and a repeat upload reports it
    /// unchanged instead of the time of the repeat.
    #[tokio::test]
    async fn stored_at_is_set_once_and_survives_reupload() {
        let h = Harness::new(1 << 20);
        let data = vec![51u8; 200];
        let sha = sha256::Hash::hash(&data).to_string();
        let stored_at = |h: &Harness| {
            let txn = h.meta.read_txn().unwrap();
            h.meta
                .get_blob_claim(&txn, &sha)
                .unwrap()
                .unwrap()
                .stored_at
        };

        let before = nostr::prelude::Timestamp::now().as_secs();
        let first = h.upload(&data).await.unwrap();
        assert!(
            first.uploaded >= before,
            "the first upload must report the time it was stored"
        );
        assert_eq!(stored_at(&h), Some(first.uploaded));

        // Move the recorded time into the past, so that a repeat upload
        // which took the current time instead would be seen to differ.
        h.meta
            .with_write(|m, txn| {
                let mut claim = m.get_blob_claim(txn, &sha)?.unwrap();
                claim.stored_at = Some(1_000);
                m.put_blob_claim(txn, &sha, &claim)
            })
            .unwrap();

        let again = h.upload(&data).await.unwrap();
        assert_eq!(
            again.uploaded, 1_000,
            "a repeat upload reports the kept time"
        );
        assert_eq!(stored_at(&h), Some(1_000), "and does not move it");

        // The same holds when the repeat has to put the bytes back.
        std::fs::remove_file(h.store.path_for(&sha)).unwrap();
        let restored = h.upload(&data).await.unwrap();
        assert_eq!(restored.uploaded, 1_000);
        assert!(h.store.exists(&sha));
    }

    /// A blob that was only declared has no storing time; the upload that
    /// stores it sets one.
    #[tokio::test]
    async fn declared_claim_gets_its_time_when_the_bytes_arrive() {
        let h = Harness::new(1 << 20);
        let data = vec![52u8; 64];
        let sha = sha256::Hash::hash(&data).to_string();
        declare(&h.meta, &sha, "tenant", "alias", 64);

        let descriptor = h.upload(&data).await.unwrap();
        assert!(descriptor.uploaded > 0);
        let txn = h.meta.read_txn().unwrap();
        let claim = h.meta.get_blob_claim(&txn, &sha).unwrap().unwrap();
        assert!(claim.stored);
        assert_eq!(claim.stored_at, Some(descriptor.uploaded));
    }

    /// Opening the store removes the temp files earlier runs left behind and
    /// nothing else: stored blobs stay.
    #[test]
    fn open_sweeps_stale_tmp_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("blobs");
        let store = BlobStore::open(&root).unwrap();

        let sha = "aabb".repeat(16);
        let stored = store.path_for(&sha);
        std::fs::create_dir_all(stored.parent().unwrap()).unwrap();
        std::fs::write(&stored, b"stored blob").unwrap();
        let tmp = root.join("tmp");
        std::fs::write(tmp.join("left-by-a-crash"), vec![0_u8; 300]).unwrap();
        std::fs::write(tmp.join("another"), vec![0_u8; 200]).unwrap();

        assert_eq!(sweep_tmp(&tmp), (2, 500), "two entries, 500 bytes");
        assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);

        // The same through `open`, which is what a restart runs.
        std::fs::write(tmp.join("left-again"), b"x").unwrap();
        let reopened = BlobStore::open(&root).unwrap();
        assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
        assert!(
            reopened.exists(&sha),
            "a stored blob must survive the sweep"
        );
        assert_eq!(std::fs::read(&stored).unwrap(), b"stored blob");
    }

    /// A `tmp` that is itself a link is not swept: what it points at is not
    /// this store's to clear.
    #[cfg(unix)]
    #[test]
    fn open_does_not_sweep_through_a_linked_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("not-a-temp-file"), b"keep me").unwrap();
        let root = dir.path().join("blobs");
        std::fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("tmp")).unwrap();

        BlobStore::open(&root).unwrap();

        assert_eq!(
            std::fs::read(elsewhere.join("not-a-temp-file")).unwrap(),
            b"keep me"
        );
    }

    /// The sweep unlinks a symlink without touching what it points at, and
    /// leaves a directory and everything under it alone.
    #[cfg(unix)]
    #[test]
    fn open_sweep_does_not_follow_links() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("blobs");
        BlobStore::open(&root).unwrap();
        let tmp = root.join("tmp");

        let outside_file = dir.path().join("outside-file");
        std::fs::write(&outside_file, b"keep me").unwrap();
        let outside_dir = dir.path().join("outside-dir");
        std::fs::create_dir(&outside_dir).unwrap();
        std::fs::write(outside_dir.join("inner"), b"keep me too").unwrap();
        std::os::unix::fs::symlink(&outside_file, tmp.join("link-to-file")).unwrap();
        std::os::unix::fs::symlink(&outside_dir, tmp.join("link-to-dir")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("nowhere"), tmp.join("dangling")).unwrap();
        let subdir = tmp.join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        std::fs::write(subdir.join("nested"), b"not ours to judge").unwrap();

        BlobStore::open(&root).unwrap();

        for link in ["link-to-file", "link-to-dir", "dangling"] {
            assert!(
                std::fs::symlink_metadata(tmp.join(link)).is_err(),
                "{link} must be unlinked"
            );
        }
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"keep me");
        assert_eq!(
            std::fs::read(outside_dir.join("inner")).unwrap(),
            b"keep me too"
        );
        assert!(subdir.is_dir(), "a directory is left alone");
        assert_eq!(
            std::fs::read(subdir.join("nested")).unwrap(),
            b"not ours to judge"
        );
    }
}
