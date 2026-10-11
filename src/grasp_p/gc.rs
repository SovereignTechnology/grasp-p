//! Background GC: delete grace-expired unreferenced blobs and release their
//! ledger charges.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use super::meta::BlobClaim;
use super::{quota, PrivateService};

pub(crate) fn spawn(svc: Arc<PrivateService>) -> JoinHandle<()> {
    let interval_secs = svc.cfg.gc_interval_secs.max(1);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        // First tick fires immediately; skip it so boot isn't a GC pass.
        interval.tick().await;
        loop {
            interval.tick().await;
            match run_pass(&svc) {
                Ok(0) => {}
                Ok(removed) => {
                    tracing::info!("private blob GC removed {removed} unreferenced blob(s)")
                }
                Err(e) => tracing::warn!("private blob GC pass failed: {e}"),
            }
        }
    })
}

/// Outcome of one [`purge_blob`] call under the meta write lock.
pub(crate) struct PurgeOutcome {
    /// `(stored, size)` of the freed claim, when one existed and passed the
    /// gate. `None` when there was no claim (a bare on-disk orphan) or the
    /// gate rejected the purge.
    pub freed: Option<(bool, u64)>,
    /// Whether a blob file was present (and therefore unlinked).
    pub unlinked: bool,
}

/// THE blob-takedown primitive (single code path — Phase-4b D1/D2): GC's
/// grace-expiry pass, GC's denylist sweep, and the denylist reload
/// purge-on-add all funnel through here.
///
/// Re-reads the claim under the meta write lock; when it exists, `gate`
/// decides whether the purge proceeds (GC passes the grace-expiry re-check,
/// takedown callers pass `|_| true`). The file is unlinked FIRST, inside
/// the same lock `finish()` and this function's other callers use: the
/// snapshot a caller may have taken earlier is stale by now — a concurrent
/// upload finish() or 30641 may have re-claimed the blob (aliases
/// repopulated, unreferenced_since cleared), and upload finish() checks
/// file existence inside its own write txn — so deciding AND unlinking
/// under the same lock closes the TOCTOU that could delete a live blob's
/// file and fresh claim. On unlink failure the txn aborts, the claim
/// survives, and a later pass retries.
///
/// After the unlink: a stored claim's ledger charge is released (a no-op
/// for never-charged/adopted claims per `quota::release_claim`), any
/// pending speculative charge is released (issue !12: a never-stored claim
/// dies with its speculative charge or the declared bytes leak in the
/// ledger), and the claim row is deleted. The unlink is idempotent
/// (`NotFound` → Ok) so claim-less orphan files are swept too.
pub(crate) fn purge_blob(
    svc: &PrivateService,
    sha: &str,
    gate: impl Fn(&BlobClaim) -> bool,
) -> anyhow::Result<PurgeOutcome> {
    svc.meta.with_write(|meta, txn| {
        let claim = meta.get_blob_claim(txn, sha)?;
        if let Some(ref claim) = claim {
            if !gate(claim) {
                return Ok(PurgeOutcome {
                    freed: None,
                    unlinked: false,
                });
            }
        }
        let file_present = svc.blobs.exists(sha);
        svc.blobs
            .remove(sha)
            .map_err(|e| anyhow::anyhow!("failed to remove blob file: {e}"))?;
        let Some(claim) = claim else {
            return Ok(PurgeOutcome {
                freed: None,
                unlinked: file_present,
            });
        };
        if claim.stored {
            quota::release_claim(meta, txn, &claim)?;
        }
        if let Some(ref spec) = claim.spec_charge {
            quota::release_spec_charge(meta, txn, spec)?;
        }
        meta.delete_blob_claim(txn, sha)?;
        Ok(PurgeOutcome {
            freed: Some((claim.stored, claim.size)),
            unlinked: file_present,
        })
    })
}

/// One GC pass: remove blobs unreferenced for longer than the grace period,
/// PLUS any blob whose sha is denylisted (Phase-4b D2 — takedown bypasses
/// both the grace period and the unreferenced requirement). Public so
/// tests / operators can trigger it deterministically later.
pub fn run_pass(svc: &PrivateService) -> anyhow::Result<usize> {
    let now = nostr::prelude::Timestamp::now().as_secs();
    let grace = svc.cfg.gc_grace_secs;

    let mut removed = 0_usize;
    let mut purged = 0_u64;
    let (expired, denylisted): (Vec<String>, Vec<String>) = {
        let txn = svc.meta.read_txn()?;
        let mut expired = Vec::new();
        let mut denylisted = Vec::new();
        for (sha, claim) in svc.meta.all_blob_claims(&txn)? {
            // D2: the denylist sweep makes purge durable even when the
            // reload's purge-on-add raced a claim that appeared later (or
            // errored mid-loop). It runs unconditionally — even on a
            // still-referenced blob: takedown = immediate.
            if svc.is_denylisted(&sha) {
                denylisted.push(sha);
                continue;
            }
            if claim.aliases.is_empty()
                && claim
                    .unreferenced_since
                    .map(|since| since.saturating_add(grace) <= now)
                    .unwrap_or(false)
            {
                expired.push(sha);
            }
        }
        (expired, denylisted)
    };

    for sha in denylisted {
        // Same purge primitive as the reload's purge-on-add (single code
        // path, D1): the unconditional gate re-reads the claim under the
        // lock and frees + unlinks whatever is there now.
        match purge_blob(svc, &sha, |_| true) {
            Ok(outcome) => {
                if outcome.freed.is_some() || outcome.unlinked {
                    purged += 1;
                    removed += 1;
                    tracing::info!(
                        sha256 = %sha,
                        freed = outcome.freed.is_some(),
                        "private blob GC purged denylisted blob"
                    );
                }
            }
            Err(e) => {
                tracing::warn!("private blob GC denylist purge failed for {sha}: {e}");
            }
        }
    }

    for sha in expired {
        // The gate re-derives the exact expiry condition the snapshot used;
        // anything re-claimed since aborts the purge for this pass.
        let outcome = purge_blob(svc, &sha, |claim| {
            claim.aliases.is_empty()
                && claim
                    .unreferenced_since
                    .map(|since| since.saturating_add(grace) <= now)
                    .unwrap_or(false)
        });
        match outcome {
            Ok(PurgeOutcome { freed: None, .. }) => {} // re-claimed (or already gone) since the snapshot
            Ok(PurgeOutcome {
                freed: Some((stored, size)),
                ..
            }) => {
                if stored {
                    crate::metrics::record_private_blob_removed(size);
                }
                removed += 1;
            }
            Err(e) => {
                tracing::warn!("private blob GC failed for {sha}: {e}");
            }
        }
    }

    if purged > 0 {
        crate::metrics::record_private_denylist_purged(purged);
    }
    if removed > 0 {
        svc.refresh_gauges();
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grasp_p::meta::{BlobClaim, LEDGER_GLOBAL_KEY};

    async fn harness() -> (tempfile::TempDir, Arc<PrivateService>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::config::Config::for_testing();
        config.private_repos_enable = true;
        config.private_meta_data_path =
            Some(dir.path().join("meta").to_string_lossy().into_owned());
        config.private_blob_data_path =
            Some(dir.path().join("blobs").to_string_lossy().into_owned());
        let database: crate::nostr::SharedDatabase =
            std::sync::Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let svc = PrivateService::new(&config, database)
            .await
            .expect("private service");
        (dir, svc)
    }

    /// D2: a denylisted sha is purged by the GC pass IMMEDIATELY — the blob
    /// below is still referenced and far inside the grace period, so the
    /// grace path must never touch it; the denylist sweep must free the
    /// claim, release the ledger charge, and unlink the bytes.
    #[tokio::test]
    async fn gc_sweeps_denylisted_blob_bypassing_grace() {
        let (_dir, svc) = harness().await;
        let data = vec![7u8; 512];
        let sha = {
            use bitcoin_hashes::{sha256, Hash};
            sha256::Hash::hash(&data).to_string()
        };

        // Stored + referenced + charged claim (the least GC-able shape).
        svc.meta
            .with_write(|meta, txn| {
                quota::charge(meta, txn, "tenant", "alias", 512, true)?;
                meta.put_blob_claim(
                    txn,
                    &sha,
                    &BlobClaim {
                        size: 512,
                        aliases: vec!["alias".to_string()],
                        unreferenced_since: None,
                        stored: true,
                        charged_tenant: Some("tenant".to_string()),
                        charged_alias: Some("alias".to_string()),
                        spec_charge: None,
                        stored_at: None,
                    },
                )
            })
            .unwrap();
        let path = svc.blobs.path_for(&sha);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &data).unwrap();

        // Grace alone never collects a referenced, in-grace blob.
        assert_eq!(run_pass(&svc).unwrap(), 0);
        assert!(svc.blobs.exists(&sha));

        // Denylisted: the next pass purges it immediately.
        svc.denylist.write().unwrap().insert(sha.clone());
        assert_eq!(run_pass(&svc).unwrap(), 1);
        assert!(!svc.blobs.exists(&sha), "bytes must be unlinked");
        let txn = svc.meta.read_txn().unwrap();
        assert!(
            svc.meta.get_blob_claim(&txn, &sha).unwrap().is_none(),
            "claim must be freed"
        );
        assert_eq!(
            svc.meta
                .get_ledger_txn(&txn, LEDGER_GLOBAL_KEY)
                .unwrap()
                .total(),
            0,
            "the stored charge must be released"
        );

        // Idempotent: a later pass finds nothing.
        drop(txn);
        assert_eq!(run_pass(&svc).unwrap(), 0);
    }
}
