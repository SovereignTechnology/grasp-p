//! Background GC: delete grace-expired unreferenced blobs and release their
//! ledger charges.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

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

/// One GC pass: remove blobs unreferenced for longer than the grace period.
/// Public so tests / operators can trigger it deterministically later.
pub fn run_pass(svc: &PrivateService) -> anyhow::Result<usize> {
    let now = nostr::Timestamp::now().as_secs();
    let grace = svc.cfg.gc_grace_secs;

    let mut removed = 0_usize;
    let expired: Vec<(String, super::meta::BlobClaim)> = {
        let txn = svc.meta.read_txn()?;
        svc.meta
            .all_blob_claims(&txn)?
            .into_iter()
            .filter(|(_, claim)| {
                claim.aliases.is_empty()
                    && claim
                        .unreferenced_since
                        .map(|since| since.saturating_add(grace) <= now)
                        .unwrap_or(false)
            })
            .collect()
    };

    for (sha, _snapshot) in expired {
        // Re-verify + delete file + delete claim + release the charge all
        // under the meta write lock. The snapshot above is stale by the time
        // we get here: a concurrent upload finish() or 30641 may have
        // re-claimed the blob (aliases repopulated, unreferenced_since
        // cleared), and upload finish() checks file existence inside its own
        // write txn — so deciding AND unlinking under the same lock closes
        // the TOCTOU that could delete a live blob's file and fresh claim.
        let outcome = svc.meta.with_write(|meta, txn| {
            let Some(claim) = meta.get_blob_claim(txn, &sha)? else {
                return Ok(None);
            };
            let still_expired = claim.aliases.is_empty()
                && claim
                    .unreferenced_since
                    .map(|since| since.saturating_add(grace) <= now)
                    .unwrap_or(false);
            if !still_expired {
                return Ok(None);
            }
            // Delete the file first (inside the lock); on failure the txn
            // aborts, the claim survives, and a later pass retries.
            svc.blobs
                .remove(&sha)
                .map_err(|e| anyhow::anyhow!("failed to remove blob file: {e}"))?;
            if claim.stored {
                quota::release_claim(meta, txn, &claim)?;
            }
            meta.delete_blob_claim(txn, &sha)?;
            Ok(Some((claim.stored, claim.size)))
        });
        match outcome {
            Ok(None) => {} // re-claimed (or already gone) since the snapshot
            Ok(Some((stored, size))) => {
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

    if removed > 0 {
        svc.refresh_gauges();
    }
    Ok(removed)
}
