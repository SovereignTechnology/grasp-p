//! Quota ledger: per-tenant, per-alias, and global byte accounting for the
//! GRASP-P private subsystem.
//!
//! Ledger and blob claims are authoritative in the meta store (never recomputed
//! from disk at boot). All helpers operate inside an already-open write txn so
//! callers can make quota changes atomic with their index mutations.

use anyhow::Result;
use heed::{RoTxn, RwTxn};

use super::meta::{BlobClaim, LedgerEntry, MetaEnv, SpecCharge, LEDGER_GLOBAL_KEY};
use super::PrivateConfig;

/// Ledger key for a tenant scope.
pub fn tenant_key(tenant_hex: &str) -> String {
    format!("t:{tenant_hex}")
}

/// Ledger key for an alias (repo) scope.
pub fn alias_key(alias: &str) -> String {
    format!("r:{alias}")
}

/// Check whether charging `additional` bytes to (tenant, alias) would exceed
/// any cap. Returns `false` when over quota.
pub fn check(
    meta: &MetaEnv,
    txn: &RoTxn,
    cfg: &PrivateConfig,
    tenant_hex: &str,
    alias: &str,
    additional: u64,
) -> Result<bool> {
    let tenant = meta.get_ledger_txn(txn, &tenant_key(tenant_hex))?;
    let alias_entry = meta.get_ledger_txn(txn, &alias_key(alias))?;
    let global = meta.get_ledger_txn(txn, LEDGER_GLOBAL_KEY)?;

    Ok(
        alias_entry.total().saturating_add(additional) <= cfg.quota_repo_bytes
            && tenant.total().saturating_add(additional) <= cfg.quota_tenant_bytes
            && global.total().saturating_add(additional) <= cfg.global_budget_bytes,
    )
}

/// Charge `bytes` to the tenant, alias, and global ledgers. `blob` selects the
/// blob-bytes column, otherwise event bytes. Caller must have checked quota.
pub fn charge(
    meta: &MetaEnv,
    txn: &mut RwTxn,
    tenant_hex: &str,
    alias: &str,
    bytes: u64,
    blob: bool,
) -> Result<()> {
    for key in [
        tenant_key(tenant_hex),
        alias_key(alias),
        LEDGER_GLOBAL_KEY.to_string(),
    ] {
        let mut entry = meta.get_ledger_txn(txn, &key)?;
        apply(&mut entry, bytes, blob, true);
        meta.put_ledger(txn, &key, &entry)?;
    }
    Ok(())
}

/// Release `bytes` from the given scopes (used by GC / offboarding).
pub fn release(
    meta: &MetaEnv,
    txn: &mut RwTxn,
    tenant_hex: Option<&str>,
    alias: Option<&str>,
    bytes: u64,
    blob: bool,
) -> Result<()> {
    let mut keys = vec![LEDGER_GLOBAL_KEY.to_string()];
    if let Some(t) = tenant_hex {
        keys.push(tenant_key(t));
    }
    if let Some(a) = alias {
        keys.push(alias_key(a));
    }
    for key in keys {
        let mut entry = meta.get_ledger_txn(txn, &key)?;
        apply(&mut entry, bytes, blob, false);
        meta.put_ledger(txn, &key, &entry)?;
    }
    Ok(())
}

/// Current global ledger total (for the metrics gauge).
pub fn global_total(meta: &MetaEnv, txn: &RoTxn) -> Result<u64> {
    Ok(meta.get_ledger_txn(txn, LEDGER_GLOBAL_KEY)?.total())
}

/// Reset the EVENT-bytes column of an alias scope (`r:<alias>`) to zero
/// (verify round 1, FC). The alias scope is keyed by the alias STRING, so
/// wrap/30641 event bytes a dead registration charged there would otherwise
/// outlive it and brick the seat for a conflict-merge winner: those bytes
/// are unattributable per tenant and every prior event charge belonged to
/// the dead holder(s). Blob/spec columns stay intact — those are real bytes
/// on disk (or recorded speculative charges) that the GC/grace paths
/// release. Pure function of meta state; ledger timing stays node-local, so
/// the deterministic merge is unaffected.
pub fn reset_alias_event_bytes(meta: &MetaEnv, txn: &mut RwTxn, alias: &str) -> Result<()> {
    let key = alias_key(alias);
    let mut entry = meta.get_ledger_txn(txn, &key)?;
    entry.event_bytes = 0;
    meta.put_ledger(txn, &key, &entry)
}

/// Release the ledger charge attached to a stored blob claim (GC).
///
/// No-op when the claim was never charged: adopted orphans carry
/// `stored = true` with `charged_tenant = None` (the bytes were already on
/// disk, so no charge was taken). Releasing anyway would subtract `size`
/// from the global ledger without any matching charge, silently inflating
/// the global budget by every adopted-then-GC'd orphan.
pub fn release_claim(meta: &MetaEnv, txn: &mut RwTxn, claim: &BlobClaim) -> Result<()> {
    if claim.charged_tenant.is_none() {
        return Ok(());
    }
    release(
        meta,
        txn,
        claim.charged_tenant.as_deref(),
        claim.charged_alias.as_deref(),
        claim.size,
        true,
    )
}

/// Release a speculative (pre-upload) charge (issue !12). Releases exactly
/// the bytes that were charged at 30641 declaration time, against the same
/// (tenant, alias) scope — never `claim.size`, which the upload path may
/// have since overwritten with the actual byte count.
pub fn release_spec_charge(meta: &MetaEnv, txn: &mut RwTxn, spec: &SpecCharge) -> Result<()> {
    release(
        meta,
        txn,
        Some(&spec.tenant),
        Some(&spec.alias),
        spec.bytes,
        true,
    )
}

fn apply(entry: &mut LedgerEntry, bytes: u64, blob: bool, add: bool) {
    let column = if blob {
        &mut entry.blob_bytes
    } else {
        &mut entry.event_bytes
    };
    *column = if add {
        column.saturating_add(bytes)
    } else {
        column.saturating_sub(bytes)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_claim(tenant: Option<&str>, alias: Option<&str>, size: u64) -> BlobClaim {
        BlobClaim {
            size,
            aliases: vec![],
            unreferenced_since: None,
            stored: true,
            charged_tenant: tenant.map(str::to_string),
            charged_alias: alias.map(str::to_string),
            spec_charge: None,
            stored_at: None,
        }
    }

    /// release_claim must release exactly what was charged — and nothing for
    /// adopted orphans (`stored = true` but never charged): releasing those
    /// would subtract bytes from the global ledger that it never gained.
    #[test]
    fn release_claim_releases_only_what_was_charged() {
        let dir = tempfile::tempdir().unwrap();
        let meta = MetaEnv::open(dir.path()).unwrap();

        meta.with_write(|m, txn| {
            charge(m, txn, "t1", "a1", 100, true)?;
            assert_eq!(global_total(m, txn)?, 100);

            // Adopted orphan: stored, no charged scopes — release is a no-op.
            release_claim(m, txn, &stored_claim(None, None, 50))?;
            assert_eq!(
                global_total(m, txn)?,
                100,
                "never-charged claim must not touch the ledger"
            );

            // Really charged claim: full release across all three scopes.
            release_claim(m, txn, &stored_claim(Some("t1"), Some("a1"), 100))?;
            assert_eq!(global_total(m, txn)?, 0);
            assert_eq!(
                m.get_ledger_txn(txn, &tenant_key("t1"))?.blob_bytes,
                0,
                "tenant scope must be released"
            );
            assert_eq!(
                m.get_ledger_txn(txn, &alias_key("a1"))?.blob_bytes,
                0,
                "alias scope must be released"
            );
            Ok(())
        })
        .unwrap();
    }
}
