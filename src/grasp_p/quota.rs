//! Quota ledger: per-tenant, per-alias, and global byte accounting for the
//! GRASP-P private subsystem.
//!
//! Ledger and blob claims are authoritative in the meta store (never recomputed
//! from disk at boot). All helpers operate inside an already-open write txn so
//! callers can make quota changes atomic with their index mutations.

use anyhow::Result;
use heed::{RoTxn, RwTxn};

use super::claims::Move;
use super::meta::{LedgerEntry, MetaEnv, LEDGER_GLOBAL_KEY};
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

/// Would a write by (tenant, alias) that charges `event_bytes` and makes the
/// blob `moves` keep the alias, the account and the node within their caps?
/// Returns `false` when over quota.
///
/// The blob moves of one write can release as well as charge (a grace
/// charge taken over, a declared size set to the stored one), so each scope
/// is judged by what the write adds to it: a scope that does not grow is not
/// refused, even one already above its cap. Other repositories' scopes that
/// the moves touch are not judged: their owners did not act. The alias and
/// account scopes count only the moves booked to them; the node counts
/// every move.
pub(crate) fn fits(
    meta: &MetaEnv,
    txn: &RoTxn,
    cfg: &PrivateConfig,
    tenant_hex: &str,
    alias: &str,
    event_bytes: u64,
    moves: &[Move],
) -> Result<bool> {
    let event = i128::from(event_bytes);
    let (mut repo_add, mut account_add, mut node_add) = (event, event, event);
    for change in moves {
        let delta = change.delta();
        node_add += delta;
        if change.tenant == tenant_hex {
            account_add += delta;
        }
        if change.alias == alias {
            repo_add += delta;
        }
    }
    let within = |key: &str, add: i128, cap: u64| -> Result<bool> {
        if add <= 0 {
            return Ok(true);
        }
        let total = i128::from(meta.get_ledger_txn(txn, key)?.total());
        Ok(total + add <= i128::from(cap))
    };
    Ok(within(&alias_key(alias), repo_add, cfg.quota_repo_bytes)?
        && within(&tenant_key(tenant_hex), account_add, cfg.quota_tenant_bytes)?
        && within(LEDGER_GLOBAL_KEY, node_add, cfg.global_budget_bytes)?)
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

/// Release `bytes` from the given scopes.
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
/// the dead holder(s). The blob column is not touched here: every blob
/// charge is recorded on its claim, and the death path releases each one
/// through `claims.rs`. Pure function of meta state; ledger timing stays
/// node-local, so the deterministic merge is unaffected.
pub fn reset_alias_event_bytes(meta: &MetaEnv, txn: &mut RwTxn, alias: &str) -> Result<()> {
    let key = alias_key(alias);
    let mut entry = meta.get_ledger_txn(txn, &key)?;
    entry.event_bytes = 0;
    meta.put_ledger(txn, &key, &entry)
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

    fn limits(repo: u64, tenant: u64, global: u64) -> PrivateConfig {
        let mut cfg = PrivateConfig::from_config(&crate::config::Config::for_testing());
        cfg.quota_repo_bytes = repo;
        cfg.quota_tenant_bytes = tenant;
        cfg.global_budget_bytes = global;
        cfg
    }

    fn change(tenant: &str, alias: &str, bytes: u64, add: bool) -> Move {
        Move {
            tenant: tenant.to_string(),
            alias: alias.to_string(),
            bytes,
            add,
        }
    }

    /// Each scope is judged by what the write adds to it, counting only the
    /// moves booked to it, and a write that adds nothing to a scope already
    /// over its cap is not refused for it.
    #[test]
    fn fits_judges_each_scope_by_what_the_write_adds() {
        let dir = tempfile::tempdir().unwrap();
        let meta = MetaEnv::open(dir.path()).unwrap();
        meta.with_write(|m, txn| {
            charge(m, txn, "t1", "a1", 900, true)?;
            charge(m, txn, "t2", "a2", 50, true)
        })
        .unwrap();
        let txn = meta.read_txn().unwrap();
        let cfg = limits(1000, 1000, 2000);

        // 100 more fits the alias exactly; 101 does not.
        let more = [change("t1", "a1", 100, true)];
        assert!(fits(&meta, &txn, &cfg, "t1", "a1", 0, &more).unwrap());
        assert!(!fits(&meta, &txn, &cfg, "t1", "a1", 1, &more).unwrap());

        // Taking over another account's charge adds nothing to the node
        // and is judged at the taker's scopes alone.
        let takeover = [change("t2", "a2", 50, false), change("t1", "a1", 50, true)];
        assert!(fits(&meta, &txn, &cfg, "t1", "a1", 0, &takeover).unwrap());

        // Over its cap and adding nothing: not refused; adding: refused.
        let tight = limits(800, 1000, 2000);
        let same = [
            change("t1", "a1", 900, false),
            change("t1", "a1", 900, true),
        ];
        assert!(fits(&meta, &txn, &tight, "t1", "a1", 0, &same).unwrap());
        assert!(!fits(&meta, &txn, &tight, "t1", "a1", 0, &more).unwrap());

        // The node counts every move, the account only its own.
        let small_node = limits(1000, 1000, 1000);
        let other = [change("t2", "a2", 100, true)];
        assert!(!fits(&meta, &txn, &small_node, "t1", "a1", 0, &other).unwrap());
        assert!(fits(&meta, &txn, &cfg, "t1", "a1", 0, &other).unwrap());

        // Taking over another account's charge is judged at the taker's own
        // scopes: the release booked to t2/a2 does not offset it.
        let tight_account = limits(1000, 920, 2000);
        assert!(!fits(&meta, &txn, &tight_account, "t1", "a1", 0, &takeover).unwrap());
        let tight_repo = limits(920, 1000, 2000);
        assert!(!fits(&meta, &txn, &tight_repo, "t1", "a1", 0, &takeover).unwrap());
    }
}
