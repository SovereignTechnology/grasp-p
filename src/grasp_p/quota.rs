//! Quota ledger: per-tenant, per-alias, and global byte accounting for the
//! GRASP-P private subsystem.
//!
//! Ledger and blob claims are authoritative in the meta store (never recomputed
//! from disk at boot). All helpers operate inside an already-open write txn so
//! callers can make quota changes atomic with their index mutations.

use anyhow::Result;
use heed::{RoTxn, RwTxn};

use super::claims::Move;
use super::meta::{LedgerEntry, MetaEnv, LEDGER_GLOBAL_KEY, META_BYTES_PER_CHARGE, META_MAP_SIZE};
use super::PrivateConfig;

/// What a blob of `size` bytes is charged at each scope: its size, and
/// never less than `NGIT_GRASP_P_MIN_BLOB_CHARGE_BYTES` (decision D5).
///
/// Every claim row costs the node meta space and every stored blob an
/// inode, whatever its size; with a floor on the charge the byte quotas
/// bound how many of them a repository, an account and the node can hold,
/// and no separate count is needed. Only the charge is raised: the claim
/// and the disk keep the real size. `claims.rs` prices every charge with
/// this and records the result on the charge, so that a later change of
/// the floor never changes what an existing charge gives back.
pub(crate) fn billable(cfg: &PrivateConfig, size: u64) -> u64 {
    size.max(cfg.min_blob_charge_bytes)
}

/// Boot checks of `NGIT_GRASP_P_MIN_BLOB_CHARGE_BYTES`, from
/// `Config::validate`.
///
/// A floor above the repository cap would refuse every blob. With a floor,
/// every charge costs at least that much at the node scope, so the node
/// holds at most `global budget / floor` of them, and each takes up to
/// [`META_BYTES_PER_CHARGE`] of a meta map whose size is fixed: a budget
/// the map cannot hold at that floor would let the claims fill it, and a
/// full map fails every GRASP-P write on the node. A floor of 0 bounds
/// nothing; it is allowed, and the operator is warned.
pub(crate) fn check_min_blob_charge(config: &crate::config::Config) -> Result<()> {
    let floor = config.private_min_blob_charge_bytes;
    if floor > config.private_quota_repo_bytes {
        anyhow::bail!(
            "NGIT_GRASP_P_MIN_BLOB_CHARGE_BYTES must not exceed NGIT_GRASP_P_QUOTA_REPO_BYTES"
        );
    }
    if floor == 0 {
        tracing::warn!(
            "NGIT_GRASP_P_MIN_BLOB_CHARGE_BYTES=0: blobs are charged their real size, so the \
             quotas do not bound how many tiny blobs an account can store or declare, and \
             their claims can fill the private meta store"
        );
        return Ok(());
    }
    let charges = config.private_global_budget_bytes / floor;
    let needed = u128::from(charges) * u128::from(META_BYTES_PER_CHARGE);
    let map = META_MAP_SIZE as u128;
    if needed > map {
        anyhow::bail!(
            "NGIT_GRASP_P_GLOBAL_BUDGET_BYTES / NGIT_GRASP_P_MIN_BLOB_CHARGE_BYTES allows \
             {charges} blob charges, which need about {needed} bytes of the private meta \
             store at {META_BYTES_PER_CHARGE} bytes each; it holds {map}. Raise \
             NGIT_GRASP_P_MIN_BLOB_CHARGE_BYTES or lower NGIT_GRASP_P_GLOBAL_BUDGET_BYTES"
        );
    }
    Ok(())
}

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

    /// A charge is the size, raised to the floor; a floor of 0 is no floor.
    #[test]
    fn billable_raises_a_size_to_the_floor() {
        let mut cfg = limits(1 << 30, 1 << 30, 1 << 30);
        for size in [0, 1, 16_383, 16_384, 16_385, u64::MAX] {
            assert_eq!(billable(&cfg, size), size, "no floor: {size}");
        }
        cfg.min_blob_charge_bytes = 16_384;
        for (size, charged) in [
            (0, 16_384),
            (1, 16_384),
            (16_383, 16_384),
            (16_384, 16_384),
            (16_385, 16_385),
            (u64::MAX, u64::MAX),
        ] {
            assert_eq!(billable(&cfg, size), charged, "floor 16384: {size}");
        }
    }

    fn with_floor(floor: u64, global_budget: u64) -> crate::config::Config {
        crate::config::Config {
            private_repos_enable: true,
            private_min_blob_charge_bytes: floor,
            private_global_budget_bytes: global_budget,
            ..crate::config::Config::for_testing()
        }
    }

    /// The boot checks, through `Config::validate`: the shipped floor and
    /// budget start; a floor above the repository cap does not; the budget
    /// may allow as many charges as the meta map holds at
    /// [`META_BYTES_PER_CHARGE`] each and not one more; 0 starts whatever
    /// the budget. Without the map check a budget of 50 GiB at a floor of
    /// one byte would let claims fill the 48 GiB map.
    #[test]
    fn the_floor_is_checked_at_boot() {
        let defaults = crate::config::Config::for_testing();
        let shipped = with_floor(16_384, defaults.private_global_budget_bytes);
        shipped
            .validate()
            .expect("the shipped floor and budget start");

        // A budget the map holds at this floor, so that only the
        // repository cap decides.
        let mut over_repo = with_floor(4096, defaults.private_quota_tenant_bytes);
        over_repo.private_quota_repo_bytes = 4095;
        let error = over_repo
            .validate()
            .expect_err("a floor above the repository cap must not start")
            .to_string();
        assert!(
            error.contains("NGIT_GRASP_P_MIN_BLOB_CHARGE_BYTES")
                && error.contains("NGIT_GRASP_P_QUOTA_REPO_BYTES"),
            "{error}"
        );
        over_repo.private_quota_repo_bytes = 4096;
        over_repo
            .validate()
            .expect("a floor equal to the repository cap starts");

        // 48 GiB / 12 KiB = 4 Mi charges fit the map, at any floor.
        let rows = META_MAP_SIZE as u64 / META_BYTES_PER_CHARGE;
        assert_eq!(rows, 4 * 1024 * 1024);
        let floor = 16_384;
        with_floor(floor, rows * floor)
            .validate()
            .expect("exactly as many charges as the map holds");
        let error = with_floor(floor, rows * floor + floor)
            .validate()
            .expect_err("one charge more than the map holds")
            .to_string();
        assert!(
            error.contains("NGIT_GRASP_P_MIN_BLOB_CHARGE_BYTES")
                && error.contains("NGIT_GRASP_P_GLOBAL_BUDGET_BYTES"),
            "{error}"
        );
        assert!(with_floor(1, defaults.private_global_budget_bytes)
            .validate()
            .is_err());
        assert!(with_floor(4096, defaults.private_global_budget_bytes)
            .validate()
            .is_err());

        for budget in [1, defaults.private_global_budget_bytes, u64::MAX] {
            let mut no_floor = with_floor(0, budget);
            no_floor.private_quota_tenant_bytes = 1;
            no_floor.private_quota_repo_bytes = 1;
            no_floor
                .validate()
                .unwrap_or_else(|e| panic!("floor 0, budget {budget}: {e}"));
        }

        // Nothing is checked while GRASP-P is off.
        let off = crate::config::Config {
            private_repos_enable: false,
            ..with_floor(1, defaults.private_global_budget_bytes)
        };
        off.validate().expect("GRASP-P off");
    }

    /// The shipped default is the 16 KiB of decision D5. `for_testing`
    /// keeps 0, so that unit tests count exact bytes.
    #[test]
    fn the_shipped_floor_is_16_kib() {
        use clap::CommandFactory;
        let mut command = crate::config::Config::command();
        command.build();
        let argument = command
            .get_arguments()
            .find(|argument| {
                argument.get_env().and_then(|name| name.to_str())
                    == Some("NGIT_GRASP_P_MIN_BLOB_CHARGE_BYTES")
            })
            .expect("the setting exists");
        let defaults: Vec<String> = argument
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(defaults, vec!["16384".to_string()]);
        assert_eq!(
            crate::config::Config::for_testing().private_min_blob_charge_bytes,
            0
        );
    }
}
