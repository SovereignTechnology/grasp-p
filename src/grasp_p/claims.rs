//! Who pays for a stored blob (decision D4): every repository that
//! references it, its full size each, at the repository, account and node
//! scopes of the ledger. The disk keeps one copy; the ledger holds one
//! charge per referencing repository.
//!
//! Every change to a claim's references and charges goes through the
//! functions here, each of which edits a claim in memory and returns the
//! ledger moves it implies, and through [`commit`], which writes the moves,
//! the per-repository index and the claim in the caller's write
//! transaction. A caller that must decide on quota first (a state root, an
//! upload, the mirror) runs the same functions on a copy and judges the
//! moves with `quota::fits` before anything is written, so the write never
//! adds more than the forecast judged (a state root's releases of what it
//! no longer names are not counted in its favour).
//!
//! The rules, and why:
//!
//! - [`attach`]: a repository that starts referencing a blob is charged its
//!   size: the stored size once the bytes are on this node, its own declared
//!   size before. A repository already referencing it is not charged again.
//! - [`redeclare`]: before the bytes are here, the repository's newest
//!   declaration sets its charge, so that a node that missed an earlier
//!   edition, or applied the editions of two write keys in another order,
//!   charges what its peer does.
//! - [`detach`]: a repository that stops referencing a blob, or dies, is
//!   released at once while another still references it. The last one to
//!   stop referencing stored bytes keeps its charge until GC deletes them
//!   (or another repository starts referencing them and takes the charge
//!   over): released at once, an upload followed by a delete, or by the
//!   repository's own deletion, would put bytes on disk that nobody pays
//!   for during the grace period, at no cost. A claim that was never stored
//!   is deleted with its last reference, so a claim that exists is either
//!   charged or on disk.
//! - [`settle_stored`]: when the bytes arrive, by upload or by the mirror,
//!   every charge is set to the stored size. A charge then depends on the
//!   blob and not on who declared it first, which is what lets the two
//!   nodes of a pair reach the same ledger whichever of them saw the
//!   references, the upload and the mirror fetch in which order.
//! - [`detach_unaffordable`]: a repository whose charge the arriving bytes
//!   raise past its own caps (it declared fewer bytes than were stored)
//!   stops referencing the blob instead, so that no account's upload
//!   carries another account over its quota.
//! - [`release_all`]: GC's purge and a takedown release every charge.
//!
//! What still depends on the order things arrive in:
//!
//! - the bytes a repository pays for a blob not yet stored on this node
//!   (its own declared size, until the blob arrives);
//! - which repository pays the grace charge of a stored blob that several
//!   stopped referencing (the last one here, until GC removes the blob),
//!   and with it whether a later state root or upload of either fits, so
//!   one node of a pair can refuse what the other accepts until then;
//! - a reference made by a client's upload alone, which only the node that
//!   took the upload holds, until that repository's next state root drops
//!   it, which may never come;
//! - whether a repository that declared fewer bytes than were stored could
//!   afford them when they arrived here, and so whether it still references
//!   the blob, until its next state root naming it.

use std::collections::BTreeSet;

use anyhow::Result;
use heed::{RoTxn, RwTxn};

use super::meta::{BlobClaim, ClaimCharge, MetaEnv};
use super::{quota, PrivateConfig};

/// One change to the blob column of the ledger: `bytes` added to, or taken
/// from, the repository scope of `alias`, the account scope of `tenant` and
/// the node scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Move {
    pub tenant: String,
    pub alias: String,
    pub bytes: u64,
    pub add: bool,
}

impl Move {
    fn charge(charge: &ClaimCharge) -> Self {
        Self {
            tenant: charge.tenant.clone(),
            alias: charge.alias.clone(),
            bytes: charge.bytes,
            add: true,
        }
    }

    fn release(charge: &ClaimCharge) -> Self {
        Self {
            add: false,
            ..Self::charge(charge)
        }
    }

    /// The signed change, for summing moves.
    pub(crate) fn delta(&self) -> i128 {
        let bytes = i128::from(self.bytes);
        if self.add {
            bytes
        } else {
            -bytes
        }
    }
}

/// A claim for a blob nobody has referenced or stored yet.
pub(crate) fn new_claim(size: u64) -> BlobClaim {
    BlobClaim {
        size,
        aliases: Vec::new(),
        unreferenced_since: None,
        stored: false,
        charges: Vec::new(),
        stored_at: None,
    }
}

/// What `alias` is charged for this blob, if anything: its reference's
/// charge, or the grace charge it carries as the last referrer.
pub(crate) fn charge_of(claim: &BlobClaim, alias: &str) -> Option<u64> {
    claim
        .charges
        .iter()
        .find(|charge| charge.alias == alias)
        .map(|charge| charge.bytes)
}

/// Whether `alias` references the blob or carries a charge on it, which is
/// when the per-repository index lists the blob under it.
fn holds(claim: &BlobClaim, alias: &str) -> bool {
    claim.aliases.iter().any(|a| a == alias) || charge_of(claim, alias).is_some()
}

/// `alias` of account `tenant` starts referencing the blob, declaring
/// `declared` bytes for it.
pub(crate) fn attach(claim: &mut BlobClaim, tenant: &str, alias: &str, declared: u64) -> Vec<Move> {
    let mut moves = Vec::new();
    if claim.aliases.iter().any(|a| a == alias) {
        return moves;
    }
    // Once the bytes are here their size is the truth, whatever this
    // repository declared.
    let bytes = if claim.stored { claim.size } else { declared };
    if claim.aliases.is_empty() {
        // With no reference left the only charge a claim can carry is the
        // grace charge of its last referrer. The same repository coming
        // back takes it up again; any other one takes the bill over.
        let own = claim
            .charges
            .iter()
            .position(|charge| charge.alias == alias && charge.tenant == tenant);
        let kept = own.map(|index| claim.charges.remove(index));
        for leftover in claim.charges.drain(..) {
            moves.push(Move::release(&leftover));
        }
        if let Some(mut charge) = kept {
            if charge.bytes != bytes {
                moves.push(Move::release(&charge));
                charge.bytes = bytes;
                moves.push(Move::charge(&charge));
            }
            claim.charges.push(charge);
            claim.aliases.push(alias.to_string());
            claim.unreferenced_since = None;
            return moves;
        }
    }
    // A charge of its own without a reference cannot exist beside other
    // references; should one be there all the same, it is replaced, never
    // doubled.
    if let Some(index) = claim.charges.iter().position(|c| c.alias == alias) {
        let stale = claim.charges.remove(index);
        moves.push(Move::release(&stale));
    }
    let charge = ClaimCharge {
        tenant: tenant.to_string(),
        alias: alias.to_string(),
        bytes,
    };
    moves.push(Move::charge(&charge));
    claim.charges.push(charge);
    claim.aliases.push(alias.to_string());
    claim.unreferenced_since = None;
    moves
}

/// `alias`, which references the blob, declares `declared` bytes for it in
/// its newest edition. Before the bytes are here that declaration is what
/// the repository pays; once they are here the stored size is, and this
/// changes nothing.
pub(crate) fn redeclare(claim: &mut BlobClaim, alias: &str, declared: u64) -> Vec<Move> {
    let mut moves = Vec::new();
    if claim.stored || !claim.aliases.iter().any(|a| a == alias) {
        return moves;
    }
    if let Some(charge) = claim.charges.iter_mut().find(|c| c.alias == alias) {
        if charge.bytes != declared {
            moves.push(Move::release(charge));
            charge.bytes = declared;
            moves.push(Move::charge(charge));
        }
    }
    moves
}

/// What becomes of a claim's row after [`detach`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Row {
    Keep,
    /// The blob was never stored and nobody references it any more.
    Delete,
}

/// `alias` stops referencing the blob: a state root no longer names it, a
/// Blossom DELETE, or the repository's death (an eviction, an honoured
/// deletion, a vanish). `now` starts the GC grace period of stored bytes
/// nobody references.
pub(crate) fn detach(claim: &mut BlobClaim, alias: &str, now: u64) -> (Vec<Move>, Row) {
    let mut moves = Vec::new();
    if !claim.aliases.iter().any(|a| a == alias) {
        // Nothing to stop. A grace charge it carries stays until GC or the
        // next referrer, also when the repository dies: its bytes stay on
        // disk until GC, and so does what it pays for them.
        return (moves, Row::Keep);
    }
    claim.aliases.retain(|a| a != alias);
    let grace = claim.aliases.is_empty() && claim.stored;
    if !grace {
        if let Some(index) = claim.charges.iter().position(|c| c.alias == alias) {
            let charge = claim.charges.remove(index);
            moves.push(Move::release(&charge));
        }
    }
    if claim.aliases.is_empty() {
        if !claim.stored {
            for leftover in claim.charges.drain(..) {
                moves.push(Move::release(&leftover));
            }
            return (moves, Row::Delete);
        }
        if claim.unreferenced_since.is_none() {
            claim.unreferenced_since = Some(now);
        }
    }
    (moves, Row::Keep)
}

/// The blob's bytes are on this node, `size` of them: every charge is set
/// to that size, and the storing time is kept from the first time.
pub(crate) fn settle_stored(claim: &mut BlobClaim, size: u64, now: u64) -> Vec<Move> {
    let mut moves = Vec::new();
    claim.stored = true;
    claim.size = size;
    claim.stored_at.get_or_insert(now);
    for charge in claim.charges.iter_mut() {
        if charge.bytes != size {
            moves.push(Move::release(charge));
            charge.bytes = size;
            moves.push(Move::charge(charge));
        }
    }
    if claim.aliases.is_empty() && claim.unreferenced_since.is_none() {
        claim.unreferenced_since = Some(now);
    }
    moves
}

/// After [`settle_stored`] (and the storing repository's own [`attach`]),
/// with `moves` holding what they made: every repository other than
/// `actor` whose charge the stored size raised, and that cannot afford the
/// raise at its own scopes, stops referencing the blob instead.
///
/// It declared fewer bytes than were stored. Carried over its caps by
/// another account's upload, two accounts could hold bytes no quota
/// counts: one declares blobs at nothing, the other uploads each, is
/// released as soon as the first references it, and does it again. Its
/// next state root naming the blob is judged at the stored size like any
/// other. It is judged with its own account's moves only, as if it had
/// made the write alone; the caller then judges the write as a whole.
pub(crate) fn detach_unaffordable(
    meta: &MetaEnv,
    txn: &RoTxn,
    cfg: &PrivateConfig,
    claim: &mut BlobClaim,
    actor: &str,
    moves: &mut Vec<Move>,
    now: u64,
) -> Result<()> {
    let raised: Vec<(String, String)> = claim
        .charges
        .iter()
        .filter(|charge| charge.alias != actor && claim.aliases.contains(&charge.alias))
        .filter(|charge| {
            moves
                .iter()
                .filter(|change| change.alias == charge.alias)
                .map(Move::delta)
                .sum::<i128>()
                > 0
        })
        .map(|charge| (charge.tenant.clone(), charge.alias.clone()))
        .collect();
    for (tenant, alias) in raised {
        let theirs: Vec<Move> = moves
            .iter()
            .filter(|change| change.tenant == tenant)
            .cloned()
            .collect();
        if !quota::fits(meta, txn, cfg, &tenant, &alias, 0, &theirs)? {
            let (released, _) = detach(claim, &alias, now);
            moves.extend(released);
        }
    }
    Ok(())
}

/// Release every charge the blob carries (GC's purge, a takedown). The
/// caller deletes the row.
pub(crate) fn release_all(claim: &mut BlobClaim) -> Vec<Move> {
    claim.aliases.clear();
    claim
        .charges
        .drain(..)
        .map(|charge| Move::release(&charge))
        .collect()
}

/// Every alias the index lists the blob under.
fn holders(claim: Option<&BlobClaim>) -> BTreeSet<&str> {
    let Some(claim) = claim else {
        return BTreeSet::new();
    };
    claim
        .aliases
        .iter()
        .map(String::as_str)
        .chain(claim.charges.iter().map(|charge| charge.alias.as_str()))
        .collect()
}

/// Write one claim change: the ledger moves, the per-repository index for
/// every alias that started or stopped holding the blob, and the row
/// (`None` deletes it). `before` is the row as read in this transaction.
pub(crate) fn commit(
    meta: &MetaEnv,
    txn: &mut RwTxn,
    sha256: &str,
    before: Option<&BlobClaim>,
    after: Option<&BlobClaim>,
    moves: &[Move],
) -> Result<()> {
    for change in moves {
        if change.add {
            quota::charge(meta, txn, &change.tenant, &change.alias, change.bytes, true)?;
        } else {
            quota::release(
                meta,
                txn,
                Some(&change.tenant),
                Some(&change.alias),
                change.bytes,
                true,
            )?;
        }
    }
    let had = holders(before);
    let has = holders(after);
    for alias in had.difference(&has) {
        meta.delete_alias_claim(txn, alias, sha256)?;
    }
    for alias in has.difference(&had) {
        meta.put_alias_claim(txn, alias, sha256)?;
    }
    match after {
        Some(claim) if before != Some(claim) => meta.put_blob_claim(txn, sha256, claim),
        Some(_) => Ok(()),
        None if before.is_some() => meta.delete_blob_claim(txn, sha256),
        None => Ok(()),
    }
}

/// [`attach`] and [`commit`] in one: `alias` of `tenant` references the
/// blob, declaring `declared` bytes. The caller has judged the quota.
pub(crate) fn attach_to(
    meta: &MetaEnv,
    txn: &mut RwTxn,
    sha256: &str,
    tenant: &str,
    alias: &str,
    declared: u64,
) -> Result<()> {
    let before = meta.get_blob_claim(txn, sha256)?;
    let mut claim = before.clone().unwrap_or_else(|| new_claim(declared));
    let moves = attach(&mut claim, tenant, alias, declared);
    commit(meta, txn, sha256, before.as_ref(), Some(&claim), &moves)?;
    // Idempotent. A referrer's entry is written even when the claim did not
    // change, so that its death always finds the blob.
    meta.put_alias_claim(txn, alias, sha256)
}

/// [`redeclare`] and [`commit`] in one. The caller has judged the quota.
pub(crate) fn redeclare_to(
    meta: &MetaEnv,
    txn: &mut RwTxn,
    sha256: &str,
    alias: &str,
    declared: u64,
) -> Result<()> {
    let Some(before) = meta.get_blob_claim(txn, sha256)? else {
        return Ok(());
    };
    let mut claim = before.clone();
    let moves = redeclare(&mut claim, alias, declared);
    commit(meta, txn, sha256, Some(&before), Some(&claim), &moves)
}

/// [`detach`] and [`commit`] in one. An index entry of `alias` that points
/// at a claim it no longer holds, or at no claim, is removed as well.
pub(crate) fn detach_from(
    meta: &MetaEnv,
    txn: &mut RwTxn,
    sha256: &str,
    alias: &str,
    now: u64,
) -> Result<()> {
    let Some(before) = meta.get_blob_claim(txn, sha256)? else {
        return meta.delete_alias_claim(txn, alias, sha256);
    };
    let mut claim = before.clone();
    let (moves, row) = detach(&mut claim, alias, now);
    let after = match row {
        Row::Keep => Some(&claim),
        Row::Delete => None,
    };
    commit(meta, txn, sha256, Some(&before), after, &moves)?;
    if !after.is_some_and(|claim| holds(claim, alias)) {
        meta.delete_alias_claim(txn, alias, sha256)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, HashSet};

    use super::*;
    use crate::grasp_p::meta::LEDGER_GLOBAL_KEY;

    const NOW: u64 = 1_000;

    fn sha(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn meta_env() -> (tempfile::TempDir, MetaEnv) {
        let dir = tempfile::tempdir().unwrap();
        let meta = MetaEnv::open(dir.path()).unwrap();
        (dir, meta)
    }

    fn claim(meta: &MetaEnv, sha256: &str) -> Option<BlobClaim> {
        let txn = meta.read_txn().unwrap();
        meta.get_blob_claim(&txn, sha256).unwrap()
    }

    fn blob_bytes(meta: &MetaEnv, key: &str) -> u64 {
        let txn = meta.read_txn().unwrap();
        meta.get_ledger_txn(&txn, key).unwrap().blob_bytes
    }

    fn repo(meta: &MetaEnv, alias: &str) -> u64 {
        blob_bytes(meta, &quota::alias_key(alias))
    }

    fn account(meta: &MetaEnv, tenant: &str) -> u64 {
        blob_bytes(meta, &quota::tenant_key(tenant))
    }

    fn node(meta: &MetaEnv) -> u64 {
        blob_bytes(meta, LEDGER_GLOBAL_KEY)
    }

    fn reference(meta: &MetaEnv, sha256: &str, tenant: &str, alias: &str, declared: u64) {
        meta.with_write(|m, txn| attach_to(m, txn, sha256, tenant, alias, declared))
            .unwrap();
    }

    fn unreference(meta: &MetaEnv, sha256: &str, alias: &str) {
        meta.with_write(|m, txn| detach_from(m, txn, sha256, alias, NOW))
            .unwrap();
    }

    /// The bytes arrive, as the mirror stores them: every charge is set to
    /// the stored size and nobody new is attached.
    fn store(meta: &MetaEnv, sha256: &str, size: u64) {
        meta.with_write(|m, txn| {
            let before = m.get_blob_claim(txn, sha256)?;
            let mut claim = before.clone().unwrap_or_else(|| new_claim(size));
            let moves = settle_stored(&mut claim, size, NOW);
            commit(m, txn, sha256, before.as_ref(), Some(&claim), &moves)
        })
        .unwrap();
    }

    /// What GC does to a blob it removes.
    fn purge(meta: &MetaEnv, sha256: &str) {
        meta.with_write(|m, txn| {
            let Some(before) = m.get_blob_claim(txn, sha256)? else {
                return Ok(());
            };
            let mut claim = before.clone();
            let moves = release_all(&mut claim);
            commit(m, txn, sha256, Some(&before), None, &moves)
        })
        .unwrap();
    }

    /// A repository dies: every blob it holds is left as by the death path.
    fn die(meta: &MetaEnv, alias: &str) {
        meta.with_write(|m, txn| {
            for sha256 in m.alias_claim_shas(txn, alias)? {
                detach_from(m, txn, &sha256, alias, NOW)?;
            }
            Ok(())
        })
        .unwrap();
    }

    /// The invariants every claim row and the ledger keep, over the
    /// repositories `repos` (alias, account) a test uses:
    ///
    /// - a row is charged or on disk;
    /// - one charge per referencing repository, none twice, and when no
    ///   repository references stored bytes at most one grace charge;
    /// - the index lists a blob under exactly the aliases that hold it;
    /// - the blob column of every scope is the sum of the charges in it.
    fn assert_invariants(meta: &MetaEnv, repos: &[(&str, &str)]) {
        let txn = meta.read_txn().unwrap();
        let claims = meta.all_blob_claims(&txn).unwrap();
        let mut by_key: BTreeMap<String, u64> = BTreeMap::new();
        for (sha256, claim) in &claims {
            assert!(
                !claim.charges.is_empty() || claim.stored,
                "{sha256}: a row that exists is charged or on disk: {claim:?}"
            );
            let aliases: HashSet<&str> = claim.aliases.iter().map(String::as_str).collect();
            assert_eq!(
                aliases.len(),
                claim.aliases.len(),
                "{sha256}: a repository references a blob once: {claim:?}"
            );
            let charged: HashSet<&str> = claim.charges.iter().map(|c| c.alias.as_str()).collect();
            assert_eq!(
                charged.len(),
                claim.charges.len(),
                "{sha256}: no repository is charged twice: {claim:?}"
            );
            if claim.aliases.is_empty() {
                assert!(
                    claim.stored && claim.charges.len() <= 1,
                    "{sha256}: an unreferenced row is stored bytes with at most a grace charge: {claim:?}"
                );
                assert!(claim.unreferenced_since.is_some(), "{sha256}: {claim:?}");
            } else {
                assert_eq!(
                    charged, aliases,
                    "{sha256}: every referencing repository pays, and only they: {claim:?}"
                );
                assert!(claim.unreferenced_since.is_none(), "{sha256}: {claim:?}");
            }
            if claim.stored {
                for charge in &claim.charges {
                    assert_eq!(
                        charge.bytes, claim.size,
                        "{sha256}: a stored blob is charged its stored size: {claim:?}"
                    );
                }
            }
            for charge in &claim.charges {
                for key in [
                    quota::alias_key(&charge.alias),
                    quota::tenant_key(&charge.tenant),
                    LEDGER_GLOBAL_KEY.to_string(),
                ] {
                    *by_key.entry(key).or_insert(0) += charge.bytes;
                }
            }
        }
        for (alias, tenant) in repos {
            let indexed: BTreeSet<String> = meta
                .alias_claim_shas(&txn, alias)
                .unwrap()
                .into_iter()
                .collect();
            let held: BTreeSet<String> = claims
                .iter()
                .filter(|(_, claim)| holds(claim, alias))
                .map(|(sha256, _)| sha256.clone())
                .collect();
            assert_eq!(indexed, held, "the index of {alias} lists what it holds");
            for key in [quota::alias_key(alias), quota::tenant_key(tenant)] {
                assert_eq!(
                    meta.get_ledger_txn(&txn, &key).unwrap().blob_bytes,
                    by_key.get(&key).copied().unwrap_or(0),
                    "the ledger at {key} is the sum of its charges"
                );
            }
        }
        assert_eq!(
            meta.get_ledger_txn(&txn, LEDGER_GLOBAL_KEY)
                .unwrap()
                .blob_bytes,
            by_key.get(LEDGER_GLOBAL_KEY).copied().unwrap_or(0),
            "the node's ledger is the sum of every charge"
        );
    }

    /// Issue 5: a repository that starts referencing a blob another account
    /// stored is charged for it like the uploader, and the disk keeps one
    /// copy.
    #[test]
    fn a_second_repository_pays_for_a_stored_blob() {
        let (_dir, meta) = meta_env();
        let x = sha(1);
        reference(&meta, &x, "ta", "ra", 600);
        store(&meta, &x, 512);
        reference(&meta, &x, "tb", "rb", 999);

        assert_eq!((repo(&meta, "ra"), account(&meta, "ta")), (512, 512));
        assert_eq!(
            (repo(&meta, "rb"), account(&meta, "tb")),
            (512, 512),
            "the second repository pays the stored size, not what it declared"
        );
        assert_eq!(node(&meta), 1024, "the node counts every charge");
        assert_invariants(&meta, &[("ra", "ta"), ("rb", "tb")]);
    }

    /// Issue 5's hostile form: the uploader drops the blob while another
    /// account still references it. The uploader is released at once and
    /// the other account goes on paying its own charge.
    #[test]
    fn dropping_a_shared_blob_releases_only_the_dropper() {
        let (_dir, meta) = meta_env();
        let x = sha(2);
        reference(&meta, &x, "ta", "ra", 512);
        store(&meta, &x, 512);
        reference(&meta, &x, "tb", "rb", 512);

        unreference(&meta, &x, "ra");
        assert_eq!((repo(&meta, "ra"), account(&meta, "ta")), (0, 0));
        assert_eq!((repo(&meta, "rb"), account(&meta, "tb")), (512, 512));
        assert_eq!(node(&meta), 512);
        assert_eq!(claim(&meta, &x).unwrap().aliases, vec!["rb".to_string()]);
        assert_invariants(&meta, &[("ra", "ta"), ("rb", "tb")]);
    }

    /// The last repository to stop referencing stored bytes keeps paying
    /// until GC removes them, so that a delete is not a free way to keep
    /// bytes on disk through the grace period.
    #[test]
    fn the_last_referrer_pays_until_the_bytes_are_removed() {
        let (_dir, meta) = meta_env();
        let x = sha(3);
        reference(&meta, &x, "ta", "ra", 512);
        store(&meta, &x, 512);

        unreference(&meta, &x, "ra");
        let kept = claim(&meta, &x).unwrap();
        assert!(kept.aliases.is_empty());
        assert_eq!(kept.unreferenced_since, Some(NOW));
        assert_eq!(charge_of(&kept, "ra"), Some(512));
        assert_eq!((repo(&meta, "ra"), node(&meta)), (512, 512));
        let txn = meta.read_txn().unwrap();
        assert_eq!(
            meta.alias_claim_shas(&txn, "ra").unwrap(),
            vec![x.clone()],
            "the index keeps the blob, so that the repository's death finds the charge"
        );
        drop(txn);
        // A second drop changes nothing.
        unreference(&meta, &x, "ra");
        assert_eq!(repo(&meta, "ra"), 512);
        assert_invariants(&meta, &[("ra", "ta")]);

        purge(&meta, &x);
        assert!(claim(&meta, &x).is_none());
        assert_eq!(
            (repo(&meta, "ra"), account(&meta, "ta"), node(&meta)),
            (0, 0, 0)
        );
        assert_invariants(&meta, &[("ra", "ta")]);
    }

    /// A repository that references bytes again during the grace period
    /// takes its own grace charge up again and is not charged twice; any
    /// other repository takes the bill over from the last referrer.
    #[test]
    fn a_grace_charge_is_taken_up_once() {
        let (_dir, meta) = meta_env();
        let x = sha(4);
        reference(&meta, &x, "ta", "ra", 512);
        store(&meta, &x, 512);
        unreference(&meta, &x, "ra");

        reference(&meta, &x, "ta", "ra", 512);
        assert_eq!((repo(&meta, "ra"), node(&meta)), (512, 512));
        assert!(claim(&meta, &x).unwrap().unreferenced_since.is_none());
        assert_invariants(&meta, &[("ra", "ta")]);

        unreference(&meta, &x, "ra");
        reference(&meta, &x, "tb", "rb", 512);
        assert_eq!(repo(&meta, "ra"), 0, "the last referrer is released");
        assert_eq!(repo(&meta, "rb"), 512);
        assert_eq!(node(&meta), 512, "one charge moved, none added");
        assert_invariants(&meta, &[("ra", "ta"), ("rb", "tb")]);
    }

    /// A claim nobody stored is deleted with its last reference, and its
    /// charges go with it at once.
    #[test]
    fn a_never_stored_claim_is_deleted_with_its_last_reference() {
        let (_dir, meta) = meta_env();
        let x = sha(5);
        reference(&meta, &x, "ta", "ra", 4096);
        reference(&meta, &x, "tb", "rb", 100);
        assert_eq!((repo(&meta, "ra"), repo(&meta, "rb")), (4096, 100));

        unreference(&meta, &x, "ra");
        assert!(claim(&meta, &x).is_some(), "rb still references it");
        assert_eq!(node(&meta), 100);

        unreference(&meta, &x, "rb");
        assert!(
            claim(&meta, &x).is_none(),
            "the row goes with the last reference"
        );
        assert_eq!(node(&meta), 0);
        assert_invariants(&meta, &[("ra", "ta"), ("rb", "tb")]);
    }

    /// A repository that dies is released at once from what another
    /// repository still references and from what nobody stored (that claim
    /// goes), and keeps the charge of stored bytes it was the last to
    /// reference until GC removes them, as before this change: released at
    /// the death, a register, upload, delete loop would keep bytes on disk
    /// that no quota counts. After GC nothing of it is left.
    #[test]
    fn a_dying_repository_keeps_only_the_grace_charges_of_stored_bytes() {
        let (_dir, meta) = meta_env();
        let (shared, alone, dropped, declared) = (sha(6), sha(7), sha(8), sha(9));
        for x in [&shared, &alone, &dropped] {
            reference(&meta, x, "ta", "ra", 300);
            store(&meta, x, 300);
        }
        reference(&meta, &shared, "tb", "rb", 300);
        reference(&meta, &declared, "ta", "ra", 4096);
        unreference(&meta, &dropped, "ra");
        assert_eq!(
            repo(&meta, "ra"),
            3 * 300 + 4096,
            "the dropped blob's grace charge included"
        );

        die(&meta, "ra");
        assert_eq!(
            (repo(&meta, "ra"), account(&meta, "ta")),
            (600, 600),
            "only the stored bytes nobody else references stay charged"
        );
        assert_eq!(repo(&meta, "rb"), 300, "the other repository keeps its own");
        assert_eq!(node(&meta), 900);
        let txn = meta.read_txn().unwrap();
        let held: BTreeSet<String> = meta
            .alias_claim_shas(&txn, "ra")
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(held, BTreeSet::from([alone.clone(), dropped.clone()]));
        drop(txn);
        assert_eq!(
            claim(&meta, &shared).unwrap().aliases,
            vec!["rb".to_string()]
        );
        assert!(claim(&meta, &declared).is_none());
        assert_invariants(&meta, &[("ra", "ta"), ("rb", "tb")]);

        for x in [&alone, &dropped] {
            purge(&meta, x);
        }
        assert_eq!(
            (repo(&meta, "ra"), account(&meta, "ta"), node(&meta)),
            (0, 0, 300)
        );
        let txn = meta.read_txn().unwrap();
        assert!(meta.alias_claim_shas(&txn, "ra").unwrap().is_empty());
        drop(txn);
        assert_invariants(&meta, &[("ra", "ta"), ("rb", "tb")]);
    }

    /// Before the bytes are here a repository pays what its newest edition
    /// declares, so a node that applied an earlier edition and one that
    /// applied only the newest charge the same; once the bytes are here the
    /// stored size decides and a new declaration changes nothing.
    #[test]
    fn the_newest_declaration_sets_the_charge_until_the_bytes_arrive() {
        fn edition(meta: &MetaEnv, sha256: &str, declared: u64) {
            meta.with_write(|m, txn| {
                attach_to(m, txn, sha256, "ta", "ra", declared)?;
                redeclare_to(m, txn, sha256, "ra", declared)
            })
            .unwrap();
        }
        let x = sha(12);
        let (_dir_a, node_a) = meta_env();
        edition(&node_a, &x, 100);
        edition(&node_a, &x, 200);
        let (_dir_b, node_b) = meta_env();
        edition(&node_b, &x, 200);
        for meta in [&node_a, &node_b] {
            assert_eq!(
                (repo(meta, "ra"), account(meta, "ta"), node(meta)),
                (200, 200, 200)
            );
            assert_invariants(meta, &[("ra", "ta")]);
        }

        store(&node_a, &x, 150);
        edition(&node_a, &x, 999);
        assert_eq!(
            repo(&node_a, "ra"),
            150,
            "stored: the declaration is ignored"
        );
        assert_invariants(&node_a, &[("ra", "ta")]);
    }

    /// When the bytes arrive every repository's charge is set to their
    /// size, whatever each one declared.
    #[test]
    fn storing_sets_every_charge_to_the_stored_size() {
        let (_dir, meta) = meta_env();
        let x = sha(10);
        reference(&meta, &x, "ta", "ra", 500);
        reference(&meta, &x, "tb", "rb", 100);
        reference(&meta, &x, "ta", "rc", 300);
        assert_eq!(node(&meta), 900);

        store(&meta, &x, 300);
        assert_eq!(
            (repo(&meta, "ra"), repo(&meta, "rb"), repo(&meta, "rc")),
            (300, 300, 300)
        );
        assert_eq!(
            account(&meta, "ta"),
            600,
            "two repositories of one account count twice"
        );
        assert_eq!(node(&meta), 900);
        assert_invariants(&meta, &[("ra", "ta"), ("rb", "tb"), ("rc", "ta")]);
    }

    /// GC's purge releases each charge exactly once, and a repeat finds
    /// nothing to release.
    #[test]
    fn a_purge_releases_every_charge_once() {
        let (_dir, meta) = meta_env();
        let x = sha(11);
        reference(&meta, &x, "ta", "ra", 64);
        reference(&meta, &x, "tb", "rb", 64);
        store(&meta, &x, 64);
        purge(&meta, &x);
        purge(&meta, &x);
        assert_eq!(
            (repo(&meta, "ra"), repo(&meta, "rb"), node(&meta)),
            (0, 0, 0)
        );
        assert!(claim(&meta, &x).is_none());
        assert_invariants(&meta, &[("ra", "ta"), ("rb", "tb")]);
    }

    /// The forecast a caller judges quota with is what the write does.
    #[test]
    fn moves_sum_to_what_the_ledger_records() {
        let mut claim = new_claim(100);
        let mut moves = attach(&mut claim, "ta", "ra", 100);
        moves.extend(attach(&mut claim, "ta", "ra", 100));
        moves.extend(attach(&mut claim, "tb", "rb", 70));
        moves.extend(settle_stored(&mut claim, 80, NOW));
        let total: i128 = moves.iter().map(Move::delta).sum();
        assert_eq!(total, 160, "two charges of the stored size");
        assert_eq!(charge_of(&claim, "ra"), Some(80));
        assert_eq!(charge_of(&claim, "rb"), Some(80));
    }

    /// A small deterministic generator, so that the sequences below are
    /// the same on every run.
    struct Lcg(u64);

    impl Lcg {
        fn pick(&mut self, below: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((self.0 >> 33) % below as u64) as usize
        }
    }

    const REPOS: [(&str, &str); 5] = [
        ("r0", "t0"),
        ("r1", "t0"),
        ("r2", "t1"),
        ("r3", "t1"),
        ("r4", "t2"),
    ];

    /// (sha256, stored size, declared size): a few blobs are declared at a
    /// size they do not have.
    fn blobs() -> Vec<(String, u64, u64)> {
        (0..6u8)
            .map(|n| {
                let size = 100 + u64::from(n) * 37;
                let declared = if n.is_multiple_of(3) { size + 11 } else { size };
                (sha(40 + n), size, declared)
            })
            .collect()
    }

    /// Any order of references, drops, stores, deaths and purges keeps
    /// every invariant after every step.
    #[test]
    fn random_operations_keep_every_invariant() {
        let blobs = blobs();
        for seed in 1..=8u64 {
            let (_dir, meta) = meta_env();
            let mut rng = Lcg(seed);
            let mut dead: HashSet<&str> = HashSet::new();
            for step in 0..200 {
                let (alias, tenant) = REPOS[rng.pick(REPOS.len())];
                let (x, size, declared) = &blobs[rng.pick(blobs.len())];
                match rng.pick(10) {
                    0..=3 if !dead.contains(alias) => reference(&meta, x, tenant, alias, *declared),
                    4..=5 => unreference(&meta, x, alias),
                    6..=7 => store(&meta, x, *size),
                    8 if step % 5 == 0 => {
                        die(&meta, alias);
                        dead.insert(alias);
                        let txn = meta.read_txn().unwrap();
                        for (sha256, claim) in meta.all_blob_claims(&txn).unwrap() {
                            if charge_of(&claim, alias).is_some() {
                                assert!(
                                    claim.stored && claim.aliases.is_empty(),
                                    "seed {seed}: {alias} died and keeps only grace \
                                     charges of stored bytes: {sha256} {claim:?}"
                                );
                            }
                        }
                    }
                    9 => {
                        if claim(&meta, x).is_some_and(|c| c.aliases.is_empty()) {
                            purge(&meta, x);
                        }
                    }
                    _ => {}
                }
                assert_invariants(&meta, &REPOS);
            }
        }
    }

    /// One node's view of a pair: what each repository's successive state
    /// roots reference (indexes into [`blobs`]), and which repository dies
    /// after its last one.
    struct History {
        editions: Vec<Vec<Vec<usize>>>,
        dies: Vec<bool>,
    }

    fn history() -> History {
        History {
            editions: vec![
                vec![vec![0, 1], vec![1, 2], vec![2, 3]],
                vec![vec![0], vec![0, 4]],
                vec![vec![1, 2, 5], vec![2], vec![2, 4, 5]],
                vec![vec![3, 4], vec![0, 3]],
                vec![vec![5], vec![], vec![1, 5]],
            ],
            dies: vec![false, false, false, true, false],
        }
    }

    enum Step {
        Edition(usize, usize),
        Store(usize),
        Death(usize),
    }

    /// Every step of the history in an order `seed` picks. Each
    /// repository's state roots keep their own order (a node applies only
    /// a newer edition), a death comes after the repository's last edition,
    /// and every blob arrives once. Its arrival settles every charge and adds
    /// no reference, as the mirror's store does; a client's upload would also
    /// attach the uploader, which this history leaves out (such a reference
    /// is known only to the node that took the upload until the
    /// repository's next state root).
    fn arrival_order(history: &History, seed: u64) -> Vec<Step> {
        let mut rng = Lcg(seed);
        let mut next_edition = vec![0usize; history.editions.len()];
        let mut died = vec![false; history.editions.len()];
        let mut stored = vec![false; blobs().len()];
        let mut order = Vec::new();
        loop {
            let mut ready: Vec<Step> = Vec::new();
            for (repo, editions) in history.editions.iter().enumerate() {
                if next_edition[repo] < editions.len() {
                    ready.push(Step::Edition(repo, next_edition[repo]));
                } else if history.dies[repo] && !died[repo] {
                    ready.push(Step::Death(repo));
                }
            }
            for (blob, done) in stored.iter().enumerate() {
                if !done {
                    ready.push(Step::Store(blob));
                }
            }
            if ready.is_empty() {
                return order;
            }
            let step = ready.swap_remove(rng.pick(ready.len()));
            match &step {
                Step::Edition(repo, _) => next_edition[*repo] += 1,
                Step::Store(blob) => stored[*blob] = true,
                Step::Death(repo) => died[*repo] = true,
            }
            order.push(step);
        }
    }

    /// Apply one node's arrival order, then let GC remove every blob nobody
    /// references (its grace period over), and read the ledger.
    fn run_node(history: &History, order: &[Step]) -> BTreeMap<String, u64> {
        let blobs = blobs();
        let (_dir, meta) = meta_env();
        for step in order {
            match *step {
                Step::Edition(repo, edition) => {
                    let (alias, tenant) = REPOS[repo];
                    let named = &history.editions[repo][edition];
                    // A state root: attach what it names, drop the rest
                    // (one retained edition).
                    let wanted: HashSet<&str> =
                        named.iter().map(|&b| blobs[b].0.as_str()).collect();
                    for &b in named {
                        reference(&meta, &blobs[b].0, tenant, alias, blobs[b].2);
                    }
                    let held = {
                        let txn = meta.read_txn().unwrap();
                        meta.alias_claim_shas(&txn, alias).unwrap()
                    };
                    for x in held.iter().filter(|x| !wanted.contains(x.as_str())) {
                        unreference(&meta, x, alias);
                    }
                }
                Step::Store(blob) => store(&meta, &blobs[blob].0, blobs[blob].1),
                Step::Death(repo) => die(&meta, REPOS[repo].0),
            }
            assert_invariants(&meta, &REPOS);
        }
        for (x, _, _) in &blobs {
            if claim(&meta, x).is_some_and(|c| c.aliases.is_empty()) {
                purge(&meta, x);
            }
        }
        assert_invariants(&meta, &REPOS);
        let mut keys: Vec<String> = vec![LEDGER_GLOBAL_KEY.to_string()];
        for (alias, tenant) in REPOS {
            keys.push(quota::alias_key(alias));
            keys.push(quota::tenant_key(tenant));
        }
        keys.into_iter()
            .map(|key| {
                let bytes = blob_bytes(&meta, &key);
                (key, bytes)
            })
            .collect()
    }

    /// Decision D4's promise to a pair: whatever order the state roots,
    /// uploads and mirror fetches arrive in, both nodes reach the same
    /// ledger, and it is what the repositories reference at the end, each
    /// blob at its stored size, a dead repository at nothing.
    #[test]
    fn pair_ledgers_agree_in_any_arrival_order() {
        let history = history();
        let blobs = blobs();
        let mut expected: HashMap<String, u64> = HashMap::new();
        for (repo, editions) in history.editions.iter().enumerate() {
            if history.dies[repo] {
                continue;
            }
            let (alias, tenant) = REPOS[repo];
            let last = editions.last().cloned().unwrap_or_default();
            let unique: BTreeSet<usize> = last.into_iter().collect();
            for b in unique {
                for key in [
                    quota::alias_key(alias),
                    quota::tenant_key(tenant),
                    LEDGER_GLOBAL_KEY.to_string(),
                ] {
                    *expected.entry(key).or_insert(0) += blobs[b].1;
                }
            }
        }

        for (seed_a, seed_b) in [(1, 2), (3, 4), (5, 6), (7, 8), (9, 10), (11, 12)] {
            let node_a = run_node(&history, &arrival_order(&history, seed_a));
            let node_b = run_node(&history, &arrival_order(&history, seed_b));
            assert_eq!(node_a, node_b, "seeds {seed_a} and {seed_b}");
            for (key, bytes) in &node_a {
                assert_eq!(
                    *bytes,
                    expected.get(key).copied().unwrap_or(0),
                    "seeds {seed_a}/{seed_b}: {key}"
                );
            }
        }
    }
}
