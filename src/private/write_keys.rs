//! Write/aux-key index queries over the meta store's `key_claims` table.

use anyhow::Result;

use super::meta::{MetaEnv, RegistrationRecord};

/// Where a claimed key sits within its alias's registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// Full write key (`w` tag): may publish 30641s and PUT/DELETE blobs.
    Write,
    /// Aux (stream/publish) key: may publish wraps only.
    Aux,
}

/// Resolve a pubkey (lowercase hex) to its claiming alias + registration +
/// role, if any. Purely a meta lookup — callers still need the DB liveness
/// check via `PrivateService::live_registration`.
pub fn find_claim(
    meta: &MetaEnv,
    pubkey_hex: &str,
) -> Result<Option<(String, RegistrationRecord, KeyRole)>> {
    let txn = meta.read_txn()?;
    let Some(alias) = meta.get_key_claim(&txn, pubkey_hex)? else {
        return Ok(None);
    };
    let Some(record) = meta.get_registration(&txn, &alias)? else {
        return Ok(None);
    };
    let role = if record.w_keys.iter().any(|k| k == pubkey_hex) {
        KeyRole::Write
    } else if record.aux_keys.iter().any(|k| k == pubkey_hex) {
        KeyRole::Aux
    } else {
        // Stale claim row (should not happen — claims are diffed atomically).
        return Ok(None);
    };
    Ok(Some((alias, record, role)))
}
