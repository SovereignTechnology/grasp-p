//! Kind-30641 state root: validation, edition-ring append (G7 amendment), and
//! blob claim maintenance.

use nostr::prelude::{Event, Filter, Kind};
use nostr_sdk::local_relay::WritePolicyResult;

use crate::nostr::policy::{reject_error, reject_invalid, reject_restricted};

use super::meta::{BlobClaim, MetaEnv, RegistrationRecord, SpecCharge};
use super::{quota, PrivateConfig, PrivateService};

/// Hard cap on the number of blob references (`m` + `pack` tags) accepted per
/// kind-30641. A 128 KiB event can pack ~1500 refs, and `handle()` creates a
/// persistent `stored=false` [`BlobClaim`] per referenced sha, then rescans
/// every retained edition under the global meta write lock. 256 refs is far
/// above any realistic repo edition.
///
/// Since issue !12, not-yet-stored declared blobs are also CHARGED to the
/// declaring (tenant, alias) at their declared size ([`SpecCharge`]), so a
/// flood of editions carrying fake pack refs runs into the tenant's own
/// quota instead of growing the shared meta LMDB unbilled. The charge is
/// released when the blob is actually stored (the upload path takes over
/// the accounting) or when the claim is GC'd after losing its last alias.
const MAX_BLOB_REFS_PER_STATE_ROOT: usize = 256;

/// One manifest/pack reference from a 30641: (sha256, declared size).
struct BlobRef {
    sha256: String,
    size: u64,
}

fn parse_blob_tag(values: &[String]) -> Result<BlobRef, String> {
    if values.len() < 2 {
        return Err("m/pack tags must be [name, sha256, bytes]".to_string());
    }
    let sha256 = values[0].clone();
    if !super::blossom_auth::is_lower_hex_64(&sha256) {
        return Err("m/pack hashes must be 64 lowercase hex chars".to_string());
    }
    let size = values[1]
        .parse::<u64>()
        .map_err(|_| "m/pack sizes must parse as u64".to_string())?;
    Ok(BlobRef { sha256, size })
}

pub(crate) struct ParsedStateRoot {
    alias: String,
    coordinate: String,
    blobs: Vec<BlobRef>,
}

pub(crate) fn parse_shape(event: &Event, max_blob_bytes: u64) -> Result<ParsedStateRoot, String> {
    let mut alias: Option<String> = None;
    let mut coordinate: Option<String> = None;
    let mut manifest: Option<BlobRef> = None;
    let mut packs: Vec<BlobRef> = Vec::new();

    for tag in event.tags.iter() {
        let v = tag.clone().to_vec();
        if v.len() < 2 {
            continue;
        }
        match v[0].as_str() {
            // FIRST d/a tag wins, matching the nostr addressable identifier
            // and `registration.rs::first_tag_value` — otherwise a multi-d-tag
            // 30641 would validate against a different alias than the DB
            // coordinate it is stored under.
            "d" => {
                if alias.is_none() {
                    alias = Some(v[1].clone());
                }
            }
            "a" => {
                if coordinate.is_none() {
                    coordinate = Some(v[1].clone());
                }
            }
            "m" => {
                if manifest.is_some() {
                    return Err("state root must carry exactly one m tag".to_string());
                }
                manifest = Some(parse_blob_tag(&v[1..])?);
            }
            "pack" => packs.push(parse_blob_tag(&v[1..])?),
            _ => {}
        }
    }

    let alias = alias.ok_or_else(|| "state root must carry a d tag".to_string())?;
    if !super::registration::is_valid_alias(&alias) {
        return Err("state root d tag must be exactly 32 lowercase hex chars".to_string());
    }
    let coordinate = coordinate
        .ok_or_else(|| "state root must carry an a tag (30640:<tenant>:<alias>)".to_string())?;
    let manifest =
        manifest.ok_or_else(|| "state root must carry an m (manifest) tag".to_string())?;

    let mut blobs = vec![manifest];
    blobs.extend(packs);
    if blobs.len() > MAX_BLOB_REFS_PER_STATE_ROOT {
        return Err(format!(
            "state root references more than {MAX_BLOB_REFS_PER_STATE_ROOT} blobs"
        ));
    }
    for blob in &blobs {
        if blob.size > max_blob_bytes {
            return Err("state root references a blob larger than the per-blob limit".to_string());
        }
    }

    Ok(ParsedStateRoot {
        alias,
        coordinate,
        blobs,
    })
}

/// Handle a kind-30641 state root event.
pub(crate) async fn handle(svc: &PrivateService, event: &Event) -> WritePolicyResult {
    let cfg = &svc.cfg;

    if let Some(rejection) = super::check_not_future_dated(event) {
        return rejection;
    }

    let event_json = event.as_json();
    if event_json.len() as u64 > cfg.max_event_bytes {
        return reject_restricted("event exceeds private repo size limit");
    }

    let parsed = match parse_shape(event, cfg.max_blob_bytes) {
        Ok(p) => p,
        Err(reason) => return reject_invalid(reason),
    };

    // Registration must be live (meta record + 30640 coordinate still in the
    // relay DB — self-healing against missed deletes).
    // FS-7 (review G2-F2): the message must contain "unregistered" — the
    // cord-git widen trigger is that substring (HANDOFF gotcha 11: any
    // "unregistered" message is the widenable case); the previous
    // "alias is not registered" did not match and was fatal client-side
    // instead of recoverable.
    let record = match svc.live_registration(&parsed.alias).await {
        Ok(Some(record)) => record,
        Ok(None) => return reject_restricted("unregistered alias"),
        Err(e) => {
            tracing::warn!("private state-root liveness check failed: {e}");
            return reject_error("private liveness check failed");
        }
    };

    // The a tag must match the live registration's coordinate.
    let expected = format!("30640:{}:{}", record.tenant_hex, parsed.alias);
    if parsed.coordinate != expected {
        return reject_invalid("state root a tag does not match the live registration");
    }

    // Signed by a registered WRITE key (aux keys cannot publish state roots).
    let author_hex = event.pubkey.to_hex();
    if !record.w_keys.contains(&author_hex) {
        return reject_restricted("event author is not a registered write key for this alias");
    }

    // §4b: apply meta changes (ring append + quota charge) ONLY when the relay
    // DB will actually store this edition. Ring membership alone is not a
    // sufficient dedup: a replayed edition older than the retained ring (or
    // older than the stored latest, which nostr-lmdb discards as
    // Replaced/Duplicate) would otherwise re-charge the ledger on every
    // replay. Mirror the DB's addressable replacement ordering against the
    // stored latest for this (author, alias) coordinate.
    let stored_filter = Filter::new()
        .kind(Kind::Custom(super::KIND_STATE_ROOT))
        .author(event.pubkey)
        .identifier(&parsed.alias)
        .limit(1);
    match svc.database.query(stored_filter).await {
        Ok(stored) => {
            if let Some(latest) = stored.into_iter().next() {
                let strictly_newer = event.created_at > latest.created_at
                    || (event.created_at == latest.created_at
                        && event.id.to_hex() < latest.id.to_hex());
                if !strictly_newer {
                    // Replay or out-of-order older edition: the DB will reject
                    // it as Duplicate/Replaced — accept without meta changes.
                    return WritePolicyResult::Accept;
                }
            }
        }
        Err(e) => {
            tracing::warn!("private state-root replacement query failed: {e}");
            return reject_error("private liveness check failed");
        }
    }

    let result = svc.meta.with_write(|meta, txn| {
        apply_state_root_txn(meta, txn, cfg, &record, &parsed, event, &event_json)
    });

    match result {
        Ok(Some(rejection)) => rejection,
        Ok(None) => {
            svc.refresh_gauges();
            WritePolicyResult::Accept
        }
        Err(e) => {
            tracing::warn!("private state-root meta update failed: {e}");
            reject_error("private meta store failure")
        }
    }
}

/// The meta transaction for an accepted 30641 — extracted from [`handle`] so
/// the R2-C in-txn identity re-check is testable against a stale pre-txn
/// `record` without racing a live handler. Returns `Ok(None)` to accept,
/// `Ok(Some(rejection))` to reject WITHOUT any mutation.
pub(crate) fn apply_state_root_txn(
    meta: &MetaEnv,
    txn: &mut heed::RwTxn,
    cfg: &PrivateConfig,
    record: &RegistrationRecord,
    parsed: &ParsedStateRoot,
    event: &Event,
    event_json: &str,
) -> anyhow::Result<Option<WritePolicyResult>> {
    let alias = &parsed.alias;
    let tenant_hex = &record.tenant_hex;
    let created_at = event.created_at.as_secs();
    let event_id_hex = event.id.to_hex();
    let event_bytes = event_json.len() as u64;
    let editions = cfg.state_history_editions as usize;

    // R2-C (verify round 2): FIRST, before any mutation, re-verify the
    // registration's identity inside the txn. Liveness was checked outside
    // it, and an eviction/death can land in between; committing with the
    // stale record would re-create claims + spec charges billed to the dead
    // scope with no cleanup trigger left (GC needs empty aliases, the
    // release loop needs a live registration, the death path early-returns
    // on replays, and zombie ring editions actively defend the zombie
    // claims via the rescan below).
    // The reason string is deliberately distinct from the genuine
    // "unregistered alias" liveness rejection above: an honest
    // same-tenant rotation also trips this arm (event_id moved), and that
    // race is TRANSIENT — a retry under the new record succeeds. Callers
    // must be able to tell the two apart (verify round 3).
    if !super::registration_identity_intact(meta, txn, alias, tenant_hex, &record.event_id)? {
        return Ok(Some(reject_restricted("alias registration changed; retry")));
    }

    let ring_key = MetaEnv::state_ring_key(alias, created_at, &event_id_hex);
    if meta.state_ring_contains(txn, &ring_key)? {
        // Idempotent by event id: replayed edition, nothing to do.
        return Ok(None);
    }

    // Issue !12: blobs this edition declares that are not yet stored and
    // carry no earlier speculative charge get charged NOW, at declared
    // size, to this (tenant, alias). Compute the total first so the
    // quota check covers event bytes + all new speculative bytes in one
    // decision (two separate checks could each pass while the sum
    // exceeds a cap).
    let mut spec_shas: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut spec_new_bytes = 0u64;
    for blob in &parsed.blobs {
        if spec_shas.contains(&blob.sha256) {
            continue; // duplicate ref within one edition
        }
        let needs_spec_charge = match meta.get_blob_claim(txn, &blob.sha256)? {
            None => true,
            Some(c) => !c.stored && c.spec_charge.is_none(),
        };
        if needs_spec_charge {
            spec_new_bytes = spec_new_bytes.saturating_add(blob.size);
            spec_shas.insert(blob.sha256.clone());
        }
    }

    if !quota::check(
        meta,
        txn,
        cfg,
        tenant_hex,
        alias,
        event_bytes.saturating_add(spec_new_bytes),
    )? {
        return Ok(Some(reject_restricted("quota exceeded")));
    }

    // Append to the ring, then trim to the newest N editions.
    meta.put_state_ring(txn, &ring_key, event_json)?;
    let ring = meta.state_ring_for_alias(txn, alias)?;
    let excess = ring.len().saturating_sub(editions);
    for (key, _) in ring.iter().take(excess) {
        meta.delete_state_ring(txn, key)?;
    }
    let retained: Vec<(String, String)> = ring.into_iter().skip(excess).collect();

    // Recompute the set of hashes referenced by ANY retained edition.
    let mut referenced = std::collections::HashSet::new();
    for (_, json) in &retained {
        if let Ok(edition) = nostr::prelude::Event::from_json(json.as_bytes()) {
            for tag in edition.tags.iter() {
                let v = tag.clone().to_vec();
                if v.len() >= 2 && (v[0] == "m" || v[0] == "pack") {
                    referenced.insert(v[1].clone());
                }
            }
        }
    }

    let now = nostr::prelude::Timestamp::now().as_secs();

    // Claim the hashes of the new edition for this alias, attaching the
    // speculative charge to the ones computed above (issue !12).
    for blob in &parsed.blobs {
        let mut claim = meta
            .get_blob_claim(txn, &blob.sha256)?
            .unwrap_or(BlobClaim {
                size: blob.size,
                aliases: Vec::new(),
                unreferenced_since: None,
                stored: false,
                charged_tenant: None,
                charged_alias: None,
                spec_charge: None,
                stored_at: None,
            });
        if spec_shas.remove(&blob.sha256) && !claim.stored && claim.spec_charge.is_none() {
            claim.spec_charge = Some(SpecCharge {
                tenant: tenant_hex.clone(),
                alias: alias.clone(),
                bytes: blob.size,
            });
        }
        if !claim.aliases.contains(alias) {
            claim.aliases.push(alias.clone());
            meta.put_alias_claim(txn, alias, &blob.sha256)?;
        }
        claim.unreferenced_since = None;
        meta.put_blob_claim(txn, &blob.sha256, &claim)?;
    }
    if spec_new_bytes > 0 {
        // One aggregate blob-column charge for all new speculative
        // declarations (all scoped to this same tenant + alias).
        quota::charge(meta, txn, tenant_hex, alias, spec_new_bytes, true)?;
    }

    // Release this alias's claim on hashes no retained edition references
    // (alias-index prefix scan, not a cross-tenant table scan).
    for sha in meta.alias_claim_shas(txn, alias)? {
        if referenced.contains(&sha) {
            continue;
        }
        let Some(mut claim) = meta.get_blob_claim(txn, &sha)? else {
            meta.delete_alias_claim(txn, alias, &sha)?;
            continue;
        };
        if claim.aliases.contains(alias) {
            claim.aliases.retain(|a| a != alias);
            // FH (verify round 1): the removed alias was CARRYING the
            // speculative charge and other aliases still reference the
            // sha — release the charge (exactly once, against the
            // recorded scope/bytes, never `claim.size`). The declarer no
            // longer makes the declaration, so it must not keep paying;
            // the remaining referrer is charged on its next referencing
            // 30641 (spec_charge is `None` again, so the dedup above
            // charges it then). Releasing only here — never while the
            // charging alias still references the sha in a retained
            // edition — keeps the declaration billed exactly once.
            let release_spec = !claim.aliases.is_empty()
                && claim
                    .spec_charge
                    .as_ref()
                    .map(|spec| &spec.alias == alias)
                    .unwrap_or(false);
            if release_spec {
                let spec = claim.spec_charge.take().expect("spec charge present");
                quota::release_spec_charge(meta, txn, &spec)?;
            }
            if claim.aliases.is_empty() && claim.unreferenced_since.is_none() {
                claim.unreferenced_since = Some(now);
            }
            meta.put_blob_claim(txn, &sha, &claim)?;
        }
        meta.delete_alias_claim(txn, alias, &sha)?;
    }

    quota::charge(meta, txn, tenant_hex, alias, event_bytes, false)?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Tag};

    const KIND_STATE_ROOT: u16 = super::super::KIND_STATE_ROOT;

    fn sha(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn base_tags(pubkey_hex: &str, alias: &str) -> Vec<Tag> {
        vec![
            Tag::custom("d", vec![alias.to_string()]),
            Tag::custom("a", vec![format!("30640:{pubkey_hex}:{alias}")]),
            // Exactly one manifest tag.
            Tag::custom("m", vec![sha(0), "10".to_string()]),
        ]
    }

    /// A 30641 carrying more than [`MAX_BLOB_REFS_PER_STATE_ROOT`] blob refs is
    /// rejected by `parse_shape`, so the unbounded-claim DoS (B1) cannot land.
    #[test]
    fn over_cap_blob_refs_rejected() {
        let keys = Keys::generate();
        let alias = "a".repeat(32);
        let mut tags = base_tags(&keys.public_key().to_hex(), &alias);
        // One manifest + MAX packs == MAX + 1 refs → over the cap.
        for i in 0..MAX_BLOB_REFS_PER_STATE_ROOT {
            tags.push(Tag::custom(
                "pack",
                vec![sha((i % 250 + 1) as u8), "10".to_string()],
            ));
        }
        let event = EventBuilder::new(Kind::Custom(KIND_STATE_ROOT), "")
            .tags(tags)
            .finalize(&keys)
            .expect("sign");

        let err = parse_shape(&event, u64::MAX)
            .err()
            .expect("over-cap must be rejected");
        assert!(err.contains("more than"), "unexpected reason: {err}");
    }

    /// A 30641 at exactly the cap still parses successfully.
    #[test]
    fn at_cap_blob_refs_accepted() {
        let keys = Keys::generate();
        let alias = "b".repeat(32);
        let mut tags = base_tags(&keys.public_key().to_hex(), &alias);
        // One manifest + (MAX - 1) packs == MAX refs → at the cap.
        for i in 0..(MAX_BLOB_REFS_PER_STATE_ROOT - 1) {
            tags.push(Tag::custom(
                "pack",
                vec![sha((i % 250 + 1) as u8), "10".to_string()],
            ));
        }
        let event = EventBuilder::new(Kind::Custom(KIND_STATE_ROOT), "")
            .tags(tags)
            .finalize(&keys)
            .expect("sign");

        assert!(parse_shape(&event, u64::MAX).is_ok());
    }
}
