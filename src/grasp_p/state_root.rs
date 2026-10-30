//! Kind-30641 state root: validation, edition-ring append (G7 amendment), and
//! blob claim maintenance (who pays: `claims.rs`).

use nostr::prelude::{Event, Filter, Kind};
use nostr_sdk::local_relay::WritePolicyResult;

use crate::nostr::policy::{reject_error, reject_invalid, reject_restricted};

use super::claims;
use super::meta::{MetaEnv, RegistrationRecord};
use super::{quota, PrivateConfig, PrivateService};

/// Hard cap on the number of blob references (`m` + `pack` tags) accepted per
/// kind-30641. A 128 KiB event can pack ~1500 refs, and `handle()` creates a
/// persistent `stored=false` [`BlobClaim`](super::meta::BlobClaim) per referenced sha, then rescans
/// every retained edition under the global meta write lock. 256 refs is far
/// above any realistic repo edition.
///
/// Every referenced blob is CHARGED to the referencing repository, at its
/// declared size until the bytes are stored here and at the stored size
/// after (`claims.rs`), so a flood of editions carrying fake pack refs runs
/// into the tenant's own quota instead of growing the shared meta LMDB
/// unbilled. A blob nobody stored loses its claim with its last reference.
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
        return reject_restricted(super::admission::OVERSIZE_REJECT_MESSAGE);
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
        Ok(None) => return reject_restricted(super::admission::STATE_ROOT_UNREGISTERED_ALIAS),
        Err(e) => {
            tracing::warn!("private state-root liveness check failed: {e}");
            return reject_error("private liveness check failed");
        }
    };

    // The a tag must match the live registration's coordinate.
    let expected = format!("30640:{}:{}", record.tenant_hex, parsed.alias);
    if parsed.coordinate != expected {
        return reject_invalid(super::admission::STATE_ROOT_COORDINATE_MISMATCH);
    }

    // Signed by a registered WRITE key (aux keys cannot publish state roots).
    let author_hex = event.pubkey.to_hex();
    if !record.w_keys.contains(&author_hex) {
        return reject_restricted(super::admission::STATE_ROOT_AUTHOR_NOT_WRITE_KEY);
    }

    // Decision D9: a listed account's state roots are refused, from a client
    // and from sync; upstream refused only those its listed key signed. After
    // the key checks, so only a write key of the repository learns that its
    // account is listed, and before the replay check, so no edition of a
    // frozen account counts as accepted.
    if let Some(reason) = svc.write_blocked(&author_hex, &record.tenant_hex) {
        return super::blacklist::reject_blocked(reason);
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
    // stale record would re-create claims and charges billed to the dead
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
        return Ok(Some(reject_restricted(
            super::admission::STATE_ROOT_REGISTRATION_CHANGED,
        )));
    }

    let ring_key = MetaEnv::state_ring_key(alias, created_at, &event_id_hex);
    if meta.state_ring_contains(txn, &ring_key)? {
        // Idempotent by event id: replayed edition, nothing to do.
        return Ok(None);
    }

    // Decision D4: this repository pays for every blob the edition names
    // that it does not pay for yet, stored or not, whoever else references
    // it. The moves are worked out on copies first, so that one quota
    // decision covers the event bytes and every new charge (two separate
    // checks could each pass while the sum exceeds a cap), and the write
    // below makes exactly those moves.
    let mut named: Vec<(&str, u64)> = Vec::with_capacity(parsed.blobs.len());
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for blob in &parsed.blobs {
        // The first tag naming a sha decides its declared size.
        if seen.insert(blob.sha256.as_str()) {
            named.push((blob.sha256.as_str(), blob.size));
        }
    }
    // Before the bytes are here a repository pays what its newest edition
    // naming a blob declares. A retained edition newer than this one (from
    // another write key of the repository) that names the blob has set
    // that already, so this one leaves it: the size then does not depend
    // on the order a node applied the editions in, nor on whether it saw
    // the older ones at all.
    let mut named_later: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (key, json) in meta.state_ring_for_alias(txn, alias)? {
        if key.as_str() > ring_key.as_str() {
            named_later.extend(edition_shas(&json));
        }
    }
    let mut moves = Vec::new();
    for &(sha256, declared) in &named {
        let mut claim = meta
            .get_blob_claim(txn, sha256)?
            .unwrap_or_else(|| claims::new_claim(declared));
        moves.extend(claims::attach(cfg, &mut claim, tenant_hex, alias, declared));
        if !named_later.contains(sha256) {
            moves.extend(claims::redeclare(cfg, &mut claim, alias, declared));
        }
    }
    if !quota::fits(meta, txn, cfg, tenant_hex, alias, event_bytes, &moves)? {
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
        referenced.extend(edition_shas(json));
    }

    let now = nostr::prelude::Timestamp::now().as_secs();

    for &(sha256, declared) in &named {
        claims::attach_to(meta, txn, cfg, sha256, tenant_hex, alias, declared)?;
        if !named_later.contains(sha256) {
            claims::redeclare_to(meta, txn, cfg, sha256, alias, declared)?;
        }
    }

    // Stop referencing what no retained edition names any more
    // (alias-index prefix scan, not a cross-tenant table scan). Another
    // repository that still references a blob keeps paying its own charge;
    // as the last referrer of stored bytes this one pays until GC removes
    // them.
    for sha in meta.alias_claim_shas(txn, alias)? {
        if referenced.contains(&sha) {
            continue;
        }
        claims::detach_from(meta, txn, &sha, alias, now)?;
    }

    quota::charge(meta, txn, tenant_hex, alias, event_bytes, false)?;
    Ok(None)
}

/// The blob hashes a stored edition names in its `m` and `pack` tags.
fn edition_shas(json: &str) -> Vec<String> {
    let mut shas = Vec::new();
    if let Ok(edition) = nostr::prelude::Event::from_json(json.as_bytes()) {
        for tag in edition.tags.iter() {
            let v = tag.clone().to_vec();
            if v.len() >= 2 && (v[0] == "m" || v[0] == "pack") {
                shas.push(v[1].clone());
            }
        }
    }
    shas
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

    fn record(keys: &Keys) -> RegistrationRecord {
        RegistrationRecord {
            tenant_hex: keys.public_key().to_hex(),
            event_id: "01".repeat(32),
            created_at: 1,
            w_keys: vec![keys.public_key().to_hex()],
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

    /// A state root of `keys`'s own repository naming `blobs`, the first as
    /// its manifest.
    fn edition(keys: &Keys, alias: &str, blobs: &[(&str, u64)], created_at: u64) -> Event {
        let (manifest, packs) = blobs.split_first().expect("a manifest");
        let mut tags = vec![
            Tag::custom("d", vec![alias.to_string()]),
            Tag::custom(
                "a",
                vec![format!("30640:{}:{alias}", keys.public_key().to_hex())],
            ),
            Tag::custom("m", vec![manifest.0.to_string(), manifest.1.to_string()]),
        ];
        for (sha256, size) in packs {
            tags.push(Tag::custom(
                "pack",
                vec![sha256.to_string(), size.to_string()],
            ));
        }
        EventBuilder::new(Kind::Custom(KIND_STATE_ROOT), "")
            .tags(tags)
            .custom_created_at(nostr::prelude::Timestamp::from_secs(created_at))
            .finalize(keys)
            .expect("sign")
    }

    fn apply(
        meta: &MetaEnv,
        cfg: &PrivateConfig,
        record: &RegistrationRecord,
        event: &Event,
    ) -> Option<WritePolicyResult> {
        let parsed = parse_shape(event, u64::MAX).expect("a valid state root");
        let json = event.as_json();
        meta.with_write(|m, txn| apply_state_root_txn(m, txn, cfg, record, &parsed, event, &json))
            .expect("the meta store")
    }

    fn blob_bytes(meta: &MetaEnv, key: &str) -> u64 {
        let txn = meta.read_txn().unwrap();
        meta.get_ledger_txn(&txn, key).unwrap().blob_bytes
    }

    /// Issue 5 at the state root: naming a blob another account stored costs
    /// the naming repository the stored size, whatever it declares, and a
    /// state root that cannot afford it is refused without a trace. Without
    /// the charge (or without the check) the second account would hold the
    /// bytes at no cost.
    #[test]
    fn naming_another_accounts_stored_blob_is_charged_or_refused() {
        let dir = tempfile::tempdir().unwrap();
        let meta = MetaEnv::open(dir.path()).unwrap();
        let (owner, other) = (Keys::generate(), Keys::generate());
        let (alias_a, alias_b) = ("a".repeat(32), "b".repeat(32));
        let (record_a, record_b) = (record(&owner), record(&other));
        let x = sha(7);
        let mut cfg = PrivateConfig::from_config(&crate::config::Config::for_testing());
        meta.with_write(|m, txn| {
            m.put_registration(txn, &alias_a, &record_a)?;
            m.put_registration(txn, &alias_b, &record_b)?;
            claims::attach_to(m, txn, &cfg, &x, &record_a.tenant_hex, &alias_a, 512)?;
            let before = m.get_blob_claim(txn, &x)?;
            let mut claim = before.clone().expect("the claim just made");
            let moves = claims::settle_stored(&cfg, &mut claim, 512, 1);
            claims::commit(m, txn, &x, before.as_ref(), Some(&claim), &moves)
        })
        .unwrap();

        // B declares 10 bytes for a blob that is 512 on disk.
        let event = edition(&other, &alias_b, &[(x.as_str(), 10)], 100);
        let event_bytes = event.as_json().len() as u64;

        cfg.quota_repo_bytes = event_bytes + 511;
        let refused = apply(&meta, &cfg, &record_b, &event);
        assert!(
            matches!(
                &refused,
                Some(WritePolicyResult::Reject { message, .. }) if message.contains("quota exceeded")
            ),
            "one byte short of event + stored size must be refused"
        );
        {
            let txn = meta.read_txn().unwrap();
            assert!(meta
                .state_ring_for_alias(&txn, &alias_b)
                .unwrap()
                .is_empty());
            let claim = meta.get_blob_claim(&txn, &x).unwrap().unwrap();
            assert_eq!(claim.aliases, vec![alias_a.clone()], "nothing attached");
        }
        assert_eq!(blob_bytes(&meta, &quota::alias_key(&alias_b)), 0);

        cfg.quota_repo_bytes = event_bytes + 512;
        assert!(
            apply(&meta, &cfg, &record_b, &event).is_none(),
            "it fits exactly"
        );
        assert_eq!(blob_bytes(&meta, &quota::alias_key(&alias_b)), 512);
        assert_eq!(
            blob_bytes(&meta, &quota::tenant_key(&record_b.tenant_hex)),
            512
        );
        assert_eq!(blob_bytes(&meta, &quota::alias_key(&alias_a)), 512);
        assert_eq!(
            blob_bytes(&meta, crate::grasp_p::meta::LEDGER_GLOBAL_KEY),
            1024
        );
    }

    /// A newer edition that no longer names a blob detaches the repository
    /// from it: released at once while another repository references it,
    /// kept as the grace charge of the last referrer of stored bytes, and a
    /// declared blob nobody stored loses its claim with its charge. The
    /// same sha named twice in one edition is charged once.
    #[test]
    fn superseding_editions_detach_what_they_no_longer_name() {
        let dir = tempfile::tempdir().unwrap();
        let meta = MetaEnv::open(dir.path()).unwrap();
        let (owner, other) = (Keys::generate(), Keys::generate());
        let (alias_a, alias_b) = ("c".repeat(32), "d".repeat(32));
        let (record_a, record_b) = (record(&owner), record(&other));
        let mut cfg = PrivateConfig::from_config(&crate::config::Config::for_testing());
        cfg.state_history_editions = 1;
        meta.with_write(|m, txn| {
            m.put_registration(txn, &alias_a, &record_a)?;
            m.put_registration(txn, &alias_b, &record_b)
        })
        .unwrap();
        let (x, y, z) = (sha(8), sha(9), sha(10));
        let repo_a = || blob_bytes(&meta, &quota::alias_key(&alias_a));
        let repo_b = || blob_bytes(&meta, &quota::alias_key(&alias_b));

        // A cap with room for the event and one charge of 300: the forecast
        // must count the sha named twice once, or the edition is refused.
        let first = edition(
            &owner,
            &alias_a,
            &[(x.as_str(), 300), (x.as_str(), 999)],
            10,
        );
        let mut tight = cfg.clone();
        tight.quota_repo_bytes = first.as_json().len() as u64 + 300;
        assert!(
            apply(&meta, &tight, &record_a, &first).is_none(),
            "the forecast counts a sha named twice once"
        );
        assert_eq!(
            repo_a(),
            300,
            "named twice, charged once, at the first size"
        );
        assert!(apply(
            &meta,
            &cfg,
            &record_b,
            &edition(&other, &alias_b, &[(x.as_str(), 300)], 10)
        )
        .is_none());
        assert_eq!(repo_b(), 300);
        meta.with_write(|m, txn| {
            let before = m.get_blob_claim(txn, &x)?;
            let mut claim = before.clone().expect("declared");
            let moves = claims::settle_stored(&cfg, &mut claim, 300, 20);
            claims::commit(m, txn, &x, before.as_ref(), Some(&claim), &moves)
        })
        .unwrap();

        // A moves on to y: released from x at once, B still pays its own.
        assert!(apply(
            &meta,
            &cfg,
            &record_a,
            &edition(&owner, &alias_a, &[(y.as_str(), 40)], 30)
        )
        .is_none());
        assert_eq!((repo_a(), repo_b()), (40, 300));

        // B moves on to z: the last referrer of stored x keeps its charge.
        assert!(apply(
            &meta,
            &cfg,
            &record_b,
            &edition(&other, &alias_b, &[(z.as_str(), 50)], 30)
        )
        .is_none());
        assert_eq!(repo_b(), 300 + 50);
        {
            let txn = meta.read_txn().unwrap();
            let kept = meta.get_blob_claim(&txn, &x).unwrap().unwrap();
            assert!(kept.aliases.is_empty() && kept.unreferenced_since.is_some());
        }

        // A drops y, which was never stored: the claim and its charge go.
        assert!(apply(
            &meta,
            &cfg,
            &record_a,
            &edition(&owner, &alias_a, &[(z.as_str(), 50)], 40)
        )
        .is_none());
        assert_eq!(repo_a(), 50);
        let txn = meta.read_txn().unwrap();
        assert!(meta.get_blob_claim(&txn, &y).unwrap().is_none());
    }

    /// Before the bytes are here a repository pays what its newest edition
    /// naming a blob declares, whichever order a node applied the editions
    /// of two write keys in and whether it saw the older one at all, so the
    /// two nodes of a pair charge the same.
    #[test]
    fn the_newest_edition_sets_a_declared_size_in_any_order() {
        let (owner, first_key, second_key) = (Keys::generate(), Keys::generate(), Keys::generate());
        let alias = "e".repeat(32);
        let record = record(&owner);
        let x = sha(11);
        let older = edition(&first_key, &alias, &[(x.as_str(), 100)], 10);
        let newer = edition(&second_key, &alias, &[(x.as_str(), 200)], 20);
        let mut cfg = PrivateConfig::from_config(&crate::config::Config::for_testing());
        cfg.state_history_editions = 4;
        for order in [vec![&older, &newer], vec![&newer, &older], vec![&newer]] {
            let dir = tempfile::tempdir().unwrap();
            let meta = MetaEnv::open(dir.path()).unwrap();
            meta.with_write(|m, txn| m.put_registration(txn, &alias, &record))
                .unwrap();
            let applied = order.len();
            for event in order {
                assert!(apply(&meta, &cfg, &record, event).is_none());
            }
            assert_eq!(
                blob_bytes(&meta, &quota::alias_key(&alias)),
                200,
                "{applied} edition(s) applied"
            );
        }
    }

    /// Decision D5 at the state root: an edition declaring as many tiny
    /// blobs as it may is charged the floor for each, at every scope, and
    /// one whose floors do not fit the repository's cap is refused without
    /// a trace. The claims keep the declared size. Without the floor, 256
    /// declared blobs of 0 bytes cost the event's bytes and nothing more.
    #[test]
    fn tiny_declared_blobs_are_charged_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let meta = MetaEnv::open(dir.path()).unwrap();
        let keys = Keys::generate();
        let alias = "f".repeat(32);
        let record = record(&keys);
        meta.with_write(|m, txn| m.put_registration(txn, &alias, &record))
            .unwrap();
        let shas: Vec<String> = (0..MAX_BLOB_REFS_PER_STATE_ROOT)
            .map(|n| format!("{n:064x}"))
            .collect();
        let blobs: Vec<(&str, u64)> = shas.iter().map(|sha256| (sha256.as_str(), 0)).collect();
        let event = edition(&keys, &alias, &blobs, 100);
        let event_bytes = event.as_json().len() as u64;
        let mut cfg = PrivateConfig::from_config(&crate::config::Config::for_testing());
        cfg.min_blob_charge_bytes = 4096;
        let floors = MAX_BLOB_REFS_PER_STATE_ROOT as u64 * 4096;

        cfg.quota_repo_bytes = event_bytes + floors - 1;
        let refused = apply(&meta, &cfg, &record, &event);
        assert!(
            matches!(
                &refused,
                Some(WritePolicyResult::Reject { message, .. }) if message.contains("quota exceeded")
            ),
            "one byte short of the event and 256 floors must be refused"
        );
        {
            let txn = meta.read_txn().unwrap();
            assert!(meta.state_ring_for_alias(&txn, &alias).unwrap().is_empty());
            assert!(meta.all_blob_claims(&txn).unwrap().is_empty());
        }
        assert_eq!(blob_bytes(&meta, &quota::alias_key(&alias)), 0);

        cfg.quota_repo_bytes = event_bytes + floors;
        assert!(
            apply(&meta, &cfg, &record, &event).is_none(),
            "it fits exactly"
        );
        for key in [
            quota::alias_key(&alias),
            quota::tenant_key(&record.tenant_hex),
            crate::grasp_p::meta::LEDGER_GLOBAL_KEY.to_string(),
        ] {
            assert_eq!(blob_bytes(&meta, &key), floors, "{key}");
        }
        let txn = meta.read_txn().unwrap();
        let claims = meta.all_blob_claims(&txn).unwrap();
        assert_eq!(claims.len(), MAX_BLOB_REFS_PER_STATE_ROOT);
        assert!(claims.iter().all(|(_, claim)| claim.size == 0));
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
