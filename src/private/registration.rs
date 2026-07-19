//! Kind-30640 private repo registration: shape validation, admission modes,
//! alias/key claims, and replay-safe application to the meta store.

use nostr::nips::nip19::ToBech32;
use nostr::Event;
use nostr_relay_builder::prelude::WritePolicyResult;

use crate::config::RegistrationMode;
use crate::nostr::policy::{reject_error, reject_restricted};

use super::meta::RegistrationRecord;
use super::{quota, PrivateConfig, PrivateService};

/// Alias: exactly 32 lowercase hex chars.
pub(crate) fn is_valid_alias(alias: &str) -> bool {
    alias.len() == 32
        && alias
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Trailing-slash-normalized substring match, mirroring
/// `events.rs::has_clone_url/has_relay` semantics against `config.domain`.
fn value_lists_domain(value: &str, domain: &str) -> bool {
    let normalized_domain = domain.trim_end_matches('/');
    value.trim_end_matches('/').contains(normalized_domain)
}

/// All values of every tag named `name` (tags may carry multiple values).
fn tag_values(event: &Event, name: &str) -> Vec<String> {
    event
        .tags
        .iter()
        .filter_map(|tag| {
            let v = tag.clone().to_vec();
            if v.len() >= 2 && v[0] == name {
                Some(v[1..].to_vec())
            } else {
                None
            }
        })
        .flatten()
        .collect()
}

/// Domain-separated message a claimed w/aux key must sign to prove
/// possession: sha256("grasp-p key-claim:<tenant-hex>:<alias>"). Binding the
/// signature to (tenant, alias) stops replaying one registration's proof into
/// another tenant's/alias's 30640.
pub fn key_pop_input(tenant_hex: &str, alias: &str) -> String {
    format!("grasp-p key-claim:{tenant_hex}:{alias}")
}

/// Verify the schnorr proof-of-possession `sig_hex` for `key_hex`.
fn verify_key_pop(key_hex: &str, sig_hex: &str, tenant_hex: &str, alias: &str) -> Result<(), String> {
    use std::str::FromStr;

    use nostr::hashes::{sha256, Hash};
    use nostr::secp256k1::{schnorr::Signature, Message, XOnlyPublicKey};

    let pk = XOnlyPublicKey::from_str(key_hex)
        .map_err(|_| "w/aux key is not a valid x-only pubkey".to_string())?;
    let sig = Signature::from_str(sig_hex)
        .map_err(|_| "w/aux key proof-of-possession signature is malformed".to_string())?;
    let digest = sha256::Hash::hash(key_pop_input(tenant_hex, alias).as_bytes());
    let message = Message::from_digest(digest.to_byte_array());
    nostr::SECP256K1
        .verify_schnorr(&sig, &message, &pk)
        .map_err(|_| "w/aux key proof-of-possession signature is invalid".to_string())
}

/// Collect the claimed keys of every `name` tag, enforcing hex shape AND
/// proof-of-possession: each key must either BE the event author (the event
/// signature is the proof) or carry a valid schnorr signature over
/// [`key_pop_input`] as the tag's third value. Without this, any pubkey could
/// squat someone else's known write key (denying the victim registration and
/// hijacking 1059 wrap attribution/quota).
fn parse_claimed_keys(
    event: &Event,
    name: &str,
    tenant_hex: &str,
    alias: &str,
) -> Result<Vec<String>, String> {
    let mut keys = Vec::new();
    for tag in event.tags.iter() {
        let v = tag.clone().to_vec();
        if v.len() < 2 || v[0] != name {
            continue;
        }
        let key = v[1].clone();
        if !super::blossom_auth::is_lower_hex_64(&key) {
            return Err("w/aux keys must be 64 lowercase hex chars".to_string());
        }
        if key != tenant_hex {
            let sig = v.get(2).ok_or_else(|| {
                "w/aux keys must carry a proof-of-possession signature".to_string()
            })?;
            verify_key_pop(&key, sig, tenant_hex, alias)?;
        }
        keys.push(key);
    }
    Ok(keys)
}

fn first_tag_value(event: &Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.clone().to_vec();
        if v.len() >= 2 && v[0] == name {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

/// Shape-validated registration fields.
struct ParsedRegistration {
    alias: String,
    w_keys: Vec<String>,
    aux_keys: Vec<String>,
    relays: Vec<String>,
    servers: Vec<String>,
    quota_class: Option<String>,
}

fn parse_shape(event: &Event, cfg: &PrivateConfig) -> Result<ParsedRegistration, String> {
    let alias = first_tag_value(event, "d")
        .ok_or_else(|| "registration must carry a d tag".to_string())?;
    if !is_valid_alias(&alias) {
        return Err("registration d tag must be exactly 32 lowercase hex chars".to_string());
    }

    let tenant_hex = event.pubkey.to_hex();
    let w_keys = parse_claimed_keys(event, "w", &tenant_hex, &alias)?;
    if w_keys.is_empty() {
        return Err("registration must carry at least one w (write key) tag".to_string());
    }
    let aux_keys = parse_claimed_keys(event, "aux", &tenant_hex, &alias)?;
    let total_keys = w_keys.len() + aux_keys.len();
    if total_keys > cfg.max_write_keys_per_alias as usize {
        return Err(format!(
            "registration exceeds the {} key limit",
            cfg.max_write_keys_per_alias
        ));
    }
    // Duplicate keys across w+aux would corrupt the claim index diffing.
    {
        let mut seen = std::collections::HashSet::new();
        for key in w_keys.iter().chain(aux_keys.iter()) {
            if !seen.insert(key) {
                return Err("registration lists the same key more than once".to_string());
            }
        }
    }

    let relays = tag_values(event, "relays");
    let servers = tag_values(event, "server");
    if !relays.iter().any(|v| value_lists_domain(v, &cfg.domain)) {
        return Err("registration relays tag must list this node".to_string());
    }
    if !servers.iter().any(|v| value_lists_domain(v, &cfg.domain)) {
        return Err("registration server tag must list this node".to_string());
    }

    Ok(ParsedRegistration {
        alias,
        w_keys,
        aux_keys,
        relays,
        servers,
        quota_class: first_tag_value(event, "quota-class"),
    })
}

/// Is `incoming` (created_at, id) strictly newer than the stored record per
/// nostr addressable-replacement semantics (equal created_at → lowest id wins)?
fn is_newer_than_stored(created_at: u64, event_id_hex: &str, stored: &RegistrationRecord) -> bool {
    created_at > stored.created_at
        || (created_at == stored.created_at && *event_id_hex < *stored.event_id)
}

/// Handle a kind-30640 registration event (admission + meta application).
pub(crate) fn handle(svc: &PrivateService, event: &Event) -> WritePolicyResult {
    let cfg = &svc.cfg;

    if let Some(rejection) = super::check_not_future_dated(event) {
        return rejection;
    }

    // Size cap on serialized JSON.
    if event.as_json().len() as u64 > cfg.max_event_bytes {
        return reject_restricted("event exceeds private repo size limit");
    }

    let parsed = match parse_shape(event, cfg) {
        Ok(p) => p,
        Err(reason) => return crate::nostr::policy::reject_invalid(reason),
    };

    let tenant_hex = event.pubkey.to_hex();
    let event_id_hex = event.id.to_hex();
    let created_at = event.created_at.as_secs();
    let event_bytes = event.as_json().len() as u64;

    let result = svc.meta.with_write(|meta, txn| {
        // Alias claim check.
        let stored = meta.get_registration(txn, &parsed.alias)?;
        if let Some(ref record) = stored {
            if record.tenant_hex != tenant_hex {
                return Ok(Some(reject_restricted("alias already registered")));
            }
        }

        // Key conflict check: any claimed key held by a DIFFERENT alias.
        for key in parsed.w_keys.iter().chain(parsed.aux_keys.iter()) {
            if let Some(holder) = meta.get_key_claim(txn, key)? {
                if holder != parsed.alias {
                    return Ok(Some(reject_restricted("write key already registered")));
                }
            }
        }

        let is_new_alias = stored.is_none();
        if is_new_alias {
            // Admission mode gates NEW aliases only.
            match cfg.registration_mode {
                RegistrationMode::Open => {}
                RegistrationMode::Whitelist => {
                    let npub = event
                        .pubkey
                        .to_bech32()
                        .unwrap_or_default();
                    if !cfg.tenant_whitelist.iter().any(|entry| entry == &npub) {
                        return Ok(Some(reject_restricted(
                            "tenant is not on the registration whitelist",
                        )));
                    }
                }
                RegistrationMode::Pow => {
                    if !event.id.check_pow(cfg.pow_bits) {
                        return Ok(Some(reject_restricted(format!(
                            "registration requires {} bits of NIP-13 proof of work",
                            cfg.pow_bits
                        ))));
                    }
                }
                RegistrationMode::Paid => {
                    // Unreachable: Config::validate() rejects paid mode.
                    return Ok(Some(reject_restricted(
                        "paid registration mode is not available",
                    )));
                }
            }

            let aliases = meta.get_tenant_aliases(txn, &tenant_hex)?;
            if aliases.len() >= cfg.max_aliases_per_tenant as usize {
                return Ok(Some(reject_restricted(
                    "tenant has reached the alias limit",
                )));
            }
        }

        // Replay/replacement ordering (§4b): apply meta changes only when the
        // event is strictly newer than the stored record; the relay DB will
        // discard older editions itself.
        if let Some(ref record) = stored {
            if !is_newer_than_stored(created_at, &event_id_hex, record) {
                return Ok(None); // Accept without meta changes.
            }
        }

        // Quota: registrations are small but still counted.
        if !quota::check(meta, txn, cfg, &tenant_hex, &parsed.alias, event_bytes)? {
            return Ok(Some(reject_restricted("quota exceeded")));
        }

        // Diff key sets against the previous edition.
        let (old_w, old_aux) = stored
            .as_ref()
            .map(|r| (r.w_keys.clone(), r.aux_keys.clone()))
            .unwrap_or_default();
        let new_keys: std::collections::HashSet<&String> =
            parsed.w_keys.iter().chain(parsed.aux_keys.iter()).collect();
        for old_key in old_w.iter().chain(old_aux.iter()) {
            if !new_keys.contains(old_key) {
                meta.delete_key_claim(txn, old_key)?;
            }
        }
        for key in parsed.w_keys.iter().chain(parsed.aux_keys.iter()) {
            meta.put_key_claim(txn, key, &parsed.alias)?;
        }

        let record = RegistrationRecord {
            tenant_hex: tenant_hex.clone(),
            event_id: event_id_hex.clone(),
            created_at,
            w_keys: parsed.w_keys.clone(),
            aux_keys: parsed.aux_keys.clone(),
            relays: parsed.relays.clone(),
            servers: parsed.servers.clone(),
            quota_class: parsed.quota_class.clone(),
            registered_at: stored
                .as_ref()
                .map(|r| r.registered_at)
                .unwrap_or_else(|| nostr::Timestamp::now().as_secs()),
            tombstoned_at: None,
        };
        meta.put_registration(txn, &parsed.alias, &record)?;

        if is_new_alias {
            let mut aliases = meta.get_tenant_aliases(txn, &tenant_hex)?;
            if !aliases.contains(&parsed.alias) {
                aliases.push(parsed.alias.clone());
                meta.put_tenant_aliases(txn, &tenant_hex, &aliases)?;
            }
        }

        quota::charge(meta, txn, &tenant_hex, &parsed.alias, event_bytes, false)?;
        Ok(None)
    });

    match result {
        Ok(Some(rejection)) => rejection,
        Ok(None) => {
            crate::metrics::record_private_registration(&cfg.registration_mode.to_string());
            svc.refresh_gauges();
            WritePolicyResult::Accept
        }
        Err(e) => {
            tracing::warn!("private registration meta update failed: {e}");
            reject_error("private meta store failure")
        }
    }
}
