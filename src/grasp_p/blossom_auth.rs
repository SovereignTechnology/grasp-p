//! Blossom (BUD-01/BUD-02 subset) kind-24242 authorization for private blob
//! routes.
//!
//! `Authorization: Nostr <base64(event-json)>`. Inbound auth events are NOT
//! pre-verified by any relay pipeline, so this module verifies id + signature
//! itself. Shape errors / expiry → 401; a valid event signed by a key that is
//! not authorized for the attributed alias → 403.

use base64::Engine as _;
use nostr::{Event, Timestamp};

use super::BlobError;

/// Maximum |now - created_at| for an auth event (±24 h).
const MAX_AUTH_AGE_SECS: u64 = 86_400;

/// Operation the auth event must authorize via its `t` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlossomOp {
    Upload,
    Delete,
}

impl BlossomOp {
    fn tag_value(&self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Delete => "delete",
        }
    }
}

/// A fully shape-verified (but not yet authorization-resolved) Blossom auth.
///
/// `PrivateService::verify_blossom_auth` upgrades this into an authorized auth
/// by resolving the `a`-tag registration and checking the signing key against
/// the alias's `w` set.
#[derive(Debug, Clone)]
pub struct BlossomAuth {
    /// Signing pubkey, lowercase hex.
    pub pubkey_hex: String,
    /// Tenant pubkey from the mandatory `a` tag, lowercase hex.
    pub tenant_hex: String,
    /// Alias from the mandatory `a` tag.
    pub alias: String,
    /// The sha256 the event commits to via its `x` tag.
    pub sha256: String,
}

/// Extract the first value of a tag by name from an event.
fn tag_value(event: &Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.clone().to_vec();
        if v.len() >= 2 && v[0] == name {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

/// Is `s` exactly 64 lowercase hex chars?
pub(crate) fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Extract the `x` (sha256) tag from an `Authorization: Nostr <b64>` header
/// without full verification — used by `PUT /upload` when no `X-SHA-256`
/// header names the target blob. Full verification still runs afterwards.
pub fn sha_from_header(header: Option<&str>) -> Result<String, BlobError> {
    let header = header.ok_or_else(|| {
        BlobError::Unauthorized("missing Authorization: Nostr <base64-event> header".into())
    })?;
    let b64 = header
        .strip_prefix("Nostr ")
        .or_else(|| header.strip_prefix("nostr "))
        .ok_or_else(|| BlobError::Unauthorized("Authorization scheme must be Nostr".into()))?
        .trim();
    let json = base64::prelude::BASE64_STANDARD
        .decode(b64)
        .map_err(|_| BlobError::Unauthorized("invalid base64 in Authorization header".into()))?;
    let event = Event::from_json(&json)
        .map_err(|_| BlobError::Unauthorized("Authorization payload is not a nostr event".into()))?;
    let x = tag_value(&event, "x").ok_or_else(|| {
        BlobError::Unauthorized("authorization event must carry an x (sha256) tag".into())
    })?;
    if !is_lower_hex_64(&x) {
        return Err(BlobError::Unauthorized(
            "authorization x tag must be 64 lowercase hex chars".into(),
        ));
    }
    Ok(x)
}

/// Parse + verify the `Authorization` header down to a shape-valid
/// [`BlossomAuth`]. Does NOT resolve the registration (caller does that).
///
/// `expected_sha` is the sha256 the HTTP operation targets; a mismatch with
/// the auth `x` tag is a 400 (client committed to a different blob).
pub fn verify_auth_shape(
    header: Option<&str>,
    op: BlossomOp,
    expected_sha: &str,
) -> Result<BlossomAuth, BlobError> {
    let header = header.ok_or_else(|| {
        BlobError::Unauthorized("missing Authorization: Nostr <base64-event> header".into())
    })?;

    let b64 = header
        .strip_prefix("Nostr ")
        .or_else(|| header.strip_prefix("nostr "))
        .ok_or_else(|| BlobError::Unauthorized("Authorization scheme must be Nostr".into()))?
        .trim();

    let json = base64::prelude::BASE64_STANDARD
        .decode(b64)
        .map_err(|_| BlobError::Unauthorized("invalid base64 in Authorization header".into()))?;

    let event = Event::from_json(&json)
        .map_err(|_| BlobError::Unauthorized("Authorization payload is not a nostr event".into()))?;

    if event.kind.as_u16() != 24242 {
        return Err(BlobError::Unauthorized(
            "authorization event must be kind 24242".into(),
        ));
    }

    if event.verify().is_err() {
        return Err(BlobError::Unauthorized(
            "authorization event has an invalid id or signature".into(),
        ));
    }

    // created_at within ±24 h.
    let now = Timestamp::now().as_secs();
    let created = event.created_at.as_secs();
    if created.abs_diff(now) > MAX_AUTH_AGE_SECS {
        return Err(BlobError::Unauthorized(
            "authorization event created_at is outside the ±24h window".into(),
        ));
    }

    // t tag must match the operation.
    match tag_value(&event, "t") {
        Some(t) if t == op.tag_value() => {}
        _ => {
            return Err(BlobError::Unauthorized(format!(
                "authorization event must carry a t tag of '{}'",
                op.tag_value()
            )))
        }
    }

    // expiration tag must exist and be in the future.
    match tag_value(&event, "expiration").and_then(|v| v.parse::<u64>().ok()) {
        Some(expiration) if expiration > now => {}
        Some(_) => return Err(BlobError::Unauthorized("authorization event is expired".into())),
        None => {
            return Err(BlobError::Unauthorized(
                "authorization event must carry a numeric expiration tag".into(),
            ))
        }
    }

    // x tag: required, 64-lower-hex, and must equal the sha being operated on.
    let x = tag_value(&event, "x").ok_or_else(|| {
        BlobError::Unauthorized("authorization event must carry an x (sha256) tag".into())
    })?;
    if !is_lower_hex_64(&x) {
        return Err(BlobError::Unauthorized(
            "authorization x tag must be 64 lowercase hex chars".into(),
        ));
    }
    if x != expected_sha {
        return Err(BlobError::BadRequest(format!(
            "authorization x tag {x} does not match the operated sha256 {expected_sha}"
        )));
    }

    // Mandatory a tag: 30640:<tenant-hex>:<alias>.
    let a = tag_value(&event, "a").ok_or_else(|| {
        BlobError::Unauthorized(
            "authorization event must carry an a tag (30640:<tenant>:<alias>)".into(),
        )
    })?;
    let parts: Vec<&str> = a.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "30640" {
        return Err(BlobError::Unauthorized(
            "authorization a tag must be 30640:<tenant-hex>:<alias>".into(),
        ));
    }
    let tenant_hex = parts[1].to_string();
    let alias = parts[2].to_string();
    if !is_lower_hex_64(&tenant_hex) || !super::registration::is_valid_alias(&alias) {
        return Err(BlobError::Unauthorized(
            "authorization a tag has a malformed tenant or alias".into(),
        ));
    }

    Ok(BlossomAuth {
        pubkey_hex: event.pubkey.to_hex(),
        tenant_hex,
        alias,
        sha256: x,
    })
}
