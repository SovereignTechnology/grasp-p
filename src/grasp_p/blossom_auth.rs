//! Blossom (BUD-01/BUD-02 subset) kind-24242 authorization for private blob
//! routes.
//!
//! `Authorization: Nostr <base64(event-json)>`, in standard base64 or in the
//! base64url form BUD-11 specifies, padded or not. Inbound auth events are NOT
//! pre-verified by any relay pipeline, so this module verifies id + signature
//! itself. Shape errors / expiry → 401; a valid event signed by a key that is
//! not authorized for the attributed alias → 403. `GET /list/<pubkey>` is the
//! exception: every refusal there is the same 401 ([`authorize_list`]).
//!
//! An authorization event can be replayed by whoever captures it, for as
//! long as the server accepts it. Two stateless checks bound that, the same
//! on every node:
//!
//! - **Time.** `created_at` must lie between one hour before and fifteen
//!   minutes after the server's clock, and `expiration` must not have
//!   passed. A captured event is therefore good for 75 minutes at the most,
//!   however far ahead its signer set `expiration`.
//! - **Server.** A BUD-11 `server` tag binds the event to the servers it
//!   names, so one captured on its way to another server is refused here.
//!   A `list` authorization must carry one that names this node. An
//!   `upload` or `delete` authorization is checked only when it carries
//!   one, because the client does not send it yet.
//!
//! There is deliberately no memory of event ids already used. What a
//! captured authorization can still do inside its window: a `list` one
//! returns that key's inventory to whoever presents it; an `upload` one,
//! together with the bytes, stores the blob again if its owner deleted it
//! meanwhile; a `delete` one removes the claim again if its owner uploaded
//! the blob again meanwhile. Nothing else: no other blob, no other alias,
//! and where the event carries a `server` tag no other server. A table of
//! used ids would close these only on one node and only until its next
//! restart, because it is not shared with the node's peer and is empty
//! after a restart, so it would promise more than it keeps.

use base64::Engine as _;
use nostr::prelude::{Event, Timestamp};

use super::host::url_denotes_domain;
use super::{BlobError, MAX_FUTURE_SKEW_SECS};

/// How long after its `created_at` an authorization event is accepted. An
/// hour is the lifetime the client gives its own tokens.
const MAX_AUTH_AGE_SECS: u64 = 3_600;

/// Is `created_at` inside the accepted window around `now`: at most
/// [`MAX_AUTH_AGE_SECS`] old, and ahead of this server's clock by no more
/// than the skew allowed to every other private event?
fn created_at_in_window(created_at: u64, now: u64) -> bool {
    created_at.saturating_add(MAX_AUTH_AGE_SECS) >= now
        && created_at <= now.saturating_add(MAX_FUTURE_SKEW_SECS)
}

/// Operation the auth event must authorize via its `t` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlossomOp {
    Upload,
    Delete,
    List,
}

impl BlossomOp {
    fn tag_value(&self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Delete => "delete",
            Self::List => "list",
        }
    }

    /// Must an authorization for this operation carry a `server` tag?
    ///
    /// `list` has no `x` and no `a` tag, so without it nothing in the event
    /// says which server it was signed for. No client lists yet, so the tag
    /// can be required there from the start. `upload` and `delete` follow
    /// once the client sends it.
    fn requires_server_tag(&self) -> bool {
        matches!(self, Self::List)
    }
}

/// The one reason every refused `GET /list/<pubkey>` carries. See
/// [`authorize_list`].
const LIST_REFUSAL: &str = "list needs a kind 24242 authorization with a t tag of 'list' and a \
     server tag naming this server, signed by the listed pubkey";

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

/// Does a `server` tag value name this node?
///
/// BUD-11 puts a bare domain in the tag, so that is the one form accepted:
/// `host` or `host:port`, with no scheme, path or user part. It is compared
/// with the node's configured domain by [`url_denotes_domain`]: host
/// equality without regard to case or a trailing dot, and the same port
/// when the configured domain has one. The mount path of a node served
/// under a base path is not part of the comparison, because the tag names a
/// server and not a URL. (The tags of a registration are URLs, and those
/// are compared with the path: `host::url_denotes_service`.)
fn names_this_node(value: &str, own_domain: &str) -> bool {
    let value = value.trim();
    let bare_authority = !value.is_empty()
        && !value.contains(|c: char| {
            c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@' | '?' | '#')
        });
    bare_authority && url_denotes_domain(&format!("https://{value}"), own_domain)
}

/// Check the event's `server` tags against this node.
///
/// With no such tag the event is not bound to any server, which is
/// acceptable only where the operation does not require the tag. With one
/// or more, at least one value must name this node.
fn server_tag_ok(event: &Event, op: BlossomOp, own_domain: &str) -> bool {
    let mut named = event
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .filter(|values| values.first().is_some_and(|name| name == "server"))
        .flat_map(|values| values.iter().skip(1))
        .peekable();
    if named.peek().is_none() {
        return !op.requires_server_tag();
    }
    named.any(|value| names_this_node(value, own_domain))
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
    let event = event_from_header(header)?;
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

/// Decode the event carried by an `Authorization: Nostr <token>` header.
///
/// BUD-11 encodes the event JSON as base64url without padding. This server
/// and its client have always used standard base64. Both are accepted, with
/// or without padding, so neither a stock Blossom client nor ours is refused
/// over the alphabet.
fn event_from_header(header: Option<&str>) -> Result<Event, BlobError> {
    let header = header.ok_or_else(|| {
        BlobError::Unauthorized("missing Authorization: Nostr <base64-event> header".into())
    })?;
    let token = header
        .strip_prefix("Nostr ")
        .or_else(|| header.strip_prefix("nostr "))
        .ok_or_else(|| BlobError::Unauthorized("Authorization scheme must be Nostr".into()))?
        .trim();
    let json = decode_token(token)
        .ok_or_else(|| BlobError::Unauthorized("invalid base64 in Authorization header".into()))?;
    Event::from_json(&json)
        .map_err(|_| BlobError::Unauthorized("Authorization payload is not a nostr event".into()))
}

/// Base64-decode an authorization token in any of the four common forms.
fn decode_token(token: &str) -> Option<Vec<u8>> {
    use base64::prelude::{
        BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD,
    };
    [
        &BASE64_STANDARD,
        &BASE64_STANDARD_NO_PAD,
        &BASE64_URL_SAFE,
        &BASE64_URL_SAFE_NO_PAD,
    ]
    .into_iter()
    .find_map(|engine| engine.decode(token).ok())
}

/// The checks every authorization event must pass, whatever it authorizes:
/// kind, id and signature, freshness, the operation's `t` tag, an
/// `expiration` that has not passed, and the `server` tag rule of the
/// operation. `own_domain` is the node's configured domain.
fn verify_event(event: &Event, op: BlossomOp, own_domain: &str) -> Result<(), BlobError> {
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

    let now = Timestamp::now().as_secs();
    if !created_at_in_window(event.created_at.as_secs(), now) {
        return Err(BlobError::Unauthorized(
            "authorization event created_at must be at most 1 hour old and at most 15 minutes \
             ahead of the server clock"
                .into(),
        ));
    }

    // t tag must match the operation.
    match tag_value(event, "t") {
        Some(t) if t == op.tag_value() => {}
        _ => {
            return Err(BlobError::Unauthorized(format!(
                "authorization event must carry a t tag of '{}'",
                op.tag_value()
            )))
        }
    }

    // expiration tag must exist and be in the future.
    match tag_value(event, "expiration").and_then(|v| v.parse::<u64>().ok()) {
        Some(expiration) if expiration > now => {}
        Some(_) => {
            return Err(BlobError::Unauthorized(
                "authorization event is expired".into(),
            ))
        }
        None => {
            return Err(BlobError::Unauthorized(
                "authorization event must carry a numeric expiration tag".into(),
            ))
        }
    }

    if server_tag_ok(event, op, own_domain) {
        Ok(())
    } else if op.requires_server_tag() {
        Err(BlobError::Unauthorized(
            "authorization event must carry a server tag naming this server".into(),
        ))
    } else {
        Err(BlobError::Unauthorized(
            "authorization event carries server tags and none names this server".into(),
        ))
    }
}

/// Authorize `GET /list/<pubkey>`: a `list` authorization signed by the
/// listed pubkey itself. BUD-12's list carries no `x` tag, and the list is
/// the signer's own, so there is no `a` tag to resolve either. What binds
/// it to this node is its `server` tag, which is required here.
///
/// Every refusal is the same error. The route must not tell a caller whether
/// `listed_hex` is a tenant of this node, so a missing header, a malformed or
/// expired event, one without a `server` tag for this node and a valid event
/// from another key are indistinguishable, and no registration is looked up
/// to decide.
pub fn authorize_list(
    header: Option<&str>,
    listed_hex: &str,
    own_domain: &str,
) -> Result<(), BlobError> {
    let signed_by_listed = event_from_header(header)
        .and_then(|event| verify_event(&event, BlossomOp::List, own_domain).map(|()| event))
        .is_ok_and(|event| event.pubkey.to_hex() == listed_hex);
    if signed_by_listed {
        Ok(())
    } else {
        Err(BlobError::Unauthorized(LIST_REFUSAL.into()))
    }
}

/// Parse + verify the `Authorization` header down to a shape-valid
/// [`BlossomAuth`]. Does NOT resolve the registration (caller does that).
///
/// `expected_sha` is the sha256 the HTTP operation targets; a mismatch with
/// the auth `x` tag is a 400 (client committed to a different blob).
/// `own_domain` is the node's configured domain, for the `server` tag.
pub fn verify_auth_shape(
    header: Option<&str>,
    op: BlossomOp,
    expected_sha: &str,
    own_domain: &str,
) -> Result<BlossomAuth, BlobError> {
    let event = event_from_header(header)?;
    verify_event(&event, op, own_domain)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

    const DOMAIN: &str = "node.example";

    fn now() -> u64 {
        Timestamp::now().as_secs()
    }

    fn header_for(event: &Event) -> String {
        // Called by path, so that the test module needs no import of the
        // trait.
        let token = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, event.as_json());
        format!("Nostr {token}")
    }

    /// A signed 24242 with a `t` tag, an unexpired `expiration` and whatever
    /// else the caller adds.
    fn auth_event(signer: &Keys, op: &str, created_at: u64, extra: Vec<Tag>) -> Event {
        let mut tags = vec![
            Tag::custom("t", vec![op.to_string()]),
            Tag::custom("expiration", vec![(now() + 600).to_string()]),
        ];
        tags.extend(extra);
        EventBuilder::new(Kind::Custom(24242), "")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(signer)
            .expect("sign 24242")
    }

    fn server_tag(domain: &str) -> Tag {
        Tag::custom("server", vec![domain.to_string()])
    }

    /// The `x` and `a` tags an upload or delete authorization needs.
    fn blob_tags(sha: &str) -> Vec<Tag> {
        vec![
            Tag::custom("x", vec![sha.to_string()]),
            Tag::custom(
                "a",
                vec![format!("30640:{}:{}", "1".repeat(64), "2".repeat(32))],
            ),
        ]
    }

    fn list_result(event: &Event) -> Result<(), BlobError> {
        authorize_list(
            Some(header_for(event).as_str()),
            &event.pubkey.to_hex(),
            DOMAIN,
        )
    }

    fn shape_result(event: &Event, op: BlossomOp, sha: &str) -> Result<BlossomAuth, BlobError> {
        verify_auth_shape(Some(header_for(event).as_str()), op, sha, DOMAIN)
    }

    fn is_401(result: &Result<BlossomAuth, BlobError>) -> bool {
        matches!(result, Err(BlobError::Unauthorized(_)))
    }

    #[test]
    fn window_is_an_hour_back_and_the_skew_ahead() {
        let now = 1_000_000_u64;
        assert!(created_at_in_window(now, now));
        assert!(created_at_in_window(now - 3_600, now));
        assert!(!created_at_in_window(now - 3_601, now));
        assert!(created_at_in_window(now + 900, now));
        assert!(!created_at_in_window(now + 901, now));
        // No wrap at either end of the range.
        assert!(!created_at_in_window(0, now));
        assert!(!created_at_in_window(u64::MAX, now));
        assert!(created_at_in_window(u64::MAX, u64::MAX));
    }

    #[test]
    fn auth_older_than_an_hour_is_refused() {
        let keys = Keys::generate();
        let sha = "a".repeat(64);
        let mut tags = blob_tags(&sha);
        tags.push(server_tag(DOMAIN));

        // Unexpired, and otherwise in order: only its age refuses it.
        let stale = auth_event(&keys, "upload", now() - 3_700, tags.clone());
        assert!(is_401(&shape_result(&stale, BlossomOp::Upload, &sha)));
        let fresh = auth_event(&keys, "upload", now() - 3_000, tags);
        assert!(shape_result(&fresh, BlossomOp::Upload, &sha).is_ok());

        let stale_list = auth_event(&keys, "list", now() - 3_700, vec![server_tag(DOMAIN)]);
        assert!(list_result(&stale_list).is_err());
    }

    #[test]
    fn auth_future_dated_past_skew_is_refused() {
        let keys = Keys::generate();
        let sha = "a".repeat(64);

        let ahead = auth_event(&keys, "upload", now() + 1_000, blob_tags(&sha));
        assert!(is_401(&shape_result(&ahead, BlossomOp::Upload, &sha)));
        let skewed = auth_event(&keys, "upload", now() + 600, blob_tags(&sha));
        assert!(shape_result(&skewed, BlossomOp::Upload, &sha).is_ok());

        let ahead_list = auth_event(&keys, "list", now() + 1_000, vec![server_tag(DOMAIN)]);
        assert!(list_result(&ahead_list).is_err());
    }

    #[test]
    fn list_auth_needs_server_tag_for_this_node() {
        let keys = Keys::generate();

        let ours = auth_event(&keys, "list", now(), vec![server_tag(DOMAIN)]);
        assert!(list_result(&ours).is_ok());
        let among_several = auth_event(
            &keys,
            "list",
            now(),
            vec![
                server_tag("other.example"),
                server_tag(DOMAIN),
                server_tag("third.example"),
            ],
        );
        assert!(list_result(&among_several).is_ok());

        let absent = auth_event(&keys, "list", now(), vec![]);
        let foreign = auth_event(&keys, "list", now(), vec![server_tag("other.example")]);
        let empty_tag = auth_event(&keys, "list", now(), vec![Tag::custom("server", [""])]);
        // Every refusal of a list is the one 401 with the one reason, and
        // these are no exception: compared with a refusal for a cause that
        // has nothing to do with the tag.
        let unrelated = authorize_list(None, &keys.public_key().to_hex(), DOMAIN)
            .expect_err("no header at all");
        for refused in [&absent, &foreign, &empty_tag] {
            let err = list_result(refused).expect_err("must be refused");
            assert_eq!(err.status(), 401);
            assert_eq!(err.reason(), unrelated.reason());
        }
    }

    #[test]
    fn upload_auth_with_foreign_server_tag_is_refused() {
        let keys = Keys::generate();
        let sha = "a".repeat(64);
        for (op_tag, op) in [("upload", BlossomOp::Upload), ("delete", BlossomOp::Delete)] {
            let mut tags = blob_tags(&sha);
            tags.push(server_tag("other.example"));
            let foreign = auth_event(&keys, op_tag, now(), tags);
            assert!(
                is_401(&shape_result(&foreign, op, &sha)),
                "{op_tag} signed for another server must be a 401"
            );

            let mut tags = blob_tags(&sha);
            tags.push(server_tag("other.example"));
            tags.push(server_tag(DOMAIN));
            let ours_too = auth_event(&keys, op_tag, now(), tags);
            assert!(shape_result(&ours_too, op, &sha).is_ok());
        }
    }

    /// The client does not send the tag yet. Until it does, an upload or a
    /// delete without one is accepted as before.
    #[test]
    fn upload_auth_without_server_tag_still_passes() {
        let keys = Keys::generate();
        let sha = "a".repeat(64);
        for (op_tag, op) in [("upload", BlossomOp::Upload), ("delete", BlossomOp::Delete)] {
            let untagged = auth_event(&keys, op_tag, now(), blob_tags(&sha));
            let auth = shape_result(&untagged, op, &sha).expect("no server tag is accepted");
            assert_eq!(auth.pubkey_hex, keys.public_key().to_hex());
            assert_eq!(auth.sha256, sha);
        }
    }

    #[test]
    fn server_tag_value_is_a_bare_domain_compared_like_every_other_host() {
        assert!(names_this_node("node.example", "node.example"));
        assert!(names_this_node("NODE.Example.", "node.example"));
        assert!(names_this_node(" node.example ", "node.example"));
        // A node whose domain has a port is named with that port.
        assert!(names_this_node("127.0.0.1:7334", "127.0.0.1:7334"));
        assert!(!names_this_node("127.0.0.1:7335", "127.0.0.1:7334"));
        assert!(!names_this_node("127.0.0.1", "127.0.0.1:7334"));
        assert!(names_this_node("[::1]:7334", "[::1]:7334"));
        assert!(!names_this_node("[::2]:7334", "[::1]:7334"));

        assert!(!names_this_node("", "node.example"));
        assert!(!names_this_node("other.example", "node.example"));
        assert!(!names_this_node("sub.node.example", "node.example"));
        assert!(!names_this_node(
            "node.example.other.example",
            "node.example"
        ));
        // Not a bare domain: a URL, a path, a user part.
        assert!(!names_this_node("https://node.example", "node.example"));
        assert!(!names_this_node("node.example/base", "node.example"));
        assert!(!names_this_node(
            "other.example@node.example",
            "node.example"
        ));
        assert!(!names_this_node(
            "node.example#other.example",
            "node.example"
        ));
        assert!(!names_this_node(
            "other.example\\@node.example",
            "node.example"
        ));
    }
}
