//! Shared constructors for [`WritePolicyResult`] values.
//!
//! These helpers are the single, canonical way to build policy results across
//! `builder.rs` and every sub-policy. Routing all results through them keeps
//! prefix handling consistent and prevents the double-prefix bug that occurs
//! when a `MachineReadablePrefix` is paired with a `message` string that *also*
//! begins with that prefix word.
//!
//! ## Prefix contract
//!
//! As of `nostr-relay-builder 0.45`, the relay renders the wire message itself
//! as `format!("{prefix}: {message}")`. Therefore callers MUST pass the bare
//! message **without** a leading `prefix:` word — the prefix is added for you.

use std::borrow::Cow;
use std::sync::OnceLock;

use nostr::message::relay::SingleWord;
use nostr_sdk::prelude::{MachineReadablePrefix, WritePolicyResult};

/// The `purgatory:` machine-readable prefix.
///
/// GRASP relays park events that are awaiting their git data in "purgatory".
/// There is no standard NIP-01 prefix for this state, so we emit a custom
/// `purgatory:` prefix (supported via [`MachineReadablePrefix::Custom`] in
/// nostr 0.45). This is paired with `status: true` so clients treat the
/// submission as received and do not retry immediately.
fn purgatory_prefix() -> MachineReadablePrefix {
    static PREFIX: OnceLock<MachineReadablePrefix> = OnceLock::new();
    PREFIX
        .get_or_init(|| {
            MachineReadablePrefix::Custom(
                SingleWord::from_static("purgatory").expect("'purgatory' is a valid single word"),
            )
        })
        .clone()
}

/// Build a rejection carrying the `invalid:` NIP-01 machine-readable prefix.
///
/// Use for client-fault rejections: malformed/unparseable events, failed
/// validation, bad refs, accepted-deletion-request, etc.
pub(crate) fn reject_invalid(message: impl Into<Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::reject(MachineReadablePrefix::Invalid, message)
}

/// Build a rejection carrying the `error:` NIP-01 machine-readable prefix.
///
/// Use for server-fault rejections: database/git failures and other internal
/// errors where the client is not at fault.
pub(crate) fn reject_error(message: impl Into<Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::reject(MachineReadablePrefix::Error, message)
}

/// Build a rejection carrying the `restricted:` NIP-01 machine-readable prefix.
///
/// Use for authorization-style rejections, e.g. an event that does not
/// reference an accepted repository or is from an unauthorized author.
pub(crate) fn reject_restricted(message: impl Into<Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::reject(MachineReadablePrefix::Restricted, message)
}

/// Build an "accepted but not yet served" response (`status: true`) for events
/// parked in purgatory while awaiting their git data.
///
/// Emits the custom `purgatory:` prefix so the response is semantically honest
/// (the relay does not yet have servable data) while still signalling success.
pub(crate) fn accepted_purgatory(message: impl Into<Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::ok_msg(purgatory_prefix(), message)
}

/// Build a "duplicate, already have it" response (`status: true`).
pub(crate) fn duplicate(message: impl Into<Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::ok_msg(MachineReadablePrefix::Duplicate, message)
}
