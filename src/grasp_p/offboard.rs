//! Who may delete what on a GRASP-P node.
//!
//! Only the account key, the key that signs a repository's registration
//! (kind 30640), deletes a private repository's data from the server, and
//! only the whole repository, through that registration (decision D6).
//! Members cannot. The
//! server cannot tell members apart behind a shared key (every member of a
//! repository holds its aux key), so a right to delete for one member would
//! be a right for every member, the read-only and the removed ones included,
//! to erase everyone's history and to block the shared key for as long as
//! upstream keeps the vanish.
//!
//! What the account key may send:
//!
//! - an offboard request: a kind 5 naming the coordinate of its own
//!   registration, `["a", "30640:<account>:<alias>"]`, with `["k", "30640"]`
//!   (the tag the peer's sync filter selects on, so the pair sees the same
//!   deletion) and dated no further ahead than [`super::MAX_FUTURE_SKEW_SECS`]
//!   (a coordinate deletion covers every edition dated before it, so a date
//!   far ahead would refuse the account's own later registrations). It
//!   names no event id: an event id names one edition, the two nodes of a
//!   pair can hold different editions for a while, so whether an id is one
//!   of the request's own would depend on the node judging it, and the
//!   coordinate already covers every edition up to the request's date;
//! - a NIP-62 vanish, which closes the account, from a key that is no
//!   repository's write or aux key and has signed no stored state root or
//!   stream wrap, naming `ALL_RELAYS` or every node of its pair: this one,
//!   the configured peers and every node its registrations list. Upstream's
//!   vanish removes every event its signer signed, so from any other key it
//!   would remove a repository's history; and upstream acts on a vanish
//!   only when it names this node, so one naming a single node of the pair
//!   would close the account there and leave it open on the other.
//!
//! The node serves public repositories in the same process (decision D1),
//! so a deletion request is GRASP-P's to shape only when it says it deletes
//! registrations: when it carries `["k", "30640"]`, spelled as the peers'
//! sync filter selects it, or names a 30640 coordinate, the kind read as
//! upstream reads it, as a number. The first rides that filter and the
//! second makes upstream act on a registration, so such a request is held
//! to the offboard shape whoever signs it (decision D15-6): the signer's own
//! 30640 coordinates and nothing else beside the k tag, no event id, no more
//! coordinates than an account may hold registrations, within the private
//! event size, and, in whitelist mode, only from a key the node could admit.
//! A request with neither mark goes to upstream as on a node without
//! GRASP-P, unless it names GRASP-P state or comes from a member key.
//!
//! Four places carry the rule:
//!
//! - [`guard`], which admission calls first for every kind 5 and kind 62. A
//!   key that is a write or aux key of a registration here may send nothing
//!   but an offboard request naming 30640 coordinates under its own key. No
//!   request may name a stored state root or stream wrap, any by a
//!   coordinate of their kinds, another account's registration, or a stored
//!   registration by event id alone. An id this node does not hold cannot be
//!   judged in a request without either mark: for a state root or a wrap the
//!   two exemptions below make the request inert. Everything else goes on to
//!   upstream, which handles it exactly as on a node without GRASP-P.
//! - [`deletion_gate_exempt`], which the write policy asks before upstream's
//!   tombstone gate. State roots and stream wraps answer to their
//!   registration alone, so no deletion request or vanish blocks them,
//!   however it got in: sent before its key was registered, which no check
//!   at request time can see, or accepted before this rule existed.
//!   Registrations stay gated, because a deletion of a registration is
//!   exactly what a later replay of that registration must not undo.
//! - [`cascade_exempt`], which upstream's announcement cascade asks. A
//!   public event that tags both a public repository and a registration,
//!   its state roots or its wraps is refused now (`attachment`), but one
//!   stored before that rule may still link them, and the cascade follows
//!   tags both ways, so a public repository's deletion must never reach
//!   them.
//! - [`removal_exempt`], which upstream asks for every stored event it is
//!   about to delete. A state root or a stream wrap stays whatever request
//!   got that far: one whose target arrived between the guard's lookup and
//!   upstream's delete, say. A registration goes only by its coordinate or
//!   its account's vanish, never by event id, so that the store and the
//!   claim-freeing hooks, which go by the same two, always agree.
//!
//! A request that passes reaches upstream's NIP-09 or NIP-62 handling and
//! the existing hooks that free a deleted registration's claims. A request
//! that arrives by sync passes the same write policy, so both nodes of a
//! pair judge it alike.

use std::collections::HashSet;

use nostr::nips::nip19::ToBech32;
use nostr::prelude::{nip62, Event, EventId, Filter, Kind, PublicKey, RelayUrl};
use nostr_sdk::local_relay::WritePolicyResult;

use super::{PrivateService, KIND_REGISTRATION, KIND_STATE_ROOT};
use crate::config::RegistrationMode;
use crate::nostr::policy::{reject_error, reject_invalid, reject_restricted};

/// The most `e` and `a` targets a deletion request may carry. Upstream
/// refuses more with the same words; the guard counts first because every
/// `e` target costs it a lookup, and it must not depend on upstream keeping
/// its own limit.
pub(crate) const MAX_TARGET_TAGS: usize = 2048;

/// A registration's kind as the k tag, the coordinate and the peers' sync
/// filter spell it.
const REGISTRATION_KIND_TEXT: &str = "30640";

// The refusals. None contains the word "unregistered": the client treats
// any message with it as the case where widening its registration helps,
// and no registration change makes one of these requests acceptable. None
// names an account, an alias or a node, and the ones that depend on the
// store read the same whether a target is missing or of another kind.

/// The signer is a write or aux key of a registration on this node.
pub(crate) const MEMBER_KEY_MESSAGE: &str =
    "a repository's write and aux keys cannot delete; the account key deletes the whole repository";

/// A vanish from a key that signed stored state roots or stream wraps.
pub(crate) const SIGNED_HISTORY_VANISH_MESSAGE: &str =
    "a key that signed state roots or stream wraps cannot vanish; the account key deletes each repository by its registration";

/// The request names a state root or a stream wrap.
pub(crate) const SERVICE_EVENT_MESSAGE: &str =
    "state roots and stream wraps are removed only with their repository's registration";

/// The request names a registration that another key signed.
pub(crate) const FOREIGN_REGISTRATION_MESSAGE: &str =
    "a registration can be deleted only by the account key that signed it";

/// The request names a registration by event id without its coordinate: a
/// stored one, or, under `["k", "30640"]`, an id this node may not hold
/// yet. A node that does not hold the edition could not tell, would take
/// the request, and would then refuse that edition when it arrives while
/// the other node of the pair kept serving it.
pub(crate) const REGISTRATION_BY_ID_MESSAGE: &str =
    "a registration is deleted by its coordinate (a tag), not by its event id alone";

/// The coordinate of a registration spells its kind in a way upstream reads
/// as 30640 and the claim-freeing hook and the tombstone gate do not, so
/// the event would go, its claims would stay, and a replay would come back.
pub(crate) const REGISTRATION_COORDINATE_MESSAGE: &str =
    "a registration coordinate must be written 30640:<pubkey>:<alias>";

/// A deletion of a registration without `["k", "30640"]`.
pub(crate) const MISSING_K_MESSAGE: &str = "deleting a registration requires a k tag of 30640";

/// More targets than [`MAX_TARGET_TAGS`]; upstream's own words.
pub(crate) const TOO_MANY_TARGETS_MESSAGE: &str = "too many deletion targets";

/// An offboard request that also names a coordinate of another kind, or
/// carries a k tag other than 30640. It rides the peers' sync filter, so
/// upstream would act on the rest on both nodes, for events the peer may
/// not hold, and the private link would carry public deletions.
pub(crate) const OFFBOARD_SHAPE_MESSAGE: &str =
    "an offboard request names nothing but its signer's registration coordinates and the k tag 30640";

/// An offboard request with an `e` tag, whatever its value. Whether an id
/// is an edition of a registration the request names depends on which
/// editions this node holds, and the two nodes of a pair can hold
/// different ones, so one node would take the request and the other refuse
/// it as final; judged on its text alone, both answer alike, and the answer
/// says nothing about what the node holds.
pub(crate) const OFFBOARD_ID_MESSAGE: &str =
    "an offboard request names its registrations by coordinate only, with no event id";

/// An offboard request with more coordinates than
/// `NGIT_GRASP_P_MAX_ALIASES_PER_TENANT`.
pub(crate) const TOO_MANY_REGISTRATIONS_MESSAGE: &str =
    "an offboard request names more registrations than an account may hold";

/// An offboard request, or the vanish of a key that holds registrations
/// here, larger than `NGIT_GRASP_P_MAX_EVENT_BYTES`.
pub(crate) const OVERSIZE_MESSAGE: &str =
    "an offboard request or an account's vanish exceeds the private event size limit";

/// Whitelist mode: an offboard request from a key that is neither listed
/// nor holds a registration here. It could never delete anything on either
/// node, the list being in the fingerprint, and it would ride the peers'
/// sync filter.
pub(crate) const NOT_ADMITTED_MESSAGE: &str =
    "offboard requests are taken only from accounts this node admits";

/// The vanish of a key that holds registrations here, naming neither
/// `ALL_RELAYS` nor every node of its pair: this one, the configured peers
/// and every node those registrations list.
pub(crate) const VANISH_TARGETS_MESSAGE: &str =
    "an account's vanish names ALL_RELAYS or every node its registrations list";

/// Whether `kind` is GRASP-P state that only a registration governs: a state
/// root, or a stream wrap of any kind, stored or ephemeral, the legacy kinds
/// included. A node that stopped taking the legacy kinds still holds the
/// wraps it took before, and a GRASP-P node admits a 1059 as nothing but a
/// stream wrap, so they count on every node.
fn is_service_kind(kind: u16) -> bool {
    kind == KIND_STATE_ROOT
        || super::is_stream_wrap_kind(kind, true)
        || super::is_ephemeral_stream_wrap_kind(kind, true)
}

/// Whether the write policy passes over upstream's tombstone gate for an
/// event of `kind` on a GRASP-P node: true for state roots and the stream
/// wraps this node takes, false for everything else, registrations
/// included. A legacy kind this node refuses is refused by admission
/// anyway, so it keeps upstream's gate and upstream's answer.
pub(crate) fn deletion_gate_exempt(svc: &PrivateService, kind: u16) -> bool {
    kind == KIND_STATE_ROOT
        || svc.accepts_stream_wrap_kind(kind)
        || svc.accepts_ephemeral_stream_wrap_kind(kind)
}

/// Whether upstream's announcement cascade passes over a stored event of
/// `kind` on a GRASP-P node: registrations, state roots and stream wraps,
/// which go only with the registration's own offboard request. No event of
/// another kind may reference them any more (`attachment`), so no cascade
/// edge should reach them; this keeps those that were stored before.
pub(crate) fn cascade_exempt(kind: u16) -> bool {
    super::is_private_event_kind(kind)
}

/// Whether upstream's deletion paths keep `event` on a GRASP-P node,
/// whatever request reached them. `owner_pubkey` is the owner the deleting
/// path recorded for what it removes.
///
/// A state root or a stream wrap always stays: it goes only with its
/// registration. A registration stays unless the path is bound to its own
/// author, which the coordinate path and the vanish are: each queries by
/// that author and records it as the owner. Upstream's `e` path records no
/// owner, and neither does the unanchored state deletion of the cascade,
/// which takes kind 30618 alone; neither may take a registration. No
/// request the guard passes names by id a registration this node holds,
/// and one naming an edition not here yet removes and frees nothing for it,
/// so nothing legitimate is lost, and the claim hook, which frees by the
/// coordinate only, never frees a seat whose event stays.
pub(crate) fn removal_exempt(event: &Event, owner_pubkey: Option<&str>) -> bool {
    let kind = event.kind.as_u16();
    if is_service_kind(kind) {
        return true;
    }
    if kind != KIND_REGISTRATION {
        return false;
    }
    let author = event.pubkey.to_hex();
    owner_pubkey != Some(author.as_str())
}

/// Judge a deletion request (kind 5) or a vanish (kind 62) before upstream
/// sees it. `Some` is the refusal; `None` hands the request to upstream.
/// Any other kind is not this guard's and gets `None`.
///
/// A store that cannot be read refuses the request, so nothing is deleted
/// on a guess.
pub(crate) async fn guard(svc: &PrivateService, event: &Event) -> Option<WritePolicyResult> {
    let refusal = if event.kind == Kind::EventDeletion {
        if too_many_targets(event) {
            // Upstream's own refusal, in its words, made here first only to
            // bound the lookups below. It is not a GRASP-P decision, so it
            // is neither counted nor logged as one.
            return Some(reject_invalid(TOO_MANY_TARGETS_MESSAGE));
        }
        judge_deletion(svc, event).await
    } else if event.kind == Kind::RequestToVanish {
        judge_vanish(svc, event).await
    } else {
        return None;
    };
    if let Some(WritePolicyResult::Reject { message, .. }) = &refusal {
        crate::metrics::record_private_event_rejected(event.kind.as_u16());
        tracing::debug!(
            event_id = %event.id.to_hex(),
            signer = %event.pubkey.to_hex(),
            kind = event.kind.as_u16(),
            reason = %message,
            "Refused a deletion request on a GRASP-P node"
        );
    }
    refusal
}

/// What one `a` target of a deletion request is.
enum Coordinate<'a> {
    /// The signer's own registration of this alias.
    OwnRegistration(&'a str),
    /// Something the guard refuses outright.
    Refused(WritePolicyResult),
    /// Not GRASP-P's: upstream decides.
    Other,
}

/// Classify one `a` value the way upstream acts on it: it splits the value
/// in three at the first two colons and reads the kind as a number, so the
/// kind is judged as that number, whatever its spelling. A coordinate of a
/// stream-wrap kind matters as much as one of a state root: wraps are not
/// addressable, so upstream reads it as "every event of that kind by the
/// signer".
fn classify_coordinate<'a>(coordinate: &'a str, signer_hex: &str) -> Coordinate<'a> {
    let mut parts = coordinate.splitn(3, ':');
    let (Some(kind_text), Some(pubkey), Some(alias)) = (parts.next(), parts.next(), parts.next())
    else {
        return Coordinate::Other;
    };
    let Ok(kind) = kind_text.parse::<u16>() else {
        return Coordinate::Other;
    };
    if is_service_kind(kind) {
        return Coordinate::Refused(reject_restricted(SERVICE_EVENT_MESSAGE));
    }
    if kind != KIND_REGISTRATION {
        return Coordinate::Other;
    }
    if pubkey != signer_hex {
        return Coordinate::Refused(reject_restricted(FOREIGN_REGISTRATION_MESSAGE));
    }
    if kind_text != REGISTRATION_KIND_TEXT {
        return Coordinate::Refused(reject_invalid(REGISTRATION_COORDINATE_MESSAGE));
    }
    Coordinate::OwnRegistration(alias)
}

/// Whether `signer_hex` is a write or aux key of a registration here. A
/// claim row whose registration is gone counts too: the meta store is the
/// only judge of membership, and a row it cannot explain is no reason to
/// let a deletion through.
fn holds_key_claim(svc: &PrivateService, signer_hex: &str) -> anyhow::Result<bool> {
    let txn = svc.meta.read_txn()?;
    Ok(svc.meta.get_key_claim(&txn, signer_hex)?.is_some())
}

fn meta_failure(error: anyhow::Error) -> WritePolicyResult {
    tracing::warn!(error = %error, "private deletion check could not read the meta store");
    reject_error("private meta store failure")
}

fn relay_store_failure(error: impl std::fmt::Display) -> WritePolicyResult {
    tracing::warn!(error = %error, "private deletion check could not read the relay store");
    reject_error("private deletion check failed")
}

/// Whether `event` is larger than the private event size limit, measured
/// as admission measures GRASP-P's own kinds.
fn oversize(svc: &PrivateService, event: &Event) -> bool {
    event.as_json().len() as u64 > svc.cfg.max_event_bytes
}

/// Whether a kind 5 carries more `e` and `a` targets than
/// [`MAX_TARGET_TAGS`], counted as upstream counts them.
fn too_many_targets(event: &Event) -> bool {
    event
        .tags
        .iter()
        .filter(|tag| {
            let v = tag.as_slice();
            v.len() >= 2 && (v[0] == "e" || v[0] == "a")
        })
        .count()
        > MAX_TARGET_TAGS
}

/// What the tags of a kind 5 say, read once, from the text alone.
#[derive(Default)]
struct DeletionTags<'a> {
    /// Aliases of the signer's own registrations named by coordinate.
    own_aliases: HashSet<&'a str>,
    /// Every `a` tag, counted as tags: a cap that counted distinct values
    /// would let repeats through uncounted.
    coordinates: usize,
    /// An `a` tag that is not a registration under the signer's key.
    other_coordinates: bool,
    /// Every `e` tag, whatever its value.
    id_tags: usize,
    /// The `e` values upstream would act on.
    ids: HashSet<EventId>,
    /// `["k", "30640"]`, spelled as the sync filter selects it.
    k_registration: bool,
    /// A k value spelled otherwise that reads as 30640. No mark: upstream
    /// never reads a k tag and the sync filter compares text, so such a
    /// request neither rides the filter nor reaches a registration. Beside
    /// a mark it is a shape error.
    k_registration_spelled_otherwise: bool,
    /// A k value of any other kind.
    other_k: bool,
}

impl DeletionTags<'_> {
    /// Whether the request says it deletes registrations: it rides the
    /// peers' sync filter (a k value of exactly `30640`, the filter's text)
    /// or would make upstream act on one (a 30640 coordinate).
    fn deletes_registrations(&self) -> bool {
        !self.own_aliases.is_empty() || self.k_registration
    }
}

/// Read the tags of a kind 5, or the first refusal its coordinates earn on
/// their own.
fn read_deletion_tags<'a>(
    event: &'a Event,
    signer_hex: &str,
) -> Result<DeletionTags<'a>, WritePolicyResult> {
    let mut tags = DeletionTags::default();
    for tag in event.tags.iter() {
        let v = tag.as_slice();
        if v.len() < 2 {
            continue;
        }
        match v[0].as_str() {
            "e" => {
                tags.id_tags += 1;
                tags.ids.extend(EventId::from_hex(&v[1]).ok());
            }
            "a" => {
                tags.coordinates += 1;
                match classify_coordinate(&v[1], signer_hex) {
                    Coordinate::OwnRegistration(alias) => {
                        tags.own_aliases.insert(alias);
                    }
                    Coordinate::Refused(refusal) => return Err(refusal),
                    Coordinate::Other => tags.other_coordinates = true,
                }
            }
            "k" if v[1] == REGISTRATION_KIND_TEXT => tags.k_registration = true,
            "k" if v[1].parse::<u16>() == Ok(KIND_REGISTRATION) => {
                tags.k_registration_spelled_otherwise = true;
            }
            "k" => tags.other_k = true,
            _ => {}
        }
    }
    Ok(tags)
}

/// Why one stored `e` target of a request with neither mark is refused, if
/// it is, with a rank: the lowest rank among the targets is the answer, so
/// it does not depend on the order the store returns them in. Such a
/// request names no registration by coordinate, so a stored registration of
/// its signer is named by id alone.
fn grasp_p_target_refusal(target: &Event, request: &Event) -> Option<(u8, WritePolicyResult)> {
    let kind = target.kind.as_u16();
    if is_service_kind(kind) {
        return Some((0, reject_restricted(SERVICE_EVENT_MESSAGE)));
    }
    if kind != KIND_REGISTRATION {
        return None;
    }
    if target.pubkey != request.pubkey {
        return Some((1, reject_restricted(FOREIGN_REGISTRATION_MESSAGE)));
    }
    Some((2, reject_restricted(REGISTRATION_BY_ID_MESSAGE)))
}

/// Kind 5. Cheap checks on the tags first, then the meta store, and, for a
/// request with neither mark, one lookup of every `e` target.
async fn judge_deletion(svc: &PrivateService, event: &Event) -> Option<WritePolicyResult> {
    let signer_hex = event.pubkey.to_hex();
    let tags = match read_deletion_tags(event, &signer_hex) {
        Ok(tags) => tags,
        Err(refusal) => return Some(refusal),
    };
    if tags.deletes_registrations() {
        judge_offboard(svc, event, &signer_hex, &tags)
    } else {
        judge_unmarked_deletion(svc, event, &signer_hex, tags.ids).await
    }
}

/// A kind 5 with neither mark of an offboard request: upstream's, unless a
/// member key signs it or it names GRASP-P state this node holds.
async fn judge_unmarked_deletion(
    svc: &PrivateService,
    event: &Event,
    signer_hex: &str,
    ids: HashSet<EventId>,
) -> Option<WritePolicyResult> {
    // A member key may send an offboard request and nothing else: what any
    // other request names may simply not have reached this node yet.
    match holds_key_claim(svc, signer_hex) {
        Ok(true) => return Some(reject_restricted(MEMBER_KEY_MESSAGE)),
        Ok(false) => {}
        Err(error) => return Some(meta_failure(error)),
    }
    if ids.is_empty() {
        return None;
    }
    // A target this node does not hold cannot be judged here; if it is a
    // state root or a stream wrap, the exemptions make the request inert
    // for it.
    let stored = match svc.database.query(Filter::new().ids(ids)).await {
        Ok(stored) => stored,
        Err(error) => return Some(relay_store_failure(error)),
    };
    stored
        .iter()
        .filter_map(|target| grasp_p_target_refusal(target, event))
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, refusal)| refusal)
}

/// A kind 5 that says it deletes registrations: the pure offboard shape,
/// for every signer (decision D15-6), judged on its text and on whether
/// the node could admit its signer, never on which events the node holds,
/// so both nodes of a pair answer alike. Each count is refused past its
/// cap, never cut short: the `e` and `a` tags were counted against
/// upstream's target cap before the tags were read.
fn judge_offboard(
    svc: &PrivateService,
    event: &Event,
    signer_hex: &str,
    tags: &DeletionTags<'_>,
) -> Option<WritePolicyResult> {
    if tags.own_aliases.is_empty() {
        // It says it deletes registrations but names none by its
        // coordinate; the peer's sync filter would carry it.
        return Some(reject_restricted(REGISTRATION_BY_ID_MESSAGE));
    }
    if !tags.k_registration {
        return Some(reject_invalid(MISSING_K_MESSAGE));
    }
    if tags.other_coordinates || tags.other_k || tags.k_registration_spelled_otherwise {
        return Some(reject_invalid(OFFBOARD_SHAPE_MESSAGE));
    }
    if let Some(refusal) = super::check_not_future_dated(event) {
        return Some(refusal);
    }
    if tags.coordinates > svc.cfg.max_aliases_per_tenant as usize {
        return Some(reject_invalid(TOO_MANY_REGISTRATIONS_MESSAGE));
    }
    if oversize(svc, event) {
        return Some(reject_invalid(OVERSIZE_MESSAGE));
    }
    if svc.cfg.registration_mode == RegistrationMode::Whitelist {
        match could_hold_an_account(svc, event, signer_hex) {
            Ok(true) => {}
            Ok(false) => return Some(reject_invalid(NOT_ADMITTED_MESSAGE)),
            Err(error) => return Some(meta_failure(error)),
        }
    }
    // An event id would make the answer depend on which editions this node
    // holds, and the two nodes of a pair can hold different ones; the
    // coordinate already covers every edition up to the request's date.
    if tags.id_tags > 0 {
        return Some(reject_invalid(OFFBOARD_ID_MESSAGE));
    }
    None
}

/// Whitelist mode: whether `signer` is listed or holds a registration here.
/// A listed key may offboard before its registration reaches this node; a
/// key that left the list keeps the seats it holds, and its offboards.
fn could_hold_an_account(
    svc: &PrivateService,
    event: &Event,
    signer_hex: &str,
) -> anyhow::Result<bool> {
    let npub = event.pubkey.to_bech32().unwrap_or_default();
    if svc.cfg.tenant_whitelist.contains(&npub) {
        return Ok(true);
    }
    let txn = svc.meta.read_txn()?;
    Ok(!svc.meta.get_tenant_aliases(&txn, signer_hex)?.is_empty())
}

/// Kind 62. Upstream removes every stored event of the signer and then
/// refuses all its later events. A write or aux key may not vanish at all
/// (its history may still be on its way here), and no key may vanish while
/// state roots or stream wraps it signed are stored: a wrap names no
/// repository, so there is no telling whose history it is. The vanish of a
/// key that holds live registrations here closes an account on both nodes
/// of the pair, so it names them all, the configured peers among them, and
/// it is held to the private event size. Any other vanish is upstream's.
async fn judge_vanish(svc: &PrivateService, event: &Event) -> Option<WritePolicyResult> {
    match holds_key_claim(svc, &event.pubkey.to_hex()) {
        Ok(true) => return Some(reject_restricted(MEMBER_KEY_MESSAGE)),
        Ok(false) => {}
        Err(error) => return Some(meta_failure(error)),
    }
    let mut kinds = vec![KIND_STATE_ROOT];
    kinds.extend(super::stream_wrap_kinds(true));
    let signed = Filter::new()
        .kinds(kinds.into_iter().map(Kind::Custom))
        .author(event.pubkey)
        .limit(1);
    match svc.database.query(signed).await {
        Ok(stored) if !stored.is_empty() => {
            return Some(reject_restricted(SIGNED_HISTORY_VANISH_MESSAGE))
        }
        Ok(_) => {}
        Err(error) => return Some(relay_store_failure(error)),
    }
    let servers = match live_registration_servers(svc, &event.pubkey).await {
        Ok(Some(servers)) => servers,
        Ok(None) => return None,
        Err(refusal) => return Some(refusal),
    };
    if oversize(svc, event) {
        return Some(reject_invalid(OVERSIZE_MESSAGE));
    }
    if !vanish_names_every_node(
        event,
        &svc.cfg.service_address,
        &svc.cfg.sync_peer_relays,
        &servers,
    ) {
        return Some(reject_invalid(VANISH_TARGETS_MESSAGE));
    }
    None
}

/// The registration records `account_hex` holds here that are not
/// tombstoned, by alias. The aliases are the account's own, bounded by the
/// alias cap when each seat was taken.
fn account_records(
    svc: &PrivateService,
    account_hex: &str,
) -> anyhow::Result<Vec<(String, super::meta::RegistrationRecord)>> {
    let txn = svc.meta.read_txn()?;
    let mut records = Vec::new();
    for alias in svc.meta.get_tenant_aliases(&txn, account_hex)? {
        if let Some(record) = svc.meta.get_registration(&txn, &alias)? {
            if record.tenant_hex == account_hex && record.tombstoned_at.is_none() {
                records.push((alias, record));
            }
        }
    }
    Ok(records)
}

/// The `server` values of the live registrations `account` signed here, or
/// `None` when it holds none. Live is as `PrivateService::live_registration`
/// has it: a record that is not tombstoned and whose event is still in the
/// relay store, found here for every alias with one query.
async fn live_registration_servers(
    svc: &PrivateService,
    account: &PublicKey,
) -> Result<Option<Vec<String>>, WritePolicyResult> {
    let records = account_records(svc, &account.to_hex()).map_err(meta_failure)?;
    if records.is_empty() {
        return Ok(None);
    }
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_REGISTRATION))
        .author(*account)
        .identifiers(records.iter().map(|(alias, _)| alias.clone()));
    let stored = svc
        .database
        .query(filter)
        .await
        .map_err(relay_store_failure)?;
    let live: HashSet<String> = stored.iter().filter_map(super::admission::d_tag).collect();
    if live.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        records
            .into_iter()
            .filter(|(alias, _)| live.contains(alias))
            .flat_map(|(_, record)| record.servers)
            .collect(),
    ))
}

/// Whether a vanish names `ALL_RELAYS`, or every node of the pair: this
/// node, each of `peers` (the configured sync peers, as their sync keys)
/// and every node that a value of `servers` names, each read as upstream
/// reads a vanish's targets.
///
/// Upstream acts on a vanish when a `relay` tag parses to a relay URL equal
/// to `wss://` or `ws://` before its service address, so this node is
/// judged by exactly that test (`the_own_node_test_is_upstreams` pins it)
/// and acts on every vanish it takes. A peer is judged by the same test
/// with its sync key, less the scheme, as its address, and a `server` value
/// with the address read from it: the host without a trailing dot, the
/// port when it is not the scheme's own, and the path without trailing
/// slashes. Every value counts, those that name this node included: a
/// node knows the other's own address only from its peer list, so when a
/// registration spells a node otherwise, both nodes must ask for that
/// spelling and for both addresses, or one would take a vanish the other
/// refuses. Two nodes whose peer lists name each other, as their matching
/// fingerprints show, thus ask the same of every vanish. A value that is no
/// absolute ws, wss, http or https URL names no node a vanish could reach
/// and asks for nothing.
fn vanish_names_every_node(
    event: &Event,
    own_address: &str,
    peers: &HashSet<String>,
    servers: &[String],
) -> bool {
    if nip62::is_valid_vanish_request_for_relay(event.tags.as_slice(), None) {
        return true;
    }
    let named: HashSet<RelayUrl> = event
        .tags
        .iter()
        .filter_map(|tag| match nip62::Nip62Tag::try_from(tag) {
            Ok(nip62::Nip62Tag::Relay(url)) => Some(url),
            _ => None,
        })
        .collect();
    let peer_addresses = peers.iter().map(|peer| {
        peer.split_once("://")
            .map_or(peer.as_str(), |(_, rest)| rest)
            .to_string()
    });
    let required: HashSet<String> = std::iter::once(own_address.to_string())
        .chain(peer_addresses)
        .chain(
            servers
                .iter()
                .filter_map(|value| node_address(value.as_str())),
        )
        .collect();
    required.iter().all(|address| {
        relay_url_candidates(address)
            .iter()
            .any(|url| named.contains(url))
    })
}

/// The relay URLs upstream compares a vanish's targets with for a node
/// whose service address is `address` (`DeletionService::relay_url_candidates`,
/// whose rule this must keep).
fn relay_url_candidates(address: &str) -> Vec<RelayUrl> {
    let address = address.trim().trim_end_matches('/');
    if address.is_empty() {
        return Vec::new();
    }
    let spellings = if address.contains("://") {
        vec![address.to_owned()]
    } else {
        vec![format!("wss://{address}"), format!("ws://{address}")]
    };
    spellings
        .iter()
        .filter_map(|spelling| RelayUrl::parse(spelling).ok())
        .collect()
}

/// The service address, without a scheme, of the node a `server` value
/// names.
fn node_address(value: &str) -> Option<String> {
    let url = url::Url::parse(value.trim()).ok()?;
    if !matches!(url.scheme(), "ws" | "wss" | "http" | "https") {
        return None;
    }
    let host = url.host_str()?.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Some(format!("{authority}{}", url.path().trim_end_matches('/')))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use bitcoin_hashes::sha256;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Tag, Timestamp, WritePolicy};

    use super::*;
    use crate::grasp_p::admission::admit;
    use crate::grasp_p::{
        KIND_EPHEMERAL_STREAM_WRAP, KIND_EPHEMERAL_WRAP, KIND_REPORT, KIND_STREAM_WRAP, KIND_WRAP,
    };
    use crate::nostr::lifecycle::RequestClassification;

    /// A node's write policy and stores, built as the server builds them,
    /// over an in-memory relay database. Nothing listens on a socket.
    struct Node {
        _dir: tempfile::TempDir,
        runtime: crate::nostr::builder::RelayRuntime,
    }

    impl Node {
        async fn start() -> Self {
            Self::start_with(true, true).await
        }

        async fn start_with(grasp_p: bool, accept_legacy: bool) -> Self {
            Self::start_configured(|config| {
                config.private_repos_enable = grasp_p;
                config.private_accept_legacy_wrap_kind = accept_legacy;
            })
            .await
        }

        /// A GRASP-P node whose settings `configure` changes first.
        async fn start_configured(configure: impl FnOnce(&mut crate::config::Config)) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
            let mut config = crate::config::Config::for_testing();
            config.git_data_path = path("git");
            config.relay_data_path = path("relay");
            config.private_repos_enable = true;
            config.private_meta_data_path = Some(path("meta"));
            config.private_blob_data_path = Some(path("blobs"));
            configure(&mut config);
            let purgatory = Arc::new(crate::purgatory::Purgatory::new(dir.path().join("git")));
            let runtime = crate::nostr::builder::create_relay(
                &config,
                purgatory,
                crate::grasp06::receive::RepoInitLocks::default(),
                None,
            )
            .await
            .expect("relay");
            Self { _dir: dir, runtime }
        }

        fn svc(&self) -> &PrivateService {
            self.runtime.grasp_p.as_deref().expect("GRASP-P is on")
        }

        /// What a client sending `event` is told: the write policy decides,
        /// and an accepted event is stored, as the relay stores it.
        async fn send(&self, event: &Event) -> WritePolicyResult {
            let client: SocketAddr = "198.51.100.7:40000".parse().expect("address");
            let result = self.runtime.write_policy.admit_event(event, &client).await;
            if matches!(result, WritePolicyResult::Accept) {
                self.store(event).await;
            }
            result
        }

        /// Put `event` in the relay store without asking the write policy.
        async fn store(&self, event: &Event) {
            self.runtime
                .stores
                .database
                .save_event(event)
                .await
                .expect("store the event");
        }

        /// Record `request` as an accepted, locally actionable deletion
        /// request, as upstream records one, without acting on it.
        async fn tombstone(&self, request: &Event) {
            self.runtime
                .stores
                .tombstones
                .record_request(
                    request,
                    Timestamp::now(),
                    RequestClassification::LocallyActionable,
                )
                .await
                .expect("record a request");
        }

        async fn stored(&self, id: EventId) -> bool {
            self.runtime
                .stores
                .database
                .event_by_id(&id)
                .await
                .expect("lookup")
                .is_some()
        }

        async fn live(&self, alias: &str) -> bool {
            self.svc()
                .live_registration(alias)
                .await
                .expect("liveness")
                .is_some()
        }

        fn claimed(&self, key: &Keys) -> bool {
            let txn = self.svc().meta.read_txn().expect("read");
            self.svc()
                .meta
                .get_key_claim(&txn, &key.public_key().to_hex())
                .expect("claim")
                .is_some()
        }
    }

    /// One private repository: its account key, a write key and the shared
    /// aux key.
    struct Repo {
        tenant: Keys,
        writer: Keys,
        aux: Keys,
        alias: String,
        registration: Event,
    }

    fn now() -> u64 {
        Timestamp::now().as_secs()
    }

    fn random_alias() -> String {
        Keys::generate().public_key().to_hex()[..32].to_string()
    }

    fn key_entry(key: &Keys, tenant: &Keys, alias: &str) -> Vec<String> {
        let digest = sha256::Hash::hash(
            super::super::registration::key_pop_input(&tenant.public_key().to_hex(), alias)
                .as_bytes(),
        );
        let sig = key.sign_schnorr(digest.to_byte_array());
        vec![key.public_key().to_hex(), sig.to_string()]
    }

    fn registration(
        tenant: &Keys,
        alias: &str,
        writer: &Keys,
        aux: &Keys,
        created_at: u64,
    ) -> Event {
        registration_naming(tenant, alias, writer, aux, created_at, &[OWN_SERVER])
    }

    /// This node's address as a registration's `server` value names it.
    const OWN_SERVER: &str = "http://localhost:7334";

    /// The other node of the pair, as the registrations below name it.
    const PEER_SERVER: &str = "https://peer.example";

    /// A registration whose `server` tag lists `servers`, this node first.
    fn registration_naming(
        tenant: &Keys,
        alias: &str,
        writer: &Keys,
        aux: &Keys,
        created_at: u64,
        servers: &[&str],
    ) -> Event {
        EventBuilder::new(Kind::Custom(KIND_REGISTRATION), "")
            .tags(vec![
                Tag::identifier(alias),
                Tag::custom("relays", vec!["ws://localhost:7334".to_string()]),
                Tag::custom("server", servers.iter().map(|s| s.to_string())),
                Tag::custom("w", key_entry(writer, tenant, alias)),
                Tag::custom("aux", key_entry(aux, tenant, alias)),
            ])
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(tenant)
            .expect("sign 30640")
    }

    fn state_root(writer: &Keys, tenant: &Keys, alias: &str, created_at: u64) -> Event {
        let coordinate = format!("30640:{}:{alias}", tenant.public_key().to_hex());
        EventBuilder::new(Kind::Custom(KIND_STATE_ROOT), "")
            .tags(vec![
                Tag::identifier(alias),
                Tag::custom("a", vec![coordinate]),
                Tag::custom("m", vec!["ab".repeat(32), "10".to_string()]),
            ])
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(writer)
            .expect("sign 30641")
    }

    /// A stored stream wrap of `kind`; the counter keeps every id distinct.
    fn wrap_of_kind(signer: &Keys, kind: u16) -> Event {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        EventBuilder::new(Kind::Custom(kind), format!("ciphertext {n}"))
            .finalize(signer)
            .expect("sign wrap")
    }

    fn wrap(signer: &Keys) -> Event {
        wrap_of_kind(signer, KIND_STREAM_WRAP)
    }

    fn note(signer: &Keys) -> Event {
        EventBuilder::new(Kind::TextNote, "a public note")
            .finalize(signer)
            .expect("sign note")
    }

    fn deletion(signer: &Keys, tags: Vec<Tag>, created_at: u64) -> Event {
        EventBuilder::new(Kind::EventDeletion, "")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(signer)
            .expect("sign kind 5")
    }

    fn vanish(signer: &Keys) -> Event {
        vanish_naming(signer, &["ALL_RELAYS"], now())
    }

    /// A vanish with one `relay` tag for each of `relays`.
    fn vanish_naming(signer: &Keys, relays: &[&str], created_at: u64) -> Event {
        EventBuilder::new(Kind::RequestToVanish, "")
            .tags(
                relays
                    .iter()
                    .map(|relay| Tag::custom("relay", vec![relay.to_string()])),
            )
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(signer)
            .expect("sign kind 62")
    }

    fn a(coordinate: String) -> Tag {
        Tag::custom("a", vec![coordinate])
    }

    fn k(kind: &str) -> Tag {
        Tag::custom("k", vec![kind.to_string()])
    }

    fn registration_coordinate(repo: &Repo) -> String {
        format!("30640:{}:{}", repo.tenant.public_key().to_hex(), repo.alias)
    }

    /// The account's offboard request for `repo`.
    fn offboard(repo: &Repo, created_at: u64) -> Event {
        deletion(
            &repo.tenant,
            vec![a(registration_coordinate(repo)), k("30640")],
            created_at,
        )
    }

    fn accepted(result: WritePolicyResult, what: &str) {
        match result {
            WritePolicyResult::Accept => {}
            WritePolicyResult::Reject {
                prefix, message, ..
            } => panic!("{what}: refused with {prefix}: {message}"),
        }
    }

    /// The text a client is sent for a refusal, as the relay renders it.
    fn refusal(result: WritePolicyResult, what: &str) -> String {
        match result {
            WritePolicyResult::Reject {
                prefix,
                message,
                status: false,
            } => {
                let text = format!("{prefix}: {message}");
                assert!(
                    !text.contains("unregistered"),
                    "{what}: the client would widen on {text:?}"
                );
                text
            }
            WritePolicyResult::Reject { message, .. } => {
                panic!("{what}: answered OK with {message:?}, expected a refusal")
            }
            WritePolicyResult::Accept => panic!("{what}: accepted, expected a refusal"),
        }
    }

    fn guard_refusal(result: Option<WritePolicyResult>, what: &str) -> String {
        refusal(
            result.unwrap_or_else(|| panic!("{what}: passed to upstream, expected a refusal")),
            what,
        )
    }

    /// A registered repository with a stored state root and a stored wrap.
    async fn repo_with_history(node: &Node) -> (Repo, Event, Event) {
        let tenant = Keys::generate();
        let writer = Keys::generate();
        let aux = Keys::generate();
        let alias = random_alias();
        let registration = registration(&tenant, &alias, &writer, &aux, now() - 120);
        accepted(node.send(&registration).await, "registration");
        let root = state_root(&writer, &tenant, &alias, now() - 60);
        accepted(node.send(&root).await, "state root");
        let stored_wrap = wrap(&aux);
        accepted(node.send(&stored_wrap).await, "wrap");
        let repo = Repo {
            tenant,
            writer,
            aux,
            alias,
            registration,
        };
        (repo, root, stored_wrap)
    }

    /// The gate is passed over for the kinds whose only authority is the
    /// registration, as this node takes them, and for no other. A kind added
    /// here by mistake stops tombstones from guarding it; one left out lets
    /// a request sent before its key was registered block that key. A node
    /// that refuses the legacy kinds keeps upstream's gate for them. Stored
    /// legacy wraps stay out of upstream's deletions whatever the setting,
    /// and the cascade passes over registrations as well.
    #[tokio::test]
    async fn the_gate_exemption_is_state_roots_and_stream_wraps_only() {
        let node = Node::start().await;
        let legacy_off = Node::start_with(true, false).await;
        let author = Keys::generate();
        let author_hex = author.public_key().to_hex();
        let other_hex = Keys::generate().public_key().to_hex();
        let owners = [None, Some(author_hex.as_str()), Some(other_hex.as_str())];
        for kind in [
            KIND_STATE_ROOT,
            KIND_STREAM_WRAP,
            KIND_WRAP,
            KIND_EPHEMERAL_STREAM_WRAP,
            KIND_EPHEMERAL_WRAP,
        ] {
            assert!(deletion_gate_exempt(node.svc(), kind), "kind {kind}");
            assert!(cascade_exempt(kind), "kind {kind}");
            let event = wrap_of_kind(&author, kind);
            for owner in owners {
                assert!(
                    removal_exempt(&event, owner),
                    "kind {kind}, owner {owner:?}"
                );
            }
        }
        for kind in [
            KIND_STATE_ROOT,
            KIND_STREAM_WRAP,
            KIND_EPHEMERAL_STREAM_WRAP,
        ] {
            assert!(deletion_gate_exempt(legacy_off.svc(), kind), "kind {kind}");
        }
        for kind in [KIND_WRAP, KIND_EPHEMERAL_WRAP] {
            assert!(!deletion_gate_exempt(legacy_off.svc(), kind), "kind {kind}");
        }
        for kind in [KIND_REGISTRATION, 5, 62, 0, 1, 30617, 30618, KIND_REPORT] {
            assert!(!deletion_gate_exempt(node.svc(), kind), "kind {kind}");
        }
        for kind in [5, 62, 0, 1, 30617, 30618, KIND_REPORT] {
            let event = wrap_of_kind(&author, kind);
            for owner in owners {
                assert!(
                    !removal_exempt(&event, owner),
                    "kind {kind}, owner {owner:?}"
                );
            }
        }
        // A registration goes only by a path bound to its own author: the
        // coordinate path and the vanish. The `e` path records no owner.
        let listed = wrap_of_kind(&author, KIND_REGISTRATION);
        assert!(removal_exempt(&listed, None));
        assert!(removal_exempt(&listed, Some(other_hex.as_str())));
        assert!(!removal_exempt(&listed, Some(author_hex.as_str())));
        assert!(cascade_exempt(KIND_REGISTRATION));
        for kind in [5, 62, 0, 1, 30617, 30618, KIND_REPORT] {
            assert!(!cascade_exempt(kind), "kind {kind}");
        }
    }

    /// A write key and the shared aux key of a live repository: every
    /// deletion request and every vanish is refused, whatever it names, and
    /// nothing is removed or blocked. Upstream would delete a member's own
    /// state root or wrap and then refuse the key's later events.
    #[tokio::test]
    async fn member_keys_cannot_delete_or_vanish() {
        let node = Node::start().await;
        let (repo, root, stored_wrap) = repo_with_history(&node).await;

        let own_note = note(&repo.writer);
        for (name, member, own_event) in [
            ("write key", &repo.writer, &root),
            ("aux key", &repo.aux, &stored_wrap),
        ] {
            let requests = [
                (
                    "its own event by id",
                    deletion(member, vec![Tag::event(own_event.id)], now()),
                ),
                (
                    "a public event by id",
                    deletion(member, vec![Tag::event(own_note.id)], now()),
                ),
                ("nothing at all", deletion(member, vec![], now())),
                ("a vanish", vanish(member)),
            ];
            for (what, request) in requests {
                let what = format!("{name}, {what}");
                assert_eq!(
                    guard_refusal(guard(node.svc(), &request).await, &what),
                    format!("restricted: {MEMBER_KEY_MESSAGE}"),
                    "{what}"
                );
                // The whole write policy gives the same answer.
                assert_eq!(
                    refusal(node.send(&request).await, &what),
                    format!("restricted: {MEMBER_KEY_MESSAGE}"),
                    "{what}"
                );
            }
        }

        assert!(node.stored(root.id).await && node.stored(stored_wrap.id).await);
        assert!(node.live(&repo.alias).await);
        // Neither key is blocked.
        accepted(node.send(&wrap(&repo.aux)).await, "a later wrap");
        accepted(
            node.send(&state_root(&repo.writer, &repo.tenant, &repo.alias, now()))
                .await,
            "a later state root",
        );
    }

    /// A member key may name a 30640 coordinate under its own key, which
    /// deletes nothing of anyone else's, and nothing beside it: not an id
    /// this node does not hold yet, not one of its own public events, not a
    /// coordinate of another kind. Being an offboard request, it is refused
    /// as any signer's would be.
    #[tokio::test]
    async fn a_member_key_names_nothing_beside_its_own_registration_coordinate() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let writer_hex = repo.writer.public_key().to_hex();
        let own_note = note(&repo.writer);
        node.store(&own_note).await;
        let by_id = format!("invalid: {OFFBOARD_ID_MESSAGE}");
        let shape = format!("invalid: {OFFBOARD_SHAPE_MESSAGE}");
        for (what, beside, want) in [
            (
                "an id this node does not hold",
                Tag::event(EventId::from_byte_array([9; 32])),
                &by_id,
            ),
            ("its own public note", Tag::event(own_note.id), &by_id),
            (
                "a public repository",
                a(format!("30617:{writer_hex}:a-public-repo")),
                &shape,
            ),
        ] {
            let request = deletion(
                &repo.writer,
                vec![a(format!("30640:{writer_hex}:x")), k("30640"), beside],
                now(),
            );
            assert_eq!(
                &guard_refusal(guard(node.svc(), &request).await, what),
                want,
                "{what}"
            );
            assert_eq!(&refusal(node.send(&request).await, what), want, "{what}");
        }
        assert!(node.stored(own_note.id).await);

        // The coordinate alone passes, and changes nothing: the claim hook
        // and the tombstone go by the registration's account, which is not
        // the write key.
        let request = deletion(
            &repo.writer,
            vec![a(format!("30640:{writer_hex}:{}", repo.alias)), k("30640")],
            now(),
        );
        assert!(guard(node.svc(), &request).await.is_none());
        accepted(node.send(&request).await, "its own coordinate alone");
        assert!(node.live(&repo.alias).await && node.claimed(&repo.writer));
        accepted(
            node.send(&state_root(&repo.writer, &repo.tenant, &repo.alias, now()))
                .await,
            "a later state root",
        );
    }

    /// Keys dropped from a registration hold no claim any more, but what
    /// they signed is still the repository's: requests that name it, by id
    /// or by a coordinate of its kind, are refused, and so is their vanish.
    /// A coordinate of a wrap kind matters because upstream reads it as
    /// "every event of that kind by the signer".
    #[tokio::test]
    async fn dropped_keys_cannot_delete_what_they_signed() {
        let node = Node::start().await;
        let (repo, root, stored_wrap) = repo_with_history(&node).await;
        let legacy_wrap = wrap_of_kind(&repo.aux, KIND_WRAP);
        accepted(node.send(&legacy_wrap).await, "a legacy wrap");
        let rotated = registration(
            &repo.tenant,
            &repo.alias,
            &Keys::generate(),
            &Keys::generate(),
            now() - 30,
        );
        accepted(node.send(&rotated).await, "rotation");
        assert!(!node.claimed(&repo.writer) && !node.claimed(&repo.aux));

        let writer_hex = repo.writer.public_key().to_hex();
        let aux_hex = repo.aux.public_key().to_hex();
        let service = format!("restricted: {SERVICE_EVENT_MESSAGE}");
        let signed = format!("restricted: {SIGNED_HISTORY_VANISH_MESSAGE}");
        let cases = [
            (
                "a state root by id",
                deletion(&repo.writer, vec![Tag::event(root.id), k("30641")], now()),
                &service,
            ),
            (
                "a state root by coordinate",
                deletion(
                    &repo.writer,
                    vec![a(format!("30641:{writer_hex}:{}", repo.alias)), k("30641")],
                    now(),
                ),
                &service,
            ),
            (
                "a wrap by id",
                deletion(&repo.aux, vec![Tag::event(stored_wrap.id)], now()),
                &service,
            ),
            (
                "a legacy wrap by id",
                deletion(&repo.aux, vec![Tag::event(legacy_wrap.id)], now()),
                &service,
            ),
            (
                "every wrap, by a coordinate of the wrap kind",
                deletion(&repo.aux, vec![a(format!("3359:{aux_hex}:x"))], now()),
                &service,
            ),
            (
                "every legacy wrap, the same way",
                deletion(&repo.aux, vec![a(format!("1059:{aux_hex}:"))], now()),
                &service,
            ),
            (
                "a state root by a coordinate spelled oddly",
                deletion(
                    &repo.writer,
                    vec![a(format!("030641:{writer_hex}:{}", repo.alias))],
                    now(),
                ),
                &service,
            ),
            ("the writer's vanish", vanish(&repo.writer), &signed),
            ("the aux key's vanish", vanish(&repo.aux), &signed),
        ];
        for (what, request, want) in cases {
            assert_eq!(
                &guard_refusal(guard(node.svc(), &request).await, what),
                want,
                "{what}"
            );
            assert_eq!(&refusal(node.send(&request).await, what), want, "{what}");
        }
        for id in [root.id, stored_wrap.id, legacy_wrap.id] {
            assert!(node.stored(id).await, "{id} must still be stored");
        }
    }

    /// The account deletes its repository by the registration's coordinate,
    /// with the k tag and a date within the skew, and no event id beside
    /// them. Every other shape of a deletion of a registration is refused,
    /// and the accepted one removes the registration, frees its keys and
    /// leaves the state root and the wrap where they are.
    #[tokio::test]
    async fn the_account_deletes_its_repository_by_the_registration_coordinate() {
        let node = Node::start().await;
        let (repo, root, stored_wrap) = repo_with_history(&node).await;
        let tenant_hex = repo.tenant.public_key().to_hex();
        let coordinate = registration_coordinate(&repo);

        let refused = [
            (
                "no k tag",
                deletion(&repo.tenant, vec![a(coordinate.clone())], now()),
                format!("invalid: {MISSING_K_MESSAGE}"),
            ),
            (
                "the k tag of another kind",
                deletion(&repo.tenant, vec![a(coordinate.clone()), k("30641")], now()),
                format!("invalid: {MISSING_K_MESSAGE}"),
            ),
            (
                "dated an hour ahead",
                offboard(&repo, now() + 3600),
                "invalid: event created_at is too far in the future".to_string(),
            ),
            (
                "the event id alone",
                deletion(
                    &repo.tenant,
                    vec![Tag::event(repo.registration.id), k("30640")],
                    now(),
                ),
                format!("restricted: {REGISTRATION_BY_ID_MESSAGE}"),
            ),
            (
                "an id this node does not hold, under the k tag",
                deletion(
                    &repo.tenant,
                    vec![Tag::event(EventId::from_byte_array([7; 32])), k("30640")],
                    now(),
                ),
                format!("restricted: {REGISTRATION_BY_ID_MESSAGE}"),
            ),
            (
                "the kind spelled with a leading zero",
                deletion(
                    &repo.tenant,
                    vec![a(format!("030640:{tenant_hex}:{}", repo.alias)), k("30640")],
                    now(),
                ),
                format!("invalid: {REGISTRATION_COORDINATE_MESSAGE}"),
            ),
            (
                "its state root beside the registration",
                deletion(
                    &repo.tenant,
                    vec![a(coordinate.clone()), Tag::event(root.id), k("30640")],
                    now(),
                ),
                format!("invalid: {OFFBOARD_ID_MESSAGE}"),
            ),
            (
                "the registration's own event id beside its coordinate",
                deletion(
                    &repo.tenant,
                    vec![
                        a(coordinate.clone()),
                        Tag::event(repo.registration.id),
                        k("30640"),
                    ],
                    now(),
                ),
                format!("invalid: {OFFBOARD_ID_MESSAGE}"),
            ),
        ];
        for (what, request, want) in refused {
            assert_eq!(
                guard_refusal(guard(node.svc(), &request).await, what),
                want,
                "{what}"
            );
            assert_eq!(refusal(node.send(&request).await, what), want, "{what}");
        }
        assert!(node.live(&repo.alias).await, "nothing was deleted");

        let request = deletion(&repo.tenant, vec![a(coordinate), k("30640")], now());
        assert!(guard(node.svc(), &request).await.is_none());
        accepted(node.send(&request).await, "the offboard request");
        assert!(!node.stored(repo.registration.id).await);
        assert!(!node.live(&repo.alias).await);
        assert!(!node.claimed(&repo.writer) && !node.claimed(&repo.aux));
        assert!(
            node.stored(root.id).await && node.stored(stored_wrap.id).await,
            "a deletion request removes no state root and no wrap"
        );
    }

    /// The same account key, offboarding by coordinate alone, is what the
    /// client sends; it passes with nothing else to look up.
    #[tokio::test]
    async fn an_offboard_request_by_coordinate_alone_passes() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let request = offboard(&repo, now());
        assert!(guard(node.svc(), &request).await.is_none());
        accepted(node.send(&request).await, "the offboard request");
        assert!(!node.live(&repo.alias).await);
    }

    /// Nobody but the account that signed a registration may name it: not
    /// a stranger by coordinate, not another account by event id in a
    /// request with neither mark (an offboard request names no id at all).
    #[tokio::test]
    async fn a_registration_is_deleted_only_by_its_own_account() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let (other, _, _) = repo_with_history(&node).await;
        let foreign = format!("restricted: {FOREIGN_REGISTRATION_MESSAGE}");

        let stranger = Keys::generate();
        let by_coordinate = deletion(
            &stranger,
            vec![a(registration_coordinate(&repo)), k("30640")],
            now(),
        );
        let by_id_from_another_account =
            deletion(&other.tenant, vec![Tag::event(repo.registration.id)], now());
        for (what, request) in [
            ("a stranger, by coordinate", by_coordinate),
            ("another account, by id", by_id_from_another_account),
        ] {
            assert_eq!(
                guard_refusal(guard(node.svc(), &request).await, what),
                foreign,
                "{what}"
            );
            assert_eq!(refusal(node.send(&request).await, what), foreign, "{what}");
        }
        assert!(node.live(&repo.alias).await && node.live(&other.alias).await);
    }

    /// An account's own registration named by event id is refused: by id
    /// alone, without the k tag too, as a registration named by id and not
    /// by coordinate, and beside the coordinate of another of its
    /// repositories, as an offboard request with an event id.
    #[tokio::test]
    async fn an_own_registration_named_by_id_needs_its_own_coordinate() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let second_alias = random_alias();
        let second = registration(
            &repo.tenant,
            &second_alias,
            &Keys::generate(),
            &Keys::generate(),
            now() - 90,
        );
        accepted(node.send(&second).await, "a second registration");
        let tenant_hex = repo.tenant.public_key().to_hex();
        let by_id = format!("restricted: {REGISTRATION_BY_ID_MESSAGE}");
        let with_id = format!("invalid: {OFFBOARD_ID_MESSAGE}");
        for (what, request, want) in [
            (
                "its id alone, without the k tag",
                deletion(&repo.tenant, vec![Tag::event(repo.registration.id)], now()),
                &by_id,
            ),
            (
                "its id beside another repository's coordinate",
                deletion(
                    &repo.tenant,
                    vec![
                        a(format!("30640:{tenant_hex}:{second_alias}")),
                        Tag::event(repo.registration.id),
                        k("30640"),
                    ],
                    now(),
                ),
                &with_id,
            ),
        ] {
            assert_eq!(
                &guard_refusal(guard(node.svc(), &request).await, what),
                want,
                "{what}"
            );
            assert_eq!(&refusal(node.send(&request).await, what), want, "{what}");
        }
        assert!(node.live(&repo.alias).await && node.live(&second_alias).await);
    }

    /// Requests that name no GRASP-P event and come from no GRASP-P member
    /// key are upstream's, exactly as on a node without GRASP-P: a
    /// stranger's deletion of its own note, of ids nobody holds and of a
    /// public repository, one whose k value reads as 30640 but is not the
    /// text the peers' sync filter selects, a stranger's vanish, and an
    /// account deleting its own public note.
    #[tokio::test]
    async fn requests_that_touch_no_grasp_p_key_or_event_are_upstreams() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let stranger = Keys::generate();
        let stranger_note = note(&stranger);
        node.store(&stranger_note).await;
        let account_note = note(&repo.tenant);
        node.store(&account_note).await;
        let public_repository = format!("30617:{}:a-public-repo", stranger.public_key().to_hex());

        let requests = [
            (
                "a stranger's own note",
                deletion(&stranger, vec![Tag::event(stranger_note.id)], now()),
            ),
            (
                "ids nobody holds",
                deletion(
                    &stranger,
                    vec![Tag::event(EventId::from_byte_array([0; 32])), k("1")],
                    now(),
                ),
            ),
            (
                "a public repository",
                deletion(&stranger, vec![a(public_repository), k("30617")], now()),
            ),
            (
                "a k value that only reads as 30640",
                deletion(
                    &stranger,
                    vec![Tag::event(EventId::from_byte_array([1; 32])), k("030640")],
                    now(),
                ),
            ),
            ("a stranger's vanish", vanish(&Keys::generate())),
            (
                "an account's own public note",
                deletion(&repo.tenant, vec![Tag::event(account_note.id)], now()),
            ),
        ];
        for (what, request) in requests {
            assert!(guard(node.svc(), &request).await.is_none(), "{what}");
            accepted(node.send(&request).await, what);
        }
        assert!(!node.stored(stranger_note.id).await && !node.stored(account_note.id).await);
        assert!(node.live(&repo.alias).await);
    }

    /// The account's vanish closes the account: it passes, upstream and
    /// the claim hook remove its registrations and free their keys, and the
    /// state roots and wraps its members signed stay. A key that is a write
    /// or aux key, of another account's repository or of its own, may not
    /// vanish, while its offboard request for its own repository still
    /// passes.
    #[tokio::test]
    async fn the_account_vanishes_and_a_member_key_does_not() {
        let node = Node::start().await;
        let member = format!("restricted: {MEMBER_KEY_MESSAGE}");

        let (repo, root, stored_wrap) = repo_with_history(&node).await;
        let request = vanish(&repo.tenant);
        assert!(guard(node.svc(), &request).await.is_none());
        accepted(node.send(&request).await, "the account's vanish");
        assert!(!node.live(&repo.alias).await && !node.stored(repo.registration.id).await);
        assert!(!node.claimed(&repo.writer) && !node.claimed(&repo.aux));
        assert!(node.stored(root.id).await && node.stored(stored_wrap.id).await);

        // An account whose own key is its repository's write key.
        let tenant = Keys::generate();
        let alias = random_alias();
        let own = registration(&tenant, &alias, &tenant, &Keys::generate(), now() - 120);
        accepted(node.send(&own).await, "registration");
        let request = vanish(&tenant);
        assert_eq!(
            guard_refusal(guard(node.svc(), &request).await, "its vanish"),
            member
        );
        assert_eq!(refusal(node.send(&request).await, "its vanish"), member);
        assert!(node.live(&alias).await);

        // An account whose key is also the aux key of another account's
        // repository.
        let (mine, _root, _wrap) = repo_with_history(&node).await;
        let other_tenant = Keys::generate();
        let other_alias = random_alias();
        let theirs = registration(
            &other_tenant,
            &other_alias,
            &Keys::generate(),
            &mine.tenant,
            now() - 90,
        );
        accepted(node.send(&theirs).await, "the other account's registration");
        let request = vanish(&mine.tenant);
        assert_eq!(
            guard_refusal(guard(node.svc(), &request).await, "vanish"),
            member
        );
        assert!(node.live(&mine.alias).await && node.live(&other_alias).await);
        let request = offboard(&mine, now());
        assert!(guard(node.svc(), &request).await.is_none());
        accepted(node.send(&request).await, "its own offboard request");
        assert!(!node.live(&mine.alias).await && node.live(&other_alias).await);
    }

    /// A vanish sent before its key was registered is accepted (nothing of
    /// the key is here yet) and must not block that key once a repository
    /// lists it: its state roots and wraps are taken. A registration the
    /// key signs itself is still refused, since registrations stay gated.
    /// Without the exemption the gate refuses all three.
    #[tokio::test]
    async fn a_vanish_sent_before_registration_does_not_block_the_key() {
        let node = Node::start().await;
        let writer = Keys::generate();
        let aux = Keys::generate();
        for key in [&writer, &aux] {
            let request = vanish(key);
            assert!(guard(node.svc(), &request).await.is_none());
            accepted(
                node.send(&request).await,
                "a vanish from a key with nothing here",
            );
        }

        let tenant = Keys::generate();
        let alias = random_alias();
        let listed = registration(&tenant, &alias, &writer, &aux, now() - 60);
        accepted(node.send(&listed).await, "a registration listing both keys");
        accepted(
            node.send(&state_root(&writer, &tenant, &alias, now()))
                .await,
            "the writer's state root",
        );
        accepted(node.send(&wrap(&aux)).await, "the aux key's wrap");

        let own = registration(&aux, &random_alias(), &aux, &Keys::generate(), now());
        assert_eq!(
            refusal(
                node.send(&own).await,
                "a registration the vanished key signs"
            ),
            "invalid: this pubkey has requested to vanish"
        );
    }

    /// Tombstones that were recorded before this rule existed (written to
    /// the store directly here) no longer block state roots or wraps, by
    /// coordinate or by id. A registration under a coordinate tombstone is
    /// still refused.
    #[tokio::test]
    async fn tombstones_recorded_earlier_block_no_state_root_or_wrap() {
        let node = Node::start().await;
        let tenant = Keys::generate();
        let writer = Keys::generate();
        let aux = Keys::generate();
        let alias = random_alias();
        let listed = registration(&tenant, &alias, &writer, &aux, now() - 60);
        accepted(node.send(&listed).await, "registration");

        let pending_root = state_root(&writer, &tenant, &alias, now());
        let pending_wrap = wrap(&aux);
        let later = now() + 600;
        let old_requests = [
            deletion(
                &writer,
                vec![a(format!("30641:{}:{alias}", writer.public_key().to_hex()))],
                later,
            ),
            deletion(&aux, vec![Tag::event(pending_wrap.id)], now()),
            deletion(
                &tenant,
                vec![a(format!("30640:{}:{alias}", tenant.public_key().to_hex()))],
                later,
            ),
        ];
        for request in &old_requests {
            node.tombstone(request).await;
        }

        accepted(
            node.send(&pending_root).await,
            "a state root under an old tombstone",
        );
        accepted(
            node.send(&pending_wrap).await,
            "a wrap under an old tombstone",
        );
        let edition = registration(&tenant, &alias, &writer, &aux, now());
        assert_eq!(
            refusal(
                node.send(&edition).await,
                "a registration under an old tombstone"
            ),
            "invalid: this event is deleted"
        );
    }

    /// Upstream's announcement cascade follows tags both ways. A public
    /// event that tags a public repository and also a registration, its
    /// state root and its wrap is refused now, but one stored before that
    /// rule stays, so the bridge is put in the store directly. The deletion
    /// of that public repository, by kind 5 or by its owner's vanish,
    /// removes the announcement and the bridge and leaves the registration,
    /// its claims, the state root and the wrap.
    #[tokio::test]
    async fn a_public_cascade_takes_no_registration_state_root_or_wrap() {
        for by_vanish in [false, true] {
            let node = Node::start().await;
            let (repo, root, stored_wrap) = repo_with_history(&node).await;
            let outsider = Keys::generate();
            let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
                .tags(vec![Tag::identifier("a-public-repo")])
                .custom_created_at(Timestamp::from_secs(now() - 30))
                .finalize(&outsider)
                .expect("sign 30617");
            node.store(&announcement).await;
            let public = format!("30617:{}:a-public-repo", outsider.public_key().to_hex());
            let bridge = EventBuilder::new(Kind::TextNote, "")
                .tags(vec![
                    a(public.clone()),
                    a(registration_coordinate(&repo)),
                    Tag::event(root.id),
                    Tag::event(stored_wrap.id),
                ])
                .finalize(&outsider)
                .expect("sign the bridge");
            assert_eq!(
                refusal(node.send(&bridge).await, "the bridge"),
                format!(
                    "restricted: {}",
                    crate::grasp_p::attachment::REFERENCES_PRIVATE_MESSAGE
                )
            );
            node.store(&bridge).await;

            let request = if by_vanish {
                vanish(&outsider)
            } else {
                deletion(&outsider, vec![a(public), k("30617")], now())
            };
            assert!(guard(node.svc(), &request).await.is_none());
            accepted(
                node.send(&request).await,
                "the public repository's deletion",
            );
            assert!(
                !node.stored(announcement.id).await && !node.stored(bridge.id).await,
                "the cascade ran"
            );
            assert!(node.live(&repo.alias).await && node.stored(repo.registration.id).await);
            assert!(node.claimed(&repo.writer) && node.claimed(&repo.aux));
            assert!(node.stored(root.id).await && node.stored(stored_wrap.id).await);
        }
    }

    /// A request that got past the guard, handed here to upstream's
    /// deletion handling directly, as a target arriving between the guard's
    /// lookup and upstream's delete would let it through, removes no state
    /// root and no wrap; upstream still acts on the rest. A vanish handed
    /// over the same way removes none either.
    #[tokio::test]
    async fn upstream_removes_no_state_root_or_wrap_however_a_request_got_in() {
        let node = Node::start().await;
        let (repo, root, stored_wrap) = repo_with_history(&node).await;
        let own_note = note(&repo.aux);
        node.store(&own_note).await;
        let by_id = deletion(
            &repo.aux,
            vec![Tag::event(stored_wrap.id), Tag::event(own_note.id)],
            now(),
        );
        accepted(
            node.runtime.deletion.handle_nip09(&by_id).await,
            "upstream's deletion alone",
        );
        assert!(
            !node.stored(own_note.id).await,
            "upstream acted on the rest"
        );
        accepted(
            node.runtime
                .deletion
                .handle_vanish(&vanish(&repo.writer))
                .await,
            "upstream's vanish alone",
        );
        assert!(node.stored(root.id).await && node.stored(stored_wrap.id).await);
        assert!(node.live(&repo.alias).await);
    }

    /// With GRASP-P off the seam and the guard are not there: the gate
    /// refuses a state-root-shaped event under a coordinate tombstone and a
    /// wrap-shaped event from a vanished key, and a key deletes its own
    /// event of either kind, as upstream does.
    #[tokio::test]
    async fn with_grasp_p_off_upstream_decides_alone() {
        let node = Node::start_with(false, true).await;
        assert!(node.runtime.grasp_p.is_none());
        let tenant = Keys::generate();
        let writer = Keys::generate();
        let alias = random_alias();

        let root = state_root(&writer, &tenant, &alias, now());
        node.tombstone(&deletion(
            &writer,
            vec![a(format!("30641:{}:{alias}", writer.public_key().to_hex()))],
            now() + 600,
        ))
        .await;
        assert_eq!(
            refusal(node.send(&root).await, "a state root"),
            "invalid: this event is deleted"
        );

        let vanished = Keys::generate();
        node.tombstone(&vanish(&vanished)).await;
        assert_eq!(
            refusal(node.send(&wrap(&vanished)).await, "a wrap"),
            "invalid: this pubkey has requested to vanish"
        );

        let other_root = state_root(&writer, &tenant, &random_alias(), now());
        node.store(&other_root).await;
        accepted(
            node.send(&deletion(&writer, vec![Tag::event(other_root.id)], now()))
                .await,
            "a write key deleting its state root",
        );
        assert!(!node.stored(other_root.id).await);
    }

    /// More targets than upstream takes are refused before any lookup, in
    /// upstream's own words.
    #[tokio::test]
    async fn too_many_targets_are_refused_first() {
        let node = Node::start().await;
        let stranger = Keys::generate();
        let tags = (0..=MAX_TARGET_TAGS)
            .map(|_| Tag::event(EventId::from_byte_array([0; 32])))
            .collect();
        let request = deletion(&stranger, tags, now());
        assert_eq!(
            guard_refusal(guard(node.svc(), &request).await, "too many targets"),
            format!("invalid: {TOO_MANY_TARGETS_MESSAGE}")
        );
    }

    /// A request that sync brought and the guard refused is remembered by
    /// id, as a refused GRASP-P kind is, so the sync batch that asked for it
    /// completes instead of asking again on every connect. A client's
    /// refused request is not, and neither is upstream's target-cap refusal.
    #[tokio::test]
    async fn a_refused_synced_request_is_remembered_by_id() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let held = node.svc().sync_rejected();
        let member = format!("restricted: {MEMBER_KEY_MESSAGE}");

        let from_client = vanish(&repo.writer);
        assert_eq!(
            guard_refusal(admit(node.svc(), &from_client, false).await, "a client's"),
            member
        );
        assert!(!held.contains(&from_client.id));

        let synced = vanish(&repo.aux);
        assert_eq!(
            guard_refusal(admit(node.svc(), &synced, true).await, "a synced one"),
            member
        );
        assert!(held.contains(&synced.id));

        let tags = (0..=MAX_TARGET_TAGS)
            .map(|_| Tag::event(EventId::from_byte_array([0; 32])))
            .collect();
        let too_many = deletion(&Keys::generate(), tags, now());
        assert_eq!(
            guard_refusal(admit(node.svc(), &too_many, true).await, "too many targets"),
            format!("invalid: {TOO_MANY_TARGETS_MESSAGE}")
        );
        assert!(!held.contains(&too_many.id));
    }

    /// A kind 5 that says it deletes registrations, by `["k", "30640"]` or
    /// a 30640 coordinate, the kind spelled any way upstream reads it, is
    /// held to the offboard shape whoever signs it (decision D15-6): it
    /// rides the peers' sync filter, and upstream would act on the rest on
    /// both nodes. A stranger's request that names anything beside its own
    /// registration coordinates and the k tag is refused, and so is any
    /// event id, whatever it names, the account's own registration
    /// included. Each refusal is kept by id when sync brought it, so sync
    /// does not ask for it again. Without the rule the shape and id cases
    /// passed for a key that is no member, and upstream deleted the
    /// stranger's note.
    #[tokio::test]
    async fn a_grasp_p_shaped_request_is_a_pure_offboard_for_every_signer() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let stranger = Keys::generate();
        let stranger_hex = stranger.public_key().to_hex();
        let own = a(format!("30640:{stranger_hex}:{}", random_alias()));
        let public_note = note(&stranger);
        node.store(&public_note).await;
        let shape = format!("invalid: {OFFBOARD_SHAPE_MESSAGE}");
        let by_id = format!("invalid: {OFFBOARD_ID_MESSAGE}");
        let no_coordinate = format!("restricted: {REGISTRATION_BY_ID_MESSAGE}");
        let foreign = format!("restricted: {FOREIGN_REGISTRATION_MESSAGE}");
        let cases = [
            (
                "a public repository beside its coordinate",
                vec![
                    own.clone(),
                    k("30640"),
                    a(format!("30617:{stranger_hex}:a-public-repo")),
                ],
                &shape,
            ),
            (
                "a malformed coordinate beside it",
                vec![own.clone(), k("30640"), a("not-a-coordinate".to_string())],
                &shape,
            ),
            (
                "a k tag of another kind beside it",
                vec![own.clone(), k("30640"), k("1")],
                &shape,
            ),
            (
                "the k tag spelled otherwise beside it",
                vec![own.clone(), k("30640"), k("030640")],
                &shape,
            ),
            (
                "its own public note by id",
                vec![own.clone(), k("30640"), Tag::event(public_note.id)],
                &by_id,
            ),
            (
                "an id nobody holds",
                vec![
                    own.clone(),
                    k("30640"),
                    Tag::event(EventId::from_byte_array([3; 32])),
                ],
                &by_id,
            ),
            (
                "an e value that is no event id",
                vec![
                    own.clone(),
                    k("30640"),
                    Tag::custom("e", vec!["zz".to_string()]),
                ],
                &by_id,
            ),
            (
                "another account's registration by id beside it",
                vec![own.clone(), k("30640"), Tag::event(repo.registration.id)],
                &by_id,
            ),
            (
                "another account's registration by coordinate",
                vec![a(registration_coordinate(&repo)), k("30640")],
                &foreign,
            ),
            (
                "its public note by id under the k tag, with no coordinate",
                vec![k("30640"), Tag::event(public_note.id)],
                &no_coordinate,
            ),
        ];
        let held = node.svc().sync_rejected();
        for (what, tags, want) in cases {
            let request = deletion(&stranger, tags, now());
            assert_eq!(
                &guard_refusal(guard(node.svc(), &request).await, what),
                want,
                "{what}"
            );
            assert_eq!(&refusal(node.send(&request).await, what), want, "{what}");
            guard_refusal(admit(node.svc(), &request, true).await, what);
            assert!(held.contains(&request.id), "{what}: kept by id");
        }
        let missing_k = deletion(&stranger, vec![own.clone(), k("030640")], now());
        assert_eq!(
            refusal(node.send(&missing_k).await, "the k tag spelled otherwise"),
            format!("invalid: {MISSING_K_MESSAGE}")
        );
        assert!(node.stored(public_note.id).await, "nothing was deleted");
        assert!(node.live(&repo.alias).await);

        // The account's own registration is no exception to the id rule.
        let with_id = deletion(
            &repo.tenant,
            vec![
                a(registration_coordinate(&repo)),
                Tag::event(repo.registration.id),
                k("30640"),
            ],
            now(),
        );
        assert_eq!(
            refusal(node.send(&with_id).await, "the account's, with its id"),
            by_id
        );
        assert!(node.live(&repo.alias).await);

        // The pure shape passes: a stranger's deletes nothing of anyone
        // else's, and the account's closes its repository.
        let pure = deletion(&stranger, vec![own, k("30640")], now());
        assert!(guard(node.svc(), &pure).await.is_none());
        accepted(node.send(&pure).await, "a stranger's pure offboard request");
        let request = deletion(
            &repo.tenant,
            vec![a(registration_coordinate(&repo)), k("30640")],
            now(),
        );
        assert!(guard(node.svc(), &request).await.is_none());
        accepted(node.send(&request).await, "the account's offboard request");
        assert!(!node.live(&repo.alias).await);
        assert!(!node.claimed(&repo.writer) && !node.claimed(&repo.aux));
    }

    /// An offboard request names no event id, not even of an edition of its
    /// own registration this node holds, dated before or after the request.
    /// Whether an id is such an edition depends on what each node holds: a
    /// node that has replaced the edition, or has not received it yet, would
    /// refuse the request as final while this one took it, and an edition
    /// dated after the request would be refused by the id's tombstone, which
    /// has no date, here and not on the peer. Nothing is removed or freed,
    /// and the coordinate alone then closes the repository.
    #[tokio::test]
    async fn an_offboard_request_names_no_event_id() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let named = |created_at| {
            deletion(
                &repo.tenant,
                vec![
                    a(registration_coordinate(&repo)),
                    Tag::event(repo.registration.id),
                    k("30640"),
                ],
                created_at,
            )
        };
        let want = format!("invalid: {OFFBOARD_ID_MESSAGE}");
        for (what, request) in [
            (
                "dated before the edition",
                named(repo.registration.created_at.as_secs() - 1),
            ),
            ("dated after the edition", named(now())),
        ] {
            assert_eq!(
                guard_refusal(guard(node.svc(), &request).await, what),
                want,
                "{what}"
            );
            assert_eq!(refusal(node.send(&request).await, what), want, "{what}");
        }
        assert!(node.stored(repo.registration.id).await && node.live(&repo.alias).await);
        assert!(node.claimed(&repo.writer) && node.claimed(&repo.aux));

        accepted(
            node.send(&offboard(&repo, now())).await,
            "the coordinate alone",
        );
        assert!(!node.live(&repo.alias).await && !node.claimed(&repo.writer));
    }

    /// An offboard request names no more registrations than an account may
    /// hold, counted as tags, and stays within the private event size, and
    /// so does the vanish of a key that holds registrations here. A request
    /// or a vanish that is not GRASP-P's is upstream's at any size.
    #[tokio::test]
    async fn offboard_requests_and_account_vanishes_are_bounded() {
        let node = Node::start_configured(|config| {
            config.private_max_aliases_per_tenant = 2;
            config.private_max_event_bytes = 4096;
        })
        .await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let tenant_hex = repo.tenant.public_key().to_hex();
        let coordinate = a(registration_coordinate(&repo));
        let too_many = format!("invalid: {TOO_MANY_REGISTRATIONS_MESSAGE}");
        let oversize = format!("invalid: {OVERSIZE_MESSAGE}");
        let padded = "x".repeat(5000);
        let cases = [
            (
                "three coordinates",
                deletion(
                    &repo.tenant,
                    vec![
                        coordinate.clone(),
                        a(format!("30640:{tenant_hex}:{}", random_alias())),
                        a(format!("30640:{tenant_hex}:{}", random_alias())),
                        k("30640"),
                    ],
                    now(),
                ),
                &too_many,
            ),
            (
                "one coordinate three times",
                deletion(
                    &repo.tenant,
                    vec![
                        coordinate.clone(),
                        coordinate.clone(),
                        coordinate.clone(),
                        k("30640"),
                    ],
                    now(),
                ),
                &too_many,
            ),
            (
                "an offboard request over the size",
                EventBuilder::new(Kind::EventDeletion, padded.clone())
                    .tags(vec![coordinate.clone(), k("30640")])
                    .finalize(&repo.tenant)
                    .expect("sign kind 5"),
                &oversize,
            ),
            (
                "the account's vanish over the size",
                EventBuilder::new(Kind::RequestToVanish, padded.clone())
                    .tags(vec![Tag::custom("relay", vec!["ALL_RELAYS".to_string()])])
                    .finalize(&repo.tenant)
                    .expect("sign kind 62"),
                &oversize,
            ),
        ];
        for (what, request, want) in cases {
            assert_eq!(
                &guard_refusal(guard(node.svc(), &request).await, what),
                want,
                "{what}"
            );
            assert_eq!(&refusal(node.send(&request).await, what), want, "{what}");
        }
        assert!(node.live(&repo.alias).await && node.claimed(&repo.writer));

        let stranger = Keys::generate();
        let own_note = note(&stranger);
        node.store(&own_note).await;
        let large_deletion = EventBuilder::new(Kind::EventDeletion, padded.clone())
            .tags(vec![Tag::event(own_note.id)])
            .finalize(&stranger)
            .expect("sign kind 5");
        let large_vanish = EventBuilder::new(Kind::RequestToVanish, padded)
            .tags(vec![Tag::custom("relay", vec!["ALL_RELAYS".to_string()])])
            .finalize(&Keys::generate())
            .expect("sign kind 62");
        for (what, request) in [
            ("a stranger's large deletion", large_deletion),
            ("a stranger's large vanish", large_vanish),
        ] {
            assert!(guard(node.svc(), &request).await.is_none(), "{what}");
            accepted(node.send(&request).await, what);
        }
        assert!(!node.stored(own_note.id).await);

        let at_the_caps = deletion(
            &repo.tenant,
            vec![coordinate.clone(), coordinate, k("30640")],
            now(),
        );
        accepted(node.send(&at_the_caps).await, "a request at the caps");
        assert!(!node.live(&repo.alias).await);
    }

    /// In whitelist mode an offboard request is taken only from a key the
    /// node could admit: one on the list, with or without a registration
    /// here yet, or one that holds a registration here, as a seat kept after
    /// its key left the list does (written to the meta store directly). A
    /// stranger's is refused, and its public deletions stay upstream's.
    #[tokio::test]
    async fn whitelist_mode_takes_offboard_requests_from_admissible_keys_only() {
        let tenant = Keys::generate();
        let listed_only = Keys::generate();
        let npubs = [&tenant, &listed_only]
            .map(|keys| keys.public_key().to_bech32().expect("npub"))
            .join(",");
        let node = Node::start_configured(move |config| {
            config.private_registration_mode = RegistrationMode::Whitelist;
            config.private_tenant_whitelist = npubs;
        })
        .await;
        let writer = Keys::generate();
        let alias = random_alias();
        let listed = registration(&tenant, &alias, &writer, &Keys::generate(), now() - 60);
        accepted(node.send(&listed).await, "a listed account's registration");

        let offboard_by = |keys: &Keys, alias: &str| {
            deletion(
                keys,
                vec![
                    a(format!("30640:{}:{alias}", keys.public_key().to_hex())),
                    k("30640"),
                ],
                now(),
            )
        };
        let stranger = Keys::generate();
        let request = offboard_by(&stranger, &random_alias());
        let want = format!("invalid: {NOT_ADMITTED_MESSAGE}");
        assert_eq!(
            guard_refusal(guard(node.svc(), &request).await, "a stranger's"),
            want
        );
        assert_eq!(refusal(node.send(&request).await, "a stranger's"), want);

        let kept = Keys::generate();
        let kept_alias = random_alias();
        let kept_aliases = vec![kept_alias.clone()];
        node.svc()
            .meta
            .with_write(|meta, txn| {
                meta.put_tenant_aliases(txn, &kept.public_key().to_hex(), &kept_aliases)
            })
            .expect("write a seat");
        for (what, request) in [
            (
                "a listed key with no registration yet",
                offboard_by(&listed_only, &random_alias()),
            ),
            (
                "a key that holds a seat here",
                offboard_by(&kept, &kept_alias),
            ),
        ] {
            assert!(guard(node.svc(), &request).await.is_none(), "{what}");
        }
        accepted(
            node.send(&offboard_by(&tenant, &alias)).await,
            "the listed account's offboard request",
        );
        assert!(!node.live(&alias).await && !node.claimed(&writer));

        let own_note = note(&stranger);
        node.store(&own_note).await;
        accepted(
            node.send(&deletion(&stranger, vec![Tag::event(own_note.id)], now()))
                .await,
            "a stranger's public deletion",
        );
        assert!(!node.stored(own_note.id).await);
    }

    /// The vanish of a key that holds registrations here closes the account
    /// on both nodes of its pair only if it names them all, because upstream
    /// acts on a vanish only on a node it names: so it must carry ALL_RELAYS
    /// or name every node the registrations' `server` tags list, this one as
    /// upstream reads its own address. Naming this node alone would close
    /// the account here and leave it open on the peer; naming the peer
    /// alone, the other way round. A refused synced vanish is kept by id. A
    /// key with no registration here is upstream's whatever it names.
    #[tokio::test]
    async fn an_accounts_vanish_names_every_node_of_its_pair() {
        let node = Node::start().await;
        let tenant = Keys::generate();
        let writer = Keys::generate();
        let aux = Keys::generate();
        let alias = random_alias();
        let listed = registration_naming(
            &tenant,
            &alias,
            &writer,
            &aux,
            now() - 60,
            &[OWN_SERVER, PEER_SERVER],
        );
        accepted(node.send(&listed).await, "a registration naming both nodes");

        let want = format!("invalid: {VANISH_TARGETS_MESSAGE}");
        let held = node.svc().sync_rejected();
        let cases: [(&str, &[&str]); 5] = [
            ("this node alone", &["wss://localhost:7334"]),
            ("the peer alone", &["wss://peer.example"]),
            (
                "this node and a relay of no node",
                &["ws://localhost:7334", "wss://elsewhere.example"],
            ),
            ("a relay of no node", &["wss://elsewhere.example"]),
            ("no relay at all", &[]),
        ];
        for (what, relays) in cases {
            let request = vanish_naming(&tenant, relays, now());
            assert_eq!(
                guard_refusal(guard(node.svc(), &request).await, what),
                want,
                "{what}"
            );
            assert_eq!(refusal(node.send(&request).await, what), want, "{what}");
            guard_refusal(admit(node.svc(), &request, true).await, what);
            assert!(held.contains(&request.id), "{what}: kept by id");
        }
        assert!(node.live(&alias).await && node.claimed(&writer));

        // Both nodes, each in a spelling upstream reads as that node.
        let both = vanish_naming(
            &tenant,
            &["ws://localhost:7334", "wss://peer.example/"],
            now(),
        );
        assert!(guard(node.svc(), &both).await.is_none());
        accepted(node.send(&both).await, "a vanish naming both nodes");
        assert!(!node.live(&alias).await && !node.stored(listed.id).await);
        assert!(!node.claimed(&writer) && !node.claimed(&aux));

        // ALL_RELAYS closes another account of the same pair.
        let other = Keys::generate();
        let other_alias = random_alias();
        let other_listed = registration_naming(
            &other,
            &other_alias,
            &Keys::generate(),
            &Keys::generate(),
            now() - 60,
            &[OWN_SERVER, PEER_SERVER],
        );
        accepted(node.send(&other_listed).await, "another registration");
        let request = vanish(&other);
        assert!(guard(node.svc(), &request).await.is_none());
        accepted(node.send(&request).await, "a vanish of all relays");
        assert!(!node.live(&other_alias).await);

        // An account whose registrations name this node alone names it.
        let single = Keys::generate();
        let single_alias = random_alias();
        let single_listed = registration(
            &single,
            &single_alias,
            &Keys::generate(),
            &Keys::generate(),
            now() - 60,
        );
        accepted(
            node.send(&single_listed).await,
            "a registration of one node",
        );
        let request = vanish_naming(&single, &["wss://localhost:7334"], now());
        assert!(guard(node.svc(), &request).await.is_none());
        accepted(node.send(&request).await, "a vanish naming this node");
        assert!(!node.live(&single_alias).await);

        // A key that holds no registration here: upstream's.
        let request = vanish_naming(&Keys::generate(), &["wss://localhost:7334"], now());
        assert!(guard(node.svc(), &request).await.is_none());
        accepted(
            node.send(&request).await,
            "a stranger's vanish of this node",
        );
    }

    /// The configured sync peers are nodes of every account's pair, so an
    /// account whose registrations list this node alone names the peer as
    /// well: a node knows the other's own address only from its peer list.
    /// Fails if the guard stops passing the peers.
    #[tokio::test]
    async fn a_configured_peer_is_a_node_of_every_accounts_pair() {
        let node = Node::start_configured(|config| {
            config.private_sync_peer_urls = Some("wss://peer.example".to_string());
        })
        .await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let alone = vanish_naming(&repo.tenant, &["ws://localhost:7334"], now());
        assert_eq!(
            guard_refusal(guard(node.svc(), &alone).await, "this node alone"),
            format!("invalid: {VANISH_TARGETS_MESSAGE}")
        );
        let both = vanish_naming(
            &repo.tenant,
            &["ws://localhost:7334", "wss://peer.example"],
            now(),
        );
        assert!(guard(node.svc(), &both).await.is_none());
        accepted(node.send(&both).await, "a vanish naming the peer too");
        assert!(!node.live(&repo.alias).await && !node.claimed(&repo.writer));
    }

    /// The two nodes of a pair ask the same of an account's vanish, however
    /// a registration spells either of them: each asks for itself by its own
    /// address, for the other by its peer key, and for every `server` value
    /// as written, those naming itself included. Before, each node passed
    /// over the values it took for itself, which it reads more loosely than
    /// the other node reads them (a port or a path its own address leaves
    /// out), so with `https://a.example:8443` listed the first vanish below
    /// was taken by `a.example` and refused by `b.example`.
    #[test]
    fn both_nodes_of_a_pair_judge_a_vanish_alike() {
        let keys = Keys::generate();
        let a_peers = HashSet::from(["wss://b.example".to_string()]);
        let b_peers = HashSet::from(["wss://a.example".to_string()]);
        let registrations: [&[&str]; 3] = [
            &["https://a.example", "https://b.example"],
            &["https://a.example:8443", "https://b.example"],
            &["https://a.example/x", "https://b.example."],
        ];
        let vanishes: [&[&str]; 5] = [
            &["wss://a.example", "wss://b.example"],
            &["wss://a.example:8443", "wss://b.example"],
            &["wss://a.example", "wss://a.example:8443", "wss://b.example"],
            &["wss://a.example", "wss://a.example/x", "wss://b.example"],
            &["wss://a.example"],
        ];
        for servers in registrations {
            let servers: Vec<String> = servers.iter().map(|value| value.to_string()).collect();
            for relays in vanishes {
                let request = vanish_naming(&keys, relays, now());
                assert_eq!(
                    vanish_names_every_node(&request, "a.example", &a_peers, &servers),
                    vanish_names_every_node(&request, "b.example", &b_peers, &servers),
                    "{servers:?} {relays:?}"
                );
            }
        }
        let odd = [
            "https://a.example:8443".to_string(),
            "https://b.example".to_string(),
        ];
        let plain = vanish_naming(&keys, vanishes[0], now());
        assert!(!vanish_names_every_node(
            &plain,
            "a.example",
            &a_peers,
            &odd
        ));
        let every_spelling = vanish_naming(&keys, vanishes[2], now());
        assert!(vanish_names_every_node(
            &every_spelling,
            "a.example",
            &a_peers,
            &odd
        ));
    }

    /// A `server` value names its node by host, port and path, so a peer
    /// under a mount path or on another port is named only that way, and a
    /// value that is no ws, wss, http or https URL asks for nothing.
    #[test]
    fn a_server_value_names_its_node_by_host_port_and_path() {
        fn servers(values: &[&str]) -> Vec<String> {
            values.iter().map(|value| value.to_string()).collect()
        }
        let keys = Keys::generate();
        let no_peers = HashSet::new();
        let mounted = servers(&[OWN_SERVER, "https://peer.example:8443/grasp", "ftp://x"]);
        let named = vanish_naming(
            &keys,
            &["ws://localhost:7334", "wss://peer.example:8443/grasp"],
            now(),
        );
        assert!(vanish_names_every_node(
            &named,
            "localhost:7334",
            &no_peers,
            &mounted
        ));
        let bare = vanish_naming(&keys, &["ws://localhost:7334", "wss://peer.example"], now());
        assert!(!vanish_names_every_node(
            &bare,
            "localhost:7334",
            &no_peers,
            &mounted
        ));
        for values in [
            &[OWN_SERVER, "https://peer.example", "ftp://x"][..],
            &[OWN_SERVER, "ftp://x"][..],
        ] {
            assert!(
                vanish_names_every_node(&bare, "localhost:7334", &no_peers, &servers(values)),
                "{values:?}"
            );
        }
    }

    /// The own-node half of the pair rule is upstream's own test, so a
    /// vanish this node takes from an account is one upstream acts on here,
    /// at the root of the domain and under a mount path. Fails when
    /// `relay_url_candidates` drifts from upstream's.
    #[tokio::test]
    async fn the_own_node_test_is_upstreams() {
        let keys = Keys::generate();
        let cases: [&[&str]; 13] = [
            &["ALL_RELAYS"],
            &["wss://localhost:7334"],
            &["ws://localhost:7334"],
            &["wss://localhost:7334/"],
            &["wss://LOCALHOST:7334"],
            &["wss://localhost:7335"],
            &["wss://localhost"],
            &["wss://localhost:7334/base"],
            &["wss://localhost:7334/grasp"],
            &["wss://localhost:7334/grasp/"],
            &["ws://localhost:7334/grasp"],
            &["wss://localhost:7334/other"],
            &[],
        ];
        for base_path in ["/", "/grasp"] {
            let node = Node::start_configured(|config| {
                config.base_path = base_path.to_string();
            })
            .await;
            let own = &node.svc().cfg.service_address;
            for relays in cases {
                let request = vanish_naming(&keys, relays, now());
                assert_eq!(
                    vanish_names_every_node(&request, own, &HashSet::new(), &[]),
                    node.runtime.deletion.vanish_targets_this_relay(&request),
                    "{base_path} {relays:?}"
                );
            }
        }
    }

    /// A key's vanish is held to an account's rules only while the key holds
    /// a live registration here: a record that is not tombstoned and whose
    /// event is still stored. A record whose event is gone, as an `e`-path
    /// deletion before merge request 15b could leave one, and a tombstoned
    /// record whose event is stored, both written here to the stores
    /// directly, leave the key's vanish to upstream. Fails if either
    /// condition of `live_registration_servers` goes.
    #[tokio::test]
    async fn only_a_live_registration_makes_a_vanish_an_accounts() {
        let node = Node::start().await;
        let record =
            |account: &Keys, tombstoned_at: Option<u64>| crate::grasp_p::meta::RegistrationRecord {
                tenant_hex: account.public_key().to_hex(),
                event_id: "00".repeat(32),
                created_at: now() - 60,
                w_keys: vec![],
                aux_keys: vec![],
                relays: vec![],
                servers: vec![OWN_SERVER.to_string()],
                quota_class: None,
                registered_at: now() - 60,
                tombstoned_at,
                first_created_at: None,
                first_event_id: None,
            };
        let without_event = Keys::generate();
        let without_event_alias = random_alias();
        let tombstoned = Keys::generate();
        let tombstoned_alias = random_alias();
        node.store(&registration(
            &tombstoned,
            &tombstoned_alias,
            &Keys::generate(),
            &Keys::generate(),
            now() - 60,
        ))
        .await;
        let seats = [
            (&without_event, &without_event_alias, None),
            (&tombstoned, &tombstoned_alias, Some(now())),
        ];
        node.svc()
            .meta
            .with_write(|meta, txn| {
                for (account, alias, tombstoned_at) in seats {
                    let aliases = vec![alias.clone()];
                    meta.put_registration(txn, alias, &record(account, tombstoned_at))?;
                    meta.put_tenant_aliases(txn, &account.public_key().to_hex(), &aliases)?;
                }
                Ok(())
            })
            .expect("write the records");
        for (what, account) in [
            ("a record whose event is gone", &without_event),
            ("a tombstoned record", &tombstoned),
        ] {
            let request = vanish_naming(account, &["wss://elsewhere.example"], now());
            assert!(guard(node.svc(), &request).await.is_none(), "{what}");
        }
    }

    /// When a request with neither mark names several stored targets the
    /// guard refuses for different reasons, the answer is the lowest-ranked
    /// one whatever order the store returns them in: GRASP-P state, then
    /// another account's registration, then an own registration named by id
    /// alone. The targets are dated so that the store's order, newest or
    /// oldest first, starts with another answer, and the tags come in both
    /// orders. Fails if the ranking goes.
    #[tokio::test]
    async fn the_refusal_does_not_depend_on_store_order() {
        let node = Node::start().await;
        let (repo, root, _wrap) = repo_with_history(&node).await;
        let newest = registration(
            &Keys::generate(),
            &random_alias(),
            &Keys::generate(),
            &Keys::generate(),
            now(),
        );
        accepted(node.send(&newest).await, "another account's registration");
        assert!(
            repo.registration.created_at < root.created_at && root.created_at < newest.created_at
        );
        let want = format!("restricted: {SERVICE_EVENT_MESSAGE}");
        let ids = [repo.registration.id, root.id, newest.id];
        for order in [ids, [ids[2], ids[1], ids[0]]] {
            let request = deletion(
                &repo.tenant,
                order.into_iter().map(Tag::event).collect(),
                now(),
            );
            assert_eq!(
                guard_refusal(guard(node.svc(), &request).await, "three targets"),
                want
            );
        }
    }

    /// A vanish dated before an account's registrations frees every claim
    /// of the account (decision D15-7). Upstream's vanish removes every
    /// event of its signer whatever its date (pinned by the canary below),
    /// so a claim kept for a registration dated after the vanish would
    /// outlive its event and wedge the alias and the keys. Another account
    /// may take them; the vanished key stays refused. Fails with the claim
    /// hook's old cutoff at the vanish's date.
    #[tokio::test]
    async fn a_vanish_dated_before_a_registration_frees_every_claim() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let stale = vanish_naming(&repo.tenant, &["ALL_RELAYS"], now() - 3600);
        assert!(guard(node.svc(), &stale).await.is_none());
        accepted(
            node.send(&stale).await,
            "a vanish dated before the registration",
        );
        assert!(
            !node.stored(repo.registration.id).await,
            "upstream removed the registration dated after the vanish"
        );
        assert!(!node.live(&repo.alias).await);
        assert!(
            !node.claimed(&repo.writer) && !node.claimed(&repo.aux),
            "every claim of the account is freed"
        );

        let other = Keys::generate();
        let taken = registration(&other, &repo.alias, &repo.writer, &repo.aux, now());
        accepted(
            node.send(&taken).await,
            "another account's registration of the alias and the keys",
        );
        assert!(node.live(&repo.alias).await && node.claimed(&repo.writer));
        let again = registration(
            &repo.tenant,
            &random_alias(),
            &Keys::generate(),
            &Keys::generate(),
            now(),
        );
        assert_eq!(
            refusal(node.send(&again).await, "the vanished key's registration"),
            "invalid: this pubkey has requested to vanish"
        );
    }

    /// Canary for decision D15-7. Upstream's vanish removes every stored
    /// event of its signer with no date bound, and then refuses all its
    /// later events, though NIP-62 bounds the removal by the vanish's
    /// `created_at`. The claim hook frees every claim of a vanished account
    /// on that ground. If this fails because upstream now keeps events
    /// dated after the vanish, give `free_claims_for_vanished_author` its
    /// cutoff back (the vanish's `created_at`), or a vanished account's
    /// newer registrations stay stored with their claims gone.
    #[tokio::test]
    async fn upstream_vanish_removes_events_of_every_date() {
        let node = Node::start_with(false, true).await;
        let keys = Keys::generate();
        let later = EventBuilder::new(Kind::TextNote, "dated after the vanish")
            .custom_created_at(Timestamp::from_secs(now() - 60))
            .finalize(&keys)
            .expect("sign note");
        node.store(&later).await;
        let stale = vanish_naming(&keys, &["ALL_RELAYS"], now() - 3600);
        accepted(node.send(&stale).await, "a vanish dated before the note");
        assert!(
            !node.stored(later.id).await,
            "upstream removed an event dated after the vanish"
        );
        assert_eq!(
            refusal(node.send(&note(&keys)).await, "a later note"),
            "invalid: this pubkey has requested to vanish"
        );
    }

    /// A registration named by event id alone stays, however the request got
    /// past the guard: handed here to upstream's deletion handling directly,
    /// as a registration stored between the guard's lookup and upstream's
    /// delete would let the account's request with neither mark through, it
    /// removes nothing, and the claim hook frees nothing for it, so the store
    /// and the claims agree. The account signs it, so upstream's own authorship
    /// check passes it. Fails without the removal exemption for
    /// registrations, and with the claim hook's old event-id branch. With
    /// GRASP-P off, upstream's `e` path removes the event as before.
    #[tokio::test]
    async fn upstream_removes_no_registration_named_by_id_alone() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        // No k tag: the shape the guard passes to upstream when the edition
        // is not stored yet at its lookup.
        let by_id = deletion(&repo.tenant, vec![Tag::event(repo.registration.id)], now());
        accepted(
            node.runtime.deletion.handle_nip09(&by_id).await,
            "upstream's deletion alone",
        );
        node.svc().free_claims_for_deleted_registrations(&by_id);
        assert!(node.stored(repo.registration.id).await && node.live(&repo.alias).await);
        assert!(node.claimed(&repo.writer) && node.claimed(&repo.aux));

        let off = Node::start_with(false, true).await;
        off.store(&repo.registration).await;
        accepted(
            off.runtime.deletion.handle_nip09(&by_id).await,
            "upstream's deletion with GRASP-P off",
        );
        assert!(!off.stored(repo.registration.id).await);
    }

    /// Kinds other than 5 and 62 are not the guard's.
    #[tokio::test]
    async fn other_kinds_are_not_judged() {
        let node = Node::start().await;
        let stranger = Keys::generate();
        for event in [note(&stranger), wrap(&stranger)] {
            assert!(guard(node.svc(), &event).await.is_none());
        }
    }
}
