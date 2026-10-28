//! Who may delete what on a GRASP-P node.
//!
//! Only the account key, the key that signs a repository's registration
//! (kind 30640), deletes a private repository's data from the server, and
//! only the whole repository, through that registration (decision D6).
//! Members cannot. The
//! server cannot tell members apart behind a shared key (every member of a
//! repository holds its aux key), so a right to delete for one member would
//! be a right for every member, the read-only and the removed ones included,
//! to erase everyone's history and to block the shared key for good.
//!
//! What the account key may send:
//!
//! - a kind 5 naming the coordinate of its own registration,
//!   `["a", "30640:<account>:<alias>"]`, with `["k", "30640"]` (the tag the
//!   peer's sync filter selects on, so the pair sees the same deletion) and
//!   dated no further ahead than [`super::MAX_FUTURE_SKEW_SECS`] (a
//!   coordinate deletion covers every edition dated before it, so a date
//!   far ahead would refuse the account's own later registrations). It may
//!   name the registration's event id beside the coordinate, never instead
//!   of it: an event id names one edition, and the two nodes of a pair can
//!   hold different editions for a while;
//! - a NIP-62 vanish, which closes the account, from a key that is no
//!   repository's write or aux key and has signed no stored state root or
//!   stream wrap. Upstream's vanish removes every event its signer signed,
//!   so from any other key it would remove a repository's history.
//!
//! Four places carry the rule:
//!
//! - [`guard`], which admission calls first for every kind 5 and kind 62. A
//!   key that is a write or aux key of a registration here may send nothing
//!   but a kind 5 naming 30640 coordinates under its own key (an offboard
//!   request), with no `e` target but a stored registration it names that
//!   way. No request may name a stored state root or stream wrap, any by a
//!   coordinate of their kinds, another account's registration, or a stored
//!   registration by event id alone. An id this node does not hold cannot be
//!   judged here: for a state root or a wrap the two exemptions below make
//!   the request inert. Everything else goes on to upstream, which handles
//!   it exactly as on a node without GRASP-P: the same process serves
//!   public repositories (decision D1).
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
//!   upstream's delete, say.
//!
//! A request that passes reaches upstream's NIP-09 or NIP-62 handling and
//! the existing hooks that free a deleted registration's claims. A request
//! that arrives by sync passes the same write policy, so both nodes of a
//! pair judge it alike.

use std::collections::HashSet;

use nostr::prelude::{Event, EventId, Filter, Kind};
use nostr_sdk::local_relay::WritePolicyResult;

use super::{PrivateService, KIND_REGISTRATION, KIND_STATE_ROOT};
use crate::nostr::policy::{reject_error, reject_invalid, reject_restricted};

/// The most `e` and `a` targets a deletion request may carry. Upstream
/// refuses more with the same words; the guard counts first because every
/// `e` target costs it a lookup, and it must not depend on upstream keeping
/// its own limit.
pub(crate) const MAX_TARGET_TAGS: usize = 2048;

// The refusals. None contains the word "unregistered": the client treats
// any message with it as the case where widening its registration helps,
// and no registration change makes one of these requests acceptable.

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

/// Whether upstream's deletion paths keep a stored event of `kind` on a
/// GRASP-P node, whatever request reached them: state roots and stream
/// wraps, which go only with their registration.
pub(crate) fn removal_exempt(kind: u16) -> bool {
    is_service_kind(kind)
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
    if kind_text != "30640" {
        return Coordinate::Refused(reject_invalid(REGISTRATION_COORDINATE_MESSAGE));
    }
    Coordinate::OwnRegistration(alias)
}

/// Whether `event` carries the tag `[name, value, ...]`.
fn has_tag_value(event: &Event, name: &str, value: &str) -> bool {
    event.tags.iter().any(|tag| {
        let v = tag.as_slice();
        v.len() >= 2 && v[0] == name && v[1] == value
    })
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

/// Kind 5. Cheap checks on the tags first, then the meta store, then one
/// lookup of every `e` target.
async fn judge_deletion(svc: &PrivateService, event: &Event) -> Option<WritePolicyResult> {
    let signer_hex = event.pubkey.to_hex();
    let mut own_aliases: HashSet<&str> = HashSet::new();
    let mut ids: HashSet<EventId> = HashSet::new();
    let mut other_coordinates = false;
    for tag in event.tags.iter() {
        let v = tag.as_slice();
        if v.len() < 2 {
            continue;
        }
        match v[0].as_str() {
            // Only the ids upstream would act on.
            "e" => ids.extend(EventId::from_hex(&v[1]).ok()),
            "a" => match classify_coordinate(&v[1], &signer_hex) {
                Coordinate::OwnRegistration(alias) => {
                    own_aliases.insert(alias);
                }
                Coordinate::Refused(refusal) => return Some(refusal),
                Coordinate::Other => other_coordinates = true,
            },
            _ => {}
        }
    }

    // A member key may send an offboard request and nothing else: what any
    // other request names may simply not have reached this node yet.
    let member = match holds_key_claim(svc, &signer_hex) {
        Ok(member) => member,
        Err(error) => return Some(meta_failure(error)),
    };
    if own_aliases.is_empty() {
        // A request that says it deletes registrations but names none by
        // its coordinate; the peer's sync filter would carry it.
        if has_tag_value(event, "k", "30640") {
            return Some(reject_restricted(REGISTRATION_BY_ID_MESSAGE));
        }
        if member {
            return Some(reject_restricted(MEMBER_KEY_MESSAGE));
        }
    } else {
        if !has_tag_value(event, "k", "30640") {
            return Some(reject_invalid(MISSING_K_MESSAGE));
        }
        if let Some(refusal) = super::check_not_future_dated(event) {
            return Some(refusal);
        }
        if member && other_coordinates {
            return Some(reject_restricted(MEMBER_KEY_MESSAGE));
        }
    }

    if ids.is_empty() {
        return None;
    }
    // A target this node does not hold cannot be judged here; if it is a
    // state root or a stream wrap, the exemptions make the request inert
    // for it. A member key gets no such benefit of the doubt.
    let wanted = ids.len();
    let stored = match svc.database.query(Filter::new().ids(ids)).await {
        Ok(stored) => stored,
        Err(error) => return Some(relay_store_failure(error)),
    };
    if member && stored.len() < wanted {
        return Some(reject_restricted(MEMBER_KEY_MESSAGE));
    }
    for target in &stored {
        let kind = target.kind.as_u16();
        if is_service_kind(kind) {
            return Some(reject_restricted(SERVICE_EVENT_MESSAGE));
        }
        if member && kind != KIND_REGISTRATION {
            return Some(reject_restricted(MEMBER_KEY_MESSAGE));
        }
        if kind == KIND_REGISTRATION {
            if target.pubkey != event.pubkey {
                return Some(reject_restricted(FOREIGN_REGISTRATION_MESSAGE));
            }
            let named = super::admission::d_tag(target)
                .is_some_and(|alias| own_aliases.contains(alias.as_str()));
            if !named {
                return Some(reject_restricted(REGISTRATION_BY_ID_MESSAGE));
            }
        }
    }
    None
}

/// Kind 62. Upstream removes every stored event of the signer and then
/// refuses all its later events. A write or aux key may not vanish at all
/// (its history may still be on its way here), and no key may vanish while
/// state roots or stream wraps it signed are stored: a wrap names no
/// repository, so there is no telling whose history it is.
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
        Ok(stored) if !stored.is_empty() => Some(reject_restricted(SIGNED_HISTORY_VANISH_MESSAGE)),
        Ok(_) => None,
        Err(error) => Some(relay_store_failure(error)),
    }
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
            let dir = tempfile::tempdir().expect("tempdir");
            let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
            let mut config = crate::config::Config::for_testing();
            config.git_data_path = path("git");
            config.relay_data_path = path("relay");
            config.private_repos_enable = grasp_p;
            config.private_accept_legacy_wrap_kind = accept_legacy;
            config.private_meta_data_path = Some(path("meta"));
            config.private_blob_data_path = Some(path("blobs"));
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
        EventBuilder::new(Kind::Custom(KIND_REGISTRATION), "")
            .tags(vec![
                Tag::identifier(alias),
                Tag::custom("relays", vec!["ws://localhost:7334".to_string()]),
                Tag::custom("server", vec!["http://localhost:7334".to_string()]),
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
        EventBuilder::new(Kind::RequestToVanish, "")
            .tags(vec![Tag::custom("relay", vec!["ALL_RELAYS".to_string()])])
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
        for kind in [
            KIND_STATE_ROOT,
            KIND_STREAM_WRAP,
            KIND_WRAP,
            KIND_EPHEMERAL_STREAM_WRAP,
            KIND_EPHEMERAL_WRAP,
        ] {
            assert!(deletion_gate_exempt(node.svc(), kind), "kind {kind}");
            assert!(removal_exempt(kind) && cascade_exempt(kind), "kind {kind}");
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
            assert!(!removal_exempt(kind), "kind {kind}");
        }
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
    /// coordinate of another kind.
    #[tokio::test]
    async fn a_member_key_names_nothing_beside_its_own_registration_coordinate() {
        let node = Node::start().await;
        let (repo, _root, _wrap) = repo_with_history(&node).await;
        let writer_hex = repo.writer.public_key().to_hex();
        let own_note = note(&repo.writer);
        node.store(&own_note).await;
        let member = format!("restricted: {MEMBER_KEY_MESSAGE}");
        for (what, beside) in [
            (
                "an id this node does not hold",
                Tag::event(EventId::from_byte_array([9; 32])),
            ),
            ("its own public note", Tag::event(own_note.id)),
            (
                "a public repository",
                a(format!("30617:{writer_hex}:a-public-repo")),
            ),
        ] {
            let request = deletion(
                &repo.writer,
                vec![a(format!("30640:{writer_hex}:x")), k("30640"), beside],
                now(),
            );
            assert_eq!(
                guard_refusal(guard(node.svc(), &request).await, what),
                member,
                "{what}"
            );
            assert_eq!(refusal(node.send(&request).await, what), member, "{what}");
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
    /// with the k tag and a date within the skew; the event id may ride
    /// along. Every other shape of a deletion of a registration is refused,
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
                format!("restricted: {SERVICE_EVENT_MESSAGE}"),
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

        let request = deletion(
            &repo.tenant,
            vec![a(coordinate), Tag::event(repo.registration.id), k("30640")],
            now(),
        );
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
    /// a stranger by coordinate, not another account by event id.
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
        let by_id_from_another_account = deletion(
            &other.tenant,
            vec![
                a(registration_coordinate(&other)),
                Tag::event(repo.registration.id),
                k("30640"),
            ],
            now(),
        );
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

    /// An account's own registration named by event id is refused unless the
    /// request also names that registration's coordinate: without the k tag
    /// too, and beside the coordinate of another of its repositories.
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
        for (what, request) in [
            (
                "its id alone, without the k tag",
                deletion(&repo.tenant, vec![Tag::event(repo.registration.id)], now()),
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
            ),
        ] {
            assert_eq!(
                guard_refusal(guard(node.svc(), &request).await, what),
                by_id,
                "{what}"
            );
            assert_eq!(refusal(node.send(&request).await, what), by_id, "{what}");
        }
        assert!(node.live(&repo.alias).await && node.live(&second_alias).await);
    }

    /// Requests that name no GRASP-P event and come from no GRASP-P member
    /// key are upstream's, exactly as on a node without GRASP-P: a
    /// stranger's deletion of its own note, of ids nobody holds and of a
    /// public repository, a stranger's vanish, and an account deleting its
    /// own public note.
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
