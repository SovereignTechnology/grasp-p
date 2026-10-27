//! GRASP-P admission arms for `Nip34WritePolicy::admit_event`.
//!
//! The write policy calls [`admit`] only when the private-repo service is
//! installed (`NGIT_GRASP_P_REPOS_ENABLE=true`), after its blacklist and
//! deletion gates. Which stream-wrap kinds route here is decided in one place
//! (`PrivateService::accepts_*_stream_wrap_kind`), so the dual-accept window
//! (3359 + legacy 1059) can never diverge from the sync filters or the NIP-11
//! advert; its complement (`rejects_retired_wrap_kind`) refuses the legacy
//! kinds outright once the window closes, so they are never handed to the
//! weaker public related-event path.

use nostr_sdk::local_relay::WritePolicyResult;
use nostr_sdk::prelude::Event;

use super::registration::REPLACE_CADENCE_REJECT_MESSAGE;
use super::PrivateService;
use crate::nostr::policy::reject_restricted;

// -----------------------------------------------------------------------------
// Rejection messages the out-of-order hold depends on
// -----------------------------------------------------------------------------
//
// Each is written once, here, and used both where the rejection is produced
// and where it is classified ([`is_dependency_rejection`]). The sync path only
// has the message to go on, so a rejection reworded in one place and not the
// other would silently stop being held; one constant makes that impossible.
// Clients match on some of these words too (any "unregistered" message is the
// case a client may widen its registration for), so they are wire text.

/// Every GRASP-P kind: the serialized event is larger than
/// `NGIT_GRASP_P_MAX_EVENT_BYTES`. Never held.
pub(crate) const OVERSIZE_REJECT_MESSAGE: &str = "event exceeds private repo size limit";

/// 30641: the alias has no live registration on this node (none yet, or its
/// 30640 is gone from the relay store).
pub(crate) const STATE_ROOT_UNREGISTERED_ALIAS: &str = "unregistered alias";

/// 30641: the `a` tag names a tenant other than the one holding the alias
/// here. The registration this state root was written under may simply not
/// have won the alias on this node yet.
pub(crate) const STATE_ROOT_COORDINATE_MISMATCH: &str =
    "state root a tag does not match the live registration";

/// 30641: the author is not a write key of the live registration. The
/// edition that adds the key (a rotation) may not have arrived yet.
pub(crate) const STATE_ROOT_AUTHOR_NOT_WRITE_KEY: &str =
    "event author is not a registered write key for this alias";

/// 30641: the registration changed between the liveness check and the write.
pub(crate) const STATE_ROOT_REGISTRATION_CHANGED: &str = "alias registration changed; retry";

/// Stream wraps: the outer author is not a key of any live registration.
pub(crate) const WRAP_UNREGISTERED_KEY: &str = "unregistered key";

/// Stream wraps: the registration changed between the liveness check and
/// the quota charge.
pub(crate) const WRAP_REGISTRATION_CHANGED: &str = "registration changed; retry";

/// The kinds whose rejections the hold knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldKind {
    /// Kind 30640.
    Registration,
    /// Kind 30641.
    StateRoot,
    /// A stored stream wrap (3359, and 1059 while the node accepts it).
    /// Ephemeral wraps are never stored and so never held.
    StreamWrap,
}

/// Which hold bucket `kind` belongs to, if any.
pub(crate) fn held_kind(kind: u16, accept_legacy: bool) -> Option<HeldKind> {
    if kind == super::KIND_REGISTRATION {
        Some(HeldKind::Registration)
    } else if kind == super::KIND_STATE_ROOT {
        Some(HeldKind::StateRoot)
    } else if super::is_stream_wrap_kind(kind, accept_legacy) {
        Some(HeldKind::StreamWrap)
    } else {
        None
    }
}

/// Is `message` a rejection that an event arriving LATER can turn into an
/// acceptance of this same event, so that keeping the whole event is worth
/// its memory?
///
/// For a 30641 and a stream wrap that later event is a registration: the
/// first one for the alias or key, a newer edition that adds the key, or the
/// one that wins the alias. For a 30640 it is time: the replacement bucket
/// refilling. Everything else is decided by the event itself (shape, size,
/// date), by the node's ledger (quota) or by a fault (store errors), and a
/// registration arriving changes none of it.
///
/// The match is on the whole message. Every message listed is a fixed
/// string; the rejections built with `format!` (shape errors that carry a
/// number, the proof-of-work demand) are all on the other side.
pub(crate) fn is_dependency_rejection(kind: HeldKind, message: &str) -> bool {
    match kind {
        HeldKind::Registration => message == REPLACE_CADENCE_REJECT_MESSAGE,
        HeldKind::StateRoot => [
            STATE_ROOT_UNREGISTERED_ALIAS,
            STATE_ROOT_COORDINATE_MISMATCH,
            STATE_ROOT_AUTHOR_NOT_WRITE_KEY,
            STATE_ROOT_REGISTRATION_CHANGED,
        ]
        .contains(&message),
        HeldKind::StreamWrap => {
            [WRAP_UNREGISTERED_KEY, WRAP_REGISTRATION_CHANGED].contains(&message)
        }
    }
}

/// Hand a client's rejection to the hold's decision point and pass the
/// result through. Synced rejections are noted by the sync manager's own
/// hook instead, which sees them all, so noting them here too would count
/// each one twice.
fn noted(
    service: &PrivateService,
    event: &Event,
    is_synced: bool,
    result: WritePolicyResult,
) -> WritePolicyResult {
    if !is_synced {
        // Only a refusal: an answer that reports success with a message
        // (the sync path filters those out too) is not a rejection.
        if let WritePolicyResult::Reject {
            ref message,
            status: false,
            ..
        } = result
        {
            service.note_rejected(event, message, false);
        }
    }
    result
}

/// Route a private-repo kind. `None` means the event is not one of GRASP-P's
/// kinds and the caller continues with its own dispatch.
///
/// Synced events (`is_synced`, loopback:0) get identical admission: a synced
/// 30640/30641/stream wrap must apply under the same rules. They only bypass
/// the per-write-key token bucket, which is a node-local DoS knob.
pub async fn admit(
    service: &PrivateService,
    event: &Event,
    is_synced: bool,
) -> Option<WritePolicyResult> {
    let kind = event.kind.as_u16();
    let stored_wrap = service.accepts_stream_wrap_kind(kind);
    let ephemeral_wrap = service.accepts_ephemeral_stream_wrap_kind(kind);

    // Size first, for every kind this subsystem admits and on both paths:
    // before the rate bucket, before any key or registration lookup, and
    // before anything could put the event in the hold. A synced event is
    // otherwise bounded only by the transport's message limit, far above
    // this one, and an event too large to ever be accepted must cost the
    // node nothing but this check.
    if service.admits_kind(kind) && event.as_json().len() as u64 > service.cfg.max_event_bytes {
        crate::metrics::record_private_event_rejected(kind);
        return Some(noted(
            service,
            event,
            is_synced,
            reject_restricted(OVERSIZE_REJECT_MESSAGE),
        ));
    }

    if kind == super::KIND_REGISTRATION {
        // FS-2 (review L3-F4): a cadence-rejected same-tenant replacement is
        // held AND rejected to the client. The NIP-20 message still says
        // retry-later, but convergence must not depend on the client actually
        // retrying: the sync timer re-offers the held event after the bucket
        // refills.
        let result = service.handle_registration(event).await;
        return Some(noted(service, event, is_synced, result));
    }

    if kind == super::KIND_STATE_ROOT {
        // Phase-4b A1: per-write-key token bucket, client submissions only.
        // A rate-limited 30641 is NOT added to the out-of-order hold: the
        // client retries.
        if !is_synced && !service.client_write_allowed(&event.pubkey.to_hex()) {
            crate::metrics::record_private_rate_limited("state_root");
            crate::metrics::record_private_event_rejected(super::KIND_STATE_ROOT);
            return Some(reject_restricted("rate-limited; retry later"));
        }
        // Phase 2 (design 1.4): a 30641 can be pushed BEFORE its authorizing
        // 30640 is known here. A rejection the registration can cure is held
        // keyed by target alias so the 30640 reprocess hook can resurrect
        // it; any other rejection is not held.
        let result = service.handle_state_root(event).await;
        return Some(noted(service, event, is_synced, result));
    }

    if stored_wrap {
        // Phase-4b A1: charged wraps and never-charged spam both spend one
        // token; a rate-limited wrap is rejected outright (no hold).
        if !is_synced && !service.client_write_allowed(&event.pubkey.to_hex()) {
            crate::metrics::record_private_rate_limited("wrap");
            crate::metrics::record_private_event_rejected(kind);
            return Some(reject_restricted("rate-limited; retry later"));
        }
        let result = match service.try_handle_wrap(event, false).await {
            Some(result) => result,
            // Unregistered outer key: REJECT, never the public related-event
            // path. A GRASP-P node admits stream wraps only for outer authors
            // in w∪aux of a live registration. The wrap is still held keyed by
            // its outer author so a later 30640 registering that key
            // reprocesses it (design 1.4, out-of-order sync).
            None => reject_restricted(WRAP_UNREGISTERED_KEY),
        };
        return Some(noted(service, event, is_synced, result));
    }

    if ephemeral_wrap {
        // Ephemeral wraps are never quota-charged, so this bucket is their
        // only cost.
        if !is_synced && !service.client_write_allowed(&event.pubkey.to_hex()) {
            crate::metrics::record_private_rate_limited("ewrap");
            crate::metrics::record_private_event_rejected(kind);
            return Some(reject_restricted("rate-limited; retry later"));
        }
        return Some(match service.try_handle_wrap(event, true).await {
            Some(result) => result,
            // Never stored, so there is no out-of-order hold.
            None => reject_restricted(WRAP_UNREGISTERED_KEY),
        });
    }

    if service.rejects_retired_wrap_kind(kind) {
        // NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND=false retires 1059/21059 on a
        // GRASP-P node: refuse them here rather than let them fall through to
        // the related-event policy, which would store any `a`/`e`-tagged
        // event from any key, uncapped and uncharged. Genuine NIP-59 gift
        // wraps go to inbox relays, never a git node. Nodes with GRASP-P
        // disabled never reach this and keep vanilla 1059 handling.
        crate::metrics::record_private_event_rejected(kind);
        return Some(reject_restricted(
            "legacy stream-wrap kind is not accepted on this node",
        ));
    }

    None
}

/// Phase-4b D3: NIP-56 report intake, observe-then-defer. Logs the event id,
/// the reporter and any sha256-looking tag values (the takedown evidence an
/// operator needs); the content is never logged. Admission then runs through
/// the related-event rules unchanged.
pub fn log_report(event: &Event) {
    let sha256_tags: Vec<String> = event
        .tags
        .iter()
        .flat_map(|tag| tag.clone().to_vec())
        .filter(|v| super::blossom_auth::is_lower_hex_64(v))
        .take(16)
        .collect();
    tracing::info!(
        event_id = %event.id.to_hex(),
        reporter = %event.pubkey.to_hex(),
        sha256_tags = ?sha256_tags,
        "NIP-56 report event received"
    );
    crate::metrics::record_private_report_event();
}

/// The first `d` tag value, the alias of a 30640/30641.
pub fn d_tag(event: &Event) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.as_slice();
        if v.len() >= 2 && v[0] == "d" {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grasp_p::{
        KIND_EPHEMERAL_STREAM_WRAP, KIND_EPHEMERAL_WRAP, KIND_REGISTRATION, KIND_STATE_ROOT,
        KIND_STREAM_WRAP, KIND_WRAP,
    };
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

    /// The classification table. A wrong row here loses replicated events
    /// until the next full re-issue (a dependency rejection left out) or
    /// lets rejections that can never be cured take hold memory (anything
    /// else let in), so every message admission can produce for a held kind
    /// is listed on one side or the other.
    #[test]
    fn only_dependency_rejections_are_holdable() {
        use HeldKind::{Registration, StateRoot, StreamWrap};

        // The words on the wire. Clients read them, and the sync path
        // classifies by them, so a change here is a protocol change.
        assert_eq!(STATE_ROOT_UNREGISTERED_ALIAS, "unregistered alias");
        assert_eq!(
            STATE_ROOT_COORDINATE_MISMATCH,
            "state root a tag does not match the live registration"
        );
        assert_eq!(
            STATE_ROOT_AUTHOR_NOT_WRITE_KEY,
            "event author is not a registered write key for this alias"
        );
        assert_eq!(
            STATE_ROOT_REGISTRATION_CHANGED,
            "alias registration changed; retry"
        );
        assert_eq!(WRAP_UNREGISTERED_KEY, "unregistered key");
        assert_eq!(WRAP_REGISTRATION_CHANGED, "registration changed; retry");
        assert_eq!(
            REPLACE_CADENCE_REJECT_MESSAGE,
            "replacement rate-limited; retry later"
        );
        assert_eq!(
            OVERSIZE_REJECT_MESSAGE,
            "event exceeds private repo size limit"
        );

        let holdable = [
            (StateRoot, STATE_ROOT_UNREGISTERED_ALIAS),
            (StateRoot, STATE_ROOT_COORDINATE_MISMATCH),
            (StateRoot, STATE_ROOT_AUTHOR_NOT_WRITE_KEY),
            (StateRoot, STATE_ROOT_REGISTRATION_CHANGED),
            (StreamWrap, WRAP_UNREGISTERED_KEY),
            (StreamWrap, WRAP_REGISTRATION_CHANGED),
            (Registration, REPLACE_CADENCE_REJECT_MESSAGE),
        ];
        for (kind, message) in holdable {
            assert!(
                is_dependency_rejection(kind, message),
                "{kind:?} rejected with {message:?} must be held"
            );
        }

        let not_holdable = [
            // 30641: size, date, shape, ledger, faults, the rate bucket and
            // the gates that run before admission.
            (StateRoot, OVERSIZE_REJECT_MESSAGE),
            (StateRoot, "event created_at is too far in the future"),
            (StateRoot, "state root must carry a d tag"),
            (
                StateRoot,
                "state root d tag must be exactly 32 lowercase hex chars",
            ),
            (
                StateRoot,
                "state root must carry an a tag (30640:<tenant>:<alias>)",
            ),
            (StateRoot, "state root must carry an m (manifest) tag"),
            (StateRoot, "state root must carry exactly one m tag"),
            (StateRoot, "state root references more than 256 blobs"),
            (
                StateRoot,
                "state root references a blob larger than the per-blob limit",
            ),
            (StateRoot, "m/pack tags must be [name, sha256, bytes]"),
            (StateRoot, "m/pack hashes must be 64 lowercase hex chars"),
            (StateRoot, "m/pack sizes must parse as u64"),
            (StateRoot, "quota exceeded"),
            (StateRoot, "private liveness check failed"),
            (StateRoot, "private meta store failure"),
            (StateRoot, "rate-limited; retry later"),
            (StateRoot, "this event is deleted"),
            (StateRoot, "this pubkey has requested to vanish"),
            // Stream wraps.
            (StreamWrap, OVERSIZE_REJECT_MESSAGE),
            (StreamWrap, "event created_at is too far in the future"),
            (StreamWrap, "quota exceeded"),
            (StreamWrap, "private liveness check failed"),
            (StreamWrap, "private meta store failure"),
            (StreamWrap, "rate-limited; retry later"),
            (
                StreamWrap,
                "legacy stream-wrap kind is not accepted on this node",
            ),
            (StreamWrap, "this event is deleted"),
            // 30640: only the cadence rejection is held.
            (Registration, OVERSIZE_REJECT_MESSAGE),
            (Registration, "event created_at is too far in the future"),
            (Registration, "alias already registered"),
            (Registration, "write key already registered"),
            (Registration, "tenant is not on the registration whitelist"),
            (
                Registration,
                "registration requires 20 bits of NIP-13 proof of work",
            ),
            (Registration, "paid registration mode is not available"),
            (Registration, "tenant has reached the alias limit"),
            (Registration, "quota exceeded"),
            (Registration, "private meta store failure"),
            // A message belongs to its own kind only.
            (StateRoot, WRAP_UNREGISTERED_KEY),
            (StateRoot, WRAP_REGISTRATION_CHANGED),
            (StateRoot, REPLACE_CADENCE_REJECT_MESSAGE),
            (StreamWrap, STATE_ROOT_UNREGISTERED_ALIAS),
            (StreamWrap, STATE_ROOT_REGISTRATION_CHANGED),
            (StreamWrap, REPLACE_CADENCE_REJECT_MESSAGE),
            (Registration, STATE_ROOT_UNREGISTERED_ALIAS),
            (Registration, WRAP_UNREGISTERED_KEY),
            // The whole bare message is matched: the classifier is handed
            // the message without its machine-readable prefix.
            (StateRoot, ""),
            (StateRoot, "unregistered"),
            (StateRoot, "unregistered alias; retry"),
            (StateRoot, "restricted: unregistered alias"),
            (StreamWrap, "restricted: unregistered key"),
        ];
        for (kind, message) in not_holdable {
            assert!(
                !is_dependency_rejection(kind, message),
                "{kind:?} rejected with {message:?} must not be held"
            );
        }
    }

    /// Which kinds the hold knows: the stored ones this node admits.
    /// Ephemeral wraps are never stored, and a retired legacy kind is not
    /// GRASP-P's any more.
    #[test]
    fn held_kinds_are_the_stored_private_kinds() {
        for legacy in [true, false] {
            assert_eq!(
                held_kind(KIND_REGISTRATION, legacy),
                Some(HeldKind::Registration)
            );
            assert_eq!(
                held_kind(KIND_STATE_ROOT, legacy),
                Some(HeldKind::StateRoot)
            );
            assert_eq!(
                held_kind(KIND_STREAM_WRAP, legacy),
                Some(HeldKind::StreamWrap)
            );
            for kind in [KIND_EPHEMERAL_STREAM_WRAP, KIND_EPHEMERAL_WRAP, 1, 30618] {
                assert_eq!(held_kind(kind, legacy), None, "kind {kind}");
            }
        }
        assert_eq!(held_kind(KIND_WRAP, true), Some(HeldKind::StreamWrap));
        assert_eq!(held_kind(KIND_WRAP, false), None);
    }

    const TEST_MAX_EVENT_BYTES: u64 = 2048;

    async fn harness() -> (tempfile::TempDir, std::sync::Arc<PrivateService>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::config::Config::for_testing();
        config.private_repos_enable = true;
        config.private_max_event_bytes = TEST_MAX_EVENT_BYTES;
        config.private_meta_data_path =
            Some(dir.path().join("meta").to_string_lossy().into_owned());
        config.private_blob_data_path =
            Some(dir.path().join("blobs").to_string_lossy().into_owned());
        let database: crate::nostr::SharedDatabase =
            std::sync::Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let svc = PrivateService::new(&config, database)
            .await
            .expect("private service");
        (dir, svc)
    }

    /// The rejection message of an admission answer; panics on anything
    /// that is not a refusal.
    fn rejection(result: Option<WritePolicyResult>) -> String {
        match result {
            Some(WritePolicyResult::Reject {
                message,
                status: false,
                ..
            }) => message.into_owned(),
            Some(WritePolicyResult::Reject { .. }) => panic!("answered OK, expected a refusal"),
            Some(WritePolicyResult::Accept) => panic!("accepted, expected a refusal"),
            None => panic!("not routed as a GRASP-P kind"),
        }
    }

    fn wrap(signer: &Keys, kind: u16, content_len: usize) -> Event {
        EventBuilder::new(Kind::Custom(kind), "c".repeat(content_len))
            .finalize(signer)
            .expect("sign")
    }

    /// A shape-valid 30641 for `alias`, padded by `content_len`.
    fn state_root(signer: &Keys, alias: &str, content_len: usize) -> Event {
        let pubkey = signer.public_key().to_hex();
        EventBuilder::new(Kind::Custom(KIND_STATE_ROOT), "c".repeat(content_len))
            .tags(vec![
                Tag::custom("d", vec![alias.to_string()]),
                Tag::custom("a", vec![format!("30640:{pubkey}:{alias}")]),
                Tag::custom("m", vec!["ab".repeat(32), "10".to_string()]),
            ])
            .finalize(signer)
            .expect("sign")
    }

    /// An event over the size limit gets the size answer whatever else is
    /// wrong with it, on both paths, and is never held; the same event
    /// within the limit gets its dependency answer and is held.
    ///
    /// "Before lookup" is visible in the answer: every event here is from a
    /// key and for an alias this node has never seen, and the lookup's
    /// answer to that is "unregistered". Getting the size answer for a
    /// stream wrap means the key was not looked up first.
    #[tokio::test]
    async fn oversize_private_event_is_refused_before_lookup_and_never_held() {
        let (_dir, svc) = harness().await;
        let hold = svc.sync_rejected();
        let stranger = Keys::generate();
        let author = stranger.public_key().to_hex();
        let alias = "ab".repeat(16);
        let over = TEST_MAX_EVENT_BYTES as usize * 2;

        // Every wrap kind, stored and ephemeral.
        for kind in [
            KIND_STREAM_WRAP,
            KIND_WRAP,
            KIND_EPHEMERAL_STREAM_WRAP,
            KIND_EPHEMERAL_WRAP,
        ] {
            let big = wrap(&stranger, kind, over);
            assert!(big.as_json().len() as u64 > TEST_MAX_EVENT_BYTES);
            assert_eq!(
                rejection(admit(&svc, &big, false).await),
                OVERSIZE_REJECT_MESSAGE,
                "kind {kind}"
            );
            assert!(!hold.contains(&big.id), "kind {kind}: nothing is kept");
        }
        assert!(hold
            .take_for_authors(std::slice::from_ref(&author))
            .is_empty());

        // 30641 and 30640.
        let big_root = state_root(&stranger, &alias, over);
        assert_eq!(
            rejection(admit(&svc, &big_root, false).await),
            OVERSIZE_REJECT_MESSAGE
        );
        assert!(!hold.contains(&big_root.id));
        assert!(hold.take_for_alias(&alias).is_empty());
        let big_registration = EventBuilder::new(Kind::Custom(KIND_REGISTRATION), "c".repeat(over))
            .tags(vec![Tag::custom("d", vec![alias.clone()])])
            .finalize(&stranger)
            .expect("sign");
        assert_eq!(
            rejection(admit(&svc, &big_registration, false).await),
            OVERSIZE_REJECT_MESSAGE
        );
        assert!(!hold.contains(&big_registration.id));
        assert_eq!(hold.held_len(), 0);
        assert_eq!(hold.held_bytes(), 0);

        // The sync path: the same answer. Admission keeps nothing for a
        // synced event; the sync hook then remembers the id and no more.
        let synced_wrap = wrap(&stranger, KIND_STREAM_WRAP, over + 1);
        let synced_root = state_root(&stranger, &alias, over + 1);
        for event in [&synced_wrap, &synced_root] {
            let message = rejection(admit(&svc, event, true).await);
            assert_eq!(message, OVERSIZE_REJECT_MESSAGE);
            assert!(!hold.contains(&event.id));
            svc.note_rejected(event, &message, true);
            assert!(hold.contains(&event.id), "the id is skipped");
        }
        assert!(hold
            .take_for_authors(std::slice::from_ref(&author))
            .is_empty());
        assert!(hold.take_for_alias(&alias).is_empty());
        assert_eq!(hold.held_len(), 0);
        assert_eq!(hold.held_bytes(), 0);
        hold.assert_accounting();

        // Within the limit the same sender and alias get the dependency
        // answers, and those are held.
        let small_wrap = wrap(&stranger, KIND_STREAM_WRAP, 16);
        assert_eq!(
            rejection(admit(&svc, &small_wrap, false).await),
            WRAP_UNREGISTERED_KEY
        );
        let small_root = state_root(&stranger, &alias, 16);
        assert_eq!(
            rejection(admit(&svc, &small_root, false).await),
            STATE_ROOT_UNREGISTERED_ALIAS
        );
        assert!(hold.contains(&small_wrap.id) && hold.contains(&small_root.id));
        assert_eq!(hold.held_len(), 2);
        assert_eq!(
            hold.held_bytes(),
            crate::sync::private_index::event_bytes(&small_wrap)
                + crate::sync::private_index::event_bytes(&small_root)
        );
        hold.assert_accounting();

        // An ephemeral wrap within the limit is refused and not held.
        let ephemeral = wrap(&stranger, KIND_EPHEMERAL_STREAM_WRAP, 16);
        assert_eq!(
            rejection(admit(&svc, &ephemeral, false).await),
            WRAP_UNREGISTERED_KEY
        );
        assert!(!hold.contains(&ephemeral.id));

        let wraps = hold.take_for_authors(std::slice::from_ref(&author));
        assert_eq!(wraps.len(), 1);
        assert_eq!(wraps[0].id, small_wrap.id);
        let roots = hold.take_for_alias(&alias);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, small_root.id);
        assert_eq!(hold.held_bytes(), 0);
        hold.assert_accounting();
    }
}
