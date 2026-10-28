//! Nothing attaches to private-repository events.
//!
//! A GRASP-P node also serves public repositories, under upstream's rules
//! and in the same process (decision D1). Upstream stores an event of an
//! unhandled kind when it references any stored event, or any stored event
//! with a matching `d` tag (`RelatedEventPolicy`), and some events with no
//! reference check at all: every kind 10317, and whatever the relay owner
//! signs. So anyone could store plaintext beside a private repository,
//! uncharged and outside GRASP-P's quotas and collection, served to anyone
//! who asks for what tags its registration, its state roots or its wraps:
//! an accusation and a blob key among them.
//!
//! Two rules, both in GRASP-P's admission, which runs before upstream's
//! dispatch:
//!
//! - [`judge`]: an event of a kind GRASP-P does not own is refused when it
//!   references private-repository content: an `a`, `A` or `q` coordinate
//!   whose kind is a GRASP-P kind, judged from the event alone, or an `e`,
//!   `E` or `q` id of a stored GRASP-P event (decision A). Both are read the
//!   way upstream's related-event rule reads them, so no reference that
//!   rule would follow gets past this one. Kinds 5 and 62 are `offboard`'s,
//!   and reports add rules of their own (`reports`).
//! - [`reference_tag_refusal`]: a GRASP-P event carries no reference tag
//!   but a state root's one `a` tag, which names its own registration.
//!   Under upstream's forward rule a stored event vouches for every event
//!   it tags, and upstream's thread-following sync asks relays that are
//!   not peers for what tags the events it follows.
//!
//! Between them no GRASP-P event can anchor an event of another kind, or
//! vouch for one, so upstream's related-event rule needs no seam.

use std::collections::HashSet;

use nostr::prelude::{Event, EventId, Filter, Kind};
use nostr_sdk::local_relay::WritePolicyResult;

use super::{PrivateService, KIND_STATE_ROOT, PRIVATE_EVENT_KINDS};
use crate::nostr::policy::{reject_error, reject_invalid, reject_restricted};

/// The most distinct values an event may carry that each cost a lookup:
/// its `e`, `E` and `q` ids that parse, and for a report its 64-hex values
/// and, beside an `x` tag, its `server` values. An event with more is
/// refused whole, as a deletion request with more than
/// `offboard::MAX_TARGET_TAGS` targets is: judging only the first ones
/// would let a reference placed after them through. A value that does not
/// parse, or comes again, costs nothing and is not counted.
pub(crate) const MAX_REFERENCES: usize = 2048;

// The refusals. None names what was referenced, none contains the word
// "unregistered" (the client widens its registration on any message with
// it, and no registration makes these events acceptable), and none
// contains upstream's "event must reference an accepted repository or
// accepted event", which sync keeps the event for and retries on.

/// An event of another kind references private-repository content.
pub(crate) const REFERENCES_PRIVATE_MESSAGE: &str =
    "events that reference private repositories are not stored on this service";

/// More references than [`MAX_REFERENCES`].
pub(crate) const TOO_MANY_REFERENCES_MESSAGE: &str = "event carries too many references to check";

/// A registration or a stream wrap with a reference tag.
pub(crate) const UNTAGGED_EVENT_MESSAGE: &str =
    "registrations and stream wraps carry no e, E, q, a or A tag";

/// A state root with a reference tag beside its own `a` tag.
pub(crate) const STATE_ROOT_TAGS_MESSAGE: &str =
    "a state root carries one a tag and no e, E, q or A tag";

/// A GRASP-P event with upstream's audit tag.
pub(crate) const AUDIT_TAG_MESSAGE: &str =
    "private repository events cannot carry the t tag grasp-audit-test-event";

/// The `t` value upstream's audit cleanup deletes by, of any kind and past
/// every deletion hook (`src/audit_cleanup.rs`). Its filter compares the
/// first value exactly, and so does this.
const AUDIT_TEST_EVENT_TAG: &str = "grasp-audit-test-event";

/// What an event references, read as upstream's related-event rule reads
/// its tags (`RelatedEventPolicy::extract_reference_tags`): `a`, `A` and
/// `q` values with a colon are coordinates, `e` and `E` values and `q`
/// values without one are event ids.
#[derive(Debug, Default)]
pub(crate) struct References {
    /// Some coordinate has a GRASP-P kind.
    pub(crate) private_coordinate: bool,
    /// The ids that parse, each once.
    pub(crate) ids: HashSet<EventId>,
}

impl References {
    pub(crate) fn read(event: &Event) -> Self {
        let mut references = Self::default();
        for tag in event.tags.iter() {
            let (Some(name), Some(value)) = (tag.as_slice().first(), tag.as_slice().get(1)) else {
                continue;
            };
            match name.as_str() {
                "a" | "A" | "q" if value.contains(':') => {
                    if coordinate_kind(value).is_some_and(super::is_private_event_kind) {
                        references.private_coordinate = true;
                    }
                }
                "e" | "E" | "q" => references.ids.extend(EventId::from_hex(value).ok()),
                _ => {}
            }
        }
        references
    }
}

/// The kind a coordinate names, read as upstream reads it: the text before
/// the first colon as a number, so `030640` and `+30640` are 30640.
/// Upstream also wants a pubkey and an identifier after it before it looks
/// anything up; a GRASP-P kind is refused here without them.
pub(crate) fn coordinate_kind(coordinate: &str) -> Option<u16> {
    coordinate.split_once(':')?.0.parse().ok()
}

/// Whether one of `ids` is a stored GRASP-P event: one query against the
/// store upstream's related-event rule reads. An id this node does not
/// hold yet cannot be judged; that event may still be on its way from the
/// peer.
pub(crate) async fn names_stored_private_event(
    svc: &PrivateService,
    ids: &HashSet<EventId>,
) -> Result<bool, String> {
    if ids.is_empty() {
        return Ok(false);
    }
    let filter = Filter::new()
        .ids(ids.iter().copied())
        .kinds(PRIVATE_EVENT_KINDS.map(Kind::from));
    let stored = svc
        .database
        .query(filter)
        .await
        .map_err(|error| error.to_string())?;
    // The kind is checked again so the answer does not rest on how the
    // store combines an id filter with a kind filter.
    Ok(stored
        .iter()
        .any(|event| super::is_private_event_kind(event.kind.as_u16())))
}

pub(crate) fn relay_store_failure(error: &str) -> WritePolicyResult {
    tracing::warn!(error = %error, "private reference check could not read the relay store");
    reject_error("private reference check failed")
}

/// Judge an event of a kind GRASP-P does not own, other than a deletion
/// request, a vanish and a report. `Some` is the refusal; `None` hands the
/// event to upstream, which decides as on a node without GRASP-P.
pub(crate) async fn judge(svc: &PrivateService, event: &Event) -> Option<WritePolicyResult> {
    let references = References::read(event);
    if references.ids.len() > MAX_REFERENCES {
        return Some(reject_invalid(TOO_MANY_REFERENCES_MESSAGE));
    }
    if !references.private_coordinate {
        match names_stored_private_event(svc, &references.ids).await {
            Ok(true) => {}
            Ok(false) => return None,
            Err(error) => return Some(relay_store_failure(&error)),
        }
    }
    tracing::debug!(
        event_id = %event.id.to_hex(),
        author = %event.pubkey.to_hex(),
        kind = event.kind.as_u16(),
        "Refused an event that references private-repository content"
    );
    Some(reject_restricted(REFERENCES_PRIVATE_MESSAGE))
}

/// Why a GRASP-P event of `kind` is refused for its tags, if it is.
///
/// A registration and a stream wrap carry no `e`, `E`, `q`, `a` or `A` tag,
/// and a state root no `e`, `E`, `q` or `A` tag and one `a` tag at most:
/// the coordinate of its own registration, which the state-root path
/// requires and checks. None carries upstream's audit tag. A tag counts by
/// its name, whatever its values. The client sends none of these.
pub(crate) fn reference_tag_refusal(kind: u16, event: &Event) -> Option<&'static str> {
    let (shape, a_tags_allowed) = if kind == KIND_STATE_ROOT {
        (STATE_ROOT_TAGS_MESSAGE, 1)
    } else {
        (UNTAGGED_EVENT_MESSAGE, 0)
    };
    let mut a_tags = 0;
    for tag in event.tags.iter() {
        let values = tag.as_slice();
        match values.first().map(String::as_str) {
            Some("e" | "E" | "q" | "A") => return Some(shape),
            Some("a") => {
                a_tags += 1;
                if a_tags > a_tags_allowed {
                    return Some(shape);
                }
            }
            Some("t") if values.get(1).map(String::as_str) == Some(AUDIT_TEST_EVENT_TAG) => {
                return Some(AUDIT_TAG_MESSAGE);
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use bitcoin_hashes::sha256;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Tag, Timestamp, WritePolicy};

    use super::*;
    use crate::grasp_p::admission::admit;
    use crate::grasp_p::{
        KIND_EPHEMERAL_STREAM_WRAP, KIND_EPHEMERAL_WRAP, KIND_REGISTRATION, KIND_REPORT,
        KIND_STREAM_WRAP, KIND_WRAP,
    };

    /// A node's write policy and stores, built as the server builds them,
    /// over an in-memory relay database. Nothing listens on a socket.
    pub(crate) struct Node {
        _dir: tempfile::TempDir,
        pub(crate) runtime: crate::nostr::builder::RelayRuntime,
        /// The relay owner's key, which upstream lets publish any kind.
        pub(crate) owner: Keys,
    }

    impl Node {
        /// GRASP-P on, every other setting as the tests' default.
        pub(crate) async fn start() -> Self {
            Self::start_with(|_, _| {}).await
        }

        /// `adjust` sees the configuration, and the node's own directory
        /// for any file it should read, before the node is built.
        pub(crate) async fn start_with(
            adjust: impl FnOnce(&mut crate::config::Config, &Path),
        ) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
            let mut config = crate::config::Config::for_testing();
            config.git_data_path = path("git");
            config.relay_data_path = path("relay");
            config.private_repos_enable = true;
            config.private_meta_data_path = Some(path("meta"));
            config.private_blob_data_path = Some(path("blobs"));
            adjust(&mut config, dir.path());
            let owner = config.relay_owner_keys().expect("owner key");
            let purgatory = Arc::new(crate::purgatory::Purgatory::new(dir.path().join("git")));
            let runtime = crate::nostr::builder::create_relay(
                &config,
                purgatory,
                crate::grasp06::receive::RepoInitLocks::default(),
                None,
            )
            .await
            .expect("relay");
            Self {
                _dir: dir,
                runtime,
                owner,
            }
        }

        pub(crate) fn svc(&self) -> &PrivateService {
            self.runtime.grasp_p.as_deref().expect("GRASP-P is on")
        }

        /// What a client sending `event` is told: the write policy decides,
        /// and an accepted event is stored, as the relay stores it.
        pub(crate) async fn send(&self, event: &Event) -> WritePolicyResult {
            self.send_from(event, "198.51.100.7:40000").await
        }

        /// The same for an event that sync brings (loopback, port 0).
        pub(crate) async fn send_synced(&self, event: &Event) -> WritePolicyResult {
            self.send_from(event, "127.0.0.1:0").await
        }

        async fn send_from(&self, event: &Event, address: &str) -> WritePolicyResult {
            let address: SocketAddr = address.parse().expect("address");
            let result = self.runtime.write_policy.admit_event(event, &address).await;
            if matches!(result, WritePolicyResult::Accept) {
                self.store(event).await;
            }
            result
        }

        /// Put `event` in the relay store without asking the write policy.
        pub(crate) async fn store(&self, event: &Event) {
            self.runtime
                .stores
                .database
                .save_event(event)
                .await
                .expect("store the event");
        }

        pub(crate) async fn stored(&self, id: EventId) -> bool {
            self.runtime
                .stores
                .database
                .event_by_id(&id)
                .await
                .expect("lookup")
                .is_some()
        }
    }

    /// One private repository: its account key, a write key, the shared
    /// aux key, and what the node holds of it.
    pub(crate) struct Repo {
        pub(crate) tenant: Keys,
        pub(crate) writer: Keys,
        pub(crate) aux: Keys,
        pub(crate) alias: String,
        pub(crate) registration: Event,
        pub(crate) root: Event,
        pub(crate) wrap: Event,
        /// The manifest blob the state root declares, so the node holds a
        /// claim for it.
        pub(crate) manifest: String,
    }

    impl Repo {
        pub(crate) fn coordinate(&self) -> String {
            format!("30640:{}:{}", self.tenant.public_key().to_hex(), self.alias)
        }
    }

    pub(crate) fn now() -> u64 {
        Timestamp::now().as_secs()
    }

    /// A fresh 64-character lowercase hex value.
    pub(crate) fn random_hex() -> String {
        Keys::generate().public_key().to_hex()
    }

    fn key_entry(key: &Keys, tenant: &Keys, alias: &str) -> Vec<String> {
        let digest = sha256::Hash::hash(
            super::super::registration::key_pop_input(&tenant.public_key().to_hex(), alias)
                .as_bytes(),
        );
        let sig = key.sign_schnorr(digest.to_byte_array());
        vec![key.public_key().to_hex(), sig.to_string()]
    }

    /// A registration naming this node and every server in `servers`,
    /// with `extra` tags at the end.
    pub(crate) fn registration(
        tenant: &Keys,
        alias: &str,
        writer: &Keys,
        aux: &Keys,
        servers: &[&str],
        extra: Vec<Tag>,
        created_at: u64,
    ) -> Event {
        let mut server_values = vec!["http://localhost:7334".to_string()];
        server_values.extend(servers.iter().map(|server| server.to_string()));
        let mut tags = vec![
            Tag::identifier(alias),
            Tag::custom("relays", vec!["ws://localhost:7334".to_string()]),
            Tag::custom("server", server_values),
            Tag::custom("w", key_entry(writer, tenant, alias)),
            Tag::custom("aux", key_entry(aux, tenant, alias)),
        ];
        tags.extend(extra);
        EventBuilder::new(Kind::Custom(KIND_REGISTRATION), "")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(tenant)
            .expect("sign 30640")
    }

    /// A state root for `alias` declaring `manifest`, with `extra` tags at
    /// the end.
    pub(crate) fn state_root(
        writer: &Keys,
        tenant: &Keys,
        alias: &str,
        manifest: &str,
        extra: Vec<Tag>,
    ) -> Event {
        let mut tags = vec![
            Tag::identifier(alias),
            Tag::custom(
                "a",
                vec![format!("30640:{}:{alias}", tenant.public_key().to_hex())],
            ),
            Tag::custom("m", vec![manifest.to_string(), "10".to_string()]),
        ];
        tags.extend(extra);
        EventBuilder::new(Kind::Custom(KIND_STATE_ROOT), "")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(now() - 60))
            .finalize(writer)
            .expect("sign 30641")
    }

    /// A stream wrap of `kind` with `tags`; the counter keeps every id
    /// distinct.
    pub(crate) fn wrap(signer: &Keys, kind: u16, tags: Vec<Tag>) -> Event {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        EventBuilder::new(Kind::Custom(kind), format!("ciphertext {n}"))
            .tags(tags)
            .finalize(signer)
            .expect("sign wrap")
    }

    /// An event of `kind` by `signer` with `tags`.
    pub(crate) fn event(signer: &Keys, kind: u16, tags: Vec<Tag>) -> Event {
        EventBuilder::new(Kind::from(kind), "")
            .tags(tags)
            .finalize(signer)
            .expect("sign")
    }

    pub(crate) fn tag(name: &str, value: &str) -> Tag {
        Tag::custom(name, vec![value.to_string()])
    }

    pub(crate) fn accepted(result: WritePolicyResult, what: &str) {
        match result {
            WritePolicyResult::Accept => {}
            WritePolicyResult::Reject {
                prefix, message, ..
            } => panic!("{what}: refused with {prefix}: {message}"),
        }
    }

    /// The text a client is sent for a refusal, as the relay renders it.
    /// A refusal that the client would widen on, or that sync would keep
    /// for upstream's related-event retry, fails here.
    pub(crate) fn refusal(result: WritePolicyResult, what: &str) -> String {
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

    pub(crate) fn references_private() -> String {
        format!("restricted: {REFERENCES_PRIVATE_MESSAGE}")
    }

    /// The related-event text upstream gives an event with no stored
    /// anchor, through its generic arm.
    pub(crate) const UPSTREAM_ORPHAN: &str =
        "restricted: Event event must reference an accepted repository or accepted event";

    /// A registered repository with a stored state root and a stored wrap,
    /// whose registration also names `servers`.
    pub(crate) async fn repo_with_servers(node: &Node, servers: &[&str]) -> Repo {
        let tenant = Keys::generate();
        let writer = Keys::generate();
        let aux = Keys::generate();
        let alias = random_hex()[..32].to_string();
        let registration = registration(
            &tenant,
            &alias,
            &writer,
            &aux,
            servers,
            Vec::new(),
            now() - 120,
        );
        accepted(node.send(&registration).await, "registration");
        let manifest = random_hex();
        let root = state_root(&writer, &tenant, &alias, &manifest, Vec::new());
        accepted(node.send(&root).await, "state root");
        let wrap = wrap(&aux, KIND_STREAM_WRAP, Vec::new());
        accepted(node.send(&wrap).await, "wrap");
        Repo {
            tenant,
            writer,
            aux,
            alias,
            registration,
            root,
            wrap,
            manifest,
        }
    }

    pub(crate) async fn repo(node: &Node) -> Repo {
        repo_with_servers(node, &[]).await
    }

    /// A public note the owner stored, which upstream's related-event
    /// rule takes as an anchor for anything that tags it.
    pub(crate) async fn public_note(node: &Node) -> Event {
        let note = event(&node.owner, 1, vec![tag("t", "a public note")]);
        accepted(node.send(&note).await, "the owner's note");
        note
    }

    #[test]
    fn the_private_kinds_are_the_six_grasp_p_kinds_and_the_cascade_list() {
        for kind in [
            KIND_REGISTRATION,
            KIND_STATE_ROOT,
            KIND_STREAM_WRAP,
            KIND_EPHEMERAL_STREAM_WRAP,
            KIND_WRAP,
            KIND_EPHEMERAL_WRAP,
        ] {
            assert!(super::super::is_private_event_kind(kind), "kind {kind}");
        }
        for kind in [
            0,
            1,
            5,
            7,
            62,
            1111,
            1617,
            KIND_REPORT,
            3358,
            10317,
            30617,
            30618,
            30642,
        ] {
            assert!(!super::super::is_private_event_kind(kind), "kind {kind}");
        }
        // The cascade passes over exactly these, for every kind there is.
        assert_eq!(
            (0..=u16::MAX)
                .filter(|kind| super::super::offboard::cascade_exempt(*kind))
                .collect::<Vec<_>>(),
            {
                let mut kinds = PRIVATE_EVENT_KINDS.to_vec();
                kinds.sort();
                kinds
            }
        );
    }

    /// Tags are read as upstream's related-event rule reads them: a
    /// coordinate's kind as a number, whatever its spelling, `q` both ways,
    /// and `a` or `A` without a colon not at all. Only the ids that parse
    /// are kept, each once, and only they count toward the cap.
    #[test]
    fn references_are_read_as_upstream_reads_them() {
        let signer = Keys::generate();
        let pk = signer.public_key().to_hex();
        for (name, value) in [
            ("a", format!("30640:{pk}:alias")),
            ("A", format!("30641:{pk}:alias")),
            ("q", format!("3359:{pk}:")),
            ("a", format!("23359:{pk}:")),
            ("a", format!("1059:{pk}:")),
            ("a", format!("21059:{pk}:")),
            ("a", format!("030640:{pk}:alias")),
            ("a", format!("+30641:{pk}:alias")),
            ("a", format!("0000003359:{pk}:")),
            ("a", "30640:not-a-key".to_string()),
        ] {
            let read = References::read(&event(&signer, 1, vec![tag(name, &value)]));
            assert!(read.private_coordinate, "{name} {value}");
        }
        for (name, value) in [
            ("a", format!("30617:{pk}:repo")),
            ("a", format!("96176:{pk}:alias")),
            ("a", format!(" 30640:{pk}:alias")),
            ("a", "30640".to_string()),
            ("A", "3359".to_string()),
            ("x", format!("30640:{pk}:alias")),
            ("e", format!("30640:{pk}:alias")),
        ] {
            let read = References::read(&event(&signer, 1, vec![tag(name, &value)]));
            assert!(!read.private_coordinate, "{name} {value}");
        }

        let id = event(&signer, 1, Vec::new()).id;
        let read = References::read(&event(
            &signer,
            1,
            vec![
                tag("e", &id.to_hex()),
                tag("E", &id.to_hex()),
                tag("q", &id.to_hex()),
                tag("q", &format!("30617:{pk}:repo")),
                tag("e", "not an id"),
                tag("p", &id.to_hex()),
            ],
        ));
        assert_eq!(read.ids, HashSet::from([id]));
        assert!(!read.private_coordinate);
    }

    /// An event of another kind that references a registration, a state
    /// root or a wrap by coordinate is refused, whatever else it tags and
    /// whether or not the event it names is stored. Each one also tags a
    /// stored public note, so upstream alone would store it: the test fails
    /// when the coordinate check goes.
    #[tokio::test]
    async fn a_coordinate_of_a_grasp_p_kind_is_refused_beside_a_public_anchor() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let anchor = public_note(&node).await;
        let stranger = Keys::generate();
        let writer = repo.writer.public_key().to_hex();
        let aux = repo.aux.public_key().to_hex();
        let unknown = random_hex();
        for (name, coordinate) in [
            ("a", repo.coordinate()),
            ("A", repo.coordinate()),
            ("q", repo.coordinate()),
            ("a", format!("30641:{writer}:{}", repo.alias)),
            ("a", format!("3359:{aux}:")),
            ("a", format!("1059:{aux}:")),
            (
                "a",
                format!(
                    "030640:{}:{}",
                    repo.tenant.public_key().to_hex(),
                    repo.alias
                ),
            ),
            // Nothing stored under this one: judged from the event alone.
            ("a", format!("30640:{unknown}:{}", &unknown[..32])),
        ] {
            for kind in [1, 7, 16, 1111, 1621, 30023] {
                let note = event(
                    &stranger,
                    kind,
                    vec![
                        tag("d", "x"),
                        tag("e", &anchor.id.to_hex()),
                        tag(name, &coordinate),
                    ],
                );
                let what = format!("kind {kind}, {name} {coordinate}");
                assert_eq!(
                    refusal(node.send(&note).await, &what),
                    references_private(),
                    "{what}"
                );
                assert!(!node.stored(note.id).await, "{what}");
            }
        }
    }

    /// The same for an `e`, `E` or `q` id of a stored registration, state
    /// root or wrap, a legacy one included. Fails when the id check goes.
    #[tokio::test]
    async fn an_id_of_a_stored_grasp_p_event_is_refused_beside_a_public_anchor() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let legacy = wrap(&repo.aux, KIND_WRAP, Vec::new());
        accepted(node.send(&legacy).await, "a legacy wrap");
        let anchor = public_note(&node).await;
        let stranger = Keys::generate();
        for target in [&repo.registration, &repo.root, &repo.wrap, &legacy] {
            for name in ["e", "E", "q"] {
                let note = event(
                    &stranger,
                    1,
                    vec![
                        tag("e", &anchor.id.to_hex()),
                        tag(name, &target.id.to_hex()),
                    ],
                );
                let what = format!("{name} of kind {}", target.kind.as_u16());
                assert_eq!(
                    refusal(node.send(&note).await, &what),
                    references_private(),
                    "{what}"
                );
            }
        }
    }

    /// A node that no longer takes the legacy kinds still holds the 1059s
    /// it took, and nothing may reference them either.
    #[tokio::test]
    async fn a_stored_legacy_wrap_counts_on_a_node_that_retired_the_kind() {
        let node =
            Node::start_with(|config, _| config.private_accept_legacy_wrap_kind = false).await;
        let legacy = wrap(&Keys::generate(), KIND_WRAP, Vec::new());
        node.store(&legacy).await;
        let anchor = public_note(&node).await;
        let note = event(
            &Keys::generate(),
            1,
            vec![tag("e", &anchor.id.to_hex()), tag("e", &legacy.id.to_hex())],
        );
        assert_eq!(
            refusal(node.send(&note).await, "a note"),
            references_private()
        );
    }

    /// Kinds upstream takes with no reference check at all, a 10317 from
    /// anyone and any kind the relay owner signs, are refused the same way:
    /// the rule runs before upstream's dispatch. Without a reference they
    /// are upstream's as before.
    #[tokio::test]
    async fn kinds_upstream_takes_unchecked_are_refused_too() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let stranger = Keys::generate();
        for (what, signer, kind) in [
            ("a 10317", &stranger, 10317),
            ("the owner's note", &node.owner, 1),
            ("the owner's custom event", &node.owner, 9999),
        ] {
            let tagged = event(signer, kind, vec![tag("e", &repo.wrap.id.to_hex())]);
            assert_eq!(
                refusal(node.send(&tagged).await, what),
                references_private(),
                "{what}"
            );
            let by_coordinate = event(signer, kind, vec![tag("a", &repo.coordinate())]);
            assert_eq!(
                refusal(node.send(&by_coordinate).await, what),
                references_private(),
                "{what}"
            );
            accepted(node.send(&event(signer, kind, Vec::new())).await, what);
        }
    }

    /// References to public content alone are upstream's: an event that
    /// tags a stored public note, or a stored public repository, is stored
    /// as upstream stores it, and one that tags nothing stored gets
    /// upstream's own answer.
    #[tokio::test]
    async fn public_references_are_upstreams() {
        let node = Node::start().await;
        let _repo = repo(&node).await;
        let anchor = public_note(&node).await;
        let maintainer = Keys::generate();
        let announcement = event(&maintainer, 30617, vec![tag("d", "a-public-repo")]);
        node.store(&announcement).await;
        let public = format!("30617:{}:a-public-repo", maintainer.public_key().to_hex());
        let stranger = Keys::generate();
        for tags in [
            vec![tag("e", &anchor.id.to_hex())],
            vec![tag("q", &anchor.id.to_hex())],
            vec![tag("a", &public)],
            vec![tag("A", &public), tag("e", &random_hex())],
        ] {
            let note = event(&stranger, 1, tags);
            assert!(judge(node.svc(), &note).await.is_none());
            accepted(node.send(&note).await, "a public reply");
        }
        let orphan = event(&stranger, 1, vec![tag("e", &random_hex())]);
        assert!(judge(node.svc(), &orphan).await.is_none());
        assert_eq!(
            refusal(node.send(&orphan).await, "an orphan"),
            UPSTREAM_ORPHAN
        );
    }

    /// An id this node does not hold yet is not recognised (decision
    /// D15-5): the event is upstream's, and once the private event is
    /// stored the same reference is refused.
    #[tokio::test]
    async fn an_id_not_stored_yet_is_judged_when_it_is() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let anchor = public_note(&node).await;
        let pending = wrap(&repo.aux, KIND_STREAM_WRAP, Vec::new());
        let early = event(
            &Keys::generate(),
            1,
            vec![
                tag("e", &anchor.id.to_hex()),
                tag("e", &pending.id.to_hex()),
            ],
        );
        accepted(node.send(&early).await, "before the wrap");
        accepted(node.send(&pending).await, "the wrap");
        let late = event(
            &Keys::generate(),
            1,
            vec![
                tag("e", &anchor.id.to_hex()),
                tag("e", &pending.id.to_hex()),
            ],
        );
        assert_eq!(
            refusal(node.send(&late).await, "after the wrap"),
            references_private()
        );
    }

    /// With GRASP-P off nothing here runs: an event that tags a stored
    /// registration, state root or wrap is upstream's, which stores it on
    /// that anchor.
    #[tokio::test]
    async fn with_grasp_p_off_upstream_decides_alone() {
        let node = Node::start_with(|config, _| config.private_repos_enable = false).await;
        assert!(node.runtime.grasp_p.is_none());
        let tenant = Keys::generate();
        let alias = random_hex()[..32].to_string();
        let stored = [
            registration(
                &tenant,
                &alias,
                &Keys::generate(),
                &Keys::generate(),
                &[],
                Vec::new(),
                now(),
            ),
            state_root(
                &Keys::generate(),
                &tenant,
                &alias,
                &random_hex(),
                Vec::new(),
            ),
            wrap(&Keys::generate(), KIND_STREAM_WRAP, Vec::new()),
        ];
        for target in &stored {
            node.store(target).await;
            let note = event(&Keys::generate(), 1, vec![tag("e", &target.id.to_hex())]);
            accepted(node.send(&note).await, "a note tagging a stored event");
        }
        let by_coordinate = event(
            &Keys::generate(),
            1,
            vec![tag(
                "a",
                &format!("30640:{}:{alias}", tenant.public_key().to_hex()),
            )],
        );
        accepted(
            node.send(&by_coordinate).await,
            "a note tagging the registration",
        );
    }

    /// More distinct ids than the cap are refused whole and before any
    /// lookup, even when the one that names a wrap comes last; at the cap
    /// the event is judged in full. Repeated ids and values that do not
    /// parse cost no lookup and do not count, so an event with more of
    /// them than the cap is upstream's.
    #[tokio::test]
    async fn past_the_cap_the_event_is_refused_whole() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let stranger = Keys::generate();
        let filler = |count: usize| -> Vec<Tag> {
            (0..count)
                .map(|n| {
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
                    tag("e", &EventId::from_byte_array(bytes).to_hex())
                })
                .collect()
        };
        let at_cap = event(&stranger, 1, filler(MAX_REFERENCES));
        assert!(judge(node.svc(), &at_cap).await.is_none());
        let mut tags = filler(MAX_REFERENCES - 1);
        tags.push(tag("e", &repo.wrap.id.to_hex()));
        let last_names_the_wrap = event(&stranger, 1, tags);
        assert_eq!(
            refusal(node.send(&last_names_the_wrap).await, "at the cap"),
            references_private()
        );
        let mut tags = filler(MAX_REFERENCES);
        tags.push(tag("e", &repo.wrap.id.to_hex()));
        let over = event(&stranger, 1, tags);
        assert_eq!(
            refusal(node.send(&over).await, "over the cap"),
            format!("invalid: {TOO_MANY_REFERENCES_MESSAGE}")
        );
        for (what, value) in [("one id repeated", random_hex()), ("junk", "x".to_string())] {
            let cheap = event(&stranger, 1, vec![tag("e", &value); MAX_REFERENCES + 1]);
            assert!(judge(node.svc(), &cheap).await.is_none(), "{what}");
        }
    }

    /// A refusal of an event that sync brought is remembered by id, so the
    /// sync batch that asked for it completes; a client's is not.
    #[tokio::test]
    async fn a_refused_synced_event_is_remembered_by_id() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let held = node.svc().sync_rejected();
        let from_client = event(&Keys::generate(), 1, vec![tag("e", &repo.wrap.id.to_hex())]);
        assert_eq!(
            refusal(node.send(&from_client).await, "a client's"),
            references_private()
        );
        assert!(!held.contains(&from_client.id));
        let synced = event(&Keys::generate(), 1, vec![tag("a", &repo.coordinate())]);
        assert_eq!(
            refusal(node.send_synced(&synced).await, "a synced one"),
            references_private()
        );
        assert!(held.contains(&synced.id));
        let tags: Vec<Tag> = (0..=MAX_REFERENCES)
            .map(|_| tag("e", &random_hex()))
            .collect();
        let too_many = event(&Keys::generate(), 1, tags);
        assert!(admit(node.svc(), &too_many, true).await.is_some());
        assert!(held.contains(&too_many.id), "the cap is final too");
        // An event the rule passes is not remembered.
        let public = event(&Keys::generate(), 1, Vec::new());
        assert!(admit(node.svc(), &public, true).await.is_none());
        assert!(!held.contains(&public.id));
    }

    /// The tag ban, kind by kind, from a client and from sync. A refused
    /// event is not held for a registration, which cannot make it
    /// acceptable, and a synced one is remembered by id only. Each event
    /// would be accepted without the ban, as the untagged controls are.
    #[tokio::test]
    async fn grasp_p_events_carry_no_reference_tags() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let anchor = public_note(&node).await.id.to_hex();
        let hold = node.svc().sync_rejected();
        let untagged = format!("invalid: {UNTAGGED_EVENT_MESSAGE}");
        let state_root_shape = format!("invalid: {STATE_ROOT_TAGS_MESSAGE}");
        let audit = format!("invalid: {AUDIT_TAG_MESSAGE}");
        let audit_tag = || tag("t", AUDIT_TEST_EVENT_TAG);
        let public = format!("30617:{}:x", Keys::generate().public_key().to_hex());

        let mut cases: Vec<(String, Event, &String)> = Vec::new();
        for name in ["e", "E", "q", "a", "A"] {
            let value = if name.eq_ignore_ascii_case("a") {
                public.clone()
            } else {
                anchor.clone()
            };
            cases.push((
                format!("a registration with {name}"),
                registration(
                    &repo.tenant,
                    &repo.alias,
                    &repo.writer,
                    &repo.aux,
                    &[],
                    vec![tag(name, &value)],
                    now(),
                ),
                &untagged,
            ));
            for kind in [
                KIND_STREAM_WRAP,
                KIND_WRAP,
                KIND_EPHEMERAL_STREAM_WRAP,
                KIND_EPHEMERAL_WRAP,
            ] {
                cases.push((
                    format!("a {kind} with {name}"),
                    wrap(&repo.aux, kind, vec![tag(name, &value)]),
                    &untagged,
                ));
            }
            if name != "a" {
                cases.push((
                    format!("a state root with {name}"),
                    state_root(
                        &repo.writer,
                        &repo.tenant,
                        &repo.alias,
                        &repo.manifest,
                        vec![tag(name, &value)],
                    ),
                    &state_root_shape,
                ));
            }
        }
        cases.push((
            "a state root with a second a tag".to_string(),
            state_root(
                &repo.writer,
                &repo.tenant,
                &repo.alias,
                &repo.manifest,
                vec![tag("a", &public)],
            ),
            &state_root_shape,
        ));
        cases.push((
            "a state root with its own coordinate twice".to_string(),
            state_root(
                &repo.writer,
                &repo.tenant,
                &repo.alias,
                &repo.manifest,
                vec![tag("a", &repo.coordinate())],
            ),
            &state_root_shape,
        ));
        cases.push((
            "a registration with the audit tag".to_string(),
            registration(
                &repo.tenant,
                &repo.alias,
                &repo.writer,
                &repo.aux,
                &[],
                vec![audit_tag()],
                now(),
            ),
            &audit,
        ));
        cases.push((
            "a state root with the audit tag".to_string(),
            state_root(
                &repo.writer,
                &repo.tenant,
                &repo.alias,
                &repo.manifest,
                vec![audit_tag()],
            ),
            &audit,
        ));
        cases.push((
            "a wrap with the audit tag".to_string(),
            wrap(&repo.aux, KIND_STREAM_WRAP, vec![audit_tag()]),
            &audit,
        ));
        for (what, refused, expected) in &cases {
            assert_eq!(
                &refusal(node.send(refused).await, what),
                *expected,
                "{what}"
            );
            assert!(!node.stored(refused.id).await, "{what}");
            assert!(!hold.contains(&refused.id), "{what}: nothing is held");
            assert_eq!(
                &refusal(node.send_synced(refused).await, what),
                *expected,
                "{what}"
            );
            // The sync manager's own hook notes a synced refusal.
            node.svc()
                .note_rejected(refused, expected.trim_start_matches("invalid: "), true);
            let kind = refused.kind.as_u16();
            let stored_kind = kind != KIND_EPHEMERAL_STREAM_WRAP && kind != KIND_EPHEMERAL_WRAP;
            assert_eq!(
                hold.contains(&refused.id),
                stored_kind,
                "{what}: the id only"
            );
        }
        assert_eq!(hold.held_len(), 0);
        assert!(hold.take_for_alias(&repo.alias).is_empty());

        // The same events without the tags are taken; the state root keeps
        // its own a tag, and a t tag of another value is no audit tag.
        accepted(
            node.send(&registration(
                &repo.tenant,
                &repo.alias,
                &repo.writer,
                &repo.aux,
                &[],
                vec![tag("t", "grasp-audit")],
                now(),
            ))
            .await,
            "a registration",
        );
        accepted(
            node.send(&state_root(
                &repo.writer,
                &repo.tenant,
                &repo.alias,
                &repo.manifest,
                Vec::new(),
            ))
            .await,
            "a state root",
        );
        accepted(
            node.send(&wrap(&repo.aux, KIND_STREAM_WRAP, vec![tag("p", &anchor)]))
                .await,
            "a wrap",
        );
    }

    /// The ban is the event's own: it does not depend on who signed it,
    /// and an unregistered key's tagged wrap gets it before the key lookup,
    /// so the wrap is not held for a registration of that key.
    #[tokio::test]
    async fn a_tagged_wrap_from_an_unregistered_key_is_not_held() {
        let node = Node::start().await;
        let stranger = Keys::generate();
        let tagged = wrap(&stranger, KIND_STREAM_WRAP, vec![tag("e", &random_hex())]);
        assert_eq!(
            refusal(node.send(&tagged).await, "a tagged wrap"),
            format!("invalid: {UNTAGGED_EVENT_MESSAGE}")
        );
        assert!(node
            .svc()
            .sync_rejected()
            .take_for_authors(&[stranger.public_key().to_hex()])
            .is_empty());
    }
}
