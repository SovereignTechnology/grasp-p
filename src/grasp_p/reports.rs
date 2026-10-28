//! Reports on private repositories are refused (decision D10).
//!
//! The takedown runbook needs a blob's key to confirm a report, and a
//! stored report would publish whatever key it carries beside a public
//! blob, together with an accusation against a customer's repository. So a
//! kind 1984 that points at private-repository content is logged and counted
//! (`admission::log_report`, the operator's intake) and refused with one
//! fixed text that names nothing (D15-3). A report that points at nothing
//! private is upstream's alone, with no GRASP-P log line and no count
//! (D15-1): the node serves public repositories too (D1), and their reports
//! are not this intake's.
//!
//! A report points at private content when it references a GRASP-P event as
//! any event would (`attachment`), or when:
//!
//! - a 64-hex tag value is a blob this node holds a claim for, or one on the
//!   loaded denylist;
//! - an `x` tag sits beside a `server` tag that names either node of the
//!   pair, the node itself or a blob's URL on it. The pair is this node's
//!   address and the peers its operator lists, by sync and by blob mirror:
//!   operator configuration, so no account can add a name to it, and a few
//!   names whatever the registrations say. The pair serves no other blobs,
//!   so a hash for it is a hash of private content, whether or not this
//!   node has it yet;
//! - a `p` or `P` tag names a write or aux key that holds a claim here
//!   (D15-2). Those keys sign nothing but private-repository events. An
//!   account key does not count, even when its registration lists it among
//!   its own write or aux keys.
//!
//! A hash or a key is compared in lower case, however the report spells it.

use std::collections::{HashSet, VecDeque};

use nostr::prelude::{Event, EventId};
use nostr_sdk::local_relay::WritePolicyResult;

use super::attachment::{References, MAX_REFERENCES, TOO_MANY_REFERENCES_MESSAGE};
use super::PrivateService;
use crate::nostr::policy::{reject_error, reject_invalid, reject_restricted};

/// The answer to every report that points at private-repository content.
/// It names no target and contains neither "unregistered" nor upstream's
/// related-event text, so neither the client nor sync acts on it.
pub(crate) const REPORT_MESSAGE: &str =
    "reports about private repositories are not stored on this service";

/// How many report ids the intake remembers. A refused report is not
/// stored, so sync fetches it again from the relays that hold it once its
/// id leaves the hold, and a page that fires for every delivery of one
/// report would hide the next one.
const LOGGED_REPORT_IDS: usize = 4096;

/// The ids of the reports the intake has logged, oldest first.
#[derive(Debug, Default)]
pub(crate) struct LoggedReports {
    ids: HashSet<EventId>,
    order: VecDeque<EventId>,
}

impl LoggedReports {
    /// Whether `id` is logged for the first time, remembering it. Past
    /// [`LOGGED_REPORT_IDS`] the oldest id is forgotten, never the new one.
    pub(crate) fn first_sighting(&mut self, id: EventId) -> bool {
        if !self.ids.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > LOGGED_REPORT_IDS {
            if let Some(oldest) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }
        true
    }
}

/// The values of a report beyond its references.
#[derive(Debug, Default)]
struct ReportValues {
    /// Every 64-hex value of every tag, in lower case, each once: each costs
    /// lookups, so this is what the cap bounds.
    hashes: HashSet<String>,
    /// The 64-hex `p` and `P` values, in lower case.
    keys: HashSet<String>,
    /// Some `x` tag has a value.
    has_x: bool,
    /// Every value of every `server` tag, each once, as written.
    servers: HashSet<String>,
}

impl ReportValues {
    fn read(event: &Event) -> Self {
        let mut values = Self::default();
        for tag in event.tags.iter() {
            let slice = tag.as_slice();
            values
                .hashes
                .extend(slice.iter().skip(1).filter_map(|value| hex_64(value)));
            match slice.first().map(String::as_str) {
                Some("p" | "P") => values.keys.extend(slice.get(1).and_then(|key| hex_64(key))),
                Some("x") => values.has_x |= slice.len() >= 2,
                Some("server") => values.servers.extend(slice.iter().skip(1).cloned()),
                _ => {}
            }
        }
        values
    }

    /// Whether more values must be looked up than the cap allows. Every id
    /// that parses is also a 64-hex value, so the hash count bounds the
    /// ids. The `server` values are compared only beside an `x` tag.
    fn over_cap(&self) -> bool {
        self.hashes.len() > MAX_REFERENCES || (self.has_x && self.servers.len() > MAX_REFERENCES)
    }

    /// The checks that need the node's own records and configuration: the
    /// names of the pair, the denylist, and the blob and key claims.
    fn point_at_private_content(&self, svc: &PrivateService) -> anyhow::Result<bool> {
        if self.names_the_pair(svc) || self.hashes.iter().any(|hash| svc.is_denylisted(hash)) {
            return Ok(true);
        }
        let txn = svc.meta.read_txn()?;
        for hash in &self.hashes {
            if svc.meta.get_blob_claim(&txn, hash)?.is_some() {
                return Ok(true);
            }
        }
        for key in &self.keys {
            if let Some(alias) = svc.meta.get_key_claim(&txn, key)? {
                // An account key listed among its own write or aux keys is
                // still an account key (D15-2): its registration's signature
                // stands in for the proof, so listing it costs nothing.
                let own_account = svc
                    .meta
                    .get_registration(&txn, &alias)?
                    .is_some_and(|record| record.tenant_hex == *key);
                if !own_account {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether an `x` tag sits beside a `server` value that names a node
    /// of the pair.
    fn names_the_pair(&self, svc: &PrivateService) -> bool {
        if !self.has_x || self.servers.is_empty() {
            return false;
        }
        let pair = pair_names(svc);
        self.servers.iter().any(|server| {
            let server = report_server_name(server);
            pair.iter().any(|node| names_node(&server, node))
        })
    }
}

/// A 64-character hex value, in lower case.
fn hex_64(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// The names of the pair, as `fingerprint_domain` writes them: this node's
/// service address and the peers in `NGIT_GRASP_P_SYNC_PEER_URLS` and
/// `NGIT_GRASP_P_MIRROR_PEER_URLS`. A registration's `server` values are
/// not read: an account writes those as it likes.
fn pair_names(svc: &PrivateService) -> Vec<String> {
    std::iter::once(svc.cfg.service_address.as_str())
        .chain(svc.cfg.sync_peer_relays.iter().map(String::as_str))
        .chain(
            svc.cfg
                .mirror_peer_urls
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(String::as_str),
        )
        .map(super::fingerprint_domain)
        .filter(|name| !name.is_empty())
        .collect()
}

/// A report's `server` value as `fingerprint_domain` writes a name. The
/// scheme is put in lower case and any user part dropped first, which
/// `fingerprint_domain` does not do for a URL this loose: it feeds the
/// fingerprint, so it stays as it is.
fn report_server_name(server: &str) -> String {
    let server = server.trim();
    let server = match server.split_once("://") {
        Some((scheme, rest)) => {
            let rest = match rest.split_once('@') {
                Some((userinfo, host)) if !userinfo.contains('/') => host,
                _ => rest,
            };
            format!("{}://{rest}", scheme.to_ascii_lowercase())
        }
        None => server.to_string(),
    };
    super::fingerprint_domain(&server)
}

/// Whether `server`, as [`report_server_name`] writes it, names the node
/// whose name is `node`: the node itself, or a blob's URL on it. Any other
/// URL on the node is not a blob's, and the node serves public
/// repositories under the same name (D1).
fn names_node(server: &str, node: &str) -> bool {
    server == node
        || server
            .strip_prefix(node)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(is_blob_segment)
}

/// A blob's path segment: 64 hex characters, with or without an extension.
fn is_blob_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.len() >= 64
        && bytes[..64].iter().all(u8::is_ascii_hexdigit)
        && (bytes.len() == 64 || bytes[64] == b'.')
}

/// Judge a kind 1984. `Some` is the refusal; `None` hands the report to
/// upstream, which decides as on a node without GRASP-P. The cheap checks
/// come first: what the event says alone, then the node's records, then
/// one query of the relay store.
pub(crate) async fn judge(svc: &PrivateService, event: &Event) -> Option<WritePolicyResult> {
    let references = References::read(event);
    let values = ReportValues::read(event);
    if values.over_cap() {
        return Some(reject_invalid(TOO_MANY_REFERENCES_MESSAGE));
    }
    let private = if references.private_coordinate {
        true
    } else {
        match values.point_at_private_content(svc) {
            Ok(true) => true,
            Ok(false) => {
                match super::attachment::names_stored_private_event(svc, &references.ids).await {
                    Ok(found) => found,
                    Err(error) => return Some(super::attachment::relay_store_failure(&error)),
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "private report check could not read the meta store");
                return Some(reject_error("private meta store failure"));
            }
        }
    };
    if !private {
        return None;
    }
    // Refused every time, logged and counted once.
    if svc.logged_reports.lock().first_sighting(event.id) {
        super::admission::log_report(event);
    }
    Some(reject_restricted(REPORT_MESSAGE))
}

#[cfg(test)]
mod tests {
    use nostr_sdk::prelude::{Keys, Tag};

    use super::*;
    use crate::grasp_p::admission::admit;
    use crate::grasp_p::attachment::tests::{
        accepted, event, now, public_note, random_hex, refusal, registration, repo,
        repo_with_servers, tag, Node, UPSTREAM_ORPHAN,
    };
    use crate::grasp_p::KIND_REPORT;

    fn report(reporter: &Keys, tags: Vec<Tag>) -> Event {
        event(reporter, KIND_REPORT, tags)
    }

    fn refused() -> String {
        format!("restricted: {REPORT_MESSAGE}")
    }

    /// A node whose denylist lists one hash, returned with it, and whose
    /// operator lists one sync peer and one blob mirror peer.
    async fn node_of_a_pair() -> (Node, String) {
        let denied = random_hex();
        let node = Node::start_with(|config, dir| {
            let path = dir.join("deny.txt");
            std::fs::write(&path, format!("{denied}\n")).expect("write the denylist");
            config.private_denylist_path = Some(path.to_string_lossy().into_owned());
            config.private_sync_peer_urls = Some("wss://peer.example".to_string());
            config.private_mirror_peer_urls = Some("https://mirror.example".to_string());
        })
        .await;
        (node, denied)
    }

    /// Every way a report points at private content, each beside a stored
    /// public note that upstream alone would take as its anchor, so each
    /// case fails when its check goes. The pair's other names come from the
    /// operator's peer lists; the registration names neither.
    #[tokio::test]
    async fn a_report_pointing_at_private_content_is_refused() {
        let (node, denied) = node_of_a_pair().await;
        let repo = repo(&node).await;
        let anchor = public_note(&node).await.id.to_hex();
        let writer = repo.writer.public_key().to_hex();
        let aux = repo.aux.public_key().to_hex();
        let tenant = repo.tenant.public_key().to_hex();
        let blob = random_hex();
        let cases: Vec<(&str, Vec<Tag>)> = vec![
            (
                "the registration's coordinate",
                vec![tag("a", &repo.coordinate())],
            ),
            ("the coordinate in q", vec![tag("q", &repo.coordinate())]),
            (
                "a state root coordinate",
                vec![tag("A", &format!("30641:{writer}:{}", repo.alias))],
            ),
            (
                "another spelling",
                vec![tag("a", &format!("030640:{tenant}:{}", repo.alias))],
            ),
            (
                "the registration's id",
                vec![tag("e", &repo.registration.id.to_hex())],
            ),
            (
                "the state root's id",
                vec![tag("E", &repo.root.id.to_hex())],
            ),
            ("the wrap's id", vec![tag("q", &repo.wrap.id.to_hex())]),
            ("a claimed blob", vec![tag("x", &repo.manifest)]),
            ("a claimed blob in an e tag", vec![tag("e", &repo.manifest)]),
            (
                "a claimed blob in capitals",
                vec![tag("x", &repo.manifest.to_ascii_uppercase())],
            ),
            ("a denylisted blob", vec![tag("x", &denied)]),
            (
                "an x beside this node's name",
                vec![tag("x", &blob), tag("server", "localhost:7334")],
            ),
            (
                "an x beside this node's URL",
                vec![tag("x", &blob), tag("server", "https://localhost:7334/")],
            ),
            (
                "an x beside a blob URL of this node",
                vec![
                    tag("x", &blob),
                    tag("server", &format!("http://localhost:7334/{blob}")),
                ],
            ),
            (
                "an x beside a blob URL of this node, spelled loosely",
                vec![
                    tag("x", &blob),
                    tag("server", &format!("HTTPS://someone@localhost:7334/{blob}")),
                ],
            ),
            (
                "an x beside the sync peer's name",
                vec![tag("x", &blob), tag("server", "peer.example")],
            ),
            (
                "an x beside a blob URL of the sync peer",
                vec![
                    tag("x", &blob),
                    tag("server", &format!("https://PEER.example/{blob}")),
                ],
            ),
            (
                "an x beside the mirror peer's name",
                vec![tag("x", &blob), tag("server", "https://mirror.example")],
            ),
            (
                "an x beside a blob URL of the mirror peer, with an extension",
                vec![
                    tag("x", &blob),
                    tag("server", &format!("https://mirror.example/{blob}.bin")),
                ],
            ),
            ("a write key", vec![tag("p", &writer)]),
            ("the aux key", vec![tag("p", &aux)]),
            ("a write key in P", vec![tag("P", &writer)]),
            (
                "a write key in capitals",
                vec![tag("p", &writer.to_ascii_uppercase())],
            ),
        ];
        let reporter = Keys::generate();
        for (what, mut tags) in cases {
            tags.push(tag("e", &anchor));
            let refused_report = report(&reporter, tags);
            assert!(judge(node.svc(), &refused_report).await.is_some(), "{what}");
            assert_eq!(
                refusal(node.send(&refused_report).await, what),
                refused(),
                "{what}"
            );
            assert!(!node.stored(refused_report.id).await, "{what}");
        }
    }

    /// A report on public content is upstream's: stored on its anchor, or
    /// refused in upstream's own words when it has none. None of these
    /// counts: the account key in `p`, even one its registration lists as
    /// its own write key; an `x` beside a server of neither node, a server
    /// a registration names among them; an `x` beside a URL on this node
    /// that is not a blob's; a server tag with no `x`.
    #[tokio::test]
    async fn a_report_on_public_content_is_upstreams() {
        let node = Node::start().await;
        let repo = repo_with_servers(&node, &["https://elsewhere.example"]).await;
        let self_listed = Keys::generate();
        let self_listed_hex = self_listed.public_key().to_hex();
        accepted(
            node.send(&registration(
                &self_listed,
                &random_hex()[..32],
                &self_listed,
                &Keys::generate(),
                &[],
                Vec::new(),
                now() - 120,
            ))
            .await,
            "a registration that lists its account as a write key",
        );
        {
            let txn = node.svc().meta.read_txn().expect("read txn");
            assert!(
                node.svc()
                    .meta
                    .get_key_claim(&txn, &self_listed_hex)
                    .expect("read the key claim")
                    .is_some(),
                "the account key holds a key claim"
            );
        }
        let anchor = public_note(&node).await;
        let blob = random_hex();
        let reporter = Keys::generate();
        for (what, mut tags) in [
            (
                "a public note",
                vec![tag("p", &node.owner.public_key().to_hex())],
            ),
            (
                "the account key",
                vec![tag("p", &repo.tenant.public_key().to_hex())],
            ),
            (
                "an account key listed as its own write key",
                vec![tag("p", &self_listed_hex)],
            ),
            (
                "an x beside another server",
                vec![tag("x", &blob), tag("server", "elsewhere.example")],
            ),
            (
                "an x beside a name that only starts like this node's",
                vec![tag("x", &blob), tag("server", "localhost:73345")],
            ),
            (
                "an x beside a public repository's URL on this node",
                vec![
                    tag("x", &blob),
                    tag("server", "http://localhost:7334/npub1x/repo.git"),
                ],
            ),
            (
                "this node's name with no x",
                vec![tag("server", "localhost:7334")],
            ),
            ("an unknown hash", vec![tag("x", &blob)]),
        ] {
            tags.push(tag("e", &anchor.id.to_hex()));
            let public = report(&reporter, tags);
            assert!(judge(node.svc(), &public).await.is_none(), "{what}");
            accepted(node.send(&public).await, what);
        }
        // With the GRASP-P arm gone from the dispatch, an orphan report
        // gets upstream's generic answer.
        let orphan = report(&reporter, vec![tag("e", &random_hex())]);
        assert!(judge(node.svc(), &orphan).await.is_none());
        assert_eq!(
            refusal(node.send(&orphan).await, "an orphan"),
            UPSTREAM_ORPHAN
        );
    }

    /// The relay owner's reports are judged too: admission runs before the
    /// arm that takes any kind the owner signs.
    #[tokio::test]
    async fn the_relay_owners_report_is_judged_too() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let owner = node.owner.clone();
        let private = report(&owner, vec![tag("a", &repo.coordinate())]);
        assert_eq!(refusal(node.send(&private).await, "the owner's"), refused());
        accepted(
            node.send(&report(&owner, vec![tag("p", &random_hex())]))
                .await,
            "the owner's public report",
        );
    }

    /// A report that sync brought and this node refuses is remembered by
    /// id; a client's is not.
    #[tokio::test]
    async fn a_refused_synced_report_is_remembered_by_id() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let held = node.svc().sync_rejected();
        let from_client = report(&Keys::generate(), vec![tag("x", &repo.manifest)]);
        assert_eq!(
            refusal(node.send(&from_client).await, "a client's"),
            refused()
        );
        assert!(!held.contains(&from_client.id));
        let synced = report(&Keys::generate(), vec![tag("x", &repo.manifest)]);
        assert_eq!(
            refusal(node.send_synced(&synced).await, "a synced one"),
            refused()
        );
        assert!(held.contains(&synced.id));
        let public = report(&Keys::generate(), vec![tag("x", &random_hex())]);
        assert!(admit(node.svc(), &public, true).await.is_none());
        assert!(!held.contains(&public.id));
    }

    /// A report that comes again, from sync or a client, is refused every
    /// time and taken into the intake once; a public one never.
    #[tokio::test]
    async fn a_report_is_logged_once_however_often_it_comes() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let private = report(&Keys::generate(), vec![tag("x", &repo.manifest)]);
        for _ in 0..3 {
            assert_eq!(
                refusal(node.send_synced(&private).await, "from sync"),
                refused()
            );
            assert_eq!(
                refusal(node.send(&private).await, "from a client"),
                refused()
            );
        }
        assert!(!node.svc().logged_reports.lock().first_sighting(private.id));
        let public = report(&Keys::generate(), vec![tag("x", &random_hex())]);
        assert!(judge(node.svc(), &public).await.is_none());
        assert!(node.svc().logged_reports.lock().first_sighting(public.id));
    }

    /// The intake's memory is bounded: past it the oldest id goes, never
    /// the new one.
    #[test]
    fn the_intake_forgets_the_oldest_report_first() {
        let id = |n: usize| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
            EventId::from_byte_array(bytes)
        };
        let mut logged = LoggedReports::default();
        assert!(logged.first_sighting(id(0)));
        assert!(!logged.first_sighting(id(0)));
        for n in 1..=LOGGED_REPORT_IDS {
            assert!(logged.first_sighting(id(n)), "{n}");
        }
        assert!(logged.first_sighting(id(0)), "the oldest was forgotten");
        assert!(!logged.first_sighting(id(LOGGED_REPORT_IDS)));
    }

    /// More distinct hash values than the cap are refused whole, even when
    /// the one that names a claimed blob comes last; at the cap the report
    /// is judged in full, and repeats count once. Beside an `x`, so are
    /// more distinct `server` values than the cap.
    #[tokio::test]
    async fn past_the_cap_a_report_is_refused_whole() {
        let node = Node::start().await;
        let repo = repo(&node).await;
        let reporter = Keys::generate();
        let too_many = format!("invalid: {TOO_MANY_REFERENCES_MESSAGE}");
        let mut tags: Vec<Tag> = (1..MAX_REFERENCES)
            .map(|_| tag("x", &random_hex()))
            .collect();
        tags.push(tag("x", &repo.manifest));
        let at_cap = report(&reporter, tags.clone());
        assert_eq!(refusal(node.send(&at_cap).await, "at the cap"), refused());
        tags.push(tag("x", &random_hex()));
        let over = report(&reporter, tags);
        assert_eq!(refusal(node.send(&over).await, "over the cap"), too_many);

        let repeated = report(
            &reporter,
            vec![tag("x", &repo.manifest); MAX_REFERENCES + 1],
        );
        assert_eq!(
            refusal(node.send(&repeated).await, "one hash repeated"),
            refused()
        );

        let servers: Vec<Tag> = (0..=MAX_REFERENCES)
            .map(|n| tag("server", &format!("s{n}.example")))
            .collect();
        let mut with_x = servers.clone();
        with_x.push(tag("x", &random_hex()));
        assert_eq!(
            refusal(
                node.send(&report(&reporter, with_x)).await,
                "too many servers"
            ),
            too_many
        );
        assert!(judge(node.svc(), &report(&reporter, servers))
            .await
            .is_none());
    }
}
