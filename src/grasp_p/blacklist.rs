//! The operator's event blacklist (`NGIT_EVENT_BLACKLIST`) applied to the
//! writes of private repositories (decision D9).
//!
//! Upstream refuses every event whose author is on the list, before any
//! other check (`Nip34WritePolicy::check_event_blacklist`), and the blob
//! routes never consult it. On a GRASP-P node that stopped an account's own
//! registrations and deletion requests, which the account key signs, and
//! none of its writes: state roots, stream wraps and blob authorizations are
//! signed by the write and aux keys its registrations list, keys the
//! operator never sees. Here a write is also refused when the registration
//! it is made under belongs to an account on the list, a registration signed
//! by one of the keys a listed account's registrations list is refused, and
//! no registration displaces a listed account's seat (`registration::apply`),
//! so a listed account is frozen on every write path, for client writes and
//! synced events alike.
//! What it stored stays where it is: its events are served, and
//! `GET /<sha256>` and `GET /list` answer as before, so a customer can take
//! their data and leave. Taking content down stays the denylist's job.
//!
//! The list is read once at start, as upstream reads it. A write one node
//! takes and its peer refuses is a split view, so the list is part of
//! `policy_fingerprint`, and a change needs both nodes restarted with the
//! same list.

use std::collections::HashSet;

use nostr::prelude::{FromBech32, PublicKey, ToBech32};
use nostr_sdk::local_relay::WritePolicyResult;
use nostr_sdk::prelude::MachineReadablePrefix;

use crate::config::Config;

/// The keys on `NGIT_EVENT_BLACKLIST`, as lowercase hex, sorted, each once.
///
/// Upstream compares an author's npub with the entries as text
/// (`EventBlacklistConfig::check`), so an entry counts here only when it is
/// exactly the npub of a key. An nprofile, a hex key, an npub in capitals
/// or anything else that is not that text blocks nothing upstream, and
/// nothing here either: both checks refuse the same keys.
pub fn blacklisted_keys(config: &Config) -> Vec<String> {
    let mut keys: Vec<String> = config
        .event_blacklist_config()
        .blacklisted_npubs
        .iter()
        .filter_map(|entry| {
            let key = PublicKey::from_bech32(entry).ok()?;
            let npub = key.to_bech32().ok()?;
            if npub == *entry {
                Some(key.to_hex())
            } else {
                None
            }
        })
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Why a write signed by `signer_hex`, under a registration of the account
/// `tenant_hex`, is refused, or `None` when neither key is on `blacklist`.
///
/// A listed signer is told in upstream's words, which upstream itself sends
/// for any event that key signs; a listed account is named as the account.
/// Neither message contains "unregistered", the word on which the client
/// widens a registration: no registration can lift a block.
pub(crate) fn write_refusal(
    blacklist: &HashSet<String>,
    signer_hex: &str,
    tenant_hex: &str,
) -> Option<String> {
    if blacklist.contains(signer_hex) {
        Some(format!("Event author {} is blacklisted", npub(signer_hex)))
    } else if blacklist.contains(tenant_hex) {
        Some(format!("Account {} is blacklisted", npub(tenant_hex)))
    } else {
        None
    }
}

/// The relay's answer to an event the blacklist refuses: upstream's prefix,
/// `blocked:`. Relay sync takes it as final, so a refused synced event
/// completes its batch and is not asked for again on every round.
pub(crate) fn reject_blocked(reason: String) -> WritePolicyResult {
    WritePolicyResult::reject(MachineReadablePrefix::Blocked, reason)
}

fn npub(hex: &str) -> String {
    PublicKey::from_hex(hex)
        .ok()
        .and_then(|key| key.to_bech32().ok())
        .unwrap_or_else(|| hex.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use base64::Engine as _;
    use bitcoin_hashes::sha256;
    use nostr::prelude::Event;
    use nostr_sdk::prelude::{
        EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp, WritePolicy,
    };

    use super::*;
    use crate::grasp_p::admission::{is_dependency_rejection, HeldKind};
    use crate::grasp_p::{
        BlobError, BlossomOp, PrivateService, KIND_EPHEMERAL_STREAM_WRAP, KIND_REGISTRATION,
        KIND_STATE_ROOT, KIND_STREAM_WRAP,
    };

    fn npub_of(keys: &Keys) -> String {
        keys.public_key().to_bech32().expect("npub")
    }

    fn hex_of(keys: &Keys) -> String {
        keys.public_key().to_hex()
    }

    fn config_listing(entries: &[String]) -> Config {
        let mut config = Config::for_testing();
        config.event_blacklist = entries.join(",");
        config
    }

    /// The set holds exactly the keys upstream's own check refuses. A key
    /// written any other way than its npub is refused by neither, so the two
    /// checks cannot disagree about who is frozen.
    #[test]
    fn blacklisted_keys_are_the_keys_upstream_refuses() {
        let listed = Keys::generate();
        let also_listed = Keys::generate();
        let as_hex = Keys::generate();
        let in_capitals = Keys::generate();
        let entries = [
            npub_of(&also_listed),
            format!("  {}  ", npub_of(&listed)),
            npub_of(&listed),
            hex_of(&as_hex),
            npub_of(&in_capitals).to_uppercase(),
            "not a key".to_string(),
            String::new(),
        ];
        let config = config_listing(&entries);
        let upstream = config.event_blacklist_config();

        let mut expected = [hex_of(&listed), hex_of(&also_listed)];
        expected.sort();
        assert_eq!(blacklisted_keys(&config), expected);

        for keys in [&listed, &also_listed] {
            assert!(upstream.check(&npub_of(keys)).is_some());
        }
        for keys in [&as_hex, &in_capitals] {
            assert!(upstream.check(&npub_of(keys)).is_none());
        }
        assert!(blacklisted_keys(&Config::for_testing()).is_empty());
    }

    /// A listed signer or a listed account refuses the write, and the
    /// signer's message is upstream's, word for word.
    #[test]
    fn write_refusal_names_the_listed_key() {
        let account = Keys::generate();
        let signer = Keys::generate();
        let other = Keys::generate();
        let upstream = config_listing(&[npub_of(&signer)]).event_blacklist_config();

        let account_listed = HashSet::from([hex_of(&account)]);
        let signer_listed = HashSet::from([hex_of(&signer)]);
        let both_listed = HashSet::from([hex_of(&account), hex_of(&signer)]);

        assert_eq!(
            write_refusal(&account_listed, &hex_of(&signer), &hex_of(&account)),
            Some(format!("Account {} is blacklisted", npub_of(&account)))
        );
        let signer_refusal = write_refusal(&signer_listed, &hex_of(&signer), &hex_of(&account));
        assert_eq!(signer_refusal, upstream.check(&npub_of(&signer)));
        assert_eq!(
            write_refusal(&both_listed, &hex_of(&signer), &hex_of(&account)),
            signer_refusal,
            "the signer is named first"
        );
        assert!(signer_refusal.is_some());
        assert!(write_refusal(&both_listed, &hex_of(&other), &hex_of(&other)).is_none());
        assert!(write_refusal(&HashSet::new(), &hex_of(&signer), &hex_of(&account)).is_none());
        for set in [&account_listed, &signer_listed, &both_listed] {
            let message = write_refusal(set, &hex_of(&signer), &hex_of(&account))
                .expect("listed keys are refused");
            assert!(!message.contains("unregistered"), "{message}");
        }
    }

    /// A node's write policy and stores, as the server builds them, over an
    /// in-memory relay database, with `blacklist` as `NGIT_EVENT_BLACKLIST`.
    struct Node {
        _dir: tempfile::TempDir,
        runtime: crate::nostr::builder::RelayRuntime,
    }

    impl Node {
        async fn start(blacklist: &[String]) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
            let mut config = config_listing(blacklist);
            config.git_data_path = path("git");
            config.relay_data_path = path("relay");
            config.private_repos_enable = true;
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

        /// What a sender of `event` is told, from a client or, with
        /// `synced`, from relay sync; an accepted event is stored.
        async fn send_from(&self, event: &Event, synced: bool) -> WritePolicyResult {
            let addr: SocketAddr = if synced {
                "127.0.0.1:0".parse().expect("address")
            } else {
                "198.51.100.7:40000".parse().expect("address")
            };
            let result = self.runtime.write_policy.admit_event(event, &addr).await;
            if matches!(result, WritePolicyResult::Accept) {
                self.store(event).await;
            }
            result
        }

        async fn send(&self, event: &Event) -> WritePolicyResult {
            self.send_from(event, false).await
        }

        async fn store(&self, event: &Event) {
            self.runtime
                .stores
                .database
                .save_event(event)
                .await
                .expect("store the event");
        }

        async fn stored(&self, event: &Event) -> bool {
            self.runtime
                .stores
                .database
                .event_by_id(&event.id)
                .await
                .expect("lookup")
                .is_some()
        }

        /// The blob routes' authorization of `op` on `sha` for the alias of
        /// `repo`, signed by `signer`.
        async fn blob_auth(
            &self,
            signer: &Keys,
            repo: &Repo,
            op: BlossomOp,
            sha: &str,
        ) -> Result<(), BlobError> {
            let t = match op {
                BlossomOp::Upload => "upload",
                BlossomOp::Delete => "delete",
                BlossomOp::List => "list",
            };
            let now = Timestamp::now().as_secs();
            let auth = EventBuilder::new(Kind::Custom(24242), "")
                .tags(vec![
                    Tag::custom("t", vec![t.to_string()]),
                    Tag::custom("x", vec![sha.to_string()]),
                    Tag::custom("expiration", vec![(now + 600).to_string()]),
                    Tag::custom(
                        "a",
                        vec![format!("30640:{}:{}", hex_of(&repo.tenant), repo.alias)],
                    ),
                ])
                .finalize(signer)
                .expect("sign 24242");
            let header = format!(
                "Nostr {}",
                base64::prelude::BASE64_STANDARD.encode(auth.as_json())
            );
            self.svc()
                .verify_blossom_auth(Some(header.as_str()), op, sha)
                .await
                .map(|_| ())
        }
    }

    /// One private repository: its account key, a write key and its aux key.
    struct Repo {
        tenant: Keys,
        writer: Keys,
        aux: Keys,
        alias: String,
    }

    impl Repo {
        fn new() -> Self {
            Self::with_writer(Keys::generate())
        }

        fn with_writer(writer: Keys) -> Self {
            Self {
                tenant: Keys::generate(),
                writer,
                aux: Keys::generate(),
                alias: Keys::generate().public_key().to_hex()[..32].to_string(),
            }
        }

        fn key_entry(&self, key: &Keys) -> Vec<String> {
            let digest = sha256::Hash::hash(
                crate::grasp_p::registration::key_pop_input(&hex_of(&self.tenant), &self.alias)
                    .as_bytes(),
            );
            let sig = key.sign_schnorr(digest.to_byte_array());
            vec![hex_of(key), sig.to_string()]
        }

        fn registration(&self) -> Event {
            self.registration_aged(120)
        }

        /// A registration dated `age_secs` before now.
        fn registration_aged(&self, age_secs: u64) -> Event {
            EventBuilder::new(Kind::Custom(KIND_REGISTRATION), "")
                .tags(vec![
                    Tag::identifier(&self.alias),
                    Tag::custom("relays", vec!["ws://localhost:7334".to_string()]),
                    Tag::custom("server", vec!["http://localhost:7334".to_string()]),
                    Tag::custom("w", self.key_entry(&self.writer)),
                    Tag::custom("aux", self.key_entry(&self.aux)),
                ])
                .custom_created_at(Timestamp::from_secs(Timestamp::now().as_secs() - age_secs))
                .finalize(&self.tenant)
                .expect("sign 30640")
        }

        fn state_root(&self, signer: &Keys) -> Event {
            EventBuilder::new(Kind::Custom(KIND_STATE_ROOT), "")
                .tags(vec![
                    Tag::identifier(&self.alias),
                    Tag::custom(
                        "a",
                        vec![format!("30640:{}:{}", hex_of(&self.tenant), self.alias)],
                    ),
                    Tag::custom("m", vec!["ab".repeat(32), "10".to_string()]),
                ])
                .finalize(signer)
                .expect("sign 30641")
        }
    }

    fn wrap(signer: &Keys, kind: u16) -> Event {
        EventBuilder::new(Kind::Custom(kind), "ciphertext")
            .finalize(signer)
            .expect("sign wrap")
    }

    fn accepted(result: WritePolicyResult, what: &str) {
        if let WritePolicyResult::Reject {
            prefix, message, ..
        } = result
        {
            panic!("{what}: refused with {prefix}: {message}");
        }
    }

    /// The text a client is sent for a refusal; panics unless it is a
    /// `blocked:` refusal.
    fn blocked(result: WritePolicyResult, what: &str) -> String {
        match result {
            WritePolicyResult::Reject {
                prefix: MachineReadablePrefix::Blocked,
                message,
                status: false,
            } => {
                assert!(!message.contains("unregistered"), "{what}: {message}");
                message.into_owned()
            }
            WritePolicyResult::Reject {
                prefix, message, ..
            } => panic!("{what}: refused with {prefix}: {message}, expected blocked"),
            WritePolicyResult::Accept => panic!("{what}: accepted, expected blocked"),
        }
    }

    fn forbidden(result: Result<(), BlobError>, what: &str) -> String {
        match result {
            Err(BlobError::Forbidden(reason)) => reason,
            other => panic!("{what}: expected 403, got {other:?}"),
        }
    }

    /// An account on the list keeps the registration it held, and every write
    /// under it is refused: by its write key and its aux key, from a client
    /// and from sync, on the blob routes as well. Its keys register nothing,
    /// and no registration takes its seat. A key on the list is refused on
    /// the blob routes under any registration. Another account on the same
    /// node writes as before.
    #[tokio::test]
    async fn a_listed_account_is_frozen_on_every_write_path() {
        let frozen = Repo::new();
        let listed_writer = Keys::generate();
        let lent_key = Repo::with_writer(listed_writer.clone());
        let free = Repo::new();
        let node = Node::start(&[npub_of(&frozen.tenant), npub_of(&listed_writer)]).await;
        let svc = node.svc();
        let account_refusal = format!("Account {} is blacklisted", npub_of(&frozen.tenant));
        let signer_refusal = format!("Event author {} is blacklisted", npub_of(&listed_writer));

        // Upstream already refuses what the account key signs.
        let registration = frozen.registration();
        let upstream = blocked(node.send(&registration).await, "the account's registration");
        assert_eq!(
            upstream,
            format!("Event author {} is blacklisted", npub_of(&frozen.tenant))
        );

        // The registration it held before it was listed stays.
        accepted(
            svc.handle_registration(&registration).await,
            "a registration taken before the list",
        );
        node.store(&registration).await;
        assert!(svc
            .live_registration(&frozen.alias)
            .await
            .expect("liveness")
            .is_some());

        for synced in [false, true] {
            let root = frozen.state_root(&frozen.writer);
            let message = blocked(node.send_from(&root, synced).await, "state root");
            assert_eq!(message, account_refusal);
            assert!(!node.stored(&root).await);
            // Final, and never held for a registration to cure.
            assert!(!is_dependency_rejection(HeldKind::StateRoot, &message));

            let stored_wrap = wrap(&frozen.aux, KIND_STREAM_WRAP);
            let message = blocked(node.send_from(&stored_wrap, synced).await, "stream wrap");
            assert_eq!(message, account_refusal);
            assert!(!node.stored(&stored_wrap).await);
            assert!(!is_dependency_rejection(HeldKind::StreamWrap, &message));

            let ephemeral = wrap(&frozen.aux, KIND_EPHEMERAL_STREAM_WRAP);
            assert_eq!(
                blocked(node.send_from(&ephemeral, synced).await, "ephemeral wrap"),
                account_refusal
            );
            let by_writer = wrap(&frozen.writer, KIND_STREAM_WRAP);
            assert_eq!(
                blocked(
                    node.send_from(&by_writer, synced).await,
                    "wrap by the write key"
                ),
                account_refusal
            );
        }

        let sha = "cd".repeat(32);
        for op in [BlossomOp::Upload, BlossomOp::Delete] {
            let reason = forbidden(
                node.blob_auth(&frozen.writer, &frozen, op, &sha).await,
                "the frozen account's write key",
            );
            assert_eq!(reason, account_refusal, "{op:?}");
        }

        // No registration displaces the frozen seat, though it is younger
        // than an hour: one dated before it, by an account that is not
        // listed, claiming its write and aux keys with valid proofs, loses.
        let usurper = Repo {
            tenant: Keys::generate(),
            writer: frozen.writer.clone(),
            aux: frozen.aux.clone(),
            alias: Keys::generate().public_key().to_hex()[..32].to_string(),
        };
        match node.send(&usurper.registration_aged(600)).await {
            WritePolicyResult::Reject { message, .. } => {
                assert_eq!(message, "write key already registered");
            }
            WritePolicyResult::Accept => panic!("a registration displaced the frozen seat"),
        }
        assert!(svc
            .live_registration(&frozen.alias)
            .await
            .expect("liveness")
            .is_some());

        // Nor does one of its keys register an account of its own, from a
        // client or from sync.
        for signer in [&frozen.writer, &frozen.aux] {
            let own = Repo {
                tenant: signer.clone(),
                writer: Keys::generate(),
                aux: Keys::generate(),
                alias: Keys::generate().public_key().to_hex()[..32].to_string(),
            };
            for synced in [false, true] {
                assert_eq!(
                    blocked(
                        node.send_from(&own.registration(), synced).await,
                        "a registration by a key of the frozen account"
                    ),
                    account_refusal
                );
            }
            assert!(svc
                .live_registration(&own.alias)
                .await
                .expect("liveness")
                .is_none());
        }

        // A listed key that another account lists as its write key: its own
        // events are upstream's to refuse, its blob authorizations are refused
        // here.
        accepted(
            node.send(&lent_key.registration()).await,
            "an account that is not listed",
        );
        assert_eq!(
            blocked(
                node.send(&lent_key.state_root(&listed_writer)).await,
                "state root by the listed key"
            ),
            signer_refusal
        );
        for op in [BlossomOp::Upload, BlossomOp::Delete] {
            let reason = forbidden(
                node.blob_auth(&listed_writer, &lent_key, op, &sha).await,
                "the listed key",
            );
            assert_eq!(reason, signer_refusal, "{op:?}");
        }
        accepted(
            node.send(&wrap(&lent_key.aux, KIND_STREAM_WRAP)).await,
            "the other keys of that account",
        );

        // An account that is not listed is not touched.
        accepted(node.send(&free.registration()).await, "registration");
        accepted(
            node.send(&free.state_root(&free.writer)).await,
            "state root",
        );
        accepted(
            node.send(&wrap(&free.aux, KIND_STREAM_WRAP)).await,
            "stream wrap",
        );
        for op in [BlossomOp::Upload, BlossomOp::Delete] {
            node.blob_auth(&free.writer, &free, op, &sha)
                .await
                .unwrap_or_else(|e| panic!("{op:?}: {e:?}"));
        }

        // What the frozen account stored is still there.
        assert!(node.stored(&registration).await);
    }
}
