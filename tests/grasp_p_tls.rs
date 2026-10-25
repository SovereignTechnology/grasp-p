//! TLS paths of a GRASP-P node (docs/grasp-p/PLAN.md, M2).
//!
//! Every other suite talks plain http/ws on loopback, so nothing noticed when
//! the v1.2 line linked two rustls crypto providers and the relay client
//! panicked the first time it dialled a `wss://` peer. This test drives each
//! outbound TLS client of the server binary through a real handshake:
//!
//! - the blob mirror (`reqwest` on native-tls / OpenSSL) fetches blobs over
//!   `https://` and must complete the handshake and the request;
//! - upstream's NIP-11 probe (`reqwest`, a client of its own) runs over
//!   `https://` before every relay dial and must complete its handshake;
//! - the relay client (nostr-sdk on rustls with the ring provider) dials a
//!   `wss://` peer. Its trust anchors are the compiled-in webpki roots and
//!   nothing else, so it can never trust a certificate made here: the test
//!   requires the handshake to get as far as certificate verification and be
//!   refused there, which only a working provider can do. That failure puts
//!   the peer on upstream's naughty list, and the test then requires a second
//!   dial: a configured peer is not muted by it.
//!
//! Node A is an ordinary plain test node. Two in-process TLS fronts terminate
//! TLS and forward the bytes to A; node B is given the fronts as its blob
//! peer and as one of its relay peers, and the run-time CA through
//! `SSL_CERT_FILE` (read by OpenSSL only).
//!
//! What this does not prove:
//!
//! - a completed `wss://` session (the upgrade and Nostr traffic over TLS).
//!   That needs a certificate chaining to a public root;
//! - the absence of a panic by direct observation. The fixture leaves a
//!   node's stderr on the test's own, so a dial that panics inside its task
//!   is caught by what never arrives: no alert at the front and no
//!   naughty-list line in the node's log;
//! - anything about the production target policy. A loopback peer is only
//!   reachable under the fixture's permissive settings.
//!
//! ```bash
//! cargo test --test grasp_p_tls -- --nocapture
//! ```
#![cfg(target_os = "linux")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use bitcoin_hashes::sha256;
use nostr_sdk::prelude::*;
use tokio_rustls::rustls::AlertDescription;

use common::port::reserve_port;
use common::sync_helpers::wait_for_log_line;
use common::TestRelay;

use front::{Handshake, TlsFront};

/// Outer bound for every cross-process wait, as in the pair suites.
const BOUND: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Bound for one plain HTTP request from the test to a node, so a node that
/// stops answering fails the test instead of hanging the job.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

// ============================================================================
// Run-time PKI: a throwaway CA and one server certificate
// ============================================================================

mod pki {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::error::ErrorStack;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, PKeyRef, Private};
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509Builder, X509Extension, X509Name, X509NameRef, X509Ref, X509};

    /// A CA and the server certificate it issued, both made for this run.
    pub struct TestPki {
        /// CA certificate, PEM. The only part that is written to disk.
        pub ca_pem: Vec<u8>,
        /// Server certificate, DER. Valid for IP 127.0.0.1 and DNS localhost.
        pub leaf_der: Vec<u8>,
        /// Server key, PKCS#8 DER. Stays in memory.
        pub leaf_key_pkcs8: Vec<u8>,
    }

    impl TestPki {
        pub fn generate() -> Result<Self, ErrorStack> {
            let ca_key = p256_key()?;
            let ca_name = name("ngit-grasp test CA, generated at run time")?;
            let mut ca = certificate(1, &ca_name, &ca_name, &ca_key)?;
            ca.append_extension(BasicConstraints::new().critical().ca().build()?)?;
            ca.append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()?,
            )?;
            ca.sign(&ca_key, MessageDigest::sha256())?;
            let ca = ca.build();

            // A proper end-entity certificate under that CA, not a
            // self-signed one: webpki refuses a CA certificate presented as
            // the server's before it ever looks for an issuer, and the test
            // wants the "unknown issuer" refusal.
            let leaf_key = p256_key()?;
            let leaf_name = name("127.0.0.1")?;
            let mut leaf = certificate(2, &leaf_name, &ca_name, &leaf_key)?;
            leaf.append_extension(BasicConstraints::new().critical().build()?)?;
            leaf.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
            leaf.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
            let names = subject_alt_names(&leaf, &ca)?;
            leaf.append_extension(names)?;
            leaf.sign(&ca_key, MessageDigest::sha256())?;

            Ok(Self {
                ca_pem: ca.to_pem()?,
                leaf_der: leaf.build().to_der()?,
                leaf_key_pkcs8: leaf_key.private_key_to_pkcs8()?,
            })
        }
    }

    fn p256_key() -> Result<PKey<Private>, ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        PKey::from_ec_key(EcKey::generate(&group)?)
    }

    fn name(common_name: &str) -> Result<X509Name, ErrorStack> {
        let mut builder = X509Name::builder()?;
        builder.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
        Ok(builder.build())
    }

    /// The fields every certificate here shares. Extensions and the
    /// signature are added by the caller.
    fn certificate(
        serial: u32,
        subject: &X509NameRef,
        issuer: &X509NameRef,
        key: &PKeyRef<Private>,
    ) -> Result<X509Builder, ErrorStack> {
        let mut builder = X509::builder()?;
        // Version 3 (the field is zero-based). webpki accepts nothing older.
        builder.set_version(2)?;
        // Each value is bound first: a borrow of a `?` expression does not
        // coerce to the `...Ref` type these setters take.
        let serial = BigNum::from_u32(serial)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(subject)?;
        builder.set_issuer_name(issuer)?;
        builder.set_pubkey(key)?;
        // A fixed instant in the past, so a clock step during the run cannot
        // make the chain "not yet valid".
        let not_before = Asn1Time::from_str("250101000000Z")?;
        builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(2)?;
        builder.set_not_after(&not_after)?;
        Ok(builder)
    }

    fn subject_alt_names(leaf: &X509Builder, ca: &X509Ref) -> Result<X509Extension, ErrorStack> {
        SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .dns("localhost")
            .build(&leaf.x509v3_context(Some(ca), None))
    }
}

// ============================================================================
// TLS front: terminates TLS, forwards the bytes to a plain test node
// ============================================================================

mod front {
    use std::fmt;
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::{JoinHandle, JoinSet};
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{self, AlertDescription, ServerConfig};
    use tokio_rustls::TlsAcceptor;

    /// First byte of a TLS handshake record (`ContentType::Handshake`).
    const TLS_HANDSHAKE_RECORD: u8 = 0x16;
    /// Releases a connection whose peer stalls mid-handshake.
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

    /// How one accepted TCP connection ended its TLS handshake.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Handshake {
        /// Completed; the bytes were then forwarded to the node.
        Completed,
        /// The client aborted the handshake with this fatal alert.
        ClientAlert(AlertDescription),
        /// The client went away before the handshake finished. `sent_tls`
        /// tells whether it had started one: a client that dies before its
        /// ClientHello connects, sends nothing and closes.
        ClosedEarly { sent_tls: bool },
        /// Anything else.
        Failed(String),
    }

    impl fmt::Display for Handshake {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Completed => f.write_str("completed"),
                Self::ClientAlert(alert) => write!(f, "refused by the client ({alert:?})"),
                Self::ClosedEarly { sent_tls: true } => f.write_str("closed mid-handshake"),
                Self::ClosedEarly { sent_tls: false } => {
                    f.write_str("closed without sending a ClientHello")
                }
                Self::Failed(reason) => write!(f, "failed: {reason}"),
            }
        }
    }

    /// A TLS 1.3 server configuration for the run-time certificate.
    ///
    /// The provider is named, never taken from the process default: choosing
    /// that default is what broke in the server, and this fixture must not be
    /// able to fail for the same reason.
    pub fn server_config(leaf_der: Vec<u8>, leaf_key_pkcs8: Vec<u8>) -> Arc<ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf_der)],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key_pkcs8)),
            )
            .expect("run-time server certificate and key");
        Arc::new(config)
    }

    /// A loopback listener that terminates TLS and forwards to `upstream`.
    pub struct TlsFront {
        port: u16,
        outcomes: Arc<Mutex<Vec<Handshake>>>,
        accept_loop: JoinHandle<()>,
    }

    impl TlsFront {
        /// `upstream` is the `host:port` of the plain node behind the front.
        pub async fn start(config: Arc<ServerConfig>, upstream: String) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind TLS front");
            let port = listener.local_addr().expect("TLS front address").port();
            let outcomes = Arc::new(Mutex::new(Vec::new()));
            let acceptor = TlsAcceptor::from(config);
            let recorded = Arc::clone(&outcomes);
            let accept_loop = tokio::spawn(async move {
                // Owned by this task, so aborting it ends every connection.
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let Ok((tcp, _)) = accepted else { break };
                            connections.spawn(serve(
                                tcp,
                                acceptor.clone(),
                                upstream.clone(),
                                Arc::clone(&recorded),
                            ));
                        }
                        Some(_) = connections.join_next() => {}
                    }
                }
            });
            Self {
                port,
                outcomes,
                accept_loop,
            }
        }

        /// `127.0.0.1:port`, the name the certificate is valid for.
        pub fn authority(&self) -> String {
            format!("127.0.0.1:{}", self.port)
        }

        pub fn count(&self, wanted: &Handshake) -> usize {
            let outcomes = self.outcomes.lock().expect("outcomes lock");
            outcomes.iter().filter(|seen| *seen == wanted).count()
        }

        /// Handshakes any client refused, whatever the alert.
        pub fn refused(&self) -> usize {
            let outcomes = self.outcomes.lock().expect("outcomes lock");
            outcomes
                .iter()
                .filter(|seen| matches!(seen, Handshake::ClientAlert(_)))
                .count()
        }

        /// Every outcome so far, for assertion messages.
        pub fn summary(&self) -> String {
            let outcomes = self.outcomes.lock().expect("outcomes lock");
            if outcomes.is_empty() {
                return "no connection".to_string();
            }
            outcomes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        }

        /// Poll until a handshake ended as `wanted`.
        pub async fn saw(&self, wanted: &Handshake, bound: Duration) -> bool {
            let deadline = tokio::time::Instant::now() + bound;
            loop {
                if self.count(wanted) > 0 {
                    return true;
                }
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    impl Drop for TlsFront {
        fn drop(&mut self) {
            self.accept_loop.abort();
        }
    }

    async fn serve(
        tcp: TcpStream,
        acceptor: TlsAcceptor,
        upstream: String,
        outcomes: Arc<Mutex<Vec<Handshake>>>,
    ) {
        let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
            let mut first = [0_u8; 1];
            let peeked = tcp.peek(&mut first).await;
            let sent_tls = matches!(peeked, Ok(1)) && first[0] == TLS_HANDSHAKE_RECORD;
            (sent_tls, acceptor.accept(tcp).await)
        })
        .await;
        let (outcome, stream) = match handshake {
            Ok((_, Ok(stream))) => (Handshake::Completed, Some(stream)),
            Ok((sent_tls, Err(error))) => (classify(&error, sent_tls), None),
            Err(_) => (Handshake::Failed("handshake timed out".to_string()), None),
        };
        outcomes.lock().expect("outcomes lock").push(outcome);

        let Some(mut stream) = stream else { return };
        if let Ok(mut node) = TcpStream::connect(upstream.as_str()).await {
            // Ends when either side closes; a relay killed at the end of the
            // test surfaces here as an error, which is not a finding.
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut node).await;
        }
    }

    /// tokio-rustls reports a rustls failure as `io::Error` with the
    /// `rustls::Error` inside, and a peer that closed mid-handshake as
    /// `UnexpectedEof`.
    fn classify(error: &io::Error, sent_tls: bool) -> Handshake {
        let tls_error = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>());
        match tls_error {
            Some(rustls::Error::AlertReceived(alert)) => Handshake::ClientAlert(*alert),
            None if error.kind() == io::ErrorKind::UnexpectedEof => {
                Handshake::ClosedEarly { sent_tls }
            }
            _ => Handshake::Failed(error.to_string()),
        }
    }
}

// ============================================================================
// GRASP-P fixtures (as in tests/private_two_node.rs)
// ============================================================================

async fn connect_client(relay_url: &str, keys: Keys) -> Client {
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys))
        .build();
    client
        .add_relay(relay_url)
        .await
        .expect("Failed to add relay");
    common::relay::connect_client(&client).await;
    client
}

/// Publish an event and return `(accepted, relay_message)`.
async fn publish_with_result(relay_url: &str, event: &Event) -> (bool, String) {
    let client = connect_client(relay_url, Keys::generate()).await;
    let output = client
        .send_event(event)
        .await
        .expect("send_event transport failure");
    let accepted = !output.success.is_empty();
    let message = output
        .failed
        .values()
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    client.disconnect().await;
    (accepted, message)
}

/// A valid alias: exactly 32 lowercase hex chars.
fn random_alias() -> String {
    Keys::generate().public_key().to_hex()[..32].to_string()
}

fn sha256_hex(data: &[u8]) -> String {
    sha256::Hash::hash(data).to_string()
}

/// Coordinate of a 30640 registration.
fn reg_coord(tenant: &PublicKey, alias: &str) -> String {
    format!("30640:{}:{alias}", tenant.to_hex())
}

/// Schnorr proof-of-possession for a claimed write key.
fn key_pop_sig(key: &Keys, tenant: &PublicKey, alias: &str) -> String {
    let digest =
        sha256::Hash::hash(format!("grasp-p key-claim:{}:{alias}", tenant.to_hex()).as_bytes());
    key.sign_schnorr(digest.to_byte_array()).to_string()
}

/// Signed kind-30640 registration listing every node in `domains`.
fn registration_event(tenant: &Keys, alias: &str, writer: &Keys, domains: &[&str]) -> Event {
    let relays: Vec<String> = domains.iter().map(|d| format!("ws://{d}")).collect();
    let servers: Vec<String> = domains.iter().map(|d| format!("http://{d}")).collect();
    let write_key = vec![
        writer.public_key().to_hex(),
        key_pop_sig(writer, &tenant.public_key(), alias),
    ];
    EventBuilder::new(Kind::Custom(30640), "")
        .tags(vec![
            Tag::identifier(alias),
            Tag::custom("relays", relays),
            Tag::custom("server", servers),
            Tag::custom("w", write_key),
        ])
        .finalize(tenant)
        .expect("sign 30640")
}

/// Signed kind-30641 state root: `m` manifest + `pack` blobs.
fn state_root_event(
    writer: &Keys,
    tenant: &PublicKey,
    alias: &str,
    manifest: (&str, u64),
    packs: &[(String, u64)],
) -> Event {
    let mut tags = vec![
        Tag::identifier(alias),
        Tag::custom("a", vec![reg_coord(tenant, alias)]),
        Tag::custom("m", vec![manifest.0.to_string(), manifest.1.to_string()]),
    ];
    for (hash, size) in packs {
        tags.push(Tag::custom("pack", vec![hash.clone(), size.to_string()]));
    }
    EventBuilder::new(Kind::Custom(30641), "")
        .tags(tags)
        .finalize(writer)
        .expect("sign 30641")
}

/// Signed kind-24242 Blossom upload authorization.
fn blossom_auth_event(signer: &Keys, sha: &str, tenant: &PublicKey, alias: &str) -> Event {
    EventBuilder::new(Kind::Custom(24242), "grasp-p tls test auth")
        .tags(vec![
            Tag::custom("t", vec!["upload".to_string()]),
            Tag::custom("x", vec![sha.to_string()]),
            Tag::custom(
                "expiration",
                vec![(Timestamp::now().as_secs() + 600).to_string()],
            ),
            Tag::custom("a", vec![reg_coord(tenant, alias)]),
        ])
        .finalize(signer)
        .expect("sign 24242")
}

/// Deterministic blob content of `len` bytes, unique per seed.
fn blob_bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (seed as usize)
                .wrapping_mul(31)
                .wrapping_add(i.wrapping_mul(2654435761)) as u8
        })
        .collect()
}

/// PUT a blob to `relay` under (tenant, alias) signed by `writer`.
async fn upload_blob(
    relay: &TestRelay,
    tenant: &Keys,
    writer: &Keys,
    alias: &str,
    data: &[u8],
) -> String {
    let sha = sha256_hex(data);
    let auth = blossom_auth_event(writer, &sha, &tenant.public_key(), alias);
    let response = reqwest::Client::new()
        .put(format!("http://{}/upload", relay.domain()))
        .header(
            "authorization",
            format!("Nostr {}", BASE64_STANDARD.encode(auth.as_json())),
        )
        .header("x-sha-256", sha.as_str())
        .body(data.to_vec())
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .expect("PUT /upload transport");
    assert_eq!(
        response.status().as_u16(),
        200,
        "blob PUT must be 200; X-Reason: {:?}",
        response.headers().get("x-reason")
    );
    sha
}

/// Poll until `GET /<sha>` on `relay` returns 200 with sha-verified bytes.
async fn wait_for_blob(relay: &TestRelay, sha: &str, bound: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + bound;
    loop {
        let response = reqwest::Client::new()
            .get(format!("http://{}/{sha}", relay.domain()))
            .timeout(HTTP_TIMEOUT)
            .send()
            .await
            .expect("GET /<sha> transport");
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .unwrap_or_default();
        if status == 200 && sha256_hex(&body) == sha {
            return Some(body);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ============================================================================
// The test
// ============================================================================

#[tokio::test]
async fn outbound_tls_clients_complete_or_refuse_a_real_handshake() {
    let tenant = Keys::generate();
    let writer = Keys::generate();
    let alias = random_alias();
    let whitelist = tenant.public_key().to_bech32().expect("npub");

    // Node A: the origin, plain http/ws like every other test node.
    let a = TestRelay::start_grasp_p_pair_node(
        reserve_port(),
        None,
        true,
        None,
        None,
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;

    // A CA for this run, and two TLS fronts for A that present its
    // certificate: one is B's blob peer, the other one of B's relay peers.
    // Two listeners keep the two kinds of client apart without parsing
    // anything.
    let pki = pki::TestPki::generate().expect("generate the run-time CA and certificate");
    let pki_dir = tempfile::tempdir().expect("temporary directory for the CA certificate");
    let ca_file = pki_dir.path().join("ca.pem");
    std::fs::write(&ca_file, pki.ca_pem).expect("write the CA certificate");
    let tls = front::server_config(pki.leaf_der, pki.leaf_key_pkcs8);
    let blob_front = TlsFront::start(Arc::clone(&tls), a.domain()).await;
    let relay_front = TlsFront::start(tls, a.domain()).await;

    // Node B: syncs events from A over plain ws, may fetch blobs only
    // through `blob_front`, and has `relay_front` as a second relay peer.
    let blob_peer = format!("https://{}", blob_front.authority());
    let wss_peer = format!("wss://{}", relay_front.authority());
    let relay_peers = format!("{},{wss_peer}", a.url());
    let b = TestRelay::start_grasp_p_pair_node(
        reserve_port(),
        Some(a.url().to_string()),
        true,
        None,
        None,
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("NGIT_GRASP_P_MIRROR_PEER_URLS", blob_peer.as_str()),
            ("NGIT_GRASP_P_SYNC_PEER_URLS", relay_peers.as_str()),
            // OpenSSL's trust store for this process only: the run-time CA.
            (
                "SSL_CERT_FILE",
                ca_file.to_str().expect("temporary path is UTF-8"),
            ),
            // reqwest honours proxy variables; loopback must never be proxied.
            ("NO_PROXY", "127.0.0.1"),
            ("no_proxy", "127.0.0.1"),
            // A relay dial may take no longer than the base backoff (1 s in
            // the fixture). Give the first attempt room on a loaded CI VM: a
            // transient failure is redialled with this backoff, a certificate
            // failure is naughty-listed at once.
            ("NGIT_SYNC_BASE_BACKOFF_SECS", "10"),
        ],
    )
    .await;

    // ---- wss ---------------------------------------------------------------
    // B accepts the wss peer and dials it. Both loopback guards are open in
    // the fixture: NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS for the GRASP-P SSRF
    // guard, NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS for upstream's target policy.
    assert!(
        wait_for_log_line(&b.log_path(), BOUND, |line| {
            line.contains("Registering private-repo peer relay") && line.contains(&wss_peer)
        })
        .await,
        "B must register {wss_peer} as a private-repo peer relay"
    );

    // The relay client reached certificate verification and refused the
    // unknown CA. A client that cannot pick a crypto provider never sends a
    // ClientHello, and one that cannot run the key schedule cannot send this
    // alert: in TLS 1.3 it travels encrypted under the handshake keys.
    let refused = Handshake::ClientAlert(AlertDescription::UnknownCA);
    assert!(
        relay_front.saw(&refused, BOUND).await,
        "B's relay client must start a TLS handshake with {wss_peer} and refuse the \
         certificate as issued by an unknown CA; the front saw: {}",
        relay_front.summary()
    );

    // Upstream's NIP-11 probe precedes every relay dial and is a reqwest
    // client of its own: it trusted the CA and completed its handshake.
    assert!(
        relay_front.count(&Handshake::Completed) >= 1,
        "the NIP-11 probe that precedes the relay dial must complete a TLS handshake; \
         the front saw: {}",
        relay_front.summary()
    );

    // B drew the right conclusion from the failure instead of losing the
    // task that made the attempt.
    assert!(
        wait_for_log_line(&b.log_path(), BOUND, |line| {
            line.contains("added to naughty list")
                && line.contains(&wss_peer)
                && line.contains("TlsCertificateInvalid")
        })
        .await,
        "B must record {wss_peer} as a relay with an invalid TLS certificate"
    );

    // For any other relay that entry means no dial for twelve hours. This
    // one is a configured peer: B dials it again by itself, so a peer whose
    // certificate is put right is found without a restart. The second
    // refusal at the front is that second dial.
    let redial_deadline = Instant::now() + BOUND;
    while relay_front.count(&refused) < 2 {
        assert!(
            Instant::now() < redial_deadline,
            "B must dial its configured peer {wss_peer} again although it is on the \
             naughty list; the front saw: {}",
            relay_front.summary()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ---- https -------------------------------------------------------------
    // Everything from here on also shows that B is alive and still syncing
    // after the failed dial.
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(String::as_str).collect();
    let registration = registration_event(&tenant, &alias, &writer, &domain_refs);
    let (accepted, message) = publish_with_result(a.url(), &registration).await;
    assert!(accepted, "30640 must be accepted on A; got {message:?}");

    // The pack spans several TLS records.
    let manifest = blob_bytes(1, 2048);
    let pack = blob_bytes(2, 100_000);
    let manifest_sha = upload_blob(&a, &tenant, &writer, &alias, &manifest).await;
    let pack_sha = upload_blob(&a, &tenant, &writer, &alias, &pack).await;
    let edition = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias,
        (&manifest_sha, manifest.len() as u64),
        &[(pack_sha.clone(), pack.len() as u64)],
    );
    let (accepted, message) = publish_with_result(a.url(), &edition).await;
    assert!(accepted, "30641 must be accepted on A; got {message:?}");

    // B's only blob peer is the TLS front, so a blob served by B came
    // through a completed handshake and a full request.
    let mirrored_manifest = wait_for_blob(&b, &manifest_sha, BOUND)
        .await
        .unwrap_or_else(|| {
            panic!(
                "manifest must be mirrored to B over https; the front saw: {}",
                blob_front.summary()
            )
        });
    assert_eq!(mirrored_manifest, manifest, "manifest bytes intact");
    let mirrored_pack = wait_for_blob(&b, &pack_sha, BOUND)
        .await
        .unwrap_or_else(|| {
            panic!(
                "pack must be mirrored to B over https; the front saw: {}",
                blob_front.summary()
            )
        });
    assert_eq!(mirrored_pack, pack, "pack bytes intact");

    // The route as B recorded it: each blob was fetched from the https peer,
    // not from A's plain address, which the registration also lists.
    for sha in [&manifest_sha, &pack_sha] {
        assert!(
            wait_for_log_line(&b.log_path(), BOUND, |line| {
                line.contains("blob fetched from peer")
                    && line.contains(&blob_peer)
                    && line.contains(sha.as_str())
            })
            .await,
            "B must log blob {sha} as fetched from {blob_peer}"
        );
    }

    assert!(
        blob_front.count(&Handshake::Completed) >= 1,
        "the blob mirror must complete a TLS handshake; the front saw: {}",
        blob_front.summary()
    );
    assert_eq!(
        blob_front.refused(),
        0,
        "the blob mirror must trust the CA in SSL_CERT_FILE; the front saw: {}",
        blob_front.summary()
    );

    b.stop().await;
    a.stop().await;
}
