//! E2E test for the `ngit-private-watchdog` binary (Phase-4b WP-F).
//!
//! Drives a real two-node private pair (helpers mirrored from
//! `tests/private_two_node.rs`), asserts the watchdog reports full parity on
//! a healthy pair (head + get blob probes, JSON report), then
//! partitions the pair (B restarted on its persistent paths with no sync
//! peer) and asserts the split-view findings: `reason=diverged` for the
//! edition A has moved past, `reason=withheld-30641` for the alias B never
//! learned of, FAIL blob-existence for the unmirrored blob, FAIL lines on
//! stderr, and grace-window suppression via --max-skew-secs.
//!
//! Review-round-1 legs (FW-2): a dead node exits 2 (never divergence), and
//! ambiguous blob-base derivation wedges ONLY the blob-dependent check —
//! checks 1-3 still print (human + json), exit 2 without divergence and
//! exit 1 when a divergence FAIL is present (divergence dominates).
//!
//! Review-round-2 leg (R2-4): `server` tags differing ONLY by path resolve
//! to the path-empty blob base (exit 0, no operator flags); genuine
//! ambiguity (one endpoint spelled two ways, no unique path-empty
//! candidate) still wedges only check 4 per the FW-2 legs.
//!
//! ```bash
//! cargo test --test private_watchdog -- --nocapture --test-threads=1
//! ```

mod common;

use std::time::{Duration, Instant};

use base64::Engine as _;
use bitcoin_hashes::{sha256, Hash};
use nostr_sdk::prelude::*;

use common::port::reserve_port;
use common::TestRelay;

const BOUND: Duration = Duration::from_secs(90);
const POLL: Duration = Duration::from_millis(250);

async fn connect_client(relay_url: &str, keys: Keys) -> Client {
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys))
        .build();
    client.add_relay(relay_url).await.expect("add relay");
    client.connect().await;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if client
            .relays()
            .await
            .values()
            .any(|r| r.status().is_connected())
        {
            return client;
        }
    }
    panic!("connect to {relay_url}");
}

async fn publish_with_result(relay_url: &str, event: &Event) -> (bool, String) {
    let client = connect_client(relay_url, Keys::generate()).await;
    let output = client.send_event(event).await.expect("send_event");
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

async fn fetch_from(relay_url: &str, filter: Filter) -> Vec<Event> {
    let client = connect_client(relay_url, Keys::generate()).await;
    let events = client
        .fetch_events(filter)
        .timeout(Duration::from_secs(10))
        .await
        .expect("fetch_events");
    client.disconnect().await;
    events.into_iter().collect()
}

fn random_alias() -> String {
    Keys::generate().public_key().to_hex()[..32].to_string()
}

fn sha256_hex(data: &[u8]) -> String {
    sha256::Hash::hash(data).to_string()
}

fn reg_coord(tenant: &PublicKey, alias: &str) -> String {
    format!("30640:{}:{alias}", tenant.to_hex())
}

fn key_pop_sig(key: &Keys, tenant: &PublicKey, alias: &str) -> String {
    let digest =
        sha256::Hash::hash(format!("grasp-p key-claim:{}:{alias}", tenant.to_hex()).as_bytes());
    key.sign_schnorr(digest.to_byte_array()).to_string()
}

fn registration_event(
    tenant: &Keys,
    alias: &str,
    writer: &Keys,
    domains: &[&str],
    created_at: Option<u64>,
) -> Event {
    let relays: Vec<String> = domains.iter().map(|d| format!("ws://{d}")).collect();
    let servers: Vec<String> = domains.iter().map(|d| format!("http://{d}")).collect();
    let tags = vec![
        Tag::identifier(alias),
        Tag::custom("relays", relays),
        Tag::custom("server", servers),
        Tag::custom(
            "w",
            vec![
                writer.public_key().to_hex(),
                key_pop_sig(writer, &tenant.public_key(), alias),
            ],
        ),
    ];
    let mut builder = EventBuilder::new(Kind::Custom(30640), "");
    if let Some(secs) = created_at {
        builder = builder.custom_created_at(Timestamp::from_secs(secs));
    }
    builder.tags(tags).finalize(tenant).expect("sign 30640")
}

/// Multi-server-tag fixture: ONE `server` tag per value (the watchdog
/// reads the first value of every `server` tag, so several values for one
/// host must arrive as separate tags). Used for both the genuinely
/// ambiguous blob-base fixture (R2-4: same endpoint spelled two ways, no
/// unique path-empty candidate) and the path-tie fixture (path-ful +
/// path-empty values, which R2-4 resolves to the path-empty one).
fn registration_event_multi_servers(
    tenant: &Keys,
    alias: &str,
    writer: &Keys,
    relay_domains: &[&str],
    server_domains: &[&str],
) -> Event {
    let mut tags = vec![
        Tag::identifier(alias),
        Tag::custom(
            "relays",
            relay_domains
                .iter()
                .map(|d| format!("ws://{d}"))
                .collect::<Vec<_>>(),
        ),
    ];
    for d in server_domains {
        tags.push(Tag::custom("server", vec![format!("http://{d}")]));
    }
    tags.push(Tag::custom(
        "w",
        vec![
            writer.public_key().to_hex(),
            key_pop_sig(writer, &tenant.public_key(), alias),
        ],
    ));
    EventBuilder::new(Kind::Custom(30640), "")
        .tags(tags)
        .finalize(tenant)
        .expect("sign 30640")
}

fn state_root_event(
    writer: &Keys,
    tenant: &PublicKey,
    alias: &str,
    manifest: (&str, u64),
    packs: &[(String, u64)],
    created_at: u64,
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
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize(writer)
        .expect("sign 30641")
}

fn blossom_auth_event(signer: &Keys, sha: &str, tenant: &PublicKey, alias: &str) -> Event {
    EventBuilder::new(Kind::Custom(24242), "watchdog smoke auth")
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

fn blob_bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (seed as usize)
                .wrapping_mul(31)
                .wrapping_add(i.wrapping_mul(2654435761)) as u8
        })
        .collect()
}

async fn put_blob(relay: &TestRelay, data: Vec<u8>, sha: &str, auth: &Event) -> (u16, String) {
    let client = reqwest::Client::new();
    let response = client
        .put(format!("http://{}/upload", relay.domain()))
        .header(
            "authorization",
            format!(
                "Nostr {}",
                base64::prelude::BASE64_STANDARD.encode(auth.as_json())
            ),
        )
        .header("x-sha-256", sha)
        .body(data)
        .send()
        .await
        .expect("PUT blob");
    let status = response.status().as_u16();
    let reason = response
        .headers()
        .get("x-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (status, reason)
}

async fn get_blob(relay: &TestRelay, sha: &str) -> (u16, Vec<u8>) {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/{sha}", relay.domain()))
        .send()
        .await
        .expect("GET blob");
    let status = response.status().as_u16();
    let body = response.bytes().await.expect("body").to_vec();
    (status, body)
}

async fn upload_blob(
    relay: &TestRelay,
    tenant: &Keys,
    writer: &Keys,
    alias: &str,
    data: &[u8],
) -> String {
    let sha = sha256_hex(data);
    let auth = blossom_auth_event(writer, &sha, &tenant.public_key(), alias);
    let (status, reason) = put_blob(relay, data.to_vec(), &sha, &auth).await;
    assert_eq!(status, 200, "blob PUT must be 200; X-Reason: {reason}");
    sha
}

async fn wait_for_blob(relay: &TestRelay, sha: &str) {
    let deadline = Instant::now() + BOUND;
    loop {
        let (status, body) = get_blob(relay, sha).await;
        if status == 200 && sha256_hex(&body) == sha {
            return;
        }
        assert!(Instant::now() < deadline, "blob {sha} never appeared");
        tokio::time::sleep(POLL).await;
    }
}

async fn wait_for_event(relay_url: &str, filter: Filter, want: usize, what: &str) -> Vec<Event> {
    let deadline = Instant::now() + BOUND;
    loop {
        let events = fetch_from(relay_url, filter.clone()).await;
        if events.len() >= want {
            return events;
        }
        assert!(Instant::now() < deadline, "{what} never replicated");
        tokio::time::sleep(POLL).await;
    }
}

struct WatchdogOut {
    code: i32,
    stdout: String,
    stderr: String,
}

async fn run_watchdog(args: &[String]) -> WatchdogOut {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_ngit-private-watchdog"))
        .args(args)
        .output()
        .await
        .expect("spawn watchdog");
    WatchdogOut {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

#[tokio::test]
async fn watchdog_e2e_happy_then_partitioned() {
    // Pair on explicit persistent paths (both nodes restartable).
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_a = format!("ws://127.0.0.1:{}", res_a.port());
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());
    let dir = tempfile::tempdir().expect("tmpdir");
    let paths = |n: &str| {
        (
            dir.path().join(format!("git-{n}")),
            dir.path().join(format!("relay-{n}")),
        )
    };
    let (a_git, a_relay) = paths("a");
    let (b_git, b_relay) = paths("b");
    // Whitelist default (post-WP-E): the tenant must be whitelisted on both
    // nodes before any registration is admitted.
    let tenant = Keys::generate();
    let whitelist = tenant.public_key().to_bech32().expect("npub");
    let a = TestRelay::start_grasp_p_pair_node(
        res_a,
        Some(url_b.clone()),
        true,
        Some(a_git.clone()),
        Some(a_relay.clone()),
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;
    let b = TestRelay::start_grasp_p_pair_node(
        res_b,
        Some(url_a.clone()),
        true,
        Some(b_git.clone()),
        Some(b_relay.clone()),
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;
    let domains = [a.domain(), b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let writer = Keys::generate();
    let alias1 = random_alias();
    let reg = registration_event(&tenant, &alias1, &writer, &domain_refs, None);
    let (accepted, msg) = publish_with_result(a.url(), &reg).await;
    assert!(accepted, "30640 rejected: {msg}");
    wait_for_event(
        b.url(),
        Filter::new().kind(Kind::Custom(30640)).identifier(&alias1),
        1,
        "30640",
    )
    .await;

    let blob1 = upload_blob(&a, &tenant, &writer, &alias1, &blob_bytes(21, 512)).await;

    let t0 = Timestamp::now().as_secs() - 3600;
    let v1 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias1,
        (&blob1, 512),
        &[],
        t0,
    );
    let (accepted, msg) = publish_with_result(a.url(), &v1).await;
    assert!(accepted, "30641 v1 rejected: {msg}");
    wait_for_event(
        b.url(),
        Filter::new().kind(Kind::Custom(30641)).identifier(&alias1),
        1,
        "30641 v1",
    )
    .await;
    // The mirror enqueues on 30641 acceptance; blob follows the event.
    wait_for_blob(&b, &blob1).await;

    let base_args = vec![
        "--relay-a".to_string(),
        a.url().to_string(),
        "--relay-b".to_string(),
        b.url().to_string(),
        "--blob-base-a".to_string(),
        format!("http://{}", a.domain()),
        "--blob-base-b".to_string(),
        format!("http://{}", b.domain()),
        "--timeout-secs".to_string(),
        "10".to_string(),
    ];

    // ---- happy path: head probe ----
    let happy = run_watchdog(&base_args).await;
    assert_eq!(
        happy.code, 0,
        "happy run failed:\n{}\n{}",
        happy.stdout, happy.stderr
    );
    assert!(
        happy.stdout.contains("PASS fingerprint-parity"),
        "{}",
        happy.stdout
    );
    assert!(
        happy.stdout.contains("PASS registration-parity"),
        "{}",
        happy.stdout
    );
    assert!(
        happy.stdout.contains("PASS manifest-parity"),
        "{}",
        happy.stdout
    );
    assert!(
        happy.stdout.contains("PASS blob-existence"),
        "{}",
        happy.stdout
    );
    assert!(
        happy.stdout.contains("PASS kinds-parity"),
        "the advertised accepted-kind set is its own check line:\n{}",
        happy.stdout
    );
    // The policy VERSION label prints next to the digest, so a version skew
    // is distinguishable from a same-version knob split at a glance.
    assert!(
        happy.stdout.contains("policy-a=grasp-p-policy-v")
            && happy.stdout.contains("policy-b=grasp-p-policy-v"),
        "fingerprint-parity must report the policy_version of both nodes:\n{}",
        happy.stdout
    );
    assert!(!happy.stdout.contains("FAIL"), "{}", happy.stdout);
    assert!(happy.stderr.is_empty(), "{}", happy.stderr);

    // ---- happy path: get probe (hash-verified) ----
    let mut get_args = base_args.clone();
    get_args.extend(["--blob-probe".to_string(), "get".to_string()]);
    let get = run_watchdog(&get_args).await;
    assert_eq!(
        get.code, 0,
        "get probe failed:\n{}\n{}",
        get.stdout, get.stderr
    );

    // ---- happy path: json report ----
    // The watchdog holds no key, and GET /list answers only the listed key,
    // so there is no list comparison: the report must not carry one.
    let mut json_args = base_args.clone();
    json_args.push("--json".to_string());
    let json = run_watchdog(&json_args).await;
    assert_eq!(
        json.code, 0,
        "json run failed:\n{}\n{}",
        json.stdout, json.stderr
    );
    let report: serde_json::Value =
        serde_json::from_str(&json.stdout).expect("watchdog --json must emit JSON");
    assert_eq!(report["ok"], true);
    assert_eq!(report["exit_code"], 0);
    let checks = report["checks"].as_array().expect("checks array");
    assert!(
        checks
            .iter()
            .any(|c| c["check"] == "blob-existence" && c["status"] == "PASS"),
        "{report}"
    );
    assert!(
        !checks.iter().any(|c| c["check"] == "list-parity"),
        "{report}"
    );

    // ---- partition: B down, fresh editions land on A only ----
    b.stop().await;
    let blob2 = upload_blob(&a, &tenant, &writer, &alias1, &blob_bytes(22, 256)).await;
    let v2 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias1,
        (&blob2, 256),
        &[(blob1.clone(), 512)],
        t0 + 1800, // beyond the 300s default grace
    );
    let (accepted, msg) = publish_with_result(a.url(), &v2).await;
    assert!(accepted, "30641 v2 rejected: {msg}");

    let alias2 = random_alias();
    let writer2 = Keys::generate();
    let reg2 = registration_event(&tenant, &alias2, &writer2, &domain_refs, None);
    let (accepted, msg) = publish_with_result(a.url(), &reg2).await;
    assert!(accepted, "30640 alias2 rejected: {msg}");
    let v3 = state_root_event(
        &writer2,
        &tenant.public_key(),
        &alias2,
        (&blob2, 256),
        &[],
        t0 + 1800,
    );
    let (accepted, msg) = publish_with_result(a.url(), &v3).await;
    assert!(accepted, "30641 v3 rejected: {msg}");

    // Restart B on its persistent paths WITHOUT any bootstrap peer: it keeps
    // v1 and never learns of v2/alias2. (Its fingerprint also changes —
    // asserted separately.)
    let res_b2 = reserve_port();
    let b2 = TestRelay::start_grasp_p_pair_node(
        res_b2,
        None,
        true,
        Some(b_git),
        Some(b_relay),
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;

    let split_args = vec![
        "--relay-a".to_string(),
        a.url().to_string(),
        "--relay-b".to_string(),
        b2.url().to_string(),
        "--blob-base-a".to_string(),
        format!("http://{}", a.domain()),
        "--blob-base-b".to_string(),
        format!("http://{}", b2.domain()),
        "--timeout-secs".to_string(),
        "10".to_string(),
    ];
    let split = run_watchdog(&split_args).await;
    assert_eq!(
        split.code, 1,
        "split run:\n{}\n{}",
        split.stdout, split.stderr
    );
    assert!(
        split.stdout.contains("FAIL fingerprint-parity"),
        "{}",
        split.stdout
    );
    assert!(
        split.stdout.contains("reason=diverged"),
        "alias1 diverged:\n{}",
        split.stdout
    );
    assert!(
        split.stdout.contains("reason=withheld-30641"),
        "alias2 withheld:\n{}",
        split.stdout
    );
    assert!(
        split.stdout.contains("FAIL blob-existence"),
        "{}",
        split.stdout
    );
    // FAIL lines are echoed to stderr for journal/cron alerting.
    assert!(
        split.stderr.contains("FAIL manifest-parity"),
        "{}",
        split.stderr
    );
    assert!(split.stderr.contains("WATCHDOG ALERT"), "{}", split.stderr);

    // Within-grace re-run: a skew window above the edition ages must turn the
    // manifest findings back into PASS (withheld/diverged suppressed).
    let mut grace_args = split_args.clone();
    grace_args.extend(["--max-skew-secs".to_string(), "7200".to_string()]);
    let grace = run_watchdog(&grace_args).await;
    assert_eq!(
        grace.code, 1,
        "grace run:\n{}\n{}",
        grace.stdout, grace.stderr
    );
    assert!(!grace.stdout.contains("withheld-30641"), "{}", grace.stdout);
    assert!(
        !grace.stdout.contains("reason=diverged"),
        "{}",
        grace.stdout
    );

    a.stop().await;
    b2.stop().await;
}

/// FW-2 / review L3-F11: a dead node is an operational error (exit 2),
/// never divergence — and nothing is half-reported.
#[tokio::test]
async fn watchdog_dead_node_is_operational_error() {
    let res_a = reserve_port();
    let a = TestRelay::start_grasp_p_pair_node(res_a, None, true, None, None, &[]).await;
    // Reserved but never started: connections are refused immediately.
    let dead = reserve_port();
    let out = run_watchdog(&[
        "--relay-a".to_string(),
        a.url().to_string(),
        "--relay-b".to_string(),
        format!("ws://127.0.0.1:{}", dead.port()),
        "--timeout-secs".to_string(),
        "3".to_string(),
    ])
    .await;
    assert_eq!(
        out.code, 2,
        "dead-node run:\n{}\n{}",
        out.stdout, out.stderr
    );
    assert!(
        out.stderr.contains("WATCHDOG OPERATIONAL ERROR"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("WATCHDOG ALERT"), "{}", out.stderr);
    assert!(!out.stdout.contains("FAIL"), "{}", out.stdout);
    // Human mode prints no half-report when the run aborts before checks.
    assert!(out.stdout.trim().is_empty(), "{}", out.stdout);
    a.stop().await;
}

/// FW-2 / review L3-F1: ambiguous blob-base derivation must wedge ONLY the
/// blob-dependent check (4) — checks 1-3 always print, in human AND json
/// mode; exit 2 without divergence, exit 1 when a divergence FAIL is present
/// (divergence dominates).
#[tokio::test]
async fn watchdog_ambiguous_bases_do_not_mask_checks() {
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_a = format!("ws://127.0.0.1:{}", res_a.port());
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());
    let dir = tempfile::tempdir().expect("tmpdir");
    let paths = |n: &str| {
        (
            dir.path().join(format!("git-{n}")),
            dir.path().join(format!("relay-{n}")),
        )
    };
    let (a_git, a_relay) = paths("a");
    let (b_git, b_relay) = paths("b");
    let tenant = Keys::generate();
    let whitelist = tenant.public_key().to_bech32().expect("npub");
    let a = TestRelay::start_grasp_p_pair_node(
        res_a,
        Some(url_b.clone()),
        true,
        Some(a_git),
        Some(a_relay),
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;
    let b = TestRelay::start_grasp_p_pair_node(
        res_b,
        Some(url_a.clone()),
        true,
        Some(b_git.clone()),
        Some(b_relay.clone()),
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;

    // Registration with TWO path-empty spellings of each node's endpoint
    // (plain and leading-zero port): same scheme/host/effective port but no
    // UNIQUE path-empty candidate — derivation is genuinely ambiguous for
    // both nodes by construction (post-R2-4 a mere path-only tie would
    // resolve to the path-empty candidate instead of erroring).
    let writer = Keys::generate();
    let alias1 = random_alias();
    let relay_domains = [a.domain(), b.domain()];
    let relay_refs: Vec<&str> = relay_domains.iter().map(|s| s.as_str()).collect();
    let zero_port = |domain: &str| {
        format!(
            "127.0.0.1:0{}",
            domain.rsplit(':').next().expect("host:port")
        )
    };
    let server_domains = [
        a.domain(),
        zero_port(&a.domain()),
        b.domain(),
        zero_port(&b.domain()),
    ];
    let server_refs: Vec<&str> = server_domains.iter().map(|s| s.as_str()).collect();
    let reg =
        registration_event_multi_servers(&tenant, &alias1, &writer, &relay_refs, &server_refs);
    let (accepted, msg) = publish_with_result(a.url(), &reg).await;
    assert!(accepted, "30640 rejected: {msg}");
    wait_for_event(
        b.url(),
        Filter::new().kind(Kind::Custom(30640)).identifier(&alias1),
        1,
        "30640",
    )
    .await;

    let blob1 = upload_blob(&a, &tenant, &writer, &alias1, &blob_bytes(31, 512)).await;
    let t0 = Timestamp::now().as_secs() - 3600;
    let v1 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias1,
        (&blob1, 512),
        &[],
        t0,
    );
    let (accepted, msg) = publish_with_result(a.url(), &v1).await;
    assert!(accepted, "30641 v1 rejected: {msg}");
    wait_for_event(
        b.url(),
        Filter::new().kind(Kind::Custom(30641)).identifier(&alias1),
        1,
        "30641 v1",
    )
    .await;
    wait_for_blob(&b, &blob1).await;

    // No --blob-base flags: derivation must hit the ambiguity.
    let base_args = vec![
        "--relay-a".to_string(),
        a.url().to_string(),
        "--relay-b".to_string(),
        b.url().to_string(),
        "--timeout-secs".to_string(),
        "10".to_string(),
    ];

    // ---- leg 1: healthy pair + ambiguous bases -> exit 2, checks 1-3 print
    let amb = run_watchdog(&base_args).await;
    assert_eq!(
        amb.code, 2,
        "ambiguous run:\n{}\n{}",
        amb.stdout, amb.stderr
    );
    assert!(
        amb.stdout.contains("PASS fingerprint-parity"),
        "{}",
        amb.stdout
    );
    assert!(
        amb.stdout.contains("PASS registration-parity"),
        "{}",
        amb.stdout
    );
    assert!(
        amb.stdout.contains("PASS manifest-parity"),
        "{}",
        amb.stdout
    );
    assert!(
        amb.stdout.contains("ERROR blob-existence"),
        "{}",
        amb.stdout
    );
    // The ERROR line steers to the explicit-base flags.
    assert!(amb.stdout.contains("--blob-base-a"), "{}", amb.stdout);
    assert!(!amb.stdout.contains("FAIL"), "{}", amb.stdout);
    assert!(
        amb.stderr.contains("WATCHDOG OPERATIONAL ERROR"),
        "{}",
        amb.stderr
    );
    assert!(!amb.stderr.contains("WATCHDOG ALERT"), "{}", amb.stderr);

    // ---- leg 1b: --json: all completed results are in the machine report
    // too.
    let mut json_args = base_args.clone();
    json_args.push("--json".to_string());
    let amb_json = run_watchdog(&json_args).await;
    assert_eq!(
        amb_json.code, 2,
        "ambiguous json run:\n{}\n{}",
        amb_json.stdout, amb_json.stderr
    );
    let report: serde_json::Value =
        serde_json::from_str(&amb_json.stdout).expect("watchdog --json must emit JSON");
    assert_eq!(report["ok"], false);
    assert_eq!(report["exit_code"], 2);
    assert!(
        report["operational_errors"]
            .as_array()
            .is_some_and(|e| !e.is_empty()),
        "{report}"
    );
    let checks = report["checks"].as_array().expect("checks array");
    let has = |check: &str, status: &str| {
        checks
            .iter()
            .any(|c| c["check"] == check && c["status"] == status)
    };
    assert!(has("fingerprint-parity", "PASS"), "{report}");
    assert!(has("registration-parity", "PASS"), "{report}");
    assert!(has("manifest-parity", "PASS"), "{report}");
    assert!(has("blob-existence", "ERROR"), "{report}");

    // ---- leg 2: partition + divergence -> exit 1 (divergence dominates),
    // FAIL manifest-parity prints alongside ERROR blob-existence.
    b.stop().await;
    let blob2 = upload_blob(&a, &tenant, &writer, &alias1, &blob_bytes(32, 256)).await;
    let v2 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias1,
        (&blob2, 256),
        &[(blob1.clone(), 512)],
        t0 + 1800, // beyond the 300s default grace
    );
    let (accepted, msg) = publish_with_result(a.url(), &v2).await;
    assert!(accepted, "30641 v2 rejected: {msg}");

    let res_b2 = reserve_port();
    let b2 = TestRelay::start_grasp_p_pair_node(
        res_b2,
        None,
        true,
        Some(b_git),
        Some(b_relay),
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;
    let split_args = vec![
        "--relay-a".to_string(),
        a.url().to_string(),
        "--relay-b".to_string(),
        b2.url().to_string(),
        "--timeout-secs".to_string(),
        "10".to_string(),
    ];
    let split = run_watchdog(&split_args).await;
    assert_eq!(
        split.code, 1,
        "ambiguous split run:\n{}\n{}",
        split.stdout, split.stderr
    );
    assert!(
        split.stdout.contains("FAIL manifest-parity"),
        "{}",
        split.stdout
    );
    assert!(split.stdout.contains("reason=diverged"), "{}", split.stdout);
    assert!(
        split.stdout.contains("ERROR blob-existence"),
        "{}",
        split.stdout
    );
    assert!(split.stderr.contains("WATCHDOG ALERT"), "{}", split.stderr);
    assert!(
        split.stderr.contains("WATCHDOG OPERATIONAL ERROR"),
        "{}",
        split.stderr
    );

    a.stop().await;
    b2.stop().await;
}

/// R2-4: tenant server tags differing ONLY by path (path-empty + path-ful
/// per node, same scheme/host/effective port) resolve to the path-empty
/// blob base deterministically — derivation no longer wedges the
/// blob-dependent checks into a chronic exit 2, no --blob-base flags
/// needed.
#[tokio::test]
async fn watchdog_path_tie_bases_resolve_to_empty_path() {
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_a = format!("ws://127.0.0.1:{}", res_a.port());
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());
    let tenant = Keys::generate();
    let whitelist = tenant.public_key().to_bech32().expect("npub");
    let a = TestRelay::start_grasp_p_pair_node(
        res_a,
        Some(url_b.clone()),
        true,
        None,
        None,
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;
    let b = TestRelay::start_grasp_p_pair_node(
        res_b,
        Some(url_a.clone()),
        true,
        None,
        None,
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;

    // Path-only tie per node: bare endpoint AND a /mirror path variant.
    let writer = Keys::generate();
    let alias1 = random_alias();
    let relay_domains = [a.domain(), b.domain()];
    let relay_refs: Vec<&str> = relay_domains.iter().map(|s| s.as_str()).collect();
    let server_domains = [
        a.domain(),
        format!("{}/mirror", a.domain()),
        b.domain(),
        format!("{}/mirror", b.domain()),
    ];
    let server_refs: Vec<&str> = server_domains.iter().map(|s| s.as_str()).collect();
    let reg =
        registration_event_multi_servers(&tenant, &alias1, &writer, &relay_refs, &server_refs);
    let (accepted, msg) = publish_with_result(a.url(), &reg).await;
    assert!(accepted, "30640 rejected: {msg}");
    wait_for_event(
        b.url(),
        Filter::new().kind(Kind::Custom(30640)).identifier(&alias1),
        1,
        "30640",
    )
    .await;

    let blob1 = upload_blob(&a, &tenant, &writer, &alias1, &blob_bytes(41, 512)).await;
    let t0 = Timestamp::now().as_secs() - 3600;
    let v1 = state_root_event(
        &writer,
        &tenant.public_key(),
        &alias1,
        (&blob1, 512),
        &[],
        t0,
    );
    let (accepted, msg) = publish_with_result(a.url(), &v1).await;
    assert!(accepted, "30641 v1 rejected: {msg}");
    wait_for_event(
        b.url(),
        Filter::new().kind(Kind::Custom(30641)).identifier(&alias1),
        1,
        "30641 v1",
    )
    .await;
    wait_for_blob(&b, &blob1).await;

    // No --blob-base flags: derivation must resolve each node's path tie to
    // the path-empty base, and the run fully passes.
    let out = run_watchdog(&[
        "--relay-a".to_string(),
        a.url().to_string(),
        "--relay-b".to_string(),
        b.url().to_string(),
        "--timeout-secs".to_string(),
        "10".to_string(),
    ])
    .await;
    assert_eq!(out.code, 0, "path-tie run:\n{}\n{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("PASS blob-existence"), "{}", out.stdout);
    assert!(!out.stdout.contains("ERROR"), "{}", out.stdout);
    assert!(out.stderr.is_empty(), "{}", out.stderr);

    a.stop().await;
    b.stop().await;
}

/// A mixed-version pair mid wire-kind migration (A dual-accepts the legacy
/// stream-wrap kinds, B has retired them) must be reported as a KIND split
/// on its own named check line.
///
/// Before this check, a wrap-kind split was only inferable from the opaque
/// `policy_fingerprint` digest — which also moves for a dozen unrelated
/// knobs, and moves on EVERY node when the preimage label bumps. An
/// operator watching only `fingerprint-parity` cannot tell "rolling upgrade
/// in progress" from "these two nodes permanently disagree about which
/// wraps they store". Both distinctions are pinned here.
#[tokio::test]
async fn watchdog_reports_wrap_kind_split() {
    let res_a = reserve_port();
    let res_b = reserve_port();
    let url_a = format!("ws://127.0.0.1:{}", res_a.port());
    let url_b = format!("ws://127.0.0.1:{}", res_b.port());
    let tenant = Keys::generate();
    let whitelist = tenant.public_key().to_bech32().expect("npub");

    // The ONLY divergence is the legacy wrap-kind acceptance.
    let a = TestRelay::start_grasp_p_pair_node(
        res_a,
        Some(url_b),
        true,
        None,
        None,
        &[("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str())],
    )
    .await;
    let b = TestRelay::start_grasp_p_pair_node(
        res_b,
        Some(url_a),
        true,
        None,
        None,
        &[
            ("NGIT_GRASP_P_TENANT_WHITELIST", whitelist.as_str()),
            ("NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND", "false"),
        ],
    )
    .await;

    let out = run_watchdog(&[
        "--relay-a".to_string(),
        a.url().to_string(),
        "--relay-b".to_string(),
        b.url().to_string(),
        "--timeout-secs".to_string(),
        "10".to_string(),
    ])
    .await;

    assert_eq!(
        out.code, 1,
        "a kind split is divergence, not an operational error:\n{}\n{}",
        out.stdout, out.stderr
    );
    assert!(
        out.stdout.contains("FAIL kinds-parity"),
        "the split must be reported as a KIND split, not inferred from the \
         fingerprint digest:\n{}",
        out.stdout
    );
    // Named explicitly: exactly the legacy wrap kinds, only on A.
    assert!(
        out.stdout.contains("only-a=1059,21059") && out.stdout.contains("only-b=-"),
        "the check must name which kinds diverge and on which side:\n{}",
        out.stdout
    );
    // Same policy version on both -> a real knob split, NOT a version skew.
    assert!(
        out.stdout.contains("FAIL fingerprint-parity"),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("SAME-VERSION knob split"),
        "with both nodes on the same policy_version the operator must be told \
         this is a real divergence, not a rolling upgrade in flight:\n{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("VERSION SKEW"),
        "no label bump is in play here:\n{}",
        out.stdout
    );

    a.stop().await;
    b.stop().await;
}

/// An operator tells which build a node runs from `--version`, and the
/// release job refuses a binary whose version does not name its commit. That
/// job runs only after a merge, so the same line is checked here first, on
/// both binaries and on the `serve` subcommand, which sets a version of its
/// own.
#[test]
fn both_binaries_name_the_grasp_p_build_in_their_version() {
    let build = ngit_grasp::grasp_p::build_info::version();
    assert!(build.contains(" (grasp-p "), "{build}");

    // Run from an empty directory: the server reads `.env` from where it is
    // started, before it parses its arguments.
    let dir = tempfile::tempdir().expect("tmpdir");
    let server = env!("CARGO_BIN_EXE_ngit-grasp");
    let watchdog = env!("CARGO_BIN_EXE_ngit-private-watchdog");
    for (binary, args) in [
        (server, &["--version"][..]),
        (server, &["serve", "--version"][..]),
        (watchdog, &["--version"][..]),
    ] {
        let out = std::process::Command::new(binary)
            .args(args)
            .current_dir(dir.path())
            .output()
            .expect("run the binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.trim_end().ends_with(&format!(" {build}")),
            "{binary} {args:?} printed {stdout:?}, which does not end with {build:?}"
        );
    }
}
