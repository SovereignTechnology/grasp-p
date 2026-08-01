//! Outbound Target Policy Regression Tests
//!
//! Repository announcements, state events, and PR events are untrusted input,
//! but their `relays` and `clone` tags feed proactive sync's outbound
//! WebSocket connections and `git fetch` subprocesses. These tests prove that
//! event-directed URLs pointing at loopback, private, link-local, or
//! local-name targets are rejected before any outbound connection is made
//! (SSRF protection), while the operator-configured bootstrap relay keeps
//! working even when it is local.
//!
//! Unlike the rest of the suite, these tests run the relay with the
//! production outbound target policy (the `TestRelay` fixture normally sets
//! `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` because the whole test
//! infrastructure lives on loopback).
//!
//! Observability: rejected targets produce `Rejecting event-directed ...`
//! warnings in the relay subprocess log (a bounded observable condition), and
//! attacker endpoints are real TCP listeners that count every accepted
//! connection, proving no dial or fetch reached them.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::{create_state_event, MockRelay, TestClient, TestRelay};
use nostr_sdk::prelude::*;

/// A commit hash that exists nowhere, keeping state events in purgatory so
/// the git sync loop must try the announced clone URLs.
const MISSING_COMMIT: &str = "1111111111111111111111111111111111111111";

/// Deadline for log-based observable conditions. Generous for loaded CI.
const LOG_DEADLINE: Duration = Duration::from_secs(30);

/// Start a TCP listener standing in for attacker infrastructure on loopback.
///
/// Returns the port and a counter of accepted connections. Any accepted
/// connection means the relay dialled an event-directed forbidden target.
async fn start_counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting listener");
    let port = listener.local_addr().expect("listener addr").port();
    let count = Arc::new(AtomicUsize::new(0));
    let task_count = Arc::clone(&count);
    tokio::spawn(async move {
        loop {
            if listener.accept().await.is_ok() {
                task_count.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (port, count)
}

/// Wait until some line of the relay subprocess log satisfies the predicate.
async fn wait_for_log_line<F>(log_path: &Path, timeout: Duration, predicate: F) -> bool
where
    F: Fn(&str) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(content) = tokio::fs::read_to_string(log_path).await {
            if content.lines().any(&predicate) {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Build a repository announcement with explicit clone and relay URL lists.
fn announcement_with_urls(
    keys: &Keys,
    identifier: &str,
    clone_urls: Vec<String>,
    relay_urls: Vec<String>,
) -> Event {
    announcement_with_urls_at(keys, identifier, clone_urls, relay_urls, Timestamp::now())
}

/// Same as [`announcement_with_urls`] with an explicit `created_at`, so a
/// test can publish a genuine replacement (newer timestamp, different id).
fn announcement_with_urls_at(
    keys: &Keys,
    identifier: &str,
    clone_urls: Vec<String>,
    relay_urls: Vec<String>,
    created_at: Timestamp,
) -> Event {
    EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom("clone", clone_urls),
            Tag::custom("relays", relay_urls),
        ])
        .custom_created_at(created_at)
        .finalize(keys)
        .expect("sign announcement")
}

/// Clone URL for the relay's own service, so announcements are admitted.
fn own_clone_url(relay: &TestRelay, keys: &Keys, identifier: &str) -> String {
    let npub = keys.public_key().to_bech32().expect("npub");
    format!("http://{}/{}/{}.git", relay.domain(), npub, identifier)
}

/// Scenario 1: an announcement listing a loopback relay URL must not cause an
/// outbound WebSocket connection.
#[tokio::test]
async fn event_directed_loopback_relay_is_rejected_without_connection() {
    let relay = TestRelay::start_with_sync_enforced_outbound_policy(None).await;
    let (attacker_port, connection_count) = start_counting_listener().await;
    let attacker_relay = format!("ws://127.0.0.1:{attacker_port}");

    let keys = Keys::generate();
    let identifier = "loopback-relay-target";
    let announcement = announcement_with_urls(
        &keys,
        identifier,
        vec![own_clone_url(&relay, &keys, identifier)],
        vec![format!("ws://{}", relay.domain()), attacker_relay.clone()],
    );

    let client = TestClient::new(relay.url(), keys.clone())
        .await
        .expect("connect to relay");
    client
        .send_event(&announcement)
        .await
        .expect("announcement listing the service must be admitted");

    let rejected = wait_for_log_line(&relay.log_path(), LOG_DEADLINE, |line| {
        line.contains("Rejecting event-directed sync relay target")
            && line.contains(&attacker_relay)
    })
    .await;
    assert!(
        rejected,
        "relay must log rejection of the loopback event-directed relay target"
    );
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        0,
        "no outbound connection may reach the loopback relay target"
    );

    client.disconnect().await;
    relay.stop().await;
}

/// Scenario 2: an announcement listing a loopback git clone URL must not
/// cause a `git fetch` (or any request) to that endpoint.
#[tokio::test]
async fn event_directed_loopback_git_url_is_rejected_without_fetch() {
    let relay = TestRelay::start_with_sync_enforced_outbound_policy(None).await;
    let (attacker_port, connection_count) = start_counting_listener().await;
    let attacker_git = format!("http://127.0.0.1:{attacker_port}/repo.git");

    let keys = Keys::generate();
    let identifier = "loopback-git-target";
    let own_url = own_clone_url(&relay, &keys, identifier);
    let own_relay = format!("ws://{}", relay.domain());

    // Backdated so the later republication is a genuine replacement.
    let announcement = announcement_with_urls_at(
        &keys,
        identifier,
        vec![own_url.clone(), attacker_git.clone()],
        vec![own_relay.clone()],
        Timestamp::from(Timestamp::now().as_secs().saturating_sub(5)),
    );
    // A state event whose commit exists nowhere keeps the identifier pending,
    // so the purgatory git sync loop must try the announced clone URLs.
    let state = create_state_event(
        &keys,
        identifier,
        &[("main", MISSING_COMMIT)],
        &[],
        &[own_url.as_str(), attacker_git.as_str()],
        &[own_relay.as_str()],
    )
    .expect("build state event");

    let client = TestClient::new(relay.url(), keys.clone())
        .await
        .expect("connect to relay");
    client
        .send_event(&announcement)
        .await
        .expect("announcement listing the service must be admitted");
    client
        .send_event(&state)
        .await
        .expect("state event must be admitted to purgatory");

    // A directly submitted state event waits three minutes before the git
    // sync loop tries its clone URLs. Republishing the announcement while
    // events are pending re-enqueues the identifier for immediate sync,
    // which is the ordinary "author updates the announcement" flow.
    let refreshed = announcement_with_urls(
        &keys,
        identifier,
        vec![own_url.clone(), attacker_git.clone()],
        vec![own_relay.clone()],
    );
    client
        .send_event(&refreshed)
        .await
        .expect("republished announcement must be admitted");

    let rejected = wait_for_log_line(&relay.log_path(), LOG_DEADLINE, |line| {
        line.contains("Rejecting event-directed git fetch target") && line.contains(&attacker_git)
    })
    .await;
    assert!(
        rejected,
        "relay must log rejection of the loopback event-directed git fetch target"
    );
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        0,
        "no git fetch or request may reach the loopback git target"
    );

    client.disconnect().await;
    relay.stop().await;
}

/// Scenario 3: private, link-local, CGNAT, unspecified, and multicast literal
/// IP addresses are all rejected for event-directed relay targets.
/// `100.125.184.46` reproduces the address observed in production logs.
#[tokio::test]
async fn event_directed_non_global_ip_relays_are_rejected() {
    let relay = TestRelay::start_with_sync_enforced_outbound_policy(None).await;

    let forbidden_relays = [
        "ws://10.11.12.13:4444".to_string(),
        "ws://169.254.9.9:4444".to_string(),
        "ws://100.125.184.46:7334".to_string(),
        "ws://0.0.0.0:4444".to_string(),
        "ws://224.0.0.1:4444".to_string(),
    ];

    let keys = Keys::generate();
    let identifier = "non-global-ip-targets";
    let mut relay_urls = vec![format!("ws://{}", relay.domain())];
    relay_urls.extend(forbidden_relays.iter().cloned());
    let announcement = announcement_with_urls(
        &keys,
        identifier,
        vec![own_clone_url(&relay, &keys, identifier)],
        relay_urls,
    );

    let client = TestClient::new(relay.url(), keys.clone())
        .await
        .expect("connect to relay");
    client
        .send_event(&announcement)
        .await
        .expect("announcement listing the service must be admitted");

    for target in &forbidden_relays {
        let rejected = wait_for_log_line(&relay.log_path(), LOG_DEADLINE, |line| {
            line.contains("Rejecting event-directed sync relay target") && line.contains(target)
        })
        .await;
        assert!(rejected, "{target} must be rejected as a sync relay target");
    }

    client.disconnect().await;
    relay.stop().await;
}

/// Scenario 4: local hostnames and URLs with embedded credentials are
/// rejected for event-directed targets.
#[tokio::test]
async fn event_directed_local_hostname_and_credential_urls_are_rejected() {
    let relay = TestRelay::start_with_sync_enforced_outbound_policy(None).await;
    let (local_port, connection_count) = start_counting_listener().await;
    let localhost_relay = format!("ws://localhost:{local_port}");
    let credential_relay = "wss://user:secret@203.0.113.9:4444".to_string();

    let keys = Keys::generate();
    let identifier = "local-name-and-credentials";
    let announcement = announcement_with_urls(
        &keys,
        identifier,
        vec![own_clone_url(&relay, &keys, identifier)],
        vec![
            format!("ws://{}", relay.domain()),
            localhost_relay.clone(),
            credential_relay.clone(),
        ],
    );

    let client = TestClient::new(relay.url(), keys.clone())
        .await
        .expect("connect to relay");
    client
        .send_event(&announcement)
        .await
        .expect("announcement listing the service must be admitted");

    let localhost_rejected = wait_for_log_line(&relay.log_path(), LOG_DEADLINE, |line| {
        line.contains("Rejecting event-directed sync relay target")
            && line.contains(&localhost_relay)
    })
    .await;
    assert!(
        localhost_rejected,
        "localhost relay target must be rejected"
    );
    // The credential URL may be refused by URL canonicalization or by the
    // outbound policy; either way it must show up as rejected, not connected.
    let credentials_rejected = wait_for_log_line(&relay.log_path(), LOG_DEADLINE, |line| {
        line.contains("Rejecting") && line.contains("203.0.113.9")
    })
    .await;
    assert!(
        credentials_rejected,
        "credential-bearing relay target must be rejected"
    );
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        0,
        "no outbound connection may reach the localhost relay target"
    );

    client.disconnect().await;
    relay.stop().await;
}

/// Scenarios 5 and 6: the exact operator-configured bootstrap relay remains
/// usable even though it is local, while an event-provided URL that resembles
/// it (same port, `localhost` spelling) is still rejected.
#[tokio::test]
async fn operator_bootstrap_relay_allowed_but_resembling_event_url_rejected() {
    let mock = MockRelay::start().await;
    let mock_url = mock.url().to_string();
    let mock_port = mock_url
        .rsplit(':')
        .next()
        .and_then(|port| port.parse::<u16>().ok())
        .expect("mock relay port");

    let relay = TestRelay::start_with_sync_enforced_outbound_policy(Some(mock_url.clone())).await;

    // Operator-configured bootstrap: connects despite being loopback.
    let connected = wait_for_log_line(&relay.log_path(), LOG_DEADLINE, |line| {
        line.contains("Connected to relay") && line.contains(&mock_url)
    })
    .await;
    assert!(
        connected,
        "operator-configured loopback bootstrap relay must stay connectable"
    );

    // Event-provided URL resembling the bootstrap exception (same port,
    // localhost spelling) must not inherit the exception.
    let resembling_relay = format!("ws://localhost:{mock_port}");
    let keys = Keys::generate();
    let identifier = "resembles-bootstrap";
    let announcement = announcement_with_urls(
        &keys,
        identifier,
        vec![own_clone_url(&relay, &keys, identifier)],
        vec![format!("ws://{}", relay.domain()), resembling_relay.clone()],
    );

    let client = TestClient::new(relay.url(), keys.clone())
        .await
        .expect("connect to relay");
    client
        .send_event(&announcement)
        .await
        .expect("announcement listing the service must be admitted");

    let rejected = wait_for_log_line(&relay.log_path(), LOG_DEADLINE, |line| {
        line.contains("Rejecting event-directed sync relay target")
            && line.contains(&resembling_relay)
    })
    .await;
    assert!(
        rejected,
        "an event URL resembling the bootstrap relay must still be rejected"
    );

    client.disconnect().await;
    relay.stop().await;
    mock.stop().await;
}

/// Scenario 7: service admission compares parsed hostname and port, so an
/// announcement embedding our domain in a path or as a suffix of another
/// host must not be admitted as "listing the service".
#[tokio::test]
async fn announcement_embedding_domain_in_foreign_urls_is_not_admitted() {
    // The permissive fixture is fine here: service admission is independent
    // of the outbound reachability policy.
    let relay = TestRelay::start().await;

    let keys = Keys::generate();
    let identifier = "substring-admission";
    // Old substring matching admitted both of these because they contain the
    // configured domain; exact host:port comparison must not.
    let announcement = announcement_with_urls(
        &keys,
        identifier,
        vec![format!(
            "http://evil.example/{}/{}.git",
            relay.domain(),
            identifier
        )],
        vec![format!("ws://evil.example/{}", relay.domain())],
    );

    let client = TestClient::new(relay.url(), keys.clone())
        .await
        .expect("connect to relay");
    let result = client.send_event(&announcement).await;
    assert!(
        result.is_err(),
        "announcement embedding the service domain in foreign URLs must be rejected"
    );

    client.disconnect().await;
    relay.stop().await;
}
