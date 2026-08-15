//! Scenario regression coverage for relay naughty-list scheduling.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::common::{TestClient, TestRelay};
use nostr_sdk::prelude::*;
use tokio::io::AsyncWriteExt;

const OBSERVATION_DEADLINE: Duration = Duration::from_secs(30);
const RECONNECT_OBSERVATION: Duration = Duration::from_secs(4);

async fn wait_for_log_line<F>(log_path: &Path, predicate: F) -> bool
where
    F: Fn(&str) -> bool,
{
    let deadline = tokio::time::Instant::now() + OBSERVATION_DEADLINE;
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

/// A reachable TCP endpoint that deliberately violates the WebSocket
/// handshake. This produces a persistent protocol failure without relying on
/// external DNS or network state.
async fn start_broken_websocket() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind broken websocket endpoint");
    let address = listener.local_addr().expect("broken endpoint address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let task_accepted = Arc::clone(&accepted);

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            task_accepted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(b"not a websocket handshake\r\n").await;
            let _ = stream.shutdown().await;
        }
    });

    (format!("ws://{address}"), accepted)
}

#[tokio::test]
async fn naughty_relay_is_not_scheduled_for_reconnection() {
    let relay = TestRelay::start_with_sync(None).await;
    let (broken_relay, accepted) = start_broken_websocket().await;
    let keys = Keys::generate();
    let identifier = "naughty-relay-scheduling";
    let npub = keys.public_key().to_bech32().expect("npub");
    let own_clone = format!("http://{}/{npub}/{identifier}.git", relay.domain());
    let own_relay = format!("ws://{}", relay.domain());
    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom("clone", vec![own_clone]),
            Tag::custom("relays", vec![own_relay, broken_relay.clone()]),
        ])
        .finalize(&keys)
        .expect("sign announcement");

    let client = TestClient::new(relay.url(), keys)
        .await
        .expect("connect client");
    client
        .send_event(&announcement)
        .await
        .expect("publish announcement");

    assert!(
        wait_for_log_line(&relay.log_path(), |line| {
            line.contains("added to naughty list") && line.contains(&broken_relay)
        })
        .await,
        "broken endpoint must be classified as naughty"
    );
    // The first attempt opens two connections: the pre-dial NIP-11 probe
    // (GRASP-08 private-service detection) and the WebSocket dial itself.
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "first dial is required");

    let reconnect_deadline = tokio::time::Instant::now() + RECONNECT_OBSERVATION;
    while tokio::time::Instant::now() < reconnect_deadline && accepted.load(Ordering::SeqCst) == 2 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "a naughty relay must not receive another dial across reconnect ticks"
    );
    let log = tokio::fs::read_to_string(relay.log_path())
        .await
        .expect("read relay log");
    assert!(
        !log.lines().any(|line| {
            line.contains("Attempting reconnection relay=") && line.contains(&broken_relay)
        }),
        "a naughty relay must be excluded before reconnect intent is logged"
    );

    client.disconnect().await;
    relay.stop().await;
}
