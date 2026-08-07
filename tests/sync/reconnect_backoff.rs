//! Reconnect failure history must survive short-lived successful handshakes.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::flapping_relay::FlappingRelay;
use crate::common::{TestClient, TestRelay};

async fn wait_for_log(log_path: &std::path::Path, needle: &str, timeout: Duration) -> String {
    tokio::time::timeout(timeout, async {
        loop {
            let contents = std::fs::read_to_string(log_path).unwrap_or_default();
            if contents.contains(needle) {
                return contents;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("relay log never contained {needle:?}"))
}

#[tokio::test]
async fn flapping_relay_handshakes_do_not_reset_exponential_backoff() {
    let flapping = FlappingRelay::start().await;
    let syncing = TestRelay::start_with_sync(None).await;
    let keys = Keys::generate();
    let identifier = "flapping-reconnect-backoff";
    let npub = keys.public_key().to_bech32().expect("npub");
    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{npub}/{identifier}.git",
                    syncing.domain()
                )],
            ),
            Tag::custom(
                "relays",
                vec![
                    format!("ws://{}", syncing.domain()),
                    flapping.url().to_string(),
                ],
            ),
        ])
        .finalize(&keys)
        .expect("sign announcement");
    let client = TestClient::new(syncing.url(), keys)
        .await
        .expect("connect publishing client");
    client
        .send_event(&announcement)
        .await
        .expect("publish flapping relay announcement");

    // The recovered session must retain the first failure instead of treating
    // its WebSocket handshake as proof of stability. Each session reaches a
    // normal REQ before the fixture drops it. Unit coverage below the actor
    // boundary verifies that the retained count drives the next backoff step.
    let attempts = flapping
        .wait_for_connections(2, Duration::from_secs(25))
        .await;
    assert_eq!(attempts.len(), 2);
    let logs = wait_for_log(
        &syncing.log_path(),
        "consecutive_failures=1",
        Duration::from_secs(5),
    )
    .await;
    assert!(logs.contains("preserving failure streak until stable"));

    client.disconnect().await;
    syncing.stop().await;
    flapping.stop().await;
}
