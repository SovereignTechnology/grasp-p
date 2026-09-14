//! Reconnect failure history must survive short-lived successful handshakes.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::flapping_relay::FlappingRelay;
use crate::common::{TestClient, TestRelay};

#[tokio::test]
async fn discovery_only_mailbox_keeps_failure_history_through_cleanup() {
    use crate::common::{send_to_relay_url, setup_announcement_on_relay, MockRelay};

    let index = MockRelay::start().await;
    let flapping = FlappingRelay::start().await;
    let owner = Keys::generate();
    let relay_list = EventBuilder::new(Kind::RelayList, "")
        .tags([Tag::custom("r", vec![flapping.url(), "read"])])
        .finalize(&owner)
        .unwrap();
    send_to_relay_url(index.url(), &relay_list).await.unwrap();
    let syncing = TestRelay::start_with_sync(Some(index.url().to_string())).await;
    let domain = syncing.domain();
    let (_announcement, _git) =
        setup_announcement_on_relay(&syncing, &owner, &[&domain], "discovery-mailbox-backoff")
            .await;

    // Owner inbox discovery has no ordinary repository/root live target.
    // The two-second cleanup pass previously erased its first failure before
    // the next handshake, so it could never reach this recovery state.
    flapping
        .wait_for_connections(2, Duration::from_secs(60))
        .await;
    let logs = wait_for_log(
        &syncing.log_path(),
        "consecutive_failures=1",
        Duration::from_secs(15),
    )
    .await;
    assert!(logs.lines().any(|line| {
        line.contains(flapping.url())
            && line.contains("consecutive_failures=1")
            && line.contains("preserving failure streak until stable")
    }));

    syncing.stop().await;
    flapping.stop().await;
    index.stop().await;
}

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
        Duration::from_secs(20),
    )
    .await;
    assert!(logs.contains("preserving failure streak until stable"));

    client.disconnect().await;
    syncing.stop().await;
    flapping.stop().await;
}
