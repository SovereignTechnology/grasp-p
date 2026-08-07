//! A relay that vanishes during NIP-11 setup must not be reported connected.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::setup_drop_relay::SetupDropRelay;
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
async fn disconnect_during_nip11_fetch_rejects_stale_connection_success() {
    let source = SetupDropRelay::start().await;
    let syncing = TestRelay::start_with_sync(None).await;
    let keys = Keys::generate();
    let identifier = "stale-connect-result";
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
                    source.url().to_string(),
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
        .expect("publish setup-drop relay announcement");

    wait_for_log(
        &syncing.log_path(),
        "Rejecting stale connection success after relay disconnected during setup",
        Duration::from_secs(15),
    )
    .await;
    let logs = wait_for_log(
        &syncing.log_path(),
        "degraded, backoff 1s",
        Duration::from_secs(5),
    )
    .await;
    assert!(!logs.contains("First connection - initiating fresh_start"));

    client.disconnect().await;
    syncing.stop().await;
    source.stop().await;
}
