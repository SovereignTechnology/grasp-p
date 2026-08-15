//! Outbound Authentication and GRASP-08 Private-Service Sync Policy
//!
//! These tests cover how a syncing instance treats relays that demand
//! authentication or advertise the GRASP-08 private-service extension:
//!
//! - A PUBLIC instance recognizes a GRASP-08 private service from its NIP-11
//!   document before dialing, and parks it without any WebSocket connection
//!   or AUTH exchange.

use std::time::Duration;

use crate::common::{wait_for_log_line, TestRelay};
use nostr_sdk::prelude::*;

/// The stable park warning emitted when a public instance excludes a
/// GRASP-08 private service from sync.
const PARK_LOG: &str = "Relay advertises GRASP-08 private service; excluding it from public sync";

/// A public instance must never dial a relay whose NIP-11 advertises
/// GRASP-08: the private service would only refuse it, and dialing would
/// leak an AUTH exchange to a service that never admits this mirror.
#[tokio::test]
async fn public_instance_parks_grasp08_relay_without_dialing() {
    let member = Keys::generate();
    let private_service = TestRelay::start_private(&member.public_key()).await;
    let syncing =
        TestRelay::start_with_sync_without_user_index(Some(private_service.url().to_string()))
            .await;

    let parked = wait_for_log_line(&syncing.log_path(), Duration::from_secs(30), |line| {
        line.contains(PARK_LOG) && line.contains(private_service.url())
    })
    .await;
    assert!(
        parked,
        "public instance must park its GRASP-08 bootstrap relay"
    );

    // Absence over time (see relay_identity.rs for the sanctioned pattern):
    // across a 2s observation window the parked relay is never connected to,
    // no NIP-42 authentication happens, and the park warning is not repeated.
    let window_end = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let log = tokio::fs::read_to_string(syncing.log_path())
            .await
            .unwrap_or_default();
        assert!(
            !log.lines()
                .any(|line| line.contains("Connected") && line.contains(private_service.url())),
            "parked GRASP-08 relay must never be dialed"
        );
        assert!(
            !log.lines()
                .any(|line| line.contains("Authenticated to relay")),
            "no NIP-42 exchange may happen with a parked relay"
        );
        assert_eq!(
            log.lines().filter(|line| line.contains(PARK_LOG)).count(),
            1,
            "park warning must be logged exactly once"
        );
        if tokio::time::Instant::now() >= window_end {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    syncing.stop().await;
    private_service.stop().await;
}
