//! Outbound Authentication and GRASP-08 Private-Service Sync Policy
//!
//! These tests cover how a syncing instance treats relays that demand
//! authentication or advertise the GRASP-08 private-service extension:
//!
//! - A PUBLIC instance recognizes a GRASP-08 private service from its NIP-11
//!   document before dialing, and parks it without any WebSocket connection
//!   or AUTH exchange.
//! - A public instance answers NIP-42 challenges from an ordinary
//!   authenticated relay with the relay owner key and syncs through it.
//! - A `restricted:` CLOSED after successful authentication is terminal:
//!   subscription work parks via the policy-refusal machinery instead of
//!   retrying.

use std::time::Duration;

use crate::common::{
    reserve_port, send_to_relay_url, wait_for_log_line, AuthGatingRelay, GateMode, MockRelay,
    TestRelay,
};
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

/// A public instance answers an ordinary relay's NIP-42 challenge with the
/// relay owner key and syncs through the authenticated session.
#[tokio::test]
async fn public_instance_authenticates_to_gated_relay_and_syncs() {
    let maintainer = Keys::generate();
    let identifier = "outbound-auth-admit";

    // The gate is the syncing relay's ONLY event source, so anything that
    // reaches it must have crossed the authenticated bridge.
    let backend = MockRelay::start().await;
    let gate = AuthGatingRelay::start(backend.url(), GateMode::Admit).await;

    // The syncing relay's address must appear in the announcement before it
    // boots, so its port is reserved up front.
    let reservation = reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", reservation.port());

    // Announcement listing the syncing relay (in both clone and relays tags,
    // for admission) plus the gate as the peer relay.
    let npub = maintainer.public_key().to_bech32().expect("npub");
    let clone_url = format!("http://{syncing_domain}/{npub}/{identifier}.git");
    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom("clone", vec![clone_url]),
            Tag::custom(
                "relays",
                vec![format!("ws://{syncing_domain}"), gate.url().to_string()],
            ),
        ])
        .finalize(&maintainer)
        .expect("signed announcement");
    send_to_relay_url(backend.url(), &announcement)
        .await
        .expect("seed announcement on backend");

    let syncing = TestRelay::start_on_reservation_with_sync_without_user_index(
        reservation,
        Some(gate.url().to_string()),
    )
    .await;

    // The announcement is admitted to purgatory on the syncing relay - proof
    // that a subscription refused pre-auth was answered after NIP-42.
    let synced = wait_for_log_line(&syncing.log_path(), Duration::from_secs(60), |line| {
        line.contains("Added announcement to purgatory") && line.contains(identifier)
    })
    .await;
    assert!(
        synced,
        "announcement must sync through the authenticated gate"
    );
    assert!(
        gate.authenticated_pubkeys()
            .contains(&syncing.owner_keys().public_key()),
        "syncing relay must authenticate with its owner key"
    );

    syncing.stop().await;
    gate.stop().await;
    backend.stop().await;
}

/// A `restricted:` CLOSED after valid authentication parks subscription work
/// via the policy-refusal machinery: no retry storm follows.
#[tokio::test]
async fn restricted_after_authentication_is_terminal() {
    let backend = MockRelay::start().await;
    let gate = AuthGatingRelay::start(backend.url(), GateMode::Restricted).await;
    let syncing = TestRelay::start_with_sync_without_user_index(Some(gate.url().to_string())).await;

    let refused = wait_for_log_line(&syncing.log_path(), Duration::from_secs(60), |line| {
        line.contains("Relay policy refused subscription") && line.contains("restricted")
    })
    .await;
    assert!(
        refused,
        "restricted CLOSED must be recorded as a policy refusal"
    );

    // No retry storm: within a bounded settling deadline the gate's REQ count
    // must hold still for one full 2s observation window.
    let settle_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut window_start = tokio::time::Instant::now();
    let mut last_count = gate.req_count();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let count = gate.req_count();
        if count != last_count {
            last_count = count;
            window_start = tokio::time::Instant::now();
        } else if window_start.elapsed() >= Duration::from_secs(2) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < settle_deadline,
            "REQ count kept growing after the restricted refusal (retry storm)"
        );
    }

    syncing.stop().await;
    gate.stop().await;
    backend.stop().await;
}
