//! NIP-09 multi-maintainer repository-state (30618) cascade integration tests.
//!
//! These tests verify identifier-level 30618 deletion rules in the relay's
//! single-node hard-delete path (main DB only; no holding DB/archival/recovery).
//!
//! Covered here:
//! - state survives while any kind-30617 announcement for the identifier remains
//! - all state for an identifier is deleted when the last announcement is deleted
//!
//! Serving note: second-maintainer announcements are served via the maintainer
//! exception path in this suite (`maintainers` tag + non-local `relays` tag).

#[path = "../common/mod.rs"]
mod common;

use common::{
    announcement_coordinate, announcement_served_by_coordinate, build_deletion,
    publish_served_announcement_with_state_for_identifier,
    publish_served_repo_with_state_event_and_maintainers, TestRelay,
};

use grasp_audit::{AuditClient, AuditConfig};
use nostr_sdk::prelude::*;
use std::time::Duration;

#[tokio::test]
async fn test_state_survives_while_any_maintainer_announcement_remains() {
    let relay = TestRelay::start().await;
    let client_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create maintainer A client");
    let client_b =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer B client");

    let (announcement_a, repo_id, state_a) = publish_served_repo_with_state_event_and_maintainers(
        &client_a,
        "state-multi-a",
        &[client_b.public_key().to_hex()],
    )
    .await;
    let (announcement_b, state_b) =
        publish_served_announcement_with_state_for_identifier(&client_b, &repo_id).await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id);

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("state_a", state_a.id),
        ("announcement_b", announcement_b.id),
        ("state_b", state_b.id),
    ] {
        assert!(
            client_a
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }
    assert!(
        announcement_served_by_coordinate(&client_b, &announcement_b, &repo_id).await,
        "announcement B must be served by coordinate before deletion"
    );

    let deletion_a = build_deletion(&client_a, &[], std::slice::from_ref(&coordinate_a));
    client_a
        .send_event(deletion_a)
        .await
        .expect("relay should accept announcement A deletion");

    tokio::time::sleep(Duration::from_millis(600)).await;

    let announcement_a_survived = client_a
        .is_event_on_relay(announcement_a.id)
        .await
        .expect("query announcement A after deletion");
    let announcement_b_survived = client_b
        .is_event_on_relay(announcement_b.id)
        .await
        .expect("query announcement B after deletion");
    let state_b_survived = client_b
        .is_event_on_relay(state_b.id)
        .await
        .expect("query state B after deletion");
    let announcement_b_by_coordinate =
        announcement_served_by_coordinate(&client_b, &announcement_b, &repo_id).await;

    relay.stop().await;

    assert!(
        !announcement_a_survived,
        "announcement A must be hard-deleted"
    );
    assert!(
        announcement_b_survived,
        "announcement B must survive, keeping identifier anchored"
    );
    assert!(
        state_b_survived,
        "state B must survive while identifier still has a live announcement"
    );
    assert!(
        announcement_b_by_coordinate,
        "announcement B must still be served by coordinate"
    );
}

#[tokio::test]
async fn test_state_deleted_when_last_maintainer_deletes() {
    let relay = TestRelay::start().await;
    let client_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create maintainer A client");
    let client_b =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer B client");

    let (announcement_a, repo_id, state_a) = publish_served_repo_with_state_event_and_maintainers(
        &client_a,
        "state-multi-last",
        &[client_b.public_key().to_hex()],
    )
    .await;
    let (announcement_b, state_b) =
        publish_served_announcement_with_state_for_identifier(&client_b, &repo_id).await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id);
    let coordinate_b = announcement_coordinate(&announcement_b, &repo_id);

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("state_a", state_a.id),
        ("announcement_b", announcement_b.id),
        ("state_b", state_b.id),
    ] {
        assert!(
            client_a
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }

    let deletion_a = build_deletion(&client_a, &[], std::slice::from_ref(&coordinate_a));
    let deletion_b = build_deletion(&client_b, &[], std::slice::from_ref(&coordinate_b));
    client_a
        .send_event(deletion_a)
        .await
        .expect("relay should accept announcement A deletion");
    client_b
        .send_event(deletion_b)
        .await
        .expect("relay should accept announcement B deletion");

    tokio::time::sleep(Duration::from_millis(600)).await;

    let announcement_a_survived = client_a
        .is_event_on_relay(announcement_a.id)
        .await
        .expect("query announcement A after deletion");
    let announcement_b_survived = client_b
        .is_event_on_relay(announcement_b.id)
        .await
        .expect("query announcement B after deletion");
    let state_a_survived = client_a
        .is_event_on_relay(state_a.id)
        .await
        .expect("query state A after deletion");
    let state_b_survived = client_b
        .is_event_on_relay(state_b.id)
        .await
        .expect("query state B after deletion");
    let announcement_a_by_coordinate =
        announcement_served_by_coordinate(&client_a, &announcement_a, &repo_id).await;
    let announcement_b_by_coordinate =
        announcement_served_by_coordinate(&client_b, &announcement_b, &repo_id).await;

    relay.stop().await;

    assert!(
        !announcement_a_survived && !announcement_b_survived,
        "all announcements for identifier must be hard-deleted"
    );
    assert!(
        !state_a_survived && !state_b_survived,
        "all 30618 state events for identifier must be hard-deleted when unanchored"
    );
    assert!(
        !announcement_a_by_coordinate && !announcement_b_by_coordinate,
        "identifier must no longer be served by announcement coordinates"
    );
}
