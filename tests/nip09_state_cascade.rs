//! NIP-09 repository-state cascade-deletion integration tests.
//!
//! These tests extend the announcement-cascade coverage to kind-30618
//! repository state events in the **single-maintainer** case.

mod common;

use common::{
    announcement_coordinate, announcement_served_by_coordinate, build_deletion,
    publish_served_repo_with_state_event, TestRelay,
};

use grasp_audit::{AuditClient, AuditConfig};
use std::time::Duration;

/// Deleting an announcement by coordinate must hard-delete the repository state
/// event (kind 30618) for the same repository from the main DB.
#[tokio::test]
async fn test_state_event_deleted_with_announcement() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "state-cascade-single").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    // STRICT pre-condition: both announcement and state are genuinely served.
    for (label, id) in [("announcement", announcement.id), ("state", state_event.id)] {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate));
    client
        .send_event(deletion)
        .await
        .expect("relay should accept announcement deletion");

    tokio::time::sleep(Duration::from_millis(600)).await;

    let announcement_survived = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement after deletion");
    let state_survived = client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query state event after deletion");
    let announcement_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement, &repo_id).await;

    relay.stop().await;

    assert!(
        !announcement_survived,
        "announcement {} must be hard-deleted",
        announcement.id
    );
    assert!(
        !state_survived,
        "state event {} must be hard-deleted with its announcement",
        state_event.id
    );
    assert!(
        !announcement_by_coordinate,
        "announcement must not be served by author+kind+identifier after deletion"
    );
}

/// Two repositories by the same maintainer are independent: deleting one
/// announcement must delete only that repository's state event.
#[tokio::test]
async fn test_state_events_are_independent_per_repository() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement_a, repo_a, state_a) =
        publish_served_repo_with_state_event(&client, "state-cascade-a").await;
    let (announcement_b, repo_b, state_b) =
        publish_served_repo_with_state_event(&client, "state-cascade-b").await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_a);

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("state_a", state_a.id),
        ("announcement_b", announcement_b.id),
        ("state_b", state_b.id),
    ] {
        assert!(
            client
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate_a));
    client
        .send_event(deletion)
        .await
        .expect("relay should accept announcement deletion");

    tokio::time::sleep(Duration::from_millis(600)).await;

    let announcement_a_survived = client
        .is_event_on_relay(announcement_a.id)
        .await
        .expect("query announcement a after deletion");
    let state_a_survived = client
        .is_event_on_relay(state_a.id)
        .await
        .expect("query state a after deletion");
    let announcement_b_survived = client
        .is_event_on_relay(announcement_b.id)
        .await
        .expect("query announcement b after deletion");
    let state_b_survived = client
        .is_event_on_relay(state_b.id)
        .await
        .expect("query state b after deletion");

    let announcement_a_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement_a, &repo_a).await;
    let announcement_b_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement_b, &repo_b).await;

    relay.stop().await;

    assert!(
        !announcement_a_survived && !state_a_survived,
        "deleted repository must lose both announcement and state event"
    );
    assert!(
        announcement_b_survived && state_b_survived,
        "unrelated repository announcement and state must survive"
    );
    assert!(
        !announcement_a_by_coordinate,
        "deleted repository coordinate must not be served"
    );
    assert!(
        announcement_b_by_coordinate,
        "unrelated repository coordinate must remain served"
    );
}
