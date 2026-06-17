//! NIP-09 multi-maintainer announcement-cascade integration tests.
//!
//! These tests verify hard-delete cascade behaviour in the relay's main DB when
//! multiple maintainers announce the same repository identifier.
//!
//! Covered here:
//! - Same-identifier announcements by different maintainers
//! - Dependent event retention when at least one referenced announcement survives
//! - Dependent event hard-deletion when all referenced announcements are deleted
//!
//! Serving note: these tests use the maintainer-exception path for the second
//! and third announcement (`maintainers` tag + non-local `relays` tag), because
//! independent second-announcement git promotion is not currently reliable in
//! this fixture setup.
//!
//! Not covered here: PR-chain kinds (1618/1619/1631/1632), which need additional
//! PR-specific test wiring outside this Phase 4 scope.

mod common;

use common::{
    announcement_coordinate, announcement_served_by_coordinate, build_deletion,
    publish_served_announcement_for_identifier, publish_served_repo_with_maintainers, TestRelay,
};

use grasp_audit::{AuditClient, AuditConfig};
use nostr_sdk::prelude::*;
use std::time::Duration;

#[tokio::test]
async fn test_two_maintainers_one_deletes_shared_event_survives() {
    let relay = TestRelay::start().await;
    let client_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create maintainer A client");
    let client_b =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer B client");

    let (announcement_a, repo_id) = publish_served_repo_with_maintainers(
        &client_a,
        "multi-maint-a",
        &[client_b.public_key().to_hex()],
    )
    .await;
    let announcement_b = publish_served_announcement_for_identifier(&client_b, &repo_id).await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id);
    let coordinate_b = announcement_coordinate(&announcement_b, &repo_id);

    let patch = client_a
        .event_builder(Kind::from(1617), "shared patch")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .tag(Tag::custom("a", vec![coordinate_b.clone()]))
        .build(client_a.keys())
        .expect("build patch");
    client_a
        .send_event(patch.clone())
        .await
        .expect("relay should accept patch");

    tokio::time::sleep(Duration::from_millis(300)).await;

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("announcement_b", announcement_b.id),
        ("patch", patch.id),
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
        announcement_served_by_coordinate(&client_a, &announcement_a, &repo_id).await,
        "announcement A must be served by coordinate before deletion"
    );
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
    let patch_survived = client_a
        .is_event_on_relay(patch.id)
        .await
        .expect("query patch after deletion");
    let announcement_a_by_coordinate =
        announcement_served_by_coordinate(&client_a, &announcement_a, &repo_id).await;
    let announcement_b_by_coordinate =
        announcement_served_by_coordinate(&client_b, &announcement_b, &repo_id).await;

    relay.stop().await;

    assert!(
        !announcement_a_survived,
        "announcement A must be hard-deleted"
    );
    assert!(announcement_b_survived, "announcement B must survive");
    assert!(
        patch_survived,
        "patch anchored to announcement B must survive"
    );
    assert!(
        !announcement_a_by_coordinate,
        "announcement A coordinate must not be served after deletion"
    );
    assert!(
        announcement_b_by_coordinate,
        "announcement B coordinate must remain served after deleting A"
    );
}

#[tokio::test]
async fn test_event_anchored_only_to_deleted_maintainer_is_removed() {
    let relay = TestRelay::start().await;
    let client_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create maintainer A client");
    let client_b =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer B client");

    let (announcement_a, repo_id) = publish_served_repo_with_maintainers(
        &client_a,
        "multi-anchored-only-a",
        &[client_b.public_key().to_hex()],
    )
    .await;
    let announcement_b = publish_served_announcement_for_identifier(&client_b, &repo_id).await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id);

    let patch = client_a
        .event_builder(Kind::from(1617), "patch anchored only to A")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .build(client_a.keys())
        .expect("build patch");
    client_a
        .send_event(patch.clone())
        .await
        .expect("relay should accept patch");

    tokio::time::sleep(Duration::from_millis(300)).await;

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("announcement_b", announcement_b.id),
        ("patch", patch.id),
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
    let patch_survived = client_a
        .is_event_on_relay(patch.id)
        .await
        .expect("query patch after deletion");

    relay.stop().await;

    assert!(
        !announcement_a_survived,
        "announcement A must be hard-deleted"
    );
    assert!(announcement_b_survived, "announcement B must survive");
    assert!(
        !patch_survived,
        "patch anchored only to deleted announcement A must be hard-deleted"
    );
}

#[tokio::test]
async fn test_two_maintainers_both_delete_unanchored_events_removed() {
    let relay = TestRelay::start().await;
    let client_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create maintainer A client");
    let client_b =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer B client");

    let (announcement_a, repo_id) = publish_served_repo_with_maintainers(
        &client_a,
        "multi-both-delete",
        &[client_b.public_key().to_hex()],
    )
    .await;
    let announcement_b = publish_served_announcement_for_identifier(&client_b, &repo_id).await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id);
    let coordinate_b = announcement_coordinate(&announcement_b, &repo_id);

    let patch = client_a
        .event_builder(Kind::from(1617), "shared patch doomed")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .tag(Tag::custom("a", vec![coordinate_b.clone()]))
        .build(client_a.keys())
        .expect("build patch");
    client_a
        .send_event(patch.clone())
        .await
        .expect("relay should accept patch");

    tokio::time::sleep(Duration::from_millis(300)).await;

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("announcement_b", announcement_b.id),
        ("patch", patch.id),
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
    let patch_survived = client_a
        .is_event_on_relay(patch.id)
        .await
        .expect("query patch after deletion");
    let announcement_a_by_coordinate =
        announcement_served_by_coordinate(&client_a, &announcement_a, &repo_id).await;
    let announcement_b_by_coordinate =
        announcement_served_by_coordinate(&client_b, &announcement_b, &repo_id).await;

    relay.stop().await;

    assert!(
        !announcement_a_survived && !announcement_b_survived,
        "both announcements must be hard-deleted"
    );
    assert!(
        !patch_survived,
        "patch must be hard-deleted after both anchoring announcements are deleted"
    );
    assert!(
        !announcement_a_by_coordinate && !announcement_b_by_coordinate,
        "neither announcement coordinate should remain served"
    );
}

#[tokio::test]
async fn test_three_maintainers_middle_deletes_event_survives() {
    let relay = TestRelay::start().await;
    let client_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create maintainer A client");
    let client_b =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer B client");
    let client_c =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer C client");

    let (announcement_a, repo_id) = publish_served_repo_with_maintainers(
        &client_a,
        "multi-three-a",
        &[
            client_b.public_key().to_hex(),
            client_c.public_key().to_hex(),
        ],
    )
    .await;
    let announcement_b = publish_served_announcement_for_identifier(&client_b, &repo_id).await;
    let announcement_c = publish_served_announcement_for_identifier(&client_c, &repo_id).await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id);
    let coordinate_b = announcement_coordinate(&announcement_b, &repo_id);
    let coordinate_c = announcement_coordinate(&announcement_c, &repo_id);

    let patch = client_a
        .event_builder(Kind::from(1617), "triple-anchored patch")
        .tag(Tag::custom("a", vec![coordinate_a]))
        .tag(Tag::custom("a", vec![coordinate_b.clone()]))
        .tag(Tag::custom("a", vec![coordinate_c]))
        .build(client_a.keys())
        .expect("build patch");
    client_a
        .send_event(patch.clone())
        .await
        .expect("relay should accept patch");

    tokio::time::sleep(Duration::from_millis(300)).await;

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("announcement_b", announcement_b.id),
        ("announcement_c", announcement_c.id),
        ("patch", patch.id),
    ] {
        assert!(
            client_a
                .is_event_on_relay(id)
                .await
                .expect("query event before deletion"),
            "{label} ({id}) must be served before deletion"
        );
    }

    let deletion_b = build_deletion(&client_b, &[], std::slice::from_ref(&coordinate_b));
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
    let announcement_c_survived = client_c
        .is_event_on_relay(announcement_c.id)
        .await
        .expect("query announcement C after deletion");
    let patch_survived = client_a
        .is_event_on_relay(patch.id)
        .await
        .expect("query patch after deletion");

    relay.stop().await;

    assert!(announcement_a_survived, "announcement A must survive");
    assert!(
        !announcement_b_survived,
        "announcement B must be hard-deleted"
    );
    assert!(announcement_c_survived, "announcement C must survive");
    assert!(
        patch_survived,
        "patch must survive because it remains anchored to announcements A and C"
    );
}
