//! NIP-09 multi-maintainer announcement-cascade integration tests.
//!
//! These tests verify hard-delete cascade behaviour in the relay's main DB when
//! multiple maintainers announce the same repository identifier.
//!
//! Covered here:
//! - Same-identifier announcements by different maintainers
//! - Dependent event retention when at least one referenced announcement survives
//! - Dependent event hard-deletion when all referenced announcements are deleted
//! - Different maintainer-subset anchors surviving a middle-maintainer deletion
//!
//! Serving note: these tests use the maintainer-exception path for the second
//! and third announcement (`maintainers` tag + non-local `relays` tag), because
//! independent second-announcement git promotion is not currently reliable in
//! this fixture setup.

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

#[tokio::test]
async fn test_three_maintainers_subset_anchors_survive_middle_deletion() {
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
        "multi-subset-a",
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

    let event_ab = client_a
        .event_builder(Kind::from(1617), "event anchored to A+B")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .tag(Tag::custom("a", vec![coordinate_b.clone()]))
        .build(client_a.keys())
        .expect("build event anchored to A+B");
    let event_bc = client_a
        .event_builder(Kind::from(1617), "event anchored to B+C")
        .tag(Tag::custom("a", vec![coordinate_b.clone()]))
        .tag(Tag::custom("a", vec![coordinate_c.clone()]))
        .build(client_a.keys())
        .expect("build event anchored to B+C");
    let event_ac = client_a
        .event_builder(Kind::from(1617), "event anchored to A+C")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .tag(Tag::custom("a", vec![coordinate_c.clone()]))
        .build(client_a.keys())
        .expect("build event anchored to A+C");

    for event in [&event_ab, &event_bc, &event_ac] {
        client_a
            .send_event(event.clone())
            .await
            .expect("relay should accept subset-anchored event");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("announcement_b", announcement_b.id),
        ("announcement_c", announcement_c.id),
        ("event_ab", event_ab.id),
        ("event_bc", event_bc.id),
        ("event_ac", event_ac.id),
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
    let event_ab_survived = client_a
        .is_event_on_relay(event_ab.id)
        .await
        .expect("query event AB after deletion");
    let event_bc_survived = client_a
        .is_event_on_relay(event_bc.id)
        .await
        .expect("query event BC after deletion");
    let event_ac_survived = client_a
        .is_event_on_relay(event_ac.id)
        .await
        .expect("query event AC after deletion");
    let announcement_b_by_coordinate =
        announcement_served_by_coordinate(&client_b, &announcement_b, &repo_id).await;

    relay.stop().await;

    assert!(announcement_a_survived, "announcement A must survive");
    assert!(
        !announcement_b_survived,
        "announcement B must be hard-deleted"
    );
    assert!(announcement_c_survived, "announcement C must survive");
    assert!(
        event_ab_survived,
        "event A+B must survive due to alternative anchor A"
    );
    assert!(
        event_bc_survived,
        "event B+C must survive due to alternative anchor C"
    );
    assert!(
        event_ac_survived,
        "event A+C must survive because both anchors remain"
    );
    assert!(
        !announcement_b_by_coordinate,
        "announcement B coordinate must not be served after deletion"
    );
}

#[tokio::test]
async fn test_shared_subgraph_survives_when_one_anchor_path_removed() {
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
        "multi-shared-subgraph",
        &[client_b.public_key().to_hex()],
    )
    .await;
    let announcement_b = publish_served_announcement_for_identifier(&client_b, &repo_id).await;
    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id);
    let coordinate_b = announcement_coordinate(&announcement_b, &repo_id);

    // Top-level dependents under different anchoring conditions.
    let top_shared = client_a
        .event_builder(Kind::from(1617), "top shared A+B")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .tag(Tag::custom("a", vec![coordinate_b.clone()]))
        .build(client_a.keys())
        .expect("build top shared event");
    let top_unique_a = client_a
        .event_builder(Kind::from(1617), "top unique A")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .build(client_a.keys())
        .expect("build top unique A event");

    // Shared descendant references both tops and should survive through top_shared.
    let shared_descendant = client_a
        .event_builder(Kind::from(1111), "shared descendant")
        .tag(Tag::custom("e", vec![top_shared.id.to_hex()]))
        .tag(Tag::custom("e", vec![top_unique_a.id.to_hex()]))
        .build(client_a.keys())
        .expect("build shared descendant");

    // Unique branch descendant should be deleted with top_unique_a.
    let unique_descendant = client_a
        .event_builder(Kind::from(1111), "unique descendant")
        .tag(Tag::custom("e", vec![top_unique_a.id.to_hex()]))
        .build(client_a.keys())
        .expect("build unique descendant");

    for event in [
        &top_shared,
        &top_unique_a,
        &shared_descendant,
        &unique_descendant,
    ] {
        client_a
            .send_event(event.clone())
            .await
            .expect("relay should accept shared-subgraph event");
    }

    tokio::time::sleep(Duration::from_millis(350)).await;

    for (label, id) in [
        ("announcement_a", announcement_a.id),
        ("announcement_b", announcement_b.id),
        ("top_shared", top_shared.id),
        ("top_unique_a", top_unique_a.id),
        ("shared_descendant", shared_descendant.id),
        ("unique_descendant", unique_descendant.id),
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

    tokio::time::sleep(Duration::from_millis(700)).await;

    let announcement_a_survived = client_a
        .is_event_on_relay(announcement_a.id)
        .await
        .expect("query announcement A after deletion");
    let announcement_b_survived = client_b
        .is_event_on_relay(announcement_b.id)
        .await
        .expect("query announcement B after deletion");
    let top_shared_survived = client_a
        .is_event_on_relay(top_shared.id)
        .await
        .expect("query top shared after deletion");
    let top_unique_a_survived = client_a
        .is_event_on_relay(top_unique_a.id)
        .await
        .expect("query top unique A after deletion");
    let shared_descendant_survived = client_a
        .is_event_on_relay(shared_descendant.id)
        .await
        .expect("query shared descendant after deletion");
    let unique_descendant_survived = client_a
        .is_event_on_relay(unique_descendant.id)
        .await
        .expect("query unique descendant after deletion");

    relay.stop().await;

    assert!(
        !announcement_a_survived,
        "announcement A must be hard-deleted"
    );
    assert!(announcement_b_survived, "announcement B must survive");
    assert!(
        top_shared_survived,
        "top shared event must survive because anchor B remains"
    );
    assert!(
        !top_unique_a_survived,
        "top unique A event must be deleted after A deletion"
    );
    assert!(
        shared_descendant_survived,
        "shared descendant must survive through still-anchored top_shared path"
    );
    assert!(
        !unique_descendant_survived,
        "unique descendant must be deleted with the A-only branch"
    );
}
