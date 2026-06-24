//! Focused integration tests for Phase 2 holding-DB semantics.

#[path = "../common/mod.rs"]
mod common;

use common::{
    announcement_coordinate, build_deletion, publish_served_announcement_for_identifier,
    publish_served_repo, publish_served_repo_with_maintainers,
    publish_served_repo_with_state_event, TestRelay,
};

use grasp_audit::{AuditClient, AuditConfig};
use ngit_grasp::nostr::lifecycle::HoldingStore;
use nostr_sdk::prelude::*;
use std::time::Duration;

async fn open_holding(relay: &TestRelay) -> HoldingStore {
    HoldingStore::open_lmdb(relay.relay_data_path(), relay.git_data_path())
        .await
        .expect("open holding db")
}

fn metadata_has_tag(event: &Event, key: &str, value: Option<&str>) -> bool {
    event.tags.iter().any(|tag| {
        let v = tag.as_slice();
        v.len() >= 2 && v[0] == key && value.map(|expected| v[1] == expected).unwrap_or(true)
    })
}

async fn assert_in_holding_with_metadata(store: &HoldingStore, id: EventId, expected_source: &str) {
    assert!(
        store.has_event(&id).await,
        "event {} must exist in holding DB",
        id
    );

    let meta = store.metadata_for_event(&id).await;
    assert!(
        !meta.is_empty(),
        "event {} must have holding metadata entries",
        id
    );
    assert!(
        meta.iter()
            .any(|e| metadata_has_tag(e, "holding-source", Some(expected_source))),
        "event {} metadata must include holding-source={}",
        id,
        expected_source
    );
    assert!(
        meta.iter()
            .any(|e| metadata_has_tag(e, "holding-deleted-at", None)),
        "event {} metadata must include holding-deleted-at",
        id
    );
}

#[tokio::test]
async fn announcement_cascade_moves_announcement_and_dependents_to_holding() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, repo_id) = publish_served_repo(&client, "holding-cascade").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let issue = client
        .create_issue(&announcement, "holding issue", "body", vec![])
        .expect("build issue");
    let comment = client
        .event_builder(Kind::from(1111), "holding comment")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build comment");

    for event in [&issue, &comment] {
        client
            .send_event(event.clone())
            .await
            .expect("send dependent event");
    }

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate));
    client
        .send_event(deletion)
        .await
        .expect("send announcement deletion");
    tokio::time::sleep(Duration::from_millis(600)).await;

    for id in [announcement.id, issue.id, comment.id] {
        assert!(
            !client
                .is_event_on_relay(id)
                .await
                .expect("query main db after deletion"),
            "event {} must no longer be served from main DB",
            id
        );
    }

    let store = open_holding(&relay).await;
    for id in [announcement.id, issue.id, comment.id] {
        assert_in_holding_with_metadata(&store, id, "nip09").await;
    }

    let resubmit = client.send_event(issue.clone()).await;
    relay.stop().await;

    assert!(
        resubmit.is_err(),
        "deleted event re-submission must be blocked by tombstone gate"
    );
}

#[tokio::test]
async fn direct_e_deletion_moves_target_to_holding() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, _repo_id) = publish_served_repo(&client, "holding-e-delete").await;
    let issue = client
        .create_issue(&announcement, "delete by e", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let deletion = build_deletion(&client, &[issue.id], &[]);
    client.send_event(deletion).await.expect("send deletion");
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert!(
        !client
            .is_event_on_relay(issue.id)
            .await
            .expect("query issue after deletion"),
        "issue must no longer be served"
    );

    let store = open_holding(&relay).await;
    assert_in_holding_with_metadata(&store, issue.id, "nip09").await;

    let resubmit = client.send_event(issue.clone()).await;
    relay.stop().await;
    assert!(resubmit.is_err(), "re-submission must be rejected");
}

#[tokio::test]
async fn direct_a_deletion_moves_coordinate_targets_to_holding() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (_announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "holding-a-delete").await;
    let state_coord = format!("30618:{}:{}", client.public_key().to_hex(), repo_id);

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&state_coord));
    client.send_event(deletion).await.expect("send deletion");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        !client
            .is_event_on_relay(state_event.id)
            .await
            .expect("query state after deletion"),
        "state event must no longer be served"
    );

    let store = open_holding(&relay).await;
    assert_in_holding_with_metadata(&store, state_event.id, "nip09").await;

    let resubmit = client.send_event(state_event.clone()).await;
    relay.stop().await;
    assert!(resubmit.is_err(), "re-submission must be rejected");
}

#[tokio::test]
async fn multi_maintainer_moves_only_events_that_are_actually_deleted() {
    let relay = TestRelay::start_with_lmdb().await;
    let client_a = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create maintainer a");
    let client_b =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create maintainer b");

    let (announcement_a, repo_id) = publish_served_repo_with_maintainers(
        &client_a,
        "holding-multi",
        &[client_b.public_key().to_hex()],
    )
    .await;
    let announcement_b = publish_served_announcement_for_identifier(&client_b, &repo_id).await;

    let coordinate_a = announcement_coordinate(&announcement_a, &repo_id);
    let coordinate_b = announcement_coordinate(&announcement_b, &repo_id);

    let shared_patch = client_a
        .event_builder(Kind::from(1617), "shared patch")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .tag(Tag::custom("a", vec![coordinate_b.clone()]))
        .build(client_a.keys())
        .expect("build shared patch");
    let deleted_patch = client_a
        .event_builder(Kind::from(1617), "a-only patch")
        .tag(Tag::custom("a", vec![coordinate_a.clone()]))
        .build(client_a.keys())
        .expect("build a-only patch");

    for event in [&shared_patch, &deleted_patch] {
        client_a
            .send_event(event.clone())
            .await
            .expect("send patch");
    }

    let deletion_a = build_deletion(&client_a, &[], std::slice::from_ref(&coordinate_a));
    client_a
        .send_event(deletion_a)
        .await
        .expect("delete announcement a");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(
        !client_a
            .is_event_on_relay(announcement_a.id)
            .await
            .expect("query announcement a"),
        "announcement a must be deleted"
    );
    assert!(
        !client_a
            .is_event_on_relay(deleted_patch.id)
            .await
            .expect("query deleted patch"),
        "a-only patch must be deleted"
    );
    assert!(
        client_b
            .is_event_on_relay(announcement_b.id)
            .await
            .expect("query announcement b"),
        "announcement b must survive"
    );
    assert!(
        client_a
            .is_event_on_relay(shared_patch.id)
            .await
            .expect("query shared patch"),
        "shared patch must survive"
    );

    let store = open_holding(&relay).await;
    assert_in_holding_with_metadata(&store, announcement_a.id, "nip09").await;
    assert_in_holding_with_metadata(&store, deleted_patch.id, "nip09").await;

    assert!(
        !store.has_event(&announcement_b.id).await,
        "surviving announcement must not be moved to holding"
    );
    assert!(
        !store.has_event(&shared_patch.id).await,
        "surviving patch must not be moved to holding"
    );

    relay.stop().await;
}

#[tokio::test]
async fn state_event_30618_moves_when_identifier_becomes_unanchored() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "holding-state-unanchored").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let deletion = build_deletion(&client, &[], std::slice::from_ref(&coordinate));
    client.send_event(deletion).await.expect("send deletion");
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert!(
        !client
            .is_event_on_relay(state_event.id)
            .await
            .expect("query state after deletion"),
        "state event must no longer be served"
    );

    let store = open_holding(&relay).await;
    assert_in_holding_with_metadata(&store, state_event.id, "nip09").await;

    let resubmit = client.send_event(state_event.clone()).await;
    relay.stop().await;
    assert!(resubmit.is_err(), "state re-submission must be rejected");
}

#[tokio::test]
async fn disrespector_mode_does_not_move_to_holding_and_target_remains_served() {
    let relay = TestRelay::start_with_lmdb_deletion_disrespector().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "holding-disrespector").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);

    let deletion = build_deletion(&client, &[announcement.id], &[coordinate]);
    client.send_event(deletion).await.expect("send deletion");
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert!(
        client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query announcement after disrespector deletion"),
        "announcement must remain served in disrespector mode"
    );

    let store = open_holding(&relay).await;
    relay.stop().await;

    assert!(
        !store.has_event(&announcement.id).await,
        "disrespector mode must not move targets into holding DB"
    );
}
