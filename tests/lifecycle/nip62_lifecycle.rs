//! Focused NIP-62 lifecycle integration tests.
//!
//! `nip62_validation.rs` locks in the standard request-to-vanish surface
//! semantics. These tests assert ngit-grasp's internal destructive-removal
//! lifecycle: targeted vanish requests must move served data through holding and
//! repository archival instead of hard-deleting directly from the main DB.

#[path = "../common/mod.rs"]
mod common;

use common::{build_vanish, publish_served_repo, TestRelay};
use grasp_audit::{AuditClient, AuditConfig};
use ngit_grasp::nostr::lifecycle::{
    HoldingStore, HOLDING_ARCHIVE_PATH_TAG, HOLDING_METADATA_KIND, HOLDING_SOURCE_TAG,
};
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

fn metadata_tag_value(event: &Event, key: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.as_slice();
        if v.len() >= 2 && v[0] == key {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

async fn assert_in_nip62_holding(store: &HoldingStore, id: EventId) -> Vec<Event> {
    assert!(
        store.has_event(&id).await,
        "event {} must exist in holding DB after vanish",
        id
    );

    let metadata = store
        .metadata_for_event(&id)
        .await
        .into_iter()
        .filter(|event| event.kind == Kind::from(HOLDING_METADATA_KIND))
        .collect::<Vec<_>>();
    assert!(
        !metadata.is_empty(),
        "event {} must have holding metadata after vanish",
        id
    );
    assert!(
        metadata
            .iter()
            .any(|event| metadata_has_tag(event, HOLDING_SOURCE_TAG, Some("nip62"))),
        "event {} metadata must be marked holding-source=nip62",
        id
    );

    metadata
}

#[tokio::test]
async fn targeted_vanish_archives_announcement_and_cascades_dependents_to_holding() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");
    let keys = client.keys().clone();

    let (announcement, _repo_id) = publish_served_repo(&client, "nip62-archive-cascade").await;
    let issue = client
        .create_issue(&announcement, "vanished issue", "body", vec![])
        .expect("build issue");
    let comment = client
        .event_builder(Kind::from(1111), "vanished comment")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .build(&keys)
        .expect("build comment");

    for event in [&issue, &comment] {
        client
            .send_event(event.clone())
            .await
            .expect("send dependent event");
    }

    let vanish = build_vanish(&client, None);
    client
        .send_event(vanish)
        .await
        .expect("send targeted vanish");
    tokio::time::sleep(Duration::from_millis(700)).await;

    for id in [announcement.id, issue.id, comment.id] {
        assert!(
            !client
                .is_event_on_relay(id)
                .await
                .expect("query main db after vanish"),
            "event {} must no longer be served after vanish",
            id
        );
    }

    let store = open_holding(&relay).await;
    let announcement_metadata = assert_in_nip62_holding(&store, announcement.id).await;
    assert_in_nip62_holding(&store, issue.id).await;
    assert_in_nip62_holding(&store, comment.id).await;

    let archive_rel_path = announcement_metadata
        .iter()
        .find_map(|event| metadata_tag_value(event, HOLDING_ARCHIVE_PATH_TAG))
        .expect("vanished announcement metadata must include git archive path");
    let archive_path = relay
        .git_data_path()
        .join(".archive")
        .join(archive_rel_path);
    assert!(archive_path.exists(), "git archive must exist on disk");

    relay.stop().await;
}

#[tokio::test]
async fn targeted_vanish_moves_remaining_author_events_to_holding() {
    let relay = TestRelay::start_with_lmdb().await;
    let repo_owner = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create repo owner client");
    let vanishing_author =
        AuditClient::new_with_keys(relay.url(), AuditConfig::isolated(), Keys::generate())
            .await
            .expect("create vanishing author client");

    let (announcement, _repo_id) = publish_served_repo(&repo_owner, "nip62-remaining-author").await;
    let issue = vanishing_author
        .create_issue(&announcement, "vanish author issue", "body", vec![])
        .expect("build issue authored by vanishing pubkey");
    vanishing_author
        .send_event(issue.clone())
        .await
        .expect("send issue authored by vanishing pubkey");
    assert!(
        vanishing_author
            .is_event_on_relay(issue.id)
            .await
            .expect("query issue before vanish"),
        "issue must be served before vanish"
    );

    let vanish = build_vanish(&vanishing_author, None);
    vanishing_author
        .send_event(vanish)
        .await
        .expect("send targeted vanish");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        !vanishing_author
            .is_event_on_relay(issue.id)
            .await
            .expect("query issue after vanish"),
        "issue must no longer be served after vanish"
    );
    assert!(
        repo_owner
            .is_event_on_relay(announcement.id)
            .await
            .expect("query other author's announcement after vanish"),
        "vanish must not delete other authors' announcements"
    );

    let store = open_holding(&relay).await;
    assert_in_nip62_holding(&store, issue.id).await;

    relay.stop().await;
}
