//! Integration tests for durable replaceable/addressable history capture.

mod common;

use common::{publish_served_repo, TestRelay};
use grasp_audit::{AuditClient, AuditConfig, DETERMINISTIC_COMMIT_HASH};
use ngit_grasp::nostr::history::ReplaceableHistoryStore;
use nostr_sdk::prelude::*;
use std::time::Duration;

async fn open_history(relay_data_path: &std::path::Path) -> ReplaceableHistoryStore {
    ReplaceableHistoryStore::open_lmdb(relay_data_path)
        .await
        .expect("open history db")
}

async fn build_announcement_version(
    client: &AuditClient,
    repo_id: &str,
    created_at: Timestamp,
    content: &str,
) -> Event {
    let relay_url = client
        .relay_url()
        .await
        .expect("client should have relay url");
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let http_url = format!("http://{}", relay_domain);
    let npub = client.public_key().to_bech32().expect("pubkey to npub");

    EventBuilder::new(Kind::GitRepoAnnouncement, content)
        .tags(vec![
            Tag::identifier(repo_id),
            Tag::custom("name", vec![repo_id.to_string()]),
            Tag::custom(
                "clone",
                vec![format!("{}/{}/{}.git", http_url, npub, repo_id)],
            ),
            Tag::custom("relays", vec![relay_url]),
        ])
        .custom_created_at(created_at)
        .finalize(client.keys())
        .expect("build announcement version")
}

fn build_state_version(
    client: &AuditClient,
    repo_id: &str,
    created_at: Timestamp,
    content: &str,
) -> Event {
    EventBuilder::new(Kind::RepoState, content)
        .tags(vec![
            Tag::identifier(repo_id),
            Tag::custom(
                "refs/heads/main",
                vec![DETERMINISTIC_COMMIT_HASH.to_string()],
            ),
            Tag::custom("HEAD", vec!["ref: refs/heads/main".to_string()]),
        ])
        .custom_created_at(created_at)
        .finalize(client.keys())
        .expect("build state version")
}

#[tokio::test]
async fn newer_30618_supersedes_older_and_preserves_old_in_history() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (_announcement, repo_id) = publish_served_repo(&client, "history-30618").await;
    let base_ts = Timestamp::now();
    let old_state = build_state_version(&client, &repo_id, base_ts, "state-v1");
    let new_state = build_state_version(
        &client,
        &repo_id,
        Timestamp::from_secs(base_ts.as_secs() + 30),
        "state-v2",
    );

    client
        .send_event(old_state.clone())
        .await
        .expect("send old state");
    client
        .send_event(new_state.clone())
        .await
        .expect("send new state");
    tokio::time::sleep(Duration::from_millis(400)).await;

    let coordinate = format!("30618:{}:{}", client.public_key().to_hex(), repo_id);
    let history = open_history(relay.relay_data_path()).await;
    let records = history
        .superseded_records_for_coordinate_before(&coordinate, Timestamp::now())
        .await;

    assert!(
        records
            .iter()
            .any(|r| r.superseded_event_id == Some(old_state.id)
                && r.replaced_by == Some(new_state.id)),
        "history must contain old 30618 as superseded by the newer 30618"
    );
    assert!(
        history
            .event_by_id(&old_state.id)
            .await
            .expect("lookup old state in history")
            .is_some(),
        "history payload must persist the superseded 30618 event"
    );

    relay.stop().await;
}

#[tokio::test]
async fn newer_30617_supersedes_older_and_preserves_old_in_history() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (first_announcement, repo_id) = publish_served_repo(&client, "history-30617").await;
    let newer_announcement = build_announcement_version(
        &client,
        &repo_id,
        Timestamp::from_secs(first_announcement.created_at.as_secs() + 30),
        "re-announcement",
    )
    .await;

    client
        .send_event(newer_announcement.clone())
        .await
        .expect("send newer announcement");
    tokio::time::sleep(Duration::from_millis(400)).await;

    let coordinate = format!("30617:{}:{}", client.public_key().to_hex(), repo_id);
    let history = open_history(relay.relay_data_path()).await;
    let records = history
        .superseded_records_for_coordinate_before(&coordinate, Timestamp::now())
        .await;

    assert!(
        records.iter().any(|r| {
            r.superseded_event_id == Some(first_announcement.id)
                && r.replaced_by == Some(newer_announcement.id)
        }),
        "history must contain old 30617 as superseded by the newer 30617"
    );
    assert!(
        history
            .event_by_id(&first_announcement.id)
            .await
            .expect("lookup old announcement in history")
            .is_some(),
        "history payload must persist the superseded 30617 event"
    );

    relay.stop().await;
}

#[tokio::test]
async fn replaceable_history_survives_restart_lmdb() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (first_announcement, repo_id) = publish_served_repo(&client, "history-restart").await;
    let newer_announcement = build_announcement_version(
        &client,
        &repo_id,
        Timestamp::from_secs(first_announcement.created_at.as_secs() + 45),
        "restart-reannouncement",
    )
    .await;
    client
        .send_event(newer_announcement.clone())
        .await
        .expect("send newer announcement");
    tokio::time::sleep(Duration::from_millis(400)).await;

    let coordinate = format!("30617:{}:{}", client.public_key().to_hex(), repo_id);
    let history_before_restart = open_history(relay.relay_data_path()).await;
    let pre_restart_records = history_before_restart
        .superseded_records_for_coordinate_before(&coordinate, Timestamp::now())
        .await;
    assert!(
        pre_restart_records.iter().any(|r| {
            r.superseded_event_id == Some(first_announcement.id)
                && r.replaced_by == Some(newer_announcement.id)
        }),
        "history metadata must exist before restart"
    );

    let relay_data_path = relay.relay_data_path().clone();
    let git_data_path = relay.git_data_path().clone();
    let owner_hex = client.public_key().to_hex();
    relay.stop().await;

    let restarted = TestRelay::start_with_existing_lmdb_paths(
        git_data_path,
        relay_data_path.clone(),
        None,
        false,
    )
    .await;
    restarted.stop().await;

    let history = open_history(&relay_data_path).await;
    let coordinate = format!("30617:{}:{}", owner_hex, repo_id);
    let records = history
        .superseded_records_for_coordinate_before(&coordinate, Timestamp::now())
        .await;

    assert!(
        records.iter().any(|r| {
            r.superseded_event_id == Some(first_announcement.id)
                && r.replaced_by == Some(newer_announcement.id)
        }),
        "history metadata must survive LMDB restart"
    );
    assert!(
        history
            .event_by_id(&first_announcement.id)
            .await
            .expect("lookup archived announcement after restart")
            .is_some(),
        "history payload must survive LMDB restart"
    );
}

#[tokio::test]
async fn serving_behavior_unchanged_latest_version_is_still_served() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (_announcement, repo_id) = publish_served_repo(&client, "history-serving").await;
    let base_ts = Timestamp::now();
    let old_state = build_state_version(&client, &repo_id, base_ts, "state-old");
    let new_state = build_state_version(
        &client,
        &repo_id,
        Timestamp::from_secs(base_ts.as_secs() + 30),
        "state-new",
    );

    client
        .send_event(old_state.clone())
        .await
        .expect("send old state");
    client
        .send_event(new_state.clone())
        .await
        .expect("send new state");
    tokio::time::sleep(Duration::from_millis(400)).await;

    let by_id_old = client
        .is_event_on_relay(old_state.id)
        .await
        .expect("query old state by id");
    let by_id_new = client
        .is_event_on_relay(new_state.id)
        .await
        .expect("query new state by id");
    assert!(
        !by_id_old,
        "superseded state must remain non-served in the main relay behavior"
    );
    assert!(by_id_new, "latest state must still be served");

    relay.stop().await;
}
