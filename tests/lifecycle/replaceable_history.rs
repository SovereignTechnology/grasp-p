//! Integration tests for durable replaceable/addressable history capture.

#[path = "../common/mod.rs"]
mod common;

use clap::Parser;
use common::{publish_served_repo, TestRelay};
use grasp_audit::{AuditClient, AuditConfig, DETERMINISTIC_COMMIT_HASH};
use ngit_grasp::config::Config;
use ngit_grasp::grasp06::receive::new_repo_init_locks;
use ngit_grasp::nostr::builder::Nip34WritePolicy;
use ngit_grasp::nostr::lifecycle::ReplaceableHistoryStore;
use ngit_grasp::nostr::lifecycle::{HoldingStore, RepositoryLifecycle, Tombstones};
use ngit_grasp::nostr::persistence::SaveContext;
use ngit_grasp::nostr::SharedDatabase;
use ngit_grasp::purgatory::Purgatory;
use nostr_sdk::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
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

fn build_policy_for_history_regression(
    database: SharedDatabase,
    history: ReplaceableHistoryStore,
    git_data_path: &std::path::Path,
) -> Nip34WritePolicy {
    let config = Config::parse_from([
        "ngit-grasp-test",
        "--domain",
        "test.example.com",
        "--archive-all",
        "--archive-read-only",
        "false",
    ]);
    let purgatory = Arc::new(Purgatory::new(git_data_path.to_path_buf()));

    Nip34WritePolicy::new(
        database,
        Tombstones::in_memory(),
        HoldingStore::in_memory(),
        RepositoryLifecycle::in_memory(),
        history,
        git_data_path.to_path_buf(),
        purgatory,
        config,
        new_repo_init_locks(),
    )
}

fn build_policy_announcement_version(
    keys: &Keys,
    repo_id: &str,
    created_at: Timestamp,
    content: &str,
) -> Event {
    let npub = keys.public_key().to_bech32().expect("pubkey to npub");

    EventBuilder::new(Kind::GitRepoAnnouncement, content)
        .tags(vec![
            Tag::identifier(repo_id),
            Tag::custom("name", vec![repo_id.to_string()]),
            Tag::custom(
                "clone",
                vec![format!("http://test.example.com/{}/{}.git", npub, repo_id)],
            ),
            Tag::custom("relays", vec!["wss://test.example.com".to_string()]),
        ])
        .custom_created_at(created_at)
        .finalize(keys)
        .expect("build policy announcement version")
}

#[tokio::test]
async fn newer_30618_supersedes_older_and_preserves_old_in_history() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (_announcement, repo_id) = publish_served_repo(&client, "history-30618").await;
    // `publish_served_repo` already saved a 30618 for this coordinate. Nostr
    // replaceable ordering is only second-granular, so a same-second "old"
    // event can be rejected instead of superseding the fixture event. Start the
    // test sequence in a deterministic future second to make both replacements
    // strictly newer.
    let base_ts = Timestamp::from_secs(Timestamp::now().as_secs() + 1);
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
        .superseded_records_for_coordinate_before(
            &coordinate,
            // The deterministic future timestamps can be ahead of wall-clock
            // `Timestamp::now()`, so query just after the newest test event
            // rather than using "now" as the history cutoff.
            Timestamp::from_secs(new_state.created_at.as_secs() + 1),
        )
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
async fn sync_style_admit_then_save_captures_superseded_history_once() {
    use nostr_relay_builder::prelude::{WritePolicy, WritePolicyResult};

    let git_dir = tempfile::tempdir().expect("git tempdir");
    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let history = ReplaceableHistoryStore::in_memory();
    let policy = build_policy_for_history_regression(db.clone(), history.clone(), git_dir.path());
    let keys = Keys::generate();
    let repo_id = format!("history-sync-once-{}", &keys.public_key().to_hex()[..8]);
    let old_announcement = build_policy_announcement_version(
        &keys,
        &repo_id,
        Timestamp::from_secs(Timestamp::now().as_secs() + 1),
        "old",
    );
    let new_announcement = build_policy_announcement_version(
        &keys,
        &repo_id,
        Timestamp::from_secs(old_announcement.created_at.as_secs() + 30),
        "new",
    );

    db.save_event(&old_announcement)
        .await
        .expect("save old announcement");

    let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let result = policy.admit_event(&new_announcement, &dummy_addr).await;
    assert!(
        matches!(result, WritePolicyResult::Accept),
        "new announcement must be accepted before central save"
    );

    // Cross a timestamp-second boundary before saving. The old persistence hook
    // also captured history here, producing a distinct metadata event instead
    // of collapsing onto the admission hook's metadata ID.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    policy
        .save_accepted_event(&new_announcement, SaveContext::RelaySync)
        .await
        .expect("save accepted announcement");

    let coordinate = format!("30617:{}:{}", keys.public_key().to_hex(), repo_id);
    let records = history
        .superseded_records_for_coordinate_before(
            &coordinate,
            Timestamp::from_secs(new_announcement.created_at.as_secs() + 1),
        )
        .await;
    let matching_records = records
        .iter()
        .filter(|r| {
            r.superseded_event_id == Some(old_announcement.id)
                && r.replaced_by == Some(new_announcement.id)
        })
        .count();

    assert_eq!(
        matching_records, 1,
        "sync-style admit then save must not duplicate superseded history metadata"
    );
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
    // `publish_served_repo` already saved a 30618 for this coordinate. Keep the
    // explicit state sequence in future seconds so the relay's second-granular
    // replaceable ordering cannot tie it with the fixture event.
    let base_ts = Timestamp::from_secs(Timestamp::now().as_secs() + 1);
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

#[tokio::test]
async fn history_not_captured_for_purgatory_only_announcement() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let relay_url = client
        .relay_url()
        .await
        .expect("client should have relay url");
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let npub = client.public_key().to_bech32().expect("pubkey to npub");
    let repo_id = format!(
        "history-purgatory-only-{}",
        &Keys::generate().public_key().to_hex()[..8]
    );

    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![
            Tag::identifier(&repo_id),
            Tag::custom("name", vec![repo_id.clone()]),
            Tag::custom(
                "clone",
                vec![format!("http://{}/{}/{}.git", relay_domain, npub, repo_id)],
            ),
            Tag::custom("relays", vec![relay_url]),
        ])
        .finalize(client.keys())
        .expect("build purgatory-only announcement");

    client
        .send_event(announcement)
        .await
        .expect("send announcement to purgatory");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let coordinate = format!("30617:{}:{}", client.public_key().to_hex(), repo_id);
    let history = open_history(relay.relay_data_path()).await;
    let latest = history
        .latest_superseded_before(&coordinate, Timestamp::now())
        .await;
    assert!(
        latest.is_none(),
        "purgatory-only announcements must not capture superseded history"
    );

    relay.stop().await;
}
