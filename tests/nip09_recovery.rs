//! Integration tests for Phase 5 NIP-09 recovery workflow.

mod common;

use common::{
    announcement_coordinate, build_deletion, create_pr_event, create_state_event,
    create_test_repo_with_commit, publish_served_announcement_for_identifier, publish_served_repo,
    publish_served_repo_with_maintainers, publish_served_repo_with_state_event, push_to_relay,
    CommitVariant, TestRelay,
};
use grasp_audit::{AuditClient, AuditConfig};
use ngit_grasp::nostr::lifecycle::{
    HoldingStore, DEFAULT_RETENTION, HOLDING_ARCHIVE_PATH_TAG, HOLDING_METADATA_KIND,
};
use nostr_sdk::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

async fn open_holding(relay: &TestRelay) -> HoldingStore {
    HoldingStore::open_lmdb(relay.relay_data_path(), relay.git_data_path())
        .await
        .expect("open holding db")
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

fn build_reannouncement(client: &AuditClient, relay: &TestRelay, repo_id: &str) -> Event {
    build_reannouncement_with_clone(
        client,
        relay,
        repo_id,
        &format!(
            "http://{}/{}/{}.git",
            relay
                .url()
                .trim_start_matches("ws://")
                .trim_start_matches("wss://"),
            client.public_key().to_bech32().expect("pubkey to bech32"),
            repo_id
        ),
    )
}

fn build_reannouncement_with_clone(
    client: &AuditClient,
    relay: &TestRelay,
    repo_id: &str,
    clone_url: &str,
) -> Event {
    let relay_url = relay.url().to_string();

    client
        .event_builder(Kind::GitRepoAnnouncement, "reannounce")
        .tag(Tag::identifier(repo_id))
        .tag(Tag::custom("name", vec![repo_id.to_string()]))
        .tag(Tag::custom("clone", vec![clone_url.to_string()]))
        .tag(Tag::custom("relays", vec![relay_url]))
        .build(client.keys())
        .expect("build re-announcement")
}

async fn publish_served_repo_for_identifier(
    client: &AuditClient,
    relay: &TestRelay,
    repo_id: &str,
) -> String {
    let temp_dir = tempfile::tempdir().expect("create temp repo for served repo publish");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("create deterministic commit for served repo");

    let relay_url = relay.url().to_string();
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let npub = client
        .public_key()
        .to_bech32()
        .expect("npub for served repo publish");
    let clone_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);

    let announcement = client
        .event_builder(Kind::GitRepoAnnouncement, "")
        .tag(Tag::identifier(repo_id))
        .tag(Tag::custom("name", vec![repo_id.to_string()]))
        .tag(Tag::custom("clone", vec![clone_url.clone()]))
        .tag(Tag::custom("relays", vec![relay_url.clone()]))
        .build(client.keys())
        .expect("build served announcement");
    client
        .send_event(announcement.clone())
        .await
        .expect("send served announcement");

    let state_event = create_state_event(
        client.keys(),
        repo_id,
        &[("main", commit_hash.as_str())],
        &[],
        &[clone_url.as_str()],
        &[relay_url.as_str()],
    )
    .expect("build served state event");
    client
        .send_event_and_note_purgatory(state_event.clone())
        .await
        .expect("send served state event");

    push_to_relay(temp_dir.path(), &relay_domain, &npub, repo_id).expect("push served repo data");
    tokio::time::sleep(Duration::from_millis(900)).await;

    assert!(
        client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query served announcement"),
        "served announcement should be promoted"
    );
    assert!(
        client
            .is_event_on_relay(state_event.id)
            .await
            .expect("query served state"),
        "served state event should be promoted"
    );

    commit_hash
}

async fn publish_served_repo_for_identifier_with_maintainers(
    client: &AuditClient,
    relay: &TestRelay,
    repo_id: &str,
    maintainer_pubkeys: &[String],
) -> String {
    let temp_dir = tempfile::tempdir().expect("create temp repo for served repo publish");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("create deterministic commit for served repo");

    let relay_url = relay.url().to_string();
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let npub = client
        .public_key()
        .to_bech32()
        .expect("npub for served repo publish");
    let clone_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);

    let mut announcement_builder = client
        .event_builder(Kind::GitRepoAnnouncement, "")
        .tag(Tag::identifier(repo_id))
        .tag(Tag::custom("name", vec![repo_id.to_string()]))
        .tag(Tag::custom("clone", vec![clone_url.clone()]))
        .tag(Tag::custom("relays", vec![relay_url.clone()]));
    if !maintainer_pubkeys.is_empty() {
        announcement_builder =
            announcement_builder.tag(Tag::custom("maintainers", maintainer_pubkeys.to_vec()));
    }

    let announcement = announcement_builder
        .build(client.keys())
        .expect("build served announcement with maintainers");
    client
        .send_event(announcement.clone())
        .await
        .expect("send served announcement with maintainers");

    let state_event = create_state_event(
        client.keys(),
        repo_id,
        &[("main", commit_hash.as_str())],
        &[],
        &[clone_url.as_str()],
        &[relay_url.as_str()],
    )
    .expect("build served state event with maintainers");
    client
        .send_event_and_note_purgatory(state_event.clone())
        .await
        .expect("send served state event with maintainers");

    push_to_relay(temp_dir.path(), &relay_domain, &npub, repo_id)
        .expect("push served repo data with maintainers");
    tokio::time::sleep(Duration::from_millis(900)).await;

    assert!(
        client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query served announcement with maintainers"),
        "served owner announcement should be promoted"
    );
    assert!(
        client
            .is_event_on_relay(state_event.id)
            .await
            .expect("query served state with maintainers"),
        "served owner state event should be promoted"
    );

    commit_hash
}

async fn wait_for_event_presence(
    client: &AuditClient,
    event_id: EventId,
    timeout: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if client.is_event_on_relay(event_id).await.unwrap_or(false) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

fn run_git_in_repo(repo_path: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .expect("run git command in repository")
}

fn run_git_bare(repo_path: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(["--git-dir", repo_path.to_str().expect("repo path utf8")])
        .args(args)
        .output()
        .expect("run git command against bare repository")
}

fn bare_ref_value(repo_path: &Path, ref_name: &str) -> Option<String> {
    let output = run_git_bare(repo_path, &["rev-parse", "--verify", ref_name]);
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn set_bare_ref(repo_path: &Path, ref_name: &str, commit: &str) {
    let output = run_git_bare(repo_path, &["update-ref", ref_name, commit]);
    assert!(
        output.status.success(),
        "failed to set bare ref {}: {}",
        ref_name,
        String::from_utf8_lossy(&output.stderr)
    );
}

struct PromotionRecoveryFixture {
    relay: TestRelay,
    client: AuditClient,
    repo_id: String,
    old_state_event: Event,
    issue: Event,
    pr: Event,
    pr_update: Event,
    reannouncement: Event,
    repo_path: PathBuf,
    archive_path: PathBuf,
    archive_backup: Vec<u8>,
}

async fn setup_parked_announcement_with_failed_ingest_recovery(
    test_name: &str,
    delete_state_with_tombstone: bool,
) -> PromotionRecoveryFixture {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id, old_state_event) =
        publish_served_repo_with_state_event(&client, test_name).await;
    let issue = client
        .create_issue(&announcement, "promotion recovery issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let repo_path = relay
        .git_data_path()
        .join(client.public_key().to_bech32().expect("npub"))
        .join(format!("{}.git", repo_id));
    let main_commit = bare_ref_value(&repo_path, "refs/heads/main").expect("read main ref");

    let announcement_coord = announcement_coordinate(&announcement, &repo_id);
    let pr = create_pr_event(
        client.keys(),
        &announcement_coord,
        &main_commit,
        "promotion recovery pr",
    )
    .expect("build pr");
    let pr_update = client
        .event_builder(Kind::GitPullRequestUpdate, "promotion recovery pr update")
        .tag(Tag::custom("a", vec![announcement_coord.clone()]))
        .tag(Tag::custom("c", vec![main_commit.clone()]))
        .build(client.keys())
        .expect("build pr update");
    client.send_event(pr.clone()).await.expect("send pr");
    client
        .send_event(pr_update.clone())
        .await
        .expect("send pr update");

    set_bare_ref(
        &repo_path,
        &format!("refs/nostr/{}", pr.id.to_hex()),
        &main_commit,
    );
    set_bare_ref(
        &repo_path,
        &format!("refs/nostr/{}", pr_update.id.to_hex()),
        &main_commit,
    );

    if delete_state_with_tombstone {
        let state_coord = format!("30618:{}:{}", client.public_key().to_hex(), repo_id);
        client
            .send_event(build_deletion(
                &client,
                &[],
                std::slice::from_ref(&state_coord),
            ))
            .await
            .expect("delete old state by coordinate");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&announcement_coord),
        ))
        .await
        .expect("delete announcement coordinate");
    tokio::time::sleep(Duration::from_millis(800)).await;

    let store = open_holding(&relay).await;
    let archive_rel = store
        .metadata_for_event(&announcement.id)
        .await
        .into_iter()
        .find(|e| e.kind == Kind::from(HOLDING_METADATA_KIND))
        .and_then(|e| metadata_tag_value(&e, HOLDING_ARCHIVE_PATH_TAG))
        .expect("archive relative path in metadata");
    let archive_path = relay.git_data_path().join(".archive").join(archive_rel);
    let archive_backup = std::fs::read(&archive_path).expect("read archive backup bytes");

    std::fs::write(&archive_path, b"corrupt archive bytes")
        .expect("corrupt archive to force ingest-time recovery failure");
    if repo_path.exists() {
        std::fs::remove_dir_all(&repo_path).expect("remove live repo after deletion");
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannouncement = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannouncement.clone())
        .await
        .expect("send re-announcement expected to park in purgatory");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(
        !client
            .is_event_on_relay(reannouncement.id)
            .await
            .expect("query parked re-announcement"),
        "corrupt archive should keep re-announcement parked in purgatory"
    );

    PromotionRecoveryFixture {
        relay,
        client,
        repo_id,
        old_state_event,
        issue,
        pr,
        pr_update,
        reannouncement,
        repo_path,
        archive_path,
        archive_backup,
    }
}

async fn submit_new_state_and_push_for_promotion(
    fixture: &PromotionRecoveryFixture,
    state_label: &str,
) -> Event {
    let temp_dir = tempfile::tempdir().expect("create temp repo for promotion");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("create promotion commit");

    let relay_url = fixture.relay.url().to_string();
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let npub = fixture
        .client
        .public_key()
        .to_bech32()
        .expect("npub for promotion push");
    let clone_url = format!("http://{}/{}/{}.git", relay_domain, npub, fixture.repo_id);

    let state_event = create_state_event(
        fixture.client.keys(),
        &fixture.repo_id,
        &[("main", commit_hash.as_str())],
        &[],
        &[clone_url.as_str()],
        &[relay_url.as_str()],
    )
    .unwrap_or_else(|e| panic!("build {state_label} state event: {e}"));

    fixture
        .client
        .send_event_and_note_purgatory(state_event.clone())
        .await
        .unwrap_or_else(|e| panic!("send {state_label} state event: {e}"));

    let status = run_git_in_repo(temp_dir.path(), &["branch", "-M", "main"]);
    assert!(
        status.status.success(),
        "rename branch for promotion push: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    push_to_relay(temp_dir.path(), &relay_domain, &npub, &fixture.repo_id)
        .unwrap_or_else(|e| panic!("push {state_label} state commit for promotion: {e}"));
    tokio::time::sleep(Duration::from_millis(900)).await;

    state_event
}

#[tokio::test]
async fn purgatory_promotion_restores_events_and_pr_git_archive_data() {
    let fixture =
        setup_parked_announcement_with_failed_ingest_recovery("promotion-recovery-success", false)
            .await;

    std::fs::write(&fixture.archive_path, &fixture.archive_backup)
        .expect("restore archive bytes before promotion");

    let promoted_state =
        submit_new_state_and_push_for_promotion(&fixture, "promotion-success").await;

    assert!(fixture
        .client
        .is_event_on_relay(fixture.reannouncement.id)
        .await
        .expect("query promoted re-announcement"));
    assert!(fixture
        .client
        .is_event_on_relay(fixture.issue.id)
        .await
        .expect("query restored issue after promotion"));
    assert!(fixture
        .client
        .is_event_on_relay(fixture.pr.id)
        .await
        .expect("query restored pr after promotion"));
    assert!(fixture
        .client
        .is_event_on_relay(fixture.pr_update.id)
        .await
        .expect("query restored pr update after promotion"));
    assert!(fixture
        .client
        .is_event_on_relay(promoted_state.id)
        .await
        .expect("query promoted new state"));

    let pr_ref = format!("refs/nostr/{}", fixture.pr.id.to_hex());
    let pr_update_ref = format!("refs/nostr/{}", fixture.pr_update.id.to_hex());
    assert!(
        bare_ref_value(&fixture.repo_path, &pr_ref).is_some(),
        "promotion recovery should restore PR git ref from archive"
    );
    assert!(
        bare_ref_value(&fixture.repo_path, &pr_update_ref).is_some(),
        "promotion recovery should restore PR update git ref from archive"
    );

    fixture.relay.stop().await;
}

#[tokio::test]
async fn purgatory_promotion_recovery_respects_state_tombstones() {
    let fixture =
        setup_parked_announcement_with_failed_ingest_recovery("promotion-recovery-tombstone", true)
            .await;

    std::fs::write(&fixture.archive_path, &fixture.archive_backup)
        .expect("restore archive bytes before tombstone promotion");

    let promoted_state =
        submit_new_state_and_push_for_promotion(&fixture, "promotion-tombstone").await;

    assert!(fixture
        .client
        .is_event_on_relay(fixture.reannouncement.id)
        .await
        .expect("query promoted re-announcement"));
    assert!(fixture
        .client
        .is_event_on_relay(promoted_state.id)
        .await
        .expect("query promoted new state"));
    assert!(
        !fixture
            .client
            .is_event_on_relay(fixture.old_state_event.id)
            .await
            .expect("query tombstoned old state"),
        "tombstoned state must not resurrect during recovery"
    );

    fixture.relay.stop().await;
}

#[tokio::test]
async fn purgatory_promotion_tombstoned_pr_events_do_not_restore_pr_refs() {
    let fixture = setup_parked_announcement_with_failed_ingest_recovery(
        "promotion-recovery-pr-tombstones",
        false,
    )
    .await;

    fixture
        .client
        .send_event(build_deletion(
            &fixture.client,
            &[fixture.pr.id, fixture.pr_update.id],
            &[],
        ))
        .await
        .expect("submit PR tombstone deletion request before promotion");
    tokio::time::sleep(Duration::from_millis(300)).await;

    std::fs::write(&fixture.archive_path, &fixture.archive_backup)
        .expect("restore archive bytes before PR tombstone promotion");

    let promoted_state =
        submit_new_state_and_push_for_promotion(&fixture, "promotion-pr-tombstone").await;

    assert!(fixture
        .client
        .is_event_on_relay(fixture.reannouncement.id)
        .await
        .expect("query promoted re-announcement"));
    assert!(fixture
        .client
        .is_event_on_relay(promoted_state.id)
        .await
        .expect("query promoted new state"));
    assert!(
        !fixture
            .client
            .is_event_on_relay(fixture.pr.id)
            .await
            .expect("query tombstoned pr"),
        "tombstoned PR must not resurrect during recovery"
    );
    assert!(
        !fixture
            .client
            .is_event_on_relay(fixture.pr_update.id)
            .await
            .expect("query tombstoned pr update"),
        "tombstoned PR update must not resurrect during recovery"
    );

    let pr_ref = format!("refs/nostr/{}", fixture.pr.id.to_hex());
    let pr_update_ref = format!("refs/nostr/{}", fixture.pr_update.id.to_hex());
    assert!(
        bare_ref_value(&fixture.repo_path, &pr_ref).is_none(),
        "tombstoned PR should have refs/nostr entry cleaned during recovery"
    );
    assert!(
        bare_ref_value(&fixture.repo_path, &pr_update_ref).is_none(),
        "tombstoned PR update should have refs/nostr entry cleaned during recovery"
    );

    fixture.relay.stop().await;
}

#[tokio::test]
async fn repeated_purgatory_promotion_attempts_remain_idempotent() {
    let fixture = setup_parked_announcement_with_failed_ingest_recovery(
        "promotion-recovery-idempotent",
        false,
    )
    .await;

    std::fs::write(&fixture.archive_path, &fixture.archive_backup)
        .expect("restore archive bytes before idempotent promotion");

    let first_state = submit_new_state_and_push_for_promotion(&fixture, "idempotent-first").await;

    // Trigger another post-promotion write flow; recovery should remain a no-op.
    let second_reannouncement =
        build_reannouncement(&fixture.client, &fixture.relay, &fixture.repo_id);
    fixture
        .client
        .send_event(second_reannouncement.clone())
        .await
        .expect("send second re-announcement after promotion");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(fixture
        .client
        .is_event_on_relay(fixture.issue.id)
        .await
        .expect("query issue after repeated promotion"));
    assert!(fixture
        .client
        .is_event_on_relay(fixture.pr.id)
        .await
        .expect("query pr after repeated promotion"));
    assert!(fixture
        .client
        .is_event_on_relay(first_state.id)
        .await
        .expect("query first promoted state"));
    assert!(fixture
        .client
        .is_event_on_relay(second_reannouncement.id)
        .await
        .expect("query second re-announcement after recovery"));

    let pending = open_holding(&fixture.relay)
        .await
        .eligible_recovery_records(
            &fixture.client.public_key().to_hex(),
            &fixture.repo_id,
            Timestamp::now(),
            DEFAULT_RETENTION,
        )
        .await;
    assert!(
        pending.is_empty(),
        "repeated promotion must keep recovery metadata drained"
    );

    fixture.relay.stop().await;
}

#[tokio::test]
async fn promotion_with_missing_or_invalid_recovery_artifacts_is_deterministic() {
    let fixture =
        setup_parked_announcement_with_failed_ingest_recovery("promotion-recovery-fallback", false)
            .await;

    let promoted_state =
        submit_new_state_and_push_for_promotion(&fixture, "promotion-fallback").await;

    assert!(fixture
        .client
        .is_event_on_relay(fixture.reannouncement.id)
        .await
        .expect("query promoted re-announcement"));
    assert!(fixture
        .client
        .is_event_on_relay(promoted_state.id)
        .await
        .expect("query promoted state in fallback path"));
    assert!(
        !fixture
            .client
            .is_event_on_relay(fixture.issue.id)
            .await
            .expect("query issue in fallback path"),
        "failed recovery should deterministically avoid partial event resurrection"
    );

    let pr_ref = format!("refs/nostr/{}", fixture.pr.id.to_hex());
    assert!(
        bare_ref_value(&fixture.repo_path, &pr_ref).is_none(),
        "without archive restore, PR git ref must remain absent"
    );

    let pending = open_holding(&fixture.relay)
        .await
        .eligible_recovery_records(
            &fixture.client.public_key().to_hex(),
            &fixture.repo_id,
            Timestamp::now(),
            DEFAULT_RETENTION,
        )
        .await;
    assert!(
        !pending.is_empty(),
        "failed recovery should leave deterministic holding records for future retries"
    );

    fixture.relay.stop().await;
}

#[tokio::test]
async fn maintainer_announcement_accept_route_runs_recovery_trigger_a() {
    let fixture = setup_parked_announcement_with_failed_ingest_recovery(
        "promotion-recovery-maintainer-accept-route",
        false,
    )
    .await;

    std::fs::write(&fixture.archive_path, &fixture.archive_backup)
        .expect("restore archive bytes before maintainer-accept recovery");

    let owner = AuditClient::new(fixture.relay.url(), AuditConfig::isolated())
        .await
        .expect("create owner client for maintainer route");
    let maintainer_hex = fixture.client.public_key().to_hex();

    let _owner_commit = publish_served_repo_for_identifier_with_maintainers(
        &owner,
        &fixture.relay,
        &fixture.repo_id,
        &[maintainer_hex],
    )
    .await;

    let maintainer_reannouncement =
        build_reannouncement(&fixture.client, &fixture.relay, &fixture.repo_id);
    fixture
        .client
        .send_event(maintainer_reannouncement.clone())
        .await
        .expect("send maintainer re-announcement recovery trigger");

    assert!(
        wait_for_event_presence(
            &fixture.client,
            maintainer_reannouncement.id,
            Duration::from_secs(8)
        )
        .await,
        "maintainer-accept route should accept re-announcement"
    );
    assert!(
        wait_for_event_presence(&fixture.client, fixture.issue.id, Duration::from_secs(8)).await,
        "maintainer-accept route should run recovery and restore issue"
    );
    assert!(
        wait_for_event_presence(&fixture.client, fixture.pr.id, Duration::from_secs(8)).await,
        "maintainer-accept route should run recovery and restore PR"
    );

    fixture.relay.stop().await;
}

#[tokio::test]
async fn state_event_received_route_runs_promotion_recovery_with_tombstones() {
    let fixture = setup_parked_announcement_with_failed_ingest_recovery(
        "promotion-recovery-state-route",
        true,
    )
    .await;

    std::fs::write(&fixture.archive_path, &fixture.archive_backup)
        .expect("restore archive bytes before state-route promotion");

    let collaborator = AuditClient::new(fixture.relay.url(), AuditConfig::isolated())
        .await
        .expect("create collaborator client");

    let commit_hash =
        publish_served_repo_for_identifier(&collaborator, &fixture.relay, &fixture.repo_id).await;

    let relay_url = fixture.relay.url().to_string();
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let collaborator_npub = collaborator
        .public_key()
        .to_bech32()
        .expect("collaborator npub for state-route test");
    let collaborator_clone = format!(
        "http://{}/{}/{}.git",
        relay_domain, collaborator_npub, fixture.repo_id
    );

    let recovery_state = create_state_event(
        fixture.client.keys(),
        &fixture.repo_id,
        &[("main", commit_hash.as_str())],
        &[],
        &[collaborator_clone.as_str()],
        &[relay_url.as_str()],
    )
    .expect("build state-route recovery trigger state event");

    fixture
        .client
        .send_event(recovery_state.clone())
        .await
        .expect("send state-route recovery trigger state event");

    assert!(
        wait_for_event_presence(
            &fixture.client,
            fixture.reannouncement.id,
            Duration::from_secs(8)
        )
        .await,
        "state-event route should promote parked re-announcement"
    );
    assert!(
        wait_for_event_presence(&fixture.client, recovery_state.id, Duration::from_secs(8)).await,
        "state-event route should accept recovery trigger state"
    );
    assert!(
        wait_for_event_presence(&fixture.client, fixture.issue.id, Duration::from_secs(8)).await,
        "state-event route should run recovery and restore issue"
    );
    assert!(
        !fixture
            .client
            .is_event_on_relay(fixture.old_state_event.id)
            .await
            .expect("query tombstoned state after state-route recovery"),
        "tombstoned state must not resurrect on state-event route"
    );

    fixture.relay.stop().await;
}

#[tokio::test]
async fn state_event_received_route_fallback_is_deterministic_when_recovery_artifacts_missing() {
    let fixture = setup_parked_announcement_with_failed_ingest_recovery(
        "promotion-recovery-state-route-fallback",
        false,
    )
    .await;

    let collaborator = AuditClient::new(fixture.relay.url(), AuditConfig::isolated())
        .await
        .expect("create collaborator client for fallback path");
    let commit_hash =
        publish_served_repo_for_identifier(&collaborator, &fixture.relay, &fixture.repo_id).await;

    let relay_url = fixture.relay.url().to_string();
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let collaborator_npub = collaborator
        .public_key()
        .to_bech32()
        .expect("collaborator npub for fallback state-route test");
    let collaborator_clone = format!(
        "http://{}/{}/{}.git",
        relay_domain, collaborator_npub, fixture.repo_id
    );

    let fallback_state = create_state_event(
        fixture.client.keys(),
        &fixture.repo_id,
        &[("main", commit_hash.as_str())],
        &[],
        &[collaborator_clone.as_str()],
        &[relay_url.as_str()],
    )
    .expect("build fallback state-route trigger state event");

    fixture
        .client
        .send_event(fallback_state.clone())
        .await
        .expect("send fallback state-route trigger state event");

    assert!(
        wait_for_event_presence(
            &fixture.client,
            fixture.reannouncement.id,
            Duration::from_secs(8)
        )
        .await,
        "state-event route should promote parked re-announcement in fallback path"
    );
    assert!(
        wait_for_event_presence(&fixture.client, fallback_state.id, Duration::from_secs(8)).await,
        "state-event route should accept fallback trigger state"
    );
    assert!(
        !fixture
            .client
            .is_event_on_relay(fixture.issue.id)
            .await
            .expect("query issue after state-route fallback"),
        "state-event route fallback must avoid partial event resurrection"
    );

    let pending = open_holding(&fixture.relay)
        .await
        .eligible_recovery_records(
            &fixture.client.public_key().to_hex(),
            &fixture.repo_id,
            Timestamp::now(),
            DEFAULT_RETENTION,
        )
        .await;
    assert!(
        !pending.is_empty(),
        "state-event route fallback should leave deterministic holding records for retries"
    );

    fixture.relay.stop().await;
}

#[tokio::test]
async fn reannouncement_restores_events_and_git_archive_happy_path() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "recovery-happy").await;
    let issue = client
        .create_issue(&announcement, "recovery issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(!client
        .is_event_on_relay(issue.id)
        .await
        .expect("query issue after deletion"));
    assert!(!client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query state after deletion"));

    let repo_path = relay
        .git_data_path()
        .join(client.public_key().to_bech32().expect("npub"))
        .join(format!("{}.git", repo_id));
    if repo_path.exists() {
        std::fs::remove_dir_all(&repo_path).expect("remove live repo to force archive restore");
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce.clone())
        .await
        .expect("send re-announcement");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(client
        .is_event_on_relay(reannounce.id)
        .await
        .expect("query re-announcement"));
    assert!(client
        .is_event_on_relay(issue.id)
        .await
        .expect("query restored issue"));
    assert!(client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query restored state"));
    assert!(repo_path.is_dir(), "git repo must be restored");

    let show_ref = Command::new("git")
        .args(["--git-dir", repo_path.to_str().unwrap(), "show-ref"])
        .output()
        .expect("run git show-ref on restored repo");
    assert!(show_ref.status.success(), "restored repo must contain refs");

    let store = open_holding(&relay).await;
    assert!(store.metadata_for_event(&issue.id).await.is_empty());
    assert!(store.metadata_for_event(&state_event.id).await.is_empty());

    relay.stop().await;
}

#[tokio::test]
async fn replacement_announcement_delisting_this_relay_triggers_runtime_deletion_flow() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "runtime-delist").await;
    let issue = client
        .create_issue(&announcement, "runtime delist issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert!(client
        .is_event_on_relay(issue.id)
        .await
        .expect("query issue before delist"));

    let replacement_delist = EventBuilder::new(Kind::GitRepoAnnouncement, "delist relay")
        .tags(vec![
            Tag::identifier(repo_id.clone()),
            Tag::custom("name", vec![repo_id.clone()]),
            Tag::custom(
                "clone",
                vec![format!(
                    "https://example.com/{}/{}.git",
                    client.public_key().to_hex(),
                    repo_id
                )],
            ),
            Tag::custom("relays", vec!["wss://example.com".to_string()]),
        ])
        .custom_created_at(Timestamp::from_secs(announcement.created_at.as_secs() + 30))
        .finalize(client.keys())
        .expect("build replacement delist announcement");

    let rejection = client.send_event(replacement_delist.clone()).await;
    assert!(
        rejection.is_err(),
        "replacement delist announcement should be rejected"
    );
    tokio::time::sleep(Duration::from_millis(900)).await;

    assert!(
        !client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query original announcement after delist"),
        "runtime de-list should delete the previously served announcement"
    );
    assert!(
        !client
            .is_event_on_relay(state_event.id)
            .await
            .expect("query state after runtime delist"),
        "runtime de-list should cascade-delete repository state"
    );
    assert!(
        !client
            .is_event_on_relay(issue.id)
            .await
            .expect("query issue after runtime delist"),
        "runtime de-list should cascade-delete dependent events"
    );

    let store = open_holding(&relay).await;
    assert!(
        !store.metadata_for_event(&announcement.id).await.is_empty(),
        "runtime de-list should archive announcement into holding metadata"
    );
    assert!(
        !store.metadata_for_event(&state_event.id).await.is_empty(),
        "runtime de-list should archive state into holding metadata"
    );
    assert!(
        !store.metadata_for_event(&issue.id).await.is_empty(),
        "runtime de-list should archive dependent events into holding metadata"
    );

    relay.stop().await;
}

#[tokio::test]
async fn out_of_retention_reannouncement_behaves_as_fresh_new_repo() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "recovery-expired").await;
    let issue = client
        .create_issue(&announcement, "expired issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    let store = open_holding(&relay).await;
    store
        .cleanup_expired(
            Timestamp::from_secs(Timestamp::now().as_secs() + 10_000),
            Duration::from_secs(1),
        )
        .await
        .expect("force cleanup expired holding records");

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce.clone())
        .await
        .expect("send re-announcement");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        !client
            .is_event_on_relay(reannounce.id)
            .await
            .expect("query re-announcement"),
        "without recovery data, re-announcement should be a fresh purgatory entry"
    );
    assert!(!client
        .is_event_on_relay(issue.id)
        .await
        .expect("query issue after out-of-retention re-announcement"));
    assert!(!client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query state after out-of-retention re-announcement"));

    relay.stop().await;
}

#[tokio::test]
async fn partial_recovery_missing_archive_restores_events_only_deterministically() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id, state_event) =
        publish_served_repo_with_state_event(&client, "recovery-missing-archive").await;
    let issue = client
        .create_issue(&announcement, "missing archive issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    let store = open_holding(&relay).await;
    let archive_rel = store
        .metadata_for_event(&announcement.id)
        .await
        .into_iter()
        .find(|e| e.kind == Kind::from(HOLDING_METADATA_KIND))
        .and_then(|e| metadata_tag_value(&e, HOLDING_ARCHIVE_PATH_TAG))
        .expect("archive relative path in metadata");
    let archive_path = relay.git_data_path().join(".archive").join(archive_rel);
    std::fs::remove_file(&archive_path).expect("remove archive file to force partial recovery");

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce.clone())
        .await
        .expect("send re-announcement");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(client
        .is_event_on_relay(reannounce.id)
        .await
        .expect("query re-announcement"));
    assert!(client
        .is_event_on_relay(issue.id)
        .await
        .expect("query restored issue"));
    assert!(client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query restored state"));

    let store = open_holding(&relay).await;
    assert!(store.metadata_for_event(&issue.id).await.is_empty());

    relay.stop().await;
}

#[tokio::test]
async fn partial_recovery_missing_holding_payload_restores_git_only_deterministically() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id) = publish_served_repo(&client, "recovery-missing-payload").await;
    let issue = client
        .create_issue(&announcement, "missing payload issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    let store = open_holding(&relay).await;
    store
        .delete_archived_payload(&issue.id)
        .await
        .expect("delete archived issue payload from holding");

    let repo_path = relay
        .git_data_path()
        .join(client.public_key().to_bech32().expect("npub"))
        .join(format!("{}.git", repo_id));
    if repo_path.exists() {
        std::fs::remove_dir_all(&repo_path).expect("remove live repo to require archive restore");
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce.clone())
        .await
        .expect("send re-announcement");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(
        repo_path.is_dir(),
        "git repository should be restored from archive"
    );
    assert!(!client
        .is_event_on_relay(issue.id)
        .await
        .expect("query missing-payload issue after recovery"));

    let store = open_holding(&relay).await;
    assert!(store.metadata_for_event(&issue.id).await.is_empty());

    relay.stop().await;
}

#[tokio::test]
async fn repeated_reannouncement_recovery_trigger_is_idempotent() {
    let relay = TestRelay::start_with_lmdb().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id) = publish_served_repo(&client, "recovery-idempotent").await;
    let issue = client
        .create_issue(&announcement, "idempotent issue", "body", vec![])
        .expect("build issue");
    client.send_event(issue.clone()).await.expect("send issue");

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion");
    tokio::time::sleep(Duration::from_millis(700)).await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    client
        .send_event(build_reannouncement(&client, &relay, &repo_id))
        .await
        .expect("first re-announcement");
    tokio::time::sleep(Duration::from_millis(700)).await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    let second = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(second.clone())
        .await
        .expect("second re-announcement");
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(client
        .is_event_on_relay(issue.id)
        .await
        .expect("query issue after repeated recovery"));
    assert!(client
        .is_event_on_relay(second.id)
        .await
        .expect("query second re-announcement"));

    let store = open_holding(&relay).await;
    let pending = store
        .eligible_recovery_records(
            &client.public_key().to_hex(),
            &repo_id,
            Timestamp::now(),
            DEFAULT_RETENTION,
        )
        .await;
    assert!(
        pending.is_empty(),
        "recovered metadata must not remain pending"
    );

    relay.stop().await;
}

#[tokio::test]
async fn multi_maintainer_reannouncement_restores_deleted_owner_slice() {
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
        "recovery-multi",
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
        .expect("build deleted patch");
    for event in [&shared_patch, &deleted_patch] {
        client_a
            .send_event(event.clone())
            .await
            .expect("send patch event");
    }

    client_a
        .send_event(build_deletion(
            &client_a,
            &[],
            std::slice::from_ref(&coordinate_a),
        ))
        .await
        .expect("delete maintainer a announcement");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(!client_a
        .is_event_on_relay(deleted_patch.id)
        .await
        .expect("query deleted patch"));
    assert!(client_a
        .is_event_on_relay(shared_patch.id)
        .await
        .expect("query shared patch"));
    assert!(client_b
        .is_event_on_relay(announcement_b.id)
        .await
        .expect("query surviving announcement b"));

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce_a = build_reannouncement(&client_a, &relay, &repo_id);
    client_a
        .send_event(reannounce_a)
        .await
        .expect("reannounce maintainer a");
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(client_a
        .is_event_on_relay(deleted_patch.id)
        .await
        .expect("query restored a-only patch"));
    assert!(client_b
        .is_event_on_relay(announcement_b.id)
        .await
        .expect("query surviving announcement b after recovery"));

    relay.stop().await;
}

#[tokio::test]
async fn disrespector_mode_has_no_recovery_state_to_apply() {
    let relay = TestRelay::start_with_lmdb_deletion_disrespector().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");

    let (announcement, repo_id) = publish_served_repo(&client, "recovery-disrespector").await;
    let coordinate = announcement_coordinate(&announcement, &repo_id);
    client
        .send_event(build_deletion(
            &client,
            &[announcement.id],
            std::slice::from_ref(&coordinate),
        ))
        .await
        .expect("send deletion request in disrespector mode");
    tokio::time::sleep(Duration::from_millis(500)).await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    let reannounce = build_reannouncement(&client, &relay, &repo_id);
    client
        .send_event(reannounce)
        .await
        .expect("send replacement announcement in disrespector mode");

    let store = open_holding(&relay).await;
    let pending = store
        .eligible_recovery_records(
            &client.public_key().to_hex(),
            &repo_id,
            Timestamp::now(),
            DEFAULT_RETENTION,
        )
        .await;
    assert!(
        pending.is_empty(),
        "disrespector mode must not create holding recovery entries"
    );

    relay.stop().await;
}
