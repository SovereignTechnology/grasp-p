//! Blacklist operations tests: startup parity, disrespector interaction,
//! manual ejection, and operational metrics wiring.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ngit_grasp::config::Config;
use ngit_grasp::grasp06::receive::new_repo_init_locks;
use ngit_grasp::metrics::{self, REGISTRY};
use ngit_grasp::nostr::builder::Nip34WritePolicy;
use ngit_grasp::nostr::lifecycle::ReplaceableHistoryStore;
use ngit_grasp::nostr::lifecycle::RepositoryLifecycle;
use ngit_grasp::nostr::lifecycle::Tombstones;
use ngit_grasp::nostr::lifecycle::{
    DeletionSource, GitArchiveMetadata, HoldingMetadata, HoldingStore, HOLDING_ARCHIVE_PATH_TAG,
};
use ngit_grasp::nostr::SharedDatabase;
use ngit_grasp::purgatory::Purgatory;
use nostr_sdk::prelude::*;
use prometheus::{Encoder, TextEncoder};

fn metadata_has_tag(event: &Event, key: &str, value: Option<&str>) -> bool {
    event.tags.iter().any(|tag| {
        let v = tag.as_slice();
        v.len() >= 2 && v[0] == key && value.map(|expected| v[1] == expected).unwrap_or(true)
    })
}

fn repo_identifier(event: &Event) -> String {
    event
        .tags
        .iter()
        .find_map(|tag| {
            let v = tag.as_slice();
            (v.len() >= 2 && v[0] == "d").then(|| v[1].clone())
        })
        .expect("announcement identifier tag")
}

fn metric_value(rendered: &str, metric_name: &str, labels: &[(&str, &str)]) -> f64 {
    rendered
        .lines()
        .find_map(|line| {
            if !line.starts_with(metric_name) {
                return None;
            }

            let labels_match = labels
                .iter()
                .all(|(k, v)| line.contains(&format!("{k}=\"{v}\"")));
            if !labels_match {
                return None;
            }

            line.split_whitespace().last()?.parse::<f64>().ok()
        })
        .unwrap_or(0.0)
}

fn render_metrics_snapshot() -> String {
    let families = REGISTRY.gather();
    let mut bytes = Vec::new();
    TextEncoder::new()
        .encode(&families, &mut bytes)
        .expect("encode prometheus metrics");
    String::from_utf8(bytes).expect("utf8 metrics")
}

fn make_announcement_with_domain(keys: &Keys, identifier: &str, domain: &str) -> Event {
    EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom("clone", vec![format!("https://{domain}/repo.git")]),
            Tag::custom("relays", vec![format!("wss://{domain}")]),
        ])
        .finalize(keys)
        .expect("build announcement")
}

fn make_announcement(keys: &Keys, identifier: &str) -> Event {
    make_announcement_with_domain(keys, identifier, "example.com")
}

fn make_issue(keys: &Keys, announcement: &Event) -> Event {
    let coordinate = format!(
        "30617:{}:{}",
        announcement.pubkey.to_hex(),
        repo_identifier(announcement)
    );
    EventBuilder::new(Kind::from(1621), "issue")
        .tags(vec![Tag::custom("a", vec![coordinate])])
        .finalize(keys)
        .expect("build issue")
}

fn make_policy(
    config: Config,
    database: SharedDatabase,
    holding: HoldingStore,
    git_data_path: &std::path::Path,
) -> Nip34WritePolicy {
    let purgatory = Arc::new(Purgatory::new(git_data_path.to_path_buf()));
    Nip34WritePolicy::new(
        database,
        Tombstones::in_memory(),
        holding.clone(),
        RepositoryLifecycle::in_memory(),
        ReplaceableHistoryStore::in_memory(),
        git_data_path.to_path_buf(),
        purgatory,
        config,
        new_repo_init_locks(),
    )
}

fn base_config() -> Config {
    Config::parse_from(["ngit-grasp-test", "--domain", "test.example.com"])
}

#[tokio::test]
async fn startup_blacklist_scan_deletes_matching_repositories_via_holding_archive_path() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");

    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let announcement = make_announcement(&owner, "blacklisted-repo");
    let issue = make_issue(&owner, &announcement);

    db.save_event(&announcement)
        .await
        .expect("save announcement");
    db.save_event(&issue).await.expect("save issue");

    let owner_npub = owner.public_key().to_bech32().expect("npub");
    let owner_dir = owner_npub.clone();
    let repo_path = git_dir.path().join(&owner_dir).join("blacklisted-repo.git");
    std::fs::create_dir_all(repo_path.join("refs")).expect("create bare repo dir");

    let mut config = base_config();
    config.repository_blacklist = owner_npub;

    let policy = make_policy(config, db.clone(), holding.clone(), git_dir.path());
    let stats = policy.deletion().run_startup_blacklist_parity_pass().await;

    assert_eq!(stats.matched_announcements, 1);
    assert_eq!(stats.successful_deletions, 1);
    assert!(
        db.event_by_id(&announcement.id)
            .await
            .expect("query announcement")
            .is_none(),
        "matching announcement must be deleted from main DB"
    );
    assert!(
        db.event_by_id(&issue.id)
            .await
            .expect("query issue")
            .is_none(),
        "dependent events must be cascade-deleted from main DB"
    );

    assert!(holding.has_event(&announcement.id).await);
    assert!(holding.has_event(&issue.id).await);
    let announcement_meta = holding.metadata_for_event(&announcement.id).await;
    assert!(
        announcement_meta
            .iter()
            .any(|m| metadata_has_tag(m, "holding-source", Some("blacklist"))),
        "holding metadata must mark blacklist deletion source"
    );

    let archive_rel = announcement_meta
        .iter()
        .flat_map(|m| m.tags.iter())
        .find_map(|tag| {
            let v = tag.as_slice();
            (v.len() >= 2 && v[0] == HOLDING_ARCHIVE_PATH_TAG).then(|| v[1].clone())
        })
        .expect("blacklist deletion should record archive path");
    let archive_abs = holding
        .archive_absolute_path(&archive_rel)
        .expect("resolve archive path");
    assert!(
        archive_abs.exists(),
        "archive artifact must exist after deletion"
    );
}

#[tokio::test]
async fn blacklist_startup_deletion_runs_even_when_disrespector_is_enabled() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");
    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let announcement = make_announcement(&owner, "repo-disrespector-blacklist");
    db.save_event(&announcement)
        .await
        .expect("save announcement");

    let owner_npub = owner.public_key().to_bech32().expect("npub");
    std::fs::create_dir_all(
        git_dir
            .path()
            .join(owner_npub.clone())
            .join("repo-disrespector-blacklist.git"),
    )
    .expect("create bare repo dir");

    let config = Config {
        repository_blacklist: owner_npub,
        deletion_request_disrespector: true,
        ..base_config()
    };

    let policy = make_policy(config, db.clone(), holding, git_dir.path());
    let stats = policy.deletion().run_startup_blacklist_parity_pass().await;

    assert_eq!(stats.successful_deletions, 1);
    assert!(
        db.event_by_id(&announcement.id)
            .await
            .expect("query announcement")
            .is_none(),
        "disrespector mode must not block blacklist deletion path"
    );
}

#[tokio::test]
async fn startup_blacklist_scan_leaves_non_matching_repositories_untouched() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");
    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let announcement = make_announcement(&owner, "safe-repo");
    db.save_event(&announcement)
        .await
        .expect("save announcement");

    let mut config = base_config();
    config.repository_blacklist = "different-repo".to_string();

    let policy = make_policy(config, db.clone(), holding.clone(), git_dir.path());
    let stats = policy.deletion().run_startup_blacklist_parity_pass().await;

    assert_eq!(stats.matched_announcements, 0);
    assert!(
        db.event_by_id(&announcement.id)
            .await
            .expect("query announcement")
            .is_some(),
        "non-matching repository must remain in main DB"
    );
    assert!(holding
        .metadata_for_event(&announcement.id)
        .await
        .is_empty());
}

#[tokio::test]
async fn startup_whitelist_scan_deletes_non_matching_repositories_via_holding_archive_path() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");

    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let announcement = make_announcement_with_domain(&owner, "not-whitelisted", "test.example.com");
    let issue = make_issue(&owner, &announcement);

    db.save_event(&announcement)
        .await
        .expect("save announcement");
    db.save_event(&issue).await.expect("save issue");

    let owner_npub = owner.public_key().to_bech32().expect("npub");
    std::fs::create_dir_all(
        git_dir
            .path()
            .join(owner_npub)
            .join("not-whitelisted.git")
            .join("refs"),
    )
    .expect("create bare repo dir");

    let mut config = base_config();
    config.repository_whitelist = "allowed-repo".to_string();

    let policy = make_policy(config, db.clone(), holding.clone(), git_dir.path());
    let stats = policy.deletion().run_startup_whitelist_parity_pass().await;

    assert_eq!(stats.mismatched_announcements, 1);
    assert_eq!(stats.successful_deletions, 1);
    assert!(
        db.event_by_id(&announcement.id)
            .await
            .expect("query announcement")
            .is_none(),
        "non-whitelisted announcement must be deleted from main DB"
    );
    assert!(
        db.event_by_id(&issue.id)
            .await
            .expect("query issue")
            .is_none(),
        "dependent events must be cascade-deleted from main DB"
    );

    assert!(holding.has_event(&announcement.id).await);
    assert!(holding.has_event(&issue.id).await);
    let announcement_meta = holding.metadata_for_event(&announcement.id).await;
    assert!(
        announcement_meta
            .iter()
            .any(|m| metadata_has_tag(m, "holding-source", Some("whitelist"))),
        "holding metadata must mark whitelist deletion source"
    );
}

#[tokio::test]
async fn startup_whitelist_scan_leaves_matching_repositories_untouched() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");

    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let announcement = make_announcement_with_domain(&owner, "matching-repo", "test.example.com");
    db.save_event(&announcement)
        .await
        .expect("save announcement");

    let mut config = base_config();
    config.repository_whitelist = "matching-repo".to_string();

    let policy = make_policy(config, db.clone(), holding.clone(), git_dir.path());
    let stats = policy.deletion().run_startup_whitelist_parity_pass().await;

    assert_eq!(stats.mismatched_announcements, 0);
    assert!(
        db.event_by_id(&announcement.id)
            .await
            .expect("query announcement")
            .is_some(),
        "whitelisted repository must remain in main DB"
    );
    assert!(holding
        .metadata_for_event(&announcement.id)
        .await
        .is_empty());
}

#[tokio::test]
async fn startup_whitelist_restore_recovers_now_whitelisted_scope_and_is_idempotent() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");
    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let owner_npub = owner.public_key().to_bech32().expect("owner npub");
    let announcement =
        make_announcement_with_domain(&owner, "whitelist-restore-repo", "test.example.com");
    let issue = make_issue(&owner, &announcement);

    db.save_event(&announcement)
        .await
        .expect("save announcement");
    db.save_event(&issue).await.expect("save issue");

    let repo_path = git_dir
        .path()
        .join(owner_npub.clone())
        .join("whitelist-restore-repo.git");
    std::fs::create_dir_all(repo_path.join("refs")).expect("create bare repo dir");

    let deletion_policy = make_policy(
        Config {
            repository_whitelist: "allowed-repo".to_string(),
            ..base_config()
        },
        db.clone(),
        holding.clone(),
        git_dir.path(),
    );
    let deletion_stats = deletion_policy
        .deletion()
        .run_startup_whitelist_parity_pass()
        .await;
    assert_eq!(deletion_stats.successful_deletions, 1);

    if repo_path.exists() {
        std::fs::remove_dir_all(&repo_path).expect("remove stale repo directory");
    }

    let announcement_meta = holding.metadata_for_event(&announcement.id).await;
    let archive_rel = announcement_meta
        .iter()
        .flat_map(|m| m.tags.iter())
        .find_map(|tag| {
            let v = tag.as_slice();
            (v.len() >= 2 && v[0] == HOLDING_ARCHIVE_PATH_TAG).then(|| v[1].clone())
        })
        .expect("whitelist deletion should record archive path");
    let archive_abs = holding
        .archive_absolute_path(&archive_rel)
        .expect("resolve archive path");
    assert!(archive_abs.exists(), "archive must exist before restore");

    let restore_policy = make_policy(
        Config {
            repository_whitelist: format!("allowed-repo,{}", owner_npub),
            ..base_config()
        },
        db.clone(),
        holding.clone(),
        git_dir.path(),
    );

    let before = render_metrics_snapshot();
    let restore_stats = restore_policy
        .deletion()
        .run_startup_whitelist_restore_pass()
        .await;
    assert_eq!(restore_stats.scanned_scopes, 1);
    assert_eq!(restore_stats.attempted_restores, 1);
    assert_eq!(restore_stats.successful_restores, 1);
    assert_eq!(restore_stats.failed_restores, 0);
    assert_eq!(restore_stats.skipped_scopes, 0);

    assert!(
        db.event_by_id(&announcement.id)
            .await
            .expect("query announcement")
            .is_some(),
        "announcement should be restored from holding"
    );
    assert!(
        db.event_by_id(&issue.id)
            .await
            .expect("query issue")
            .is_some(),
        "dependent events should be restored from holding"
    );
    assert!(
        holding
            .metadata_for_event(&announcement.id)
            .await
            .is_empty(),
        "holding metadata should be cleaned after restore"
    );
    assert!(!archive_abs.exists(), "consumed archive should be deleted");

    let after = render_metrics_snapshot();
    let attempted_before = metric_value(
        &before,
        "ngit_whitelist_startup_restore_total",
        &[("result", "attempted"), ("reason", "none")],
    );
    let attempted_after = metric_value(
        &after,
        "ngit_whitelist_startup_restore_total",
        &[("result", "attempted"), ("reason", "none")],
    );
    assert!(
        attempted_after >= attempted_before + 1.0,
        "expected attempted restore metric to increase by at least 1 (before={}, after={})",
        attempted_before,
        attempted_after
    );

    let success_before = metric_value(
        &before,
        "ngit_whitelist_startup_restore_total",
        &[("result", "succeeded"), ("reason", "none")],
    );
    let success_after = metric_value(
        &after,
        "ngit_whitelist_startup_restore_total",
        &[("result", "succeeded"), ("reason", "none")],
    );
    assert!(
        success_after >= success_before + 1.0,
        "expected successful restore metric to increase by at least 1 (before={}, after={})",
        success_before,
        success_after
    );

    let second_stats = restore_policy
        .deletion()
        .run_startup_whitelist_restore_pass()
        .await;
    assert_eq!(second_stats.scanned_scopes, 0);
    assert_eq!(second_stats.attempted_restores, 0);
    assert_eq!(second_stats.successful_restores, 0);
    assert_eq!(second_stats.failed_restores, 0);
    assert_eq!(second_stats.skipped_scopes, 0);
}

#[tokio::test]
async fn startup_whitelist_restore_skips_scopes_still_not_whitelisted() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");
    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let owner_npub = owner.public_key().to_bech32().expect("owner npub");
    let announcement =
        make_announcement_with_domain(&owner, "whitelist-still-blocked-repo", "test.example.com");
    db.save_event(&announcement)
        .await
        .expect("save announcement");

    std::fs::create_dir_all(
        git_dir
            .path()
            .join(owner_npub)
            .join("whitelist-still-blocked-repo.git")
            .join("refs"),
    )
    .expect("create bare repo dir");

    let deletion_policy = make_policy(
        Config {
            repository_whitelist: "allowed-repo".to_string(),
            ..base_config()
        },
        db.clone(),
        holding.clone(),
        git_dir.path(),
    );
    let deletion_stats = deletion_policy
        .deletion()
        .run_startup_whitelist_parity_pass()
        .await;
    assert_eq!(deletion_stats.successful_deletions, 1);

    let restore_policy = make_policy(
        Config {
            repository_whitelist: "allowed-repo".to_string(),
            ..base_config()
        },
        db.clone(),
        holding,
        git_dir.path(),
    );

    let before = render_metrics_snapshot();
    let restore_stats = restore_policy
        .deletion()
        .run_startup_whitelist_restore_pass()
        .await;
    assert_eq!(restore_stats.scanned_scopes, 1);
    assert_eq!(restore_stats.attempted_restores, 0);
    assert_eq!(restore_stats.successful_restores, 0);
    assert_eq!(restore_stats.failed_restores, 0);
    assert_eq!(restore_stats.skipped_scopes, 1);

    assert!(
        db.event_by_id(&announcement.id)
            .await
            .expect("query announcement")
            .is_none(),
        "still-non-whitelisted scope must not be restored"
    );

    let after = render_metrics_snapshot();
    let skipped_before = metric_value(
        &before,
        "ngit_whitelist_startup_restore_total",
        &[("result", "skipped"), ("reason", "not_whitelisted")],
    );
    let skipped_after = metric_value(
        &after,
        "ngit_whitelist_startup_restore_total",
        &[("result", "skipped"), ("reason", "not_whitelisted")],
    );
    assert_eq!(skipped_after, skipped_before + 1.0);
}

#[tokio::test]
async fn startup_blacklist_restore_recovers_unblacklisted_scope_and_is_idempotent() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");
    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let owner_npub = owner.public_key().to_bech32().expect("owner npub");
    let announcement = make_announcement(&owner, "blacklist-restore-repo");
    let issue = make_issue(&owner, &announcement);

    db.save_event(&announcement)
        .await
        .expect("save announcement");
    db.save_event(&issue).await.expect("save issue");

    let repo_path = git_dir
        .path()
        .join(owner_npub.clone())
        .join("blacklist-restore-repo.git");
    std::fs::create_dir_all(repo_path.join("refs")).expect("create bare repo dir");

    let deletion_policy = make_policy(
        Config {
            repository_blacklist: owner_npub.clone(),
            ..base_config()
        },
        db.clone(),
        holding.clone(),
        git_dir.path(),
    );
    let deletion_stats = deletion_policy
        .deletion()
        .run_startup_blacklist_parity_pass()
        .await;
    assert_eq!(deletion_stats.successful_deletions, 1);

    if repo_path.exists() {
        std::fs::remove_dir_all(&repo_path).expect("remove stale repo directory");
    }

    let announcement_meta = holding.metadata_for_event(&announcement.id).await;
    let archive_rel = announcement_meta
        .iter()
        .flat_map(|m| m.tags.iter())
        .find_map(|tag| {
            let v = tag.as_slice();
            (v.len() >= 2 && v[0] == HOLDING_ARCHIVE_PATH_TAG).then(|| v[1].clone())
        })
        .expect("blacklist deletion should record archive path");
    let archive_abs = holding
        .archive_absolute_path(&archive_rel)
        .expect("resolve archive path");
    assert!(archive_abs.exists(), "archive must exist before restore");

    let restore_policy = make_policy(
        Config {
            blacklist_auto_restore: true,
            ..base_config()
        },
        db.clone(),
        holding.clone(),
        git_dir.path(),
    );

    let before = render_metrics_snapshot();
    let restore_stats = restore_policy
        .deletion()
        .run_startup_blacklist_restore_pass()
        .await;
    assert_eq!(restore_stats.scanned_scopes, 1);
    assert_eq!(restore_stats.attempted_restores, 1);
    assert_eq!(restore_stats.successful_restores, 1);
    assert_eq!(restore_stats.failed_restores, 0);
    assert_eq!(restore_stats.skipped_scopes, 0);

    assert!(
        db.event_by_id(&announcement.id)
            .await
            .expect("query announcement")
            .is_some(),
        "announcement should be restored from holding"
    );
    assert!(
        db.event_by_id(&issue.id)
            .await
            .expect("query issue")
            .is_some(),
        "dependent events should be restored from holding"
    );
    assert!(
        holding
            .metadata_for_event(&announcement.id)
            .await
            .is_empty(),
        "holding metadata should be cleaned after restore"
    );
    assert!(!archive_abs.exists(), "consumed archive should be deleted");

    let after = render_metrics_snapshot();
    let attempted_before = metric_value(
        &before,
        "ngit_blacklist_startup_restore_total",
        &[("result", "attempted"), ("reason", "none")],
    );
    let attempted_after = metric_value(
        &after,
        "ngit_blacklist_startup_restore_total",
        &[("result", "attempted"), ("reason", "none")],
    );
    assert!(
        attempted_after >= attempted_before + 1.0,
        "expected attempted restore metric to increase by at least 1 (before={}, after={})",
        attempted_before,
        attempted_after
    );

    let success_before = metric_value(
        &before,
        "ngit_blacklist_startup_restore_total",
        &[("result", "succeeded"), ("reason", "none")],
    );
    let success_after = metric_value(
        &after,
        "ngit_blacklist_startup_restore_total",
        &[("result", "succeeded"), ("reason", "none")],
    );
    assert!(
        success_after >= success_before + 1.0,
        "expected successful restore metric to increase by at least 1 (before={}, after={})",
        success_before,
        success_after
    );

    let second_stats = restore_policy
        .deletion()
        .run_startup_blacklist_restore_pass()
        .await;
    assert_eq!(second_stats.scanned_scopes, 0);
    assert_eq!(second_stats.attempted_restores, 0);
    assert_eq!(second_stats.successful_restores, 0);
    assert_eq!(second_stats.failed_restores, 0);
    assert_eq!(second_stats.skipped_scopes, 0);
}

#[tokio::test]
async fn startup_blacklist_restore_skips_scopes_still_blacklisted() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");
    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let owner_npub = owner.public_key().to_bech32().expect("owner npub");
    let announcement = make_announcement(&owner, "blacklist-still-blocked-repo");
    db.save_event(&announcement)
        .await
        .expect("save announcement");

    std::fs::create_dir_all(
        git_dir
            .path()
            .join(owner_npub.clone())
            .join("blacklist-still-blocked-repo.git")
            .join("refs"),
    )
    .expect("create bare repo dir");

    let deletion_policy = make_policy(
        Config {
            repository_blacklist: owner_npub.clone(),
            ..base_config()
        },
        db.clone(),
        holding.clone(),
        git_dir.path(),
    );
    let deletion_stats = deletion_policy
        .deletion()
        .run_startup_blacklist_parity_pass()
        .await;
    assert_eq!(deletion_stats.successful_deletions, 1);

    let restore_policy = make_policy(
        Config {
            repository_blacklist: owner_npub,
            blacklist_auto_restore: true,
            ..base_config()
        },
        db.clone(),
        holding,
        git_dir.path(),
    );

    let before = render_metrics_snapshot();
    let restore_stats = restore_policy
        .deletion()
        .run_startup_blacklist_restore_pass()
        .await;
    assert_eq!(restore_stats.scanned_scopes, 1);
    assert_eq!(restore_stats.attempted_restores, 0);
    assert_eq!(restore_stats.successful_restores, 0);
    assert_eq!(restore_stats.failed_restores, 0);
    assert_eq!(restore_stats.skipped_scopes, 1);

    assert!(
        db.event_by_id(&announcement.id)
            .await
            .expect("query announcement")
            .is_none(),
        "still-blacklisted scope must not be restored"
    );

    let after = render_metrics_snapshot();
    let skipped_before = metric_value(
        &before,
        "ngit_blacklist_startup_restore_total",
        &[("result", "skipped"), ("reason", "still_blacklisted")],
    );
    let skipped_after = metric_value(
        &after,
        "ngit_blacklist_startup_restore_total",
        &[("result", "skipped"), ("reason", "still_blacklisted")],
    );
    assert_eq!(skipped_after, skipped_before + 1.0);
}

#[tokio::test]
async fn manual_ejection_removes_holding_and_archive_idempotently() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");

    let owner = Keys::generate();
    let owner_hex = owner.public_key().to_hex();
    let owner_npub = owner.public_key().to_bech32().expect("owner npub");

    let event = EventBuilder::new(Kind::TextNote, "payload")
        .finalize(&owner)
        .expect("build event");

    let archive_rel = format!("{}/{}-{}.tar.gz", owner_npub, "manual-repo", 1234);
    let archive_abs = git_dir.path().join(".archive").join(&archive_rel);
    std::fs::create_dir_all(archive_abs.parent().expect("archive parent"))
        .expect("create archive dir");
    std::fs::write(&archive_abs, b"archive-bytes").expect("write archive file");

    holding
        .archive_event(
            &event,
            &HoldingMetadata {
                deleted_at: Timestamp::from_secs(1234),
                source: DeletionSource::Blacklist,
                coordinate: Some(format!("30617:{}:manual-repo", owner_hex)),
                identifier: Some("manual-repo".to_string()),
                owner_pubkey: Some(owner_hex.clone()),
                git_archive: Some(GitArchiveMetadata {
                    relative_path: archive_rel,
                    created_at: Timestamp::from_secs(1234),
                }),
            },
        )
        .await
        .expect("archive event with metadata");

    let first = holding
        .manual_eject_repository(&owner_hex, "manual-repo")
        .await
        .expect("first ejection");
    assert_eq!(first.records_matched, 1);
    assert_eq!(first.metadata_deleted, 1);
    assert_eq!(first.archived_events_deleted, 1);
    assert_eq!(first.archive_files_deleted, 1);

    let second = holding
        .manual_eject_repository(&owner_hex, "manual-repo")
        .await
        .expect("second ejection");
    assert_eq!(second.records_matched, 0);
    assert_eq!(second.metadata_deleted, 0);
    assert_eq!(second.archived_events_deleted, 0);
    assert_eq!(second.archive_files_deleted, 0);
}

#[tokio::test]
async fn metrics_increment_on_blacklist_cleanup_recovery_and_manual_ejection_paths() {
    let relay_dir = tempfile::tempdir().expect("relay tempdir");
    let git_dir = tempfile::tempdir().expect("git tempdir");

    // Blacklist deletion path
    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let holding = HoldingStore::open_lmdb(relay_dir.path(), git_dir.path())
        .await
        .expect("open holding lmdb");
    let owner = Keys::generate();
    let owner_npub = owner.public_key().to_bech32().expect("owner npub");
    let announcement = make_announcement(&owner, "metrics-blacklist");
    db.save_event(&announcement)
        .await
        .expect("save announcement");
    std::fs::create_dir_all(
        git_dir
            .path()
            .join(owner_npub.clone())
            .join("metrics-blacklist.git"),
    )
    .expect("create bare repo dir");

    let config = Config {
        repository_blacklist: owner_npub,
        ..base_config()
    };
    let policy = make_policy(config, db.clone(), holding.clone(), git_dir.path());
    let _ = policy.deletion().run_startup_blacklist_parity_pass().await;

    // Holding cleanup path
    let stale = EventBuilder::new(Kind::TextNote, "stale")
        .finalize(&Keys::generate())
        .expect("build stale event");
    holding
        .archive_event(
            &stale,
            &HoldingMetadata {
                deleted_at: Timestamp::from_secs(1),
                source: DeletionSource::Nip09,
                coordinate: None,
                identifier: None,
                owner_pubkey: None,
                git_archive: None,
            },
        )
        .await
        .expect("archive stale event");
    let _ = holding
        .cleanup_expired(Timestamp::from_secs(500), Duration::from_secs(10))
        .await
        .expect("cleanup");

    // Recovery path metrics wiring (called by recovery workflow).
    metrics::record_recovery_attempt();
    metrics::record_recovery_partial();

    // Startup restore path metrics wiring (called by restore passes).
    metrics::record_blacklist_startup_restore_attempt();
    metrics::record_whitelist_startup_restore_attempt();

    // Manual ejection path
    let _ = holding
        .manual_eject_repository(&owner.public_key().to_hex(), "metrics-blacklist")
        .await
        .expect("manual ejection");

    let rendered = render_metrics_snapshot();
    assert!(rendered.contains("ngit_blacklist_deletions_total"));
    assert!(rendered.contains("ngit_blacklist_startup_restore_total"));
    assert!(rendered.contains("ngit_whitelist_startup_restore_total"));
    assert!(rendered.contains("ngit_holding_cleanup_runs_total"));
    assert!(rendered.contains("ngit_recovery_total"));
    assert!(rendered.contains("ngit_manual_ejections_total"));
}
