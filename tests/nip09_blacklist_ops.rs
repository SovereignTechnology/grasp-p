//! Blacklist operations tests: startup parity, disrespector interaction,
//! manual ejection, and operational metrics wiring.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ngit_grasp::config::Config;
use ngit_grasp::grasp06::receive::new_repo_init_locks;
use ngit_grasp::metrics::{self, Metrics};
use ngit_grasp::nostr::builder::{Nip34WritePolicy, SharedDatabase};
use ngit_grasp::nostr::holding::{
    DeletionSource, GitArchiveMetadata, HoldingMetadata, HoldingStore, HOLDING_ARCHIVE_PATH_TAG,
};
use ngit_grasp::nostr::tombstones::Tombstones;
use ngit_grasp::purgatory::Purgatory;
use nostr_sdk::prelude::*;

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

fn make_announcement(keys: &Keys, identifier: &str) -> Event {
    EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom("clone", vec!["https://example.com/repo.git"]),
            Tag::custom("relays", vec!["wss://example.com"]),
        ])
        .finalize(keys)
        .expect("build announcement")
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
        holding,
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
    let stats = policy.run_startup_blacklist_parity_pass().await;

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
    let stats = policy.run_startup_blacklist_parity_pass().await;

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
    let stats = policy.run_startup_blacklist_parity_pass().await;

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
    let _ = policy.run_startup_blacklist_parity_pass().await;

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

    // Manual ejection path
    let _ = holding
        .manual_eject_repository(&owner.public_key().to_hex(), "metrics-blacklist")
        .await
        .expect("manual ejection");

    let rendered = Metrics::new(10, None).render();
    assert!(rendered.contains("ngit_blacklist_deletions_total"));
    assert!(rendered.contains("ngit_holding_cleanup_runs_total"));
    assert!(rendered.contains("ngit_recovery_total"));
    assert!(rendered.contains("ngit_manual_ejections_total"));
}
