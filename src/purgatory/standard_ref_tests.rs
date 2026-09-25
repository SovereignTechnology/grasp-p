use super::*;
use crate::nostr::lifecycle::RepositoryLifecycle;
fn database() -> crate::nostr::SharedDatabase {
    Arc::new(nostr_memory::MemoryDatabase::unbounded())
}
fn refs(path: &Path) -> Result<std::collections::BTreeMap<String, String>, String> {
    crate::git::list_refs(path).map(|refs| refs.into_iter().collect())
}

fn git(path: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(path)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn repository(root: &Path, owner: PublicKey, name: &str) -> (PathBuf, String) {
    let path = root
        .join(owner.to_bech32().unwrap())
        .join(format!("{name}.git"));
    std::fs::create_dir_all(&path).unwrap();
    git(&path, &["init", "--bare"]);
    let tree = git(&path, &["mktree"]);
    let commit = git(&path, &["commit-tree", &tree, "-m", "test"]);
    (path, commit)
}

fn expire(p: &Purgatory, id: &str) {
    p.pr_events.get_mut(id).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
}

#[tokio::test]
async fn standard_refs_expire_after_restart_without_touching_other_refs() {
    let root = tempfile::tempdir().unwrap();
    let owner = Keys::generate().public_key();
    let p = Purgatory::new(root.path());
    let id = "ab".repeat(32);
    let reference = format!("refs/nostr/{id}");
    let mut paths = Vec::new();
    for name in ["one", "two"] {
        let (path, commit) = repository(root.path(), owner, name);
        git(&path, &["update-ref", &reference, &commit]);
        git(&path, &["update-ref", "refs/heads/main", &commit]);
        p.add_standard_pr_placeholder(id.clone(), commit, owner, name.into());
        paths.push(path);
    }
    let (unrelated, commit) = repository(root.path(), owner, "unrelated");
    git(&unrelated, &["update-ref", &reference, &commit]);
    let state = root.path().join("purgatory.json");
    p.save_to_disk(&state).unwrap();
    let restored = Purgatory::new(root.path());
    restored.restore_from_disk(&state).unwrap();
    assert_eq!(restored.find_pr(&id).unwrap().standard_refs.len(), 2);
    expire(&restored, &id);
    assert_eq!(
        restored.cleanup().2,
        0,
        "sync sweep must retain cleanup metadata"
    );
    assert_eq!(
        restored
            .cleanup_standard_pr_refs(&RepositoryLifecycle::in_memory(), &database())
            .await,
        1
    );
    assert!(restored.find_pr(&id).is_none());
    for path in paths {
        let refs = refs(&path).unwrap();
        assert!(!refs.contains_key(&reference));
        assert!(refs.contains_key("refs/heads/main"));
    }
    assert!(refs(&unrelated).unwrap().contains_key(&reference));
}

#[tokio::test]
async fn standard_ref_expiry_retries_lock_failure_and_preserves_replaced_ref() {
    let root = tempfile::tempdir().unwrap();
    let owner = Keys::generate().public_key();
    let (path, commit) = repository(root.path(), owner, "one");
    let p = Purgatory::new(root.path());
    let id = "cd".repeat(32);
    let reference = format!("refs/nostr/{id}");
    git(&path, &["update-ref", &reference, &commit]);
    p.add_standard_pr_placeholder(id.clone(), commit.clone(), owner, "one".into());
    expire(&p, &id);
    let lifecycle = RepositoryLifecycle::in_memory();
    let db = database();
    let lock = path.join(format!("{reference}.lock"));
    std::fs::write(&lock, b"").unwrap();
    assert_eq!(p.cleanup_standard_pr_refs(&lifecycle, &db).await, 0);
    assert!(p.find_pr(&id).is_some());
    std::fs::remove_file(lock).unwrap();
    let tree = git(&path, &["mktree"]);
    let replacement = git(&path, &["commit-tree", &tree, "-m", "replacement"]);
    git(&path, &["update-ref", &reference, &replacement]);
    assert_eq!(p.cleanup_standard_pr_refs(&lifecycle, &db).await, 0);
    assert_eq!(refs(&path).unwrap()[&reference], replacement);
    git(&path, &["update-ref", &reference, &commit]);
    assert_eq!(p.cleanup_standard_pr_refs(&lifecycle, &db).await, 1);
}

#[tokio::test]
async fn standard_ref_expiry_rechecks_refresh_and_event_arrival_after_push_lock() {
    let root = tempfile::tempdir().unwrap();
    let owner = Keys::generate().public_key();
    let (path, commit) = repository(root.path(), owner, "one");
    let p = Purgatory::new(root.path());
    let id = "ef".repeat(32);
    let reference = format!("refs/nostr/{id}");
    git(&path, &["update-ref", &reference, &commit]);
    let lifecycle = RepositoryLifecycle::in_memory();
    let db = database();
    for event_arrives in [false, true] {
        p.add_standard_pr_placeholder(id.clone(), commit.clone(), owner, "one".into());
        expire(&p, &id);
        let guard = lifecycle.read_repository(&owner.to_hex(), "one").await;
        let cleanup = p.cleanup_standard_pr_refs(&lifecycle, &db);
        tokio::pin!(cleanup);
        assert!(futures_util::poll!(&mut cleanup).is_pending());
        if event_arrives {
            p.remove_pr(&id);
        } else {
            p.add_standard_pr_placeholder(id.clone(), commit.clone(), owner, "one".into());
        }
        drop(guard);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), cleanup)
                .await
                .unwrap(),
            0
        );
        assert!(refs(&path).unwrap().contains_key(&reference));
    }
}

#[tokio::test]
async fn standard_push_authorization_records_each_repository_and_legacy_state_still_loads() {
    let root = tempfile::tempdir().unwrap();
    let owner = Keys::generate().public_key();
    let database: crate::nostr::SharedDatabase =
        Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let p = Arc::new(Purgatory::new(root.path()));
    let id = "12".repeat(32);
    let commit = "34".repeat(20);
    let line = format!(
        "{} {commit} refs/nostr/{id}\0report-status\n",
        "0".repeat(40)
    );
    let body = hyper::body::Bytes::from(format!("{:04x}{line}0000", line.len() + 4));
    for name in ["one", "two", "one"] {
        let result = crate::git::authorization::authorize_push(
            &database,
            name,
            &owner.to_hex(),
            &body,
            &p,
            root.path(),
        )
        .await
        .unwrap();
        assert!(result.authorized);
    }
    assert_eq!(p.find_pr(&id).unwrap().standard_refs.len(), 2);
    let state = root.path().join("state.json");
    p.save_to_disk(&state).unwrap();
    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
    for entry in json["pr_events"].as_object_mut().unwrap().values_mut() {
        entry.as_object_mut().unwrap().remove("standard_refs");
    }
    std::fs::write(&state, serde_json::to_vec(&json).unwrap()).unwrap();
    let restored = Purgatory::new(root.path());
    restored.restore_from_disk(&state).unwrap();
    assert!(restored.find_pr(&id).unwrap().standard_refs.is_empty());
}

#[tokio::test]
async fn standard_and_prs_copies_both_expire() {
    let root = tempfile::tempdir().unwrap();
    let owner = Keys::generate().public_key();
    let (path, commit) = repository(root.path(), owner, "one");
    let p = Purgatory::new(root.path());
    p.set_prs_cleanup_ctx(PrsCleanupCtx {
        git_data_path: root.path().to_path_buf(),
        repo_init_locks: Default::default(),
    });
    let id = "56".repeat(32);
    let reference = format!("refs/nostr/{id}");
    git(&path, &["update-ref", &reference, &commit]);
    p.add_standard_pr_placeholder(id.clone(), commit.clone(), owner, "one".into());
    p.add_prs_pr_placeholder(id.clone(), commit.clone(), owner, "one".into());
    let prs = crate::grasp06::paths::prs_repo_path(root.path(), &owner.to_hex(), "one");
    std::fs::create_dir_all(prs.parent().unwrap()).unwrap();
    git(
        root.path(),
        &[
            "clone",
            "--bare",
            path.to_str().unwrap(),
            prs.to_str().unwrap(),
        ],
    );
    git(&prs, &["update-ref", &reference, &commit]);
    expire(&p, &id);
    assert_eq!(
        p.cleanup_standard_pr_refs(&RepositoryLifecycle::in_memory(), &database())
            .await,
        0
    );
    assert!(!refs(&path).unwrap().contains_key(&reference));
    assert_eq!(p.cleanup().2, 1);
    assert!(!prs.exists());
    assert!(p.find_pr(&id).is_none());
}

#[tokio::test]
async fn standard_ref_expiry_preserves_event_accepted_after_last_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let keys = Keys::generate();
    let owner = keys.public_key();
    let (path, commit) = repository(root.path(), owner, "one");
    let event = EventBuilder::new(Kind::GitPullRequest, "")
        .tags([Tag::custom("c", [commit.clone()])])
        .finalize(&keys)
        .unwrap();
    let id = event.id.to_hex();
    let reference = format!("refs/nostr/{id}");
    git(&path, &["update-ref", &reference, &commit]);
    let p = Purgatory::new(root.path());
    p.add_standard_pr_placeholder(id.clone(), commit, owner, "one".into());
    expire(&p, &id);
    let db = database();
    db.save_event(&event).await.unwrap();
    assert_eq!(
        p.cleanup_standard_pr_refs(&RepositoryLifecycle::in_memory(), &db)
            .await,
        1
    );
    assert!(p.find_pr(&id).is_none());
    assert!(refs(&path).unwrap().contains_key(&reference));
}

#[tokio::test]
async fn standard_ref_expiry_retries_after_partial_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let owner = Keys::generate().public_key();
    let p = Purgatory::new(root.path());
    let id = "78".repeat(32);
    let reference = format!("refs/nostr/{id}");
    let mut paths = Vec::new();
    for name in ["one", "two", "rejected-push"] {
        let (path, commit) = repository(root.path(), owner, name);
        if name != "rejected-push" {
            git(&path, &["update-ref", &reference, &commit]);
        }
        p.add_standard_pr_placeholder(id.clone(), commit, owner, name.into());
        paths.push(path);
    }
    expire(&p, &id);
    let lock = paths[1].join(format!("{reference}.lock"));
    std::fs::write(&lock, b"").unwrap();
    let lifecycle = RepositoryLifecycle::in_memory();
    let db = database();
    assert_eq!(p.cleanup_standard_pr_refs(&lifecycle, &db).await, 0);
    assert!(!refs(&paths[0]).unwrap().contains_key(&reference));
    assert!(refs(&paths[1]).unwrap().contains_key(&reference));
    std::fs::remove_file(lock).unwrap();
    assert_eq!(p.cleanup_standard_pr_refs(&lifecycle, &db).await, 1);
    assert!(p.find_pr(&id).is_none());
}
