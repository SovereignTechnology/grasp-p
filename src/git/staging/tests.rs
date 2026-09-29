use super::*;
use std::process::Command;

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub storage: LocalGitStorage,
    pub key: FamilyKey,
    pub view: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_view("owner")
    }

    /// A view at `<parent>/repo.git` below the Git data root.
    pub fn with_view(parent: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(root.path().canonicalize().unwrap());
        let key = FamilyKey::sha1("repo").unwrap();
        storage.ensure_family(&key).unwrap();
        let view = storage.git_data_path().join(parent).join("repo.git");
        std::fs::create_dir_all(view.parent().unwrap()).unwrap();
        storage.create_thin_view(&key, &view).unwrap();
        Self {
            _root: root,
            storage,
            key,
            view,
        }
    }

    pub fn family(&self) -> PathBuf {
        self.storage.family_repo_path(&self.key)
    }

    /// Whether the family holds `oid` and its whole history by itself.
    fn family_holds(&self, oid: &str) -> bool {
        Command::new("git")
            .current_dir(self.family())
            .args(["rev-list", "--objects", "--missing=error", oid])
            .output()
            .unwrap()
            .status
            .success()
    }
}

fn output(repo: &Path, args: &[&str], input: &[u8]) -> String {
    let mut child = Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// Write a commit with one unique blob into `repo`'s own object directory.
pub(super) fn commit(repo: &Path, content: &str, parent: Option<&str>) -> String {
    let blob = output(repo, &["hash-object", "-w", "--stdin"], content.as_bytes());
    let tree = output(
        repo,
        &["mktree"],
        format!("100644 blob {blob}\tfile\n").as_bytes(),
    );
    let mut args = vec!["commit-tree", tree.as_str(), "-m", content];
    if let Some(parent) = parent {
        args.extend(["-p", parent]);
    }
    output(repo, &args, b"")
}

pub(super) fn reference(repo: &Path, name: &str, oid: &str) {
    output(repo, &["update-ref", name, oid], b"");
}

pub(super) fn delete_reference(repo: &Path, name: &str) {
    output(repo, &["update-ref", "-d", name], b"");
}

fn family_objects(fixture: &Fixture) -> String {
    output(
        &fixture.family(),
        &["cat-file", "--batch-all-objects", "--batch-check"],
        b"",
    )
}

pub(super) const PENDING: &str =
    "refs/nostr/1111111111111111111111111111111111111111111111111111111111111111";
pub(super) const ABANDONED: &str =
    "refs/nostr/2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn abandoned_upload_is_reclaimed_without_touching_the_family() {
    let fixture = Fixture::new();
    let before = family_objects(&fixture);
    assert!(stage(&fixture.view, &[]).unwrap());
    let tip = commit(&fixture.view, "abandoned", None);
    reference(&fixture.view, ABANDONED, &tip);

    assert_eq!(compact(&fixture.view).unwrap(), Compaction::Pending);
    assert!(object_exists(&fixture.view, &tip).unwrap());
    assert!(is_staged(&fixture.view));

    delete_reference(&fixture.view, ABANDONED);
    assert_eq!(compact(&fixture.view).unwrap(), Compaction::Done);
    assert!(!object_exists(&fixture.view, &tip).unwrap());
    assert!(!is_staged(&fixture.view));
    assert_eq!(family_objects(&fixture), before);
}

#[test]
fn pending_upload_keeps_its_history_when_a_sibling_is_reclaimed() {
    let fixture = Fixture::new();
    stage(&fixture.view, &[]).unwrap();
    let parent = commit(&fixture.view, "pending parent", None);
    let pending = commit(&fixture.view, "pending", Some(&parent));
    let abandoned = commit(&fixture.view, "abandoned", None);
    reference(&fixture.view, PENDING, &pending);
    reference(&fixture.view, ABANDONED, &abandoned);
    // Pack both uploads together so reclaiming one must rewrite the pack.
    assert_eq!(compact(&fixture.view).unwrap(), Compaction::Pending);

    delete_reference(&fixture.view, ABANDONED);
    assert_eq!(compact(&fixture.view).unwrap(), Compaction::Pending);

    assert!(!object_exists(&fixture.view, &abandoned).unwrap());
    output(
        &fixture.view,
        &["rev-list", "--objects", "--missing=error", &pending],
        b"",
    );
    assert!(!fixture.family_holds(&pending));
}

#[test]
fn promotion_makes_history_complete_in_the_family_alone() {
    let fixture = Fixture::new();
    stage(&fixture.view, &[]).unwrap();
    let parent = commit(&fixture.view, "parent", None);
    let tip = commit(&fixture.view, "tip", Some(&parent));
    let unrelated = commit(&fixture.view, "unrelated", None);
    reference(&fixture.view, PENDING, &tip);
    reference(&fixture.view, ABANDONED, &unrelated);

    promote(&fixture.view, &[Tip::new(PENDING, &tip)]).unwrap();

    assert!(fixture.family_holds(&tip));
    assert!(
        !object_exists(&fixture.family(), &unrelated).unwrap(),
        "promotion copies only the accepted history"
    );
    delete_reference(&fixture.view, ABANDONED);
    assert_eq!(compact(&fixture.view).unwrap(), Compaction::Done);
    // The view still serves the promoted ref, now through the family.
    output(
        &fixture.view,
        &["rev-list", "--objects", "--missing=error", &tip],
        b"",
    );
}

#[test]
fn promotion_refuses_incomplete_history() {
    let fixture = Fixture::new();
    stage(&fixture.view, &[]).unwrap();
    let parent = commit(&fixture.view, "parent", None);
    let tip = commit(&fixture.view, "tip", Some(&parent));
    reference(&fixture.view, PENDING, &tip);
    std::fs::remove_file(
        fixture
            .view
            .join("objects")
            .join(&parent[..2])
            .join(&parent[2..]),
    )
    .unwrap();

    assert!(promote(&fixture.view, &[Tip::new(PENDING, &tip)]).is_err());
    assert!(!fixture.family_holds(&tip));
    let retained = output(
        &fixture.family(),
        &["for-each-ref", "refs/grasp/retained/"],
        b"",
    );
    assert_eq!(retained, "", "no retention root for incomplete history");
}

#[test]
fn owed_history_survives_ref_deletion_until_the_family_holds_it() {
    let fixture = Fixture::new();
    let tip_oid = {
        // Record the signed tip before its objects exist, as a push does.
        let probe = Fixture::new();
        commit(&probe.view, "signed", None)
    };
    let owed = Tip::new("refs/heads/main", &tip_oid);
    stage(&fixture.view, std::slice::from_ref(&owed)).unwrap();
    assert_eq!(commit(&fixture.view, "signed", None), tip_oid);
    reference(&fixture.view, "refs/heads/main", &tip_oid);

    // Promotion cannot install its retention root while this lock exists.
    let digest = sha256::Hash::hash(format!("refs/heads/main\0{tip_oid}").as_bytes());
    let lock = fixture
        .family()
        .join(format!("refs/grasp/retained/{digest}.lock"));
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::write(&lock, b"").unwrap();
    assert_eq!(settle(&fixture.view).unwrap(), 1);

    // A State deletion removes the ref. Rollback still needs the history.
    delete_reference(&fixture.view, "refs/heads/main");
    assert!(
        compact(&fixture.view).is_err(),
        "owed tips block compaction"
    );
    assert!(object_exists(&fixture.view, &tip_oid).unwrap());
    assert!(is_staged(&fixture.view));

    std::fs::remove_file(&lock).unwrap();
    assert_eq!(compact(&fixture.view).unwrap(), Compaction::Done);
    assert!(fixture.family_holds(&tip_oid));
}

#[test]
fn owed_tip_of_a_push_that_never_completed_is_dropped() {
    let fixture = Fixture::new();
    let absent = "0123456789012345678901234567890123456789";
    stage(&fixture.view, &[Tip::new("refs/heads/main", absent)]).unwrap();

    assert_eq!(settle(&fixture.view).unwrap(), 0);
    assert_eq!(compact(&fixture.view).unwrap(), Compaction::Done);
}

#[test]
fn one_unavailable_owed_tip_does_not_hold_back_another() {
    let fixture = Fixture::new();
    stage(&fixture.view, &[]).unwrap();
    let parent = commit(&fixture.view, "broken parent", None);
    let broken = commit(&fixture.view, "broken", Some(&parent));
    let sound = commit(&fixture.view, "sound", None);
    stage(
        &fixture.view,
        &[
            Tip::new("refs/heads/broken", &broken),
            Tip::new("refs/heads/sound", &sound),
        ],
    )
    .unwrap();
    std::fs::remove_file(
        fixture
            .view
            .join("objects")
            .join(&parent[..2])
            .join(&parent[2..]),
    )
    .unwrap();

    assert_eq!(settle(&fixture.view).unwrap(), 1);
    assert!(fixture.family_holds(&sound));
}

#[test]
fn legacy_repository_without_a_family_is_never_staged() {
    let root = tempfile::tempdir().unwrap();
    output(root.path(), &["init", "--bare", "legacy.git"], b"");
    let legacy = root.path().join("legacy.git");

    assert!(!stage(&legacy, &[]).unwrap());
    assert!(!is_staged(&legacy));
    assert_eq!(compact(&legacy).unwrap(), Compaction::Done);
}

#[test]
fn objects_held_before_first_staging_move_to_the_family() {
    let fixture = Fixture::new();
    let packed = commit(&fixture.view, "packed before staging", None);
    reference(&fixture.view, "refs/heads/packed", &packed);
    output(&fixture.view, &["repack", "-a", "-d", "-l", "-q"], b"");
    delete_reference(&fixture.view, "refs/heads/packed");
    let loose = commit(&fixture.view, "loose before staging", None);

    stage(&fixture.view, &[]).unwrap();

    assert!(fixture.family_holds(&packed));
    assert!(fixture.family_holds(&loose));
    assert!(!has_local_objects(&fixture.view).unwrap());
    // Neither commit has a ref, yet compaction cannot reach them any more.
    assert_eq!(compact(&fixture.view).unwrap(), Compaction::Done);
    assert!(fixture.family_holds(&packed));
    assert!(fixture.family_holds(&loose));
}
