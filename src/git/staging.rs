//! Unsigned uploads stay in their view until a signed event earns family storage.
//!
//! A push naming a `refs/nostr/<event-id>` for which no signed event is known
//! writes its objects to the view's own object directory instead of the
//! identifier family. The family is never garbage-collected, so this keeps
//! abandoned uploads reclaimable. Accepting the PR event promotes the tip's
//! history into the family first.
//!
//! While a view holds staged objects every push to it is received into the
//! view, because a client may omit objects that only staging holds. Signed
//! tips of such pushes are recorded as *owed* before Git runs and stay owed
//! until their history is complete in the family alone. Compaction refuses to
//! run while anything is owed: the absence of a ref never proves that history
//! is disposable, since rollback depends on history no current ref names.
//!
//! Every function that reads or changes staged objects or the registry record
//! requires the caller to hold the family write lease. Pushes already hold it
//! for their whole duration, so it also excludes them from compaction.
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{bail, ensure, Context, Result};
use bitcoin_hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

use super::storage::{FamilyKey, LocalGitStorage, ObjectFormat};

mod worker;
pub use worker::{request_maintenance, run_worker};

const REGISTRY_DIR: &str = "staging";
const RETAINED_GLOB: &str = "--glob=refs/grasp/retained/*";

/// A signed ref tip whose history the family must hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tip {
    pub reference: String,
    pub oid: String,
}

impl Tip {
    pub fn new(reference: impl Into<String>, oid: impl Into<String>) -> Self {
        Self {
            reference: reference.into(),
            oid: oid.into(),
        }
    }
}

/// Persistent registration of one view holding staged objects.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Record {
    /// View path relative to the Git data root.
    view: PathBuf,
    #[serde(default)]
    owed: Vec<Tip>,
}

/// Outcome of one compaction.
#[derive(Debug, PartialEq, Eq)]
pub enum Compaction {
    /// No staged objects remain and the view is no longer registered.
    Done,
    /// Staging holds only history that live refs need and the family lacks.
    Pending,
}

/// A thin view resolved to its family and registry record.
struct View {
    path: PathBuf,
    storage: LocalGitStorage,
    key: FamilyKey,
    record: PathBuf,
}

impl View {
    /// `None` for a legacy repository that has no family alternate.
    fn resolve(view: &Path) -> Result<Option<Self>> {
        let path = std::fs::canonicalize(view)
            .with_context(|| format!("resolve view {}", view.display()))?;
        let text = match std::fs::read_to_string(path.join("objects/info/alternates")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let objects = PathBuf::from(text.lines().next().context("empty family alternate")?);
        let repo = objects.parent().context("family repository")?;
        let root = repo.ancestors().nth(4).context("family storage root")?;
        let identifier = repo
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".git"))
            .context("family identifier")?;
        // The family path names its object format; no Git process is needed.
        let format = match repo
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
        {
            Some("sha1") => ObjectFormat::Sha1,
            Some("sha256") => ObjectFormat::Sha256,
            _ => bail!("unsupported alternate for staging: {}", path.display()),
        };
        let storage = LocalGitStorage::new(root);
        let key = FamilyKey::new(format, identifier)?;
        ensure!(
            storage.family_objects_path(&key) == objects,
            "unsupported alternate for staging: {}",
            path.display()
        );
        let root = std::fs::canonicalize(storage.git_data_path())?;
        let relative = path
            .strip_prefix(&root)
            .context("view outside Git storage")?;
        let digest = sha256::Hash::hash(relative.as_os_str().as_encoded_bytes());
        let record = registry_dir(&storage).join(format!("{digest}.json"));
        Ok(Some(Self {
            path,
            storage,
            key,
            record,
        }))
    }

    fn family(&self) -> PathBuf {
        self.storage.family_repo_path(&self.key)
    }

    fn relative(&self) -> Result<PathBuf> {
        let root = std::fs::canonicalize(self.storage.git_data_path())?;
        Ok(self.path.strip_prefix(root)?.to_owned())
    }

    fn load(&self) -> Result<Option<Record>> {
        match std::fs::read(&self.record) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
                format!("parse staging record {}", self.record.display())
            })?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, record: &Record) -> Result<()> {
        let directory = self.record.parent().context("staging registry")?;
        std::fs::create_dir_all(directory)?;
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        file.write_all(&serde_json::to_vec(record)?)?;
        file.as_file().sync_all()?;
        file.persist(&self.record)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    fn unregister(&self) -> Result<()> {
        match std::fs::remove_file(&self.record) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        File::open(self.record.parent().context("staging registry")?)?.sync_all()?;
        Ok(())
    }
}

fn registry_dir(storage: &LocalGitStorage) -> PathBuf {
    storage.internal_path().join(REGISTRY_DIR)
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|c| c.is_ascii_hexdigit())
}

fn git(repo: &Path, args: &[&str], input: &[u8]) -> Result<Output> {
    spawn_git(repo, args, input, Stdio::null())
}

/// Run Git and keep its output. Only for commands that print one short line
/// per input line, which the reader thread drains while input is written.
fn git_output(repo: &Path, args: &[&str], input: &[u8]) -> Result<String> {
    let output = spawn_git(repo, args, input, Stdio::piped())?;
    ensure!(
        output.status.success(),
        "git {} failed in {}: {}",
        args.first().copied().unwrap_or_default(),
        repo.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn spawn_git(repo: &Path, args: &[&str], input: &[u8], stdout: Stdio) -> Result<Output> {
    let mut child = Command::new("git")
        .current_dir(repo)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn git {}", args.first().copied().unwrap_or_default()))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let input = input.to_owned();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let output = child.wait_with_output()?;
    match writer.join() {
        Ok(Err(error)) if error.kind() != std::io::ErrorKind::BrokenPipe => {
            return Err(error.into())
        }
        Ok(_) => {}
        Err(_) => bail!("git input writer panicked"),
    }
    Ok(output)
}

fn run(repo: &Path, args: &[&str]) -> Result<()> {
    let output = git(repo, args, b"")?;
    ensure!(
        output.status.success(),
        "git {} failed in {}: {}",
        args.first().copied().unwrap_or_default(),
        repo.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn object_exists(repo: &Path, oid: &str) -> Result<bool> {
    Ok(git(repo, &["cat-file", "-e", oid], b"")?.status.success())
}

/// Whether `oids` and their history are present in the family alone.
///
/// The walk stops at retained roots. Those were complete when installed and
/// the family is append-only, so the cost follows the new history rather than
/// the whole repository. Detecting damage behind a root is the integrity
/// worker's job; a damaged root fails this check and therefore the promotion.
fn complete_in_family(family: &Path, oids: &[&str]) -> Result<bool> {
    let mut input = Vec::new();
    for oid in oids {
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }
    input.extend_from_slice(format!("--not\n{RETAINED_GLOB}\n").as_bytes());
    let output = git(
        family,
        &["rev-list", "--objects", "--missing=error", "--stdin"],
        &input,
    )?;
    Ok(output.status.success())
}

/// Whether the view is registered as holding staged objects.
///
/// Reads one directory entry; safe without the family lease as a hint. A
/// decision that depends on it must be made while holding the lease.
pub fn is_staged(view: &Path) -> bool {
    View::resolve(view)
        .ok()
        .flatten()
        .is_some_and(|view| view.record.is_file())
}

/// Whether a staged view holds `oid` with all history the family lacks.
///
/// The walk stops at the family base tips the view advertises, so its cost
/// follows the staged history.
pub fn holds_history(view: &Path, oid: &str) -> bool {
    valid_oid(oid)
        && is_staged(view)
        && git(
            view,
            &[
                "rev-list",
                "--objects",
                "--missing=error",
                oid,
                "--not",
                "--alternate-refs",
            ],
            b"",
        )
        .is_ok_and(|output| output.status.success())
}

/// Whether signed history is still owed to the family from this view.
///
/// A view that owes history must not be removed, even with no refs left.
pub fn owes_history(view: &Path) -> bool {
    match View::resolve(view).and_then(|view| view.map(|view| view.load()).transpose()) {
        Ok(record) => record
            .flatten()
            .is_some_and(|record| !record.owed.is_empty()),
        // Unreadable ownership metadata is never permission to delete.
        Err(_) => true,
    }
}

/// Register the view and record `owed` tips before Git can write any object.
///
/// Returns `false` for a legacy repository without a family, which keeps its
/// own objects and is never staged.
pub fn stage(view: &Path, owed: &[Tip]) -> Result<bool> {
    let Some(view) = View::resolve(view)? else {
        return Ok(false);
    };
    ensure!(
        owed.iter().all(|tip| valid_oid(&tip.oid)),
        "invalid owed object ID"
    );
    let mut record = match view.load()? {
        Some(record) => record,
        None => {
            // Whatever the view holds before it is first staged predates
            // staging and cannot be told apart from accepted history.
            absorb_local_objects(&view)?;
            Record::default()
        }
    };
    record.view = view.relative()?;
    let before = record.owed.len();
    for tip in owed {
        if !record.owed.contains(tip) {
            record.owed.push(tip.clone());
        }
    }
    if before != record.owed.len() || !view.record.is_file() {
        view.save(&record)?;
    }
    Ok(true)
}

/// Move every object file of the view into the family.
///
/// Files are linked into the family before they are removed from the view, so
/// a concurrent reader of the view always finds each object in one of them.
fn absorb_local_objects(view: &View) -> Result<()> {
    let source = view.path.join("objects");
    let target = view.storage.family_objects_path(&view.key);
    let mut moved = Vec::new();
    for entry in std::fs::read_dir(&source)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "info" || !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = target.join(&name);
        let mut files: Vec<_> = std::fs::read_dir(entry.path())?
            .map(|file| file.map(|file| file.path()))
            .collect::<std::io::Result<_>>()?;
        // Git finds a pack through its index, so the index arrives last.
        files.sort_by_key(|file| file.extension().is_some_and(|ext| ext == "idx"));
        for file in files {
            if !file.is_file() {
                continue;
            }
            std::fs::create_dir_all(&directory)?;
            let destination = directory.join(file.file_name().context("object file name")?);
            match std::fs::hard_link(&file, &destination) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            moved.push(file);
        }
        File::open(&directory)?.sync_all()?;
    }
    if moved.is_empty() {
        return Ok(());
    }
    File::open(&target)?.sync_all()?;
    tracing::info!(
        view = %view.path.display(),
        files = moved.len(),
        "Moved existing view objects into the family before staging"
    );
    // Remove indexes first, the reverse of the order they were installed in.
    moved.sort_by_key(|file| file.extension().is_none_or(|ext| ext != "idx"));
    for file in moved {
        std::fs::remove_file(file)?;
    }
    Ok(())
}

/// Copy the history of `tips` into the family and retain it there.
///
/// Succeeds only when every tip is complete in the family alone, which is the
/// condition for accepting the event that names it.
pub fn promote(view: &Path, tips: &[Tip]) -> Result<()> {
    let Some(view) = View::resolve(view)? else {
        return Ok(());
    };
    promote_resolved(&view, tips)
}

fn promote_resolved(view: &View, tips: &[Tip]) -> Result<()> {
    if tips.is_empty() {
        return Ok(());
    }
    ensure!(
        tips.iter().all(|tip| valid_oid(&tip.oid)),
        "invalid staged object ID"
    );
    let family = view.family();
    let mut oids: Vec<&str> = tips.iter().map(|tip| tip.oid.as_str()).collect();
    oids.sort_unstable();
    oids.dedup();

    if !complete_in_family(&family, &oids)? {
        let source = view.path.to_str().context("non-UTF-8 view path")?;
        let mut args = vec![
            "-c",
            "uploadpack.allowAnySHA1InWant=true",
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-auto-maintenance",
            "--no-recurse-submodules",
            source,
        ];
        args.extend_from_slice(&oids);
        run(&family, &args).context("copy staged history into the family")?;
        ensure!(
            complete_in_family(&family, &oids)?,
            "promoted history is incomplete in the family"
        );
    }
    for tip in tips {
        view.storage
            .retain_tip(&view.key, &tip.reference, &tip.oid)?;
        view.storage
            .advertise_base_tip(&view.key, &tip.reference, &tip.oid)?;
    }
    Ok(())
}

/// Promote every owed tip and return how many remain owed.
///
/// A tip whose object is in neither store belongs to a push that never
/// completed and is dropped. Failures leave their tips owed for a retry.
pub fn settle(view: &Path) -> Result<usize> {
    let Some(view) = View::resolve(view)? else {
        return Ok(0);
    };
    settle_resolved(&view)
}

fn settle_resolved(view: &View) -> Result<usize> {
    let Some(mut record) = view.load()? else {
        return Ok(0);
    };
    if record.owed.is_empty() {
        return Ok(0);
    }
    let mut present = Vec::new();
    for tip in std::mem::take(&mut record.owed) {
        if object_exists(&view.path, &tip.oid)? {
            present.push(tip);
        } else {
            tracing::debug!(
                view = %view.path.display(),
                reference = %tip.reference,
                oid = %tip.oid,
                "Dropping owed tip of a push that did not complete"
            );
        }
    }
    // One fetch covers the usual case. After a failure retry each tip, so one
    // unavailable tip cannot keep independent history out of the family.
    if let Err(error) = promote_resolved(view, &present) {
        let batch = present.len() > 1;
        for tip in present {
            let failed = if batch {
                promote_resolved(view, std::slice::from_ref(&tip)).err()
            } else {
                None
            };
            if !batch || failed.is_some() {
                tracing::warn!(
                    view = %view.path.display(),
                    reference = %tip.reference,
                    oid = %tip.oid,
                    error = %failed.as_ref().unwrap_or(&error),
                    "Signed history remains staged; promotion will retry"
                );
                record.owed.push(tip);
            }
        }
    }
    view.save(&record)?;
    Ok(record.owed.len())
}

/// Shrink staging to the history that live refs need and the family lacks.
///
/// Refuses to run while any tip is owed. Every live ref is a root, so a
/// pending upload keeps exactly its own history.
pub fn compact(view: &Path) -> Result<Compaction> {
    let Some(view) = View::resolve(view)? else {
        return Ok(Compaction::Done);
    };
    if !view.record.is_file() {
        return Ok(Compaction::Done);
    }
    let owed = settle_resolved(&view)?;
    if owed > 0 {
        bail!("{owed} signed tips are still owed to the family");
    }
    run(
        &view.path,
        &["repack", "-a", "-d", "-l", "-q", "--no-write-bitmap-index"],
    )?;
    run(&view.path, &["prune", "--expire=now"])?;
    remove_loose_copies(&view)?;
    if has_local_objects(&view.path)? {
        return Ok(Compaction::Pending);
    }
    view.unregister()?;
    Ok(Compaction::Done)
}

/// Remove loose objects that the family also holds.
///
/// Repacking leaves them behind: they are reachable, so pruning keeps them,
/// and `--local` keeps them out of the new pack.
fn remove_loose_copies(view: &View) -> Result<()> {
    let objects = view.path.join("objects");
    let mut loose = Vec::new();
    for entry in std::fs::read_dir(&objects)? {
        let entry = entry?;
        let prefix = entry.file_name();
        let Some(prefix) = prefix.to_str().filter(|name| name.len() == 2) else {
            continue;
        };
        for object in std::fs::read_dir(entry.path())? {
            let object = object?;
            if let Some(rest) = object.file_name().to_str() {
                let oid = format!("{prefix}{rest}");
                if valid_oid(&oid) {
                    loose.push((oid, object.path()));
                }
            }
        }
    }
    if loose.is_empty() {
        return Ok(());
    }
    let mut input = Vec::new();
    for (oid, _) in &loose {
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }
    let report = git_output(
        &view.family(),
        &["cat-file", "--batch-check=%(objectname)"],
        &input,
    )?;
    ensure!(
        report.lines().count() == loose.len(),
        "unexpected object report from the family"
    );
    for ((oid, path), line) in loose.iter().zip(report.lines()) {
        if line == oid {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn has_local_objects(view: &Path) -> Result<bool> {
    for entry in std::fs::read_dir(view.join("objects"))? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "info" || !entry.file_type()?.is_dir() {
            continue;
        }
        if std::fs::read_dir(entry.path())?.next().is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Promote an accepted tip out of staging, taking the family lease.
///
/// A view without staged objects received its history into the family, so
/// there is nothing to copy and no lease is taken.
pub async fn promote_accepted(view: &Path, tip: Tip) -> Result<()> {
    promote_accepted_tips(view, vec![tip]).await
}

/// Promote every concrete State tip before accepting or releasing the event.
/// A State can adopt an unsigned upload without a subsequent Git push.
pub async fn promote_state(
    view: &Path,
    state: &crate::nostr::events::RepositoryState,
) -> Result<()> {
    let tips = state
        .branches
        .iter()
        .map(|branch| Tip::new(format!("refs/heads/{}", branch.name), &branch.commit))
        .chain(
            state
                .tags
                .iter()
                .map(|tag| Tip::new(format!("refs/tags/{}", tag.name), &tag.commit)),
        )
        .filter(|tip| !tip.oid.starts_with("ref: "))
        .collect();
    promote_accepted_tips(view, tips).await
}

async fn promote_accepted_tips(view: &Path, tips: Vec<Tip>) -> Result<()> {
    if !is_staged(view) {
        return Ok(());
    }
    let Some(resolved) = View::resolve(view)? else {
        return Ok(());
    };
    let lease = resolved.storage.write_lease(&resolved.key).await?;
    let path = resolved.path.clone();
    tokio::task::spawn_blocking(move || {
        let _lease = lease;
        promote(&path, &tips)
    })
    .await??;
    request_maintenance(view);
    Ok(())
}

#[cfg(test)]
mod tests;
