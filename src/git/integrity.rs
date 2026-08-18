//! Identifier-family Git integrity inspection and repair orchestration.
//!
//! The durable integrity boundary is one object-format/identifier family plus
//! every owner and GRASP-06 view backed by it. Legacy repository migration is
//! only one producer of these families; steady-state and operator-triggered
//! checks use the same report.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bitcoin_hashes::{sha256, Hash};
use clap::Args;
use nostr_sdk::prelude::{FromBech32, PublicKey};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use super::storage::{FamilyKey, LocalGitStorage, ObjectFormat};
use super::validate_repository_identifier;

const REQUEST_VERSION: u32 = 1;
const REQUEST_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Arguments for queueing an identifier-family integrity check in the live
/// relay process.
#[derive(Debug, Args)]
pub struct IntegrityCheckArgs {
    /// Repository identifier (`d` tag value). All object formats and views for
    /// this identifier are checked together.
    #[arg(long)]
    pub identifier: String,

    /// Attempt repair using accepted repository clone URLs.
    #[arg(long, default_value_t = false)]
    pub repair: bool,

    /// Git data path containing the `.grasp` family storage directory.
    #[arg(long, env = "NGIT_GIT_DATA_PATH", default_value = "./data/git")]
    pub git_data_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IntegrityRequest {
    version: u32,
    identifier: String,
    repair: bool,
}

/// Queue an integrity request for the running relay. Requests are durable and
/// idempotent; if the service is stopped, the next launch consumes them.
pub fn enqueue_manual_check(args: &IntegrityCheckArgs) -> Result<PathBuf> {
    if !validate_repository_identifier(&args.identifier) {
        return Err(anyhow!(
            "invalid repository identifier {:?}",
            args.identifier
        ));
    }
    let storage = LocalGitStorage::new(&args.git_data_path);
    let directory = request_directory(&storage);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("create integrity request directory {}", directory.display()))?;
    let request = IntegrityRequest {
        version: REQUEST_VERSION,
        identifier: args.identifier.clone(),
        repair: args.repair,
    };
    let digest =
        sha256::Hash::hash(format!("{}\0{}", request.identifier, request.repair).as_bytes());
    let path = directory.join(format!("{digest}.json"));
    crate::atomic_file::write(&path, &serde_json::to_vec_pretty(&request)?)
        .with_context(|| format!("write integrity request {}", path.display()))?;
    Ok(path)
}

/// A view ref whose target is absent from the identifier family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingRefTarget {
    pub view: PathBuf,
    pub reference: String,
    pub oid: String,
}

/// Integrity state for one identifier family and all views that use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyIntegrityReport {
    pub key: FamilyKey,
    pub views: Vec<PathBuf>,
    pub refs_checked: usize,
    pub missing_oids: BTreeSet<String>,
    pub missing_ref_targets: Vec<MissingRefTarget>,
    pub invalid_alternates: Vec<PathBuf>,
    pub pack_errors: Vec<String>,
    pub fsck_diagnostics: Vec<String>,
}

impl FamilyIntegrityReport {
    /// Whether the family and every one of its views passed inspection.
    pub fn is_healthy(&self) -> bool {
        self.missing_oids.is_empty()
            && self.missing_ref_targets.is_empty()
            && self.invalid_alternates.is_empty()
            && self.pack_errors.is_empty()
            && self.fsck_diagnostics.is_empty()
    }
}

/// Network operations needed by the family healer.
///
/// Production delegates to the existing hardened purgatory fetch client;
/// tests can supply deterministic local object sources.
#[async_trait]
pub trait FamilyRepairSource: Send + Sync {
    async fn accepted_clone_urls(&self, identifier: &str) -> Result<Vec<String>>;

    async fn fetch_missing_oids(
        &self,
        target_view: &Path,
        url: &str,
        oids: &[String],
    ) -> Result<Vec<String>>;
}

/// Result of an optional repair attempt followed by a fresh integrity check.
#[derive(Debug)]
pub struct FamilyRepairOutcome {
    pub initial: FamilyIntegrityReport,
    pub final_report: FamilyIntegrityReport,
    pub sources_tried: Vec<String>,
    pub source_failures: Vec<String>,
}

impl FamilyRepairOutcome {
    pub fn repaired(&self) -> bool {
        !self.initial.is_healthy() && self.final_report.is_healthy()
    }
}

#[derive(Default)]
struct PassStats {
    checked: usize,
    healthy: usize,
    repaired: usize,
    unresolved: usize,
    failed: usize,
}

/// Start the non-blocking integrity worker.
///
/// It checks and heals every installed family once after startup, then
/// consumes identifier-scoped requests written by [`enqueue_manual_check`].
pub fn spawn_integrity_worker(
    storage: LocalGitStorage,
    source: Arc<crate::purgatory::sync::RealSyncContext>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_startup_pass(&storage, source.as_ref()).await;
        let first = tokio::time::Instant::now() + REQUEST_POLL_INTERVAL;
        let mut interval = tokio::time::interval_at(first, REQUEST_POLL_INTERVAL);
        loop {
            interval.tick().await;
            process_manual_requests(&storage, source.as_ref()).await;
        }
    })
}

async fn run_startup_pass<S: FamilyRepairSource + ?Sized>(storage: &LocalGitStorage, source: &S) {
    let families = match discover_families(storage) {
        Ok(families) => families,
        Err(error) => {
            error!(%error, "Git identifier-family integrity startup discovery failed");
            return;
        }
    };
    info!(
        families = families.len(),
        "Git identifier-family integrity startup pass started"
    );
    let mut stats = PassStats::default();
    for key in families {
        run_one_family(storage, &key, source, true, "startup", &mut stats).await;
        tokio::task::yield_now().await;
    }
    info!(
        checked = stats.checked,
        healthy = stats.healthy,
        repaired = stats.repaired,
        unresolved = stats.unresolved,
        failed = stats.failed,
        "Git identifier-family integrity startup pass completed"
    );
}

async fn process_manual_requests<S: FamilyRepairSource + ?Sized>(
    storage: &LocalGitStorage,
    source: &S,
) {
    let requests = match load_requests(storage) {
        Ok(requests) => requests,
        Err(error) => {
            error!(%error, "Read manual Git integrity requests");
            return;
        }
    };
    for (path, request) in requests {
        let families = match discover_families(storage) {
            Ok(families) => families
                .into_iter()
                .filter(|key| key.identifier == request.identifier)
                .collect::<Vec<_>>(),
            Err(error) => {
                error!(
                    identifier = %request.identifier,
                    %error,
                    "Manual Git integrity family discovery failed"
                );
                remove_consumed_request(&path);
                continue;
            }
        };
        if families.is_empty() {
            error!(
                identifier = %request.identifier,
                "Manual Git integrity request matched no identifier family"
            );
            remove_consumed_request(&path);
            continue;
        }
        let mut stats = PassStats::default();
        for key in families {
            run_one_family(storage, &key, source, request.repair, "manual", &mut stats).await;
        }
        info!(
            identifier = %request.identifier,
            repair = request.repair,
            checked = stats.checked,
            healthy = stats.healthy,
            repaired = stats.repaired,
            unresolved = stats.unresolved,
            failed = stats.failed,
            "Manual Git identifier-family integrity request completed"
        );
        remove_consumed_request(&path);
    }
}

async fn run_one_family<S: FamilyRepairSource + ?Sized>(
    storage: &LocalGitStorage,
    key: &FamilyKey,
    source: &S,
    repair: bool,
    trigger: &'static str,
    stats: &mut PassStats,
) {
    stats.checked += 1;
    let outcome = match check_and_repair_family(storage, key, source, repair).await {
        Ok(outcome) => outcome,
        Err(error) => {
            stats.failed += 1;
            error!(
                identifier = %key.identifier,
                object_format = %key.object_format,
                trigger,
                repair,
                %error,
                "Git identifier-family integrity check failed"
            );
            return;
        }
    };
    if outcome.final_report.is_healthy() {
        if outcome.repaired() {
            stats.repaired += 1;
            info!(
                identifier = %key.identifier,
                object_format = %key.object_format,
                trigger,
                sources_tried = outcome.sources_tried.len(),
                "Git identifier family repaired"
            );
        } else {
            stats.healthy += 1;
        }
        return;
    }

    stats.unresolved += 1;
    let missing_sample = outcome
        .final_report
        .missing_oids
        .iter()
        .take(16)
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let diagnostic = outcome
        .final_report
        .fsck_diagnostics
        .first()
        .map(String::as_str)
        .unwrap_or("");
    let source_failure = outcome
        .source_failures
        .first()
        .map(String::as_str)
        .unwrap_or("");
    error!(
        identifier = %key.identifier,
        object_format = %key.object_format,
        trigger,
        repair,
        views = outcome.final_report.views.len(),
        missing_oids = outcome.final_report.missing_oids.len(),
        missing_sample,
        missing_ref_targets = outcome.final_report.missing_ref_targets.len(),
        invalid_alternates = outcome.final_report.invalid_alternates.len(),
        pack_errors = outcome.final_report.pack_errors.len(),
        fsck_diagnostics = outcome.final_report.fsck_diagnostics.len(),
        diagnostic,
        sources_tried = outcome.sources_tried.len(),
        source_failures = outcome.source_failures.len(),
        source_failure,
        "Git identifier family remains unhealthy after integrity check"
    );
}

fn request_directory(storage: &LocalGitStorage) -> PathBuf {
    storage.internal_path().join("integrity-requests")
}

fn load_requests(storage: &LocalGitStorage) -> Result<Vec<(PathBuf, IntegrityRequest)>> {
    let directory = request_directory(storage);
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut paths = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    paths.sort();
    let mut requests = Vec::new();
    for path in paths {
        let request: IntegrityRequest = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("parse integrity request {}", path.display()))?;
        if request.version != REQUEST_VERSION
            || !validate_repository_identifier(&request.identifier)
        {
            return Err(anyhow!("invalid integrity request {}", path.display()));
        }
        requests.push((path, request));
    }
    Ok(requests)
}

fn remove_consumed_request(path: &Path) {
    if let Err(error) = std::fs::remove_file(path) {
        warn!(request = %path.display(), %error, "Remove consumed Git integrity request");
    }
}

/// Inspect a family, repair local view wiring, fetch missing OIDs from every
/// accepted clone source as needed, then inspect it again.
pub async fn check_and_repair_family<S: FamilyRepairSource + ?Sized>(
    storage: &LocalGitStorage,
    key: &FamilyKey,
    source: &S,
    repair: bool,
) -> Result<FamilyRepairOutcome> {
    let lease = storage.write_lease(key).await?;
    let initial = inspect_family(storage, key)?;
    if initial.is_healthy() || !repair {
        return Ok(FamilyRepairOutcome {
            final_report: initial.clone(),
            initial,
            sources_tried: Vec::new(),
            source_failures: Vec::new(),
        });
    }

    for view in &initial.invalid_alternates {
        storage.configure_thin_view(key, view)?;
    }
    drop(lease);

    let mut current = inspect_family(storage, key)?;
    let mut sources_tried = Vec::new();
    let mut source_failures = Vec::new();
    if !current.missing_oids.is_empty() {
        let mut urls = source.accepted_clone_urls(&key.identifier).await?;
        urls.sort();
        urls.dedup();
        let target = current
            .views
            .first()
            .cloned()
            .unwrap_or_else(|| storage.family_repo_path(key));
        for url in urls {
            let missing: Vec<_> = current.missing_oids.iter().cloned().collect();
            if missing.is_empty() {
                break;
            }
            sources_tried.push(url.clone());
            if let Err(error) = source.fetch_missing_oids(&target, &url, &missing).await {
                source_failures.push(format!("{url}: {error}"));
            }
            current = inspect_family(storage, key)?;
        }
    }

    // A view ref that was deliberately preserved while its target was absent
    // becomes a useful family root as soon as repair restores that object.
    let _lease = storage.write_lease(key).await?;
    for target in &initial.missing_ref_targets {
        if oid_exists(&storage.family_repo_path(key), &target.oid)? {
            let source_ref = format!("{}:{}", target.view.display(), target.reference);
            storage.retain_tip(key, &source_ref, &target.oid)?;
            storage.advertise_base_tip(key, &source_ref, &target.oid)?;
        }
    }
    let final_report = inspect_family(storage, key)?;
    Ok(FamilyRepairOutcome {
        initial,
        final_report,
        sources_tried,
        source_failures,
    })
}

#[async_trait]
impl FamilyRepairSource for crate::purgatory::sync::RealSyncContext {
    async fn accepted_clone_urls(&self, identifier: &str) -> Result<Vec<String>> {
        self.accepted_repository_clone_urls(identifier).await
    }

    async fn fetch_missing_oids(
        &self,
        target_view: &Path,
        url: &str,
        oids: &[String],
    ) -> Result<Vec<String>> {
        crate::purgatory::sync::SyncContext::fetch_oids_with_role(
            self,
            target_view,
            url,
            oids,
            crate::purgatory::sync::GitFetchRole::Integrity,
        )
        .await
    }
}

/// Discover every installed identifier family in deterministic order.
pub fn discover_families(storage: &LocalGitStorage) -> Result<Vec<FamilyKey>> {
    let mut families = Vec::new();
    for object_format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let root = storage
            .internal_path()
            .join("families")
            .join(object_format.as_str());
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("read {}", root.display())),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(identifier) = name.to_str().and_then(|name| name.strip_suffix(".git")) else {
                continue;
            };
            if !validate_repository_identifier(identifier) {
                return Err(anyhow!(
                    "invalid identifier-family path {}",
                    entry.path().display()
                ));
            }
            families.push(FamilyKey::new(object_format, identifier)?);
        }
    }
    families.sort_by(|left, right| {
        (left.object_format.as_str(), left.identifier.as_str())
            .cmp(&(right.object_format.as_str(), right.identifier.as_str()))
    });
    Ok(families)
}

/// Inspect one family and every owner or `/prs/` view backed by its identifier.
pub fn inspect_family(storage: &LocalGitStorage, key: &FamilyKey) -> Result<FamilyIntegrityReport> {
    let family = storage.family_repo_path(key);
    if !family.is_dir() {
        return Err(anyhow!("family is missing: {}", family.display()));
    }
    let actual_format = ObjectFormat::detect(&family)?;
    if actual_format != key.object_format {
        return Err(anyhow!(
            "family {} has object format {}, expected {}",
            family.display(),
            actual_format,
            key.object_format
        ));
    }

    let views = discover_views(storage, key)?;
    let mut missing_oids = BTreeSet::new();
    let mut missing_ref_targets = Vec::new();
    let mut invalid_alternates = Vec::new();
    let mut refs_checked = 0;

    for view in &views {
        if !storage.is_thin_view(key, view) {
            invalid_alternates.push(view.clone());
        }
        for (reference, oid) in list_refs(view)? {
            refs_checked += 1;
            if !oid_exists(&family, &oid)? {
                missing_oids.insert(oid.clone());
                missing_ref_targets.push(MissingRefTarget {
                    view: view.clone(),
                    reference,
                    oid,
                });
            }
        }
    }

    let pack_errors = inspect_packs(&family)?;
    let (fsck_missing, fsck_diagnostics) = inspect_connectivity(&family, key.object_format)?;
    missing_oids.extend(fsck_missing);

    Ok(FamilyIntegrityReport {
        key: key.clone(),
        views,
        refs_checked,
        missing_oids,
        missing_ref_targets,
        invalid_alternates,
        pack_errors,
        fsck_diagnostics,
    })
}

fn discover_views(storage: &LocalGitStorage, key: &FamilyKey) -> Result<Vec<PathBuf>> {
    let mut views = Vec::new();
    let entries = match std::fs::read_dir(storage.git_data_path()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(views),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "prs" {
            discover_pr_views(&entry.path(), key, &mut views)?;
        } else if name.starts_with("npub1") && PublicKey::from_bech32(&name).is_ok() {
            maybe_add_view(&entry.path(), key, &mut views)?;
        }
    }
    views.sort();
    Ok(views)
}

fn discover_pr_views(root: &Path, key: &FamilyKey, views: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.len() == 64 && name.chars().all(|character| character.is_ascii_hexdigit()) {
            maybe_add_view(&entry.path(), key, views)?;
        }
    }
    Ok(())
}

fn maybe_add_view(directory: &Path, key: &FamilyKey, views: &mut Vec<PathBuf>) -> Result<()> {
    let candidate = directory.join(format!("{}.git", key.identifier));
    if !candidate.is_dir() {
        return Ok(());
    }
    if ObjectFormat::detect(&candidate)? == key.object_format {
        views.push(candidate);
    }
    Ok(())
}

fn list_refs(repo: &Path) -> Result<Vec<(String, String)>> {
    let output = Command::new("git")
        .args(["for-each-ref", "--format=%(refname)%00%(objectname)"])
        .current_dir(repo)
        .output()
        .with_context(|| format!("list refs in {}", repo.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "list refs in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut refs = Vec::new();
    for line in output.stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Some(separator) = line.iter().position(|byte| *byte == 0) else {
            return Err(anyhow!("unexpected git for-each-ref output"));
        };
        refs.push((
            String::from_utf8(line[..separator].to_vec())?,
            String::from_utf8(line[separator + 1..].to_vec())?,
        ));
    }
    Ok(refs)
}

fn inspect_packs(family: &Path) -> Result<Vec<String>> {
    let pack_dir = family.join("objects/pack");
    let entries = match std::fs::read_dir(&pack_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut errors = Vec::new();
    let mut indexes = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("pack") if !path.with_extension("idx").is_file() => {
                errors.push(format!("pack has no index: {}", path.display()));
            }
            Some("idx") if !path.with_extension("pack").is_file() => {
                errors.push(format!("index has no pack: {}", path.display()));
            }
            Some("idx") => indexes.push(path),
            _ => {}
        }
    }
    indexes.sort();
    for index in indexes {
        let status = Command::new("git")
            .arg("verify-pack")
            .arg(&index)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .with_context(|| format!("verify pack index {}", index.display()))?;
        if !status.success() {
            errors.push(format!("pack verification failed: {}", index.display()));
        }
    }
    errors.sort();
    Ok(errors)
}

fn inspect_connectivity(
    family: &Path,
    object_format: ObjectFormat,
) -> Result<(BTreeSet<String>, Vec<String>)> {
    let output = Command::new("git")
        .args(["fsck", "--full", "--no-reflogs", "--no-dangling"])
        .env("LC_ALL", "C")
        .current_dir(family)
        .output()
        .with_context(|| format!("inspect family connectivity in {}", family.display()))?;
    if output.status.success() {
        return Ok((BTreeSet::new(), Vec::new()));
    }

    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let oid_len = match object_format {
        ObjectFormat::Sha1 => 40,
        ObjectFormat::Sha256 => 64,
    };
    let mut missing = BTreeSet::new();
    let mut diagnostics = Vec::new();
    for line in diagnostic
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first() == Some(&"missing") {
            if let Some(oid) = fields.iter().rev().find(|field| {
                field.len() == oid_len && field.chars().all(|ch| ch.is_ascii_hexdigit())
            }) {
                missing.insert((*oid).to_owned());
            }
        }
        if diagnostics.len() < 64 {
            diagnostics.push(line.chars().take(2048).collect());
        }
    }
    if diagnostics.is_empty() {
        diagnostics.push(format!("git fsck exited with {}", output.status));
    }
    Ok((missing, diagnostics))
}

fn oid_exists(repo: &Path, oid: &str) -> Result<bool> {
    let output = Command::new("git")
        .args(["cat-file", "-e", oid])
        .current_dir(repo)
        .output()
        .with_context(|| format!("check object {oid} in {}", repo.display()))?;
    Ok(output.status.success())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::process::Stdio;

    use nostr_sdk::prelude::{Keys, ToBech32};

    use super::*;

    struct LocalRepairSource {
        url: String,
        family_objects: PathBuf,
    }

    #[async_trait]
    impl FamilyRepairSource for LocalRepairSource {
        async fn accepted_clone_urls(&self, _identifier: &str) -> Result<Vec<String>> {
            Ok(vec![self.url.clone()])
        }

        async fn fetch_missing_oids(
            &self,
            target_view: &Path,
            url: &str,
            oids: &[String],
        ) -> Result<Vec<String>> {
            let mut command = Command::new("git");
            command
                .arg("fetch")
                .arg("--no-write-fetch-head")
                .arg(url)
                .args(oids)
                .env("GIT_OBJECT_DIRECTORY", &self.family_objects)
                .current_dir(target_view);
            let output = command.output()?;
            if !output.status.success() {
                return Err(anyhow!(String::from_utf8_lossy(&output.stderr).into_owned()));
            }
            Ok(oids.to_vec())
        }
    }

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", "/nonexistent")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn write_commit(repo: &Path, parent: Option<&str>) -> String {
        let tree = git(repo, &["mktree"]);
        let mut contents = format!(
            "tree {tree}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\nintegrity fixture\n"
        );
        if let Some(parent) = parent {
            contents.insert_str(
                contents.find("author ").unwrap(),
                &format!("parent {parent}\n"),
            );
        }
        let mut child = Command::new("git")
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .current_dir(repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(contents.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn fixture() -> (
        tempfile::TempDir,
        LocalGitStorage,
        FamilyKey,
        PathBuf,
        String,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        let key = FamilyKey::sha1("shared").unwrap();
        let family = storage.ensure_family(&key).unwrap();
        let commit = write_commit(&family, None);
        storage.retain_tip(&key, "fixture", &commit).unwrap();
        storage
            .advertise_base_tip(&key, "fixture", &commit)
            .unwrap();
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let view = storage.git_data_path().join(owner).join("shared.git");
        storage.create_thin_view(&key, &view).unwrap();
        git(&view, &["update-ref", "refs/heads/main", &commit]);
        (temp, storage, key, view, commit)
    }

    #[test]
    fn healthy_family_checks_family_and_views() {
        let (_temp, storage, key, _view, _commit) = fixture();

        let report = inspect_family(&storage, &key).unwrap();

        assert!(report.is_healthy(), "{report:#?}");
        assert_eq!(report.views.len(), 1);
        assert_eq!(report.refs_checked, 1);
        assert_eq!(discover_families(&storage).unwrap(), vec![key]);
    }

    #[test]
    fn reports_missing_graph_objects_and_view_ref_targets() {
        let (_temp, storage, key, view, commit) = fixture();
        let family = storage.family_repo_path(&key);
        let child = write_commit(&family, Some(&commit));
        git(&view, &["update-ref", "refs/heads/main", &child]);
        storage.retain_tip(&key, "child", &child).unwrap();
        let object = family.join("objects").join(&commit[..2]).join(&commit[2..]);
        fs::remove_file(object).unwrap();
        let broken = "2".repeat(40);
        fs::create_dir_all(view.join("refs/heads")).unwrap();
        fs::write(view.join("refs/heads/broken"), format!("{broken}\n")).unwrap();

        let report = inspect_family(&storage, &key).unwrap();

        assert!(!report.is_healthy());
        assert!(report.missing_oids.contains(&commit));
        assert!(report.missing_oids.contains(&broken));
        assert!(report
            .missing_ref_targets
            .iter()
            .any(|target| target.reference == "refs/heads/broken" && target.oid == broken));
        assert!(!report.fsck_diagnostics.is_empty());
    }

    #[test]
    fn reports_a_view_whose_family_alternate_changed() {
        let (_temp, storage, key, view, _commit) = fixture();
        fs::write(view.join("objects/info/alternates"), "/wrong/objects\n").unwrap();

        let report = inspect_family(&storage, &key).unwrap();

        assert_eq!(report.invalid_alternates, vec![view]);
        assert!(!report.is_healthy());
    }

    #[test]
    fn reports_an_unindexed_family_pack() {
        let (_temp, storage, key, _view, _commit) = fixture();
        let pack = storage
            .family_repo_path(&key)
            .join("objects/pack/pack-0000000000000000000000000000000000000000.pack");
        fs::write(pack, b"incomplete").unwrap();

        let report = inspect_family(&storage, &key).unwrap();

        assert_eq!(report.pack_errors.len(), 1);
        assert!(report.pack_errors[0].contains("pack has no index"));
    }

    #[test]
    fn manual_requests_are_durable_and_identifier_scoped() {
        let temp = tempfile::tempdir().unwrap();
        let args = IntegrityCheckArgs {
            identifier: "shared".to_owned(),
            repair: true,
            git_data_path: temp.path().join("git").to_string_lossy().into_owned(),
        };

        let path = enqueue_manual_check(&args).unwrap();
        let storage = LocalGitStorage::new(&args.git_data_path);
        let requests = load_requests(&storage).unwrap();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, path);
        assert_eq!(requests[0].1.identifier, "shared");
        assert!(requests[0].1.repair);
    }

    #[test]
    fn manual_requests_reject_unsafe_identifiers() {
        let temp = tempfile::tempdir().unwrap();
        let args = IntegrityCheckArgs {
            identifier: "../escape".to_owned(),
            repair: false,
            git_data_path: temp.path().join("git").to_string_lossy().into_owned(),
        };

        assert!(enqueue_manual_check(&args).is_err());
    }

    #[tokio::test]
    async fn manual_requests_are_consumed_by_the_family_worker() {
        let (temp, storage, _key, _view, _commit) = fixture();
        let args = IntegrityCheckArgs {
            identifier: "shared".to_owned(),
            repair: false,
            git_data_path: storage.git_data_path().to_string_lossy().into_owned(),
        };
        let request = enqueue_manual_check(&args).unwrap();
        let source = LocalRepairSource {
            url: String::new(),
            family_objects: temp.path().join("unused"),
        };

        process_manual_requests(&storage, &source).await;

        assert!(!request.exists());
    }

    #[tokio::test]
    async fn repairs_missing_objects_from_an_identifier_clone_source() {
        let (temp, storage, key, view, commit) = fixture();
        let family = storage.family_repo_path(&key);
        let source_repo = temp.path().join("source.git");
        git(
            temp.path(),
            &[
                "clone",
                "--bare",
                family.to_str().unwrap(),
                source_repo.to_str().unwrap(),
            ],
        );
        git(
            &source_repo,
            &["update-ref", "refs/heads/recovery", &commit],
        );
        let object = family.join("objects").join(&commit[..2]).join(&commit[2..]);
        fs::remove_file(object).unwrap();
        assert!(!inspect_family(&storage, &key).unwrap().is_healthy());
        let source = LocalRepairSource {
            url: source_repo.to_string_lossy().into_owned(),
            family_objects: storage.family_objects_path(&key),
        };

        let outcome = check_and_repair_family(&storage, &key, &source, true)
            .await
            .unwrap();

        assert!(outcome.repaired(), "{outcome:#?}");
        assert_eq!(outcome.sources_tried, vec![source.url]);
        assert!(outcome.source_failures.is_empty());
        assert!(oid_exists(&family, &commit).unwrap());
        assert_eq!(git(&view, &["rev-parse", "refs/heads/main"]), commit);
    }
}
