//! Crash-safe launch migration from full bare repositories to thin family views.
//!
//! The migration runs before any relay task can access Git storage. Original
//! repositories are moved under `.grasp/migration/backups` and are never
//! deleted automatically. Every object reported by `cat-file
//! --batch-all-objects`, including unreachable objects, is copied into a
//! verified union pack before a view can be replaced.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use bitcoin_hashes::{sha256, Hash};
use nostr_sdk::prelude::{FromBech32, PublicKey};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::storage::{FamilyKey, LocalGitStorage, ObjectFormat, STORAGE_VERSION};
use super::validate_repository_identifier;

const MIGRATION_VERSION: u32 = 1;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub migrated_views: usize,
    pub recovered_views: usize,
    pub families_built: usize,
    pub already_current: bool,
}

#[derive(Debug, Clone)]
struct Candidate {
    relative_path: PathBuf,
    view_path: PathBuf,
    source_path: PathBuf,
    backup_path: PathBuf,
    journal_path: PathBuf,
    key: FamilyKey,
    recovered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RefSnapshot {
    oid: String,
    symbolic_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalState {
    Prepared,
    BackedUp,
    ViewInstalled,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ViewJournal {
    version: u32,
    relative_path: PathBuf,
    object_format: String,
    identifier: String,
    refs: BTreeMap<String, RefSnapshot>,
    head: Vec<u8>,
    state: JournalState,
}

/// Upgrade all eligible Git repositories under one storage root.
///
/// This function is safe to call on every launch. The storage-version marker
/// advances only after every legacy path and incomplete journal is reconciled.
pub async fn migrate_on_startup(storage: &LocalGitStorage) -> Result<MigrationReport> {
    std::fs::create_dir_all(storage.git_data_path()).with_context(|| {
        format!(
            "create Git data directory {}",
            storage.git_data_path().display()
        )
    })?;
    let storage_is_current = validate_storage_version(storage)?;
    let mut candidates = scan_active_legacy_views(storage)?;
    if storage_is_current && candidates.is_empty() {
        return Ok(MigrationReport {
            already_current: true,
            ..MigrationReport::default()
        });
    }

    let journals = load_journals(storage)?;
    reconcile_journals(storage, journals, &mut candidates)?;
    candidates.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    candidates.dedup_by(|left, right| left.relative_path == right.relative_path);

    let mut report = MigrationReport::default();
    let mut by_family: HashMap<FamilyKey, Vec<Candidate>> = HashMap::new();
    for candidate in candidates {
        by_family
            .entry(candidate.key.clone())
            .or_default()
            .push(candidate);
    }
    let mut families: Vec<_> = by_family.into_iter().collect();
    families.sort_by(|(left, _), (right, _)| {
        left.object_format
            .as_str()
            .cmp(right.object_format.as_str())
            .then(left.identifier.cmp(&right.identifier))
    });

    for (key, candidates) in families {
        build_family_union(storage, &key, &candidates)?;
        report.families_built += 1;
        for candidate in candidates {
            install_view(storage, &candidate)?;
            if candidate.recovered {
                report.recovered_views += 1;
            } else {
                report.migrated_views += 1;
            }
        }
    }

    verify_all_views(storage)?;
    write_atomic(
        &storage.storage_version_path(),
        format!("{STORAGE_VERSION}\n").as_bytes(),
    )?;
    report.already_current = report.migrated_views == 0 && report.recovered_views == 0;
    Ok(report)
}

/// Enumerate installed family repositories for S3 adoption after migration.
pub fn family_keys(storage: &LocalGitStorage) -> Result<Vec<FamilyKey>> {
    let mut keys = Vec::new();
    let families = storage.internal_path().join("families");
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let path = families.join(format.as_str());
        let Ok(entries) = std::fs::read_dir(path) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Some(identifier) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix(".git"))
                .map(str::to_owned)
            else {
                continue;
            };
            keys.push(FamilyKey::new(format, identifier)?);
        }
    }
    keys.sort_by(|left, right| {
        left.object_format
            .as_str()
            .cmp(right.object_format.as_str())
            .then(left.identifier.cmp(&right.identifier))
    });
    Ok(keys)
}

/// Import every object and ref tip from an archived repository into a family.
///
/// The caller must hold the family's write lease. This deliberately includes
/// unreachable objects so restoring a pre-family archive does not narrow the
/// rollback history retained by the original repository.
pub(crate) fn import_archived_repository(
    storage: &LocalGitStorage,
    key: &FamilyKey,
    source: &Path,
) -> Result<()> {
    let source_format = ObjectFormat::detect(source)?;
    if source_format != key.object_format {
        return Err(anyhow!(
            "archived repository {} uses {}, expected {}",
            source.display(),
            source_format,
            key.object_format
        ));
    }
    let family = storage.ensure_family(key)?;
    let expected_oids = list_all_objects(source)?;
    copy_object_database(source, &family, key.object_format)?;
    ensure_oids(&family, &expected_oids)?;
    for (name, reference) in snapshot_refs(source)? {
        storage.retain_tip(key, &name, &reference.oid)?;
        storage.advertise_base_tip(key, &name, &reference.oid)?;
    }
    Ok(())
}

fn validate_storage_version(storage: &LocalGitStorage) -> Result<bool> {
    let path = storage.storage_version_path();
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Ok(false);
    };
    let version: u32 = contents
        .trim()
        .parse()
        .with_context(|| format!("parse storage version in {}", path.display()))?;
    if version > STORAGE_VERSION {
        return Err(anyhow!(
            "Git storage version {version} is newer than supported version {STORAGE_VERSION}"
        ));
    }
    Ok(version == STORAGE_VERSION)
}

fn scan_active_legacy_views(storage: &LocalGitStorage) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    let root = storage.git_data_path();
    for owner_entry in std::fs::read_dir(root)? {
        let owner_entry = owner_entry?;
        if !owner_entry.file_type()?.is_dir() {
            continue;
        }
        let owner = owner_entry.file_name().to_string_lossy().into_owned();
        if owner == "prs" {
            scan_prs_tree(storage, &owner_entry.path(), &mut candidates)?;
            continue;
        }
        if !owner.starts_with("npub1") || PublicKey::from_bech32(&owner).is_err() {
            continue;
        }
        scan_repo_directory(storage, &owner_entry.path(), &mut candidates)?;
    }
    Ok(candidates)
}

fn scan_prs_tree(
    storage: &LocalGitStorage,
    prs_path: &Path,
    candidates: &mut Vec<Candidate>,
) -> Result<()> {
    for submitter in std::fs::read_dir(prs_path)? {
        let submitter = submitter?;
        if !submitter.file_type()?.is_dir() {
            continue;
        }
        let name = submitter.file_name().to_string_lossy().into_owned();
        if name.len() != 64 || !name.chars().all(|ch| ch.is_ascii_hexdigit()) {
            continue;
        }
        scan_repo_directory(storage, &submitter.path(), candidates)?;
    }
    Ok(())
}

fn scan_repo_directory(
    storage: &LocalGitStorage,
    directory: &Path,
    candidates: &mut Vec<Candidate>,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(identifier) = file_name
            .to_str()
            .and_then(|name| name.strip_suffix(".git"))
        else {
            continue;
        };
        if !validate_repository_identifier(identifier) {
            return Err(anyhow!(
                "unsafe repository identifier in migration path {}",
                entry.path().display()
            ));
        }
        let object_format = ObjectFormat::detect(&entry.path())?;
        let key = FamilyKey::new(object_format, identifier)?;
        if storage.is_thin_view(&key, &entry.path()) {
            continue;
        }
        if entry.path().join("objects/info/alternates").exists() {
            return Err(anyhow!(
                "legacy repository {} uses an unknown alternate; refusing lossy migration",
                entry.path().display()
            ));
        }
        candidates.push(candidate_for_active(storage, &entry.path(), key)?);
    }
    Ok(())
}

fn candidate_for_active(
    storage: &LocalGitStorage,
    view_path: &Path,
    key: FamilyKey,
) -> Result<Candidate> {
    let relative_path = view_path
        .strip_prefix(storage.git_data_path())
        .context("repository path escaped Git data root")?
        .to_path_buf();
    let backup_path = backup_root(storage).join(&relative_path);
    Ok(Candidate {
        journal_path: journal_path(storage, &relative_path),
        relative_path,
        view_path: view_path.to_path_buf(),
        source_path: view_path.to_path_buf(),
        backup_path,
        key,
        recovered: false,
    })
}

fn reconcile_journals(
    storage: &LocalGitStorage,
    journals: Vec<(PathBuf, ViewJournal)>,
    candidates: &mut Vec<Candidate>,
) -> Result<()> {
    for (journal_path, mut journal) in journals {
        if journal.version != MIGRATION_VERSION {
            return Err(anyhow!(
                "unsupported migration journal version {} in {}",
                journal.version,
                journal_path.display()
            ));
        }
        let path_identifier = validate_relative_view_path(&journal.relative_path)?;
        if path_identifier != journal.identifier {
            return Err(anyhow!(
                "migration journal identifier {:?} does not match path {}",
                journal.identifier,
                journal.relative_path.display()
            ));
        }
        let format = parse_object_format(&journal.object_format)?;
        let key = FamilyKey::new(format, journal.identifier.clone())?;
        let view_path = storage.git_data_path().join(&journal.relative_path);
        let backup_path = backup_root(storage).join(&journal.relative_path);

        if view_path.exists() && storage.is_thin_view(&key, &view_path) {
            verify_view(&view_path, &journal.refs, &journal.head)?;
            if !backup_path.is_dir() {
                return Err(anyhow!(
                    "migrated view {} has no rollback backup",
                    view_path.display()
                ));
            }
            if journal.state != JournalState::Complete {
                journal.state = JournalState::Complete;
                write_journal(&journal_path, &journal)?;
            }
            candidates.retain(|candidate| candidate.relative_path != journal.relative_path);
            continue;
        }

        let source_path = if backup_path.is_dir() {
            if view_path.exists() {
                return Err(anyhow!(
                    "both legacy view and migration backup exist for {}",
                    journal.relative_path.display()
                ));
            }
            backup_path.clone()
        } else if view_path.is_dir() {
            view_path.clone()
        } else {
            return Err(anyhow!(
                "migration journal {} has neither source nor backup repository",
                journal_path.display()
            ));
        };
        candidates.retain(|candidate| candidate.relative_path != journal.relative_path);
        candidates.push(Candidate {
            relative_path: journal.relative_path,
            view_path,
            source_path,
            backup_path,
            journal_path,
            key,
            recovered: true,
        });
    }
    Ok(())
}

fn build_family_union(
    storage: &LocalGitStorage,
    key: &FamilyKey,
    candidates: &[Candidate],
) -> Result<()> {
    let family = storage.ensure_family(key)?;
    let staging = migration_root(storage)
        .join("family-staging")
        .join(key.object_format.as_str())
        .join(format!("{}.git", key.identifier));
    remove_migration_staging(&staging, &migration_root(storage).join("family-staging"))?;
    if let Some(parent) = staging.parent() {
        std::fs::create_dir_all(parent)?;
    }
    run_git(
        None,
        &[
            "init",
            "--bare",
            "--quiet",
            &format!("--object-format={}", key.object_format),
            staging.to_string_lossy().as_ref(),
        ],
        "initialize migration family staging repository",
    )?;

    let mut sources = vec![family.clone()];
    sources.extend(
        candidates
            .iter()
            .map(|candidate| candidate.source_path.clone()),
    );
    let mut expected_oids = Vec::new();
    for source in &sources {
        let format = ObjectFormat::detect(source)?;
        if format != key.object_format {
            return Err(anyhow!(
                "object format mismatch while merging {}",
                source.display()
            ));
        }
        expected_oids.extend(list_all_objects(source)?);
        copy_object_database(source, &staging, key.object_format)?;
    }
    expected_oids.sort();
    expected_oids.dedup();
    ensure_oids(&staging, &expected_oids)?;

    if !expected_oids.is_empty() {
        let union_dir = migration_root(storage)
            .join("union-packs")
            .join(key.object_format.as_str())
            .join(&key.identifier);
        remove_migration_staging(&union_dir, &migration_root(storage).join("union-packs"))?;
        std::fs::create_dir_all(&union_dir)?;
        let base = union_dir.join("pack");
        let pack_hash = pack_explicit_objects(&staging, &base, &expected_oids)?;
        let pack = union_dir.join(format!("pack-{pack_hash}.pack"));
        let index = union_dir.join(format!("pack-{pack_hash}.idx"));
        verify_pack(&index)?;
        let family_pack_dir = family.join("objects/pack");
        std::fs::create_dir_all(&family_pack_dir)?;
        install_if_absent(&pack, &family_pack_dir.join(pack.file_name().unwrap()))?;
        install_if_absent(&index, &family_pack_dir.join(index.file_name().unwrap()))?;
        fsync_directory(&family_pack_dir)?;
    }

    ensure_oids(&family, &expected_oids)?;
    for candidate in candidates {
        for (name, reference) in snapshot_refs(&candidate.source_path)? {
            storage.retain_tip(key, &name, &reference.oid)?;
            storage.advertise_base_tip(key, &name, &reference.oid)?;
        }
    }
    audit_family_connectivity(&family)?;
    remove_migration_staging(&staging, &migration_root(storage).join("family-staging"))?;
    Ok(())
}

fn install_view(storage: &LocalGitStorage, candidate: &Candidate) -> Result<()> {
    let refs = snapshot_refs(&candidate.source_path)?;
    let head = std::fs::read(candidate.source_path.join("HEAD"))
        .with_context(|| format!("read HEAD from {}", candidate.source_path.display()))?;

    let mut journal = ViewJournal {
        version: MIGRATION_VERSION,
        relative_path: candidate.relative_path.clone(),
        object_format: candidate.key.object_format.as_str().to_owned(),
        identifier: candidate.key.identifier.clone(),
        refs: refs.clone(),
        head: head.clone(),
        state: JournalState::Prepared,
    };
    write_journal(&candidate.journal_path, &journal)?;

    let staged_view = migration_root(storage)
        .join("view-staging")
        .join(journal_name(&candidate.relative_path));
    remove_migration_staging(&staged_view, &migration_root(storage).join("view-staging"))?;
    storage.create_thin_view(&candidate.key, &staged_view)?;
    preserve_view_configuration(
        storage,
        &candidate.key,
        &candidate.source_path,
        &staged_view,
    )?;
    install_refs(&staged_view, &refs)?;
    write_atomic(&staged_view.join("HEAD"), &head)?;
    verify_view(&staged_view, &refs, &head)?;

    if !candidate.backup_path.exists() {
        if candidate.view_path != candidate.source_path || !candidate.view_path.is_dir() {
            return Err(anyhow!(
                "migration source/view mismatch for {}",
                candidate.relative_path.display()
            ));
        }
        if let Some(parent) = candidate.backup_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&candidate.view_path, &candidate.backup_path).with_context(|| {
            format!(
                "move legacy repository {} to rollback backup {}",
                candidate.view_path.display(),
                candidate.backup_path.display()
            )
        })?;
        fsync_directory(candidate.view_path.parent().context("view has no parent")?)?;
        fsync_directory(
            candidate
                .backup_path
                .parent()
                .context("backup has no parent")?,
        )?;
    }
    journal.state = JournalState::BackedUp;
    write_journal(&candidate.journal_path, &journal)?;

    if !candidate.view_path.exists() {
        if let Some(parent) = candidate.view_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&staged_view, &candidate.view_path)
            .with_context(|| format!("install migrated view {}", candidate.view_path.display()))?;
        fsync_directory(candidate.view_path.parent().context("view has no parent")?)?;
    }
    journal.state = JournalState::ViewInstalled;
    write_journal(&candidate.journal_path, &journal)?;
    verify_view(&candidate.view_path, &refs, &head)?;
    journal.state = JournalState::Complete;
    write_journal(&candidate.journal_path, &journal)?;
    Ok(())
}

fn preserve_view_configuration(
    storage: &LocalGitStorage,
    key: &FamilyKey,
    source: &Path,
    target: &Path,
) -> Result<()> {
    let source_config = source.join("config");
    if source_config.is_file() {
        std::fs::copy(&source_config, target.join("config"))?;
    }
    storage.configure_thin_view(key, target)?;
    let source_description = source.join("description");
    if source_description.is_file() {
        std::fs::copy(source_description, target.join("description"))?;
    }
    copy_directory_contents(&source.join("hooks"), &target.join("hooks"))?;
    Ok(())
}

fn verify_all_views(storage: &LocalGitStorage) -> Result<()> {
    if !scan_active_legacy_views(storage)?.is_empty() {
        return Err(anyhow!(
            "legacy Git repositories remain after storage migration"
        ));
    }
    for (_, journal) in load_journals(storage)? {
        if journal.state != JournalState::Complete {
            return Err(anyhow!(
                "incomplete migration journal remains for {}",
                journal.relative_path.display()
            ));
        }
    }
    Ok(())
}

fn snapshot_refs(repo: &Path) -> Result<BTreeMap<String, RefSnapshot>> {
    let output = Command::new("git")
        .args([
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(symref)",
        ])
        .current_dir(repo)
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "list refs in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut refs = BTreeMap::new();
    for line in output.stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split(|byte| *byte == 0).collect();
        if fields.len() != 3 {
            return Err(anyhow!("unexpected git for-each-ref output"));
        }
        let name = String::from_utf8(fields[0].to_vec())?;
        let oid = String::from_utf8(fields[1].to_vec())?;
        let symbolic_target = if fields[2].is_empty() {
            None
        } else {
            Some(String::from_utf8(fields[2].to_vec())?)
        };
        refs.insert(
            name,
            RefSnapshot {
                oid,
                symbolic_target,
            },
        );
    }
    Ok(refs)
}

fn install_refs(repo: &Path, refs: &BTreeMap<String, RefSnapshot>) -> Result<()> {
    for (name, reference) in refs {
        if let Some(target) = &reference.symbolic_target {
            run_git(
                Some(repo),
                &["symbolic-ref", name, target],
                "install migrated symbolic ref",
            )?;
        } else {
            run_git(
                Some(repo),
                &["update-ref", name, &reference.oid],
                "install migrated ref",
            )?;
        }
    }
    Ok(())
}

fn verify_view(
    view: &Path,
    expected_refs: &BTreeMap<String, RefSnapshot>,
    expected_head: &[u8],
) -> Result<()> {
    if snapshot_refs(view)? != *expected_refs {
        return Err(anyhow!("migrated refs differ in {}", view.display()));
    }
    if std::fs::read(view.join("HEAD"))? != expected_head {
        return Err(anyhow!("migrated HEAD differs in {}", view.display()));
    }
    for reference in expected_refs.values() {
        ensure_oid(view, &reference.oid)?;
    }
    Ok(())
}

fn list_all_objects(repo: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args([
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ])
        .current_dir(repo)
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "enumerate every object in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .map(str::to_owned)
        .collect())
}

fn copy_object_database(source: &Path, target: &Path, format: ObjectFormat) -> Result<()> {
    let source_objects = source.join("objects");
    let target_objects = target.join("objects");
    let oid_len = match format {
        ObjectFormat::Sha1 => 40,
        ObjectFormat::Sha256 => 64,
    };
    for fanout in std::fs::read_dir(&source_objects)? {
        let fanout = fanout?;
        let name = fanout.file_name().to_string_lossy().into_owned();
        if fanout.file_type()?.is_dir()
            && name.len() == 2
            && name.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            for object in std::fs::read_dir(fanout.path())? {
                let object = object?;
                let suffix = object.file_name().to_string_lossy().into_owned();
                if object.file_type()?.is_file()
                    && suffix.len() == oid_len - 2
                    && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
                {
                    let destination = target_objects.join(&name).join(&suffix);
                    install_if_absent(&object.path(), &destination)?;
                }
            }
        }
    }
    let source_packs = source_objects.join("pack");
    let target_packs = target_objects.join("pack");
    if source_packs.is_dir() {
        for pack in std::fs::read_dir(source_packs)? {
            let pack = pack?;
            let name = pack.file_name().to_string_lossy().into_owned();
            if !pack.file_type()?.is_file() || !name.ends_with(".pack") {
                continue;
            }
            let index = pack.path().with_extension("idx");
            if !index.is_file() {
                warn!(
                    pack = %pack.path().display(),
                    "Skipping Git-invisible pack without an index; the migration backup retains it"
                );
                continue;
            }
            install_if_absent(&pack.path(), &target_packs.join(&name))?;
            install_if_absent(&index, &target_packs.join(index.file_name().unwrap()))?;
        }
    }
    Ok(())
}

fn pack_explicit_objects(repo: &Path, base: &Path, oids: &[String]) -> Result<String> {
    let mut child = Command::new("git")
        .arg("pack-objects")
        .arg(base)
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child.stdin.as_mut().context("git pack-objects stdin")?;
        for oid in oids {
            writeln!(stdin, "{oid}")?;
        }
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "build migration union pack: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn verify_pack(index: &Path) -> Result<()> {
    let status = Command::new("git")
        .arg("verify-pack")
        .arg(index)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(anyhow!(
            "migration pack does not verify: {}",
            index.display()
        ));
    }
    Ok(())
}

fn ensure_oid(repo: &Path, oid: &str) -> Result<()> {
    let status = Command::new("git")
        .args(["cat-file", "-e", oid])
        .current_dir(repo)
        .status()?;
    if !status.success() {
        return Err(anyhow!("object {oid} is missing from {}", repo.display()));
    }
    Ok(())
}

fn ensure_oids(repo: &Path, expected: &[String]) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    let available: HashSet<_> = list_all_objects(repo)?.into_iter().collect();
    if let Some(missing) = expected.iter().find(|oid| !available.contains(*oid)) {
        return Err(anyhow!(
            "object {missing} is missing from {}",
            repo.display()
        ));
    }
    Ok(())
}

fn audit_family_connectivity(repo: &Path) -> Result<()> {
    let output = Command::new("git")
        .args(["fsck", "--full", "--no-reflogs", "--no-dangling"])
        .current_dir(repo)
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let diagnostic: String = diagnostic.trim().chars().take(2048).collect();
    warn!(
        repository = %repo.display(),
        status = %output.status,
        diagnostic,
        "Migrated family preserves a pre-existing incomplete object graph"
    );
    Ok(())
}

fn install_if_absent(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::hard_link(source, destination) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(source, destination)?;
            Ok(())
        }
    }
}

fn copy_directory_contents(source: &Path, target: &Path) -> Result<()> {
    if !source.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(target)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let destination = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_directory_contents(&entry.path(), &destination)?;
        } else if entry.file_type()?.is_file() {
            std::fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn load_journals(storage: &LocalGitStorage) -> Result<Vec<(PathBuf, ViewJournal)>> {
    let root = migration_root(storage).join("journal");
    let Ok(entries) = std::fs::read_dir(root) else {
        return Ok(Vec::new());
    };
    let mut journals = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        let journal = serde_json::from_slice(&std::fs::read(entry.path())?)
            .with_context(|| format!("parse migration journal {}", entry.path().display()))?;
        journals.push((entry.path(), journal));
    }
    journals.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(journals)
}

fn write_journal(path: &Path, journal: &ViewJournal) -> Result<()> {
    write_atomic(path, &serde_json::to_vec_pretty(journal)?)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("atomic migration file has no parent")?;
    std::fs::create_dir_all(parent)?;
    let pending = parent.join(format!(
        ".{}.pending-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&pending, path)?;
    fsync_directory(parent)
}

fn fsync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn run_git(current_dir: Option<&Path>, args: &[&str], description: &str) -> Result<()> {
    let mut command = Command::new("git");
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    let output = command.args(args).output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "{description}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn migration_root(storage: &LocalGitStorage) -> PathBuf {
    storage.internal_path().join("migration")
}

fn backup_root(storage: &LocalGitStorage) -> PathBuf {
    migration_root(storage).join("backups")
}

fn journal_path(storage: &LocalGitStorage, relative_path: &Path) -> PathBuf {
    migration_root(storage)
        .join("journal")
        .join(format!("{}.json", journal_name(relative_path)))
}

fn journal_name(relative_path: &Path) -> String {
    sha256::Hash::hash(relative_path.to_string_lossy().as_bytes()).to_string()
}

fn parse_object_format(value: &str) -> Result<ObjectFormat> {
    match value {
        "sha1" => Ok(ObjectFormat::Sha1),
        "sha256" => Ok(ObjectFormat::Sha256),
        _ => Err(anyhow!("unsupported journal object format {value:?}")),
    }
}

fn validate_relative_view_path(path: &Path) -> Result<String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(anyhow!("unsafe migration view path {}", path.display()));
    }
    let components: Vec<_> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    let repo_name = match components.as_slice() {
        [owner, repo] if owner.starts_with("npub1") && PublicKey::from_bech32(owner).is_ok() => {
            *repo
        }
        ["prs", submitter, repo]
            if submitter.len() == 64 && submitter.chars().all(|ch| ch.is_ascii_hexdigit()) =>
        {
            *repo
        }
        _ => return Err(anyhow!("unsafe migration view path {}", path.display())),
    };
    let identifier = repo_name
        .strip_suffix(".git")
        .filter(|identifier| validate_repository_identifier(identifier))
        .ok_or_else(|| anyhow!("unsafe migration view path {}", path.display()))?;
    Ok(identifier.to_owned())
}

fn remove_migration_staging(path: &Path, allowed_root: &Path) -> Result<()> {
    if !path.starts_with(allowed_root) || path == allowed_root {
        return Err(anyhow!(
            "refusing to remove migration path outside staging root: {}",
            path.display()
        ));
    }
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use nostr_sdk::prelude::{Keys, ToBech32};

    use super::*;

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn legacy_repo(
        root: &Path,
        owner: &str,
        identifier: &str,
        contents: &[u8],
    ) -> (PathBuf, String) {
        let repo = root.join(owner).join(format!("{identifier}.git"));
        std::fs::create_dir_all(repo.parent().unwrap()).unwrap();
        assert!(Command::new("git")
            .args(["init", "--bare", "--quiet", "--initial-branch=main"])
            .arg(&repo)
            .status()
            .unwrap()
            .success());
        let mut child = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(&repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(contents).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let oid = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        git(&repo, &["update-ref", "refs/test/data", &oid]);
        (repo, oid)
    }

    #[test]
    fn batch_object_verification_reports_missing_objects() {
        let temp = tempfile::tempdir().unwrap();
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let (repo, oid) = legacy_repo(temp.path(), &owner, "example", b"present\n");

        ensure_oids(&repo, std::slice::from_ref(&oid)).unwrap();

        let missing = "0".repeat(40);
        let error = ensure_oids(&repo, std::slice::from_ref(&missing)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("object {missing} is missing from {}", repo.display())
        );
    }

    #[tokio::test]
    async fn migration_preserves_a_preexisting_incomplete_object_graph() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let (repo, _) = legacy_repo(storage.git_data_path(), &owner, "incomplete", b"present\n");
        let tree = git(&repo, &["mktree"]);
        let missing_parent = "1".repeat(40);
        let commit = format!(
            "tree {tree}\nparent {missing_parent}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\nincomplete history\n"
        );
        let mut child = Command::new("git")
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .current_dir(&repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(commit.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let commit_oid = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        git(&repo, &["update-ref", "refs/heads/main", &commit_oid]);
        assert!(!Command::new("git")
            .args(["fsck", "--full", "--no-reflogs", "--no-dangling"])
            .current_dir(&repo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());

        let report = migrate_on_startup(&storage).await.unwrap();

        assert_eq!(report.migrated_views, 1);
        let key = FamilyKey::new(ObjectFormat::Sha1, "incomplete").unwrap();
        ensure_oid(&storage.family_repo_path(&key), &commit_oid).unwrap();
    }

    #[tokio::test]
    async fn migration_archives_a_pack_without_an_index() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let (repo, oid) = legacy_repo(storage.git_data_path(), &owner, "orphan-pack", b"present\n");
        let relative = repo.strip_prefix(storage.git_data_path()).unwrap();
        let orphan_name = "pack-0000000000000000000000000000000000000000.pack";
        let orphan = repo.join("objects/pack").join(orphan_name);
        std::fs::create_dir_all(orphan.parent().unwrap()).unwrap();
        std::fs::write(&orphan, b"not a readable Git pack\n").unwrap();

        let report = migrate_on_startup(&storage).await.unwrap();

        assert_eq!(report.migrated_views, 1);
        let archived = backup_root(&storage)
            .join(relative)
            .join("objects/pack")
            .join(orphan_name);
        assert_eq!(
            std::fs::read(archived).unwrap(),
            b"not a readable Git pack\n"
        );
        let key = FamilyKey::new(ObjectFormat::Sha1, "orphan-pack").unwrap();
        let family = storage.family_repo_path(&key);
        assert!(!family.join("objects/pack").join(orphan_name).exists());
        ensure_oid(&family, &oid).unwrap();
    }

    #[tokio::test]
    async fn migration_deduplicates_views_and_preserves_unreachable_objects() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        let owner_one = Keys::generate().public_key().to_bech32().unwrap();
        let owner_two = Keys::generate().public_key().to_bech32().unwrap();
        let (first, first_oid) = legacy_repo(
            storage.git_data_path(),
            &owner_one,
            "example",
            b"shared data\n",
        );
        let (second, second_oid) = legacy_repo(
            storage.git_data_path(),
            &owner_two,
            "example",
            b"other data\n",
        );
        let mut child = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(&first)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"unreachable rollback data\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let unreachable = String::from_utf8_lossy(&output.stdout).trim().to_owned();

        let report = migrate_on_startup(&storage).await.unwrap();
        assert_eq!(report.migrated_views, 2);
        assert_eq!(report.families_built, 1);
        let key = FamilyKey::sha1("example").unwrap();
        assert!(storage.is_thin_view(&key, &first));
        assert!(storage.is_thin_view(&key, &second));
        assert_eq!(
            super::super::get_ref_commit(&first, "refs/test/data"),
            Some(first_oid)
        );
        assert_eq!(
            super::super::get_ref_commit(&second, "refs/test/data"),
            Some(second_oid)
        );
        ensure_oid(&storage.family_repo_path(&key), &unreachable).unwrap();
        assert!(backup_root(&storage)
            .join(&owner_one)
            .join("example.git")
            .is_dir());
        assert!(backup_root(&storage)
            .join(&owner_two)
            .join("example.git")
            .is_dir());

        let second_report = migrate_on_startup(&storage).await.unwrap();
        assert!(second_report.already_current);
        assert_eq!(second_report.migrated_views, 0);
    }

    #[tokio::test]
    async fn migration_resumes_after_legacy_repo_was_renamed_to_backup() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let (view, oid) = legacy_repo(storage.git_data_path(), &owner, "recovery", b"recover me\n");
        let candidate =
            candidate_for_active(&storage, &view, FamilyKey::sha1("recovery").unwrap()).unwrap();
        let refs = snapshot_refs(&view).unwrap();
        let head = std::fs::read(view.join("HEAD")).unwrap();
        write_journal(
            &candidate.journal_path,
            &ViewJournal {
                version: MIGRATION_VERSION,
                relative_path: candidate.relative_path.clone(),
                object_format: "sha1".to_owned(),
                identifier: "recovery".to_owned(),
                refs,
                head,
                state: JournalState::Prepared,
            },
        )
        .unwrap();
        std::fs::create_dir_all(candidate.backup_path.parent().unwrap()).unwrap();
        std::fs::rename(&view, &candidate.backup_path).unwrap();

        let report = migrate_on_startup(&storage).await.unwrap();
        assert_eq!(report.recovered_views, 1);
        assert_eq!(
            super::super::get_ref_commit(&view, "refs/test/data"),
            Some(oid)
        );
        assert!(storage.is_thin_view(&FamilyKey::sha1("recovery").unwrap(), &view));
    }

    #[tokio::test]
    async fn archived_repository_import_preserves_unreachable_objects() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        let (archive, referenced) =
            legacy_repo(temp.path(), "archive", "restored", b"referenced\n");
        let mut child = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(&archive)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"unreachable archive data\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let unreachable = String::from_utf8_lossy(&output.stdout).trim().to_owned();

        let key = FamilyKey::sha1("restored").unwrap();
        let _lease = storage.write_lease(&key).await.unwrap();
        import_archived_repository(&storage, &key, &archive).unwrap();

        let family = storage.family_repo_path(&key);
        ensure_oid(&family, &referenced).unwrap();
        ensure_oid(&family, &unreachable).unwrap();
        assert!(!git(&family, &["for-each-ref", "refs/grasp/retained/"]).is_empty());
    }
}
