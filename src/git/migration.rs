//! Crash-safe launch migration from full bare repositories to thin family views.
//!
//! The migration runs before any relay task can access Git storage. Original
//! repositories are moved under `.grasp/migration/backups` while their family
//! is converted. Every object reported by `cat-file --batch-all-objects`,
//! including unreachable objects, is copied into a verified union pack before
//! a view can be replaced.
//!
//! Backups are retired family by family: once every view of one identifier
//! family is installed, each backup is verified against the family (every
//! Git-readable backup object present, thin views wired and matching their
//! journal snapshot, family packs valid) and then deleted before the next
//! family is migrated. Peak migration overhead is therefore bounded by the
//! family currently in flight rather than the whole legacy dataset. Packs
//! without an index are Git-invisible and are quarantined under
//! `.grasp/migration/unindexed-packs` instead of being destroyed.

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
    /// Legacy repository backups deleted after their family verified.
    pub retired_backups: usize,
    /// Backups kept because post-migration verification could not prove the
    /// family supersedes them. They remain operator-managed.
    pub retained_backups: usize,
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
    /// Retirement verification passed and the backup is disposable. Written
    /// before backup deletion starts so an interrupted deletion resumes
    /// without re-verification.
    Retired,
}

/// A completed view whose legacy backup is ready to be verified and retired.
struct RetirementUnit {
    journal_path: PathBuf,
    journal: ViewJournal,
    view_path: PathBuf,
    backup_path: PathBuf,
    key: FamilyKey,
    /// Whether a verification failure must abort startup. True while the
    /// journal snapshot is authoritative (an active migration run); false for
    /// journals from a long-committed migration whose view refs have
    /// legitimately drifted, where an unverifiable backup is retained instead.
    strict: bool,
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
    /// The legacy repository carried a server-side `shallow` marker, so its
    /// object set is a deliberate truncation. Its backup may only retire once
    /// the family holds the complete closure of the backup's refs.
    #[serde(default)]
    shallow: bool,
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
    let journals = load_journals(storage)?;
    if storage_is_current && candidates.is_empty() && journals.is_empty() {
        return Ok(MigrationReport {
            already_current: true,
            ..MigrationReport::default()
        });
    }

    let mut report = MigrationReport::default();
    let retirement = reconcile_journals(
        storage,
        storage_is_current,
        journals,
        &mut candidates,
        &mut report,
    )?;
    candidates.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    candidates.dedup_by(|left, right| left.relative_path == right.relative_path);

    let mut by_family: HashMap<FamilyKey, (Vec<Candidate>, Vec<RetirementUnit>)> = HashMap::new();
    for candidate in candidates {
        by_family
            .entry(candidate.key.clone())
            .or_default()
            .0
            .push(candidate);
    }
    for unit in retirement {
        by_family.entry(unit.key.clone()).or_default().1.push(unit);
    }
    let mut families: Vec<_> = by_family.into_iter().collect();
    families.sort_by(|(left, _), (right, _)| {
        left.object_format
            .as_str()
            .cmp(right.object_format.as_str())
            .then(left.identifier.cmp(&right.identifier))
    });

    let mut retained_journals = Vec::new();
    for (key, (candidates, mut units)) in families {
        if !candidates.is_empty() {
            build_family_union(storage, &key, &candidates)?;
            report.families_built += 1;
            for candidate in candidates {
                let journal = install_view(storage, &candidate)?;
                if candidate.recovered {
                    report.recovered_views += 1;
                } else {
                    report.migrated_views += 1;
                }
                units.push(RetirementUnit {
                    journal_path: candidate.journal_path.clone(),
                    journal,
                    view_path: candidate.view_path.clone(),
                    backup_path: candidate.backup_path.clone(),
                    key: key.clone(),
                    strict: true,
                });
            }
        }
        retire_family_backups(storage, &key, units, &mut report, &mut retained_journals)?;
    }

    verify_all_views(storage, &retained_journals)?;
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
        retain_family_tip(storage, key, &family, &name, &reference.oid)?;
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
    storage_is_current: bool,
    journals: Vec<(PathBuf, ViewJournal)>,
    candidates: &mut Vec<Candidate>,
    report: &mut MigrationReport,
) -> Result<Vec<RetirementUnit>> {
    let mut units = Vec::new();
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

        if journal.state == JournalState::Retired {
            // Verification already committed durably; only deletion remains.
            // Finishing it here also frees space before new migration work.
            if remove_retired_backup(storage, &backup_path)? {
                report.retired_backups += 1;
            }
            remove_journal(&journal_path)?;
            continue;
        }

        if view_path.exists() && storage.is_thin_view(&key, &view_path) {
            if !storage_is_current {
                // The snapshot from the interrupted run is still authoritative.
                verify_view(&view_path, &journal.refs, &journal.head)?;
            }
            if journal.state != JournalState::Complete {
                journal.state = JournalState::Complete;
                write_journal(&journal_path, &journal)?;
            }
            candidates.retain(|candidate| candidate.relative_path != journal.relative_path);
            units.push(RetirementUnit {
                journal_path,
                journal,
                view_path,
                backup_path,
                key,
                strict: !storage_is_current,
            });
            continue;
        }

        if storage_is_current && journal.state == JournalState::Complete {
            // A journal from a migration that fully committed long ago. The
            // view has since been rewritten, replaced, or removed by normal
            // repository lifecycle, so the ref snapshot is stale.
            if view_path.exists() {
                if backup_path.is_dir() {
                    return Err(anyhow!(
                        "both legacy view and migration backup exist for {}",
                        journal.relative_path.display()
                    ));
                }
                // The path was replaced by a non-thin repository; the active
                // scan migrates it afresh under a new journal.
                remove_journal(&journal_path)?;
                continue;
            }
            if backup_path.is_dir() {
                // The migrated view was deleted after the migration committed
                // (for example by a NIP-09 delete state). The relaxed
                // retirement gate cannot verify a missing view, so this
                // backup is retained as delete-state rollback material.
                units.push(RetirementUnit {
                    journal_path,
                    journal,
                    view_path,
                    backup_path,
                    key,
                    strict: false,
                });
                continue;
            }
            // View and backup are both gone; nothing is left to protect.
            remove_journal(&journal_path)?;
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
    Ok(units)
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
            retain_family_tip(storage, key, &family, &name, &reference.oid)?;
        }
    }
    audit_family_connectivity(&family)?;
    remove_migration_staging(&staging, &migration_root(storage).join("family-staging"))?;
    Ok(())
}

fn install_view(storage: &LocalGitStorage, candidate: &Candidate) -> Result<ViewJournal> {
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
        shallow: candidate.source_path.join("shallow").is_file(),
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
    Ok(journal)
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
    // A legacy shallow marker keeps the view serving exactly what the
    // legacy repository served until integrity repair recovers the full
    // closure; the marker is removed when its family becomes complete.
    let source_shallow = source.join("shallow");
    if source_shallow.is_file() {
        std::fs::copy(source_shallow, target.join("shallow"))?;
    }
    copy_directory_contents(&source.join("hooks"), &target.join("hooks"))?;
    Ok(())
}

fn verify_all_views(storage: &LocalGitStorage, retained_journals: &[PathBuf]) -> Result<()> {
    if !scan_active_legacy_views(storage)?.is_empty() {
        return Err(anyhow!(
            "legacy Git repositories remain after storage migration"
        ));
    }
    for (path, journal) in load_journals(storage)? {
        if !retained_journals.contains(&path) {
            return Err(anyhow!(
                "unretired migration journal remains for {}",
                journal.relative_path.display()
            ));
        }
    }
    Ok(())
}

/// Retire one family's legacy backups after every view of that family is
/// installed.
///
/// Each backup is deleted only after verification proves the family and its
/// views supersede it. Verification failures abort startup for units created
/// by an active migration run and retain the backup (with a warning) for
/// units left over from a migration that already committed.
fn retire_family_backups(
    storage: &LocalGitStorage,
    key: &FamilyKey,
    units: Vec<RetirementUnit>,
    report: &mut MigrationReport,
    retained_journals: &mut Vec<PathBuf>,
) -> Result<()> {
    if units.is_empty() {
        return Ok(());
    }
    let mut family_packs_verified = false;
    let mut all_retired = true;
    for unit in units {
        if !unit.backup_path.is_dir() {
            // Already retired out of band, for example by an operator who
            // verified and deleted the backups manually.
            remove_journal(&unit.journal_path)?;
            continue;
        }
        let verified = (|| -> Result<()> {
            if !family_packs_verified {
                verify_family_packs(&storage.family_repo_path(key))?;
            }
            verify_retirement(storage, &unit)
        })();
        match verified {
            Ok(()) => {
                family_packs_verified = true;
                let shallow = unit.journal.shallow || unit.backup_path.join("shallow").is_file();
                if shallow {
                    // A shallow legacy repository is a deliberate truncation:
                    // its backup may only retire once the family holds the
                    // complete closure of the backup's refs. Recovery needs
                    // the network-based integrity repair that runs after
                    // startup, so this never fails startup; the backup waits.
                    if let Err(error) = super::integrity::family_contains_closure(
                        &storage.family_repo_path(key),
                        &unit.backup_path,
                    ) {
                        tracing::error!(
                            identifier = %key.identifier,
                            object_format = %key.object_format,
                            backup = %unit.backup_path.display(),
                            %error,
                            "Family closure of a shallow legacy repository is unresolved; retaining its backup"
                        );
                        retained_journals.push(unit.journal_path);
                        report.retained_backups += 1;
                        all_retired = false;
                        continue;
                    }
                    remove_shallow_marker(&unit.view_path)?;
                }
                quarantine_unindexed_packs(storage, &unit)?;
                let mut journal = unit.journal;
                journal.state = JournalState::Retired;
                write_journal(&unit.journal_path, &journal)?;
                remove_retired_backup(storage, &unit.backup_path)?;
                remove_journal(&unit.journal_path)?;
                report.retired_backups += 1;
            }
            Err(error) if unit.strict => {
                return Err(error.context(format!(
                    "verify migrated family before retiring backup {}",
                    unit.backup_path.display()
                )));
            }
            Err(error) => {
                warn!(
                    backup = %unit.backup_path.display(),
                    %error,
                    "Keeping unverifiable migration backup as operator-managed rollback material"
                );
                retained_journals.push(unit.journal_path);
                report.retained_backups += 1;
                all_retired = false;
            }
        }
    }
    if all_retired {
        // The union pack and index were hard-linked into the family during
        // migration; the staging copies are redundant once nothing can need
        // a rebuild of this family.
        let union_root = migration_root(storage).join("union-packs");
        let union_dir = union_root
            .join(key.object_format.as_str())
            .join(&key.identifier);
        remove_migration_staging(&union_dir, &union_root)?;
    }
    Ok(())
}

/// Prove that deleting a backup loses nothing the family cannot serve.
///
/// This deliberately does not reuse the integrity module's family inspection:
/// that check treats pre-existing missing objects and broken ref targets as
/// unhealthy, but an object that was never in the backup cannot be preserved
/// by keeping the backup. Such damage stays visible through the integrity
/// worker's own startup pass and `integrity-check --repair`.
fn verify_retirement(storage: &LocalGitStorage, unit: &RetirementUnit) -> Result<()> {
    if !unit.view_path.is_dir() || !storage.is_thin_view(&unit.key, &unit.view_path) {
        return Err(anyhow!(
            "migrated path {} is not an installed thin view",
            unit.view_path.display()
        ));
    }
    if unit.strict {
        verify_view(&unit.view_path, &unit.journal.refs, &unit.journal.head)?;
    }
    let family = storage.family_repo_path(&unit.key);
    let backup_objects = list_all_objects(&unit.backup_path)?;
    ensure_oids(&family, &backup_objects).with_context(|| {
        format!(
            "family must contain every Git-readable object of backup {}",
            unit.backup_path.display()
        )
    })?;
    Ok(())
}

/// Require every family pack to be indexed and to pass `git verify-pack`.
fn verify_family_packs(family: &Path) -> Result<()> {
    let pack_dir = family.join("objects/pack");
    let entries = match std::fs::read_dir(&pack_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mut indexes = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("pack") if !path.with_extension("idx").is_file() => {
                return Err(anyhow!("family pack has no index: {}", path.display()));
            }
            Some("idx") => indexes.push(path),
            _ => {}
        }
    }
    indexes.sort();
    for index in indexes {
        verify_pack(&index)?;
    }
    Ok(())
}

/// Preserve Git-invisible packs before their backup directory is deleted.
///
/// A pack without an index cannot be enumerated by `cat-file`, so the
/// superset verification cannot vouch for it. Moving it aside keeps the raw
/// bytes available for manual `git index-pack` recovery.
fn quarantine_unindexed_packs(storage: &LocalGitStorage, unit: &RetirementUnit) -> Result<()> {
    let source_packs = unit.backup_path.join("objects/pack");
    let entries = match std::fs::read_dir(&source_packs) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !entry.file_type()?.is_file()
            || !name.ends_with(".pack")
            || entry.path().with_extension("idx").is_file()
        {
            continue;
        }
        let destination = migration_root(storage)
            .join("unindexed-packs")
            .join(&unit.journal.relative_path)
            .join(&name);
        if destination.exists() {
            continue;
        }
        let parent = destination.parent().context("quarantine has no parent")?;
        std::fs::create_dir_all(parent)?;
        std::fs::rename(entry.path(), &destination).with_context(|| {
            format!(
                "quarantine Git-invisible pack {} to {}",
                entry.path().display(),
                destination.display()
            )
        })?;
        fsync_directory(parent)?;
        warn!(
            pack = %destination.display(),
            "Quarantined a Git-invisible pack without an index before backup retirement"
        );
    }
    Ok(())
}

/// Delete a retired backup directory and prune emptied parents.
///
/// Returns whether a backup directory existed. Only paths strictly below the
/// migration backup root are ever removed.
fn remove_retired_backup(storage: &LocalGitStorage, backup: &Path) -> Result<bool> {
    let root = backup_root(storage);
    if !backup.starts_with(&root) || backup == root {
        return Err(anyhow!(
            "refusing to remove path outside migration backup root: {}",
            backup.display()
        ));
    }
    match std::fs::remove_dir_all(backup) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("remove retired backup {}", backup.display()));
        }
    }
    let mut parent = backup.parent();
    while let Some(directory) = parent {
        if !directory.starts_with(&root) || std::fs::remove_dir(directory).is_err() {
            break;
        }
        parent = directory.parent();
    }
    Ok(true)
}

/// Drop a view's server-side shallow marker once its family is complete.
fn remove_shallow_marker(view: &Path) -> Result<()> {
    let marker = view.join("shallow");
    match std::fs::remove_file(&marker) {
        Ok(()) => {
            fsync_directory(view)?;
            tracing::info!(
                view = %view.display(),
                "Removed server-side shallow marker; the family holds the complete closure"
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove shallow marker {}", marker.display()))
        }
    }
}

fn remove_journal(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                fsync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove migration journal {}", path.display()))
        }
    }
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
        } else if oid_is_available(repo, &reference.oid)? {
            run_git(
                Some(repo),
                &["update-ref", name, &reference.oid],
                "install migrated ref",
            )?;
        } else {
            let relative = Path::new(name);
            if !name.starts_with("refs/")
                || relative.is_absolute()
                || relative
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(anyhow!("unsafe migrated ref name {name:?}"));
            }
            write_atomic(
                &repo.join(relative),
                format!("{}\n", reference.oid).as_bytes(),
            )?;
            warn!(
                repository = %repo.display(),
                reference = %name,
                oid = %reference.oid,
                "Preserving a pre-existing ref whose target object is missing"
            );
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
    for (name, reference) in expected_refs {
        if !oid_is_available(view, &reference.oid)? {
            warn!(
                repository = %view.display(),
                reference = %name,
                oid = %reference.oid,
                "Verified a preserved ref whose target object is missing"
            );
        }
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

fn oid_is_available(repo: &Path, oid: &str) -> Result<bool> {
    let output = Command::new("git")
        .args(["cat-file", "-e", oid])
        .current_dir(repo)
        .output()?;
    Ok(output.status.success())
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

fn retain_family_tip(
    storage: &LocalGitStorage,
    key: &FamilyKey,
    family: &Path,
    name: &str,
    oid: &str,
) -> Result<()> {
    if oid_is_available(family, oid)? {
        storage.retain_tip(key, name, oid)?;
        storage.advertise_base_tip(key, name, oid)?;
    } else {
        warn!(
            repository = %family.display(),
            reference = %name,
            oid = %oid,
            "Not advertising a pre-existing ref whose target object is missing"
        );
    }
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
        assert!(oid_is_available(&storage.family_repo_path(&key), &commit_oid).unwrap());
    }

    #[tokio::test]
    async fn migration_quarantines_a_pack_without_an_index() {
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
        assert_eq!(report.retired_backups, 1);
        let quarantined = migration_root(&storage)
            .join("unindexed-packs")
            .join(relative)
            .join(orphan_name);
        assert_eq!(
            std::fs::read(quarantined).unwrap(),
            b"not a readable Git pack\n"
        );
        assert!(!backup_root(&storage).exists());
        let key = FamilyKey::new(ObjectFormat::Sha1, "orphan-pack").unwrap();
        let family = storage.family_repo_path(&key);
        assert!(!family.join("objects/pack").join(orphan_name).exists());
        assert!(oid_is_available(&family, &oid).unwrap());
    }

    #[tokio::test]
    async fn migration_preserves_a_ref_with_a_missing_target() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let (repo, _) = legacy_repo(storage.git_data_path(), &owner, "missing-ref", b"present\n");
        let missing = "2".repeat(40);
        let broken_ref = repo.join("refs/heads/broken");
        std::fs::create_dir_all(broken_ref.parent().unwrap()).unwrap();
        std::fs::write(&broken_ref, format!("{missing}\n")).unwrap();
        assert_eq!(
            snapshot_refs(&repo).unwrap()["refs/heads/broken"].oid,
            missing
        );

        let report = migrate_on_startup(&storage).await.unwrap();

        assert_eq!(report.migrated_views, 1);
        assert_eq!(
            std::fs::read_to_string(&broken_ref).unwrap(),
            format!("{missing}\n")
        );
        assert_eq!(
            snapshot_refs(&repo).unwrap()["refs/heads/broken"].oid,
            missing
        );
        let key = FamilyKey::new(ObjectFormat::Sha1, "missing-ref").unwrap();
        let family = storage.family_repo_path(&key);
        assert!(!oid_is_available(&family, &missing).unwrap());
        assert!(!git(
            &family,
            &["for-each-ref", "--format=%(objectname)", "refs/grasp/"]
        )
        .lines()
        .any(|oid| oid == missing));
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
        // Both backups of the single family were retired after verification.
        assert_eq!(report.retired_backups, 2);
        assert_eq!(report.retained_backups, 0);
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
        assert!(oid_is_available(&storage.family_repo_path(&key), &unreachable).unwrap());
        assert!(!backup_root(&storage).exists());
        assert!(load_journals(&storage).unwrap().is_empty());

        let second_report = migrate_on_startup(&storage).await.unwrap();
        assert!(second_report.already_current);
        assert_eq!(second_report.migrated_views, 0);
        assert_eq!(second_report.retired_backups, 0);
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
                shallow: false,
            },
        )
        .unwrap();
        std::fs::create_dir_all(candidate.backup_path.parent().unwrap()).unwrap();
        std::fs::rename(&view, &candidate.backup_path).unwrap();

        let report = migrate_on_startup(&storage).await.unwrap();
        assert_eq!(report.recovered_views, 1);
        assert_eq!(report.retired_backups, 1);
        assert_eq!(
            super::super::get_ref_commit(&view, "refs/test/data"),
            Some(oid)
        );
        assert!(storage.is_thin_view(&FamilyKey::sha1("recovery").unwrap(), &view));
        assert!(!candidate.backup_path.exists());
        assert!(!candidate.journal_path.exists());
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
        assert!(oid_is_available(&family, &referenced).unwrap());
        assert!(oid_is_available(&family, &unreachable).unwrap());
        assert!(!git(&family, &["for-each-ref", "refs/grasp/retained/"]).is_empty());
    }

    fn write_blob(repo: &Path, contents: &[u8]) -> String {
        let mut child = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(contents).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    struct RetirementFixture {
        storage: LocalGitStorage,
        view: PathBuf,
        backup: PathBuf,
        journal_path: PathBuf,
        oid: String,
    }

    /// Build the on-disk state of a migration whose view is installed and
    /// journaled but whose backup has not been retired yet.
    async fn committed_migration(
        temp: &Path,
        identifier: &str,
        state: JournalState,
    ) -> RetirementFixture {
        let storage = LocalGitStorage::new(temp.join("git"));
        std::fs::create_dir_all(storage.git_data_path()).unwrap();
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let (legacy, oid) = legacy_repo(&temp.join("legacy"), &owner, identifier, b"retire me\n");
        let key = FamilyKey::sha1(identifier).unwrap();
        {
            let _lease = storage.write_lease(&key).await.unwrap();
            import_archived_repository(&storage, &key, &legacy).unwrap();
        }
        let view = storage
            .git_data_path()
            .join(&owner)
            .join(format!("{identifier}.git"));
        storage.create_thin_view(&key, &view).unwrap();
        git(&view, &["update-ref", "refs/test/data", &oid]);
        let refs = snapshot_refs(&view).unwrap();
        let head = std::fs::read(view.join("HEAD")).unwrap();
        let relative = view
            .strip_prefix(storage.git_data_path())
            .unwrap()
            .to_path_buf();
        let journal_path = journal_path(&storage, &relative);
        write_journal(
            &journal_path,
            &ViewJournal {
                version: MIGRATION_VERSION,
                relative_path: relative.clone(),
                object_format: "sha1".to_owned(),
                identifier: identifier.to_owned(),
                refs,
                head,
                state,
                shallow: false,
            },
        )
        .unwrap();
        let backup = backup_root(&storage).join(&relative);
        std::fs::create_dir_all(backup.parent().unwrap()).unwrap();
        std::fs::rename(&legacy, &backup).unwrap();
        RetirementFixture {
            storage,
            view,
            backup,
            journal_path,
            oid,
        }
    }

    fn mark_storage_current(storage: &LocalGitStorage) {
        write_atomic(
            &storage.storage_version_path(),
            format!("{STORAGE_VERSION}\n").as_bytes(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn interrupted_retirement_resumes_on_restart() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = committed_migration(temp.path(), "resume", JournalState::Complete).await;

        let report = migrate_on_startup(&fixture.storage).await.unwrap();

        assert_eq!(report.retired_backups, 1);
        assert_eq!(report.retained_backups, 0);
        assert!(!fixture.backup.exists());
        assert!(!backup_root(&fixture.storage).exists());
        assert!(!fixture.journal_path.exists());
        assert_eq!(
            super::super::get_ref_commit(&fixture.view, "refs/test/data"),
            Some(fixture.oid.clone())
        );
        assert!(fixture.storage.storage_version_path().is_file());
    }

    #[tokio::test]
    async fn retired_journal_deletes_backup_without_reverification() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = committed_migration(temp.path(), "retired", JournalState::Retired).await;
        // An object only the backup has would fail retirement verification,
        // but a durable `retired` state means verification already happened.
        let extra = write_blob(&fixture.backup, b"backup-only data\n");
        assert!(!oid_is_available(
            &fixture
                .storage
                .family_repo_path(&FamilyKey::sha1("retired").unwrap()),
            &extra
        )
        .unwrap());

        let report = migrate_on_startup(&fixture.storage).await.unwrap();

        assert_eq!(report.retired_backups, 1);
        assert!(!fixture.backup.exists());
        assert!(!fixture.journal_path.exists());
    }

    #[tokio::test]
    async fn failed_family_verification_preserves_legacy_backup() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let (repo, oid) = legacy_repo(storage.git_data_path(), &owner, "gate", b"keep me\n");
        let relative = repo
            .strip_prefix(storage.git_data_path())
            .unwrap()
            .to_path_buf();
        let key = FamilyKey::sha1("gate").unwrap();
        let family = storage.ensure_family(&key).unwrap();
        let orphan = family.join("objects/pack/pack-1111111111111111111111111111111111111111.pack");
        std::fs::create_dir_all(orphan.parent().unwrap()).unwrap();
        std::fs::write(&orphan, b"garbage family pack\n").unwrap();

        let error = migrate_on_startup(&storage).await.unwrap_err();

        assert!(
            format!("{error:#}").contains("family pack has no index"),
            "{error:#}"
        );
        let backup = backup_root(&storage).join(&relative);
        assert!(backup.is_dir());
        assert!(oid_is_available(&backup, &oid).unwrap());
        assert!(journal_path(&storage, &relative).is_file());
        assert!(!storage.storage_version_path().exists());

        // After the operator fixes the family, restart finishes retirement.
        std::fs::remove_file(&orphan).unwrap();
        let report = migrate_on_startup(&storage).await.unwrap();
        assert_eq!(report.migrated_views, 0);
        assert_eq!(report.retired_backups, 1);
        assert!(!backup.exists());
        assert!(storage.storage_version_path().is_file());
        assert_eq!(
            super::super::get_ref_commit(&repo, "refs/test/data"),
            Some(oid)
        );
    }

    #[tokio::test]
    async fn completed_installations_without_backups_start_normally() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = committed_migration(temp.path(), "manual", JournalState::Complete).await;
        std::fs::remove_dir_all(&fixture.backup).unwrap();
        mark_storage_current(&fixture.storage);
        // Refs drift during normal service after a committed migration; the
        // stale journal snapshot must not be enforced against them.
        git(
            &fixture.view,
            &["update-ref", "refs/test/drifted", &fixture.oid],
        );

        let report = migrate_on_startup(&fixture.storage).await.unwrap();

        assert!(report.already_current);
        assert_eq!(report.retired_backups, 0);
        assert_eq!(report.retained_backups, 0);
        assert!(!fixture.journal_path.exists());

        let second = migrate_on_startup(&fixture.storage).await.unwrap();
        assert!(second.already_current);
    }

    #[tokio::test]
    async fn completed_journal_without_view_or_backup_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = committed_migration(temp.path(), "deleted", JournalState::Complete).await;
        std::fs::remove_dir_all(&fixture.backup).unwrap();
        std::fs::remove_dir_all(&fixture.view).unwrap();
        mark_storage_current(&fixture.storage);

        let report = migrate_on_startup(&fixture.storage).await.unwrap();

        assert!(report.already_current);
        assert!(!fixture.journal_path.exists());
    }

    #[tokio::test]
    async fn stale_backup_is_retained_when_family_cannot_prove_superset() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = committed_migration(temp.path(), "stale", JournalState::Complete).await;
        mark_storage_current(&fixture.storage);
        // The backup holds an object the family does not; deleting it would
        // lose data, so the relaxed gate keeps it and startup continues.
        write_blob(&fixture.backup, b"only in backup\n");

        let report = migrate_on_startup(&fixture.storage).await.unwrap();

        assert!(report.already_current);
        assert_eq!(report.retired_backups, 0);
        assert_eq!(report.retained_backups, 1);
        assert!(fixture.backup.is_dir());
        assert!(fixture.journal_path.is_file());

        // Idempotent across restarts.
        let second = migrate_on_startup(&fixture.storage).await.unwrap();
        assert_eq!(second.retained_backups, 1);
        assert!(fixture.backup.is_dir());
    }

    fn write_commit_object(repo: &Path, parent: Option<&str>) -> String {
        let tree = git(repo, &["mktree"]);
        let mut contents = format!(
            "tree {tree}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\nshallow fixture\n"
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

    #[tokio::test]
    async fn shallow_legacy_backup_waits_for_family_closure() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        std::fs::create_dir_all(storage.git_data_path()).unwrap();
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let origin = temp.path().join("origin.git");
        git(
            temp.path(),
            &["init", "--bare", "--quiet", origin.to_str().unwrap()],
        );
        let parent = write_commit_object(&origin, None);
        let child = write_commit_object(&origin, Some(&parent));
        git(&origin, &["update-ref", "refs/heads/main", &child]);

        let view = storage
            .git_data_path()
            .join(&owner)
            .join("shallow-repo.git");
        std::fs::create_dir_all(view.parent().unwrap()).unwrap();
        git(
            temp.path(),
            &[
                "clone",
                "--bare",
                "--quiet",
                "--depth",
                "1",
                &format!("file://{}", origin.display()),
                view.to_str().unwrap(),
            ],
        );
        assert!(view.join("shallow").is_file());

        let report = migrate_on_startup(&storage).await.unwrap();

        // The truncated backup waits for closure recovery; startup proceeds.
        assert_eq!(report.migrated_views, 1);
        assert_eq!(report.retired_backups, 0);
        assert_eq!(report.retained_backups, 1);
        let key = FamilyKey::sha1("shallow-repo").unwrap();
        assert!(storage.is_thin_view(&key, &view));
        assert!(view.join("shallow").is_file());
        let backup = backup_root(&storage).join(&owner).join("shallow-repo.git");
        assert!(backup.is_dir());
        assert!(storage.storage_version_path().is_file());

        // A client-requested shallow clone keeps working while recovery is
        // pending.
        let shallow_clone = temp.path().join("shallow-clone.git");
        git(
            temp.path(),
            &[
                "clone",
                "--bare",
                "--quiet",
                "--depth",
                "1",
                &format!("file://{}", view.display()),
                shallow_clone.to_str().unwrap(),
            ],
        );

        // Model integrity repair recovering the full closure from an
        // accepted clone source.
        copy_object_database(&origin, &storage.family_repo_path(&key), ObjectFormat::Sha1).unwrap();

        let second = migrate_on_startup(&storage).await.unwrap();

        assert_eq!(second.retired_backups, 1);
        assert_eq!(second.retained_backups, 0);
        assert!(!backup.exists());
        assert!(!view.join("shallow").exists());
        assert!(load_journals(&storage).unwrap().is_empty());
        // With the closure complete and the marker gone, a full clone works.
        let full_clone = temp.path().join("full-clone.git");
        git(
            temp.path(),
            &[
                "clone",
                "--bare",
                "--quiet",
                &format!("file://{}", view.display()),
                full_clone.to_str().unwrap(),
            ],
        );
        assert!(oid_is_available(&full_clone, &parent).unwrap());
    }

    #[tokio::test]
    async fn stale_backup_without_view_is_retained_as_rollback_material() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = committed_migration(temp.path(), "unlinked", JournalState::Complete).await;
        mark_storage_current(&fixture.storage);
        std::fs::remove_dir_all(&fixture.view).unwrap();

        let report = migrate_on_startup(&fixture.storage).await.unwrap();

        assert!(report.already_current);
        assert_eq!(report.retained_backups, 1);
        assert!(fixture.backup.is_dir());
        assert!(fixture.journal_path.is_file());
    }
}
