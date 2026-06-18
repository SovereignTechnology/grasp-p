//! Repository maintenance cleanup engine.
//!
//! Provides the new `maintenance cleanup` pipeline and keeps
//! `cleanup-empty-repos` as a compatibility wrapper.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::Args;
use nostr_lmdb::NostrLmdb;
use nostr_sdk::prelude::*;

use crate::git::authorization::{
    collect_authorized_maintainers, fetch_repository_data_excluding_purgatory,
};
use crate::git::process;
use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::policy::{build_event_graph, traverse_and_mark_deletions, RetentionReason};
use crate::purgatory::can_apply_state;

const GRAPH_DEPENDENT_KINDS: &[u16] = &[1111, 1617, 1618, 1619, 1621, 1630, 1631, 1632, 1633];

#[derive(Debug, Args)]
pub struct MaintenanceCleanupArgs {
    /// Path to relay LMDB data.
    #[arg(long, env = "NGIT_RELAY_DATA_PATH", default_value = "./data/relay")]
    pub relay_data_path: String,

    /// Path to git data directory.
    #[arg(long, env = "NGIT_GIT_DATA_PATH", default_value = "./data/git")]
    pub git_data_path: String,

    /// Execute safe repair actions. Default is dry-run.
    #[arg(long, default_value_t = false)]
    pub execute: bool,

    /// Allow deletion of non-empty orphan repos (destructive).
    #[arg(long, default_value_t = false)]
    pub prune_orphans: bool,

    /// Allow pruning unresolved missing-git repositories/events (destructive).
    #[arg(long, default_value_t = false)]
    pub prune_missing_git: bool,

    /// Require minimum age before destructive pruning (e.g. 24h, 7d, 3600s).
    #[arg(long)]
    pub prune_after: Option<String>,
}

/// Backward-compatible args for `cleanup-empty-repos`.
#[derive(Debug, Args)]
pub struct CleanupArgs {
    #[arg(long, env = "NGIT_RELAY_DATA_PATH", default_value = "./data/relay")]
    pub relay_data_path: String,

    #[arg(long, env = "NGIT_GIT_DATA_PATH", default_value = "./data/git")]
    pub git_data_path: String,

    #[arg(long, default_value_t = false)]
    pub execute: bool,

    #[arg(long, default_value_t = false)]
    pub purge_orphans: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassProfile {
    All,
    RepoFsOnly,
}

#[derive(Debug, Clone)]
struct MaintenanceOptions {
    execute: bool,
    prune_orphans: bool,
    prune_missing_git: bool,
    prune_after: Option<Duration>,
    profile: PassProfile,
    legacy_force_prune_missing_git: bool,
}

#[derive(Debug, Clone)]
struct RepoFsIssue {
    announcement: Event,
    npub: String,
    identifier: String,
    repo_path: PathBuf,
    repo_exists: bool,
    has_refs: bool,
    valid_authorized_state_exists: bool,
    owner_state_events: Vec<Event>,
}

#[derive(Debug, Clone)]
struct OrphanRepo {
    repo_path: PathBuf,
    npub: String,
    dir_name: String,
    has_data: bool,
}

#[derive(Debug, Default, Clone)]
struct ScanPlan {
    issues: Vec<RepoFsIssue>,
    orphan_repos: Vec<OrphanRepo>,
}

#[derive(Debug, Default, Clone)]
struct CascadeReport {
    scanned_candidates: usize,
    deleted_events: usize,
    planned_announcement_prunes: usize,
    sample_deleted_ids: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct StateRealignReport {
    scanned_identifiers: usize,
    realigned_repositories: usize,
    refs_created: usize,
    refs_updated: usize,
    refs_deleted: usize,
    degraded_missing_git: usize,
    sample_degraded: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct RepoFsReport {
    scanned_announcements: usize,
    missing_or_empty_repos: usize,
    pruned_missing_git_announcements: usize,
    pruned_missing_git_states: usize,
    degraded_valid_state_missing_git: usize,
    orphan_repos_found: usize,
    orphan_empty_removed: usize,
    orphan_nonempty_removed: usize,
    orphan_nonempty_skipped: usize,
    sample_issue_paths: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct MaintenanceRunReport {
    cascade: CascadeReport,
    state_realign: StateRealignReport,
    repo_fs: RepoFsReport,
}

pub async fn run(args: &CleanupArgs) -> Result<()> {
    let options = MaintenanceOptions {
        execute: args.execute,
        prune_orphans: args.purge_orphans,
        prune_missing_git: args.execute,
        prune_after: None,
        profile: PassProfile::RepoFsOnly,
        legacy_force_prune_missing_git: args.execute,
    };

    println!("=== cleanup-empty-repos compatibility wrapper ===");
    println!("This command now uses the shared maintenance cleanup engine.");
    println!("For full maintenance passes use: ngit-grasp maintenance cleanup ...");
    println!();

    run_engine(
        Path::new(&args.relay_data_path),
        Path::new(&args.git_data_path),
        options,
    )
    .await
    .map(|_| ())
}

pub async fn run_maintenance_cleanup(args: &MaintenanceCleanupArgs) -> Result<()> {
    let options = MaintenanceOptions {
        execute: args.execute,
        prune_orphans: args.prune_orphans,
        prune_missing_git: args.prune_missing_git,
        prune_after: parse_prune_after(args.prune_after.as_deref())?,
        profile: PassProfile::All,
        legacy_force_prune_missing_git: false,
    };

    run_engine(
        Path::new(&args.relay_data_path),
        Path::new(&args.git_data_path),
        options,
    )
    .await
    .map(|_| ())
}

async fn run_engine(
    relay_data_path: &Path,
    git_data_path: &Path,
    options: MaintenanceOptions,
) -> Result<MaintenanceRunReport> {
    if options.execute {
        println!("=== maintenance cleanup (EXECUTE) ===");
        println!("Relay should be stopped before destructive operations.");
    } else {
        println!("=== maintenance cleanup (DRY-RUN) ===");
        println!("Pass --execute to run safe repairs.");
    }
    println!(
        "gates execute={} prune_orphans={} prune_missing_git={} prune_after={}",
        options.execute,
        options.prune_orphans,
        options.prune_missing_git || options.legacy_force_prune_missing_git,
        format_prune_after(options.prune_after),
    );
    println!(
        "paths relay_data={} git_data={}",
        relay_data_path.display(),
        git_data_path.display()
    );
    println!();

    let database: Arc<dyn NostrDatabase> = Arc::new(
        NostrLmdb::open(relay_data_path)
            .await
            .with_context(|| format!("Failed to open LMDB at {}", relay_data_path.display()))?,
    );

    run_engine_with_db(database, git_data_path, options).await
}

async fn run_engine_with_db(
    database: Arc<dyn NostrDatabase>,
    git_data_path: &Path,
    options: MaintenanceOptions,
) -> Result<MaintenanceRunReport> {
    let mut report = MaintenanceRunReport::default();

    let plan = build_scan_plan(&database, git_data_path).await?;

    let planned_prune_ids: HashSet<EventId> = if options.execute
        && (options.prune_missing_git || options.legacy_force_prune_missing_git)
    {
        plan.issues
            .iter()
            .filter(|issue| prune_allowed_for_issue(issue, options.prune_after))
            .map(|issue| issue.announcement.id)
            .collect()
    } else {
        HashSet::new()
    };

    if options.profile == PassProfile::All {
        report.cascade = run_cascade_reconcile(
            &database,
            &planned_prune_ids,
            options.execute,
            options.prune_after,
        )
        .await?;
        print_cascade_report(&report.cascade, options.execute);

        report.state_realign = run_state_realign(&database, git_data_path, options.execute).await?;
        print_state_realign_report(&report.state_realign, options.execute);
    }

    report.repo_fs = run_repo_fs_reconcile(
        &database,
        git_data_path,
        &plan,
        &planned_prune_ids,
        &options,
    )
    .await?;
    print_repo_fs_report(&report.repo_fs, options.execute, &options);

    println!();
    println!("maintenance.cleanup complete execute={}", options.execute);

    Ok(report)
}

async fn build_scan_plan(
    database: &Arc<dyn NostrDatabase>,
    git_data_path: &Path,
) -> Result<ScanPlan> {
    let filter = Filter::new().kind(Kind::GitRepoAnnouncement);
    let announcements = database
        .query(filter)
        .await
        .context("Failed to query kind 30617 announcements")?;

    let mut issues = Vec::new();

    for event in announcements {
        let announcement = match RepositoryAnnouncement::from_event(event.clone()) {
            Ok(a) => a,
            Err(_) => continue,
        };

        let repo_path = git_data_path.join(announcement.repo_path());
        let (repo_exists, has_refs) = repo_ref_status(&repo_path);
        if has_refs {
            continue;
        }

        let owner_filter = Filter::new()
            .kind(Kind::RepoState)
            .author(event.pubkey)
            .identifier(announcement.identifier.clone());

        let owner_state_events: Vec<Event> = database
            .query(owner_filter)
            .await
            .with_context(|| {
                format!(
                    "Failed to query owner states for {}/{}",
                    announcement.owner_npub(),
                    announcement.identifier
                )
            })?
            .into_iter()
            .collect();

        let valid_authorized_state_exists =
            owner_has_authorized_state(database, &announcement.identifier, &event.pubkey.to_hex())
                .await;

        issues.push(RepoFsIssue {
            announcement: event,
            npub: announcement.owner_npub(),
            identifier: announcement.identifier,
            repo_path,
            repo_exists,
            has_refs,
            valid_authorized_state_exists,
            owner_state_events,
        });
    }

    let orphan_repos = find_orphan_repos(git_data_path, database).await?;
    Ok(ScanPlan {
        issues,
        orphan_repos,
    })
}

async fn run_cascade_reconcile(
    database: &Arc<dyn NostrDatabase>,
    planned_prune_ids: &HashSet<EventId>,
    execute: bool,
    prune_after: Option<Duration>,
) -> Result<CascadeReport> {
    let mut report = CascadeReport {
        planned_announcement_prunes: planned_prune_ids.len(),
        ..Default::default()
    };

    let candidates = query_cascade_candidates(database).await?;
    report.scanned_candidates = candidates.len();

    if candidates.is_empty() {
        return Ok(report);
    }

    let graph = build_event_graph(&candidates);
    let mut kept: HashMap<EventId, RetentionReason> = HashMap::new();

    for event in &candidates {
        if event.kind == Kind::GitRepoAnnouncement && !planned_prune_ids.contains(&event.id) {
            kept.insert(
                event.id,
                RetentionReason {
                    event_id: event.id,
                    valid_announcements: vec![announcement_address_of(event)],
                    event_type: "Repository Announcement".to_string(),
                },
            );
        }
    }

    let traversal = traverse_and_mark_deletions(&graph, &kept, EventId::all_zeros());

    let mut deletable_ids: Vec<EventId> = Vec::new();
    for event in &candidates {
        if !traversal.delete.contains(&event.id) {
            continue;
        }

        let is_announcement = event.kind == Kind::GitRepoAnnouncement;
        if is_announcement && !planned_prune_ids.contains(&event.id) {
            continue;
        }

        if !is_announcement || planned_prune_ids.contains(&event.id) {
            deletable_ids.push(event.id);
        }
    }

    report.sample_deleted_ids = deletable_ids
        .iter()
        .take(10)
        .map(|id| id.to_hex())
        .collect();

    if execute && !deletable_ids.is_empty() {
        database
            .delete(Filter::new().ids(deletable_ids.clone()))
            .await
            .context("Cascade reconcile deletion failed")?;
        report.deleted_events = deletable_ids.len();
    } else {
        report.deleted_events = deletable_ids.len();
    }

    if report.planned_announcement_prunes > 0 {
        println!(
            "cascade-reconcile planned prune_missing_git announcements={} prune_after={}",
            report.planned_announcement_prunes,
            format_prune_after(prune_after)
        );
    }

    Ok(report)
}

async fn run_state_realign(
    database: &Arc<dyn NostrDatabase>,
    git_data_path: &Path,
    execute: bool,
) -> Result<StateRealignReport> {
    let mut report = StateRealignReport::default();

    let events = database
        .query(Filter::new().kinds([Kind::GitRepoAnnouncement, Kind::RepoState]))
        .await
        .context("Failed to query announcements/states for state-realign")?;

    let mut identifiers = HashSet::new();
    for event in events {
        if let Some(identifier) = identifier_from_event(&event) {
            identifiers.insert(identifier);
        }
    }

    report.scanned_identifiers = identifiers.len();

    for identifier in identifiers {
        let repo_data = match fetch_repository_data_excluding_purgatory(database, &identifier).await
        {
            Ok(data) => data,
            Err(_) => continue,
        };

        if repo_data.announcements.is_empty() {
            continue;
        }

        let by_owner = collect_authorized_maintainers(&repo_data.announcements);

        for announcement in &repo_data.announcements {
            let owner_hex = announcement.event.pubkey.to_hex();
            let Some(maintainers) = by_owner.get(&owner_hex) else {
                continue;
            };

            let latest_state = repo_data
                .states
                .iter()
                .filter(|state| maintainers.contains(&state.event.pubkey.to_hex()))
                .max_by(|a, b| {
                    a.event
                        .created_at
                        .cmp(&b.event.created_at)
                        .then_with(|| a.event.id.cmp(&b.event.id))
                });

            let Some(latest_state) = latest_state else {
                continue;
            };

            let target_repo_path = git_data_path.join(announcement.repo_path());
            if !target_repo_path.is_dir() {
                report.degraded_missing_git += 1;
                push_sample(
                    &mut report.sample_degraded,
                    format!(
                        "{}/{} missing target repo {} for state {}",
                        announcement.owner_npub(),
                        identifier,
                        target_repo_path.display(),
                        latest_state.event.id.to_hex()
                    ),
                );
                continue;
            }

            let source_repo_path = repo_data.announcements.iter().find_map(|candidate| {
                let candidate_path = git_data_path.join(candidate.repo_path());
                if candidate_path.is_dir() && can_apply_state(&latest_state.event, &candidate_path)
                {
                    Some(candidate_path)
                } else {
                    None
                }
            });

            let Some(source_repo_path) = source_repo_path else {
                report.degraded_missing_git += 1;
                push_sample(
                    &mut report.sample_degraded,
                    format!(
                        "{}/{} valid state {} exists but git data missing",
                        announcement.owner_npub(),
                        identifier,
                        latest_state.event.id.to_hex()
                    ),
                );
                continue;
            };

            if execute {
                let result = process::process_state_with_git_data(
                    latest_state,
                    &source_repo_path,
                    &repo_data,
                    git_data_path,
                );
                report.realigned_repositories += result.repos_synced;
                report.refs_created += result.refs_created;
                report.refs_updated += result.refs_updated;
                report.refs_deleted += result.refs_deleted;
            } else {
                report.realigned_repositories += 1;
            }
        }
    }

    Ok(report)
}

async fn run_repo_fs_reconcile(
    database: &Arc<dyn NostrDatabase>,
    git_data_path: &Path,
    plan: &ScanPlan,
    planned_prune_ids: &HashSet<EventId>,
    options: &MaintenanceOptions,
) -> Result<RepoFsReport> {
    let mut report = RepoFsReport {
        scanned_announcements: plan.issues.len(),
        missing_or_empty_repos: plan.issues.len(),
        orphan_repos_found: plan.orphan_repos.len(),
        ..Default::default()
    };

    for issue in &plan.issues {
        push_sample(
            &mut report.sample_issue_paths,
            format!(
                "{}/{} repo={} exists={} has_refs={}",
                issue.npub,
                issue.identifier,
                issue.repo_path.display(),
                issue.repo_exists,
                issue.has_refs
            ),
        );

        if issue.valid_authorized_state_exists {
            report.degraded_valid_state_missing_git += 1;
        }

        let should_prune = options.execute
            && (options.prune_missing_git || options.legacy_force_prune_missing_git)
            && prune_allowed_for_issue(issue, options.prune_after);

        if !should_prune {
            continue;
        }

        if issue.repo_exists {
            let _ = std::fs::remove_dir_all(&issue.repo_path);
            remove_parent_if_empty(&issue.repo_path);
        }

        // Cascade pass may already remove this announcement; delete-by-id is idempotent.
        database
            .delete(Filter::new().id(issue.announcement.id))
            .await
            .with_context(|| {
                format!(
                    "Failed deleting announcement {} during repo-fs prune",
                    issue.announcement.id.to_hex()
                )
            })?;
        report.pruned_missing_git_announcements += 1;

        let announcement_was_cascade_pruned = planned_prune_ids.contains(&issue.announcement.id);
        if announcement_was_cascade_pruned {
            // state prune check still needed because cascade pass does not touch states.
        }

        if no_announcements_for_identifier(database, &issue.identifier).await? {
            let state_count = count_events(
                database,
                Filter::new()
                    .kind(Kind::RepoState)
                    .identifier(issue.identifier.clone()),
            )
            .await?;

            database
                .delete(
                    Filter::new()
                        .kind(Kind::RepoState)
                        .identifier(issue.identifier.clone()),
                )
                .await
                .with_context(|| {
                    format!(
                        "Failed deleting unanchored states for identifier {}",
                        issue.identifier
                    )
                })?;

            report.pruned_missing_git_states += state_count;
        }
    }

    for orphan in &plan.orphan_repos {
        push_sample(
            &mut report.sample_issue_paths,
            format!(
                "orphan {}/{} path={} has_data={}",
                orphan.npub,
                orphan.dir_name,
                orphan.repo_path.display(),
                orphan.has_data
            ),
        );
        if orphan.has_data {
            let allowed = options.execute
                && options.prune_orphans
                && prune_allowed_for_path(&orphan.repo_path, options.prune_after);

            if allowed {
                let _ = std::fs::remove_dir_all(&orphan.repo_path);
                remove_parent_if_empty(&orphan.repo_path);
                report.orphan_nonempty_removed += 1;
            } else {
                report.orphan_nonempty_skipped += 1;
            }
        } else if options.execute {
            let _ = std::fs::remove_dir_all(&orphan.repo_path);
            remove_parent_if_empty(&orphan.repo_path);
            report.orphan_empty_removed += 1;
        }
    }

    let _ = git_data_path;
    Ok(report)
}

fn prune_allowed_for_issue(issue: &RepoFsIssue, prune_after: Option<Duration>) -> bool {
    if let Some(min_age) = prune_after {
        let newest = issue
            .owner_state_events
            .iter()
            .map(|e| e.created_at.as_secs())
            .max()
            .unwrap_or(issue.announcement.created_at.as_secs());
        return age_secs(newest) >= min_age.as_secs();
    }
    true
}

fn prune_allowed_for_path(path: &Path, prune_after: Option<Duration>) -> bool {
    let Some(min_age) = prune_after else {
        return true;
    };

    let modified = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    match modified {
        Some(ts) => age_secs(ts) >= min_age.as_secs(),
        None => false,
    }
}

fn age_secs(timestamp_secs: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    now.saturating_sub(timestamp_secs)
}

fn format_prune_after(value: Option<Duration>) -> String {
    value
        .map(|d| format!("{}s", d.as_secs()))
        .unwrap_or_else(|| "none".to_string())
}

fn parse_prune_after(input: Option<&str>) -> Result<Option<Duration>> {
    let Some(raw) = input else {
        return Ok(None);
    };

    parse_duration_like(raw).map(Some)
}

fn parse_duration_like(raw: &str) -> Result<Duration> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("--prune-after cannot be empty"));
    }

    let split_at = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());

    let (num_part, unit_part) = trimmed.split_at(split_at);
    let value: u64 = num_part
        .parse()
        .map_err(|_| anyhow!("invalid duration value: {}", raw))?;
    let unit = if unit_part.is_empty() { "s" } else { unit_part };

    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 60 * 60 * 24,
        "w" => 60 * 60 * 24 * 7,
        _ => {
            return Err(anyhow!(
                "invalid duration unit '{}'; use s, m, h, d, or w",
                unit
            ))
        }
    };

    Ok(Duration::from_secs(value.saturating_mul(multiplier)))
}

fn repo_ref_status(repo_path: &Path) -> (bool, bool) {
    if !repo_path.exists() {
        return (false, false);
    }

    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repo_path)
        .args(["for-each-ref", "--format=%(refname)"])
        .output();

    match output {
        Ok(out) => {
            let has_refs = !String::from_utf8_lossy(&out.stdout).trim().is_empty();
            (true, has_refs)
        }
        Err(_) => (true, false),
    }
}

async fn owner_has_authorized_state(
    database: &Arc<dyn NostrDatabase>,
    identifier: &str,
    owner_hex: &str,
) -> bool {
    let Ok(repo_data) = fetch_repository_data_excluding_purgatory(database, identifier).await
    else {
        return false;
    };

    let by_owner = collect_authorized_maintainers(&repo_data.announcements);
    let Some(maintainers) = by_owner.get(owner_hex) else {
        return false;
    };

    repo_data
        .states
        .iter()
        .any(|state| maintainers.contains(&state.event.pubkey.to_hex()))
}

async fn no_announcements_for_identifier(
    database: &Arc<dyn NostrDatabase>,
    identifier: &str,
) -> Result<bool> {
    let remaining = database
        .query(
            Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .identifier(identifier.to_string()),
        )
        .await
        .with_context(|| format!("Failed querying remaining announcements for {}", identifier))?;
    Ok(remaining.is_empty())
}

async fn count_events(database: &Arc<dyn NostrDatabase>, filter: Filter) -> Result<usize> {
    Ok(database
        .query(filter)
        .await
        .context("Failed counting events")?
        .len())
}

async fn query_cascade_candidates(database: &Arc<dyn NostrDatabase>) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    events.extend(
        database
            .query(Filter::new().kind(Kind::GitRepoAnnouncement))
            .await
            .context("Failed querying announcements for cascade")?,
    );

    for kind_num in GRAPH_DEPENDENT_KINDS {
        events.extend(
            database
                .query(Filter::new().kind(Kind::from(*kind_num)))
                .await
                .with_context(|| format!("Failed querying kind {} for cascade", kind_num))?,
        );
    }

    Ok(events)
}

fn announcement_address_of(event: &Event) -> String {
    let identifier = identifier_from_event(event).unwrap_or_default();
    format!("30617:{}:{}", event.pubkey.to_hex(), identifier)
}

fn identifier_from_event(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == "d")
        .and_then(|t| t.content())
        .map(|s| s.to_string())
}

fn push_sample(samples: &mut Vec<String>, value: String) {
    if samples.len() < 10 {
        samples.push(value);
    }
}

fn remove_parent_if_empty(repo_path: &Path) {
    let Some(parent) = repo_path.parent() else {
        return;
    };
    if !parent.exists() {
        return;
    }
    let Ok(mut entries) = std::fs::read_dir(parent) else {
        return;
    };
    if entries.next().is_none() {
        let _ = std::fs::remove_dir(parent);
    }
}

async fn find_orphan_repos(
    git_data_path: &Path,
    database: &Arc<dyn NostrDatabase>,
) -> Result<Vec<OrphanRepo>> {
    let mut orphans = Vec::new();

    let npub_entries = match std::fs::read_dir(git_data_path) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(orphans),
        Err(e) => {
            return Err(anyhow!(
                "Failed to read git data directory {}: {}",
                git_data_path.display(),
                e
            ))
        }
    };

    for npub_entry in npub_entries {
        let npub_entry = npub_entry.context("Failed to read git data directory entry")?;
        let npub_path = npub_entry.path();
        if !npub_path.is_dir() {
            continue;
        }
        if crate::grasp06::paths::is_prs_repo_path(&npub_path, git_data_path) {
            continue;
        }
        let npub = npub_entry.file_name().to_string_lossy().into_owned();

        let repo_entries = match std::fs::read_dir(&npub_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for repo_entry in repo_entries {
            let repo_entry = repo_entry.context("Failed to read repo directory entry")?;
            let repo_path = repo_entry.path();
            if !repo_path.is_dir() {
                continue;
            }
            let dir_name = repo_entry.file_name().to_string_lossy().into_owned();
            if !dir_name.ends_with(".git") {
                continue;
            }

            let identifier = dir_name.strip_suffix(".git").unwrap_or(&dir_name);
            let filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .identifier(identifier.to_string());
            let matching = database
                .query(filter)
                .await
                .with_context(|| format!("Failed to query announcement for {}", identifier))?;

            let has_event = matching
                .iter()
                .any(|ev| ev.pubkey.to_bech32().map(|n| n == npub).unwrap_or(false));
            if has_event {
                continue;
            }

            let (_, has_refs) = repo_ref_status(&repo_path);
            orphans.push(OrphanRepo {
                repo_path,
                npub: npub.clone(),
                dir_name,
                has_data: has_refs,
            });
        }
    }

    Ok(orphans)
}

fn print_cascade_report(report: &CascadeReport, execute: bool) {
    println!("pass=cascade-reconcile execute={}", execute);
    println!(
        "  scanned_candidates={} deleted_events={} planned_prune_announcements={}",
        report.scanned_candidates, report.deleted_events, report.planned_announcement_prunes
    );
    if !report.sample_deleted_ids.is_empty() {
        println!(
            "  sample_deleted_event_ids={}",
            report.sample_deleted_ids.join(",")
        );
    }
}

fn print_state_realign_report(report: &StateRealignReport, execute: bool) {
    println!("pass=state-realign execute={}", execute);
    println!(
        "  scanned_identifiers={} realigned_repositories={} refs_created={} refs_updated={} refs_deleted={}",
        report.scanned_identifiers,
        report.realigned_repositories,
        report.refs_created,
        report.refs_updated,
        report.refs_deleted
    );
    if report.degraded_missing_git > 0 {
        println!(
            "  degraded_valid_state_missing_git={} (not pruned without --prune-missing-git)",
            report.degraded_missing_git
        );
        for sample in &report.sample_degraded {
            println!("  degraded_sample={}", sample);
        }
    }
}

fn print_repo_fs_report(report: &RepoFsReport, execute: bool, options: &MaintenanceOptions) {
    println!("pass=repo-fs-reconcile execute={}", execute);
    println!(
        "  scanned_announcements={} missing_or_empty_repos={} degraded_valid_state_missing_git={}",
        report.scanned_announcements,
        report.missing_or_empty_repos,
        report.degraded_valid_state_missing_git
    );
    println!(
        "  orphan_repos_found={} orphan_empty_removed={} orphan_nonempty_removed={} orphan_nonempty_skipped={}",
        report.orphan_repos_found,
        report.orphan_empty_removed,
        report.orphan_nonempty_removed,
        report.orphan_nonempty_skipped
    );
    println!(
        "  pruned_missing_git_announcements={} pruned_missing_git_states={}",
        report.pruned_missing_git_announcements, report.pruned_missing_git_states
    );
    if report.degraded_valid_state_missing_git > 0
        && !options.prune_missing_git
        && !options.legacy_force_prune_missing_git
    {
        println!(
            "  degraded_notice=valid 30618 exists but git data missing (reported only; use --prune-missing-git to delete)"
        );
    }
    for sample in &report.sample_issue_paths {
        println!("  issue_sample={}", sample);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::FinalizeEvent;
    use nostr_memory::MemoryDatabase;
    use nostr_relay_builder::prelude::{EventBuilder, Keys, Tag};
    use tempfile::tempdir;

    fn announcement(keys: &Keys, identifier: &str) -> Event {
        EventBuilder::new(Kind::GitRepoAnnouncement, "repo")
            .tags(vec![
                Tag::custom("d", vec![identifier.to_string()]),
                Tag::custom("clone", vec![format!("https://relay/{}", identifier)]),
                Tag::custom("relays", vec!["wss://relay".to_string()]),
            ])
            .finalize(keys)
            .unwrap()
    }

    fn state(keys: &Keys, identifier: &str, oid: &str) -> Event {
        EventBuilder::new(Kind::RepoState, "state")
            .tags(vec![
                Tag::custom("d", vec![identifier.to_string()]),
                Tag::custom("refs/heads/main", vec![oid.to_string()]),
                Tag::custom("HEAD", vec!["ref: refs/heads/main".to_string()]),
            ])
            .finalize(keys)
            .unwrap()
    }

    fn issue(keys: &Keys, addr: &str) -> Event {
        EventBuilder::new(Kind::from(1621), "issue")
            .tags(vec![Tag::custom("a", vec![addr.to_string()])])
            .finalize(keys)
            .unwrap()
    }

    fn default_options() -> MaintenanceOptions {
        MaintenanceOptions {
            execute: false,
            prune_orphans: false,
            prune_missing_git: false,
            prune_after: None,
            profile: PassProfile::All,
            legacy_force_prune_missing_git: false,
        }
    }

    async fn count_kind(db: &Arc<dyn NostrDatabase>, kind: Kind) -> usize {
        db.query(Filter::new().kind(kind)).await.unwrap().len()
    }

    #[tokio::test]
    async fn dry_run_does_not_mutate() {
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        let tmp = tempdir().unwrap();
        let git_path = tmp.path();

        let owner = Keys::generate();
        let ann = announcement(&owner, "repo-a");
        db.save_event(&ann).await.unwrap();

        let owner_npub = owner.public_key().to_bech32().unwrap();
        let orphan_path = git_path.join(owner_npub).join("orphan.git");
        std::fs::create_dir_all(&orphan_path).unwrap();
        Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(&orphan_path)
            .status()
            .unwrap();

        let report = run_engine_with_db(db.clone(), git_path, default_options())
            .await
            .unwrap();

        assert_eq!(count_kind(&db, Kind::GitRepoAnnouncement).await, 1);
        assert!(orphan_path.exists());
        assert!(report.repo_fs.orphan_repos_found >= 1);
    }

    #[tokio::test]
    async fn execute_safe_only_skips_destructive_paths() {
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        let tmp = tempdir().unwrap();
        let git_path = tmp.path();

        let owner = Keys::generate();
        let ann = announcement(&owner, "repo-safe");
        let st = state(
            &owner,
            "repo-safe",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        db.save_event(&ann).await.unwrap();
        db.save_event(&st).await.unwrap();

        let owner_npub = owner.public_key().to_bech32().unwrap();
        let nonempty_orphan = git_path.join(owner_npub).join("orphan-nonempty.git");
        create_nonempty_bare_repo(&nonempty_orphan);

        let mut options = default_options();
        options.execute = true;

        let report = run_engine_with_db(db.clone(), git_path, options)
            .await
            .unwrap();

        assert_eq!(count_kind(&db, Kind::GitRepoAnnouncement).await, 1);
        assert_eq!(count_kind(&db, Kind::RepoState).await, 1);
        assert!(nonempty_orphan.exists());
        assert!(report.repo_fs.degraded_valid_state_missing_git >= 1);
        assert_eq!(report.repo_fs.pruned_missing_git_announcements, 0);
        assert_eq!(report.repo_fs.orphan_nonempty_removed, 0);
    }

    #[tokio::test]
    async fn destructive_flags_gate_mutations() {
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        let tmp = tempdir().unwrap();
        let git_path = tmp.path();

        let owner = Keys::generate();
        let ann = announcement(&owner, "repo-prune");
        let st = state(
            &owner,
            "repo-prune",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        db.save_event(&ann).await.unwrap();
        db.save_event(&st).await.unwrap();

        let owner_npub = owner.public_key().to_bech32().unwrap();
        let nonempty_orphan = git_path.join(owner_npub).join("orphan-prune.git");
        create_nonempty_bare_repo(&nonempty_orphan);

        let mut options = default_options();
        options.execute = true;
        options.prune_missing_git = true;
        options.prune_orphans = true;

        let report = run_engine_with_db(db.clone(), git_path, options)
            .await
            .unwrap();

        assert_eq!(count_kind(&db, Kind::GitRepoAnnouncement).await, 0);
        assert_eq!(count_kind(&db, Kind::RepoState).await, 0);
        assert!(!nonempty_orphan.exists());
        assert!(report.repo_fs.pruned_missing_git_announcements >= 1);
        assert!(report.repo_fs.orphan_nonempty_removed >= 1);
    }

    #[tokio::test]
    async fn cascade_reconcile_cleans_legacy_orphan_dependents() {
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        let tmp = tempdir().unwrap();

        let keys = Keys::generate();
        let dangling = issue(
            &keys,
            "30617:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:ghost",
        );
        db.save_event(&dangling).await.unwrap();

        let mut options = default_options();
        options.execute = true;

        let report = run_engine_with_db(db.clone(), tmp.path(), options)
            .await
            .unwrap();

        assert_eq!(count_kind(&db, Kind::from(1621)).await, 0);
        assert!(report.cascade.deleted_events >= 1);
    }

    #[tokio::test]
    async fn idempotent_second_run_has_no_new_mutations() {
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        let tmp = tempdir().unwrap();
        let git_path = tmp.path();

        let owner = Keys::generate();
        let ann = announcement(&owner, "repo-idempotent");
        let st = state(
            &owner,
            "repo-idempotent",
            "cccccccccccccccccccccccccccccccccccccccc",
        );
        let ann_addr = format!("30617:{}:{}", ann.pubkey.to_hex(), "repo-idempotent");
        let dep = issue(&owner, &ann_addr);

        db.save_event(&ann).await.unwrap();
        db.save_event(&st).await.unwrap();
        db.save_event(&dep).await.unwrap();

        let mut options = default_options();
        options.execute = true;
        options.prune_missing_git = true;

        let first = run_engine_with_db(db.clone(), git_path, options.clone())
            .await
            .unwrap();
        let second = run_engine_with_db(db.clone(), git_path, options)
            .await
            .unwrap();

        assert!(
            first.cascade.deleted_events >= 1
                || first.repo_fs.pruned_missing_git_announcements >= 1
        );
        assert_eq!(second.cascade.deleted_events, 0);
        assert_eq!(second.repo_fs.pruned_missing_git_announcements, 0);
        assert_eq!(second.repo_fs.pruned_missing_git_states, 0);
    }

    fn create_nonempty_bare_repo(path: &Path) {
        assert!(Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(path)
            .status()
            .unwrap()
            .success());

        let output = Command::new("git")
            .arg("--git-dir")
            .arg(path)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .expect("stdin")
                    .write_all(b"hello")
                    .expect("write blob");
                child.wait_with_output()
            })
            .expect("hash object");
        assert!(output.status.success());
        let oid = String::from_utf8_lossy(&output.stdout).trim().to_string();

        assert!(Command::new("git")
            .arg("--git-dir")
            .arg(path)
            .args(["update-ref", "refs/tags/test-nonempty", &oid])
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn parse_duration_like_supports_units() {
        assert_eq!(parse_duration_like("10s").unwrap().as_secs(), 10);
        assert_eq!(parse_duration_like("5m").unwrap().as_secs(), 300);
        assert_eq!(parse_duration_like("2h").unwrap().as_secs(), 7200);
        assert_eq!(parse_duration_like("1d").unwrap().as_secs(), 86400);
    }
}
