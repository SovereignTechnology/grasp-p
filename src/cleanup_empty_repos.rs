//! Cleanup Empty Repositories
//!
//! Scans the LMDB database for kind 30617 (repository announcement) events whose
//! corresponding bare git repository on disk is empty (no refs) or missing entirely.
//! For each such repository, also removes any kind 30618 (state) events for the same
//! (pubkey, identifier) coordinate.
//!
//! ## Rationale
//!
//! A relay should not store announcement or state events for a repository that has no
//! git data. If the bare repo is empty or absent, the events are stale and should be
//! removed so the relay does not serve them.
//!
//! Two scans are performed:
//!
//! 1. **DB → filesystem**: finds 30617 events whose bare git repo is empty or missing.
//!    Both the 30617 and any matching 30618 events are removed.
//!
//! 2. **Filesystem → DB**: finds bare git repos on disk with no matching 30617 event.
//!    Empty orphan repos are always removed. Non-empty orphan repos are flagged and
//!    only removed when `--purge-orphans` is also passed.
//!
//! ## Usage
//!
//! ```text
//! # Dry-run (default): print what would be deleted
//! ngit-grasp cleanup-empty-repos --relay-data-path /var/lib/ngit-grasp/relay \
//!                                 --git-data-path   /var/lib/ngit-grasp/git
//!
//! # Execute: delete the bare repos and remove events from the DB
//! ngit-grasp cleanup-empty-repos --relay-data-path /var/lib/ngit-grasp/relay \
//!                                 --git-data-path   /var/lib/ngit-grasp/git \
//!                                 --execute
//!
//! # Also purge non-empty orphan repos (no matching 30617 in DB)
//! ngit-grasp cleanup-empty-repos --relay-data-path /var/lib/ngit-grasp/relay \
//!                                 --git-data-path   /var/lib/ngit-grasp/git \
//!                                 --execute --purge-orphans
//! ```
//!
//! The relay service should be stopped before running with `--execute` to avoid
//! races with the live relay process.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;
use nostr_lmdb::NostrLmdb;
use nostr_sdk::prelude::*;

use crate::nostr::events::RepositoryAnnouncement;

/// Arguments for the `cleanup-empty-repos` subcommand.
#[derive(Debug, Args)]
pub struct CleanupArgs {
    /// Path to the LMDB relay data directory (contains the nostr event database).
    ///
    /// Defaults to `./data/relay` (same default as the relay itself).
    #[arg(long, env = "NGIT_RELAY_DATA_PATH", default_value = "./data/relay")]
    pub relay_data_path: String,

    /// Path to the git data directory (contains bare repositories).
    ///
    /// Defaults to `./data/git` (same default as the relay itself).
    #[arg(long, env = "NGIT_GIT_DATA_PATH", default_value = "./data/git")]
    pub git_data_path: String,

    /// Actually delete empty repositories and remove their events from the database.
    ///
    /// Without this flag the command runs in dry-run mode and only prints what
    /// would be deleted. Stop the relay service before using this flag.
    #[arg(long, default_value_t = false)]
    pub execute: bool,

    /// Also purge non-empty orphan git repos (repos on disk with no matching 30617 event).
    ///
    /// By default, non-empty orphan repos are flagged but not deleted. Pass this flag
    /// together with `--execute` to permanently delete them. Use with caution.
    #[arg(long, default_value_t = false)]
    pub purge_orphans: bool,
}

/// A bare git repo on disk that has no matching kind 30617 event in the DB.
#[derive(Debug)]
struct OrphanRepo {
    /// Absolute path to the bare repo directory
    repo_path: PathBuf,
    /// npub directory name (may not be a valid npub)
    npub: String,
    /// Repository directory name (e.g. "my-repo.git")
    dir_name: String,
    /// Whether the repo has any refs (non-empty)
    has_data: bool,
}

/// A repository that has an empty (or missing) bare git repo on disk.
#[derive(Debug)]
struct EmptyRepo {
    /// The kind 30617 event
    announcement: Event,
    /// Derived npub (bech32) of the owner
    npub: String,
    /// Repository identifier (d-tag value)
    identifier: String,
    /// Absolute path to the bare repo directory
    repo_path: PathBuf,
    /// Whether the directory exists at all (vs exists but is empty)
    repo_exists: bool,
    /// Any kind 30618 state events found in the local DB for this coordinate
    state_events: Vec<Event>,
}

/// Run the cleanup-empty-repos subcommand.
pub async fn run(args: &CleanupArgs) -> Result<()> {
    let relay_data_path = Path::new(&args.relay_data_path);
    let git_data_path = Path::new(&args.git_data_path);

    if args.execute {
        println!("=== cleanup-empty-repos (EXECUTE MODE) ===");
        println!("WARNING: This will permanently delete data. The relay should be stopped.");
        println!();
    } else {
        println!("=== cleanup-empty-repos (DRY-RUN MODE) ===");
        println!("Pass --execute to actually delete. Stop the relay first.");
        println!();
    }

    println!("Relay data path : {}", relay_data_path.display());
    println!("Git data path   : {}", git_data_path.display());
    println!();

    // Open the LMDB database
    println!("Opening LMDB database...");
    let database: Arc<dyn NostrDatabase> = Arc::new(
        NostrLmdb::open(relay_data_path)
            .await
            .with_context(|| format!("Failed to open LMDB at {}", relay_data_path.display()))?,
    );
    println!("Database opened.");
    println!();

    // Query all kind 30617 events
    let filter = Filter::new().kind(Kind::GitRepoAnnouncement);
    let announcements = database
        .query(filter)
        .await
        .context("Failed to query kind 30617 events")?;

    println!(
        "Found {} kind 30617 announcement(s) in database.",
        announcements.len()
    );
    println!();

    // Identify empty repos
    let mut empty_repos: Vec<EmptyRepo> = Vec::new();

    for event in announcements.iter() {
        let announcement = match RepositoryAnnouncement::from_event(event.clone()) {
            Ok(a) => a,
            Err(e) => {
                eprintln!(
                    "  WARN: Could not parse announcement {} (skipping): {}",
                    event.id.to_hex(),
                    e
                );
                continue;
            }
        };

        let npub = announcement.owner_npub();
        let identifier = announcement.identifier.clone();
        let repo_path = git_data_path.join(announcement.repo_path());

        let (repo_exists, is_empty) = check_repo_empty(&repo_path);

        if !is_empty {
            // Repo has git data — leave it alone
            continue;
        }

        // Look up any kind 30618 state events for this (pubkey, identifier) in the local DB
        let state_filter = Filter::new()
            .kind(Kind::RepoState)
            .author(event.pubkey)
            .identifier(identifier.clone());

        let state_events = database
            .query(state_filter)
            .await
            .with_context(|| format!("Failed to query kind 30618 for {}/{}", npub, identifier))?;

        empty_repos.push(EmptyRepo {
            announcement: event.clone(),
            npub,
            identifier,
            repo_path,
            repo_exists,
            state_events: state_events.into_iter().collect(),
        });
    }

    // --- Filesystem → DB scan: orphan repos ---
    println!("Scanning git data directory for orphan repos (no matching 30617 event)...");
    let orphan_repos = find_orphan_repos(git_data_path, &database).await?;
    println!(
        "Found {} orphan repo(s) on disk with no matching 30617 event.",
        orphan_repos.len()
    );
    println!();

    if empty_repos.is_empty() && orphan_repos.is_empty() {
        println!("Nothing to do.");
        return Ok(());
    }

    // Print report
    println!(
        "Found {} repository/repositories with empty or missing git data:\n",
        empty_repos.len()
    );

    for (i, repo) in empty_repos.iter().enumerate() {
        let repo_status = if repo.repo_exists {
            "exists but empty (no refs)"
        } else {
            "missing from disk"
        };
        println!(
            "  [{:>3}] {}/{} — git repo {}",
            i + 1,
            repo.npub,
            repo.identifier,
            repo_status,
        );
        println!("         30617 event : {}", repo.announcement.id.to_hex());
        if repo.state_events.is_empty() {
            println!("         30618 events: none in local DB");
        } else {
            for se in &repo.state_events {
                println!("         30618 event : {}", se.id.to_hex());
            }
        }
        println!("         repo path   : {}", repo.repo_path.display());
    }

    // Print orphan report
    if !orphan_repos.is_empty() {
        println!(
            "Found {} orphan repo(s) on disk with no matching 30617 event:\n",
            orphan_repos.len()
        );
        let mut empty_orphan_count = 0usize;
        let mut nonempty_orphan_count = 0usize;
        for (i, repo) in orphan_repos.iter().enumerate() {
            let status = if repo.has_data {
                nonempty_orphan_count += 1;
                "NON-EMPTY (has git data)"
            } else {
                empty_orphan_count += 1;
                "empty (no refs)"
            };
            println!(
                "  [{:>3}] {}/{} — {}",
                i + 1,
                repo.npub,
                repo.dir_name,
                status,
            );
            println!("         repo path: {}", repo.repo_path.display());
        }
        println!();
        if nonempty_orphan_count > 0 {
            println!(
                "  NOTE: {} non-empty orphan repo(s) will NOT be deleted unless --purge-orphans is passed.",
                nonempty_orphan_count
            );
        }
        if empty_orphan_count > 0 {
            println!(
                "  NOTE: {} empty orphan repo(s) will be deleted (no git data to lose).",
                empty_orphan_count
            );
        }
        println!();
    }

    if !args.execute {
        let would_delete = empty_repos.len()
            + orphan_repos.iter().filter(|r| !r.has_data).count()
            + if args.purge_orphans {
                orphan_repos.iter().filter(|r| r.has_data).count()
            } else {
                0
            };
        println!("DRY-RUN: {} item(s) would be cleaned up.", would_delete);
        if orphan_repos.iter().any(|r| r.has_data) && !args.purge_orphans {
            println!(
                "  (non-empty orphan repos flagged above would be skipped; add --purge-orphans to include them)"
            );
        }
        println!("Run with --execute to perform the cleanup (stop the relay first).");
        return Ok(());
    }

    // Execute: delete repos and remove events
    println!("Executing cleanup...");
    println!();

    let mut deleted_repos = 0usize;
    let mut failed_repos = 0usize;
    let mut deleted_announcements = 0usize;
    let mut deleted_state_events = 0usize;

    for repo in &empty_repos {
        println!("Cleaning up {}/{}...", repo.npub, repo.identifier);

        // 1. Delete the bare repo directory (if it exists)
        if repo.repo_exists {
            match std::fs::remove_dir_all(&repo.repo_path) {
                Ok(()) => {
                    println!("  Deleted git repo: {}", repo.repo_path.display());
                    deleted_repos += 1;

                    // Remove the parent npub directory if now empty
                    if let Some(npub_dir) = repo.repo_path.parent() {
                        if npub_dir.exists() {
                            match std::fs::read_dir(npub_dir) {
                                Ok(mut entries) => {
                                    if entries.next().is_none() {
                                        if let Err(e) = std::fs::remove_dir(npub_dir) {
                                            eprintln!(
                                                "  WARN: Could not remove empty npub dir {}: {}",
                                                npub_dir.display(),
                                                e
                                            );
                                        } else {
                                            println!(
                                                "  Removed empty npub dir: {}",
                                                npub_dir.display()
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "  WARN: Could not read npub dir {}: {}",
                                        npub_dir.display(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "  ERROR: Failed to delete git repo {}: {}",
                        repo.repo_path.display(),
                        e
                    );
                    failed_repos += 1;
                    // Continue — still try to remove the DB events
                }
            }
        }

        // 2. Remove the kind 30617 announcement from the DB
        //    Use a filter matching the specific event ID so we only delete this exact event.
        let announcement_filter = Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .id(repo.announcement.id);

        match database.delete(announcement_filter).await {
            Ok(()) => {
                println!("  Deleted 30617 event: {}", repo.announcement.id.to_hex());
                deleted_announcements += 1;
            }
            Err(e) => {
                eprintln!(
                    "  ERROR: Failed to delete 30617 event {}: {}",
                    repo.announcement.id.to_hex(),
                    e
                );
            }
        }

        // 3. Remove any kind 30618 state events for this coordinate
        if !repo.state_events.is_empty() {
            let state_filter = Filter::new()
                .kind(Kind::RepoState)
                .author(repo.announcement.pubkey)
                .identifier(repo.identifier.clone());

            match database.delete(state_filter).await {
                Ok(()) => {
                    for se in &repo.state_events {
                        println!("  Deleted 30618 event: {}", se.id.to_hex());
                        deleted_state_events += 1;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "  ERROR: Failed to delete 30618 events for {}/{}: {}",
                        repo.npub, repo.identifier, e
                    );
                }
            }
        }
    }

    // --- Execute orphan repo cleanup ---
    let mut deleted_orphan_repos = 0usize;
    let mut skipped_nonempty_orphans = 0usize;

    for repo in &orphan_repos {
        if repo.has_data && !args.purge_orphans {
            println!(
                "SKIP (non-empty, --purge-orphans not set): {}/{} — {}",
                repo.npub,
                repo.dir_name,
                repo.repo_path.display()
            );
            skipped_nonempty_orphans += 1;
            continue;
        }

        println!(
            "Deleting orphan repo {}/{} ({})...",
            repo.npub,
            repo.dir_name,
            if repo.has_data { "non-empty" } else { "empty" }
        );

        match std::fs::remove_dir_all(&repo.repo_path) {
            Ok(()) => {
                println!("  Deleted git repo: {}", repo.repo_path.display());
                deleted_orphan_repos += 1;

                // Remove the parent npub directory if now empty
                if let Some(npub_dir) = repo.repo_path.parent() {
                    if npub_dir.exists() {
                        match std::fs::read_dir(npub_dir) {
                            Ok(mut entries) => {
                                if entries.next().is_none() {
                                    if let Err(e) = std::fs::remove_dir(npub_dir) {
                                        eprintln!(
                                            "  WARN: Could not remove empty npub dir {}: {}",
                                            npub_dir.display(),
                                            e
                                        );
                                    } else {
                                        println!(
                                            "  Removed empty npub dir: {}",
                                            npub_dir.display()
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "  WARN: Could not read npub dir {}: {}",
                                    npub_dir.display(),
                                    e
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "  ERROR: Failed to delete orphan repo {}: {}",
                    repo.repo_path.display(),
                    e
                );
                failed_repos += 1;
            }
        }
    }

    println!();
    println!("=== Cleanup complete ===");
    println!("  Git repos deleted (stale events)  : {}", deleted_repos);
    println!(
        "  Git repos deleted (orphans)        : {}",
        deleted_orphan_repos
    );
    if skipped_nonempty_orphans > 0 {
        println!(
            "  Non-empty orphans skipped          : {} (re-run with --purge-orphans to delete)",
            skipped_nonempty_orphans
        );
    }
    if failed_repos > 0 {
        println!(
            "  Git repos failed                   : {} (see errors above)",
            failed_repos
        );
    }
    println!(
        "  30617 events removed               : {}",
        deleted_announcements
    );
    println!(
        "  30618 events removed               : {}",
        deleted_state_events
    );

    Ok(())
}

/// Scan the git data directory for bare repos that have no matching 30617 event in the DB.
///
/// The expected layout is `<git_data_path>/<npub>/<identifier>.git`.
/// Any directory under `<git_data_path>` that ends in `.git` and has no corresponding
/// 30617 event (matched by pubkey + identifier d-tag) is returned as an orphan.
async fn find_orphan_repos(
    git_data_path: &Path,
    database: &Arc<dyn NostrDatabase>,
) -> Result<Vec<OrphanRepo>> {
    let mut orphans = Vec::new();

    // Iterate npub-level directories
    let npub_entries = match std::fs::read_dir(git_data_path) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(orphans),
        Err(e) => {
            return Err(anyhow::anyhow!(
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
        // Skip the GRASP-06 `/prs/` subtree: it does not follow the
        // `<npub>/<identifier>.git` layout and is not described by 30617
        // announcements, so every repo under it would otherwise look like
        // an orphan to this scan.
        if crate::grasp06::paths::is_prs_repo_path(&npub_path, git_data_path) {
            continue;
        }
        let npub = npub_entry.file_name().to_string_lossy().into_owned();

        // Iterate repo-level directories inside this npub dir
        let repo_entries = match std::fs::read_dir(&npub_path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "  WARN: Could not read npub directory {}: {}",
                    npub_path.display(),
                    e
                );
                continue;
            }
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

            // Derive the identifier (strip .git suffix)
            let identifier = dir_name.strip_suffix(".git").unwrap_or(&dir_name);

            // Check whether a 30617 event exists for this (npub, identifier)
            // We query by identifier d-tag; if the npub is not a valid bech32 pubkey
            // we won't be able to filter by author, so we check the results manually.
            let filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .identifier(identifier.to_string());

            let matching = database
                .query(filter)
                .await
                .with_context(|| format!("Failed to query 30617 for identifier {}", identifier))?;

            // Verify at least one event's owner npub matches the directory name
            let has_event = matching
                .iter()
                .any(|ev| ev.pubkey.to_bech32().map(|n| n == npub).unwrap_or(false));

            if has_event {
                continue;
            }

            let (_, is_empty) = check_repo_empty(&repo_path);
            orphans.push(OrphanRepo {
                repo_path,
                npub: npub.clone(),
                dir_name,
                has_data: !is_empty,
            });
        }
    }

    Ok(orphans)
}

/// Check whether a bare git repository is empty (has no refs).
///
/// Returns `(exists, is_empty)`:
/// - `(false, true)` — path does not exist (treated as empty)
/// - `(true, true)`  — path exists but `git --git-dir=<path> for-each-ref` returns no output
/// - `(true, false)` — path exists and has at least one ref
fn check_repo_empty(repo_path: &Path) -> (bool, bool) {
    if !repo_path.exists() {
        return (false, true);
    }

    // Run `git --git-dir=<path> for-each-ref` — empty output means no refs.
    // --git-dir must be a global option before the subcommand, not an argument to for-each-ref.
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repo_path)
        .args(["for-each-ref", "--format=%(refname)"])
        .output();

    match output {
        Ok(out) => {
            // Trim whitespace; if nothing remains, the repo is empty
            let stdout = String::from_utf8_lossy(&out.stdout);
            let is_empty = stdout.trim().is_empty();
            (true, is_empty)
        }
        Err(_) => {
            // Could not run git — treat as empty to be safe (will be reported)
            (true, true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn find_orphan_repos_skips_prs_subtree() {
        // Layout under <git_data_path>:
        //   prs/<hex>/<id>.git    <-- must be ignored (GRASP-06 endpoint)
        //   <npub-shaped>/<id>.git <-- a real orphan to prove the scan still works
        let tmp = tempdir().expect("tempdir");
        let git_data_path = tmp.path();

        // /prs/<hex>/<id>.git — bare repo so check_repo_empty doesn't complain
        let prs_repo = crate::grasp06::paths::prs_repo_path(
            git_data_path,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "my-pr-repo",
        );
        std::fs::create_dir_all(&prs_repo).expect("mkdir prs repo");
        let init = Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(&prs_repo)
            .status()
            .expect("git init prs repo");
        assert!(init.success(), "git init must succeed for the test fixture");

        // A standard-shaped orphan repo so we can assert the scan still finds
        // real orphans after the /prs/ skip.
        let orphan_owner = "npub1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0000000";
        let orphan_repo = git_data_path.join(orphan_owner).join("standard-orphan.git");
        std::fs::create_dir_all(&orphan_repo).expect("mkdir orphan repo");
        let init = Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(&orphan_repo)
            .status()
            .expect("git init orphan");
        assert!(init.success(), "git init must succeed for the test fixture");

        // Empty LMDB DB so every disk repo is an "orphan" by definition.
        let db_dir = tempdir().expect("tempdir db");
        let database: Arc<dyn NostrDatabase> = Arc::new(
            NostrLmdb::open(db_dir.path())
                .await
                .expect("open empty NostrLmdb"),
        );

        let orphans = find_orphan_repos(git_data_path, &database)
            .await
            .expect("scan succeeds");

        assert!(
            orphans.iter().all(|o| !o
                .repo_path
                .starts_with(prs_repo.parent().unwrap().parent().unwrap())
                || !crate::grasp06::paths::is_prs_repo_path(&o.repo_path, git_data_path)),
            "/prs/ repo must not be reported as orphan: got {:?}",
            orphans
                .iter()
                .map(|o| o.repo_path.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            orphans.iter().any(|o| o.repo_path == orphan_repo),
            "standard orphan must still be detected: got {:?}",
            orphans
                .iter()
                .map(|o| o.repo_path.clone())
                .collect::<Vec<_>>()
        );
    }
}
