//! Audit Event Cleanup
//!
//! Background job that periodically removes grasp-audit test events and their
//! associated git repositories from the relay.
//!
//! The grasp-audit tool tags every event it creates with:
//!   `["t", "grasp-audit-test-event"]`
//!
//! This job:
//! 1. Queries kind 30617 (repo announcement) events tagged "grasp-audit-test-event"
//!    that are older than `AUDIT_CLEANUP_AGE_SECS` seconds.
//! 2. Deletes the corresponding bare git repositories from disk.
//! 3. Deletes all events tagged "grasp-audit-test-event" older than the threshold
//!    from the Nostr database.
//!
//! Runs every `AUDIT_CLEANUP_INTERVAL_SECS` seconds.

use std::path::{Path, PathBuf};
use std::time::Duration;

use nostr_sdk::prelude::*;
use tracing::{debug, error, info, warn};

use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::SharedDatabase;

/// How old an audit event must be before it is eligible for deletion (2 hours).
const AUDIT_CLEANUP_AGE_SECS: u64 = 2 * 3600;

/// How often the cleanup job runs (30 minutes).
const AUDIT_CLEANUP_INTERVAL_SECS: u64 = 30 * 60;

/// The hashtag used by grasp-audit to mark all test events.
const AUDIT_TEST_EVENT_TAG: &str = "grasp-audit-test-event";

/// Run the audit cleanup loop indefinitely.
///
/// Spawned as a background tokio task in `main.rs`.
pub async fn run_audit_cleanup_loop(database: SharedDatabase, git_data_path: PathBuf) {
    // Use an interval that fires immediately on the first tick, then every 30 minutes.
    let mut interval = tokio::time::interval(Duration::from_secs(AUDIT_CLEANUP_INTERVAL_SECS));
    loop {
        interval.tick().await;
        run_audit_cleanup_once(&database, &git_data_path).await;
    }
}

/// Perform a single cleanup pass.
async fn run_audit_cleanup_once(database: &SharedDatabase, git_data_path: &Path) {
    let cutoff = Timestamp::from(
        Timestamp::now()
            .as_secs()
            .saturating_sub(AUDIT_CLEANUP_AGE_SECS),
    );

    // --- Step 1: Find repo announcements to delete git repos for ---
    let repo_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .hashtag(AUDIT_TEST_EVENT_TAG)
        .until(cutoff);

    let repo_events = match database.query(repo_filter).await {
        Ok(events) => events,
        Err(e) => {
            error!("audit_cleanup: failed to query repo announcements: {}", e);
            return;
        }
    };

    let mut repos_deleted = 0usize;
    let mut repos_failed = 0usize;

    for event in repo_events.iter() {
        match RepositoryAnnouncement::from_event(event.clone()) {
            Ok(announcement) => {
                let repo_path = git_data_path.join(announcement.repo_path());
                if repo_path.exists() {
                    match std::fs::remove_dir_all(&repo_path) {
                        Ok(()) => {
                            debug!("audit_cleanup: deleted git repo {}", repo_path.display());
                            repos_deleted += 1;

                            // Remove the parent npub directory if it is now empty
                            if let Some(npub_dir) = repo_path.parent() {
                                if npub_dir.exists() {
                                    match std::fs::read_dir(npub_dir) {
                                        Ok(mut entries) => {
                                            if entries.next().is_none() {
                                                if let Err(e) = std::fs::remove_dir(npub_dir) {
                                                    warn!(
                                                        "audit_cleanup: could not remove empty npub dir {}: {}",
                                                        npub_dir.display(),
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(
                                                "audit_cleanup: could not read npub dir {}: {}",
                                                npub_dir.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "audit_cleanup: failed to delete git repo {}: {}",
                                repo_path.display(),
                                e
                            );
                            repos_failed += 1;
                        }
                    }
                } else {
                    debug!(
                        "audit_cleanup: git repo already absent: {}",
                        repo_path.display()
                    );
                }
            }
            Err(e) => {
                warn!(
                    "audit_cleanup: could not parse repo announcement {}: {}",
                    event.id, e
                );
            }
        }
    }

    // --- Step 2: Delete all audit events from the database ---
    let all_audit_filter = Filter::new().hashtag(AUDIT_TEST_EVENT_TAG).until(cutoff);

    match database.delete(all_audit_filter).await {
        Ok(()) => {
            info!(
                "audit_cleanup: deleted audit events older than {}s; git repos deleted={}, failed={}",
                AUDIT_CLEANUP_AGE_SECS, repos_deleted, repos_failed
            );
        }
        Err(e) => {
            error!(
                "audit_cleanup: failed to delete audit events from database: {}",
                e
            );
        }
    }
}
