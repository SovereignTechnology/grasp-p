//! Event-driven staging maintenance.
//!
//! Pushes, promotions and ref deletions request maintenance for their view.
//! The persistent registry restores those requests after a restart. A view
//! whose remaining staged objects belong to pending refs is parked until the
//! next request rather than polled.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::{compact, is_staged, registry_dir, Compaction, Record, View};
use crate::git::storage::LocalGitStorage;
use crate::grasp06::receive::{remove_prs_repo_if_empty, RepoInitLocks};

/// How long maintenance queues behind active writers of the family before it
/// gives way. The lease is fair, so waiting longer would hold up later pushes.
const LEASE_WAIT: Duration = Duration::from_millis(250);
const FIRST_RETRY: Duration = Duration::from_secs(1);
const LAST_RETRY: Duration = Duration::from_secs(300);

struct Work {
    due: Instant,
    /// Delay before the attempt after next; doubles on each failure.
    retry: Duration,
}

static QUEUE: LazyLock<Mutex<HashMap<PathBuf, Work>>> = LazyLock::new(Mutex::default);
static WAKE: Notify = Notify::const_new();

fn queue() -> std::sync::MutexGuard<'static, HashMap<PathBuf, Work>> {
    QUEUE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Ask the worker to settle and compact a view. Cheap for unstaged views.
pub fn request_maintenance(view: &Path) {
    if !is_staged(view) {
        return;
    }
    let Ok(view) = std::fs::canonicalize(view) else {
        return;
    };
    queue().insert(
        view,
        Work {
            due: Instant::now(),
            retry: FIRST_RETRY,
        },
    );
    WAKE.notify_waiters();
}

/// Queue every registered view and drop records of views that no longer exist.
fn recover(storage: &LocalGitStorage) -> Result<()> {
    let entries = match std::fs::read_dir(registry_dir(storage)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let result = (|| -> Result<()> {
            let record: Record = serde_json::from_slice(&std::fs::read(&path)?)?;
            anyhow::ensure!(
                !record.view.as_os_str().is_empty()
                    && record
                        .view
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "invalid view path"
            );
            let view = storage.git_data_path().join(&record.view);
            if view.try_exists()? {
                request_maintenance(&view);
            } else {
                std::fs::remove_file(&path)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            tracing::warn!(record = %path.display(), %error, "Cannot recover staged Git view");
        }
    }
    Ok(())
}

/// One maintenance attempt. An error means the attempt should be retried.
pub(super) async fn maintain(view: &Path, prs_locks: &RepoInitLocks) -> Result<Compaction> {
    let Some(resolved) = View::resolve(view)? else {
        return Ok(Compaction::Done);
    };
    let lease = tokio::time::timeout(LEASE_WAIT, resolved.storage.write_lease(&resolved.key))
        .await
        .context("family is busy")??;
    let path = resolved.path.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let _lease = lease;
        compact(&path)
    })
    .await??;
    if outcome == Compaction::Done {
        remove_prs_repo_if_empty(prs_locks, resolved.storage.git_data_path(), &resolved.path);
    }
    Ok(outcome)
}

/// Run staging maintenance until the task is aborted.
pub async fn run_worker(storage: LocalGitStorage, prs_locks: RepoInitLocks) {
    let root = match std::fs::canonicalize(storage.git_data_path()) {
        Ok(root) => root,
        Err(error) => {
            tracing::warn!(%error, "Cannot start staging maintenance");
            return;
        }
    };
    let recovery = storage.clone();
    match tokio::task::spawn_blocking(move || recover(&recovery)).await {
        Ok(Ok(())) => {}
        result => tracing::warn!(?result, "Staging registry recovery failed"),
    }
    loop {
        // Register for wake-ups before reading the queue, so a request made
        // between the read and the wait is not missed.
        let woken = WAKE.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();
        let now = Instant::now();
        let next = {
            let mut queue = queue();
            let next = queue
                .iter()
                .filter(|(view, _)| view.starts_with(&root))
                .min_by_key(|(_, work)| work.due)
                .map(|(view, work)| (view.clone(), work.due, work.retry));
            if let Some((view, due, _)) = &next {
                if *due <= now {
                    queue.remove(view);
                }
            }
            next
        };
        match next {
            Some((view, due, retry)) if due <= now => {
                if !view.exists() {
                    continue;
                }
                if let Err(error) = maintain(&view, &prs_locks).await {
                    tracing::debug!(view = %view.display(), %error, "Staging maintenance will retry");
                    // A request that arrived meanwhile is newer than this failure.
                    queue().entry(view).or_insert(Work {
                        due: Instant::now() + retry,
                        retry: (retry * 2).min(LAST_RETRY),
                    });
                }
            }
            Some((_, due, _)) => {
                tokio::select! {
                    _ = tokio::time::sleep_until(due) => {}
                    _ = woken => {}
                }
            }
            None => woken.await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{commit, delete_reference, reference, Fixture, ABANDONED, PENDING};
    use super::super::{object_exists, stage};
    use super::*;
    use crate::grasp06::receive::new_repo_init_locks;

    const DEADLINE: Duration = Duration::from_secs(10);

    async fn wait_until(description: &str, condition: impl Fn() -> bool) {
        tokio::time::timeout(DEADLINE, async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {description}"));
    }

    #[tokio::test]
    async fn ref_deletion_wakes_the_worker_to_reclaim_an_abandoned_upload() {
        let fixture = Fixture::new();
        stage(&fixture.view, &[]).unwrap();
        let pending = commit(&fixture.view, "pending", None);
        let abandoned = commit(&fixture.view, "abandoned", None);
        reference(&fixture.view, PENDING, &pending);
        reference(&fixture.view, ABANDONED, &abandoned);
        let worker = tokio::spawn(run_worker(fixture.storage.clone(), new_repo_init_locks()));

        crate::git::delete_ref(&fixture.view, ABANDONED).unwrap();

        let view = fixture.view.clone();
        wait_until("the abandoned upload to be reclaimed", || {
            !object_exists(&view, &abandoned).unwrap()
        })
        .await;
        assert!(object_exists(&fixture.view, &pending).unwrap());
        assert!(is_staged(&fixture.view), "a pending upload stays staged");
        worker.abort();
    }

    #[tokio::test]
    async fn restart_recovers_a_view_registered_before_it() {
        let fixture = Fixture::new();
        stage(&fixture.view, &[]).unwrap();
        let abandoned = commit(&fixture.view, "abandoned", None);
        reference(&fixture.view, ABANDONED, &abandoned);
        // The ref expired without a maintenance request, as after a crash.
        delete_reference(&fixture.view, ABANDONED);

        let worker = tokio::spawn(run_worker(fixture.storage.clone(), new_repo_init_locks()));

        let view = fixture.view.clone();
        wait_until("the recovered view to be reclaimed", || !is_staged(&view)).await;
        assert!(!object_exists(&fixture.view, &abandoned).unwrap());
        worker.abort();
    }

    #[tokio::test]
    async fn maintenance_gives_way_to_a_busy_family_and_succeeds_later() {
        let fixture = Fixture::new();
        stage(&fixture.view, &[]).unwrap();
        let abandoned = commit(&fixture.view, "abandoned", None);
        let locks = new_repo_init_locks();

        // A push holds the family lease for as long as it runs.
        let push = fixture.storage.write_lease(&fixture.key).await.unwrap();
        assert!(maintain(&fixture.view, &locks).await.is_err());
        assert!(object_exists(&fixture.view, &abandoned).unwrap());

        drop(push);
        assert_eq!(
            maintain(&fixture.view, &locks).await.unwrap(),
            Compaction::Done
        );
        assert!(!object_exists(&fixture.view, &abandoned).unwrap());
    }

    #[tokio::test]
    async fn empty_prs_repository_is_removed_once_its_staging_is_reclaimed() {
        let submitter = "a".repeat(64);
        let fixture = Fixture::with_view(&format!("prs/{submitter}"));
        stage(&fixture.view, &[]).unwrap();
        commit(&fixture.view, "abandoned", None);

        let outcome = maintain(&fixture.view, &new_repo_init_locks()).await;

        assert_eq!(outcome.unwrap(), Compaction::Done);
        assert!(!fixture.view.exists());
    }
}
