//! Repository lifecycle locking and runtime state.
//!
//! Git Smart HTTP serving, deletion, recovery, holding cleanup, and manual
//! ejection all coordinate through the same per-repository lifecycle lock. The
//! lock storage is owned here so repository runtime coordination is not coupled
//! to holding/deletion storage.

use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use fs2::FileExt;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock as AsyncRwLock};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct RecoveryScope {
    pub owner_pubkey_hex: String,
    pub identifier: String,
}

pub struct LifecycleReadGuard {
    _memory_guard: OwnedRwLockReadGuard<()>,
}

pub struct LifecycleWriteGuard {
    _memory_guard: OwnedRwLockWriteGuard<()>,
    _lock_file: Option<File>,
}

#[derive(Clone, Debug)]
pub struct RepositoryLifecycleLocks {
    /// Shared per-repository lifecycle read/write locks.
    ///
    /// Lock ordering invariant for deletion/recovery/cleanup paths: acquire all
    /// required `(owner_pubkey_hex, identifier)` lifecycle locks first (sorted
    /// lexicographically), then touch main DB / tombstones / holding DB /
    /// repository filesystem / archive filesystem. Never acquire a lifecycle
    /// lock while holding a lower-level lock or a purgatory map entry reference.
    /// A matching lock file under `.lifecycle-locks/` extends the invariant to
    /// short-lived CLI write operations such as `holding-eject`, which run in a
    /// separate process and cannot share this in-memory map. Read-side Git Smart
    /// HTTP operations share the in-memory read lock only, while write-side
    /// operations also take an advisory lock on an open lock file. The lock file
    /// is intentionally left in place; only the advisory lock matters, and the
    /// OS releases it automatically if the process dies.
    locks: Arc<DashMap<RecoveryScope, Arc<AsyncRwLock<()>>>>,
    lock_dir: Option<PathBuf>,
}

impl RepositoryLifecycleLocks {
    pub fn in_memory() -> Self {
        Self {
            locks: Arc::new(DashMap::new()),
            lock_dir: None,
        }
    }

    pub fn for_git_data_path(git_data_path: &Path) -> Self {
        Self {
            locks: Arc::new(DashMap::new()),
            lock_dir: Some(git_data_path.join(".lifecycle-locks")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RepositoryLifecycle {
    locks: RepositoryLifecycleLocks,
}

impl RepositoryLifecycle {
    pub fn new(locks: RepositoryLifecycleLocks) -> Self {
        Self { locks }
    }

    pub fn in_memory() -> Self {
        Self::new(RepositoryLifecycleLocks::in_memory())
    }

    pub fn for_git_data_path(git_data_path: &Path) -> Self {
        Self::new(RepositoryLifecycleLocks::for_git_data_path(git_data_path))
    }

    /// Acquire a shared repository lifecycle lock used by Git Smart HTTP
    /// operations (`info/refs`, `git-upload-pack`, and `git-receive-pack`).
    ///
    /// The lifecycle lock protects repository existence/replacement/removal;
    /// Git's own internal locking handles concurrent push/fetch ref and object
    /// consistency.
    pub async fn read_repository(
        &self,
        owner_pubkey_hex: &str,
        identifier: &str,
    ) -> LifecycleReadGuard {
        let scope = RecoveryScope {
            owner_pubkey_hex: owner_pubkey_hex.to_string(),
            identifier: identifier.to_string(),
        };
        let lock = self
            .locks
            .locks
            .entry(scope)
            .or_insert_with(|| Arc::new(AsyncRwLock::new(())))
            .value()
            .clone();
        LifecycleReadGuard {
            _memory_guard: lock.read_owned().await,
        }
    }

    /// Acquire an exclusive repository lifecycle lock used by deletion,
    /// recovery, holding cleanup, and manual ejection.
    ///
    /// Callers must take this before mutating the main DB / tombstones / holding
    /// DB / archive files / bare repository filesystem for a specific
    /// `(owner_pubkey_hex, identifier)` scope. It is intentionally per-repo (not
    /// global) so unrelated repositories keep operating concurrently.
    pub async fn write_repository(
        &self,
        owner_pubkey_hex: &str,
        identifier: &str,
    ) -> LifecycleWriteGuard {
        self.write_repositories(vec![RecoveryScope {
            owner_pubkey_hex: owner_pubkey_hex.to_string(),
            identifier: identifier.to_string(),
        }])
        .await
        .pop()
        .expect("single lifecycle lock requested")
    }

    /// Acquire exclusive lifecycle locks for multiple repository scopes in a
    /// stable order to avoid deadlocks.
    pub async fn write_repositories(
        &self,
        scopes: impl IntoIterator<Item = RecoveryScope>,
    ) -> Vec<LifecycleWriteGuard> {
        let mut scopes: Vec<_> = scopes.into_iter().collect();
        scopes.sort();
        scopes.dedup();

        let mut guards = Vec::with_capacity(scopes.len());
        for scope in scopes {
            let lock = self
                .locks
                .locks
                .entry(scope.clone())
                .or_insert_with(|| Arc::new(AsyncRwLock::new(())))
                .value()
                .clone();
            let memory_guard = lock.write_owned().await;
            let lock_file = self.acquire_scope_file_lock(&scope).await;
            guards.push(LifecycleWriteGuard {
                _memory_guard: memory_guard,
                _lock_file: lock_file,
            });
        }
        guards
    }

    async fn acquire_scope_file_lock(&self, scope: &RecoveryScope) -> Option<File> {
        let lock_dir = self.locks.lock_dir.as_ref()?;
        if let Err(e) = std::fs::create_dir_all(lock_dir) {
            tracing::warn!(path = %lock_dir.display(), error = %e, "Failed to create lifecycle lock directory");
            return None;
        }

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        scope.hash(&mut hasher);
        let lock_path = lock_dir.join(format!("{:016x}.lock", hasher.finish()));

        loop {
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
            {
                Ok(file) => file,
                Err(e) => {
                    tracing::warn!(
                        owner = %scope.owner_pubkey_hex,
                        identifier = %scope.identifier,
                        path = %lock_path.display(),
                        error = %e,
                        "Failed to open lifecycle lock file; continuing with in-process lock only"
                    );
                    return None;
                }
            };

            match file.try_lock_exclusive() {
                Ok(()) => return Some(file),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(e) => {
                    tracing::warn!(
                        owner = %scope.owner_pubkey_hex,
                        identifier = %scope.identifier,
                        path = %lock_path.display(),
                        error = %e,
                        "Failed to lock lifecycle lock file; continuing with in-process lock only"
                    );
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_relay_builder::prelude::Keys;

    #[tokio::test]
    async fn lifecycle_read_locks_can_be_held_concurrently() {
        let lifecycle = RepositoryLifecycle::in_memory();
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "popular-repo";

        let first_guard = lifecycle.read_repository(&owner_hex, identifier).await;
        let second_guard = tokio::time::timeout(
            Duration::from_millis(100),
            lifecycle.read_repository(&owner_hex, identifier),
        )
        .await
        .expect("second read lock should not wait behind first read lock");

        drop(second_guard);
        drop(first_guard);
    }

    #[tokio::test]
    async fn lifecycle_push_and_fetch_read_locks_can_overlap() {
        let lifecycle = RepositoryLifecycle::in_memory();
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "push-fetch-overlap";

        let push_guard = lifecycle.read_repository(&owner_hex, identifier).await;
        let fetch_guard = tokio::time::timeout(
            Duration::from_millis(100),
            lifecycle.read_repository(&owner_hex, identifier),
        )
        .await
        .expect("fetch lifecycle read lock should not wait behind push lifecycle read lock");

        drop(fetch_guard);
        drop(push_guard);
    }

    #[tokio::test]
    async fn lifecycle_write_lock_waits_for_active_read_lock() {
        let lifecycle = RepositoryLifecycle::in_memory();
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "read-before-delete";

        let read_guard = lifecycle.read_repository(&owner_hex, identifier).await;
        let writer_lifecycle = lifecycle.clone();
        let writer_owner = owner_hex.clone();
        let writer_identifier = identifier.to_string();
        let (writer_acquired_tx, writer_acquired_rx) = tokio::sync::oneshot::channel();

        let writer = tokio::spawn(async move {
            let guard = writer_lifecycle
                .write_repository(&writer_owner, &writer_identifier)
                .await;
            let _ = writer_acquired_tx.send(());
            guard
        });

        tokio::time::timeout(Duration::from_millis(100), writer_acquired_rx)
            .await
            .expect_err("write lock should wait while read lock is active");

        drop(read_guard);
        let write_guard = tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("write lock should acquire after read lock drops")
            .expect("writer task should join");
        drop(write_guard);
    }

    #[tokio::test]
    async fn lifecycle_queued_write_blocks_new_read_lock() {
        let lifecycle = RepositoryLifecycle::in_memory();
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "delete-waits-fairly";

        let first_read_guard = lifecycle.read_repository(&owner_hex, identifier).await;

        let writer_lifecycle = lifecycle.clone();
        let writer_owner = owner_hex.clone();
        let writer_identifier = identifier.to_string();
        let (writer_started_tx, writer_started_rx) = tokio::sync::oneshot::channel();
        let (writer_acquired_tx, writer_acquired_rx) = tokio::sync::oneshot::channel();
        let (release_writer_tx, release_writer_rx) = tokio::sync::oneshot::channel();

        let writer = tokio::spawn(async move {
            let _ = writer_started_tx.send(());
            let guard = writer_lifecycle
                .write_repository(&writer_owner, &writer_identifier)
                .await;
            let _ = writer_acquired_tx.send(());
            let _ = release_writer_rx.await;
            drop(guard);
        });

        writer_started_rx
            .await
            .expect("writer task should start before second reader");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let reader_lifecycle = lifecycle.clone();
        let reader_owner = owner_hex.clone();
        let reader_identifier = identifier.to_string();
        let (second_read_acquired_tx, second_read_acquired_rx) = tokio::sync::oneshot::channel();
        let second_reader = tokio::spawn(async move {
            let guard = reader_lifecycle
                .read_repository(&reader_owner, &reader_identifier)
                .await;
            let _ = second_read_acquired_tx.send(());
            guard
        });

        tokio::time::timeout(Duration::from_millis(100), second_read_acquired_rx)
            .await
            .expect_err("new read lock should wait behind queued writer");

        drop(first_read_guard);
        tokio::time::timeout(Duration::from_secs(1), writer_acquired_rx)
            .await
            .expect("writer should acquire after active reader drops")
            .expect("writer should report acquisition");

        let _ = release_writer_tx.send(());
        writer.await.expect("writer task should join");
        let second_read_guard = tokio::time::timeout(Duration::from_secs(1), second_reader)
            .await
            .expect("second read should acquire after writer releases")
            .expect("second reader task should join");
        drop(second_read_guard);
    }

    #[tokio::test]
    async fn lifecycle_write_lock_ignores_stale_lock_file() {
        let git_data_dir = tempfile::tempdir().expect("temp git data dir");
        let lifecycle = RepositoryLifecycle::for_git_data_path(git_data_dir.path());
        let owner_hex = Keys::generate().public_key().to_hex();
        let identifier = "stale-lock-file";
        let scope = RecoveryScope {
            owner_pubkey_hex: owner_hex.clone(),
            identifier: identifier.to_string(),
        };

        let lock_dir = git_data_dir.path().join(".lifecycle-locks");
        std::fs::create_dir_all(&lock_dir).expect("create lock dir");
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        scope.hash(&mut hasher);
        let lock_path = lock_dir.join(format!("{:016x}.lock", hasher.finish()));
        std::fs::write(&lock_path, b"stale process died before cleanup")
            .expect("create stale lock file");

        let write_guard = tokio::time::timeout(
            Duration::from_millis(100),
            lifecycle.write_repository(&owner_hex, identifier),
        )
        .await
        .expect("stale lock file should not block advisory lock acquisition");
        drop(write_guard);

        assert!(
            lock_path.exists(),
            "advisory lock files remain in place so file existence cannot become a stale lock"
        );
    }
}
