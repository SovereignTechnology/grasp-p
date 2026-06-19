//! Repository lifecycle locking facade.
//!
//! Git Smart HTTP serving, deletion, recovery, holding cleanup, and manual
//! ejection all coordinate through the same per-repository lifecycle lock. The
//! concrete lock storage currently lives in [`HoldingStore`], but callers depend
//! on this facade so lifecycle coordination is not exposed as a deletion/write
//! policy concern.

use crate::nostr::holding::{HoldingStore, LifecycleReadGuard, LifecycleWriteGuard, RecoveryScope};

#[derive(Clone, Debug)]
pub struct RepositoryLifecycle {
    holding: HoldingStore,
}

impl RepositoryLifecycle {
    pub fn new(holding: HoldingStore) -> Self {
        Self { holding }
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
        self.holding
            .read_recovery_scope(owner_pubkey_hex, identifier)
            .await
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
        self.holding
            .write_recovery_scope(owner_pubkey_hex, identifier)
            .await
    }

    /// Acquire exclusive lifecycle locks for multiple repository scopes in a
    /// stable order to avoid deadlocks.
    pub async fn write_repositories(
        &self,
        scopes: impl IntoIterator<Item = RecoveryScope>,
    ) -> Vec<LifecycleWriteGuard> {
        self.holding.write_recovery_scopes(scopes).await
    }
}
