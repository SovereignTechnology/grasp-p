use crate::nostr::lifecycle::HoldingStore;
use crate::nostr::lifecycle::ReplaceableHistoryStore;
use crate::nostr::lifecycle::RepositoryLifecycle;
use crate::nostr::lifecycle::Tombstones;
use crate::nostr::SharedDatabase;
use crate::{config::Config, grasp06::receive::RepoInitLocks, purgatory::Purgatory};
use std::path::PathBuf;
use std::sync::Arc;

/// Deletion-specific context wrapper.
///
/// This provides a dedicated module boundary around dependencies used by
/// deletion/vanish handling and deletion gates.
#[derive(Clone)]
pub struct DeletionContext {
    pub domain: String,
    pub database: SharedDatabase,
    pub tombstones: Tombstones,
    pub holding: HoldingStore,
    pub lifecycle: RepositoryLifecycle,
    pub history: ReplaceableHistoryStore,
    pub git_data_path: PathBuf,
    pub purgatory: Arc<Purgatory>,
    pub config: Config,
    pub repo_init_locks: RepoInitLocks,
}

impl DeletionContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: impl Into<String>,
        database: SharedDatabase,
        tombstones: Tombstones,
        holding: HoldingStore,
        lifecycle: RepositoryLifecycle,
        history: ReplaceableHistoryStore,
        git_data_path: impl Into<PathBuf>,
        purgatory: Arc<Purgatory>,
        config: Config,
        repo_init_locks: RepoInitLocks,
    ) -> Self {
        Self {
            domain: domain.into(),
            database,
            tombstones,
            holding,
            lifecycle,
            history,
            git_data_path: git_data_path.into(),
            purgatory,
            config,
            repo_init_locks,
        }
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn database(&self) -> &SharedDatabase {
        &self.database
    }

    pub fn tombstones(&self) -> &Tombstones {
        &self.tombstones
    }

    pub fn holding(&self) -> &HoldingStore {
        &self.holding
    }

    pub fn lifecycle(&self) -> &RepositoryLifecycle {
        &self.lifecycle
    }

    pub fn history(&self) -> &ReplaceableHistoryStore {
        &self.history
    }

    pub fn git_data_path(&self) -> &PathBuf {
        &self.git_data_path
    }

    pub fn purgatory(&self) -> &Arc<Purgatory> {
        &self.purgatory
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn repo_init_locks(&self) -> &RepoInitLocks {
        &self.repo_init_locks
    }
}
