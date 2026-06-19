use crate::nostr::history::ReplaceableHistoryStore;
use crate::nostr::holding::HoldingStore;
use crate::nostr::policy::PolicyContext;
use crate::nostr::tombstones::Tombstones;
use crate::nostr::SharedDatabase;
use crate::{config::Config, grasp06::receive::RepoInitLocks, purgatory::Purgatory};
use std::path::PathBuf;
use std::sync::Arc;

/// Deletion-specific context wrapper.
///
/// This provides a dedicated module boundary around dependencies used by
/// deletion/vanish handling, repository lifecycle locking, and deletion gates.
#[derive(Clone)]
pub struct DeletionContext {
    pub domain: String,
    pub database: SharedDatabase,
    pub tombstones: Tombstones,
    pub holding: HoldingStore,
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
            history,
            git_data_path: git_data_path.into(),
            purgatory,
            config,
            repo_init_locks,
        }
    }

    pub fn from_policy_context(policy_ctx: &PolicyContext) -> Self {
        Self {
            domain: policy_ctx.domain.clone(),
            database: policy_ctx.database.clone(),
            tombstones: policy_ctx.tombstones.clone(),
            holding: policy_ctx.holding.clone(),
            history: policy_ctx.history.clone(),
            git_data_path: policy_ctx.git_data_path.clone(),
            purgatory: policy_ctx.purgatory.clone(),
            config: policy_ctx.config.clone(),
            repo_init_locks: policy_ctx.repo_init_locks.clone(),
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

impl From<PolicyContext> for DeletionContext {
    fn from(policy_ctx: PolicyContext) -> Self {
        Self::from_policy_context(&policy_ctx)
    }
}
