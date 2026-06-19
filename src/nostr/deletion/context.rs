use crate::nostr::builder::SharedDatabase;
use crate::nostr::history::ReplaceableHistoryStore;
use crate::nostr::holding::HoldingStore;
use crate::nostr::policy::PolicyContext;
use crate::nostr::tombstones::Tombstones;
use crate::{config::Config, grasp06::receive::RepoInitLocks, purgatory::Purgatory};
use std::path::PathBuf;
use std::sync::Arc;

/// Deletion-specific context wrapper.
///
/// This provides a dedicated module boundary around dependencies used by
/// deletion/vanish handling, repository lifecycle locking, and deletion gates.
#[derive(Clone)]
pub struct DeletionContext {
    policy_ctx: PolicyContext,
}

impl DeletionContext {
    pub fn from_policy_context(policy_ctx: PolicyContext) -> Self {
        Self { policy_ctx }
    }

    pub fn policy_context(&self) -> &PolicyContext {
        &self.policy_ctx
    }

    pub fn domain(&self) -> &str {
        &self.policy_ctx.domain
    }

    pub fn database(&self) -> &SharedDatabase {
        &self.policy_ctx.database
    }

    pub fn tombstones(&self) -> &Tombstones {
        &self.policy_ctx.tombstones
    }

    pub fn holding(&self) -> &HoldingStore {
        &self.policy_ctx.holding
    }

    pub fn history(&self) -> &ReplaceableHistoryStore {
        &self.policy_ctx.history
    }

    pub fn git_data_path(&self) -> &PathBuf {
        &self.policy_ctx.git_data_path
    }

    pub fn purgatory(&self) -> &Arc<Purgatory> {
        &self.policy_ctx.purgatory
    }

    pub fn config(&self) -> &Config {
        &self.policy_ctx.config
    }

    pub fn repo_init_locks(&self) -> &RepoInitLocks {
        &self.policy_ctx.repo_init_locks
    }
}
