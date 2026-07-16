mod archival;
mod cascade;
mod context;
mod policy;
mod pr_refs;
mod purgatory;
mod recovery;
mod rollback;
mod runtime;
mod service;
mod startup;

/// Measured result of destructive deletion work.
///
/// Only the two successful removal counters make a deletion request "used".
/// `skipped` and `failures` are diagnostic counters for fail-safe preservation
/// and unsuccessful database/filesystem operations respectively.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DeletionOutcome {
    pub main_db_deleted: usize,
    pub purgatory_removed: usize,
    pub skipped: usize,
    pub failures: usize,
}

impl DeletionOutcome {
    pub(crate) fn removed_events(self) -> usize {
        self.main_db_deleted.saturating_add(self.purgatory_removed)
    }

    pub(crate) fn used(self) -> bool {
        self.removed_events() > 0
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.main_db_deleted = self.main_db_deleted.saturating_add(other.main_db_deleted);
        self.purgatory_removed = self
            .purgatory_removed
            .saturating_add(other.purgatory_removed);
        self.skipped = self.skipped.saturating_add(other.skipped);
        self.failures = self.failures.saturating_add(other.failures);
    }
}

pub use context::DeletionContext;
pub use policy::DeletionPolicy;
pub use runtime::{run_holding_eject, DeletionCleanupTask, DeletionRuntime, HoldingEjectArgs};
pub use service::DeletionService;
pub use startup::{
    BlacklistParityStats, BlacklistRestoreStats, RequestLifecycleStartupStats,
    StartupReconciliationStats, WhitelistParityStats, WhitelistRestoreStats,
};

#[cfg(test)]
mod tests {
    use super::DeletionOutcome;

    #[test]
    fn outcome_merge_is_saturating_and_only_removals_are_use() {
        let mut outcome = DeletionOutcome {
            skipped: usize::MAX,
            failures: 1,
            ..Default::default()
        };
        outcome.merge(DeletionOutcome {
            main_db_deleted: 1,
            purgatory_removed: 2,
            skipped: 1,
            failures: 2,
        });
        assert_eq!(outcome.removed_events(), 3);
        assert!(outcome.used());
        assert_eq!(outcome.skipped, usize::MAX);
        assert_eq!(outcome.failures, 3);
        assert!(!DeletionOutcome {
            skipped: 1,
            failures: 1,
            ..Default::default()
        }
        .used());
    }
}
