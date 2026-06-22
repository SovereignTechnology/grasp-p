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

pub use context::DeletionContext;
pub use policy::DeletionPolicy;
pub use runtime::{run_holding_eject, DeletionCleanupTask, DeletionRuntime, HoldingEjectArgs};
pub use service::DeletionService;
pub use startup::{
    BlacklistParityStats, BlacklistRestoreStats, StartupReconciliationStats, WhitelistParityStats,
    WhitelistRestoreStats,
};

pub use cascade::{build_event_graph, EventGraph, EventNode};
pub use cascade::{reevaluate_events_without_announcement, ReevaluationResult, RetentionReason};
pub use cascade::{traverse_and_mark_deletions, CircularDependency, TraversalResult};
