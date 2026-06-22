mod archival;
mod cascade;
mod context;
pub mod graph;
mod policy;
mod pr_refs;
mod purgatory;
mod recovery;
pub mod reevaluation;
mod rollback;
mod runtime;
mod service;
mod startup;
pub mod traversal;

pub use context::DeletionContext;
pub use policy::DeletionPolicy;
pub use runtime::{run_holding_eject, DeletionCleanupTask, DeletionRuntime, HoldingEjectArgs};
pub use service::DeletionService;
pub use startup::{
    BlacklistParityStats, BlacklistRestoreStats, StartupReconciliationStats, WhitelistParityStats,
    WhitelistRestoreStats,
};

pub use graph::{build_event_graph, EventGraph, EventNode};
pub use reevaluation::{
    reevaluate_events_without_announcement, ReevaluationResult, RetentionReason,
};
pub use traversal::{traverse_and_mark_deletions, CircularDependency, TraversalResult};
