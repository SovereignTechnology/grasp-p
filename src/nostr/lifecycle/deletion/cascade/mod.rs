//! Announcement cascade deletion implementation.
//!
//! `orchestration` contains the production NIP-09/blacklist/whitelist cascade
//! algorithm. The `graph`, `reevaluation`, and `traversal` modules are legacy
//! reconciliation helpers retained for `cleanup-empty-repos`; their tests cover
//! that offline reconciliation behavior, not the live deletion cascade.

mod graph;
mod orchestration;
mod reevaluation;
mod traversal;

pub use graph::{build_event_graph, EventGraph, EventNode};
pub use reevaluation::{
    reevaluate_events_without_announcement, ReevaluationResult, RetentionReason,
};
pub use traversal::{traverse_and_mark_deletions, CircularDependency, TraversalResult};
