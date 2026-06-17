/// Policy module for NIP-34 write policies
///
/// This module splits the large Nip34WritePolicy into focused sub-policies:
/// - `AnnouncementPolicy` - Repository announcement validation
/// - `StatePolicy` - State event validation + ref alignment
/// - `PrEventPolicy` - PR/PR Update validation
/// - `RelatedEventPolicy` - Forward/backward reference checking
mod announcement;
mod deletion;
mod pr_event;
mod related;
mod result;
mod state;

// Multi-maintainer cascade deletion: dependency graph + retention re-evaluation
// + reachability traversal. These are pure algorithm modules (graph/traversal
// have no DB dependency; reevaluation queries the shared database) and carry
// their own unit tests. They are the building blocks for graph-based cascade
// deletion of repository announcements.
mod graph;
mod reevaluation;
mod traversal;

pub(crate) use result::{
    accepted_purgatory, duplicate, reject_error, reject_invalid, reject_restricted,
};

pub use announcement::{AnnouncementPolicy, AnnouncementResult};
pub use deletion::DeletionPolicy;
pub use pr_event::PrEventPolicy;
pub use related::{ReferenceResult, RelatedEventPolicy};
pub use state::{StatePolicy, StateResult};

// Cascade-deletion graph algorithm exports (used by the deletion policy when it
// is wired up to perform graph-based cascade; re-exported here so sibling
// modules can refer to them via `super::`).
pub use graph::{build_event_graph, EventGraph, EventNode};
pub use reevaluation::{
    reevaluate_events_without_announcement, ReevaluationResult, RetentionReason,
};
pub use traversal::{traverse_and_mark_deletions, CircularDependency, TraversalResult};

// Re-export AlignmentResult from git::sync (canonical location)
pub use crate::git::sync::AlignmentResult;

use super::SharedDatabase;
#[cfg(test)]
use crate::grasp06::receive::new_repo_init_locks;
use crate::grasp06::receive::RepoInitLocks;
use crate::nostr::history::ReplaceableHistoryStore;
use crate::nostr::holding::HoldingStore;
use crate::nostr::tombstones::Tombstones;
use crate::purgatory::Purgatory;
use nostr_relay_builder::LocalRelay;
use std::sync::Arc;

/// Shared context for all sub-policies
#[derive(Clone)]
pub struct PolicyContext {
    pub domain: String,
    pub database: SharedDatabase,
    /// Persistent record of NIP-09 deletions and NIP-62 vanish requests.
    ///
    /// Since the LMDB backend no longer auto-processes NIP-09/NIP-62
    /// (`process_nip09(false)` / `process_nip62(false)`), ngit-grasp owns the
    /// deletion/vanish bookkeeping. This store persists deletion/vanish requests
    /// so re-submission of a deleted event (or an event from a vanished pubkey)
    /// is still rejected, surviving restarts.
    pub tombstones: Tombstones,
    /// Holding DB for events moved out of main DB by deletion flows.
    pub holding: HoldingStore,
    /// Durable rollback history for superseded replaceable/addressable events.
    pub history: ReplaceableHistoryStore,
    pub git_data_path: std::path::PathBuf,
    pub purgatory: Arc<Purgatory>,
    /// Local relay for notifying WebSocket subscribers (set after relay creation)
    pub local_relay: Arc<std::sync::RwLock<Option<LocalRelay>>>,
    /// Configuration reference for policy settings (includes blacklists)
    pub config: crate::config::Config,
    /// Per-path locks shared with the GRASP-06 `/prs/` receive handler so
    /// validation paths that may delete a `/prs/` bare repo serialise
    /// against in-flight pushes to the same `(submitter, identifier)`.
    pub repo_init_locks: RepoInitLocks,
}

impl PolicyContext {
    pub fn new(
        domain: impl Into<String>,
        database: SharedDatabase,
        tombstones: Tombstones,
        holding: HoldingStore,
        history: ReplaceableHistoryStore,
        git_data_path: impl Into<std::path::PathBuf>,
        purgatory: Arc<Purgatory>,
        config: crate::config::Config,
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
            local_relay: Arc::new(std::sync::RwLock::new(None)),
            config,
            repo_init_locks,
        }
    }

    /// Construct a [`PolicyContext`] with a fresh, isolated [`RepoInitLocks`]
    /// map. Intended for unit tests that exercise policy logic without a
    /// running HTTP server.
    #[cfg(test)]
    pub fn new_for_test(
        domain: impl Into<String>,
        database: SharedDatabase,
        git_data_path: impl Into<std::path::PathBuf>,
        purgatory: Arc<Purgatory>,
        config: crate::config::Config,
    ) -> Self {
        Self::new(
            domain,
            database,
            Tombstones::in_memory(),
            HoldingStore::in_memory(),
            ReplaceableHistoryStore::in_memory(),
            git_data_path,
            purgatory,
            config,
            new_repo_init_locks(),
        )
    }

    /// Set the local relay after it's been created.
    ///
    /// This is called after the relay is built since the relay depends on the policy
    /// but the policy needs the relay for purgatory notifications.
    pub fn set_local_relay(&self, relay: LocalRelay) {
        let mut guard = self.local_relay.write().unwrap();
        *guard = Some(relay);
    }

    /// Get a clone of the local relay if it's been set.
    pub fn get_local_relay(&self) -> Option<LocalRelay> {
        let guard = self.local_relay.read().unwrap();
        guard.clone()
    }
}
