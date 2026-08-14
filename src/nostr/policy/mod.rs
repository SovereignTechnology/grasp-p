/// Policy module for NIP-34 write policies
///
/// This module splits the large Nip34WritePolicy into focused sub-policies:
/// - `AnnouncementPolicy` - Repository announcement validation
/// - `StatePolicy` - State event validation + ref alignment
/// - `PrEventPolicy` - PR/PR Update validation
/// - `RelatedEventPolicy` - Forward/backward reference checking
/// - Deletion handling lives in `crate::nostr::lifecycle`
mod announcement;
mod identity;
mod pr_event;
mod related;
mod result;
mod state;

pub(crate) use result::{
    accepted_purgatory, duplicate, reject_error, reject_invalid, reject_restricted,
};

pub use announcement::{AnnouncementPolicy, AnnouncementResult};
pub use identity::{
    IdentityAdmission, ProactiveParticipantAuthorIndex, SharedProactiveParticipantAuthorIndex,
};
pub use pr_event::PrEventPolicy;
pub use related::{ReferenceResult, RelatedEventPolicy};
pub use state::{StatePolicy, StateResult};

// Re-export AlignmentResult from git::sync (canonical location)
pub use crate::git::sync::AlignmentResult;

use super::SharedDatabase;
use crate::purgatory::Purgatory;
use nostr_sdk::local_relay::LocalRelay;
use std::sync::Arc;

/// Shared context for all sub-policies
#[derive(Clone)]
pub struct PolicyContext {
    pub domain: String,
    pub database: SharedDatabase,
    pub git_data_path: std::path::PathBuf,
    pub purgatory: Arc<Purgatory>,
    /// Local relay for notifying WebSocket subscribers (set after relay creation)
    pub local_relay: Arc<std::sync::RwLock<Option<LocalRelay>>>,
    /// Configuration reference for policy settings (includes blacklists)
    pub config: crate::config::Config,
}

impl PolicyContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: impl Into<String>,
        database: SharedDatabase,
        git_data_path: impl Into<std::path::PathBuf>,
        purgatory: Arc<Purgatory>,
        config: crate::config::Config,
    ) -> Self {
        Self {
            domain: domain.into(),
            database,
            git_data_path: git_data_path.into(),
            purgatory,
            local_relay: Arc::new(std::sync::RwLock::new(None)),
            config,
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
        Self::new(domain, database, git_data_path, purgatory, config)
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
