//! Core data types for the purgatory system.
//!
//! Purgatory is an in-memory holding area for nostr events that depend on git data
//! that hasn't arrived yet, and vice versa. This solves the "which arrives first?"
//! problem where either the nostr event or git push can arrive first.

use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Instant;

/// Source of an event entering purgatory.
///
/// Tracks whether an event was submitted directly by a user or fetched via
/// proactive sync from another relay. This distinction is used for:
/// - Filtered logging: Direct submissions log at WARN level, synced at DEBUG
/// - Operational monitoring: Helps identify user-facing issues vs sync noise
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EventSource {
    /// Event was published directly to this relay by a user
    #[default]
    Direct,
    /// Event was fetched via proactive sync from another relay
    Sync,
}

impl EventSource {
    /// Returns true if this is a direct submission (not synced)
    pub fn is_direct(&self) -> bool {
        matches!(self, EventSource::Direct)
    }
}

/// Default value for Instant fields during deserialization
fn instant_now() -> Instant {
    Instant::now()
}

/// A reference name and its target object.
///
/// Used to identify specific git refs (branches, tags) that a state event
/// is waiting for. The combination of ref_name and object_sha uniquely
/// identifies a git reference at a specific point in time.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RefPair {
    /// Full ref name, e.g., "refs/heads/main" or "refs/tags/v1.0"
    pub ref_name: String,
    /// Target object SHA (commit or annotated tag)
    pub object_sha: String,
}

/// A git reference update from receive-pack protocol.
///
/// Represents the full update information: what the ref was, what it will be,
/// and which ref is being updated. This allows detection of:
/// - Additions: old_oid is all zeros
/// - Deletions: new_oid is all zeros
/// - Modifications: both are non-zero but different
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RefUpdate {
    /// Old object SHA (40 zeros = ref is being created)
    pub old_oid: String,
    /// New object SHA (40 zeros = ref is being deleted)
    pub new_oid: String,
    /// Full ref name, e.g., "refs/heads/main" or "refs/tags/v1.0"
    pub ref_name: String,
}

impl RefUpdate {
    /// Check if this update is creating a new ref
    pub fn is_creation(&self) -> bool {
        self.old_oid == "0000000000000000000000000000000000000000"
    }

    /// Check if this update is deleting a ref
    pub fn is_deletion(&self) -> bool {
        self.new_oid == "0000000000000000000000000000000000000000"
    }

    /// Check if this update is modifying an existing ref
    pub fn is_modification(&self) -> bool {
        !self.is_creation() && !self.is_deletion()
    }
}

/// Entry for a state event (kind 30618) waiting in purgatory.
///
/// State events declare the current state of a repository but may arrive
/// before the corresponding git data has been pushed. This entry holds
/// the event and associated metadata until the git data arrives.
///
/// Note: `Instant` fields cannot be serialized directly. Use the `persistence`
/// module to convert to/from serializable wrapper types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatePurgatoryEntry {
    /// The nostr state event (kind 30618) awaiting git data
    pub event: Event,

    /// The repository identifier from the event's 'd' tag
    pub identifier: String,

    /// Event author pubkey
    pub author: PublicKey,

    /// When this entry was added to purgatory
    #[serde(skip, default = "instant_now")]
    pub created_at: Instant,

    /// Expiry deadline (30 min from creation, may be extended)
    #[serde(skip, default = "instant_now")]
    pub expires_at: Instant,

    /// Source of this event (direct submission vs sync)
    #[serde(default)]
    pub source: EventSource,
}

/// Entry for a PR event (kind 1617/1618) or placeholder waiting in purgatory.
///
/// PR events reference specific commits but may arrive before the git push
/// containing those commits. Alternatively, a git push may arrive first,
/// creating a placeholder entry waiting for the corresponding PR event.
///
/// Note: `Instant` fields cannot be serialized directly. Use the `persistence`
/// module to convert to/from serializable wrapper types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrPurgatoryEntry {
    /// The nostr PR event, if received (None = git data arrived first)
    pub event: Option<Event>,

    /// The expected commit SHA from 'c' tag (if event exists)
    /// or the actual commit pushed (if git arrived first)
    pub commit: String,

    /// When this entry was added to purgatory
    #[serde(skip, default = "instant_now")]
    pub created_at: Instant,

    /// Expiry deadline (30 min from creation, may be extended)
    #[serde(skip, default = "instant_now")]
    pub expires_at: Instant,

    /// Source of this event (direct submission vs sync)
    #[serde(default)]
    pub source: EventSource,

    /// Exact normal-endpoint refs awaiting this event; persisted for expiry cleanup.
    #[serde(default)]
    pub standard_refs: Vec<StandardPrRef>,

    /// If set, this placeholder was created by a push to the GRASP-06
    /// `/prs/<submitter>/<identifier>.git` endpoint (06.md line 12). When
    /// the corresponding PR event arrives, its signer MUST equal
    /// `submitter` and it MUST carry an `a` tag with d-tag equal to
    /// `identifier`. Mismatches cause the pushed ref + placeholder to be
    /// discarded so an attacker cannot land an arbitrary
    /// `refs/nostr/<event-id>` under their own `/prs/` namespace and
    /// later "claim" it with an unrelated event published elsewhere.
    ///
    /// `None` for placeholders created via the standard endpoint.
    #[serde(default)]
    pub prs_scope: Option<PrsPlaceholderScope>,
}

/// Binding between a GRASP-06 `/prs/` placeholder and the submitter + repo
/// identifier from the URL the push landed on. See [`PrPurgatoryEntry::prs_scope`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrsPlaceholderScope {
    /// Submitter pubkey from the `/prs/<npub>/...` URL segment.
    pub submitter: PublicKey,
    /// Repository identifier (the URL's `<d>` value, percent-decoded).
    pub identifier: String,
}

/// Entry for a repository announcement (kind 30617) waiting in purgatory.
///
/// Announcements are held in purgatory until git data arrives, proving
/// the repository has actual content. This prevents serving announcements
/// for empty repositories.
///
/// Note: `Instant` fields cannot be serialized directly. Use the `persistence`
/// module to convert to/from serializable wrapper types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnouncementPurgatoryEntry {
    /// The nostr announcement event (kind 30617)
    pub event: Event,

    /// The repository identifier from the event's 'd' tag
    pub identifier: String,

    /// The owner pubkey (event author)
    pub owner: PublicKey,

    /// Path to the bare git repository
    pub repo_path: PathBuf,

    /// Relay URLs from the announcement (for sync registration)
    pub relays: HashSet<String>,

    /// When this entry was added to purgatory
    #[serde(skip, default = "instant_now")]
    pub created_at: Instant,

    /// Expiry deadline (30 min from creation, may be extended)
    #[serde(skip, default = "instant_now")]
    pub expires_at: Instant,

    /// Whether the bare repo has been deleted (soft expiry)
    pub soft_expired: bool,
}

/// A pushed normal-endpoint ref, including the value cleanup may safely delete.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StandardPrRef {
    pub owner: PublicKey,
    pub identifier: String,
    pub commit: String,
}
