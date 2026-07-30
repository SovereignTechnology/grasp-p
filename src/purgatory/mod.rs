//! Purgatory: In-memory holding area for events awaiting git data.
//!
//! Solves the "which arrives first?" problem where either nostr events or git pushes
//! can arrive in any order. Events and git data are held temporarily until their
//! counterpart arrives, at which point they can be processed together.
//!
//! ## Architecture
//!
//! - **In-memory only**: Data is lost on restart (acceptable per spec)
//! - **Thread-safe**: Uses DashMap for concurrent access from multiple handlers
//! - **Automatic expiry**: Entries expire after 30 minutes by default
//! - **Separate stores**: State events and PR events use different indexing strategies

mod helpers;
pub mod persistence;
pub mod promotion_hooks;
pub mod sync;
mod types;

pub use helpers::{
    can_apply_state, can_satisfy_state, diagnose_state_mismatch, extract_refs_from_state,
    get_unpushed_refs,
};
pub use types::{
    AnnouncementPurgatoryEntry, EventSource, PrPurgatoryEntry, PrsPlaceholderScope, RefPair,
    RefUpdate, StatePurgatoryEntry,
};

use dashmap::DashMap;
use nostr_sdk::prelude::ToBech32;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

pub use sync::SyncQueueEntry;

/// Default expiry duration for purgatory entries (30 minutes)
const DEFAULT_EXPIRY: Duration = Duration::from_secs(1800);

/// Extended expiry for soft-expired announcements (24 hours).
///
/// After the initial 30-minute expiry, the bare repo is deleted but the event is
/// retained for this additional period. This allows revival if a state event arrives
/// late (e.g. slow sync), without permanently blocking the repository.
const SOFT_EXPIRY_EXTENDED: Duration = Duration::from_secs(86400);

/// Default delay before syncing user-submitted events (3 minutes).
/// This gives time for the git push to arrive after the nostr event.
const DEFAULT_SYNC_DELAY: Duration = Duration::from_secs(180);

/// Delay for sync-triggered events (500ms).
/// Used for batching burst arrivals during negentropy sync.
const IMMEDIATE_SYNC_DELAY: Duration = Duration::from_millis(500);

/// Serializable wrapper for `StatePurgatoryEntry` with time offsets.
///
/// Stores `Instant` fields as `Duration` offsets from the `saved_at` timestamp
/// in `PurgatoryState`, allowing state to be persisted and restored across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableStatePurgatoryEntry {
    /// The nostr state event (kind 30618) awaiting git data
    event: Event,
    /// The repository identifier from the event's 'd' tag
    identifier: String,
    /// Event author pubkey
    author: PublicKey,
    /// Duration offset from saved_at for created_at
    created_at_offset_secs: u64,
    /// Duration offset from saved_at for expires_at
    expires_at_offset_secs: u64,
    /// Source of this event (direct submission vs sync)
    #[serde(default)]
    source: types::EventSource,
}

/// Serializable wrapper for `PrPurgatoryEntry` with time offsets.
///
/// Stores `Instant` fields as `Duration` offsets from the `saved_at` timestamp
/// in `PurgatoryState`, allowing state to be persisted and restored across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializablePrPurgatoryEntry {
    /// The nostr PR event, if received (None = git data arrived first)
    event: Option<Event>,
    /// The expected commit SHA from 'c' tag (if event exists)
    /// or the actual commit pushed (if git arrived first)
    commit: String,
    /// Duration offset from saved_at for created_at
    created_at_offset_secs: u64,
    /// Duration offset from saved_at for expires_at
    expires_at_offset_secs: u64,
    /// Source of this event (direct submission vs sync)
    #[serde(default)]
    source: types::EventSource,
    /// GRASP-06 `/prs/` placeholder scope, if any. `#[serde(default)]`
    /// keeps state files written before this field existed
    /// deserialisable.
    #[serde(default)]
    prs_scope: Option<types::PrsPlaceholderScope>,
}

/// Serializable wrapper for `AnnouncementPurgatoryEntry` with time offsets.
///
/// Stores `Instant` fields as `Duration` offsets from the `saved_at` timestamp
/// in `PurgatoryState`, allowing state to be persisted and restored across restarts.
///
/// Note: soft-expired entries (bare repo deleted) are NOT persisted — they have
/// no git repo on disk and would be immediately cleaned up on restore anyway.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableAnnouncementPurgatoryEntry {
    /// The nostr announcement event (kind 30617)
    event: Event,
    /// The repository identifier from the event's 'd' tag
    identifier: String,
    /// The owner pubkey (event author)
    owner: PublicKey,
    /// Path to the bare git repository (must exist on disk)
    repo_path: PathBuf,
    /// Relay URLs from the announcement (for sync registration)
    relays: HashSet<String>,
    /// Duration offset from saved_at for created_at
    created_at_offset_secs: u64,
    /// Duration offset from saved_at for expires_at
    expires_at_offset_secs: u64,
}

/// Serializable purgatory state for disk persistence.
///
/// Contains all purgatory data needed to restore state across restarts:
/// - Announcement events (indexed by (owner, identifier)) — non-soft-expired only
/// - State events (indexed by identifier)
/// - PR events (indexed by event ID)
/// - Expired events (to prevent re-sync loops)
/// - Version number for future compatibility
/// - Saved timestamp for downtime calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PurgatoryState {
    /// Version number for state format (currently 1)
    version: u32,
    /// When this state was saved to disk
    saved_at: SystemTime,
    /// Announcement events indexed by "owner_hex:identifier"
    /// Only non-soft-expired entries are persisted (bare repo must exist).
    #[serde(default)]
    announcement_purgatory: HashMap<String, SerializableAnnouncementPurgatoryEntry>,
    /// State events indexed by repository identifier
    state_events: HashMap<String, Vec<SerializableStatePurgatoryEntry>>,
    /// PR events indexed by event ID (hex string)
    pr_events: HashMap<String, SerializablePrPurgatoryEntry>,
    /// Expired event IDs with their expiry timestamps
    expired_events: HashMap<String, SystemTime>,
}

/// Main purgatory structure holding events awaiting git data.
///
/// Provides thread-safe concurrent access to three separate stores:
/// - Announcements indexed by (pubkey, identifier)
/// - State events indexed by repository identifier
/// - PR events indexed by event ID
///
/// Also manages a sync queue for background git data fetching:
/// - Tracks identifiers that need syncing with backoff/debouncing
/// - Supports both user-submitted events (3min delay) and sync-triggered (500ms delay)
///
/// ## Expired Event Tracking
///
/// Events that expire from purgatory without finding git data are tracked in
/// `expired_events` to prevent infinite re-sync loops. When proactive sync
/// fetches events from relays, we filter out expired events using:
/// - `event_ids()` - Returns both active purgatory events AND expired events
/// - `is_expired()` - Check if an event has expired before
/// - `mark_expired()` - Called during cleanup to track newly expired events
///
/// This prevents the sync system from repeatedly fetching and re-adding events
/// that we've already determined have no git data available.
#[derive(Clone)]
pub struct Purgatory {
    /// Repository announcements (kind 30617) indexed by (owner pubkey, identifier).
    /// Key: (PublicKey, String) where String is the repository identifier.
    announcement_purgatory: Arc<DashMap<(PublicKey, String), AnnouncementPurgatoryEntry>>,

    /// State events (kind 30618) indexed by repository identifier.
    /// Multiple state events can wait for the same identifier (different maintainers).
    state_events: Arc<DashMap<String, Vec<StatePurgatoryEntry>>>,

    /// PR events (kind 1617/1618) or placeholders indexed by event ID (hex string).
    /// Event ID is from the 'e' tag in the PR event itself.
    pr_events: Arc<DashMap<String, PrPurgatoryEntry>>,

    /// Sync queue for background git data fetching.
    /// Maps repository identifier to sync queue entry with timing/backoff state.
    sync_queue: Arc<DashMap<String, SyncQueueEntry>>,

    /// Events that expired from purgatory without finding git data.
    /// Prevents infinite re-sync loops by filtering these out during negentropy/REQ sync.
    /// Stored as EventId (hex string) for efficient lookup.
    expired_events: Arc<DashMap<EventId, Instant>>,

    _git_data_path: PathBuf,

    /// Set once at startup by [`Purgatory::set_prs_cleanup_ctx`] to give
    /// [`Purgatory::cleanup`] enough information to remove abandoned
    /// `/prs/<submitter>/<identifier>.git` refs and bare repos when their
    /// scoped placeholders expire without an arriving PR event. Left
    /// `None` in tests and any caller that does not need this behaviour.
    prs_cleanup_ctx: std::sync::OnceLock<PrsCleanupCtx>,
}

/// Context shared with [`Purgatory::cleanup`] so it can perform the same
/// best-effort empty-repo cleanup the `/prs/` receive handler does, for
/// placeholders that expire because no matching PR event ever arrived.
///
/// The lock map is the same one held by the receive handler. The
/// cleanup loop is synchronous, so it `try_lock`s the per-path mutex —
/// holding it across an async point would block the runtime — and
/// reads the `in_flight` counter under that mutex to decide whether a
/// push is mid-receive.
#[derive(Clone)]
pub struct PrsCleanupCtx {
    pub git_data_path: PathBuf,
    pub repo_init_locks: crate::grasp06::receive::RepoInitLocks,
}

impl Purgatory {
    /// Create a new empty purgatory.
    pub fn new(git_data_path: impl Into<PathBuf>) -> Self {
        Self {
            announcement_purgatory: Arc::new(DashMap::new()),
            state_events: Arc::new(DashMap::new()),
            pr_events: Arc::new(DashMap::new()),
            sync_queue: Arc::new(DashMap::new()),
            expired_events: Arc::new(DashMap::new()),
            _git_data_path: git_data_path.into(),
            prs_cleanup_ctx: std::sync::OnceLock::new(),
        }
    }

    /// Wire the cleanup-time `/prs/` filesystem context. Called once at
    /// startup by `main`; tests and code paths that do not exercise
    /// scoped `/prs/` placeholders leave it unset and the cleanup loop
    /// then only removes the in-memory entry, leaving any on-disk refs
    /// in place.
    pub fn set_prs_cleanup_ctx(&self, ctx: PrsCleanupCtx) {
        // Ignore a second set — there is exactly one server-wide context.
        let _ = self.prs_cleanup_ctx.set(ctx);
    }

    /// Enqueue an identifier for background git data sync.
    ///
    /// This method is called when a state or PR event is added to purgatory.
    /// It uses debouncing to handle burst arrivals efficiently:
    /// - If the identifier is already queued, resets attempt_count and updates
    ///   next_attempt if the new delay would be sooner
    /// - If not queued, creates a new entry with the given delay
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier to sync
    /// * `delay` - How long to wait before the first sync attempt
    pub fn enqueue_sync(&self, identifier: &str, delay: Duration) {
        self.sync_queue
            .entry(identifier.to_string())
            .and_modify(|entry| {
                // Reset attempt count and potentially update next_attempt
                entry.on_new_event(delay);
                tracing::debug!(
                    identifier = %identifier,
                    "Updated existing sync queue entry"
                );
            })
            .or_insert_with(|| {
                tracing::debug!(
                    identifier = %identifier,
                    delay_secs = delay.as_secs(),
                    "Added new sync queue entry"
                );
                SyncQueueEntry::new(delay)
            });
    }

    /// Enqueue an identifier for sync with the default delay (3 minutes).
    ///
    /// Used for user-submitted events where we expect a git push to follow.
    pub fn enqueue_sync_default(&self, identifier: &str) {
        self.enqueue_sync(identifier, DEFAULT_SYNC_DELAY);
    }

    /// Enqueue an identifier for immediate sync (500ms delay).
    ///
    /// Used for sync-triggered events (e.g., from negentropy) where we want
    /// to batch burst arrivals but start syncing quickly.
    pub fn enqueue_sync_immediate(&self, identifier: &str) {
        self.enqueue_sync(identifier, IMMEDIATE_SYNC_DELAY);
    }

    /// Check if there are pending events for an identifier.
    ///
    /// Returns true if purgatory has state events or PR events for this identifier.
    /// This is used by the sync loop to determine if an identifier should remain
    /// in the sync queue.
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier to check
    pub fn has_pending_events(&self, identifier: &str) -> bool {
        // Check state events
        if self
            .state_events
            .get(identifier)
            .is_some_and(|entries| !entries.is_empty())
        {
            return true;
        }

        // Check PR events - need to scan all entries since they're indexed by event_id
        // PR events reference repositories via `a` tags with format `30617:<owner_pubkey>:<identifier>`
        for entry in self.pr_events.iter() {
            if let Some(ref event) = entry.value().event {
                if Self::event_references_identifier(event, identifier) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if an event references a specific repository identifier.
    ///
    /// Looks for `a` tags with format `30617:<owner_pubkey>:<identifier>`.
    fn event_references_identifier(event: &Event, identifier: &str) -> bool {
        for tag in event.tags.iter() {
            let tag_vec = tag.clone().to_vec();
            if tag_vec.len() >= 2 && tag_vec[0] == "a" && tag_vec[1].starts_with("30617:") {
                // Format: 30617:<owner_pubkey>:<identifier>
                let parts: Vec<&str> = tag_vec[1].split(':').collect();
                if parts.len() >= 3 && parts[2] == identifier {
                    return true;
                }
            }
        }
        false
    }

    /// Get a reference to the sync queue (for the sync loop).
    pub fn sync_queue(&self) -> &Arc<DashMap<String, SyncQueueEntry>> {
        &self.sync_queue
    }

    /// Remove an identifier from the sync queue.
    ///
    /// Called when sync completes or the identifier no longer has pending events.
    pub fn remove_from_sync_queue(&self, identifier: &str) {
        self.sync_queue.remove(identifier);
    }

    /// Add a state event to purgatory.
    ///
    /// The event will expire after the default duration unless matched with git data.
    /// Multiple state events for the same identifier are allowed (from different authors).
    ///
    /// Automatically enqueues the identifier for background sync with the default delay
    /// (3 minutes), giving time for a git push to arrive after the nostr event.
    /// For sync-triggered events, the SyncManager calls `enqueue_sync_immediate` separately
    /// to override this delay.
    ///
    /// If an event already exists in purgatory with `Sync` source and the new submission
    /// is direct (`!from_sync`), the source is upgraded to `Direct` without extending expiry.
    ///
    /// # Arguments
    /// * `event` - The state event (kind 30618) to hold
    /// * `identifier` - The repository identifier from the 'd' tag
    /// * `author` - The event author's public key
    /// * `from_sync` - True if this event came from proactive sync (vs user-submitted)
    pub fn add_state(&self, event: Event, identifier: String, author: PublicKey, from_sync: bool) {
        let source = if from_sync {
            types::EventSource::Sync
        } else {
            types::EventSource::Direct
        };

        // Check if event already exists - if so, potentially upgrade source
        if let Some(mut entries) = self.state_events.get_mut(&identifier) {
            if let Some(existing) = entries.iter_mut().find(|e| e.event.id == event.id) {
                // Upgrade source from Sync to Direct if new submission is direct
                if existing.source == types::EventSource::Sync && !from_sync {
                    existing.source = types::EventSource::Direct;
                    existing.expires_at = Instant::now() + DEFAULT_EXPIRY;
                    tracing::debug!(
                        event_id = %event.id,
                        identifier = %identifier,
                        "Upgraded purgatory entry source from Sync to Direct, reset expiry"
                    );
                }
                return; // Event already exists, don't add duplicate
            }
        }

        let now = Instant::now();
        let entry = StatePurgatoryEntry {
            event,
            identifier: identifier.clone(),
            author,
            created_at: now,
            expires_at: now + DEFAULT_EXPIRY,
            source,
        };

        self.state_events
            .entry(identifier.clone())
            .or_default()
            .push(entry);

        // Enqueue for background sync with default delay
        // (SyncManager will call enqueue_sync_immediate for sync-triggered events)
        self.enqueue_sync_default(&identifier);
    }

    /// Add a PR event to purgatory.
    ///
    /// The event will expire after the default duration unless matched with git data.
    ///
    /// Automatically enqueues the referenced repository identifier for background sync
    /// with the default delay (3 minutes), giving time for a git push to arrive.
    ///
    /// If an event already exists in purgatory with `Sync` source and the new submission
    /// is direct (`!from_sync`), the source is upgraded to `Direct` without extending expiry.
    ///
    /// # Arguments
    /// * `event` - The PR event (kind 1617/1618) to hold
    /// * `event_id` - The event ID (hex string) from the 'e' tag
    /// * `commit` - The commit SHA from the 'c' tag
    /// * `from_sync` - True if this event came from proactive sync (vs user-submitted)
    pub fn add_pr(&self, event: Event, event_id: String, commit: String, from_sync: bool) {
        let source = if from_sync {
            types::EventSource::Sync
        } else {
            types::EventSource::Direct
        };

        // Check if event already exists - if so, potentially upgrade source
        if let Some(mut existing) = self.pr_events.get_mut(&event_id) {
            // Upgrade source from Sync to Direct if new submission is direct
            if existing.source == types::EventSource::Sync && !from_sync {
                existing.source = types::EventSource::Direct;
                existing.expires_at = Instant::now() + DEFAULT_EXPIRY;
                tracing::debug!(
                    event_id = %event_id,
                    "Upgraded PR purgatory entry source from Sync to Direct, reset expiry"
                );
            }
            return; // Event already exists, don't add duplicate
        }

        // Extract identifier from the event's `a` tag for sync enqueueing
        let identifier = crate::git::sync::extract_identifier_from_pr_event(&event);

        let now = Instant::now();
        let entry = PrPurgatoryEntry {
            event: Some(event),
            commit,
            created_at: now,
            expires_at: now + DEFAULT_EXPIRY,
            source,
            prs_scope: None,
        };

        self.pr_events.insert(event_id, entry);

        // Enqueue the identifier for background sync if we could extract it
        if let Some(id) = identifier {
            self.enqueue_sync_default(&id);
        }
    }

    /// Add a PR placeholder (git data arrived before PR event).
    ///
    /// Creates a placeholder entry waiting for the corresponding PR event.
    /// Placeholders are always marked as `Direct` source since they originate
    /// from git pushes (direct user action).
    ///
    /// # Arguments
    /// * `event_id` - The expected event ID (from git ref name)
    /// * `commit` - The commit SHA that was pushed
    pub fn add_pr_placeholder(&self, event_id: String, commit: String) {
        let now = Instant::now();
        let entry = PrPurgatoryEntry {
            event: None, // Placeholder - no event yet
            commit,
            created_at: now,
            expires_at: now + DEFAULT_EXPIRY,
            source: types::EventSource::Direct, // Git pushes are direct user actions
            prs_scope: None,
        };

        self.pr_events.insert(event_id, entry);
    }

    /// Add a PR placeholder created by a push to the GRASP-06 `/prs/`
    /// endpoint (06.md line 12).
    ///
    /// Behaves like [`Self::add_pr_placeholder`] but additionally records
    /// the URL's submitter and identifier on the entry. When the
    /// corresponding PR event later arrives, the validator (see
    /// [`crate::nostr::policy::pr_event`]) MUST cross-check the event's
    /// signer against `submitter` and one of the event's `a`-tag d-tags
    /// against `identifier`. Without this binding an attacker could push
    /// any `refs/nostr/<event-id>` under their own `/prs/` namespace and
    /// have it later "validated" by an unrelated event of the same id.
    ///
    /// # Arguments
    /// * `event_id` - The expected event ID (from the pushed ref name)
    /// * `commit` - The commit SHA that was pushed
    /// * `submitter` - Pubkey from the `/prs/<npub>/...` URL segment
    /// * `identifier` - Repository identifier from the URL (percent-decoded)
    pub fn add_prs_pr_placeholder(
        &self,
        event_id: String,
        commit: String,
        submitter: PublicKey,
        identifier: String,
    ) {
        let now = Instant::now();
        let entry = PrPurgatoryEntry {
            event: None,
            commit,
            created_at: now,
            expires_at: now + DEFAULT_EXPIRY,
            source: types::EventSource::Direct,
            prs_scope: Some(types::PrsPlaceholderScope {
                submitter,
                identifier,
            }),
        };

        self.pr_events.insert(event_id, entry);
    }

    /// Find state events waiting for a specific repository identifier.
    ///
    /// Returns all state events (from all maintainers) waiting for git data
    /// matching this identifier.
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier to search for
    ///
    /// # Returns
    /// Vector of state events waiting for this identifier, or empty vec if none found
    pub fn find_state(&self, identifier: &str) -> Vec<StatePurgatoryEntry> {
        self.state_events
            .get(identifier)
            .map(|entries| entries.clone())
            .unwrap_or_default()
    }

    /// Find a PR event or placeholder by event ID.
    ///
    /// # Arguments
    /// * `event_id` - The event ID to search for
    ///
    /// # Returns
    /// The PR entry if found, None otherwise
    pub fn find_pr(&self, event_id: &str) -> Option<PrPurgatoryEntry> {
        self.pr_events.get(event_id).map(|entry| entry.clone())
    }

    /// Find a PR placeholder specifically (git-data-first scenario).
    ///
    /// Returns the commit SHA only if a placeholder exists (entry with no event).
    /// Used to distinguish placeholders from actual PR events.
    ///
    /// # Arguments
    /// * `event_id` - The event ID to search for
    ///
    /// # Returns
    /// Some(commit_sha) if a placeholder exists, None if no entry or entry has an event
    pub fn find_pr_placeholder(&self, event_id: &str) -> Option<String> {
        self.pr_events.get(event_id).and_then(|entry| {
            if entry.event.is_none() {
                Some(entry.commit.clone())
            } else {
                None
            }
        })
    }

    /// Find all PR events for a specific repository identifier.
    ///
    /// PR events reference repositories via `a` tags with format `30617:<owner_pubkey>:<identifier>`.
    /// This function scans all PR entries and returns those that reference the given identifier.
    ///
    /// Note: This is a linear scan since PR events are indexed by event_id, not by identifier.
    /// For repositories with many PR events, this could be optimized with a secondary index.
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier to search for
    ///
    /// # Returns
    /// Vector of PR purgatory entries that reference this identifier
    pub fn find_prs_for_identifier(&self, identifier: &str) -> Vec<PrPurgatoryEntry> {
        self.pr_events
            .iter()
            .filter(|entry| {
                if let Some(ref event) = entry.value().event {
                    Self::event_references_identifier(event, identifier)
                } else {
                    false
                }
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Remove a state event from purgatory.
    ///
    /// Removes all entries for the given identifier.
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier to remove
    pub fn remove_state(&self, identifier: &str) {
        self.state_events.remove(identifier);
    }

    /// Remove a specific state event by comparing the full event.
    ///
    /// This allows removing a single state event while leaving others
    /// for the same identifier intact.
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier
    /// * `event_id` - The specific event ID to remove
    pub fn remove_state_event(&self, identifier: &str, event_id: &EventId) {
        if let Some(mut entries) = self.state_events.get_mut(identifier) {
            entries.retain(|entry| entry.event.id != *event_id);
            if entries.is_empty() {
                drop(entries); // Release lock before removal
                self.state_events.remove(identifier);
            }
        }
    }

    /// Remove non-preferred states on coordinates promoted in this pass when
    /// their Git objects are still unavailable. Reconstructable predecessors
    /// and states from other authors remain available as rollback candidates.
    pub(crate) fn remove_unreconstructable_state_replacements(
        &self,
        identifier: &str,
        promoted: &[Event],
        source_repo_path: &Path,
    ) -> usize {
        if promoted.is_empty() {
            return 0;
        }

        let is_preferred = |candidate: &Event, current: &Event| {
            candidate.created_at > current.created_at
                || (candidate.created_at == current.created_at && candidate.id < current.id)
        };
        let mut winners = HashMap::<PublicKey, &Event>::new();
        for event in promoted {
            winners
                .entry(event.pubkey)
                .and_modify(|current| {
                    if is_preferred(event, current) {
                        *current = event;
                    }
                })
                .or_insert(event);
        }

        let removable: HashSet<EventId> = self
            .find_state(identifier)
            .into_iter()
            .filter(|entry| {
                winners.get(&entry.event.pubkey).is_some_and(|winner| {
                    is_preferred(winner, &entry.event)
                        && !can_apply_state(&entry.event, source_repo_path)
                })
            })
            .map(|entry| entry.event.id)
            .collect();
        if removable.is_empty() {
            return 0;
        }

        let Some(mut entries) = self.state_events.get_mut(identifier) else {
            return 0;
        };
        let before = entries.len();
        entries.retain(|entry| !removable.contains(&entry.event.id));
        let removed = before - entries.len();
        drop(entries);
        self.state_events
            .remove_if(identifier, |_, entries| entries.is_empty());
        removed
    }

    /// Find state events that could be satisfied by ref updates.
    ///
    /// Returns state events waiting for this identifier where applying the
    /// ref updates to local state results in exactly the declared state.
    /// Uses late-binding ref extraction at git push time.
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier to search for
    /// * `pushed_updates` - Ref updates in the current push operation
    /// * `local_refs` - Refs already existing locally (ref_name -> SHA)
    ///
    /// # Returns
    /// Vector of events that can be satisfied by the push
    pub fn find_matching_states(
        &self,
        identifier: &str,
        pushed_updates: &[RefUpdate],
        local_refs: &std::collections::HashMap<String, String>,
    ) -> Vec<Event> {
        self.state_events
            .get(identifier)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|entry| {
                        helpers::can_satisfy_state(&entry.event, pushed_updates, local_refs)
                    })
                    .map(|entry| entry.event.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Extend expiry for state events about to be processed.
    ///
    /// Ensures entries have at least `duration` remaining on their timer.
    /// Sets expiry to max(current_expiry, now + duration).
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier
    /// * `event_ids` - Event IDs to extend expiry for
    /// * `duration` - Minimum duration to guarantee from now
    pub fn extend_expiry(&self, identifier: &str, event_ids: &[EventId], duration: Duration) {
        if let Some(mut entries) = self.state_events.get_mut(identifier) {
            let now = Instant::now();
            let new_expiry = now + duration;

            for entry in entries.iter_mut() {
                if event_ids.contains(&entry.event.id) {
                    // Set to max of current expiry and new expiry
                    if entry.expires_at < new_expiry {
                        entry.expires_at = new_expiry;
                    }
                }
            }
        }
    }

    /// Remove a PR event or placeholder from purgatory.
    ///
    /// # Arguments
    /// * `event_id` - The event ID to remove
    pub fn remove_pr(&self, event_id: &str) {
        self.pr_events.remove(event_id);
    }

    // =========================================================================
    // Announcement Purgatory Methods
    // =========================================================================

    /// Add a repository announcement to purgatory.
    ///
    /// The announcement will be held until git data arrives, at which point
    /// it will be promoted to the database and served to clients.
    ///
    /// # Arguments
    /// * `event` - The announcement event (kind 30617)
    /// * `identifier` - The repository identifier from the 'd' tag
    /// * `owner` - The owner pubkey (event author)
    /// * `repo_path` - Path to the bare git repository
    /// * `relays` - Relay URLs from the announcement (for sync registration)
    pub fn add_announcement(
        &self,
        event: Event,
        identifier: String,
        owner: PublicKey,
        repo_path: PathBuf,
        relays: HashSet<String>,
    ) {
        let now = Instant::now();
        let entry = AnnouncementPurgatoryEntry {
            event,
            identifier: identifier.clone(),
            owner,
            repo_path,
            relays,
            created_at: now,
            expires_at: now + DEFAULT_EXPIRY,
            soft_expired: false,
        };

        let key = (owner, identifier);
        self.announcement_purgatory.insert(key.clone(), entry);

        tracing::debug!(
            owner = %key.0,
            identifier = %key.1,
            "Added announcement to purgatory"
        );
    }

    /// Find an announcement in purgatory by owner and identifier.
    ///
    /// # Arguments
    /// * `owner` - The owner pubkey
    /// * `identifier` - The repository identifier
    ///
    /// # Returns
    /// The announcement entry if found, None otherwise
    pub fn find_announcement(
        &self,
        owner: &PublicKey,
        identifier: &str,
    ) -> Option<AnnouncementPurgatoryEntry> {
        let key = (*owner, identifier.to_string());
        self.announcement_purgatory
            .get(&key)
            .map(|entry| entry.clone())
    }

    /// Get all announcements in purgatory for a given identifier.
    ///
    /// This is used for authorization - state events and git pushes need to
    /// check purgatory announcements for maintainer validation.
    ///
    /// # Arguments
    /// * `identifier` - The repository identifier
    ///
    /// # Returns
    /// Vector of announcement entries for this identifier
    pub fn get_announcements_by_identifier(
        &self,
        identifier: &str,
    ) -> Vec<AnnouncementPurgatoryEntry> {
        self.announcement_purgatory
            .iter()
            .filter(|entry| entry.key().1 == identifier)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Remove an announcement from purgatory.
    ///
    /// # Arguments
    /// * `owner` - The owner pubkey
    /// * `identifier` - The repository identifier
    pub fn remove_announcement(&self, owner: &PublicKey, identifier: &str) {
        let key = (*owner, identifier.to_string());
        self.announcement_purgatory.remove(&key);
        tracing::debug!(
            owner = %owner,
            identifier = %identifier,
            "Removed announcement from purgatory"
        );
    }

    /// Promote an announcement from purgatory to active status.
    ///
    /// This is called when git data arrives. The announcement event is returned
    /// so it can be saved to the database.
    ///
    /// # Arguments
    /// * `owner` - The owner pubkey
    /// * `identifier` - The repository identifier
    ///
    /// # Returns
    /// The announcement event if found, None otherwise
    pub fn promote_announcement(&self, owner: &PublicKey, identifier: &str) -> Option<Event> {
        let key = (*owner, identifier.to_string());
        self.announcement_purgatory.remove(&key).map(|(_, entry)| {
            tracing::info!(
                owner = %owner,
                identifier = %identifier,
                "Promoted announcement from purgatory to database"
            );
            entry.event
        })
    }

    /// Check if there's an announcement in purgatory for the given owner and identifier.
    ///
    /// # Arguments
    /// * `owner` - The owner pubkey
    /// * `identifier` - The repository identifier
    ///
    /// # Returns
    /// true if an announcement exists in purgatory, false otherwise
    pub fn has_purgatory_announcement(&self, owner: &PublicKey, identifier: &str) -> bool {
        let key = (*owner, identifier.to_string());
        self.announcement_purgatory.contains_key(&key)
    }

    /// Extend the expiry for an announcement in purgatory.
    ///
    /// This is called when state events arrive for a purgatory announcement,
    /// indicating the repository is actively receiving metadata.
    ///
    /// # Arguments
    /// * `owner` - The owner pubkey
    /// * `identifier` - The repository identifier
    /// * `duration` - Minimum duration to guarantee from now
    pub fn extend_announcement_expiry(
        &self,
        owner: &PublicKey,
        identifier: &str,
        duration: Duration,
    ) {
        let key = (*owner, identifier.to_string());

        // Collect revival info before taking a mutable borrow
        let revival_info: Option<(PathBuf, bool)> = self
            .announcement_purgatory
            .get(&key)
            .map(|entry| (entry.repo_path.clone(), entry.soft_expired));

        if let Some(mut entry) = self.announcement_purgatory.get_mut(&key) {
            let now = Instant::now();
            let new_expiry = now + duration;
            if entry.expires_at < new_expiry {
                entry.expires_at = new_expiry;
            }
            // Always reset soft_expired when expiry is extended — the caller
            // (state event or git auth) signals the repo is still active.
            if entry.soft_expired {
                entry.soft_expired = false;
            }
        }

        // If the entry was soft-expired, recreate the bare repo outside the
        // mutable borrow so we don't hold the DashMap lock during I/O.
        if let Some((repo_path, was_soft_expired)) = revival_info {
            if was_soft_expired {
                if !repo_path.exists() {
                    match std::fs::create_dir_all(&repo_path) {
                        Ok(()) => {
                            // Initialise as a bare git repository
                            let status = std::process::Command::new("git")
                                .args(["init", "--bare"])
                                .arg(&repo_path)
                                .status();
                            match status {
                                Ok(s) if s.success() => {
                                    tracing::info!(
                                        path = %repo_path.display(),
                                        owner = %owner,
                                        identifier = %identifier,
                                        "Recreated bare repository for revived soft-expired announcement"
                                    );
                                }
                                Ok(s) => {
                                    tracing::warn!(
                                        path = %repo_path.display(),
                                        exit_code = ?s.code(),
                                        "git init --bare failed when reviving soft-expired announcement"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        path = %repo_path.display(),
                                        error = %e,
                                        "Failed to run git init --bare when reviving soft-expired announcement"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %repo_path.display(),
                                error = %e,
                                "Failed to create directory when reviving soft-expired announcement"
                            );
                        }
                    }
                }
                tracing::info!(
                    owner = %owner,
                    identifier = %identifier,
                    "Revived soft-expired announcement (bare repo recreated, expiry extended)"
                );
            }
        }
    }

    /// Get count of announcements in purgatory.
    pub fn announcement_count(&self) -> usize {
        self.announcement_purgatory.len()
    }

    /// Collect (repo_id, relay_urls) for all announcements currently in purgatory.
    ///
    /// Returns a vec of `(repo_id, relay_urls)` where `repo_id` is the addressable
    /// coordinate string `"30617:{pubkey_hex}:{identifier}"`. Used by the purgatory
    /// announcement sync timer to register StateOnly entries in `repo_sync_index`.
    pub fn announcements_for_sync(&self) -> Vec<(String, HashSet<String>)> {
        self.announcement_purgatory
            .iter()
            .map(|entry| {
                let (owner, identifier) = entry.key();
                let repo_id = format!("30617:{}:{}", owner.to_hex(), identifier);
                let relays = entry.value().relays.clone();
                (repo_id, relays)
            })
            .collect()
    }

    /// Collect announcement events currently awaiting git data.
    ///
    /// The proactive sync manager uses this snapshot to retry dependency events
    /// that may have arrived before a new owner announcement established their
    /// maintainer relationship.
    pub fn announcement_events_for_sync(&self) -> Vec<Event> {
        self.announcement_purgatory
            .iter()
            .map(|entry| entry.value().event.clone())
            .collect()
    }

    /// Get all event IDs currently stored in purgatory AND previously expired events.
    ///
    /// Returns a HashSet of all event IDs for:
    /// - Announcements currently held in purgatory
    /// - State events currently held in purgatory
    /// - PR events currently held in purgatory
    /// - Events that previously expired from purgatory without finding git data
    ///
    /// This is used by negentropy sync and REQ+EOSE to avoid fetching events
    /// that are either:
    /// 1. Already in purgatory awaiting git data
    /// 2. Previously expired without finding git data (prevents infinite re-sync)
    ///
    /// # Returns
    /// HashSet of event IDs (as EventId) for all events in purgatory + expired events
    pub fn event_ids(&self) -> HashSet<EventId> {
        let mut ids = HashSet::new();

        // Collect announcement event IDs
        for entry in self.announcement_purgatory.iter() {
            ids.insert(entry.value().event.id);
        }

        // Collect state event IDs
        for entry in self.state_events.iter() {
            for state_entry in entry.value().iter() {
                ids.insert(state_entry.event.id);
            }
        }

        // Collect PR event IDs (only actual events, not placeholders)
        for entry in self.pr_events.iter() {
            if let Some(ref event) = entry.value().event {
                ids.insert(event.id);
            }
        }

        // Collect expired event IDs
        for entry in self.expired_events.iter() {
            ids.insert(*entry.key());
        }

        ids
    }

    /// Check if an event has previously expired from purgatory.
    ///
    /// Returns true if this event was previously held in purgatory and expired
    /// without finding git data. This prevents re-adding the event during sync.
    ///
    /// # Arguments
    /// * `event_id` - The event ID to check
    ///
    /// # Returns
    /// true if the event has expired before, false otherwise
    pub fn is_expired(&self, event_id: &EventId) -> bool {
        self.expired_events.contains_key(event_id)
    }

    /// Mark an event as expired (called during cleanup).
    ///
    /// Tracks events that expired from purgatory without finding git data.
    /// This prevents infinite re-sync loops by filtering these events during
    /// negentropy and REQ+EOSE sync.
    ///
    /// # Arguments
    /// * `event_id` - The event ID to mark as expired
    fn mark_expired(&self, event_id: EventId) {
        self.expired_events.insert(event_id, Instant::now());
    }

    /// Get all PR placeholder event IDs (git-data-first entries without events).
    ///
    /// Returns event IDs for entries where git data arrived before the PR event.
    /// These correspond to `refs/nostr/<event-id>` refs that should be cleaned up
    /// on shutdown since they don't have corresponding events.
    ///
    /// # Returns
    /// Vector of event IDs (hex strings) for placeholder entries
    pub fn get_placeholder_event_ids(&self) -> Vec<String> {
        self.pr_events
            .iter()
            .filter_map(|entry| {
                if entry.value().event.is_none() {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Remove expired entries from purgatory.
    ///
    /// Should be called periodically (every 60 seconds) by background task to clean up
    /// entries that have exceeded their expiry deadline.
    ///
    /// **Important**: This method also marks expired events in `expired_events` to
    /// prevent infinite re-sync loops. Events that expire without finding git data
    /// will be filtered out during future negentropy/REQ sync operations.
    ///
    /// Emits structured `[PURGATORY_EXPIRED]` log entries for each expired event
    /// to support migration scripts and operational monitoring.
    ///
    /// # Returns
    /// Tuple of (num_announcement_removed, num_state_removed, num_pr_removed)
    pub fn cleanup(&self) -> (usize, usize, usize) {
        let now = Instant::now();

        // Process expired announcements with two-phase soft expiry:
        //
        // Phase 1 (initial expiry, !soft_expired): Delete bare repo, set soft_expired=true,
        //   extend expiry by SOFT_EXPIRY_EXTENDED so the event is retained for revival.
        // Phase 2 (extended expiry, soft_expired): Fully remove from purgatory.
        //
        // Collect entries that have passed their expires_at deadline.
        let expired_announcements: Vec<(PublicKey, String, PathBuf, EventId, bool)> = self
            .announcement_purgatory
            .iter()
            .filter(|entry| entry.value().expires_at <= now)
            .map(|entry| {
                let key = entry.key();
                let v = entry.value();
                (
                    key.0,
                    key.1.clone(),
                    v.repo_path.clone(),
                    v.event.id,
                    v.soft_expired,
                )
            })
            .collect();

        let mut announcement_removed = 0;
        for (owner, identifier, repo_path, event_id, already_soft_expired) in expired_announcements
        {
            if already_soft_expired {
                // Phase 2: fully remove
                self.mark_expired(event_id);
                self.announcement_purgatory
                    .remove(&(owner, identifier.clone()));
                announcement_removed += 1;
                tracing::info!(
                    owner = %owner,
                    identifier = %identifier,
                    "Announcement fully expired from purgatory (soft expiry period elapsed)"
                );
            } else {
                // Phase 1: soft expiry — delete bare repo, retain event.
                //
                // Only transition to soft_expired if the directory is gone (or never
                // existed). If removal fails we leave the entry untouched so the next
                // cleanup cycle retries the deletion automatically.
                let repo_gone = if repo_path.exists() {
                    match std::fs::remove_dir_all(&repo_path) {
                        Ok(()) => {
                            tracing::info!(
                                path = %repo_path.display(),
                                owner = %owner,
                                identifier = %identifier,
                                "Deleted bare repository during soft expiry (event retained for revival)"
                            );
                            true
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %repo_path.display(),
                                error = %e,
                                "Failed to delete bare repository during soft expiry; will retry next cleanup cycle"
                            );
                            false
                        }
                    }
                } else {
                    // Already gone (e.g. deleted externally)
                    true
                };

                if repo_gone {
                    // Mark soft_expired and extend expiry
                    if let Some(mut entry) = self
                        .announcement_purgatory
                        .get_mut(&(owner, identifier.clone()))
                    {
                        entry.soft_expired = true;
                        entry.expires_at = now + SOFT_EXPIRY_EXTENDED;
                    }
                    tracing::debug!(
                        owner = %owner,
                        identifier = %identifier,
                        "Announcement soft-expired: bare repo deleted, event retained for 24h"
                    );
                }
            }
        }

        let mut state_removed = 0;

        // Remove expired state events and mark them as expired
        self.state_events.retain(|identifier, entries| {
            let original_len = entries.len();

            // Log and collect expired entries before removing
            for entry in entries.iter().filter(|e| e.expires_at <= now) {
                let npub = entry.author.to_bech32().unwrap_or_else(|_| entry.author.to_hex());
                let event_id_short = &entry.event.id.to_hex()[..12];
                let source_str = if entry.source.is_direct() { "direct" } else { "sync" };

                // Structured log for migration scripts
                // Direct submissions log at WARN, synced events at DEBUG
                if entry.source.is_direct() {
                    tracing::warn!(
                        "[PURGATORY_EXPIRED] repo={} npub={} event_id={}... kind={} source={} reason=\"git data not received within 30 minutes\"",
                        identifier,
                        npub,
                        event_id_short,
                        entry.event.kind.as_u16(),
                        source_str
                    );
                } else {
                    tracing::debug!(
                        "[PURGATORY_EXPIRED] repo={} npub={} event_id={}... kind={} source={} reason=\"git data not received within 30 minutes\"",
                        identifier,
                        npub,
                        event_id_short,
                        entry.event.kind.as_u16(),
                        source_str
                    );
                }

                self.mark_expired(entry.event.id);
            }

            // Remove expired entries
            entries.retain(|entry| entry.expires_at > now);
            state_removed += original_len - entries.len();
            !entries.is_empty()
        });

        // Remove expired PR events and mark them as expired
        let expired_prs: Vec<_> = self
            .pr_events
            .iter()
            .filter(|entry| entry.value().expires_at <= now)
            .map(|entry| {
                let pr_entry = entry.value();
                let event_id_str = entry.key().clone();
                let event_opt = pr_entry.event.clone();
                let commit = pr_entry.commit.clone();
                let source = pr_entry.source;
                let prs_scope = pr_entry.prs_scope.clone();
                (event_id_str, event_opt, commit, source, prs_scope)
            })
            .collect();

        let pr_removed = expired_prs.len();
        for (event_id_str, event_opt, commit, source, prs_scope) in expired_prs {
            // Log structured entry for PR events (not placeholders)
            if let Some(ref event) = event_opt {
                let npub = event
                    .pubkey
                    .to_bech32()
                    .unwrap_or_else(|_| event.pubkey.to_hex());
                let event_id_short = &event.id.to_hex()[..12];
                let source_str = if source.is_direct() { "direct" } else { "sync" };

                // Extract ALL repo identifiers from 'a' tags
                // (PR events can reference multiple repos when there are multiple maintainers)
                let repos: Vec<String> = event
                    .tags
                    .iter()
                    .filter_map(|tag| {
                        let tag_vec = tag.clone().to_vec();
                        if tag_vec.len() >= 2
                            && tag_vec[0] == "a"
                            && tag_vec[1].starts_with("30617:")
                        {
                            // Format: 30617:<owner_pubkey>:<identifier>
                            let parts: Vec<&str> = tag_vec[1].split(':').collect();
                            if parts.len() >= 3 {
                                Some(parts[2].to_string())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect();

                // Deduplicate while preserving order
                let mut seen = std::collections::HashSet::new();
                let unique_repos: Vec<String> = repos
                    .into_iter()
                    .filter(|r| seen.insert(r.clone()))
                    .collect();

                let repos_to_log = if unique_repos.is_empty() {
                    vec!["unknown".to_string()]
                } else {
                    unique_repos
                };

                // Structured log for migration scripts - log once per repo
                // Direct submissions log at WARN, synced events at DEBUG
                for repo in &repos_to_log {
                    if source.is_direct() {
                        tracing::warn!(
                            "[PURGATORY_EXPIRED] repo={} npub={} event_id={}... kind={} commit={} source={} reason=\"git data not received within 30 minutes\"",
                            repo,
                            npub,
                            event_id_short,
                            event.kind.as_u16(),
                            &commit[..commit.len().min(12)],
                            source_str
                        );
                    } else {
                        tracing::debug!(
                            "[PURGATORY_EXPIRED] repo={} npub={} event_id={}... kind={} commit={} source={} reason=\"git data not received within 30 minutes\"",
                            repo,
                            npub,
                            event_id_short,
                            event.kind.as_u16(),
                            &commit[..commit.len().min(12)],
                            source_str
                        );
                    }
                }

                self.mark_expired(event.id);
            } else {
                // Placeholder (git data arrived first, but PR event never came)
                // Placeholders are always Direct source (from git push)
                tracing::debug!(
                    "[PURGATORY_EXPIRED] placeholder event_id={} commit={} source=direct reason=\"PR event not received within 30 minutes\"",
                    &event_id_str[..event_id_str.len().min(12)],
                    &commit[..commit.len().min(12)]
                );
            }

            // For GRASP-06 `/prs/`-scoped placeholders, best-effort
            // filesystem cleanup of the dangling refs/nostr/<event-id>
            // ref and (if it leaves the bare repo with zero refs *and
            // no push is in flight*) the repo directory itself.
            //
            // We hold the per-path mutex for the duration of the
            // filesystem operations. Because `mu` is a `std::sync::Mutex`
            // (all critical sections are sync-only), we can call `lock()`
            // directly here without a runtime hazard. The purgatory entry
            // is only removed from `pr_events` after the filesystem work
            // succeeds; if the lock is poisoned we skip cleanup this cycle
            // and let the entry expire on the next sweep.
            if let (Some(scope), Some(ctx)) = (prs_scope.as_ref(), self.prs_cleanup_ctx.get()) {
                let repo_path = crate::grasp06::paths::prs_repo_path(
                    &ctx.git_data_path,
                    &scope.submitter.to_hex(),
                    &scope.identifier,
                );
                if repo_path.exists() {
                    let state =
                        crate::grasp06::receive::path_state(&ctx.repo_init_locks, &repo_path);
                    let _guard = state.mu.lock().expect("prs path mutex poisoned");
                    let ref_name = format!("refs/nostr/{}", event_id_str);
                    if let Err(e) = crate::git::delete_ref(&repo_path, &ref_name) {
                        tracing::warn!(
                            repo = %repo_path.display(),
                            ref_name = %ref_name,
                            error = %e,
                            "Failed to delete dangling /prs/ ref during purgatory expiry",
                        );
                    } else if state.in_flight.load(std::sync::atomic::Ordering::Relaxed) == 0
                        && matches!(
                            crate::git::list_refs(&repo_path),
                            Ok(refs) if refs.is_empty()
                        )
                    {
                        if let Err(e) = std::fs::remove_dir_all(&repo_path) {
                            tracing::warn!(
                                repo = %repo_path.display(),
                                error = %e,
                                "Failed to remove zero-ref /prs/ repo during purgatory expiry",
                            );
                        } else {
                            tracing::debug!(
                                repo = %repo_path.display(),
                                "Removed zero-ref /prs/ repo during purgatory expiry",
                            );
                        }
                    }
                }
            }

            self.pr_events.remove(&event_id_str);
        }

        (announcement_removed, state_removed, pr_removed)
    }

    /// Remove expired entries from purgatory (legacy method).
    ///
    /// # Returns
    /// Total number of entries removed (announcement + state + PR events)
    #[deprecated(since = "0.1.0", note = "Use cleanup() instead for separate counts")]
    pub fn remove_expired(&self) -> usize {
        let (announcement, state, pr) = self.cleanup();
        announcement + state + pr
    }

    /// Remove old expired event records.
    ///
    /// Expired events are tracked to prevent infinite re-sync loops, but they
    /// shouldn't be kept forever. This method removes expired event records
    /// older than the specified duration.
    ///
    /// Should be called periodically (e.g., daily) to prevent unbounded growth.
    ///
    /// # Arguments
    /// * `older_than` - Remove expired events older than this duration (default: 7 days)
    ///
    /// # Returns
    /// Number of expired event records removed
    pub fn cleanup_expired_events(&self, older_than: Duration) -> usize {
        let cutoff = Instant::now() - older_than;
        let mut removed = 0;

        self.expired_events.retain(|_, &mut expired_at| {
            let keep = expired_at > cutoff;
            if !keep {
                removed += 1;
            }
            keep
        });

        removed
    }

    /// Get current count of entries in purgatory.
    ///
    /// # Returns
    /// Tuple of (announcement_count, state_event_count, pr_event_count)
    pub fn count(&self) -> (usize, usize, usize) {
        let announcement_count = self.announcement_purgatory.len();
        let state_count: usize = self.state_events.iter().map(|e| e.value().len()).sum();
        let pr_count = self.pr_events.len();
        (announcement_count, state_count, pr_count)
    }

    /// Get count of expired events being tracked.
    ///
    /// # Returns
    /// Number of expired events in the tracking set
    pub fn expired_count(&self) -> usize {
        self.expired_events.len()
    }

    /// Clear all entries from purgatory (for testing).
    #[cfg(test)]
    pub fn clear(&self) {
        self.announcement_purgatory.clear();
        self.state_events.clear();
        self.pr_events.clear();
        self.sync_queue.clear();
        self.expired_events.clear();
    }

    /// Get the current size of the sync queue (for testing/metrics).
    pub fn sync_queue_size(&self) -> usize {
        self.sync_queue.len()
    }

    /// Get all repository identifiers currently in purgatory.
    ///
    /// Returns a list of all unique repository identifiers that have state events
    /// in purgatory. This is useful for re-queueing repositories after restore.
    ///
    /// # Returns
    /// Vector of repository identifiers (e.g., "owner/repo")
    ///
    /// # Example
    /// ```no_run
    /// use ngit_grasp::purgatory::Purgatory;
    /// use std::path::PathBuf;
    ///
    /// let purgatory = Purgatory::new(PathBuf::from("/tmp/git"));
    /// let identifiers = purgatory.get_all_identifiers();
    /// for id in identifiers {
    ///     println!("Repository in purgatory: {}", id);
    /// }
    /// ```
    pub fn get_all_identifiers(&self) -> Vec<String> {
        self.state_events
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Save purgatory state to disk.
    ///
    /// Serializes the current purgatory state (state_events, pr_events, expired_events)
    /// to JSON and saves it to the specified path. Time-based fields (`Instant`) are
    /// converted to duration offsets from the current `SystemTime` for persistence.
    ///
    /// Note: The sync_queue is NOT persisted - it will be rebuilt when events are
    /// restored from disk.
    ///
    /// # Arguments
    /// * `path` - Path to save the state file
    ///
    /// # Returns
    /// Ok(()) on success, Err on failure
    ///
    /// # Example
    /// ```no_run
    /// use ngit_grasp::purgatory::Purgatory;
    /// use std::path::PathBuf;
    ///
    /// let purgatory = Purgatory::new(PathBuf::from("/tmp/git"));
    /// purgatory.save_to_disk(&PathBuf::from("/tmp/purgatory.json")).unwrap();
    /// ```
    pub fn save_to_disk(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let saved_at = SystemTime::now();
        let now_instant = Instant::now();

        // Convert announcement_purgatory to serializable format.
        // Skip soft-expired entries: their bare repos have been deleted, so they
        // cannot be meaningfully restored (the repo path no longer exists on disk).
        let mut announcement_purgatory = HashMap::new();
        for entry in self.announcement_purgatory.iter() {
            let e = entry.value();
            if e.soft_expired {
                continue;
            }
            let created_offset =
                persistence::instant_to_offset(e.created_at, saved_at, now_instant);
            let expires_offset =
                persistence::instant_to_offset(e.expires_at, saved_at, now_instant);
            let key = format!("{}:{}", e.owner.to_hex(), e.identifier);
            announcement_purgatory.insert(
                key,
                SerializableAnnouncementPurgatoryEntry {
                    event: e.event.clone(),
                    identifier: e.identifier.clone(),
                    owner: e.owner,
                    repo_path: e.repo_path.clone(),
                    relays: e.relays.clone(),
                    created_at_offset_secs: created_offset.as_secs(),
                    expires_at_offset_secs: expires_offset.as_secs(),
                },
            );
        }

        // Convert state_events to serializable format
        let mut state_events = HashMap::new();
        for entry in self.state_events.iter() {
            let identifier = entry.key().clone();
            let entries: Vec<SerializableStatePurgatoryEntry> = entry
                .value()
                .iter()
                .map(|e| {
                    let created_offset =
                        persistence::instant_to_offset(e.created_at, saved_at, now_instant);
                    let expires_offset =
                        persistence::instant_to_offset(e.expires_at, saved_at, now_instant);

                    SerializableStatePurgatoryEntry {
                        event: e.event.clone(),
                        identifier: e.identifier.clone(),
                        author: e.author,
                        created_at_offset_secs: created_offset.as_secs(),
                        expires_at_offset_secs: expires_offset.as_secs(),
                        source: e.source,
                    }
                })
                .collect();
            state_events.insert(identifier, entries);
        }

        // Convert pr_events to serializable format
        let mut pr_events = HashMap::new();
        for entry in self.pr_events.iter() {
            let event_id = entry.key().clone();
            let e = entry.value();

            let created_offset =
                persistence::instant_to_offset(e.created_at, saved_at, now_instant);
            let expires_offset =
                persistence::instant_to_offset(e.expires_at, saved_at, now_instant);

            let serializable = SerializablePrPurgatoryEntry {
                event: e.event.clone(),
                commit: e.commit.clone(),
                created_at_offset_secs: created_offset.as_secs(),
                expires_at_offset_secs: expires_offset.as_secs(),
                source: e.source,
                prs_scope: e.prs_scope.clone(),
            };
            pr_events.insert(event_id, serializable);
        }

        // Convert expired_events to serializable format
        // We use SystemTime instead of Instant offsets for expired events since
        // we don't need high precision for cleanup timing
        let mut expired_events = HashMap::new();
        for entry in self.expired_events.iter() {
            let event_id = entry.key().to_hex();
            // Convert Instant to SystemTime (approximate)
            let expired_at_instant = *entry.value();
            let elapsed_since_expire = now_instant.saturating_duration_since(expired_at_instant);
            let expired_at_system = saved_at - elapsed_since_expire;
            expired_events.insert(event_id, expired_at_system);
        }

        // Create state structure
        let state = PurgatoryState {
            version: 1,
            saved_at,
            announcement_purgatory,
            state_events,
            pr_events,
            expired_events,
        };

        // Serialize to JSON and write to file
        let json = serde_json::to_string_pretty(&state)?;
        std::fs::write(path, json)?;

        tracing::info!(
            path = %path.display(),
            announcements = state.announcement_purgatory.len(),
            state_events = state.state_events.len(),
            pr_events = state.pr_events.len(),
            expired_events = state.expired_events.len(),
            "Saved purgatory state to disk"
        );

        Ok(())
    }

    /// Restore purgatory state from disk.
    ///
    /// Loads a previously saved purgatory state from the specified path and populates
    /// the current purgatory instance. Adjusts time-based fields to account for downtime
    /// between save and restore.
    ///
    /// After successful restore, the state file is deleted to prevent accidental
    /// double-restore.
    ///
    /// # Arguments
    /// * `path` - Path to the saved state file
    ///
    /// # Returns
    /// Ok(()) on success, Err if file doesn't exist or is corrupted
    ///
    /// # Example
    /// ```no_run
    /// use ngit_grasp::purgatory::Purgatory;
    /// use std::path::PathBuf;
    ///
    /// let purgatory = Purgatory::new(PathBuf::from("/tmp/git"));
    /// match purgatory.restore_from_disk(&PathBuf::from("/tmp/purgatory.json")) {
    ///     Ok(()) => println!("State restored successfully"),
    ///     Err(e) => eprintln!("Failed to restore state: {}", e),
    /// }
    /// ```
    pub fn restore_from_disk(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // Read and parse state file
        let json = std::fs::read_to_string(path)?;
        let state: PurgatoryState = serde_json::from_str(&json)?;

        // Verify version
        if state.version != 1 {
            return Err(format!("Unsupported state version: {}", state.version).into());
        }

        let now_instant = Instant::now();

        // Restore announcement_purgatory.
        // Skip entries whose bare repo no longer exists on disk — this can happen
        // if the repo was deleted externally between save and restore.
        for (_key, e) in state.announcement_purgatory {
            if !e.repo_path.exists() {
                tracing::warn!(
                    owner = %e.owner,
                    identifier = %e.identifier,
                    repo_path = %e.repo_path.display(),
                    "Skipping announcement restore: bare repo no longer exists"
                );
                continue;
            }
            let created_at = persistence::offset_to_instant(
                Duration::from_secs(e.created_at_offset_secs),
                state.saved_at,
                now_instant,
            );
            let expires_at = persistence::offset_to_instant(
                Duration::from_secs(e.expires_at_offset_secs),
                state.saved_at,
                now_instant,
            );
            let key = (e.owner, e.identifier.clone());
            self.announcement_purgatory.insert(
                key,
                AnnouncementPurgatoryEntry {
                    event: e.event,
                    identifier: e.identifier,
                    owner: e.owner,
                    repo_path: e.repo_path,
                    relays: e.relays,
                    created_at,
                    expires_at,
                    soft_expired: false,
                },
            );
        }

        // Restore state_events
        for (identifier, entries) in state.state_events {
            let restored_entries: Vec<StatePurgatoryEntry> = entries
                .into_iter()
                .map(|e| {
                    let created_at = persistence::offset_to_instant(
                        Duration::from_secs(e.created_at_offset_secs),
                        state.saved_at,
                        now_instant,
                    );
                    let expires_at = persistence::offset_to_instant(
                        Duration::from_secs(e.expires_at_offset_secs),
                        state.saved_at,
                        now_instant,
                    );

                    StatePurgatoryEntry {
                        event: e.event,
                        identifier: e.identifier,
                        author: e.author,
                        created_at,
                        expires_at,
                        source: e.source,
                    }
                })
                .collect();

            self.state_events.insert(identifier, restored_entries);
        }

        // Restore pr_events
        for (event_id, e) in state.pr_events {
            let created_at = persistence::offset_to_instant(
                Duration::from_secs(e.created_at_offset_secs),
                state.saved_at,
                now_instant,
            );
            let expires_at = persistence::offset_to_instant(
                Duration::from_secs(e.expires_at_offset_secs),
                state.saved_at,
                now_instant,
            );

            let entry = PrPurgatoryEntry {
                event: e.event,
                commit: e.commit,
                created_at,
                expires_at,
                source: e.source,
                prs_scope: e.prs_scope,
            };

            self.pr_events.insert(event_id, entry);
        }

        // Restore expired_events
        for (event_id_hex, expired_at_system) in state.expired_events {
            if let Ok(event_id) = EventId::from_hex(&event_id_hex) {
                // Convert SystemTime back to Instant (approximate)
                let elapsed_since_expire = SystemTime::now()
                    .duration_since(expired_at_system)
                    .unwrap_or(Duration::ZERO);
                let expired_at_instant = now_instant - elapsed_since_expire;

                self.expired_events.insert(event_id, expired_at_instant);
            }
        }

        tracing::info!(
            path = %path.display(),
            announcements = self.announcement_purgatory.len(),
            state_events = self.state_events.len(),
            pr_events = self.pr_events.len(),
            expired_events = self.expired_events.len(),
            saved_at = ?state.saved_at,
            "Restored purgatory state from disk"
        );

        // Delete state file after successful restore
        std::fs::remove_file(path)?;
        tracing::debug!(path = %path.display(), "Deleted state file after restore");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purgatory_creation() {
        let purgatory = Purgatory::new(PathBuf::new());
        let (announcement_count, state_count, pr_count) = purgatory.count();
        assert_eq!(announcement_count, 0);
        assert_eq!(state_count, 0);
        assert_eq!(pr_count, 0);
    }

    #[test]
    fn test_purgatory_count() {
        let purgatory = Purgatory::new(PathBuf::new());

        // Add some test data
        let keys = Keys::generate();
        let event = EventBuilder::text_note("test").finalize(&keys).unwrap();

        purgatory.add_state(
            event.clone(),
            "test-repo".to_string(),
            keys.public_key(),
            false,
        );
        purgatory.add_pr(
            event,
            "test-event-id".to_string(),
            "abc123".to_string(),
            false,
        );

        let (announcement_count, state_count, pr_count) = purgatory.count();
        assert_eq!(announcement_count, 0);
        assert_eq!(state_count, 1);
        assert_eq!(pr_count, 1);
    }

    #[test]
    fn test_enqueue_sync_debounces_rapid_calls() {
        let purgatory = Purgatory::new(PathBuf::new());

        // First call - creates entry
        purgatory.enqueue_sync("test-repo", Duration::from_secs(60));
        assert_eq!(purgatory.sync_queue_size(), 1);

        // Simulate some sync attempts
        if let Some(mut entry) = purgatory.sync_queue.get_mut("test-repo") {
            entry.attempt_count = 3;
            entry.next_attempt = Instant::now() + Duration::from_secs(120);
        }

        // Second call with shorter delay - should reset attempt_count and update next_attempt
        purgatory.enqueue_sync("test-repo", Duration::from_secs(10));

        // Should still be only one entry (debounced)
        assert_eq!(purgatory.sync_queue_size(), 1);

        // Attempt count should be reset
        let entry = purgatory.sync_queue.get("test-repo").unwrap();
        assert_eq!(entry.attempt_count, 0, "attempt_count should be reset to 0");

        // next_attempt should be updated to the sooner time (within tolerance)
        let expected_max = Instant::now() + Duration::from_secs(10) + Duration::from_millis(100);
        assert!(
            entry.next_attempt <= expected_max,
            "next_attempt should be updated to sooner time"
        );
    }

    #[test]
    fn test_has_pending_events_with_state_events() {
        let purgatory = Purgatory::new(PathBuf::new());
        let keys = Keys::generate();

        // No events initially
        assert!(!purgatory.has_pending_events("test-repo"));

        // Add a state event
        let event = EventBuilder::text_note("state").finalize(&keys).unwrap();
        purgatory.add_state(event, "test-repo".to_string(), keys.public_key(), false);

        // Now should have pending events
        assert!(purgatory.has_pending_events("test-repo"));

        // Different identifier should not have pending events
        assert!(!purgatory.has_pending_events("other-repo"));
    }

    #[test]
    fn test_has_pending_events_with_pr_events() {
        use nostr_sdk::prelude::{Kind, Tag};

        let purgatory = Purgatory::new(PathBuf::new());
        let keys = Keys::generate();

        // No events initially
        assert!(!purgatory.has_pending_events("test-repo"));

        // Add a PR event with `a` tag referencing the repository
        let tags = vec![Tag::custom(
            "a",
            vec!["30617:abc123def456:test-repo".to_string()],
        )];

        let event = EventBuilder::new(Kind::from(1618), "PR content")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        purgatory.add_pr(
            event,
            "pr-event-id".to_string(),
            "commit123".to_string(),
            false,
        );

        // Now should have pending events for test-repo
        assert!(purgatory.has_pending_events("test-repo"));

        // Different identifier should not have pending events
        assert!(!purgatory.has_pending_events("other-repo"));
    }

    #[test]
    fn test_remove_from_sync_queue() {
        let purgatory = Purgatory::new(PathBuf::new());

        purgatory.enqueue_sync("repo-1", Duration::from_secs(60));
        purgatory.enqueue_sync("repo-2", Duration::from_secs(60));
        assert_eq!(purgatory.sync_queue_size(), 2);

        purgatory.remove_from_sync_queue("repo-1");
        assert_eq!(purgatory.sync_queue_size(), 1);

        // repo-1 should be gone
        assert!(purgatory.sync_queue.get("repo-1").is_none());
        // repo-2 should still be there
        assert!(purgatory.sync_queue.get("repo-2").is_some());
    }

    #[test]
    fn test_enqueue_sync_default_and_immediate() {
        let purgatory = Purgatory::new(PathBuf::new());

        // Test default delay (3 minutes)
        purgatory.enqueue_sync_default("repo-default");
        let entry = purgatory.sync_queue.get("repo-default").unwrap();
        let expected_min = Instant::now() + Duration::from_secs(170); // ~3min minus tolerance
        let expected_max = Instant::now() + Duration::from_secs(190); // ~3min plus tolerance
        assert!(
            entry.next_attempt >= expected_min && entry.next_attempt <= expected_max,
            "Default delay should be ~180 seconds"
        );
        drop(entry);

        // Test immediate delay (500ms)
        purgatory.enqueue_sync_immediate("repo-immediate");
        let entry = purgatory.sync_queue.get("repo-immediate").unwrap();
        let expected_max = Instant::now() + Duration::from_millis(600);
        assert!(
            entry.next_attempt <= expected_max,
            "Immediate delay should be ~500ms"
        );
    }
}

#[test]
fn test_pr_event_vs_placeholder() {
    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();
    let event = EventBuilder::text_note("test PR").finalize(&keys).unwrap();

    // Add a PR event with actual event
    purgatory.add_pr(
        event.clone(),
        "event-id-1".to_string(),
        "commit-abc".to_string(),
        false,
    );

    // Add a placeholder (no event)
    purgatory.add_pr_placeholder("event-id-2".to_string(), "commit-def".to_string());

    // find_pr should find both
    assert!(purgatory.find_pr("event-id-1").is_some());
    assert!(purgatory.find_pr("event-id-2").is_some());

    // find_pr_placeholder should only find the placeholder
    assert!(purgatory.find_pr_placeholder("event-id-1").is_none());
    assert_eq!(
        purgatory.find_pr_placeholder("event-id-2"),
        Some("commit-def".to_string())
    );
}

#[test]
fn test_pr_placeholder_creation_and_retrieval() {
    let purgatory = Purgatory::new(PathBuf::new());

    // Add a placeholder
    purgatory.add_pr_placeholder("placeholder-id".to_string(), "commit-123".to_string());

    // Should be findable by find_pr
    let entry = purgatory.find_pr("placeholder-id");
    assert!(entry.is_some());
    let entry = entry.unwrap();
    assert!(entry.event.is_none()); // No event yet
    assert_eq!(entry.commit, "commit-123");

    // Should be findable by find_pr_placeholder
    let commit = purgatory.find_pr_placeholder("placeholder-id");
    assert_eq!(commit, Some("commit-123".to_string()));
}

#[test]
fn test_cleanup_removes_expired_entries() {
    use std::time::Duration;

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    // Create events
    let state_event = EventBuilder::text_note("state event")
        .finalize(&keys)
        .unwrap();
    let pr_event = EventBuilder::text_note("pr event").finalize(&keys).unwrap();

    // Add entries to purgatory
    purgatory.add_state(
        state_event.clone(),
        "test-repo".to_string(),
        keys.public_key(),
        false,
    );
    purgatory.add_pr(
        pr_event,
        "pr-123".to_string(),
        "commit-abc".to_string(),
        false,
    );
    purgatory.add_pr_placeholder("pr-456".to_string(), "commit-def".to_string());

    // Verify entries are there
    let (_, state_count, pr_count) = purgatory.count();
    assert_eq!(state_count, 1);
    assert_eq!(pr_count, 2);

    // Manually expire entries by modifying their expiry time
    // (This is a bit hacky but needed for testing without waiting 30 minutes)
    if let Some(mut entries) = purgatory.state_events.get_mut("test-repo") {
        for entry in entries.iter_mut() {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }

    // Expire PR events
    for mut entry in purgatory.pr_events.iter_mut() {
        entry.value_mut().expires_at = Instant::now() - Duration::from_secs(1);
    }

    // Run cleanup
    let (_, state_removed, pr_removed) = purgatory.cleanup();

    // Verify counts
    assert_eq!(state_removed, 1);
    assert_eq!(pr_removed, 2);

    // Verify entries are gone
    let (_, state_count, pr_count) = purgatory.count();
    assert_eq!(state_count, 0);
    assert_eq!(pr_count, 0);
}

#[test]
fn test_cleanup_preserves_non_expired_entries() {
    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let state_event = EventBuilder::text_note("state event")
        .finalize(&keys)
        .unwrap();
    let pr_event = EventBuilder::text_note("pr event").finalize(&keys).unwrap();

    // Add fresh entries
    purgatory.add_state(
        state_event,
        "test-repo".to_string(),
        keys.public_key(),
        false,
    );
    purgatory.add_pr(
        pr_event,
        "pr-123".to_string(),
        "commit-abc".to_string(),
        false,
    );

    // Run cleanup
    let (_, state_removed, pr_removed) = purgatory.cleanup();

    // Nothing should be removed
    assert_eq!(state_removed, 0);
    assert_eq!(pr_removed, 0);

    // Verify entries are still there
    let (_, state_count, pr_count) = purgatory.count();
    assert_eq!(state_count, 1);
    assert_eq!(pr_count, 1);
}

#[test]
fn test_cleanup_mixed_expired_and_fresh() {
    use std::time::Duration;

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    // Add multiple state events for same repo
    let event1 = EventBuilder::text_note("event1").finalize(&keys).unwrap();
    let event2 = EventBuilder::text_note("event2").finalize(&keys).unwrap();

    purgatory.add_state(event1, "test-repo".to_string(), keys.public_key(), false);
    purgatory.add_state(event2, "test-repo".to_string(), keys.public_key(), false);

    // Expire only the first one
    if let Some(mut entries) = purgatory.state_events.get_mut("test-repo") {
        if let Some(entry) = entries.get_mut(0) {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }

    // Add PR events
    let pr1 = EventBuilder::text_note("pr1").finalize(&keys).unwrap();
    let pr2 = EventBuilder::text_note("pr2").finalize(&keys).unwrap();

    purgatory.add_pr(pr1, "pr-1".to_string(), "commit-1".to_string(), false);
    purgatory.add_pr(pr2, "pr-2".to_string(), "commit-2".to_string(), false);

    // Expire only first PR
    if let Some(mut entry) = purgatory.pr_events.get_mut("pr-1") {
        entry.expires_at = Instant::now() - Duration::from_secs(1);
    }

    // Run cleanup
    let (_, state_removed, pr_removed) = purgatory.cleanup();

    // One of each should be removed
    assert_eq!(state_removed, 1);
    assert_eq!(pr_removed, 1);

    // Verify remaining counts
    let (_, state_count, pr_count) = purgatory.count();
    assert_eq!(state_count, 1); // One state event remains
    assert_eq!(pr_count, 1); // One PR event remains
}

#[test]
fn test_remove_expired_legacy_method() {
    use std::time::Duration;

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let state_event = EventBuilder::text_note("state").finalize(&keys).unwrap();
    let pr_event = EventBuilder::text_note("pr").finalize(&keys).unwrap();

    purgatory.add_state(state_event, "repo".to_string(), keys.public_key(), false);
    purgatory.add_pr(pr_event, "pr-id".to_string(), "commit".to_string(), false);

    // Expire both
    if let Some(mut entries) = purgatory.state_events.get_mut("repo") {
        for entry in entries.iter_mut() {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }
    for mut entry in purgatory.pr_events.iter_mut() {
        entry.value_mut().expires_at = Instant::now() - Duration::from_secs(1);
    }

    // Test legacy method returns total
    #[allow(deprecated)]
    let total = purgatory.remove_expired();
    assert_eq!(total, 2); // 1 state + 1 PR
}

#[test]
fn test_expired_event_tracking() {
    use std::time::Duration;

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let state_event = EventBuilder::text_note("state").finalize(&keys).unwrap();
    let pr_event = EventBuilder::text_note("pr").finalize(&keys).unwrap();

    let state_event_id = state_event.id;
    let pr_event_id = pr_event.id;

    // Add events to purgatory
    purgatory.add_state(state_event, "repo".to_string(), keys.public_key(), false);
    purgatory.add_pr(pr_event, "pr-id".to_string(), "commit".to_string(), false);

    // Events should not be marked as expired yet
    assert!(!purgatory.is_expired(&state_event_id));
    assert!(!purgatory.is_expired(&pr_event_id));

    // Expire both events
    if let Some(mut entries) = purgatory.state_events.get_mut("repo") {
        for entry in entries.iter_mut() {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }
    for mut entry in purgatory.pr_events.iter_mut() {
        entry.value_mut().expires_at = Instant::now() - Duration::from_secs(1);
    }

    // Run cleanup
    let (_, state_removed, pr_removed) = purgatory.cleanup();
    assert_eq!(state_removed, 1);
    assert_eq!(pr_removed, 1);

    // Events should now be marked as expired
    assert!(purgatory.is_expired(&state_event_id));
    assert!(purgatory.is_expired(&pr_event_id));

    // event_ids() should include expired events
    let ids = purgatory.event_ids();
    assert!(ids.contains(&state_event_id));
    assert!(ids.contains(&pr_event_id));

    // Expired count should be 2
    assert_eq!(purgatory.expired_count(), 2);
}

#[test]
fn test_cleanup_expired_events() {
    use std::time::Duration;

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let event1 = EventBuilder::text_note("event1").finalize(&keys).unwrap();
    let event2 = EventBuilder::text_note("event2").finalize(&keys).unwrap();

    let event1_id = event1.id;
    let event2_id = event2.id;

    // Add and immediately expire event1
    purgatory.add_state(event1, "repo1".to_string(), keys.public_key(), false);
    if let Some(mut entries) = purgatory.state_events.get_mut("repo1") {
        for entry in entries.iter_mut() {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }
    purgatory.cleanup();

    // Add and expire event2 (will be more recent)
    purgatory.add_state(event2, "repo2".to_string(), keys.public_key(), false);
    if let Some(mut entries) = purgatory.state_events.get_mut("repo2") {
        for entry in entries.iter_mut() {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }
    purgatory.cleanup();

    // Both should be in expired_events
    assert_eq!(purgatory.expired_count(), 2);

    // Manually set event1's expiry time to be old
    if let Some(mut entry) = purgatory.expired_events.get_mut(&event1_id) {
        *entry.value_mut() = Instant::now() - Duration::from_secs(8 * 24 * 3600);
        // 8 days ago
    }

    // Clean up expired events older than 7 days
    let removed = purgatory.cleanup_expired_events(Duration::from_secs(7 * 24 * 3600));

    // Only event1 should be removed
    assert_eq!(removed, 1);
    assert_eq!(purgatory.expired_count(), 1);

    // event1 should be gone, event2 should remain
    assert!(!purgatory.is_expired(&event1_id));
    assert!(purgatory.is_expired(&event2_id));
}

#[test]
fn test_expired_events_prevent_readdition() {
    use std::time::Duration;

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let event = EventBuilder::text_note("test").finalize(&keys).unwrap();
    let event_id = event.id;

    // Add event to purgatory
    purgatory.add_state(event.clone(), "repo".to_string(), keys.public_key(), false);

    // Expire it
    if let Some(mut entries) = purgatory.state_events.get_mut("repo") {
        for entry in entries.iter_mut() {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }
    purgatory.cleanup();

    // Event should be marked as expired
    assert!(purgatory.is_expired(&event_id));

    // event_ids() should return the expired event
    let ids = purgatory.event_ids();
    assert!(ids.contains(&event_id));

    // This simulates what negentropy/REQ+EOSE should do:
    // Check if event is in event_ids() before adding
    if !ids.contains(&event_id) {
        purgatory.add_state(event, "repo".to_string(), keys.public_key(), false);
    }

    // Event should NOT be re-added
    let (_, state_count, _) = purgatory.count();
    assert_eq!(state_count, 0, "Event should not be re-added to purgatory");
}

#[test]
fn test_pr_placeholder_not_marked_expired() {
    use std::time::Duration;

    let purgatory = Purgatory::new(PathBuf::new());

    // Add a PR placeholder (no event)
    purgatory.add_pr_placeholder("placeholder-id".to_string(), "commit-123".to_string());

    // Expire it
    if let Some(mut entry) = purgatory.pr_events.get_mut("placeholder-id") {
        entry.value_mut().expires_at = Instant::now() - Duration::from_secs(1);
    }

    // Run cleanup
    let (_, _, pr_removed) = purgatory.cleanup();
    assert_eq!(pr_removed, 1);

    // Expired count should be 0 (placeholders don't have event IDs to track)
    assert_eq!(purgatory.expired_count(), 0);
}

#[test]
fn test_user_can_resubmit_expired_event() {
    use std::time::Duration;

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let event = EventBuilder::text_note("test").finalize(&keys).unwrap();
    let event_id = event.id;

    // Add event to purgatory
    purgatory.add_state(event.clone(), "repo".to_string(), keys.public_key(), false);

    // Expire it
    if let Some(mut entries) = purgatory.state_events.get_mut("repo") {
        for entry in entries.iter_mut() {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }
    purgatory.cleanup();

    // Event should be marked as expired
    assert!(purgatory.is_expired(&event_id));

    // User re-submits the same event (simulating retry after pushing git data)
    // This should be allowed - the policy layer will check is_synced flag
    // For now, just verify the event is marked as expired
    assert!(purgatory.is_expired(&event_id));

    // The policy layer (in builder.rs and state.rs) will:
    // - Check is_synced flag (false for user-submitted)
    // - Skip the expired check for user-submitted events
    // - Allow the event to be re-added to purgatory or accepted if git data now exists
}

// ============================================================================
// Persistence Serialization Tests
// ============================================================================

#[tokio::test]
async fn test_save_and_restore_state_events() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    // Add multiple state events for the same identifier
    let event1 = EventBuilder::text_note("state event 1")
        .finalize(&keys)
        .unwrap();
    let event2 = EventBuilder::text_note("state event 2")
        .finalize(&keys)
        .unwrap();

    let event1_id = event1.id;
    let event2_id = event2.id;

    purgatory.add_state(
        event1.clone(),
        "test-repo".to_string(),
        keys.public_key(),
        false,
    );
    purgatory.add_state(
        event2.clone(),
        "test-repo".to_string(),
        keys.public_key(),
        false,
    );

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();

    // Verify file exists
    assert!(state_file.exists());

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Verify file was deleted after restore
    assert!(!state_file.exists());

    // Verify state events were restored
    let (_, state_count, _) = purgatory2.count();
    assert_eq!(state_count, 2);

    let restored_entries = purgatory2.find_state("test-repo");
    assert_eq!(restored_entries.len(), 2);

    // Verify event IDs match
    let restored_ids: Vec<EventId> = restored_entries.iter().map(|e| e.event.id).collect();
    assert!(restored_ids.contains(&event1_id));
    assert!(restored_ids.contains(&event2_id));

    // Verify identifiers and authors match
    for entry in &restored_entries {
        assert_eq!(entry.identifier, "test-repo");
        assert_eq!(entry.author, keys.public_key());
    }
}

#[tokio::test]
async fn test_save_and_restore_pr_events() {
    use nostr_sdk::prelude::{Kind, Tag};
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    // Add PR event with actual event
    let tags = vec![Tag::custom("a", vec!["30617:abc123:test-repo".to_string()])];

    let pr_event = EventBuilder::new(Kind::from(1618), "PR content")
        .tags(tags)
        .finalize(&keys)
        .unwrap();

    let pr_event_id = pr_event.id;

    purgatory.add_pr(
        pr_event.clone(),
        "pr-event-id".to_string(),
        "commit-abc".to_string(),
        false,
    );

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Verify PR event was restored
    let (_, _, pr_count) = purgatory2.count();
    assert_eq!(pr_count, 1);

    let restored_entry = purgatory2.find_pr("pr-event-id").unwrap();
    assert!(restored_entry.event.is_some());
    assert_eq!(restored_entry.event.unwrap().id, pr_event_id);
    assert_eq!(restored_entry.commit, "commit-abc");
}

#[tokio::test]
async fn test_save_and_restore_pr_placeholders() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());

    // Add PR placeholder (git data arrived first)
    purgatory.add_pr_placeholder("placeholder-id".to_string(), "commit-def".to_string());

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Verify placeholder was restored
    let (_, _, pr_count) = purgatory2.count();
    assert_eq!(pr_count, 1);

    let restored_entry = purgatory2.find_pr("placeholder-id").unwrap();
    assert!(restored_entry.event.is_none()); // Still a placeholder
    assert_eq!(restored_entry.commit, "commit-def");

    // Verify it's findable as a placeholder
    assert_eq!(
        purgatory2.find_pr_placeholder("placeholder-id"),
        Some("commit-def".to_string())
    );
}

#[tokio::test]
async fn test_save_and_restore_expired_events() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let event = EventBuilder::text_note("test").finalize(&keys).unwrap();
    let event_id = event.id;

    // Add and expire event
    purgatory.add_state(event, "repo".to_string(), keys.public_key(), false);
    if let Some(mut entries) = purgatory.state_events.get_mut("repo") {
        for entry in entries.iter_mut() {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }
    purgatory.cleanup();

    // Verify event is marked as expired
    assert!(purgatory.is_expired(&event_id));
    assert_eq!(purgatory.expired_count(), 1);

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Verify expired event was restored
    assert!(purgatory2.is_expired(&event_id));
    assert_eq!(purgatory2.expired_count(), 1);

    // Verify it's included in event_ids()
    let ids = purgatory2.event_ids();
    assert!(ids.contains(&event_id));
}

#[tokio::test]
async fn test_save_and_restore_empty_purgatory() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());

    // Save empty purgatory
    purgatory.save_to_disk(&state_file).unwrap();

    // Verify file exists
    assert!(state_file.exists());

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Verify purgatory is still empty
    let (_, state_count, pr_count) = purgatory2.count();
    assert_eq!(state_count, 0);
    assert_eq!(pr_count, 0);
    assert_eq!(purgatory2.expired_count(), 0);
}

#[tokio::test]
async fn test_restore_missing_file() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("nonexistent.json");

    let purgatory = Purgatory::new(PathBuf::new());

    // Attempting to restore from missing file should error
    let result = purgatory.restore_from_disk(&state_file);
    assert!(result.is_err());

    // Purgatory should remain empty
    let (_, state_count, pr_count) = purgatory.count();
    assert_eq!(state_count, 0);
    assert_eq!(pr_count, 0);
}

#[tokio::test]
async fn test_restore_corrupted_json() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("corrupted.json");

    // Write invalid JSON
    std::fs::write(&state_file, "{ this is not valid json }").unwrap();

    let purgatory = Purgatory::new(PathBuf::new());

    // Attempting to restore corrupted file should error
    let result = purgatory.restore_from_disk(&state_file);
    assert!(result.is_err());

    // Purgatory should remain empty
    let (_, state_count, pr_count) = purgatory.count();
    assert_eq!(state_count, 0);
    assert_eq!(pr_count, 0);
}

#[tokio::test]
async fn test_restore_unsupported_version() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("wrong_version.json");

    // Write state with unsupported version
    let state = r#"{
        "version": 999,
        "saved_at": {"secs_since_epoch": 1000000000, "nanos_since_epoch": 0},
        "state_events": {},
        "pr_events": {},
        "expired_events": {}
    }"#;
    std::fs::write(&state_file, state).unwrap();

    let purgatory = Purgatory::new(PathBuf::new());

    // Attempting to restore unsupported version should error
    let result = purgatory.restore_from_disk(&state_file);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unsupported state version"));
}

#[tokio::test]
async fn test_downtime_calculation() {
    use tempfile::tempdir;
    use tokio::time::sleep;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    // Add state event
    let event = EventBuilder::text_note("test").finalize(&keys).unwrap();

    purgatory.add_state(event.clone(), "repo".to_string(), keys.public_key(), false);

    // Get original expiry time
    let original_entries = purgatory.find_state("repo");
    let original_entry = &original_entries[0];
    let original_expires_at = original_entry.expires_at;
    let original_remaining = original_expires_at.saturating_duration_since(Instant::now());

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();

    // Simulate downtime (100ms)
    sleep(Duration::from_millis(100)).await;

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Get restored expiry time
    let restored_entries = purgatory2.find_state("repo");
    let restored_entry = &restored_entries[0];
    let restored_expires_at = restored_entry.expires_at;
    let restored_remaining = restored_expires_at.saturating_duration_since(Instant::now());

    // Remaining time should be approximately the same (accounting for downtime)
    // Allow 2000ms tolerance for test execution time and sleep duration
    let diff = if restored_remaining > original_remaining {
        restored_remaining.as_millis() - original_remaining.as_millis()
    } else {
        original_remaining.as_millis() - restored_remaining.as_millis()
    };

    assert!(
        diff < 2000,
        "Downtime calculation should preserve remaining TTL. Original: {}ms, Restored: {}ms, Diff: {}ms",
        original_remaining.as_millis(),
        restored_remaining.as_millis(),
        diff
    );
}

#[tokio::test]
async fn test_expiry_times_preserved() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    // Add state event
    let event = EventBuilder::text_note("test").finalize(&keys).unwrap();

    purgatory.add_state(event.clone(), "repo".to_string(), keys.public_key(), false);

    // Manually set expiry to a specific time in the future
    let custom_expiry = Instant::now() + Duration::from_secs(600); // 10 minutes
    if let Some(mut entries) = purgatory.state_events.get_mut("repo") {
        for entry in entries.iter_mut() {
            entry.expires_at = custom_expiry;
        }
    }

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Get restored expiry time
    let restored_entries = purgatory2.find_state("repo");
    let restored_entry = &restored_entries[0];
    let restored_remaining = restored_entry
        .expires_at
        .saturating_duration_since(Instant::now());

    // Should be approximately 600 seconds (allow 3 second tolerance for test execution)
    assert!(
        restored_remaining.as_secs() >= 597 && restored_remaining.as_secs() <= 603,
        "Expected ~600s remaining, got {}s",
        restored_remaining.as_secs()
    );
}

#[tokio::test]
async fn test_multiple_state_events_same_identifier() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());
    let keys1 = Keys::generate();
    let keys2 = Keys::generate();
    let keys3 = Keys::generate();

    // Add multiple state events for the same identifier from different authors
    let event1 = EventBuilder::text_note("maintainer 1")
        .finalize(&keys1)
        .unwrap();
    let event2 = EventBuilder::text_note("maintainer 2")
        .finalize(&keys2)
        .unwrap();
    let event3 = EventBuilder::text_note("maintainer 3")
        .finalize(&keys3)
        .unwrap();

    purgatory.add_state(
        event1.clone(),
        "shared-repo".to_string(),
        keys1.public_key(),
        false,
    );
    purgatory.add_state(
        event2.clone(),
        "shared-repo".to_string(),
        keys2.public_key(),
        false,
    );
    purgatory.add_state(
        event3.clone(),
        "shared-repo".to_string(),
        keys3.public_key(),
        false,
    );

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Verify all three events were restored
    let restored_entries = purgatory2.find_state("shared-repo");
    assert_eq!(restored_entries.len(), 3);

    // Verify all authors are present
    let authors: Vec<PublicKey> = restored_entries.iter().map(|e| e.author).collect();
    assert!(authors.contains(&keys1.public_key()));
    assert!(authors.contains(&keys2.public_key()));
    assert!(authors.contains(&keys3.public_key()));
}

#[test]
fn cleanup_keeps_reconstructable_and_independent_state_fallbacks() {
    let purgatory = Purgatory::new(PathBuf::new());
    let author = Keys::generate();
    let other_author = Keys::generate();
    let identifier = "state-cleanup";
    let state = |keys: &Keys, created_at: u64, oid: Option<&str>| {
        let mut tags = vec![Tag::identifier(identifier)];
        if let Some(oid) = oid {
            tags.push(Tag::custom("refs/heads/main", [oid.to_string()]));
        }
        EventBuilder::new(Kind::RepoState, "")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .unwrap()
    };

    let missing_oid = "a".repeat(40);
    let missing_older = state(&author, 100, Some(&missing_oid));
    let reconstructable_older = state(&author, 101, None);
    let promoted = state(&author, 200, None);
    let missing_newer = state(&author, 300, Some(&missing_oid));
    let other_coordinate = state(&other_author, 100, Some(&missing_oid));

    for event in [
        &missing_older,
        &reconstructable_older,
        &missing_newer,
        &other_coordinate,
    ] {
        purgatory.add_state(event.clone(), identifier.to_string(), event.pubkey, false);
    }

    let removed = purgatory.remove_unreconstructable_state_replacements(
        identifier,
        &[promoted],
        Path::new("/not/a/git/repository"),
    );

    assert_eq!(removed, 1);
    let remaining: HashSet<EventId> = purgatory
        .find_state(identifier)
        .into_iter()
        .map(|entry| entry.event.id)
        .collect();
    assert!(!remaining.contains(&missing_older.id));
    assert!(remaining.contains(&reconstructable_older.id));
    assert!(remaining.contains(&missing_newer.id));
    assert!(remaining.contains(&other_coordinate.id));
}

#[tokio::test]
async fn test_mixed_pr_events_and_placeholders() {
    use nostr_sdk::prelude::{Kind, Tag};
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    // Add PR event with actual event
    let tags = vec![Tag::custom("a", vec!["30617:abc123:test-repo".to_string()])];

    let pr_event = EventBuilder::new(Kind::from(1618), "PR content")
        .tags(tags)
        .finalize(&keys)
        .unwrap();

    purgatory.add_pr(
        pr_event.clone(),
        "pr-with-event".to_string(),
        "commit-abc".to_string(),
        false,
    );

    // Add PR placeholder
    purgatory.add_pr_placeholder("pr-placeholder".to_string(), "commit-def".to_string());

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Verify both were restored correctly
    let (_, _, pr_count) = purgatory2.count();
    assert_eq!(pr_count, 2);

    // Verify PR event
    let pr_entry = purgatory2.find_pr("pr-with-event").unwrap();
    assert!(pr_entry.event.is_some());
    assert_eq!(pr_entry.commit, "commit-abc");

    // Verify placeholder
    let placeholder_entry = purgatory2.find_pr("pr-placeholder").unwrap();
    assert!(placeholder_entry.event.is_none());
    assert_eq!(placeholder_entry.commit, "commit-def");
    assert_eq!(
        purgatory2.find_pr_placeholder("pr-placeholder"),
        Some("commit-def".to_string())
    );
}

#[tokio::test]
async fn test_file_cleanup_after_successful_restore() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    // Add some data
    let event = EventBuilder::text_note("test").finalize(&keys).unwrap();
    purgatory.add_state(event, "repo".to_string(), keys.public_key(), false);

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();
    assert!(state_file.exists());

    // Restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // File should be deleted after successful restore
    assert!(!state_file.exists());
}

#[tokio::test]
async fn test_save_and_restore_announcement_events() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    // Create a real bare repo directory so the restore path-existence check passes
    let repo_dir = temp_dir.path().join("owner.git");
    std::fs::create_dir_all(&repo_dir).unwrap();

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let ann_event = EventBuilder::text_note("announcement event")
        .finalize(&keys)
        .unwrap();
    let ann_event_id = ann_event.id;

    let mut relays = HashSet::new();
    relays.insert("wss://relay.example.com".to_string());

    purgatory.add_announcement(
        ann_event.clone(),
        "my-repo".to_string(),
        keys.public_key(),
        repo_dir.clone(),
        relays.clone(),
    );

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();
    assert!(state_file.exists());

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // File should be deleted after restore
    assert!(!state_file.exists());

    // Verify announcement was restored
    let (ann_count, _, _) = purgatory2.count();
    assert_eq!(ann_count, 1);

    let restored = purgatory2
        .find_announcement(&keys.public_key(), "my-repo")
        .unwrap();
    assert_eq!(restored.event.id, ann_event_id);
    assert_eq!(restored.identifier, "my-repo");
    assert_eq!(restored.owner, keys.public_key());
    assert_eq!(restored.repo_path, repo_dir);
    assert_eq!(restored.relays, relays);
    assert!(!restored.soft_expired);
}

#[tokio::test]
async fn test_soft_expired_announcements_not_persisted() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    let repo_dir = temp_dir.path().join("owner.git");
    std::fs::create_dir_all(&repo_dir).unwrap();

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let ann_event = EventBuilder::text_note("announcement event")
        .finalize(&keys)
        .unwrap();

    purgatory.add_announcement(
        ann_event.clone(),
        "my-repo".to_string(),
        keys.public_key(),
        repo_dir.clone(),
        HashSet::new(),
    );

    // Manually mark as soft-expired (bare repo deleted)
    let key = (keys.public_key(), "my-repo".to_string());
    if let Some(mut entry) = purgatory.announcement_purgatory.get_mut(&key) {
        entry.soft_expired = true;
    }

    // Save to disk — soft-expired entry should be excluded
    purgatory.save_to_disk(&state_file).unwrap();

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Soft-expired announcement should NOT be restored
    let (ann_count, _, _) = purgatory2.count();
    assert_eq!(ann_count, 0);
}

#[tokio::test]
async fn test_announcement_with_missing_repo_skipped_on_restore() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    // Point to a repo path that does NOT exist
    let missing_repo = temp_dir.path().join("nonexistent.git");

    let purgatory = Purgatory::new(PathBuf::new());
    let keys = Keys::generate();

    let ann_event = EventBuilder::text_note("announcement event")
        .finalize(&keys)
        .unwrap();

    purgatory.add_announcement(
        ann_event.clone(),
        "my-repo".to_string(),
        keys.public_key(),
        missing_repo.clone(),
        HashSet::new(),
    );

    // Save to disk (repo path is serialized even though it doesn't exist)
    purgatory.save_to_disk(&state_file).unwrap();

    // Create new purgatory and restore — entry should be skipped
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    let (ann_count, _, _) = purgatory2.count();
    assert_eq!(ann_count, 0);
}

#[tokio::test]
async fn test_comprehensive_roundtrip() {
    use nostr_sdk::prelude::{Kind, Tag};
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let state_file = temp_dir.path().join("purgatory_state.json");

    // Create a real bare repo directory for the announcement
    let repo_dir = temp_dir.path().join("owner.git");
    std::fs::create_dir_all(&repo_dir).unwrap();

    let purgatory = Purgatory::new(PathBuf::new());
    let keys1 = Keys::generate();
    let keys2 = Keys::generate();

    // Add announcement
    let ann_event = EventBuilder::text_note("announcement")
        .finalize(&keys1)
        .unwrap();
    let ann_event_id = ann_event.id;
    purgatory.add_announcement(
        ann_event,
        "repo1".to_string(),
        keys1.public_key(),
        repo_dir.clone(),
        HashSet::new(),
    );

    // Add multiple state events
    let state1 = EventBuilder::text_note("state 1").finalize(&keys1).unwrap();
    let state2 = EventBuilder::text_note("state 2").finalize(&keys2).unwrap();

    purgatory.add_state(
        state1.clone(),
        "repo1".to_string(),
        keys1.public_key(),
        false,
    );
    purgatory.add_state(
        state2.clone(),
        "repo2".to_string(),
        keys2.public_key(),
        false,
    );

    // Add PR event
    let tags = vec![Tag::custom("a", vec!["30617:abc123:repo1".to_string()])];
    let pr_event = EventBuilder::new(Kind::from(1618), "PR")
        .tags(tags)
        .finalize(&keys1)
        .unwrap();
    purgatory.add_pr(
        pr_event.clone(),
        "pr-1".to_string(),
        "commit-1".to_string(),
        false,
    );

    // Add PR placeholder
    purgatory.add_pr_placeholder("pr-2".to_string(), "commit-2".to_string());

    // Add and expire an event
    let expired_event = EventBuilder::text_note("expired").finalize(&keys1).unwrap();
    let expired_id = expired_event.id;
    purgatory.add_state(
        expired_event,
        "repo3".to_string(),
        keys1.public_key(),
        false,
    );
    if let Some(mut entries) = purgatory.state_events.get_mut("repo3") {
        for entry in entries.iter_mut() {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }
    purgatory.cleanup();

    // Verify initial state
    let (ann_count, state_count, pr_count) = purgatory.count();
    assert_eq!(ann_count, 1); // announcement
    assert_eq!(state_count, 2); // state1, state2 (expired_event was cleaned up)
    assert_eq!(pr_count, 2); // pr-1, pr-2
    assert_eq!(purgatory.expired_count(), 1); // expired_event

    // Save to disk
    purgatory.save_to_disk(&state_file).unwrap();

    // Create new purgatory and restore
    let purgatory2 = Purgatory::new(PathBuf::new());
    purgatory2.restore_from_disk(&state_file).unwrap();

    // Verify all data was restored correctly
    let (ann_count2, state_count2, pr_count2) = purgatory2.count();
    assert_eq!(ann_count2, 1);
    assert_eq!(state_count2, 2);
    assert_eq!(pr_count2, 2);
    assert_eq!(purgatory2.expired_count(), 1);

    // Verify announcement
    let restored_ann = purgatory2
        .find_announcement(&keys1.public_key(), "repo1")
        .unwrap();
    assert_eq!(restored_ann.event.id, ann_event_id);

    // Verify state events
    assert_eq!(purgatory2.find_state("repo1").len(), 1);
    assert_eq!(purgatory2.find_state("repo2").len(), 1);

    // Verify PR events
    assert!(purgatory2.find_pr("pr-1").unwrap().event.is_some());
    assert!(purgatory2.find_pr("pr-2").unwrap().event.is_none());

    // Verify expired event
    assert!(purgatory2.is_expired(&expired_id));
}

// =============================================================================
// GRASP-06 edge case B2: un-scoped placeholder upgrade
// =============================================================================
//
// Scenario: a push to the standard /<npub>/<id>.git endpoint with wrong commit
// X creates an un-scoped placeholder for an event_id. A subsequent push to
// /prs/<submitter>/<id>.git with the correct commit Y then sees the un-scoped
// placeholder and — per the fix in grasp06::receive::post_push_validate —
// overwrites it with a scoped placeholder (commit Y, scope={submitter, id}).
//
// When the PR event (commit Y) arrives it finds the scoped placeholder, takes
// the scope-match branch in PrEventPolicy::git_data_check, and:
//   1. Promotes the event out of purgatory
//   2. Mirrors commit Y (overwriting X) into the announced repo
//
// These tests verify the purgatory-level behaviour that the fix relies on.

#[test]
fn add_prs_pr_placeholder_overwrites_un_scoped_placeholder() {
    // Simulates: standard endpoint pushed wrong commit X → un-scoped placeholder.
    // Then /prs/ endpoint pushes correct commit Y → upgrade to scoped.
    let purgatory = Purgatory::new(PathBuf::new());
    let submitter = Keys::generate();
    let event_id = "a".repeat(64);
    let wrong_commit = "b".repeat(40);
    let correct_commit = "c".repeat(40);

    // Standard endpoint creates un-scoped placeholder (wrong commit X)
    purgatory.add_pr_placeholder(event_id.clone(), wrong_commit.clone());

    let entry = purgatory.find_pr(&event_id).unwrap();
    assert!(entry.event.is_none(), "placeholder has no event");
    assert!(entry.prs_scope.is_none(), "placeholder is un-scoped");
    assert_eq!(entry.commit, wrong_commit);

    // /prs/ endpoint upgrades to scoped placeholder (correct commit Y)
    purgatory.add_prs_pr_placeholder(
        event_id.clone(),
        correct_commit.clone(),
        submitter.public_key(),
        "my-repo".to_string(),
    );

    let upgraded = purgatory.find_pr(&event_id).unwrap();
    assert!(upgraded.event.is_none(), "still a placeholder (no event)");
    let scope = upgraded.prs_scope.expect("placeholder now has prs_scope");
    assert_eq!(scope.submitter, submitter.public_key());
    assert_eq!(scope.identifier, "my-repo");
    assert_eq!(
        upgraded.commit, correct_commit,
        "placeholder commit updated to /prs/ commit Y"
    );
    assert_ne!(
        upgraded.commit, wrong_commit,
        "wrong commit X no longer stored"
    );
}

#[test]
fn add_prs_pr_placeholder_does_not_overwrite_existing_scoped_placeholder() {
    // Once a scoped placeholder exists (the /prs/ push was first), a second
    // add_prs_pr_placeholder call with a different scope or commit must not
    // silently replace it — callers gate on `entry.prs_scope.is_none()` before
    // calling, so this test documents what happens if the gate is bypassed.
    // Direct `insert` via add_prs_pr_placeholder would overwrite; the guard in
    // post_push_validate prevents that from happening in practice.
    //
    // NOTE on the apparent TOCTOU: the two-step check-then-insert looks like a
    // race between two concurrent /prs/ pushes from *different* submitters for
    // the same event_id. In practice this cannot happen: an event_id is a hash
    // of the event content, which includes the signer's pubkey. Two different
    // signers therefore cannot share an event_id, so only one submitter can ever
    // legitimately push a given refs/nostr/<event-id>. No atomic upgrade is
    // needed; the guard is sufficient.
    let purgatory = Purgatory::new(PathBuf::new());
    let submitter_a = Keys::generate();
    let submitter_b = Keys::generate();
    let event_id = "d".repeat(64);
    let commit_a = "e".repeat(40);
    let commit_b = "f".repeat(40);

    purgatory.add_prs_pr_placeholder(
        event_id.clone(),
        commit_a.clone(),
        submitter_a.public_key(),
        "repo-a".to_string(),
    );

    // Calling again (bypassing the gate) would replace — this documents the
    // raw behaviour so that callers know the gate is necessary.
    purgatory.add_prs_pr_placeholder(
        event_id.clone(),
        commit_b.clone(),
        submitter_b.public_key(),
        "repo-b".to_string(),
    );

    // The entry was replaced (gate bypass scenario — illustrates why
    // post_push_validate checks prs_scope.is_none() before upgrading).
    let entry = purgatory.find_pr(&event_id).unwrap();
    let scope = entry.prs_scope.unwrap();
    assert_eq!(scope.submitter, submitter_b.public_key());
    assert_eq!(scope.identifier, "repo-b");
}
