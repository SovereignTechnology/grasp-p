//! Self-Subscriber for Proactive Sync
//!
//! Monitors the relay's own database for repository announcements and
//! updates the RepoSyncIndex when new relevant events are discovered.
//!
//! This module subscribes to relevant event kinds on our own relay and
//! batches updates before sending them to the SyncManager.
//!
//! See `docs/explanation/grasp-02-proactive-sync.md` for full design details.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use futures_util::StreamExt;
use nostr_sdk::prelude::Timestamp;
use nostr_sdk::prelude::*;
use tokio::sync::{broadcast, mpsc};

use crate::nostr::SharedDatabase;

use super::{AddFilters, RepoSyncIndex, RepoSyncNeeds, SyncLevel};

/// Counts remain complete while remotely influenced log samples stay bounded.
const LOG_COLLECTION_SAMPLE_SIZE: usize = 5;

// =============================================================================
// LoopControl - Result of notification processing
// =============================================================================

/// Control flow result from processing a notification
enum LoopControl {
    /// Continue processing the next notification
    Continue,
    /// Break out of the event loop
    Break,
}

// =============================================================================
// PendingUpdates - Accumulator for batching
// =============================================================================

/// Accumulates updates between batch timer firings
struct PendingUpdates {
    /// Repos discovered since last batch, keyed by repo addressable ref
    repos: HashMap<String, RepoSyncNeeds>,
    /// Latest announcement relay set for each addressable repository.
    ///
    /// Root events add work without changing ownership. Announcements replace
    /// relay ownership, so keeping that distinction prevents obsolete URLs
    /// from becoming permanent members of the sync index.
    relay_replacements: HashMap<String, HashSet<String>>,
}

impl PendingUpdates {
    /// Create a new empty pending updates accumulator
    fn new() -> Self {
        Self {
            repos: HashMap::new(),
            relay_replacements: HashMap::new(),
        }
    }

    /// Record the latest addressable announcement for a repository.
    fn replace_announcement_relays(&mut self, repo_id: String, relays: HashSet<String>) {
        let entry = self
            .repos
            .entry(repo_id.clone())
            .or_insert_with(|| RepoSyncNeeds {
                relays: HashSet::new(),
                root_events: HashSet::new(),
                sync_level: SyncLevel::Full,
            });
        entry.relays = relays.clone();
        self.relay_replacements.insert(repo_id, relays);
    }

    /// Add root-event work without changing announcement relay ownership.
    fn add_root_event(&mut self, repo_id: String, relays: HashSet<String>, event_id: EventId) {
        let entry = self
            .repos
            .entry(repo_id.clone())
            .or_insert_with(|| RepoSyncNeeds {
                relays: HashSet::new(),
                root_events: HashSet::new(),
                sync_level: SyncLevel::Full,
            });
        if !self.relay_replacements.contains_key(&repo_id) {
            entry.relays.extend(relays);
        }
        entry.root_events.insert(event_id);
    }

    /// Check if there are any pending updates
    fn is_empty(&self) -> bool {
        self.repos.is_empty()
    }

    /// Take all pending updates, leaving empty
    fn take(
        &mut self,
    ) -> (
        HashMap<String, RepoSyncNeeds>,
        HashMap<String, HashSet<String>>,
    ) {
        (
            std::mem::take(&mut self.repos),
            std::mem::take(&mut self.relay_replacements),
        )
    }
}

fn dirty_relays(updates: &HashMap<String, RepoSyncNeeds>) -> HashSet<String> {
    updates
        .values()
        .flat_map(|needs| needs.relays.iter().cloned())
        .collect()
}

// =============================================================================
// SelfSubscriber - Main Component
// =============================================================================

/// Subscribes to own relay's events to discover repos needing sync
///
/// The SelfSubscriber connects to our own relay and monitors for:
/// - 30617 (Repository Announcements) - to discover repos listing our relay
/// - 1617 (Patches) - root events referencing repos
/// - 1618 (Issues) - root events referencing repos
/// - 1621 (PRs) - root events referencing repos
///
/// Note: 30618 is NOT subscribed to here (per v4 spec - only synced from remote relays)
pub struct SelfSubscriber {
    /// Our own relay URL (to connect to)
    own_relay_url: String,
    /// Our service domain (for filtering relevant repos)
    relay_domain: String,
    /// Shared index of repos to sync
    repo_sync_index: RepoSyncIndex,
    /// Channel to send AddFilters actions to SyncManager
    action_tx: mpsc::Sender<AddFilters>,
    /// Last time we connected - used for since filter on reconnect
    last_connected: Option<Timestamp>,
    /// Database for querying existing events on startup
    database: SharedDatabase,
}

impl SelfSubscriber {
    /// Create a new SelfSubscriber
    ///
    /// # Arguments
    /// * `own_relay_url` - The WebSocket URL of our own relay
    /// * `relay_domain` - Our service domain (used for filtering relevant repos)
    /// * `repo_sync_index` - Shared index to update with discovered repos
    /// * `action_tx` - Channel to send AddFilters actions to the SyncManager
    /// * `database` - Database for querying existing events on startup
    pub fn new(
        own_relay_url: String,
        relay_domain: String,
        repo_sync_index: RepoSyncIndex,
        action_tx: mpsc::Sender<AddFilters>,
        database: SharedDatabase,
    ) -> Self {
        Self {
            own_relay_url,
            relay_domain,
            repo_sync_index,
            action_tx,
            last_connected: None,
            database,
        }
    }

    /// Get batch window from environment or use default
    ///
    /// When `NGIT_TEST=1` is set, uses 200ms for faster test execution.
    /// Default: 5000ms (5 seconds)
    fn get_batch_window() -> Duration {
        if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
            Duration::from_millis(200)
        } else {
            Duration::from_millis(5000)
        }
    }

    /// Load existing events from database on startup
    ///
    /// Queries the database with two separate queries to build the initial
    /// PendingUpdates state. This ensures all repos get Layer 2/3 filters
    /// created, not just those returned by the WebSocket subscription
    /// (which has limits on the number of events returned).
    ///
    /// Query order:
    /// 1. First query: Get announcements (30617) to populate repo_sync_index
    ///    with repos and their relays
    /// 2. Second query: Get root events (1617/1618/1621) for handle_root_event()
    ///    to add root event IDs for Layer 3 filter creation
    ///
    /// Returns a PendingUpdates containing all repos that need Layer 2/3 filters.
    async fn load_existing_events(&self) -> PendingUpdates {
        let mut pending = PendingUpdates::new();

        tracing::info!("Loading all events from database");

        // First query: Get all announcements to populate repo_sync_index
        let announcement_filter = Filter::new().kind(Kind::GitRepoAnnouncement);

        let announcements = match self.database.query(announcement_filter).await {
            Ok(events) => {
                tracing::info!(count = events.len(), "Loaded announcements from database");
                events
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Failed to query announcements from database"
                );
                return pending;
            }
        };

        // Process announcements
        let mut announcements_loaded = 0;
        for event in announcements.iter() {
            if let Some(repo_id) = Self::extract_repo_id(event) {
                let relays = Self::extract_relay_urls(event);
                pending.replace_announcement_relays(repo_id, relays);
                announcements_loaded += 1;
            }
        }

        // Update repo_sync_index with announcements BEFORE querying root events
        {
            let mut index = self.repo_sync_index.write().await;
            for (repo_id, needs) in &pending.repos {
                let entry = index
                    .entry(repo_id.clone())
                    .or_insert_with(|| RepoSyncNeeds {
                        relays: HashSet::new(),
                        root_events: HashSet::new(),
                        sync_level: SyncLevel::StateOnly,
                    });
                entry.relays.extend(needs.relays.clone());
            }
        }

        // Second query: Get all root events for handle_root_event()
        let root_filter =
            Filter::new().kinds(vec![Kind::GitPatch, Kind::GitIssue, Kind::GitPullRequest]);

        let root_events = match self.database.query(root_filter).await {
            Ok(events) => {
                tracing::info!(count = events.len(), "Loaded root events from database");
                events
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Failed to query root events from database"
                );
                // Continue with just announcements
                return pending;
            }
        };

        // Process root events
        let mut root_events_processed = 0;
        for event in root_events.iter() {
            self.handle_root_event(event, &mut pending).await;
            root_events_processed += 1;
        }

        tracing::info!(
            announcements_loaded = announcements_loaded,
            root_events_processed = root_events_processed,
            "Processed existing events from database"
        );

        pending
    }

    /// Process a relay pool notification
    ///
    /// Handles incoming events from the subscription, queueing 30617 announcements
    /// for batch processing and immediately processing root events.
    ///
    /// Returns `LoopControl::Break` if the loop should exit, `LoopControl::Continue` otherwise.
    async fn process_notification(
        &self,
        notification: ClientNotification,
        pending: &mut PendingUpdates,
    ) -> LoopControl {
        match notification {
            ClientNotification::Event { event, .. } => {
                // Process 30617 events for relay discovery
                // Note: Events reaching here have already passed write policy validation
                // (archive_all, archive_whitelist, blacklist, etc.) so no additional
                // filtering is needed.
                if event.kind == Kind::GitRepoAnnouncement {
                    // Extract repo ID and relays
                    if let Some(repo_id) = Self::extract_repo_id(&event) {
                        let relays = Self::extract_relay_urls(&event);
                        // 30617 announcements don't contribute to root_events - those are
                        // the 1617/1618/1621 event IDs that get added when we receive
                        // root events via handle_root_event. See mod.rs:71 for details.
                        pending.replace_announcement_relays(repo_id.clone(), relays.clone());
                        tracing::info!(
                            event_id = %event.id,
                            repo_id = %repo_id,
                            relay_count = relays.len(),
                            relay_sample = ?relays.iter().take(LOG_COLLECTION_SAMPLE_SIZE).collect::<Vec<_>>(),
                            "[DIAG] Queued 30617 announcement for batch processing"
                        );
                    }
                } else {
                    // For root event kinds (1617, 1618, 1621),
                    // process them to update the RepoSyncIndex AND add to pending
                    // for Layer 3 filter creation
                    tracing::trace!(
                        kind = %event.kind,
                        event_id = %event.id,
                        "Received root event"
                    );
                    self.handle_root_event(&event, pending).await;
                }
                LoopControl::Continue
            }
            ClientNotification::Shutdown => {
                tracing::info!("SelfSubscriber received shutdown notification");
                LoopControl::Break
            }
            _ => LoopControl::Continue,
        }
    }

    /// Extract relay URLs from event tags
    ///
    /// Extracts URLs from:
    /// - `relays` tags: ["relays", "wss://relay1.com", "wss://relay2.com", ...]
    /// - `clone` tags: ["clone", "https://example.com/repo.git", ...] (converted to ws://)
    fn extract_relay_urls(event: &Event) -> HashSet<String> {
        let mut relays = HashSet::new();

        for tag in event.tags.iter() {
            let tag_vec = tag.as_slice();
            if tag_vec.is_empty() {
                continue;
            }

            match tag_vec[0].as_str() {
                "relays" => {
                    // All subsequent values are relay URLs
                    for url in tag_vec.iter().skip(1) {
                        relays.insert(url.to_string());
                    }
                }
                "clone" if tag_vec.len() >= 2 => {
                    // Convert ALL http(s) clone URLs to ws(s) relay URLs
                    for clone_url in tag_vec.iter().skip(1) {
                        if let Some(relay_url) = clone_url_to_relay_url(clone_url) {
                            relays.insert(relay_url);
                        }
                    }
                }
                _ => {}
            }
        }

        relays
    }

    /// Extract repo identifier from event
    ///
    /// For kind 30617, uses the `d` tag to build the addressable reference
    /// Format: 30617:pubkey:identifier
    fn extract_repo_id(event: &Event) -> Option<String> {
        // For kind 30617, extract d tag and build addressable ref
        if event.kind == Kind::GitRepoAnnouncement {
            for tag in event.tags.iter() {
                let tag_vec = tag.as_slice();
                if tag_vec.len() >= 2 && tag_vec[0] == "d" {
                    return Some(format!("30617:{}:{}", event.pubkey, tag_vec[1]));
                }
            }
        }

        // For other kinds (1617, 1618, 1621), we'd need to look at
        // their 'a' tags to find which repo they belong to.
        // That processing happens in the batch processing, not here.
        None
    }

    /// Main run loop
    ///
    /// Connects to own relay, subscribes to relevant event kinds,
    /// and batches updates before processing them.
    ///
    /// The optional shutdown receiver allows graceful termination when
    /// received via the broadcast channel.
    pub async fn run(mut self, mut shutdown_rx: Option<broadcast::Receiver<()>>) {
        let client = Client::default();

        // Add own relay
        if let Err(e) = client.add_relay(&self.own_relay_url).await {
            tracing::error!(
                url = %self.own_relay_url,
                error = %e,
                "Failed to add own relay for self-subscription"
            );
            return;
        }

        // Connect
        client.connect().await;

        // Subscribe to announcement and root event kinds
        // Per v4 spec: 30617, 1617, 1618, 1621 (NOT 30618)
        // Plus kind 10317 (User Grasp List) for GRASP discovery
        let mut filter = Filter::new().kinds(vec![
            Kind::GitRepoAnnouncement,
            Kind::GitPatch,
            Kind::GitIssue,
            Kind::GitPullRequest,
            Kind::GitUserGraspList,
        ]);
        if let Some(timestamp) = self.last_connected {
            // Quick reconnect - use since filter (15 min buffer)
            let since = Timestamp::from(timestamp.as_secs().saturating_sub(15 * 60));
            tracing::debug!(
                since = %since,
                "Using since filter for reconnect"
            );
            filter = filter.since(since);
        }

        // Update last_connected AFTER creating filter but BEFORE subscribing
        self.last_connected = Some(Timestamp::now());

        if let Err(e) = client.subscribe(filter).await {
            tracing::error!(
                error = %e,
                "Failed to subscribe to own relay for self-subscription"
            );
            return;
        }

        tracing::info!(
            url = %self.own_relay_url,
            domain = %self.relay_domain,
            "SelfSubscriber started"
        );

        let mut notifications = client.notifications();
        let batch_window = Self::get_batch_window();

        // Load existing events from database on startup
        // This ensures all repos get Layer 2/3 filters created, not just those
        // returned by the WebSocket subscription (which has limits)
        let mut pending = self.load_existing_events().await;

        // Timer does NOT reset on new events - use interval
        let mut timer = tokio::time::interval(batch_window);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            // Build the select based on whether we have a shutdown receiver
            if let Some(ref mut rx) = shutdown_rx {
                tokio::select! {
                    notification = notifications.next() => {
                        match notification {
                            Some(notification) => {
                                if let LoopControl::Break = self.process_notification(notification, &mut pending).await {
                                    break;
                                }
                            }
                            None => {
                                tracing::info!("SelfSubscriber notification stream ended");
                                break;
                            }
                        }
                    }
                    _ = timer.tick() => {
                        if !pending.is_empty() {
                            self.process_batch(&mut pending).await;
                        }
                    }
                    _ = rx.recv() => {
                        tracing::info!("SelfSubscriber received shutdown signal");
                        break;
                    }
                }
            } else {
                // No shutdown receiver - original behavior
                tokio::select! {
                    notification = notifications.next() => {
                        match notification {
                            Some(notification) => {
                                if let LoopControl::Break = self.process_notification(notification, &mut pending).await {
                                    break;
                                }
                            }
                            None => {
                                tracing::info!("SelfSubscriber notification stream ended");
                                break;
                            }
                        }
                    }
                    _ = timer.tick() => {
                        if !pending.is_empty() {
                            self.process_batch(&mut pending).await;
                        }
                    }
                }
            }
        }

        tracing::info!("SelfSubscriber stopped");
    }

    /// Handle a root event (1617/1618/1621)
    ///
    /// Extracts the 'a' tag to find the repo addressable reference,
    /// then updates the RepoSyncIndex with the event ID AND adds to pending
    /// so that Layer 3 filters will be created in the next batch.
    async fn handle_root_event(&self, event: &Event, pending: &mut PendingUpdates) {
        // Extract 'a' tag to find the repo addressable reference
        let repo_a_tag = event.tags.iter().find(|tag| {
            let tag_vec = tag.as_slice();
            !tag_vec.is_empty() && tag_vec[0] == "a"
        });

        let repo_ref = match repo_a_tag {
            Some(tag) => {
                let tag_vec = tag.as_slice();
                // Get first value from tag (the 'a' tag value at index 1)
                if tag_vec.len() >= 2 {
                    tag_vec[1].clone()
                } else {
                    tracing::warn!(
                        event_id = %event.id,
                        "Root event has 'a' tag but no content"
                    );
                    return;
                }
            }
            None => {
                tracing::warn!(
                    event_id = %event.id,
                    "Root event missing 'a' tag"
                );
                return;
            }
        };

        // Look up repo in repo_sync_index - add root event directly and also to pending
        let mut index = self.repo_sync_index.write().await;
        if let Some(repo_sync) = index.get_mut(&repo_ref) {
            // Add event.id to root_events set in the index (immediate availability)
            repo_sync.root_events.insert(event.id);

            // Clone the relays before releasing the lock - Layer 3 filters need to be
            // sent to the same relays as Layer 2 filters for this repo
            let relays = repo_sync.relays.clone();

            // Release lock before modifying pending
            drop(index);

            // Also add root event to pending - this ensures batch processing runs
            // and creates Layer 3 filters for events referencing this root event.
            // CRITICAL: Include relays so derive_relay_targets knows where to send filters!
            pending.add_root_event(repo_ref.clone(), relays.clone(), event.id);

            tracing::debug!(
                event_id = %event.id,
                repo_ref = %repo_ref,
                relay_count = relays.len(),
                "Added root event to index and pending for Layer 3 filter creation"
            );
        } else {
            tracing::debug!(
                event_id = %event.id,
                repo_ref = %repo_ref,
                "Root event references unknown repo"
            );
        }
    }

    /// Process accumulated batch
    ///
    /// Updates the RepoSyncIndex with discovered repos, then marks only the
    /// relays changed by this batch for SyncManager recomputation.
    async fn process_batch(&self, pending: &mut PendingUpdates) {
        let (updates, relay_replacements) = pending.take();

        if updates.is_empty() {
            return;
        }

        tracing::info!(
            repo_count = updates.len(),
            "Processing batch of repo updates"
        );

        // Log what repos and relays we discovered
        for (repo_id, needs) in &updates {
            tracing::info!(
                repo_id = %repo_id,
                relay_count = needs.relays.len(),
                relay_sample = ?needs.relays.iter().take(LOG_COLLECTION_SAMPLE_SIZE).collect::<Vec<_>>(),
                "Discovered repo with relay URLs"
            );
        }

        let mut dirty_relays = dirty_relays(&updates);

        // Update RepoSyncIndex
        let mut index = self.repo_sync_index.write().await;

        for (repo_id, needs) in updates {
            // Merge with existing entry or insert new
            let entry = index
                .entry(repo_id.clone())
                .or_insert_with(|| RepoSyncNeeds {
                    relays: HashSet::new(),
                    root_events: HashSet::new(),
                    sync_level: SyncLevel::Full,
                });
            // Upgrade sync_level to Full - this handles the case where the entry
            // already exists as StateOnly (purgatory announcement) and is now being
            // promoted (git data arrived and the event was broadcast via notify_event).
            entry.sync_level = SyncLevel::Full;
            if let Some(replacement) = relay_replacements.get(&repo_id) {
                dirty_relays.extend(entry.relays.iter().cloned());
                entry.relays = replacement.clone();
            } else {
                entry.relays.extend(needs.relays);
            }
            entry.root_events.extend(needs.root_events);

            tracing::debug!(
                repo_id = %repo_id,
                relay_count = entry.relays.len(),
                event_count = entry.root_events.len(),
                "Updated repo sync needs"
            );
        }

        drop(index);

        // Send only the relay keys dirtied by this batch. The SyncManager
        // recomputes their current desired work against pending and confirmed
        // state, avoiding an O(all repositories × all relays) rebuild for
        // every historic batch.
        for relay_url in dirty_relays {
            // Skip our own relay URL (we're subscribed to ourselves via self-subscription)
            if relay_url.contains(&self.relay_domain) {
                continue;
            }

            let action = AddFilters {
                relay_url: relay_url.clone(),
                items: crate::sync::PendingItems::default(),
                filters: Vec::new(),
            };

            if let Err(e) = self.action_tx.send(action).await {
                tracing::error!(
                    relay = %relay_url,
                    error = %e,
                    "Failed to send AddFilters action"
                );
            } else {
                tracing::info!(
                    relay = %relay_url,
                    "Marked relay dirty for SyncManager recomputation"
                );
            }
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert clone URL to relay URL
///
/// Converts http://domain:port/path.git to ws://domain:port
/// Converts https://domain:port/path.git to wss://domain:port
/// Strips the path component to get just the relay URL
/// Returns None for unsupported URL schemes
fn clone_url_to_relay_url(clone_url: &str) -> Option<String> {
    let (ws_scheme, rest) = if clone_url.starts_with("http://") {
        ("ws://", clone_url.strip_prefix("http://")?)
    } else if clone_url.starts_with("https://") {
        ("wss://", clone_url.strip_prefix("https://")?)
    } else {
        return None;
    };

    // Extract just the host:port part (everything before the first /)
    let host_port = rest.split('/').next()?;
    Some(format!("{}{}", ws_scheme, host_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clone_url_to_relay_url_https() {
        assert_eq!(
            clone_url_to_relay_url("https://example.com/repo.git"),
            Some("wss://example.com".to_string())
        );
    }

    #[test]
    fn test_clone_url_to_relay_url_http() {
        assert_eq!(
            clone_url_to_relay_url("http://localhost:3000/repo.git"),
            Some("ws://localhost:3000".to_string())
        );
    }

    #[test]
    fn test_clone_url_to_relay_url_with_port() {
        assert_eq!(
            clone_url_to_relay_url("http://127.0.0.1:41463/test-repo.git"),
            Some("ws://127.0.0.1:41463".to_string())
        );
    }

    #[test]
    fn test_clone_url_to_relay_url_unsupported() {
        assert_eq!(clone_url_to_relay_url("git://example.com/repo.git"), None);
        assert_eq!(
            clone_url_to_relay_url("ssh://git@example.com/repo.git"),
            None
        );
    }

    #[test]
    fn dirty_relay_signals_are_limited_to_the_current_batch() {
        let updates = HashMap::from([(
            "30617:owner:new-repo".to_string(),
            RepoSyncNeeds {
                relays: HashSet::from([
                    "wss://owner.example".to_string(),
                    "wss://shared.example".to_string(),
                ]),
                root_events: HashSet::new(),
                sync_level: SyncLevel::Full,
            },
        )]);

        assert_eq!(
            dirty_relays(&updates),
            HashSet::from([
                "wss://owner.example".to_string(),
                "wss://shared.example".to_string(),
            ]),
            "a fresh historic batch must not rebuild work for unrelated indexed relays"
        );
    }

    #[test]
    fn announcement_replacement_does_not_union_obsolete_relays() {
        let repo = "30617:owner:repo".to_string();
        let old = "wss://old.example".to_string();
        let new = "wss://new.example".to_string();
        let mut pending = PendingUpdates::new();

        pending.replace_announcement_relays(repo.clone(), HashSet::from([old]));
        pending.replace_announcement_relays(repo.clone(), HashSet::from([new.clone()]));

        let (updates, replacements) = pending.take();
        assert_eq!(updates[&repo].relays, HashSet::from([new.clone()]));
        assert_eq!(replacements[&repo], HashSet::from([new]));
    }

    #[test]
    fn root_event_does_not_override_latest_announcement_relays() {
        let repo = "30617:owner:repo".to_string();
        let relay = "wss://owner.example".to_string();
        let root = EventId::from_byte_array([7; 32]);
        let mut pending = PendingUpdates::new();

        pending.replace_announcement_relays(repo.clone(), HashSet::from([relay.clone()]));
        pending.add_root_event(
            repo.clone(),
            HashSet::from(["wss://stale.example".to_string()]),
            root,
        );

        let (updates, replacements) = pending.take();
        assert_eq!(updates[&repo].relays, HashSet::from([relay.clone()]));
        assert_eq!(updates[&repo].root_events, HashSet::from([root]));
        assert_eq!(replacements[&repo], HashSet::from([relay]));
    }
}
