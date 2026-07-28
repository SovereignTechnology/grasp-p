//! Proactive Sync Module - GRASP-02 v4 Implementation
//!
//! This module implements proactive synchronization of repository data from external
//! relays based on relay URLs listed in 30617 repository announcements.
//!
//! ## Architecture
//!
//! The sync system uses three index structures:
//! - `RepoSyncIndex` - What we WANT to sync (source of truth from self-subscription)
//! - `RelaySyncIndex` - What we have CONFIRMED syncing + connection state
//! - `PendingSyncIndex` - In-flight batches awaiting EOSE confirmation
//!
//! See `docs/explanation/grasp-02-proactive-sync-v4.md` for full design details.

pub mod algorithms;
pub mod filters;
pub mod health;
pub mod metrics;
pub mod naughty_list;
pub mod private_index;
pub mod rejected_index;
pub mod relay_connection;
pub mod self_subscriber;

// Re-export core algorithm types
pub use algorithms::{AddFilters, RelaySyncNeeds};

// Re-export metrics types
pub use metrics::SyncMetrics;

// Re-export rejected index types
pub use rejected_index::{EventType, RejectionReason};
// Note: RejectedEventsIndex struct exists in rejected_index.rs but not yet used
// Current code still uses the simple HashSet type alias below

// Re-export relay connection types
pub use relay_connection::{NegentropySyncResult, RelayConnection, RelayEvent};

// Re-export self-subscriber types
pub use self_subscriber::SelfSubscriber;

// Re-export health tracking types
pub use health::RelayHealthTracker;
use tokio::time::sleep;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::*;
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::config::Config;
use crate::nostr::builder::Nip34WritePolicy;
use crate::nostr::SharedDatabase;
use nostr_relay_builder::prelude::LocalRelay;

// =============================================================================
// Type Aliases for Index Structures
// =============================================================================

/// What we WANT to sync - derived from events received via self-subscription.
/// Updated immediately when self-subscriber batch fires.
/// Key: repo addressable ref - 30617:pubkey:identifier
pub type RepoSyncIndex = Arc<RwLock<HashMap<String, RepoSyncNeeds>>>;

/// What we have CONFIRMED syncing - includes connection state for integrated lifecycle.
/// Key: relay URL
pub type RelaySyncIndex = Arc<RwLock<HashMap<String, RelayState>>>;

/// Tracks batches of subscriptions that are in-flight, awaiting EOSE.
/// Each batch has its own ID and can confirm independently.
/// Key: relay URL
pub type PendingSyncIndex = Arc<RwLock<HashMap<String, Vec<PendingBatch>>>>;

/// Tracks EventIds of announcement events (30617/30618) that were rejected during sync.
/// These events are excluded from negentropy sync and skipped during REQ+EOSE processing
/// to avoid repeatedly fetching and rejecting the same events.
///
/// Uses the two-tier RejectedEventsIndex from rejected_index.rs:
/// - Hot cache: Full events for 2 minutes (enables immediate re-processing)
/// - Cold index: Metadata for 7 days (prevents repeated downloads)
use rejected_index::RejectedEventsIndex;

// =============================================================================
// Supporting Data Structures
// =============================================================================

/// Level of sync needed for a repository
///
/// Purgatory announcements only need state events synced (to validate git data).
/// Promoted repos need full L2/L3 sync (patches, issues, PRs, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncLevel {
    /// Full L2 + L3 sync (promoted repos with git data)
    #[default]
    Full,
    /// Only state events (kind 30618) - for purgatory announcements
    StateOnly,
}

/// What repos and root events need to be synced
#[derive(Debug, Clone, Default)]
pub struct RepoSyncNeeds {
    /// Relay URLs listed in this repo's 30617 announcement
    pub relays: HashSet<String>,
    /// Root event IDs - 1617/1618/1621 - that reference this repo
    pub root_events: HashSet<EventId>,
    /// Sync level - StateOnly for purgatory, Full for promoted repos
    pub sync_level: SyncLevel,
}

/// Connection status for a relay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionStatus {
    /// Not currently connected
    #[default]
    Disconnected,
    /// Connection attempt in progress
    Connecting,
    /// Successfully connected, historic sync in progress
    Syncing,
    /// Successfully connected, historic sync completed
    Connected,
    /// Successfully connected, historic sync had failures but live sync active
    ConnectedHistoricSyncFailures,
    /// Disconnection initiated, waiting for event loop to terminate
    /// State is retained to process remaining queued events
    Disconnecting,
}

impl ConnectionStatus {
    /// Returns true if live sync is active (can accept new filters)
    pub fn is_live_sync_active(&self) -> bool {
        matches!(
            self,
            ConnectionStatus::Syncing
                | ConnectionStatus::Connected
                | ConnectionStatus::ConnectedHistoricSyncFailures
        )
    }
}

/// Complete state for a single relay - combines sync needs with connection lifecycle
#[derive(Debug)]
pub struct RelayState {
    /// Repos we have confirmed syncing from this relay
    pub repos: HashSet<String>,
    /// Root events we have confirmed tracking
    pub root_events: HashSet<EventId>,
    /// If true, never disconnect this relay
    pub is_bootstrap: bool,
    /// Current connection status
    pub connection_status: ConnectionStatus,
    /// When we last successfully connected - used for since filter on reconnect
    pub last_connected: Option<Timestamp>,
    /// When we disconnected - for 15-minute state retention rule
    pub disconnected_at: Option<Timestamp>,
    /// Whether announcement filter historic sync has completed for this relay
    /// Used to determine if we can use `since` filter on reconnect for Layer 1
    pub announcements_synced: bool,
    /// Whether initial historic sync has fully completed (all layers)
    /// Used to transition from Syncing -> Connected status
    pub historic_sync_completed: bool,
    /// When historic sync completed (None if never completed or cleared on fresh_start)
    pub historic_sync_completed_at: Option<Timestamp>,
    /// Whether any batch failed during historic sync
    /// Set to true when retry protection triggers or other failures occur
    /// Used to transition to ConnectedDegraded instead of Connected
    pub historic_sync_had_failures: bool,
}

impl Default for RelayState {
    fn default() -> Self {
        Self {
            repos: HashSet::new(),
            root_events: HashSet::new(),
            is_bootstrap: false,
            connection_status: ConnectionStatus::Disconnected,
            last_connected: None,
            disconnected_at: None,
            announcements_synced: false,
            historic_sync_completed: false,
            historic_sync_completed_at: None,
            historic_sync_had_failures: false,
        }
    }
}

impl RelayState {
    /// Check if state should be cleared based on 15-minute rule
    pub fn should_clear_state(&self) -> bool {
        match self.disconnected_at {
            Some(disconnected) => {
                let now = Timestamp::now();
                now.as_secs().saturating_sub(disconnected.as_secs()) > 900 // 15 minutes
            }
            None => false, // Still connected or never connected
        }
    }

    /// Clear repos and root_events - called when reconnect takes > 15 minutes
    pub fn clear_sync_state(&mut self) {
        self.repos.clear();
        self.root_events.clear();
        self.announcements_synced = false;
        self.historic_sync_completed = false;
        self.historic_sync_completed_at = None;
        self.historic_sync_had_failures = false;
    }
}

/// Method used for synchronization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMethod {
    /// Traditional REQ+EOSE flow - waits for EOSE on subscriptions
    ReqEose,
    /// NIP-77 negentropy sync - confirms immediately after sync completes
    Negentropy,
}

/// Result of processing an event from sync
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessResult {
    /// Event was new and saved to database
    Saved,
    /// Event already existed in database
    Duplicate,
    /// Event added to Purgatory
    Purgatory,
    /// Event rejected by write policy
    Rejected,
}

/// Statistics from re-processing events from hot cache
#[derive(Debug, Clone, Default)]
pub struct ReprocessingStats {
    /// Number of events successfully saved
    pub saved: usize,
    /// Number of events that were duplicates
    pub duplicate: usize,
    /// Number of events added to purgatory
    pub purgatory: usize,
    /// Number of events still rejected
    pub rejected: usize,
}

/// Pagination state for a subscription in non-Negentropy historic sync
#[derive(Debug, Clone)]
pub struct PaginationState {
    /// Number of events received for this subscription
    pub event_count: usize,
    /// Smallest created_at timestamp seen (for pagination with `until`)
    pub min_created_at: Option<Timestamp>,
    /// Original filter to reconstruct for next page
    pub original_filter: Filter,
}

/// A batch of items pending confirmation
#[derive(Debug, Clone)]
pub struct PendingBatch {
    /// Unique ID for this batch - for debugging/logging
    pub batch_id: u64,
    /// The items this batch is syncing
    pub items: PendingItems,
    /// Subscription IDs that must ALL receive EOSE before confirming (for ReqEose)
    /// Empty for Negentropy sync method
    pub outstanding_subs: HashSet<SubscriptionId>,
    /// The sync method used for this batch
    pub sync_method: SyncMethod,
    /// Pagination tracking for REQ+EOSE subscriptions (empty for Negentropy)
    /// Maps subscription ID to its pagination state
    pub pagination_state: HashMap<SubscriptionId, PaginationState>,
    /// Event IDs requested via negentropy ID-based fetch (None for REQ+EOSE)
    /// Used to validate that all requested events were received
    pub requested_event_ids: Option<HashSet<EventId>>,
    /// Event IDs actually received for this batch (None for REQ+EOSE)
    /// Compared against requested_event_ids to detect missing events
    pub received_event_ids: Option<HashSet<EventId>>,
    /// Number of retry attempts for missing events (Negentropy only)
    /// Used to prevent infinite retry loops when relay consistently fails
    pub retry_count: usize,
    /// Whether this batch failed (completed with missing data)
    /// Set to true when retry protection triggers or other failures occur
    pub failed: bool,
}

/// Items included in a pending batch
#[derive(Debug, Clone, Default)]
pub struct PendingItems {
    /// Repos being synced in this batch
    pub repos: HashSet<String>,
    /// Root events being synced in this batch
    pub root_events: HashSet<EventId>,
}

// =============================================================================
// SyncManager - Main Entry Point
// =============================================================================

/// Notification from spawned tasks about relay disconnections
#[derive(Debug)]
pub struct DisconnectNotification {
    /// The relay URL that disconnected
    pub relay_url: String,
}

/// Notification from spawned tasks about EOSE (End Of Stored Events)
#[derive(Debug)]
pub struct EoseNotification {
    /// The relay URL that sent EOSE
    pub relay_url: String,
    /// The subscription ID that completed
    pub sub_id: SubscriptionId,
}

/// Notification from spawned tasks about successful connection
#[derive(Debug)]
pub struct ConnectNotification {
    /// The relay URL that connected
    pub relay_url: String,
}

/// Quick reconnect window in seconds (15 minutes)
const QUICK_RECONNECT_WINDOW_SECS: u64 = 15 * 60;

/// Maximum filter count before triggering consolidation
const CONSOLIDATION_THRESHOLD: usize = 70;

/// Maximum time to wait for pending batches (30 seconds)
const CONSOLIDATION_WAIT_TIMEOUT_SECS: u64 = 30;

/// Page size threshold for historic sync pagination (non-negentropy)
/// If a subscription receives >= 75 events, we fetch the next page
const PAGINATION_THRESHOLD: usize = 75;

/// FS-3 (review L2-F4): per-peer min-interval floor between private
/// sync-filter re-issues. Past [`CONSOLIDATION_THRESHOLD`] derived filters,
/// every index-dirty 5s tick used to trigger a full consolidate
/// (unsubscribe-all + resubscribe + since=None backfill) on every live
/// peer — at 128 aliases x the 4/hour cadence budget that is a dirty tick
/// every ~7s, i.e. near-continuous consolidation. Both re-issue triggers
/// (PrivateSyncIndex change and the hourly full re-issue timer) share this
/// floor per peer.
#[derive(Debug, Default)]
struct PrivateReissueFloor {
    /// peer relay URL → when it last received a re-issue.
    last_sent: HashMap<String, std::time::Instant>,
}

impl PrivateReissueFloor {
    /// True (recording the send) when `relay_url` may be re-issued under
    /// `floor`; false while the previous send is inside the interval. A
    /// zero floor disables gating. Entries older than the floor are pruned
    /// on each call so the map stays bounded by the recently-seen peer set.
    fn admit(&mut self, relay_url: &str, floor: Duration, now: std::time::Instant) -> bool {
        if floor.is_zero() {
            return true;
        }
        self.last_sent.retain(|_, at| now.duration_since(*at) < floor);
        if let Some(at) = self.last_sent.get(relay_url) {
            if now.duration_since(*at) < floor {
                return false;
            }
        }
        self.last_sent.insert(relay_url.to_string(), now);
        true
    }
}

/// Result of a private filter re-issue round (FS-3/FS-8): how many live
/// peers were actually re-issued vs skipped by the FS-3 floor.
#[derive(Debug, Default, Clone, Copy)]
struct PrivateReissueOutcome {
    sent: usize,
    floor_skipped: usize,
}

// =============================================================================
// Daily Timer
// =============================================================================

/// Run the daily timer for periodic fresh syncs
///
/// This function runs in a loop, sleeping for a random interval between
/// 23-25 hours, then triggering a daily sync for all relays. The random
/// interval prevents thundering herd effects across multiple ngit-grasp instances.
///
/// The daily sync:
/// - Unsubscribes from all current subscriptions
/// - Clears pending batches and sync state
/// - Re-discovers all repos and events from scratch
///
/// This detects state drift over time that might occur from missed events.
async fn run_daily_timer(
    sync_manager: Arc<Mutex<SyncManager>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    use ::rand::RngExt;

    loop {
        // Random interval between 23-25 hours
        let hours = 23.0 + ::rand::rng().random::<f64>() * 2.0;
        let seconds = (hours * 3600.0) as u64;

        tracing::info!(
            hours = format!("{:.1}", hours),
            "Daily timer scheduled to fire in {:.1} hours",
            hours
        );

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(seconds)) => {
                // Timer fired - do daily sync
                // Get list of relays
                let relay_urls: Vec<String> = {
                    let manager = sync_manager.lock().await;
                    let index = manager.relay_sync_index.read().await;
                    let urls: Vec<String> = index.keys().cloned().collect();
                    drop(index);
                    urls
                };

                tracing::info!(
                    relay_count = relay_urls.len(),
                    "Daily timer fired, starting daily sync for all relays"
                );

                // Trigger daily sync for each relay
                for relay_url in relay_urls {
                    let mut manager = sync_manager.lock().await;
                    manager.daily_sync(&relay_url).await;
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Daily timer received shutdown signal");
                break;
            }
        }
    }
}

/// Background task that periodically syncs purgatory announcements into repo_sync_index.
///
/// Runs every 5 seconds by default (200ms when `NGIT_TEST=1`).
/// For each announcement currently in purgatory, ensures there is a `StateOnly` entry in
/// `repo_sync_index`. New entries trigger `handle_new_sync_filters` which connects to the
/// relay URLs listed in the announcement and subscribes to state events (kind 30618).
///
/// This is the sole registration path for purgatory announcements:
/// - Sync-path announcements: registered here within one interval of arriving.
/// - User-submitted purgatory announcements: the SelfSubscriber never sees them
///   (they're rejected from DB), so this timer is the only registration path.
async fn run_purgatory_announcement_sync(
    sync_manager: Arc<Mutex<SyncManager>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let interval = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_millis(200)
    } else {
        Duration::from_secs(5)
    };
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let mut manager = sync_manager.lock().await;
                manager.sync_purgatory_announcements_to_index().await;
            }
            _ = shutdown_rx.recv() => {
                tracing::debug!("Purgatory announcement sync timer received shutdown signal");
                break;
            }
        }
    }
}

/// GRASP-P Phase 2: background task that rebuilds the PrivateSyncIndex from
/// the relay DB's kind-30640 events (every 5s, 200ms when `NGIT_TEST=1`).
///
/// Spawned ONLY when `config.private_repos_enable`. This is the single
/// registration path into the private index and covers both sources
/// uniformly (client-pushed AND synced 30640s both live in the relay DB).
/// On change it re-issues derived 30641/stream-wrap filters to connected peers,
/// connects any newly-listed peer relays, and reprocesses held out-of-order
/// events whose registration just became available.
async fn run_private_registration_sync(
    sync_manager: Arc<Mutex<SyncManager>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let interval = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_millis(200)
    } else {
        Duration::from_secs(5)
    };
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let mut manager = sync_manager.lock().await;
                manager.sync_private_registrations_to_index().await;
            }
            _ = shutdown_rx.recv() => {
                tracing::debug!("Private registration sync timer received shutdown signal");
                break;
            }
        }
    }
}

/// GRASP-P Phase-4b B1: periodic since=None full re-issue of the private
/// sync filters (Layer-1 kind-30640 + the current derived 30641/stream-wrap
/// filters) to every live peer. Sibling to `run_private_registration_sync`,
/// spawned ONLY when `config.private_repos_enable` and
/// `NGIT_PRIVATE_FULL_REISSUE_INTERVAL_SECS` > 0 (0 = disabled).
///
/// Gaps that live delivery cannot heal — expired rejected-hot-cache entries,
/// negentropy blind spots, cadence-limited 30640 rejections (WP-A A2, which
/// deliberately rely on redelivery) — otherwise wait for a reconnect or the
/// daily fresh sync; this timer bounds that wait to ~1 hour. Each sleep is
/// jittered (±10%) so paired nodes do not re-issue in lockstep. Under
/// `NGIT_TEST=1` the interval is clamped to <= 2s (the 5s→200ms idiom,
/// scaled for an hourly timer) so integration tests can observe it.
async fn run_private_full_reissue_timer(
    sync_manager: Arc<Mutex<SyncManager>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    use ::rand::RngExt;

    let base_secs = {
        let manager = sync_manager.lock().await;
        let secs = manager.config.private_full_reissue_interval_secs;
        if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
            secs.min(2)
        } else {
            secs
        }
    };
    if base_secs == 0 {
        tracing::debug!("Private full re-issue timer disabled (interval 0)");
        return;
    }
    tracing::info!(
        interval_secs = base_secs,
        "Private full re-issue timer started"
    );
    loop {
        // ±10% jitter around the configured interval.
        let jitter = 0.9 + ::rand::rng().random::<f64>() * 0.2;
        let interval = Duration::from_secs_f64(base_secs as f64 * jitter);
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let mut manager = sync_manager.lock().await;
                manager.reissue_private_filters_full().await;
            }
            _ = shutdown_rx.recv() => {
                tracing::debug!("Private full re-issue timer received shutdown signal");
                break;
            }
        }
    }
}

// Combined Health and Metrics Checker

/// Background task for cleaning up expired entries from the rejected events index
///
/// This task runs two cleanup operations at different intervals:
/// 1. **Hot cache cleanup (60s)**: Remove events older than 2 minutes from hot cache
/// 2. **Cold index cleanup (daily)**: Remove metadata older than 7 days from cold index
///
/// A single `RejectedEventsIndex` handles both announcement and state events,
/// differentiated by `EventType`. Each cleanup pass processes both types.
///
/// The hot cache cleanup runs frequently to keep memory usage low (events expire quickly).
/// The cold index cleanup runs daily since metadata is small and expires slowly.
async fn run_rejected_index_cleanup(
    sync_manager: Arc<Mutex<SyncManager>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    // FS-4 (review L3-F5): NGIT_TEST-clamped like the other timers — the
    // physical expiry of held/rejected entries otherwise lags the lazy TTL
    // filtering by up to 60s, slowing every heal-path test.
    let hot_cache_interval = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_millis(200)
    } else {
        Duration::from_secs(60)
    };
    let cold_index_interval = Duration::from_secs(86400); // 24 hours

    tracing::info!("Rejected index cleanup started (hot cache: 60s, cold index: daily)");

    let mut hot_cache_timer = tokio::time::interval(hot_cache_interval);
    let mut cold_index_timer = tokio::time::interval(cold_index_interval);

    // Tick immediately to set the initial delay
    hot_cache_timer.tick().await;
    cold_index_timer.tick().await;

    loop {
        tokio::select! {
            _ = hot_cache_timer.tick() => {
                let manager = sync_manager.lock().await;

                // Clean up hot cache for both event types (single index handles both)
                // Note: cleanup_expired_for_type updates metrics with type label
                let (ann_hot_expired, _) = manager.rejected_events_index.cleanup_expired_for_type("announcement");
                let (state_hot_expired, _) = manager.rejected_events_index.cleanup_expired_for_type("state");

                // GRASP-P Phase 2: expire held private events on the same
                // hot-cache TTL. Inert when private repos are disabled.
                if let Some(private) = manager.write_policy.private() {
                    let expired = private.sync_rejected().cleanup_expired();
                    if expired > 0 {
                        tracing::debug!(
                            expired = expired,
                            "Cleaned up expired held private events"
                        );
                    }
                }

                if ann_hot_expired + state_hot_expired > 0 {
                    tracing::debug!(
                        announcements = ann_hot_expired,
                        states = state_hot_expired,
                        "Cleaned up expired entries from rejected events hot cache"
                    );
                }
            }
            _ = cold_index_timer.tick() => {
                let manager = sync_manager.lock().await;

                // Clean up cold index for both event types (single index handles both)
                let (_, ann_cold_expired) = manager.rejected_events_index.cleanup_expired_for_type("announcement");
                let (_, state_cold_expired) = manager.rejected_events_index.cleanup_expired_for_type("state");

                if ann_cold_expired + state_cold_expired > 0 {
                    tracing::info!(
                        announcements = ann_cold_expired,
                        states = state_cold_expired,
                        "Cleaned up expired entries from rejected events cold index"
                    );
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Rejected index cleanup received shutdown signal");
                break;
            }
        }
    }
}

/// Background task for checking relay health and updating metrics
///
/// This task runs every 2 seconds and performs three operations:
///
/// 1. **Disconnect checking**: Check for empty relays and disconnect non-bootstrap ones
/// 2. **Rate limit recovery**: Check for relays whose rate limit cooldown has expired
/// 3. **Metrics update**: Update Prometheus metrics with current health states from health_tracker
///
/// The metrics update ensures that health states are kept current in metrics even when
/// they change due to timeouts, cooldowns expiring, or stability periods completing.
///
/// The 2-second interval provides a good balance between responsiveness and overhead.
/// While disconnect checking traditionally ran at 60s intervals, the faster cadence here
/// is acceptable since the operations are lightweight (just index checks, no I/O).
async fn run_health_and_metrics_checker(
    sync_manager: Arc<Mutex<SyncManager>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let interval = Duration::from_secs(2);
    tracing::info!("Health and metrics checker started with 2s interval");

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let mut manager = sync_manager.lock().await;

                // 1. Check for disconnects and retry disconnected relays
                manager.check_disconnects().await;
                manager.retry_disconnected_relays().await;

                // 2. Check for rate limit recovery
                manager.check_rate_limit_recovery().await;

                // 3. Check for naughty list expiration
                if let Some(naughty_list) = manager.health_tracker.naughty_list() {
                    let recovered = naughty_list.expire_old_entries();
                    for url in recovered {
                        tracing::info!(
                            relay = %url,
                            "Relay removed from naughty list after expiration, will retry"
                        );
                    }
                }

                // 4. Update metrics with current health states and naughty list
                if let Some(ref metrics) = manager.metrics {
                    // Get all tracked relay URLs
                    let relay_urls: Vec<String> = {
                        let index = manager.relay_sync_index.read().await;
                        index.keys().cloned().collect()
                    };

                    // Update health state for each relay
                    for relay_url in relay_urls {
                        let state = manager.health_tracker.get_state(&relay_url);
                        metrics.record_health_state(&relay_url, state);
                    }

                    // Update naughty list metrics
                    if let Some(naughty_list) = manager.health_tracker.naughty_list() {
                        let entries = naughty_list.get_all();
                        metrics.update_naughty_list(entries);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Health and metrics checker received shutdown signal");
                break;
            }
        }
    }
}

/// Manages proactive synchronization with external relays
///
/// The SyncManager runs as a background task, subscribing to repository
/// announcements on the local relay and syncing data from external relays
/// listed in those announcements.
pub struct SyncManager {
    /// Bootstrap relay URL for initial sync (optional)
    bootstrap_relay_url: Option<String>,
    /// Our service domain - used for filtering relevant repos
    service_domain: String,
    /// Database for event storage and queries
    database: SharedDatabase,
    /// Write policy for validating incoming events
    write_policy: Nip34WritePolicy,
    /// Purgatory for read-only access to events awaiting git data
    purgatory: Arc<crate::purgatory::Purgatory>,
    /// Local relay for submitting synced events (enables broadcast to WebSocket subscribers)
    local_relay: LocalRelay,
    /// Configuration reference for sync settings
    config: Config,
    /// What we want to sync (source of truth)
    repo_sync_index: RepoSyncIndex,
    /// What we've confirmed syncing + connection state
    relay_sync_index: RelaySyncIndex,
    /// In-flight subscription batches
    pending_sync_index: PendingSyncIndex,
    /// Rejected events (30617/30618) - two-tier storage for re-processing
    /// Handles both announcement and state events via EventType discriminator
    rejected_events_index: Arc<RejectedEventsIndex>,
    /// GRASP-P Phase 2: alias → registration sync needs, rebuilt from the
    /// relay DB's kind-30640 events. Only populated when
    /// `config.private_repos_enable`; drives the derived 30641/stream-wrap filters.
    private_sync_index: Arc<RwLock<private_index::PrivateSyncIndex>>,
    /// FS-3 (review L2-F4): per-peer floor between private filter
    /// re-issues (index-change-triggered consolidations AND the hourly
    /// full re-issue), plus the sticky flag that retries a floor-skipped
    /// index-change re-issue on a later tick.
    private_reissue_floor: PrivateReissueFloor,
    private_reissue_pending: bool,
    /// Active relay connections - keyed by relay URL
    connections: HashMap<String, RelayConnection>,
    /// Health tracker for relay connection state
    health_tracker: Arc<RelayHealthTracker>,
    /// Counter for generating unique batch IDs
    next_batch_id: u64,
    /// Channel for disconnect notifications (set during run)
    disconnect_tx: Option<tokio::sync::mpsc::Sender<DisconnectNotification>>,
    /// Channel for EOSE notifications (set during run)
    eose_tx: Option<tokio::sync::mpsc::Sender<EoseNotification>>,
    /// Channel for connect notifications (set during run)
    connect_tx: Option<tokio::sync::mpsc::Sender<ConnectNotification>>,
    /// Channel for broadcasting shutdown signal to all background tasks
    shutdown_tx: Option<broadcast::Sender<()>>,
    /// Prometheus metrics for sync operations (None if metrics disabled)
    metrics: Option<SyncMetrics>,
}

impl SyncManager {
    /// Create a new SyncManager
    ///
    /// # Arguments
    /// * `bootstrap_relay_url` - Optional relay URL for initial historical sync
    /// * `service_domain` - The domain this relay serves (for filtering repos)
    /// * `database` - Shared database for event storage
    /// * `write_policy` - Policy for validating events before storage
    /// * `local_relay` - Local relay for submitting synced events (enables WebSocket broadcast)
    /// * `config` - Configuration for sync settings
    /// * `data_path` - Path to git data directory (for persistence)
    /// * `sync_metrics` - Optional pre-registered SyncMetrics (passed from Metrics if metrics are enabled)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bootstrap_relay_url: Option<String>,
        service_domain: String,
        database: SharedDatabase,
        write_policy: Nip34WritePolicy,
        local_relay: LocalRelay,
        config: &Config,
        data_path: PathBuf,
        sync_metrics: Option<SyncMetrics>,
    ) -> Self {
        // Extract purgatory from write_policy for read-only access
        let purgatory = write_policy.purgatory().clone();

        // Create rejected events index
        let rejected_events_index = Arc::new(if let Some(ref metrics) = sync_metrics {
            RejectedEventsIndex::with_metrics(
                Duration::from_secs(config.rejected_hot_cache_duration_secs),
                Duration::from_secs(config.rejected_cold_index_expiry_secs),
                metrics.clone(),
            )
        } else {
            RejectedEventsIndex::new(
                Duration::from_secs(config.rejected_hot_cache_duration_secs),
                Duration::from_secs(config.rejected_cold_index_expiry_secs),
            )
        });

        // Attempt to restore rejected events index from disk
        let rejected_index_path = data_path.join("rejected-events-cache.json");
        if rejected_index_path.exists() {
            match rejected_events_index.restore_from_disk(&rejected_index_path) {
                Ok(()) => {
                    tracing::info!("Restored rejected events index from disk");
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to restore rejected events index: {}, starting empty",
                        e
                    );
                }
            }
        }

        Self {
            bootstrap_relay_url,
            service_domain,
            database,
            write_policy,
            purgatory,
            local_relay,
            config: config.clone(),
            repo_sync_index: Arc::new(RwLock::new(HashMap::new())),
            relay_sync_index: Arc::new(RwLock::new(HashMap::new())),
            pending_sync_index: Arc::new(RwLock::new(HashMap::new())),
            rejected_events_index,
            private_sync_index: Arc::new(RwLock::new(
                private_index::PrivateSyncIndex::default(),
            )),
            private_reissue_floor: PrivateReissueFloor::default(),
            private_reissue_pending: false,
            connections: HashMap::new(),
            health_tracker: Arc::new(RelayHealthTracker::new(config)),
            next_batch_id: 0,
            disconnect_tx: None,
            eose_tx: None,
            connect_tx: None,
            shutdown_tx: None,
            metrics: sync_metrics,
        }
    }

    /// Generate a unique batch ID
    ///
    /// Increments the internal counter and returns the new value.
    /// Used for tracking pending batches and debugging/logging.
    fn next_batch_id(&mut self) -> u64 {
        self.next_batch_id += 1;
        self.next_batch_id
    }

    /// Get a clone of the rejected events index Arc.
    ///
    /// This allows access to the rejected events index for persistence
    /// even after the SyncManager has been moved into a task.
    ///
    /// # Returns
    /// Arc clone of the rejected events index
    pub fn rejected_events_index(&self) -> Arc<RejectedEventsIndex> {
        self.rejected_events_index.clone()
    }

    /// Save rejected events index to disk.
    ///
    /// This is called during shutdown to persist the rejected events cache,
    /// allowing us to avoid re-downloading rejected events after restart.
    ///
    /// # Arguments
    /// * `path` - Path to save the rejected index file
    ///
    /// # Returns
    /// Ok(()) on success, Err if save fails
    pub fn save_rejected_index(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        self.rejected_events_index.save_to_disk(path)
    }

    /// Handle EOSE (End Of Stored Events) for a subscription
    ///
    /// This method:
    /// - Finds the PendingBatch containing this subscription ID
    /// - Removes the subscription from outstanding_subs
    /// - When all subscriptions complete (outstanding_subs empty):
    ///   - Calls confirm_batch to move items to confirmed state
    async fn handle_eose(&mut self, relay_url: &str, sub_id: SubscriptionId) {
        // Check if relay is in Disconnecting state
        let is_disconnecting = {
            let index = self.relay_sync_index.read().await;
            index
                .get(relay_url)
                .map(|s| s.connection_status == ConnectionStatus::Disconnecting)
                .unwrap_or(false)
        };

        // 1. Find and update the pending batch
        let mut pending = self.pending_sync_index.write().await;

        let Some(batches) = pending.get_mut(relay_url) else {
            // This can happen when EOSE arrives after batch has already been confirmed/removed.
            // Common causes:
            // 1. During intentional disconnect (cleanup in progress)
            // 2. Duplicate/late EOSE from relay (e.g., live_sync REQ subscriptions may send
            //    multiple EOSE messages - some relays do this)
            // 3. Race condition between batch confirmation and EOSE arrival
            //
            // NOTE: If we wanted to investigate whether these are truly duplicate EOSEs,
            // we could track recently-completed subscription IDs (with timestamps) and
            // check if this sub_id was recently confirmed. This would distinguish between:
            // - Duplicate EOSE (sub_id was recently in outstanding_subs)
            // - Truly unknown subscription (sub_id never tracked)
            if is_disconnecting {
                // Expected during intentional disconnect - suppress noisy log
                tracing::trace!(
                    relay = %relay_url,
                    sub_id = %sub_id,
                    "EOSE received during disconnect cleanup - ignoring"
                );
            } else {
                // Expected when batch completes before late/duplicate EOSE arrives
                tracing::trace!(
                    relay = %relay_url,
                    sub_id = %sub_id,
                    "EOSE received after batch already completed (late or duplicate EOSE)"
                );
            }
            return;
        };

        // Find the batch containing this subscription
        let batch_index = batches
            .iter()
            .position(|b| b.outstanding_subs.contains(&sub_id));

        let Some(batch_idx) = batch_index else {
            // Live subscriptions (limit:0, no auto-close) are not tracked in PendingBatch.
            // They complete immediately with EOSE (no historic events) and stay open for new events.
            // Observed in production: sync_live() subscriptions trigger this path (expected).
            // Also possible: duplicate/late EOSE from relay after batch already completed.
            tracing::trace!(
                relay = %relay_url,
                sub_id = %sub_id,
                "EOSE received for subscription not tracked in batch (live subscription or late EOSE)"
            );
            return;
        };

        // Remove the subscription from outstanding_subs
        let batch = &mut batches[batch_idx];
        batch.outstanding_subs.remove(&sub_id);

        tracing::debug!(
            relay = %relay_url,
            sub_id = %sub_id,
            batch_id = batch.batch_id,
            remaining_subs = batch.outstanding_subs.len(),
            "EOSE processed for subscription"
        );

        // Check for pagination: if this subscription hit the threshold, fetch next page
        if let Some(pagination_state) = batch.pagination_state.remove(&sub_id) {
            if pagination_state.event_count >= PAGINATION_THRESHOLD {
                if let Some(min_created_at) = pagination_state.min_created_at {
                    tracing::info!(
                        relay = %relay_url,
                        sub_id = %sub_id,
                        batch_id = batch.batch_id,
                        event_count = pagination_state.event_count,
                        min_created_at = %min_created_at,
                        "Subscription hit pagination threshold, fetching next page"
                    );

                    // Create next page filter: same as original but with .until(min_created_at)
                    // dont subtract 1 second to avoid duplicate events at the boundary
                    // as this would lead to missed events with the same created_at timestamp
                    let until_timestamp = Timestamp::from(min_created_at.as_secs());
                    let mut next_filter = pagination_state.original_filter.clone();
                    next_filter = next_filter.until(until_timestamp);

                    // Store relay_url for spawning the subscription after releasing the lock
                    let relay_url_for_pagination = relay_url.to_string();
                    let batch_id = batch.batch_id;

                    // Drop the lock before async operations
                    drop(pending);

                    // Wait for rate limiting to clear before pagination continues
                    if self.health_tracker.is_rate_limited(relay_url) {
                        tracing::debug!(
                            relay = %relay_url,
                            batch_id = batch_id,
                            "Relay is rate limited, waiting before pagination"
                        );

                        // Loop until rate limit clears, sleeping with jitter between checks
                        while self.health_tracker.is_rate_limited(relay_url) {
                            let jitter_secs = 1 + (rand::random::<u64>() % 5); // 1-5 seconds
                            sleep(Duration::from_secs(jitter_secs)).await;
                        }

                        tracing::debug!(
                            relay = %relay_url,
                            batch_id = batch_id,
                            "Rate limit cleared, continuing pagination"
                        );
                        let batch_exists = {
                            let pending = self.pending_sync_index.read().await;
                            pending
                                .get(&relay_url_for_pagination)
                                .map(|batches| batches.iter().any(|b| b.batch_id == batch_id))
                                .unwrap_or(false)
                        };

                        // If we were rate limited, verify batch still exists after waiting
                        // (batches are wiped during disconnect, so avoid orphaned pagination)
                        if !batch_exists {
                            tracing::debug!(
                                relay = %relay_url_for_pagination,
                                batch_id = batch_id,
                                "Batch no longer exists after rate limit wait, skipping pagination"
                            );
                            return;
                        }
                    }

                    // Subscribe to next page and add to outstanding_subs
                    if let Some(conn) = self.connections.get(&relay_url_for_pagination) {
                        match conn.subscribe_filter(next_filter.clone(), true).await {
                            Ok(new_sub_id) => {
                                // Re-acquire lock to update the batch
                                let mut pending = self.pending_sync_index.write().await;
                                if let Some(batches) = pending.get_mut(&relay_url_for_pagination) {
                                    if let Some(batch) =
                                        batches.iter_mut().find(|b| b.batch_id == batch_id)
                                    {
                                        batch.outstanding_subs.insert(new_sub_id.clone());
                                        // Initialize pagination state for new subscription
                                        batch.pagination_state.insert(
                                            new_sub_id.clone(),
                                            PaginationState {
                                                event_count: 0,
                                                min_created_at: None,
                                                original_filter: next_filter,
                                            },
                                        );
                                        tracing::info!(
                                            relay = %relay_url_for_pagination,
                                            new_sub_id = %new_sub_id,
                                            batch_id = batch_id,
                                            until = %until_timestamp,
                                            "Next page subscription created"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    relay = %relay_url_for_pagination,
                                    batch_id = batch_id,
                                    error = %e,
                                    "Failed to create pagination subscription, continuing without next page"
                                );
                            }
                        }
                    }

                    // Early return since we've released and re-acquired locks
                    return;
                }
            }
        }

        // Check if batch is complete
        if !batch.outstanding_subs.is_empty() {
            return;
        }

        // 2. Batch complete - validate negentropy ID fetches before confirming
        // For negentropy batches, check if all requested events were received
        if batch.sync_method == SyncMethod::Negentropy {
            if let (Some(requested), Some(received)) =
                (&batch.requested_event_ids, &batch.received_event_ids)
            {
                let missing: Vec<EventId> = requested.difference(received).cloned().collect();

                if !missing.is_empty() {
                    let requested_count = requested.len();
                    let received_count = received.len();
                    let retry_count = batch.retry_count;

                    // Check if we made any progress (received ANY events we requested)
                    // If received_count is 0, relay returned nothing useful - abort retry
                    //
                    // NOTE: Some relays (e.g., azzamo.net, snort.social) have been observed
                    // returning zero events during negentropy retry even though manual queries
                    // (REQ by ID) show they DO have these events. This appears to be relay-
                    // specific behavior where the relay refuses to serve events via negentropy
                    // retry for unknown reasons (rate limiting, negentropy implementation bugs,
                    // or other internal logic). When retry returns zero, fall back to REQ+EOSE.
                    if retry_count > 0 && received_count == 0 {
                        tracing::info!(
                            relay = %relay_url,
                            batch_id = batch.batch_id,
                            retry_count = retry_count,
                            requested_count = requested_count,
                            missing_count = missing.len(),
                            missing_ids = ?missing.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
                            "Negentropy retry made no progress - relay returned zero requested events. \
                             Marking relay as not supporting negentropy and falling back to REQ+EOSE."
                        );

                        // Mark relay as not supporting negentropy so future batches skip it
                        if let Some(conn) = self.connections.get(relay_url) {
                            conn.mark_negentropy_unsupported();
                        }

                        // Prepare for REQ+EOSE fallback using semantic filters
                        // (not ID-based queries which already failed)
                        let relay_url_for_fallback = relay_url.to_string();
                        let batch_id = batch.batch_id;
                        let batch_repos = batch.items.repos.clone();
                        let batch_root_events = batch.items.root_events.clone();
                        let missing_count = missing.len();

                        // Drop the lock before async operations
                        drop(pending);

                        // Create REQ+EOSE subscriptions using original semantic filters
                        // This queries by kind/author/tags instead of by ID, which may
                        // succeed even when ID-based queries fail.
                        // Split batch_repos by SyncLevel to avoid sending Layer 2 filters
                        // (#a/#A/#q) for StateOnly (purgatory) repos - those PRs would be
                        // rejected as orphan and then silently dropped by nostr-sdk deduplication.
                        let (full_repos, state_only_repos) = {
                            let repo_index = self.repo_sync_index.read().await;
                            let mut full = HashSet::new();
                            let mut state_only = HashSet::new();
                            for repo_ref in &batch_repos {
                                match repo_index.get(repo_ref).map(|n| n.sync_level) {
                                    Some(SyncLevel::StateOnly) => {
                                        state_only.insert(repo_ref.clone());
                                    }
                                    _ => {
                                        full.insert(repo_ref.clone());
                                    }
                                }
                            }
                            (full, state_only)
                        };
                        let fallback_filters = filters::build_sync_level_aware_filters(
                            &full_repos,
                            &state_only_repos,
                            &batch_root_events,
                            None,
                        );

                        if fallback_filters.is_empty() {
                            tracing::warn!(
                                relay = %relay_url_for_fallback,
                                batch_id = batch_id,
                                repos = batch_repos.len(),
                                root_events = batch_root_events.len(),
                                "Cannot create semantic fallback filters - no repos or root_events in batch"
                            );
                            // Fall through to ID-based fallback as last resort
                        }

                        let mut new_sub_ids = HashSet::new();
                        if let Some(conn) = self.connections.get(&relay_url_for_fallback) {
                            for filter in fallback_filters {
                                match conn.subscribe_filter(filter, true).await {
                                    Ok(sub_id) => {
                                        new_sub_ids.insert(sub_id);
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            relay = %relay_url_for_fallback,
                                            batch_id = batch_id,
                                            error = %e,
                                            "Failed to create REQ+EOSE fallback subscription"
                                        );
                                    }
                                }
                            }
                        }

                        if !new_sub_ids.is_empty() {
                            // Re-acquire lock and update batch to use REQ+EOSE
                            let mut pending = self.pending_sync_index.write().await;
                            if let Some(batches) = pending.get_mut(&relay_url_for_fallback) {
                                if let Some(batch) =
                                    batches.iter_mut().find(|b| b.batch_id == batch_id)
                                {
                                    // Switch to REQ+EOSE sync method
                                    batch.sync_method = SyncMethod::ReqEose;
                                    // Clear negentropy-specific tracking
                                    batch.requested_event_ids = None;
                                    batch.received_event_ids = None;
                                    // Reset retry count for REQ+EOSE flow
                                    batch.retry_count = 0;
                                    // Add new subscriptions to outstanding_subs
                                    batch.outstanding_subs.extend(new_sub_ids.clone());

                                    tracing::info!(
                                        relay = %relay_url_for_fallback,
                                        batch_id = batch_id,
                                        fallback_subs = new_sub_ids.len(),
                                        missing_events = missing_count,
                                        "Switched batch to REQ+EOSE fallback, waiting for EOSE"
                                    );
                                }
                            }
                            // Early return - batch not complete yet, waiting for REQ+EOSE EOSE
                            return;
                        } else {
                            // Failed to create any fallback subscriptions, mark as failed
                            tracing::error!(
                                relay = %relay_url_for_fallback,
                                batch_id = batch_id,
                                missing_count = missing_count,
                                "Failed to create REQ+EOSE fallback subscriptions - completing batch with partial results"
                            );

                            // Re-acquire lock to extract the batch
                            let mut pending = self.pending_sync_index.write().await;
                            if let Some(batches) = pending.get_mut(&relay_url_for_fallback) {
                                if let Some(idx) =
                                    batches.iter().position(|b| b.batch_id == batch_id)
                                {
                                    let mut completed_batch = batches.remove(idx);
                                    completed_batch.failed = true; // Mark as failed
                                    if batches.is_empty() {
                                        pending.remove(&relay_url_for_fallback);
                                    }
                                    drop(pending);
                                    self.confirm_batch(&relay_url_for_fallback, completed_batch)
                                        .await;
                                }
                            }
                            return;
                        }
                    }

                    tracing::warn!(
                        relay = %relay_url,
                        batch_id = batch.batch_id,
                        retry_count = retry_count,
                        requested_count = requested_count,
                        received_count = received_count,
                        missing_count = missing.len(),
                        missing_ids = ?missing.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
                        "Negentropy sync incomplete - relay returned fewer events than requested. \
                         This may indicate a relay limit on ID-based queries. \
                         Retrying missing events."
                    );

                    // Create retry subscription for missing events
                    // Chunk by 300 to avoid overly large filters
                    let relay_url_for_retry = relay_url.to_string();
                    let batch_id = batch.batch_id;

                    // Drop the lock before async operations
                    drop(pending);

                    // Create new subscriptions for missing events
                    let retry_filters: Vec<_> = missing
                        .chunks(300)
                        .map(|c| Filter::new().ids(c.iter().copied()))
                        .collect();

                    let mut new_sub_ids = HashSet::new();
                    if let Some(conn) = self.connections.get(&relay_url_for_retry) {
                        for filter in retry_filters {
                            match conn.subscribe_filter(filter, true).await {
                                Ok(sub_id) => {
                                    new_sub_ids.insert(sub_id);
                                }
                                Err(e) => {
                                    tracing::error!(
                                        relay = %relay_url_for_retry,
                                        batch_id = batch_id,
                                        error = %e,
                                        "Failed to create retry subscription for missing events"
                                    );
                                }
                            }
                        }
                    }

                    if !new_sub_ids.is_empty() {
                        // Re-acquire lock and update batch with new subscriptions
                        let mut pending = self.pending_sync_index.write().await;
                        if let Some(batches) = pending.get_mut(&relay_url_for_retry) {
                            if let Some(batch) = batches.iter_mut().find(|b| b.batch_id == batch_id)
                            {
                                batch.outstanding_subs.extend(new_sub_ids.clone());
                                // Update requested_event_ids to only include missing ones
                                batch.requested_event_ids = Some(missing.iter().cloned().collect());
                                // Clear received_event_ids for fresh tracking
                                batch.received_event_ids = Some(HashSet::new());
                                // Increment retry counter
                                batch.retry_count += 1;

                                tracing::info!(
                                    relay = %relay_url_for_retry,
                                    batch_id = batch_id,
                                    retry_subs = new_sub_ids.len(),
                                    missing_events = missing.len(),
                                    retry_attempt = batch.retry_count,
                                    "Created retry subscriptions for missing negentropy events"
                                );
                            }
                        }
                        // Early return - batch not complete yet, waiting for retry EOSE
                        return;
                    } else {
                        // Failed to create retry subscriptions, log and continue to confirm
                        // with partial results
                        tracing::error!(
                            relay = %relay_url_for_retry,
                            batch_id = batch_id,
                            missing_count = missing.len(),
                            "Failed to retry missing events - confirming batch with partial results"
                        );

                        // Re-acquire lock to extract the batch
                        let mut pending = self.pending_sync_index.write().await;
                        if let Some(batches) = pending.get_mut(&relay_url_for_retry) {
                            if let Some(idx) = batches.iter().position(|b| b.batch_id == batch_id) {
                                let completed_batch = batches.remove(idx);
                                if batches.is_empty() {
                                    pending.remove(&relay_url_for_retry);
                                }
                                drop(pending);
                                self.confirm_batch(&relay_url_for_retry, completed_batch)
                                    .await;
                            }
                        }
                        return;
                    }
                }
            }
        }

        // 3. Batch complete - extract and remove
        let completed_batch = batches.remove(batch_idx);

        // Clean up empty relay entry
        if batches.is_empty() {
            pending.remove(relay_url);
        }

        // Drop the pending lock before confirm_batch
        drop(pending);

        // 4. Confirm the batch (moves items to RelayState)
        self.confirm_batch(relay_url, completed_batch).await;
    }

    /// Confirm a completed batch by moving items to RelayState
    ///
    /// This method is used by both sync paths (REQ+EOSE and Negentropy) to
    /// move repos and root_events from pending to confirmed state. This unified
    /// flow ensures consistent state tracking regardless of sync method.
    ///
    /// For generic filter batches (identified by empty repos and root_events),
    /// this sets the announcements_synced flag to enable incremental sync on reconnect.
    ///
    /// # Arguments
    /// * `relay_url` - The relay URL the batch belongs to
    /// * `batch` - The completed batch to confirm
    async fn confirm_batch(&self, relay_url: &str, batch: PendingBatch) {
        let batch_id = batch.batch_id;
        let repos_count = batch.items.repos.len();
        let events_count = batch.items.root_events.len();
        let sync_method = batch.sync_method;
        let is_generic_filter = repos_count == 0 && events_count == 0;

        let mut relay_index = self.relay_sync_index.write().await;

        if let Some(state) = relay_index.get_mut(relay_url) {
            // Move repos to confirmed
            state.repos.extend(batch.items.repos);
            // Move root_events to confirmed
            state.root_events.extend(batch.items.root_events.clone());

            // Set announcements_synced flag for generic filter batches
            if is_generic_filter {
                state.announcements_synced = true;
                tracing::info!(
                    relay = %relay_url,
                    batch_id = batch_id,
                    sync_method = ?sync_method,
                    "Generic filter (announcements) historic sync complete - announcements_synced set to true"
                );

                // Provide helpful feedback for bootstrap relay
                if state.is_bootstrap {
                    let announcement_count = events_count;
                    if announcement_count == 0 {
                        tracing::info!(
                            relay = %relay_url,
                            domain = %self.config.domain,
                            "Bootstrap sync found no announcements for domain - verify domain is correct or try different bootstrap relay"
                        );
                    } else {
                        tracing::info!(
                            relay = %relay_url,
                            domain = %self.config.domain,
                            announcement_count,
                            "Bootstrap sync discovered announcements for domain"
                        );
                    }
                }
            }

            // Track if this batch failed (for ConnectedDegraded transition)
            if batch.failed {
                state.historic_sync_had_failures = true;
                tracing::warn!(
                    relay = %relay_url,
                    batch_id = batch_id,
                    "Batch failed - will transition to ConnectedHistoricSyncFailures instead of Connected"
                );
            }

            // DEBUG TRACING: Log the root events being confirmed
            tracing::info!(
                relay = %relay_url,
                batch_id = batch_id,
                sync_method = ?sync_method,
                repos_confirmed = repos_count,
                root_events_confirmed = events_count,
                root_events_ids = ?batch.items.root_events.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
                total_repos = state.repos.len(),
                total_root_events = state.root_events.len(),
                all_root_events = ?state.root_events.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
                is_generic_filter = is_generic_filter,
                announcements_synced = state.announcements_synced,
                had_failures = state.historic_sync_had_failures,
                "Batch confirmed - items moved from pending to confirmed"
            );
        } else {
            tracing::warn!(
                relay = %relay_url,
                batch_id = batch_id,
                "Batch completed but no RelayState found for relay"
            );
        }

        // Release lock before checking if historic sync is complete
        drop(relay_index);

        // Spawn background task to check if historic sync is complete
        // This avoids blocking the confirm_batch flow for 6 seconds
        let relay_url = relay_url.to_string();
        let pending_index = self.pending_sync_index.clone();
        let relay_index = self.relay_sync_index.clone();
        let metrics = self.metrics.clone();

        tokio::spawn(async move {
            Self::check_and_complete_historic_sync_impl(
                &relay_url,
                pending_index,
                relay_index,
                metrics,
            )
            .await;
        });
    }

    /// Check if historic sync is complete and transition to Connected status
    ///
    /// This method uses a double-check pattern to avoid race conditions with
    /// the self-subscriber's batching window. The sequence is:
    ///
    /// 1. First check: Are there pending batches?
    /// 2. Wait for batch window + buffer (6 seconds)
    /// 3. Second check: Are there still no pending batches?
    /// 4. If still no pending batches, transition to Connected
    ///
    /// This ensures that events received just before the first check have time
    /// to be batched and create Layer 2/3 filters before we mark sync complete.
    ///
    /// The 6-second delay is based on:
    /// - Self-subscriber batch window: 5 seconds (200ms when `NGIT_TEST=1`)
    /// - Buffer for processing: 1 second
    ///
    /// Called after each batch is confirmed to detect completion.
    /// Spawned as a background task to avoid blocking the confirm_batch flow.
    async fn check_and_complete_historic_sync_impl(
        relay_url: &str,
        pending_index: PendingSyncIndex,
        relay_index: RelaySyncIndex,
        metrics: Option<SyncMetrics>,
    ) {
        // First check: Are there any pending batches?
        let has_pending = {
            let pending = pending_index.read().await;
            pending
                .get(relay_url)
                .is_some_and(|batches| !batches.is_empty())
        };

        if has_pending {
            // Still syncing, don't transition yet
            return;
        }

        // Wait for self-subscriber batch window + buffer to catch any in-flight events
        // that might create new Layer 2/3 filters
        tokio::time::sleep(Duration::from_millis(6000)).await;

        // Second check: Are there still no pending batches?
        let has_pending = {
            let pending = pending_index.read().await;
            pending
                .get(relay_url)
                .is_some_and(|batches| !batches.is_empty())
        };

        if has_pending {
            // New batches appeared during the wait - still syncing
            return;
        }

        // No pending batches after waiting - safe to transition to Connected or ConnectedDegraded
        let mut relay_index_guard = relay_index.write().await;
        if let Some(state) = relay_index_guard.get_mut(relay_url) {
            if state.connection_status == ConnectionStatus::Syncing {
                // Check if any batches failed during historic sync
                let new_status = if state.historic_sync_had_failures {
                    ConnectionStatus::ConnectedHistoricSyncFailures
                } else {
                    ConnectionStatus::Connected
                };

                state.connection_status = new_status;
                state.historic_sync_completed = true;
                state.historic_sync_completed_at = Some(Timestamp::now());

                tracing::info!(
                    relay = %relay_url,
                    repos_synced = state.repos.len(),
                    root_events_synced = state.root_events.len(),
                    had_failures = state.historic_sync_had_failures,
                    status = ?new_status,
                    "Historic sync complete - transitioned to {} status",
                    if state.historic_sync_had_failures { "ConnectedHistoricSyncFailures" } else { "Connected" }
                );

                // Update metrics
                if let Some(ref metrics) = metrics {
                    metrics.record_connection_status(relay_url, new_status);
                }
            }
        }
    }

    /// Perform a daily sync for a specific relay
    ///
    /// This method:
    /// - Unsubscribes from all current subscriptions on the relay
    /// - Clears pending batches for this relay
    /// - Clears sync state (repos and root_events) in RelayState
    /// - Recomputes actions to re-discover all repos/events
    ///
    /// This is triggered by the daily timer to detect state drift over time.
    async fn daily_sync(&mut self, relay_url: &str) {
        tracing::info!(relay = %relay_url, "Starting daily sync");

        // Get connection
        let connection = match self.connections.get(relay_url) {
            Some(conn) => conn,
            None => {
                tracing::warn!(
                    relay = %relay_url,
                    "No connection for relay, skipping daily sync"
                );
                return;
            }
        };

        // Unsubscribe all current subscriptions
        connection.unsubscribe_all().await;

        // Clear pending batches for this relay
        {
            let mut pending = self.pending_sync_index.write().await;
            pending.remove(relay_url);
        }

        // Get relay state and clear sync state (repos and root_events)
        {
            let mut index = self.relay_sync_index.write().await;
            if let Some(state) = index.get_mut(relay_url) {
                let repos_cleared = state.repos.len();
                let events_cleared = state.root_events.len();
                state.clear_sync_state();
                tracing::debug!(
                    relay = %relay_url,
                    repos_cleared = repos_cleared,
                    events_cleared = events_cleared,
                    "Cleared sync state for daily sync"
                );
            }
        }

        // maybe we just run start fresh with a daily flag? make sture so start layer 1 filters
        self.fresh_start(relay_url).await;

        // if let Some(ref metrics) = self.metrics {
        //     metrics.record_event(event_source::DAILY);
        // }

        // tracing::info!(relay = %relay_url, "Daily sync complete");
    }

    /// Run the sync manager
    ///
    /// Coordinates all sync components:
    /// 1. Spawns self-subscriber to monitor own relay for announcements
    /// 2. Spawns daily timer for periodic fresh syncs
    /// 3. Connects to bootstrap relay if configured
    /// 4. Handles relay actions from self-subscriber
    /// 5. Handles disconnect, EOSE, and connect notifications from spawned relay tasks
    pub async fn run(mut self) {
        use tokio::sync::mpsc;

        tracing::info!(
            bootstrap_relay = ?self.bootstrap_relay_url,
            service_domain = %self.service_domain,
            "SyncManager starting"
        );

        // 1. Create action channel for self-subscriber -> manager communication
        let (action_tx, mut action_rx) = mpsc::channel::<AddFilters>(100);

        // 2. Create disconnect channel for spawned tasks -> manager communication
        let (disconnect_tx, mut disconnect_rx) = mpsc::channel::<DisconnectNotification>(100);

        // 3. Create EOSE channel for spawned tasks -> manager communication
        let (eose_tx, mut eose_rx) = mpsc::channel::<EoseNotification>(100);

        // 4. Create connect channel for spawned tasks -> manager communication
        let (connect_tx, mut connect_rx) = mpsc::channel::<ConnectNotification>(100);

        // 4b. Create shutdown broadcast channel for graceful shutdown
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);

        // 5. Spawn self-subscriber with shutdown receiver
        let self_subscriber = SelfSubscriber::new(
            format!("ws://{}", self.config.bind_address),
            self.service_domain.clone(),
            Arc::clone(&self.repo_sync_index),
            action_tx,
            self.database.clone(),
        );
        let subscriber_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move { self_subscriber.run(Some(subscriber_shutdown)).await });

        // 5b. Store channel senders for use by handlers
        self.disconnect_tx = Some(disconnect_tx.clone());
        self.eose_tx = Some(eose_tx.clone());
        self.connect_tx = Some(connect_tx.clone());
        self.shutdown_tx = Some(shutdown_tx.clone());

        // 6. Connect to bootstrap relay if configured
        if let Some(ref bootstrap_url) = self.bootstrap_relay_url.clone() {
            self.register_relay(bootstrap_url.clone(), true).await;
            self.try_connect_relay(bootstrap_url).await;
        }

        // 7. Wrap self in Arc<Mutex> for sharing with timer task
        let sync_manager = Arc::new(Mutex::new(self));

        // 8. Spawn daily timer task with shutdown receiver
        let timer_manager = Arc::clone(&sync_manager);
        let timer_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            run_daily_timer(timer_manager, timer_shutdown).await;
        });

        // 9. Spawn health and metrics checker task with shutdown receiver
        // This combines disconnect checking, rate limit recovery, and metrics updates
        let checker_manager = Arc::clone(&sync_manager);
        let checker_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            run_health_and_metrics_checker(checker_manager, checker_shutdown).await;
        });

        // 10. Spawn rejected events index cleanup task
        // Hot cache cleanup every 60s, cold index cleanup daily
        let cleanup_manager = Arc::clone(&sync_manager);
        let cleanup_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            run_rejected_index_cleanup(cleanup_manager, cleanup_shutdown).await;
        });

        // 11. Spawn purgatory announcement sync timer (every 5s)
        // Ensures purgatory announcements (including user-submitted ones that never
        // touch the DB) are registered in repo_sync_index as StateOnly so that
        // state event subscriptions are established on their listed relay URLs.
        let purgatory_sync_manager = Arc::clone(&sync_manager);
        let purgatory_sync_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            run_purgatory_announcement_sync(purgatory_sync_manager, purgatory_sync_shutdown).await;
        });

        // 12b. GRASP-P Phase 2: spawn the private registration sync timer.
        // Strictly additive — never spawned when private repos are disabled.
        let private_enabled = {
            let manager = sync_manager.lock().await;
            manager.config.private_repos_enable
        };
        if private_enabled {
            let private_sync_manager = Arc::clone(&sync_manager);
            let private_sync_shutdown = shutdown_tx.subscribe();
            tokio::spawn(async move {
                run_private_registration_sync(private_sync_manager, private_sync_shutdown).await;
            });

            // 12c. GRASP-P Phase-4b B1: hourly since=None full re-issue of
            // the private sync filters (0 = disabled).
            let full_reissue_manager = Arc::clone(&sync_manager);
            let full_reissue_shutdown = shutdown_tx.subscribe();
            tokio::spawn(async move {
                run_private_full_reissue_timer(full_reissue_manager, full_reissue_shutdown).await;
            });
        }

        // 12. Main loop - handle actions from self-subscriber, disconnect, EOSE, and connect notifications
        loop {
            // Wait for an event without holding the lock
            tokio::select! {
                action = action_rx.recv() => {
                    match action {
                        Some(add_filters) => {
                            // Process AddFilters action directly
                            let mut manager = sync_manager.lock().await;
                            manager.handle_new_sync_filters(add_filters).await;
                        }
                        None => break,
                    }
                }
                disconnect = disconnect_rx.recv() => {
                    match disconnect {
                        Some(notification) => {
                            // Acquire lock to process disconnect
                            let mut manager = sync_manager.lock().await;
                            manager.handle_disconnect(&notification.relay_url).await;
                        }
                        None => {
                            // All disconnect senders dropped - unlikely but handle gracefully
                            tracing::debug!("Disconnect channel closed");
                        }
                    }
                }
                eose = eose_rx.recv() => {
                    match eose {
                        Some(notification) => {
                            // Acquire lock to process EOSE
                            let mut manager = sync_manager.lock().await;
                            manager.handle_eose(&notification.relay_url, notification.sub_id).await;
                        }
                        None => {
                            // All EOSE senders dropped - unlikely but handle gracefully
                            tracing::debug!("EOSE channel closed");
                        }
                    }
                }
                connect = connect_rx.recv() => {
                    match connect {
                        Some(notification) => {
                            // Acquire lock to process connect
                            let mut manager = sync_manager.lock().await;
                            manager.handle_connect_or_reconnect(&notification.relay_url).await;
                        }
                        None => {
                            // All connect senders dropped - unlikely but handle gracefully
                            tracing::debug!("Connect channel closed");
                        }
                    }
                }
            }
        }
    }

    /// Handle AddFilters action - subscribe to filters on a relay
    ///
    /// This method handles all filter additions:
    /// - For new relays: creates entry with Connecting status, spawns connection
    /// - For existing connected relays: subscribes to filters, creates PendingBatch
    /// - For disconnected/connecting relays: returns (will be handled on connection)
    async fn handle_new_sync_filters(&mut self, action: AddFilters) {
        // Step 1: Check if relay exists in relay_sync_index
        let connection_status = {
            let index = self.relay_sync_index.read().await;
            index.get(&action.relay_url).map(|s| s.connection_status)
        };

        match connection_status {
            None => {
                // New relay - register and connect
                tracing::info!(
                    relay = %action.relay_url,
                    repos = action.items.repos.len(),
                    "Registering and connecting to new relay"
                );

                // Register relay (creates RelayConnection, initializes RelayState, updates metrics)
                self.register_relay(action.relay_url.clone(), false).await;
                self.try_connect_relay(&action.relay_url).await;
                // Connection will trigger handle_connect_or_reconnect which will process items
                return;
            }
            Some(ConnectionStatus::Disconnected)
            | Some(ConnectionStatus::Connecting)
            | Some(ConnectionStatus::Disconnecting) => {
                // Will be handled when connection succeeds (or ignored if disconnecting)
                tracing::debug!(
                    relay = %action.relay_url,
                    status = ?connection_status,
                    "Relay not connected, action will be processed on connection"
                );
                return;
            }
            Some(ConnectionStatus::Syncing)
            | Some(ConnectionStatus::Connected)
            | Some(ConnectionStatus::ConnectedHistoricSyncFailures) => {
                // Continue to subscribe - live sync is active, can accept new filters
            }
        }

        // Step 2: Check if relay is rate-limited before creating new pending items
        if self.health_tracker.is_rate_limited(&action.relay_url) {
            tracing::debug!(
                relay = %action.relay_url,
                repos = action.items.repos.len(),
                root_events = action.items.root_events.len(),
                "Skipping AddFilters for rate-limited relay, will recompute after cooldown"
            );
            return;
        }

        // Step 3: Check if consolidation is needed BEFORE adding new filters
        self.maybe_consolidate(&action.relay_url, action.filters.len())
            .await;

        // Subscribe to each filter and collect subscription IDs
        tracing::info!(
            relay = %action.relay_url,
            filter_count = action.filters.len(),
            repo_count = action.items.repos.len(),
            root_event_count = action.items.root_events.len(),
            "handle_add_filters: calling sync_live and historic_sync"
        );

        self.sync_live(&action.relay_url, &action.filters).await;
        self.historic_sync(&action.relay_url, action.filters, action.items, None)
            .await;
    }

    /// Handle a connection success (called when a relay connects or reconnects)
    ///
    /// This method:
    /// 1. Updates RelayState to Connected
    /// 2. Spawns event loop (MUST happen on every connection/reconnect)
    /// 3. Dispatches to appropriate reconnection strategy based on disconnect time
    async fn handle_connect_or_reconnect(&mut self, relay_url: &str) {
        use tokio::sync::mpsc;

        // 1. Capture old last_connected BEFORE updating state
        // This is critical for correct first-connection detection
        let old_last_connected = {
            let index = self.relay_sync_index.read().await;
            index.get(relay_url).and_then(|s| s.last_connected)
        };

        // 2. Update state to Syncing (will transition to Connected after historic sync completes)
        {
            let mut index = self.relay_sync_index.write().await;
            let state = index.entry(relay_url.to_string()).or_default();
            state.connection_status = ConnectionStatus::Syncing;
            state.last_connected = Some(Timestamp::now());
            state.disconnected_at = None;
        }

        // Update metrics - record as syncing initially
        if let Some(ref metrics) = self.metrics {
            metrics.record_connection_status(relay_url, ConnectionStatus::Syncing);
            metrics.inc_connected_count();
        }

        // 2. SPAWN EVENT LOOP (moved from spawn_relay_connection)
        // This MUST happen on every connection (initial or reconnect)
        // because event loops die on disconnect and cannot be reused
        let connection = match self.connections.get(relay_url) {
            Some(c) => c.clone(),
            None => {
                tracing::error!(relay = %relay_url, "No RelayConnection found for connected relay");
                return;
            }
        };

        let (event_tx, mut event_rx) = mpsc::channel::<RelayEvent>(1000);

        // Spawn event loop task
        let relay_url_for_loop = relay_url.to_string();
        tokio::spawn(async move {
            connection.run_event_loop(event_tx).await;
            tracing::debug!(relay = %relay_url_for_loop, "Event loop terminated");
        });

        // Spawn event processor task
        let relay_url_clone = relay_url.to_string();
        let database = Arc::clone(&self.database);
        let write_policy = self.write_policy.clone();
        let local_relay = self.local_relay.clone();
        let disconnect_tx = self.disconnect_tx.as_ref().unwrap().clone();
        let eose_tx = self.eose_tx.as_ref().unwrap().clone();
        let metrics_clone = self.metrics.clone();
        let pending_sync_index = Arc::clone(&self.pending_sync_index);
        let health_tracker = Arc::clone(&self.health_tracker);
        let rejected_events_index = Arc::clone(&self.rejected_events_index);

        tokio::spawn(async move {
            let mut disconnect_sent = false;

            while let Some(relay_event) = event_rx.recv().await {
                match relay_event {
                    RelayEvent::Event(event, subscription_id) => {
                        // Skip events we've already rejected (announcements only)
                        if (event.kind == Kind::GitRepoAnnouncement
                            || event.kind == Kind::RepoState)
                            && rejected_events_index.contains(&event.id)
                        {
                            tracing::trace!(
                                event_id = %event.id,
                                kind = %event.kind.as_u16(),
                                relay = %relay_url_clone,
                                "Skipping previously rejected announcement event"
                            );
                            continue;
                        }

                        // GRASP-P Phase 2: skip known-rejected private events
                        // (30640/30641 + the accepted stream-wrap kinds) —
                        // same refetch-loop protection, via the dedicated
                        // private rejected index. Inert when private repos
                        // are disabled (private() is None).
                        if let Some(private) = write_policy.private() {
                            let kind = event.kind.as_u16();
                            let is_private_kind = kind == crate::private::KIND_REGISTRATION
                                || kind == crate::private::KIND_STATE_ROOT
                                || private.accepts_stream_wrap_kind(kind);
                            if is_private_kind && private.sync_rejected().contains(&event.id) {
                                tracing::trace!(
                                    event_id = %event.id,
                                    kind = %kind,
                                    relay = %relay_url_clone,
                                    "Skipping previously rejected private event"
                                );
                                continue;
                            }
                        }

                        let result = Self::process_event_static(
                            &event,
                            &relay_url_clone,
                            &database,
                            &write_policy,
                            &local_relay,
                            &rejected_events_index,
                            crate::nostr::persistence::SaveContext::RelaySync,
                        )
                        .await;
                        // Only record metric when event is actually saved
                        if result == ProcessResult::Saved {
                            if let Some(ref metrics) = metrics_clone {
                                metrics.record_synced_event();
                            }
                        }

                        // For sync-triggered events that go to purgatory, trigger immediate sync
                        // (instead of the default 3-minute delay for user-submitted events)
                        //
                        // Note: announcement events (kind 30617) are registered in repo_sync_index
                        // by the purgatory announcement sync timer (run_purgatory_announcement_sync)
                        // rather than inline here.
                        if result == ProcessResult::Purgatory {
                            // State events (kind 30618) - extract identifier and trigger immediate sync
                            if event.kind.as_u16() == 30618 {
                                if let Some(identifier) = event.tags.iter().find_map(|tag| {
                                    let tag_vec = tag.clone().to_vec();
                                    if tag_vec.len() >= 2 && tag_vec[0] == "d" {
                                        Some(tag_vec[1].clone())
                                    } else {
                                        None
                                    }
                                }) {
                                    tracing::debug!(
                                        event_id = %event.id,
                                        identifier = %identifier,
                                        "Triggering immediate sync for synced state event in purgatory"
                                    );
                                    write_policy.purgatory().enqueue_sync_immediate(&identifier);
                                }
                            }
                            // PR events (kind 1617/1618) - extract identifier from 'a' tag
                            else if event.kind.as_u16() == 1617 || event.kind.as_u16() == 1618 {
                                if let Some(identifier) =
                                    crate::git::sync::extract_identifier_from_pr_event(&event)
                                {
                                    tracing::debug!(
                                        event_id = %event.id,
                                        identifier = %identifier,
                                        "Triggering immediate sync for synced PR event in purgatory"
                                    );
                                    write_policy.purgatory().enqueue_sync_immediate(&identifier);
                                }
                            }
                        }

                        // Track pagination state for this subscription (REQ+EOSE)
                        // and received event IDs for negentropy batches
                        if result == ProcessResult::Saved || result == ProcessResult::Duplicate {
                            let mut pending = pending_sync_index.write().await;
                            if let Some(batches) = pending.get_mut(&relay_url_clone) {
                                for batch in batches.iter_mut() {
                                    // Track pagination state (REQ+EOSE path)
                                    if let Some(state) =
                                        batch.pagination_state.get_mut(&subscription_id)
                                    {
                                        state.event_count += 1;
                                        // Track minimum created_at timestamp
                                        match state.min_created_at {
                                            None => state.min_created_at = Some(event.created_at),
                                            Some(min) if event.created_at < min => {
                                                state.min_created_at = Some(event.created_at);
                                            }
                                            _ => {}
                                        }
                                    }

                                    // Track received event IDs (negentropy path)
                                    // Only track if this batch has requested_event_ids set
                                    // and the subscription is one we're waiting on
                                    if batch.requested_event_ids.is_some()
                                        && batch.outstanding_subs.contains(&subscription_id)
                                    {
                                        if let Some(ref mut received) = batch.received_event_ids {
                                            received.insert(event.id);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    RelayEvent::EndOfStoredEvents(sub_id) => {
                        tracing::debug!(
                            relay = %relay_url_clone,
                            sub_id = %sub_id,
                            "EOSE received, notifying SyncManager"
                        );
                        let _ = eose_tx
                            .send(EoseNotification {
                                relay_url: relay_url_clone.clone(),
                                sub_id,
                            })
                            .await;
                    }
                    RelayEvent::Notice(notice) => {
                        // Check for rate limiting indicators
                        let notice_lower = notice.to_lowercase();
                        let is_rate_limit = (notice_lower.contains("rate")
                            && notice_lower.contains("limit"))
                            || notice_lower.contains("too many")
                            || notice_lower.contains("slow down")
                            || notice_lower.contains("throttl");

                        if is_rate_limit {
                            tracing::warn!(
                                relay = %relay_url_clone,
                                notice = %notice,
                                "Rate limiting NOTICE detected from relay"
                            );

                            // Mark relay as rate limited
                            health_tracker.record_rate_limit(&relay_url_clone);

                            // Update metrics with new health state
                            if let Some(ref metrics) = metrics_clone {
                                let state = health_tracker.get_state(&relay_url_clone);
                                metrics.record_health_state(&relay_url_clone, state);
                            }
                        } else {
                            // Log at TRACE level to avoid duplicate with nostr_relay_pool's DEBUG log
                            // (nostr-sdk already logs all NOTICE messages at DEBUG level)
                            tracing::trace!(
                                relay = %relay_url_clone,
                                notice = %notice,
                                "Relay issued notice"
                            );
                        }
                    }
                    RelayEvent::Closed(reason) => {
                        // CLOSED message means one subscription was closed, not the whole connection
                        // This is normal behavior (e.g., when historic_sync completes)
                        tracing::debug!(
                            relay = %relay_url_clone,
                            reason = %reason,
                            "Relay closed a subscription (not a connection close)"
                        );
                        // Don't break - other subscriptions remain active
                        // Don't send disconnect - connection is still alive
                    }
                    RelayEvent::Shutdown => {
                        tracing::info!(relay = %relay_url_clone, "Relay shutdown detected");
                        if !disconnect_sent {
                            let _ = disconnect_tx
                                .send(DisconnectNotification {
                                    relay_url: relay_url_clone.clone(),
                                })
                                .await;
                            disconnect_sent = true;
                        }
                        break;
                    }
                }
            }

            // If the event channel closed without a Closed/Shutdown event
            if !disconnect_sent {
                tracing::info!(
                    relay = %relay_url_clone,
                    "Event channel closed, notifying SyncManager of disconnect"
                );
                let _ = disconnect_tx
                    .send(DisconnectNotification {
                        relay_url: relay_url_clone,
                    })
                    .await;
            }
        });

        tracing::info!(
            relay = %relay_url,
            "Event loop and processor spawned for connected relay"
        );

        // 3. Decide reconnection strategy based on OLD last_connected time
        // Use the value captured BEFORE the update to correctly detect first connections
        if let Some(last) = old_last_connected {
            let elapsed = Timestamp::now().as_secs().saturating_sub(last.as_secs());
            if elapsed < QUICK_RECONNECT_WINDOW_SECS {
                // Short disconnect - quick reconnect
                tracing::info!(
                    relay = %relay_url,
                    disconnect_secs = elapsed,
                    "Short disconnection - initiating quick_reconnect"
                );
                self.quick_reconnect(relay_url, Timestamp::from(elapsed))
                    .await;
            } else {
                // Long disconnect - fresh start
                tracing::info!(
                    relay = %relay_url,
                    disconnect_secs = elapsed,
                    "Long disconnection - initiating fresh_start"
                );
                self.fresh_start(relay_url).await;
            }
        } else {
            // First connection - fresh start
            tracing::info!(
                relay = %relay_url,
                "First connection - initiating fresh_start"
            );
            self.fresh_start(relay_url).await;
        }
    }

    /// Fresh start - clears state and does full sync
    ///
    /// Called by: initial connect, long_reconnect, daily_sync
    ///
    /// Flow:
    /// 1. Clear PendingSyncIndex for this relay
    /// 2. Clear RelaySyncIndex sync state (repos/root_events)
    /// 3. Update connection state to Connected
    /// 4. L1 live + L1 historic (negentropy if available)
    /// 5. compute_actions → AddFilters → sync_computed_filters for L2+L3
    async fn fresh_start(&mut self, relay_url: &str) {
        let _now = Timestamp::now();

        tracing::info!(relay = %relay_url, "Starting fresh_start");

        // Step 1: Clear PendingSyncIndex for this relay
        {
            let mut pending = self.pending_sync_index.write().await;
            if pending.remove(relay_url).is_some() {
                tracing::debug!(
                    relay = %relay_url,
                    "Cleared pending batches in fresh_start"
                );
            }
        }

        // Step 2: Clear RelaySyncIndex sync state (but preserve connection metadata)
        {
            let mut index = self.relay_sync_index.write().await;
            if let Some(state) = index.get_mut(relay_url) {
                let repos_cleared = state.repos.len();
                let events_cleared = state.root_events.len();
                state.clear_sync_state();
                if repos_cleared > 0 || events_cleared > 0 {
                    tracing::debug!(
                        relay = %relay_url,
                        repos_cleared = repos_cleared,
                        events_cleared = events_cleared,
                        "Cleared sync state in fresh_start"
                    );
                }
                // Only sync if we're connected (live sync active)
                if state.connection_status.is_live_sync_active() {
                    drop(index);
                    self.sync_generic_filters(relay_url, None).await;
                    // Step 5: compute_actions for L2+L3 (will be triggered by EOSE)
                    self.recompute_new_sync_filters_for_relay(relay_url).await;
                }
            } else {
                drop(index);
            }
        }
    }

    async fn sync_generic_filters(&mut self, relay_url: &str, since: Option<Timestamp>) {
        let mut filters = vec![filters::build_announcement_filter(None)];

        // GRASP-P Phase 2: the private registration filter (kind 30640) is a
        // Layer-1 sibling — always subscribed alongside announcements — and
        // the current derived 30641/stream-wrap filters ride the same connect-time
        // subscription so a (re)connected peer is fully covered. Strictly
        // additive: with private repos disabled the filter set is unchanged.
        if self.config.private_repos_enable {
            filters.push(filters::build_private_registration_filter(None));
            let derived_inputs = self.private_sync_index.read().await.derived_inputs();
            filters.extend(filters::build_private_derived_filters(
                &derived_inputs,
                None,
                self.config.private_accept_legacy_wrap_kind,
            ));
        }

        // Create live subscription for ongoing announcements
        let _sub_ids = self.sync_live(relay_url, &filters).await;

        // Use historic_sync with empty PendingItems for generic filters
        // Generic filters (announcements) don't have associated repos or root_events
        let items = PendingItems::default();
        let _batch_id = self.historic_sync(relay_url, filters, items, since).await;
    }

    /// GRASP-P Phase 2: rebuild the PrivateSyncIndex from the relay DB's
    /// kind-30640 events, reprocess held out-of-order events for newly
    /// available registrations, and (on change) re-issue derived filters to
    /// connected peers + connect newly-listed peer relays.
    ///
    /// Driven by `run_private_registration_sync` (5s, 200ms in tests). The
    /// DB is the single source of truth, so client-pushed and synced 30640s
    /// (and NIP-09 deletes, which remove the event from the DB) are all
    /// reflected within one interval.
    async fn sync_private_registrations_to_index(&mut self) {
        if !self.config.private_repos_enable {
            return;
        }

        let filter = Filter::new().kind(Kind::Custom(crate::private::KIND_REGISTRATION));
        let events = match self.database.query(filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!("private registration index query failed: {e}");
                return;
            }
        };

        let mut entries: HashMap<String, private_index::PrivateRepoEntry> = HashMap::new();
        for event in events.into_iter() {
            let mut alias: Option<String> = None;
            let mut keys: Vec<String> = Vec::new();
            let mut relay_urls: Vec<String> = Vec::new();
            let mut server_urls: Vec<String> = Vec::new();
            for tag in event.tags.iter() {
                let v = tag.clone().to_vec();
                if v.len() < 2 {
                    continue;
                }
                match v[0].as_str() {
                    "d" => {
                        if alias.is_none() {
                            alias = Some(v[1].clone());
                        }
                    }
                    // Key tags are [name, pubkey, pop-signature]; only the
                    // pubkey matters for filters.
                    "w" | "aux" => keys.push(v[1].clone()),
                    "relays" => relay_urls.extend(v[1..].iter().cloned()),
                    "server" => server_urls.extend(v[1..].iter().cloned()),
                    _ => {}
                }
            }
            let Some(alias) = alias else { continue };
            keys.sort();
            keys.dedup();
            entries.insert(
                alias,
                private_index::PrivateRepoEntry {
                    keys,
                    relay_urls,
                    server_urls,
                },
            );
        }

        let diff = {
            let mut index = self.private_sync_index.write().await;
            index.replace_all(entries)
        };

        // Out-of-order reprocess (design 1.4): drain held 30641s keyed by a
        // newly-registered alias and held stream wraps authored by a newly-claimed
        // key, then re-run them through the standard application path. The
        // sync path ALSO reprocesses inline on 30640 Accept; this timer pass
        // covers registrations that arrived via client WebSocket push.
        if !diff.added_aliases.is_empty() || !diff.added_keys.is_empty() {
            if let Some(private) = self.write_policy.private() {
                let private = Arc::clone(private);
                let mut held: Vec<Event> = Vec::new();
                for alias in &diff.added_aliases {
                    held.extend(private.sync_rejected().take_for_alias(alias));
                }
                held.extend(private.sync_rejected().take_for_authors(&diff.added_keys));
                let mut seen: HashSet<EventId> = HashSet::new();
                held.retain(|e| seen.insert(e.id));
                for event in held {
                    let result = Box::pin(Self::process_event_static(
                        &event,
                        "private-30640-reprocess",
                        &self.database,
                        &self.write_policy,
                        &self.local_relay,
                        &self.rejected_events_index,
                        crate::nostr::persistence::SaveContext::HotCacheReprocess,
                    ))
                    .await;
                    tracing::info!(
                        event_id = %event.id,
                        kind = %event.kind.as_u16(),
                        result = ?result,
                        "Re-processed held private event after 30640 registration"
                    );
                }
            }
        }

        // FS-2 (review L3-F4) + R2-1 (verify round 2): retry held
        // cadence-rejected 30640 replacements on EVERY tick (not just index
        // changes), but bounded: per-entry refill-aware eligibility (the
        // drain skips not-yet-eligible entries — retrying faster than the
        // bucket refills is pure waste), newest-only-per-(tenant,alias)
        // holds, and a per-tick FIFO drain cap. Worst case per 5s tick:
        // MAX_REGISTRATION_RETRIES_PER_TICK x full Live admission (parse +
        // up to 64 PoP schnorr verifies ~4-7ms + one LMDB write txn that
        // commits even on reject) ~= 0.26-0.45s under the SyncManager
        // mutex — vs ~3.3-5.7 cores sustained for the pre-R2-1 design
        // (a 4096-deep hold retried every tick). Bucket refill is
        // wall-clock-lazy (the token bucket accrues on the next try_take),
        // so a retry after enough wall time succeeds under normal Live
        // admission; a retry still over cadence is re-held by the rejection
        // path (fresh eligibility + TTL), and an edition that went stale
        // while held is absorbed by the accept-no-op anchor-repair path.
        // This runs before the diff gate: the retry must not wait for an
        // index change.
        if let Some(private) = self.write_policy.private() {
            let drain = private.sync_rejected().drain_registrations(
                std::time::Instant::now(),
                private_index::MAX_REGISTRATION_RETRIES_PER_TICK,
            );
            let retried = drain.events.len();
            for event in drain.events {
                let result = Box::pin(Self::process_event_static(
                    &event,
                    "private-cadence-retry",
                    &self.database,
                    &self.write_policy,
                    &self.local_relay,
                    &self.rejected_events_index,
                    crate::nostr::persistence::SaveContext::HotCacheReprocess,
                ))
                .await;
                // R2-1(d): per-retry outcomes at debug — the info-level
                // signal is the per-tick summary below (a flooded hold
                // used to emit ~820 info lines/s).
                tracing::debug!(
                    event_id = %event.id,
                    kind = %event.kind.as_u16(),
                    result = ?result,
                    "Re-processed held cadence-rejected 30640 replacement"
                );
            }
            // R2-1(d): one counts-only info line per tick while the hold
            // is non-empty.
            if retried > 0 || drain.remaining > 0 {
                tracing::info!(
                    retried,
                    held_remaining = drain.remaining,
                    "Private cadence-rejected 30640 retry drain"
                );
            }
        }

        // FS-3 (review L2-F4): a re-issue is due when the index changed OR
        // a previous re-issue was floor-skipped. The replace_all diff is
        // NOT sticky (rebuilding an unchanged index reports
        // changed=false), so the pending flag is what retries a skipped
        // re-issue on a later tick — skipped consolidations are deferred,
        // never dropped.
        let wants_reissue = diff.changed || self.private_reissue_pending;
        if !wants_reissue {
            return;
        }

        let derived = {
            let index = self.private_sync_index.read().await;
            filters::build_private_derived_filters(
                &index.derived_inputs(),
                None,
                self.config.private_accept_legacy_wrap_kind,
            )
        };

        // Connect operator-allowlisted peer relays not yet registered. Peers
        // come EXCLUSIVELY from NGIT_PRIVATE_SYNC_PEER_URLS — tenant 30640
        // `relays` tags are advisory metadata and must never trigger an
        // outbound connection (SSRF / membership-map-leak guard). Their
        // filters arrive on connect via sync_generic_filters.
        let peer_urls = private_index::configured_peer_relay_urls(
            &self.config.private_sync_peer_url_entries(),
            &self.service_domain,
        );
        let unknown_peers: Vec<String> = {
            let index = self.relay_sync_index.read().await;
            peer_urls
                .iter()
                .filter(|url| !index.contains_key(*url))
                .cloned()
                .collect()
        };
        for url in unknown_peers {
            if !crate::private::mirror::relay_peer_allowed(
                &url,
                self.config.private_mirror_allow_private_ips,
            )
            .await
            {
                tracing::warn!(
                    relay = %url,
                    "Skipping private-repo peer relay: SSRF guard rejected URL"
                );
                continue;
            }
            tracing::info!(relay = %url, "Registering private-repo peer relay");
            self.register_relay(url.clone(), false).await;
            self.try_connect_relay(&url).await;
        }

        if derived.is_empty() {
            // No aliases means nothing to re-issue; any pending retry is
            // moot (a peer that connects later gets the current — empty —
            // derived set at connect time).
            self.private_reissue_pending = false;
            return;
        }

        // Re-issue the derived filters to every live-connected relay
        // (since=None backfill, mirroring handle_new_sync_filters). A peer
        // skipped by the FS-3 floor keeps the retry pending for a later
        // tick; a clean round clears it.
        let outcome = self.reissue_filters_to_live_relays(derived).await;
        self.private_reissue_pending = outcome.floor_skipped > 0;
    }

    /// Re-issue private sync filters to every live-connected relay with a
    /// since=None backfill (mirrors handle_new_sync_filters). Shared by the
    /// PrivateSyncIndex change path above and the Phase-4b B1 periodic full
    /// re-issue timer below.
    ///
    /// FS-3 (review L2-F4): each peer is additionally gated by the
    /// NGIT_PRIVATE_REISSUE_MIN_INTERVAL_SECS floor (NGIT_TEST-clamped to
    /// <= 1s, the hourly-timer idiom scaled down) — past the consolidation
    /// threshold a churning derived-filter set would otherwise consolidate
    /// a peer on every dirty 5s tick. Rate-limited relays are skipped as
    /// before (their recovery is the health tracker's, not this floor's).
    async fn reissue_filters_to_live_relays(&mut self, filters: Vec<Filter>) -> PrivateReissueOutcome {
        let floor_secs = self.config.private_reissue_min_interval_secs;
        let floor_secs = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
            floor_secs.min(1)
        } else {
            floor_secs
        };
        let floor = Duration::from_secs(floor_secs);
        let now = std::time::Instant::now();
        let live_relays: Vec<String> = {
            let index = self.relay_sync_index.read().await;
            index
                .iter()
                .filter(|(_, state)| state.connection_status.is_live_sync_active())
                .map(|(url, _)| url.clone())
                .collect()
        };
        let mut outcome = PrivateReissueOutcome::default();
        for relay_url in live_relays {
            if self.health_tracker.is_rate_limited(&relay_url) {
                continue;
            }
            if !self.private_reissue_floor.admit(&relay_url, floor, now) {
                outcome.floor_skipped += 1;
                continue;
            }
            self.maybe_consolidate(&relay_url, filters.len()).await;
            self.sync_live(&relay_url, &filters).await;
            self.historic_sync(&relay_url, filters.clone(), PendingItems::default(), None)
                .await;
            outcome.sent += 1;
        }
        outcome
    }

    /// GRASP-P Phase-4b B1: periodic since=None full re-issue of the private
    /// sync filters — the Layer-1 kind-30640 registration filter PLUS the
    /// current derived 30641/stream-wrap filters — to every live peer (driven by
    /// `run_private_full_reissue_timer`, hourly by default).
    ///
    /// Exactly mirrors the index-change path's delivery mechanism (live
    /// re-subscribe + since=None historic backfill) but is NOT gated on an
    /// index diff: it heals gaps the change path cannot see — expired
    /// rejected-hot-cache entries, negentropy blind spots, and
    /// cadence-limited 30640 rejections (WP-A A2) that deliberately rely on
    /// redelivery. With an empty index (zero aliases) the bare 30640 filter
    /// is still re-issued (cheap self-heal for missed registrations).
    /// Public subscriptions are deliberately NOT torn down — that is
    /// fresh_start/daily_sync territory and far too heavy for an hourly
    /// timer.
    async fn reissue_private_filters_full(&mut self) {
        if !self.config.private_repos_enable {
            return;
        }
        // Same filter build as the connect-time path (sync_generic_filters):
        // 30640 first, then the derived filters from the CURRENT index.
        let mut filters = vec![filters::build_private_registration_filter(None)];
        let derived_inputs = self.private_sync_index.read().await.derived_inputs();
        filters.extend(filters::build_private_derived_filters(
            &derived_inputs,
            None,
            self.config.private_accept_legacy_wrap_kind,
        ));
        let outcome = self.reissue_filters_to_live_relays(filters).await;
        // FS-8 (review L3-F7): the counter must tell the truth — increment
        // only when at least one peer was actually re-issued. A round where
        // every live relay was skipped (rate-limit cooldown or the FS-3
        // floor) counts separately so a chronically-skipped peer is visible
        // instead of masquerading as a healthy re-issue cadence.
        if outcome.sent > 0 {
            crate::metrics::record_private_full_reissue();
        } else {
            crate::metrics::record_private_full_reissue_skipped();
        }
    }

    /// Quick reconnect - for disconnections < 15 minutes
    ///
    /// Re-establishes subscriptions after a brief disconnection by:
    /// 1. Clearing stale PendingSyncIndex entries
    /// 2. Syncing L1 filters with since timestamp (announcements)
    /// 3. Rebuilding L2+L3 from preserved RelaySyncIndex state
    /// 4. Computing actions for new items discovered during catchup
    ///
    /// Basic connection state and metrics are managed by handle_connect_or_reconnect.
    /// This method handles reconnect-specific concerns (health tracking, reconnect metrics).
    async fn quick_reconnect(&mut self, relay_url: &str, since: Timestamp) {
        // Step 1: Clear PendingSyncIndex for this relay
        // Old subscriptions are dead after disconnect
        {
            let mut pending = self.pending_sync_index.write().await;
            pending.remove(relay_url);
        }

        // Record successful reconnection in health tracker
        self.health_tracker.record_success(relay_url);

        // Record reconnect-specific metrics (not basic connection metrics)
        if let Some(ref metrics) = self.metrics {
            metrics.record_health_state(relay_url, self.health_tracker.get_state(relay_url));
        }

        // Step 2: L1 live + L1 historic with since filter (or full sync if announcements never completed)
        let announcement_since = {
            let index = self.relay_sync_index.read().await;
            if let Some(state) = index.get(relay_url) {
                if state.announcements_synced {
                    Some(since) // Can use incremental sync
                } else {
                    None // Need full sync - announcements never completed
                }
            } else {
                None
            }
        };

        self.sync_generic_filters(relay_url, announcement_since)
            .await;

        // Step 3: Rebuild L2+L3 from confirmed state with since filter
        // This uses the preserved repos/root_events from RelaySyncIndex
        self.rebuild_layer2_and_layer3(relay_url, Some(since)).await;

        // Step 4: compute_actions for any NEW items discovered while disconnected
        self.recompute_new_sync_filters_for_relay(relay_url).await;
    }

    /// Rebuild Layer 2 and Layer 3 subscriptions for a relay
    ///
    /// Uses the confirmed repos and root_events from RelayState to build filters.
    /// If since is provided, applies it to all filters for incremental sync.
    ///
    /// CRITICAL: This method now creates a PendingBatch to track subscriptions,
    /// ensuring EOSE handling works correctly for live sync scenarios.
    async fn rebuild_layer2_and_layer3(&mut self, relay_url: &str, since: Option<Timestamp>) {
        use crate::sync::filters::build_layer2_and_layer3_filters;

        // Get confirmed state from relay_sync_index
        let (repos, root_events) = {
            let index = self.relay_sync_index.read().await;
            match index.get(relay_url) {
                Some(state) => (state.repos.clone(), state.root_events.clone()),
                None => {
                    tracing::warn!(
                        relay = %relay_url,
                        "No RelayState found for rebuild_layer2_and_layer3"
                    );
                    return;
                }
            }
        };

        // Nothing to rebuild if no confirmed items
        if repos.is_empty() && root_events.is_empty() {
            tracing::debug!(
                relay = %relay_url,
                "No confirmed items to rebuild Layer 2/3 for"
            );
            return;
        }

        // Build Layer 2 and Layer 3 filters
        let filters = build_layer2_and_layer3_filters(&repos, &root_events, since);

        if filters.is_empty() {
            tracing::debug!(
                relay = %relay_url,
                "No filters generated for Layer 2/3 rebuild"
            );
            return;
        }
        self.sync_live(relay_url, &filters).await;
    }

    /// Register a relay for managed connection/reconnection
    ///
    /// Creates a RelayConnection object and stores it in the connections HashMap.
    /// Also initializes RelayState if it doesn't exist.
    /// Does NOT connect - connection happens via try_connect_relay or retry_disconnected_relays.
    /// The RelayConnection persists forever and is reused on reconnects.
    async fn register_relay(&mut self, relay_url: String, is_bootstrap: bool) {
        // Create RelayConnection if not exists
        if !self.connections.contains_key(&relay_url) {
            // Get relay owner keys for NIP-42 authentication
            let keys = self
                .config
                .relay_owner_keys()
                .expect("relay_owner_keys should be available");

            let connection = RelayConnection::new_with_database(
                relay_url.clone(),
                Arc::clone(&self.database),
                keys,
            );
            self.connections.insert(relay_url.clone(), connection);
            tracing::debug!(relay = %relay_url, "Registered new relay connection");
        }

        // Initialize RelayState if not exists
        let is_new = {
            let mut index = self.relay_sync_index.write().await;
            if !index.contains_key(&relay_url) {
                let new_state = RelayState {
                    connection_status: ConnectionStatus::Disconnected,
                    is_bootstrap,
                    last_connected: None,
                    disconnected_at: None,
                    repos: HashSet::new(),
                    root_events: HashSet::new(),
                    announcements_synced: false,
                    historic_sync_completed: false,
                    historic_sync_completed_at: None,
                    historic_sync_had_failures: false,
                };
                index.insert(relay_url.clone(), new_state);
                true
            } else {
                // If relay already exists and is_bootstrap is true, update the flag
                if is_bootstrap {
                    if let Some(state) = index.get_mut(&relay_url) {
                        state.is_bootstrap = true;
                    }
                }
                false
            }
        };

        // Track new relay in metrics
        if is_new {
            if let Some(ref metrics) = self.metrics {
                metrics.inc_tracked_count();
                // Initialize connection status to disconnected
                metrics.set_relay_connected(&relay_url, false);
            }
            tracing::info!(relay = %relay_url, "Registered new relay for tracking");
        }
    }

    /// Attempt a single connection to a registered relay
    ///
    /// Uses the existing RelayConnection from the HashMap and attempts to connect.
    /// On success, sends ConnectNotification which triggers handle_connect_or_reconnect.
    /// On failure, updates state and health tracker.
    async fn try_connect_relay(&mut self, relay_url: &str) {
        // 1. Mark attempting and update metrics
        {
            let mut index = self.relay_sync_index.write().await;
            if let Some(state) = index.get_mut(relay_url) {
                state.connection_status = ConnectionStatus::Connecting;
            }
        }

        // Update metrics to show connecting status
        if let Some(ref metrics) = self.metrics {
            metrics.record_connection_status(relay_url, ConnectionStatus::Connecting);
        }

        // 2. Record attempt in health tracker
        self.health_tracker.record_attempt(relay_url);

        // 3. Get connection and attempt
        let connection = match self.connections.get(relay_url) {
            Some(c) => c,
            None => {
                tracing::error!(relay = %relay_url, "No RelayConnection registered");
                return;
            }
        };

        let timeout = self.health_tracker.base_backoff_secs();

        match connection.connect(timeout).await {
            Ok(()) => {
                // Success - record and send notification
                self.health_tracker.record_success(relay_url);

                if let Some(ref metrics) = self.metrics {
                    metrics.record_connection_attempt(relay_url, true);
                }

                if let Some(ref connect_tx) = self.connect_tx {
                    let _ = connect_tx
                        .send(ConnectNotification {
                            relay_url: relay_url.to_string(),
                        })
                        .await;
                }
            }
            Err(e) => {
                // Classify error to determine if it's a naughty relay or transient issue
                let error_str = e.to_string();

                if let Some(category) = naughty_list::NaughtyListTracker::classify_error(&error_str)
                {
                    // Persistent infrastructure issue - use naughty list
                    if let Some(ref naughty_list) = self.health_tracker.naughty_list() {
                        let is_new = naughty_list.record(relay_url, category, error_str.clone());

                        if is_new {
                            tracing::warn!(
                                relay = %relay_url,
                                category = ?category,
                                error = %e,
                                "Relay has persistent configuration issue, added to naughty list"
                            );
                        } else {
                            tracing::debug!(
                                relay = %relay_url,
                                category = ?category,
                                "Naughty relay failure (already tracked)"
                            );
                        }
                    }
                } else {
                    // Transient network issue - use existing backoff flow
                    tracing::debug!(
                        relay = %relay_url,
                        error = %e,
                        "Connection failed (transient issue, backoff active)"
                    );
                }

                // 4. Update state back to Disconnected on failure
                {
                    let mut index = self.relay_sync_index.write().await;
                    if let Some(state) = index.get_mut(relay_url) {
                        state.connection_status = ConnectionStatus::Disconnected;
                    }
                }

                // 5. Record failure in health tracker
                self.health_tracker.record_failure(relay_url);

                // 6. Update metrics
                if let Some(ref metrics) = self.metrics {
                    metrics.record_connection_attempt(relay_url, false);
                    metrics.record_connection_status(relay_url, ConnectionStatus::Disconnected);
                    metrics
                        .record_health_state(relay_url, self.health_tracker.get_state(relay_url));
                }
            }
        }
    }

    /// Recompute sync actions for a specific relay
    ///
    /// Uses derive_relay_targets and compute_actions to find new items
    /// that need to be synced. Processes AddFilters actions for new items.
    async fn recompute_new_sync_filters_for_relay(&mut self, relay_url: &str) {
        use crate::sync::algorithms::{compute_actions, derive_relay_targets};

        // Get current state from indexes (need to collect to avoid holding locks)
        let all_targets = {
            let repo_index = self.repo_sync_index.read().await;
            derive_relay_targets(&repo_index)
        };

        // Filter to only targets for this specific relay
        let relay_target = match all_targets.get(relay_url) {
            Some(target) => target.clone(),
            None => {
                tracing::debug!(
                    relay = %relay_url,
                    "No sync targets found for relay"
                );
                return;
            }
        };

        // Build single-relay targets map for compute_actions
        let mut single_relay_targets = std::collections::HashMap::new();
        single_relay_targets.insert(relay_url.to_string(), relay_target);

        // Compute actions for new items
        let actions = {
            let pending_index = self.pending_sync_index.read().await;
            let relay_index = self.relay_sync_index.read().await;
            compute_actions(&single_relay_targets, &pending_index, &relay_index)
        };

        if actions.is_empty() {
            tracing::debug!(
                relay = %relay_url,
                "No new items to sync for relay"
            );
            return;
        }

        // Process each action
        for action in actions {
            tracing::info!(
                relay = %action.relay_url,
                new_repos = action.items.repos.len(),
                new_root_events = action.items.root_events.len(),
                filters = action.filters.len(),
                "Processing AddFilters for new items"
            );
            self.handle_new_sync_filters(action).await;
        }
    }

    /// Sync purgatory announcements into repo_sync_index as StateOnly entries.
    ///
    /// Called periodically by the purgatory announcement sync timer (every 5s).
    /// For each announcement currently in purgatory, ensures a `StateOnly` entry
    /// exists in `repo_sync_index`. New entries are then picked up by
    /// `handle_new_sync_filters` which connects to listed relay URLs and subscribes
    /// to state events for that repo.
    ///
    /// Idempotent: existing entries are not downgraded (a promoted Full entry stays Full).
    async fn sync_purgatory_announcements_to_index(&mut self) {
        use crate::sync::algorithms::{compute_actions, derive_relay_targets};

        // Collect all purgatory announcements (snapshot - no async holds)
        let announcements = self.purgatory.announcements_for_sync();

        if announcements.is_empty() {
            return;
        }

        // Register any new entries in repo_sync_index as StateOnly
        let mut new_relay_urls: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        {
            let mut index = self.repo_sync_index.write().await;
            for (repo_id, relays) in &announcements {
                let entry = index.entry(repo_id.clone()).or_insert_with(|| {
                    tracing::debug!(
                        repo_id = %repo_id,
                        "Registering purgatory announcement in repo_sync_index as StateOnly"
                    );
                    RepoSyncNeeds {
                        relays: std::collections::HashSet::new(),
                        root_events: std::collections::HashSet::new(),
                        sync_level: SyncLevel::StateOnly,
                    }
                });
                // Don't downgrade an already-Full entry
                // Add any new relay URLs
                for relay in relays {
                    if entry.relays.insert(relay.clone()) {
                        new_relay_urls.insert(relay.clone());
                    }
                }
            }
        }

        if new_relay_urls.is_empty() {
            return;
        }

        // For any relay URLs that are new, compute and send AddFilters actions
        let all_targets = {
            let repo_index = self.repo_sync_index.read().await;
            derive_relay_targets(&repo_index)
        };

        let actions = {
            let pending_index = self.pending_sync_index.read().await;
            let relay_index = self.relay_sync_index.read().await;
            compute_actions(&all_targets, &pending_index, &relay_index)
        };

        for action in actions {
            // Only act on relays that have new URLs (avoids redundant work)
            if new_relay_urls.contains(&action.relay_url) {
                tracing::info!(
                    relay = %action.relay_url,
                    repos = action.items.repos.len(),
                    "Purgatory sync timer: connecting to new relay from purgatory announcement"
                );
                self.handle_new_sync_filters(action).await;
            }
        }
    }

    /// Handle a relay disconnection
    ///
    /// This method is called when the event loop terminates and sends a disconnect notification.
    /// It handles two cases:
    /// - Unexpected disconnects: Updates state to Disconnected, keeps RelayConnection for reconnect
    /// - Intentional disconnects: Completes cleanup of Disconnecting relays (removes from indices)
    async fn handle_disconnect(&mut self, relay_url: &str) {
        // Check if this was an intentional disconnect (Disconnecting status)
        let was_intentional = {
            let index = self.relay_sync_index.read().await;
            index
                .get(relay_url)
                .map(|s| s.connection_status == ConnectionStatus::Disconnecting)
                .unwrap_or(false)
        };

        if was_intentional {
            // Intentional disconnect - complete cleanup by removing state
            tracing::info!(relay = %relay_url, "Event loop terminated for intentional disconnect, completing cleanup");

            // Update metrics to Disconnected before cleanup
            if let Some(ref metrics) = self.metrics {
                metrics.record_connection_status(relay_url, ConnectionStatus::Disconnected);
            }

            // Remove from relay_sync_index
            {
                let mut index = self.relay_sync_index.write().await;
                if index.remove(relay_url).is_some() {
                    tracing::debug!(
                        relay = %relay_url,
                        "Removed relay from relay_sync_index"
                    );
                }
            }

            // Remove from pending_sync_index
            {
                let mut pending = self.pending_sync_index.write().await;
                if pending.remove(relay_url).is_some() {
                    tracing::debug!(
                        relay = %relay_url,
                        "Removed relay from pending_sync_index"
                    );
                }
            }

            // Remove the connection object (won't reconnect)
            if self.connections.remove(relay_url).is_some() {
                tracing::debug!(
                    relay = %relay_url,
                    "Removed connection from connections map"
                );
            }

            // Update metrics - decrement connected count
            if let Some(ref metrics) = self.metrics {
                metrics.dec_connected_count();
            }

            tracing::info!(relay = %relay_url, "Intentional disconnect cleanup complete");
        } else {
            // Unexpected disconnect - update state but keep for reconnection
            tracing::warn!(relay = %relay_url, "Unexpected relay disconnect detected");

            // Update RelayState in relay_sync_index
            {
                let mut index = self.relay_sync_index.write().await;
                if let Some(state) = index.get_mut(relay_url) {
                    state.connection_status = ConnectionStatus::Disconnected;
                    state.disconnected_at = Some(Timestamp::now());
                    tracing::info!(
                        relay = %relay_url,
                        repos_tracked = state.repos.len(),
                        "Relay state updated to disconnected"
                    );
                } else {
                    tracing::debug!(
                        relay = %relay_url,
                        "No RelayState found for disconnected relay"
                    );
                    return;
                }
            }

            // Clear pending sync batches for this relay
            {
                let mut pending = self.pending_sync_index.write().await;
                if pending.remove(relay_url).is_some() {
                    tracing::debug!(
                        relay = %relay_url,
                        "Cleared pending sync batches for disconnected relay"
                    );
                }
            }

            // Keep RelayConnection in HashMap for reuse on reconnect
            tracing::debug!(
                relay = %relay_url,
                "Keeping RelayConnection in HashMap for reconnection"
            );

            // Record failure in health tracker
            self.health_tracker.record_failure(relay_url);

            // Update metrics
            if let Some(ref metrics) = self.metrics {
                metrics.record_connection_status(relay_url, ConnectionStatus::Disconnected);
                metrics.dec_connected_count();
                metrics.record_health_state(relay_url, self.health_tracker.get_state(relay_url));
            }

            tracing::info!(
                relay = %relay_url,
                health_state = %self.health_tracker.get_state(relay_url),
                "Unexpected disconnect handling complete"
            );
        }
    }

    /// Re-process events from hot cache after their dependencies become available
    ///
    /// This helper consolidates the common pattern of re-processing rejected events
    /// when their missing dependencies (owner announcements, git data, etc.) arrive.
    ///
    /// # Arguments
    /// * `events` - Events to re-process from hot cache
    /// * `context` - Description for logging (e.g., "maintainer announcement", "state event")
    /// * `pubkey` - Public key for logging context
    /// * `identifier` - Repository identifier for logging context
    /// * `relay_url` - Relay URL for process_event_static
    /// * `database` - Shared database for event storage
    /// * `write_policy` - Policy for validating events
    /// * `local_relay` - Local relay for broadcasting events
    /// * `rejected_events_index` - Index for tracking rejected events
    ///
    /// # Returns
    /// Statistics about re-processing outcomes
    #[allow(clippy::too_many_arguments)]
    async fn reprocess_events_from_hot_cache(
        events: Vec<Event>,
        context: &str,
        pubkey: &PublicKey,
        identifier: &str,
        relay_url: &str,
        database: &SharedDatabase,
        write_policy: &Nip34WritePolicy,
        local_relay: &LocalRelay,
        rejected_events_index: &Arc<RejectedEventsIndex>,
    ) -> ReprocessingStats {
        let mut stats = ReprocessingStats::default();

        for event in events {
            tracing::info!(
                event_id = %event.id,
                pubkey = %pubkey,
                identifier = %identifier,
                context = %context,
                "Re-processing {} from hot cache",
                context
            );

            // Recursive call to process_event_static
            // This is safe because:
            // 1. Event was removed from hot cache before this call
            // 2. Second attempt uses new context (different code path)
            // 3. If second attempt fails, stays in cold index only (no third attempt)
            // Use Box::pin to avoid infinitely sized future
            let reprocess_result = Box::pin(Self::process_event_static(
                &event,
                relay_url,
                database,
                write_policy,
                local_relay,
                rejected_events_index,
                crate::nostr::persistence::SaveContext::HotCacheReprocess,
            ))
            .await;

            match reprocess_result {
                ProcessResult::Saved => {
                    stats.saved += 1;
                    tracing::info!(
                        event_id = %event.id,
                        pubkey = %pubkey,
                        identifier = %identifier,
                        "{} accepted on re-processing",
                        context
                    );
                }
                ProcessResult::Duplicate => {
                    stats.duplicate += 1;
                    tracing::debug!(
                        event_id = %event.id,
                        "{} already exists (duplicate)",
                        context
                    );
                }
                ProcessResult::Purgatory => {
                    stats.purgatory += 1;
                    tracing::debug!(
                        event_id = %event.id,
                        "{} added to purgatory (waiting for git data)",
                        context
                    );
                }
                ProcessResult::Rejected => {
                    stats.rejected += 1;
                    tracing::warn!(
                        event_id = %event.id,
                        pubkey = %pubkey,
                        identifier = %identifier,
                        "{} still rejected on re-processing",
                        context
                    );
                }
            }
        }

        stats
    }

    /// Process a single event from a relay (static version for spawned tasks)
    ///
    /// Processes events with dedup, policy check, database save, and broadcast:
    /// - Deduplication (skips if event already exists)
    /// - Write policy validation
    /// - Database save
    /// - Broadcast to WebSocket subscribers via notify_event (enables recursive relay discovery)
    ///
    /// Returns `ProcessResult` to indicate whether the event was saved, duplicate, or rejected.
    async fn process_event_static(
        event: &Event,
        relay_url: &str,
        database: &SharedDatabase,
        write_policy: &Nip34WritePolicy,
        local_relay: &LocalRelay,
        rejected_events_index: &Arc<RejectedEventsIndex>,
        save_context: crate::nostr::persistence::SaveContext,
    ) -> ProcessResult {
        use nostr_relay_builder::prelude::{WritePolicy, WritePolicyResult};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        // Check if event already exists
        match database.event_by_id(&event.id).await {
            Ok(Some(_)) => {
                tracing::trace!(event_id = %event.id, "Event already exists, skipping");
                return ProcessResult::Duplicate;
            }
            Err(e) => {
                tracing::warn!(event_id = %event.id, error = %e, "Database error checking event");
                return ProcessResult::Rejected;
            }
            Ok(None) => {} // Continue processing
        }

        // Apply write policy using a dummy address (sync events aren't from network clients)
        let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let result = write_policy.admit_event(event, &dummy_addr).await;

        match result {
            WritePolicyResult::Accept => {
                // Save event to database

                if let Err(e) = write_policy.save_accepted_event(event, save_context).await {
                    tracing::error!(
                        event_id = %event.id,
                        relay = %relay_url,
                        error = %e,
                        "Failed to save synced event"
                    );
                    return ProcessResult::Rejected;
                }

                // Broadcast to WebSocket subscribers (enables recursive relay discovery)
                // This allows SelfSubscriber to receive synced 30617 announcements
                let broadcast_success = local_relay.notify_event(event.clone());

                tracing::debug!(
                    event_id = %event.id,
                    relay = %relay_url,
                    kind = %event.kind.as_u16(),
                    broadcast = broadcast_success,
                    "Synced event saved and broadcast"
                );

                // When a repository announcement is accepted, re-process any rejected events:
                // 1. Maintainer announcements that were rejected because the owner announcement didn't exist yet
                // 2. State events that were rejected because no announcement existed
                // This handles race conditions where events arrive before their dependencies during relay sync.
                if event.kind == Kind::GitRepoAnnouncement {
                    use crate::nostr::events::RepositoryAnnouncement;

                    match RepositoryAnnouncement::from_event(event.clone()) {
                        Ok(announcement) => {
                            // Re-process rejected maintainer announcements
                            if !announcement.maintainers.is_empty() {
                                tracing::debug!(
                                    event_id = %event.id,
                                    identifier = %announcement.identifier,
                                    maintainer_count = announcement.maintainers.len(),
                                    "Owner announcement accepted, checking for rejected maintainer announcements"
                                );

                                // For each maintainer, invalidate and get their events
                                for maintainer_hex in &announcement.maintainers {
                                    // Parse maintainer public key
                                    match PublicKey::from_hex(maintainer_hex) {
                                        Ok(maintainer_pubkey) => {
                                            let (removed, hot_events) = rejected_events_index
                                                .invalidate_and_get(
                                                    &maintainer_pubkey,
                                                    &announcement.identifier,
                                                    Some(rejected_index::EventType::Announcement),
                                                );

                                            if removed > 0 {
                                                tracing::info!(
                                                    maintainer = %maintainer_hex,
                                                    identifier = %announcement.identifier,
                                                    removed_from_cold_index = removed,
                                                    hot_cache_events = hot_events.len(),
                                                    "Invalidated rejected maintainer announcements"
                                                );
                                            }

                                            // Re-process events from hot cache immediately
                                            if !hot_events.is_empty() {
                                                let _stats = Self::reprocess_events_from_hot_cache(
                                                    hot_events,
                                                    "maintainer announcement",
                                                    &maintainer_pubkey,
                                                    &announcement.identifier,
                                                    relay_url,
                                                    database,
                                                    write_policy,
                                                    local_relay,
                                                    rejected_events_index,
                                                )
                                                .await;
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                maintainer_hex = %maintainer_hex,
                                                error = %e,
                                                "Invalid maintainer public key in announcement"
                                            );
                                        }
                                    }
                                }
                            }

                            // Re-process rejected state events for this announcement
                            let (removed, hot_events) = rejected_events_index.invalidate_and_get(
                                &event.pubkey,
                                &announcement.identifier,
                                Some(rejected_index::EventType::State),
                            );

                            if removed > 0 {
                                tracing::info!(
                                    pubkey = %event.pubkey,
                                    identifier = %announcement.identifier,
                                    removed_from_cold_index = removed,
                                    hot_cache_events = hot_events.len(),
                                    "Invalidated rejected state events (announcement now exists)"
                                );
                            }

                            // Re-process state events from hot cache immediately
                            if !hot_events.is_empty() {
                                let _stats = Self::reprocess_events_from_hot_cache(
                                    hot_events,
                                    "state event",
                                    &event.pubkey,
                                    &announcement.identifier,
                                    relay_url,
                                    database,
                                    write_policy,
                                    local_relay,
                                    rejected_events_index,
                                )
                                .await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                event_id = %event.id,
                                error = %e,
                                "Failed to parse repository announcement for rejected event invalidation"
                            );
                        }
                    }
                }

                // When a state event is accepted (git data arrived), re-process any other
                // rejected state events for the same repository. This handles the case where
                // multiple state events arrive but only one has git data initially.
                // Events in the hot cache are re-processed immediately now that git data is available.
                if event.kind == Kind::RepoState {
                    // Extract identifier from 'd' tag
                    if let Some(identifier) = event
                        .tags
                        .iter()
                        .find(|t| t.kind() == "d")
                        .and_then(|t| t.content())
                    {
                        // Get rejected state events for this pubkey + identifier
                        let (removed, hot_events) = rejected_events_index.invalidate_and_get(
                            &event.pubkey,
                            identifier,
                            Some(rejected_index::EventType::State),
                        );

                        if removed > 0 {
                            tracing::info!(
                                pubkey = %event.pubkey,
                                identifier = %identifier,
                                removed_from_cold_index = removed,
                                hot_cache_events = hot_events.len(),
                                "Invalidated rejected state events (git data now available)"
                            );
                        }

                        // Re-process events from hot cache immediately
                        if !hot_events.is_empty() {
                            let _stats = Self::reprocess_events_from_hot_cache(
                                hot_events,
                                "state event",
                                &event.pubkey,
                                identifier,
                                relay_url,
                                database,
                                write_policy,
                                local_relay,
                                rejected_events_index,
                            )
                            .await;
                        }
                    }
                }

                // GRASP-P Phase 2 (design 1.4): a 30640 registration was
                // accepted — re-process held 30641s targeting the registered
                // alias and held stream wraps authored by any newly-registered
                // w/aux key. Inert when private repos are disabled.
                if event.kind.as_u16() == crate::private::KIND_REGISTRATION {
                    if let Some(private) = write_policy.private() {
                        let alias = event.tags.iter().find_map(|tag| {
                            let v = tag.clone().to_vec();
                            if v.len() >= 2 && v[0] == "d" {
                                Some(v[1].clone())
                            } else {
                                None
                            }
                        });
                        let keys: Vec<String> = event
                            .tags
                            .iter()
                            .filter_map(|tag| {
                                let v = tag.clone().to_vec();
                                if v.len() >= 2 && (v[0] == "w" || v[0] == "aux") {
                                    Some(v[1].clone())
                                } else {
                                    None
                                }
                            })
                            .collect();

                        let mut held: Vec<Event> = Vec::new();
                        if let Some(ref alias) = alias {
                            held.extend(private.sync_rejected().take_for_alias(alias));
                        }
                        held.extend(private.sync_rejected().take_for_authors(&keys));
                        let mut seen: HashSet<EventId> = HashSet::new();
                        held.retain(|e| seen.insert(e.id));

                        for held_event in held {
                            // Safe recursion: the event was removed from the
                            // private hold (and its skip-set entry cleared)
                            // before this call; a second rejection re-holds
                            // it without looping.
                            let result = Box::pin(Self::process_event_static(
                                &held_event,
                                relay_url,
                                database,
                                write_policy,
                                local_relay,
                                rejected_events_index,
                                crate::nostr::persistence::SaveContext::HotCacheReprocess,
                            ))
                            .await;
                            tracing::info!(
                                event_id = %held_event.id,
                                kind = %held_event.kind.as_u16(),
                                alias = ?alias,
                                result = ?result,
                                "Re-processed held private event after synced 30640 accept"
                            );
                        }
                    }
                }

                ProcessResult::Saved
            }
            WritePolicyResult::Reject {
                message, status, ..
            } => {
                if status {
                    tracing::debug!(
                        event_id = %event.id,
                        kind = %event.kind.as_u16(),
                        reason = %message,
                        "Event added to purgatory"
                    );
                    // Note: git data sync for state events is triggered by the policy
                    // layer when adding to purgatory (via start_state_sync)
                    ProcessResult::Purgatory
                } else {
                    tracing::debug!(
                        event_id = %event.id,
                        relay = %relay_url,
                        kind = %event.kind.as_u16(),
                        reason = %message,
                        "Event rejected by write policy"
                    );

                    // Track rejected announcement and state events to avoid re-fetching them
                    if event.kind == Kind::GitRepoAnnouncement || event.kind == Kind::RepoState {
                        // Extract identifier from 'd' tag
                        if let Some(identifier) = event
                            .tags
                            .iter()
                            .find(|t| t.kind() == "d")
                            .and_then(|t| t.content())
                        {
                            // Determine rejection reason based on message
                            let reason = if message.contains("doesn't list this service")
                                || message.contains("Announcement must list service")
                            {
                                rejected_index::RejectionReason::DoesNotListService
                            } else if message.contains("maintainer")
                                || message.contains("no announcement exists")
                                || message.contains("not authorized")
                            {
                                rejected_index::RejectionReason::MaintainerNotYetValid
                            } else {
                                rejected_index::RejectionReason::Other
                            };

                            // Use appropriate method based on event kind
                            if event.kind == Kind::RepoState {
                                rejected_events_index.add_state(
                                    event.clone(),
                                    event.pubkey,
                                    identifier.to_string(),
                                    reason,
                                );
                                tracing::debug!(
                                    event_id = %event.id,
                                    kind = %event.kind.as_u16(),
                                    identifier = %identifier,
                                    "Added rejected state event to two-tier index"
                                );
                            } else {
                                rejected_events_index.add_announcement(
                                    event.clone(),
                                    event.pubkey,
                                    identifier.to_string(),
                                    reason,
                                );
                                tracing::debug!(
                                    event_id = %event.id,
                                    kind = %event.kind.as_u16(),
                                    identifier = %identifier,
                                    pubkey = %event.pubkey,
                                    "Added rejected announcement to two-tier index"
                                );
                            }
                        } else {
                            tracing::warn!(
                                event_id = %event.id,
                                kind = %event.kind.as_u16(),
                                "Event missing 'd' tag, cannot track in rejected index"
                            );
                        }
                    }

                    // GRASP-P Phase 2 (design 1.4): hold rejected private
                    // events in the dedicated index. The existing (pubkey,
                    // d-tag) registration above does NOT fit these kinds —
                    // stream wraps have an ephemeral outer pubkey and no
                    // `d` tag — so 30641s are keyed by their target alias
                    // and stream wraps by their outer author (which is
                    // kind-agnostic: a held 1059 and a held 3359 from the
                    // same write key share a bucket and are released
                    // together). Inert when disabled.
                    if let Some(private) = write_policy.private() {
                        match event.kind.as_u16() {
                            crate::private::KIND_REGISTRATION => {
                                // FS-2 (review L3-F4): a cadence-rejected
                                // same-tenant replacement is HELD (full
                                // event) and retried by the
                                // sync_private_registrations_to_index timer
                                // after the bucket refills — when every
                                // node rejects the same replacement in
                                // lockstep, an id-only skip-set entry would
                                // leave the event stored nowhere and
                                // unhealable (re-issue only re-fetches what
                                // a peer holds). Every other 30640
                                // rejection keeps the id-only semantics
                                // (no missing dependency to wait for).
                                if message.contains(
                                    crate::private::registration::REPLACE_CADENCE_REJECT_MESSAGE,
                                ) {
                                    private.sync_rejected().add_registration(event.clone());
                                } else {
                                    private.sync_rejected().add_id_only(event.id);
                                }
                            }
                            crate::private::KIND_STATE_ROOT => {
                                let alias = event.tags.iter().find_map(|tag| {
                                    let v = tag.clone().to_vec();
                                    if v.len() >= 2 && v[0] == "d" {
                                        Some(v[1].clone())
                                    } else {
                                        None
                                    }
                                });
                                match alias {
                                    Some(alias) => private
                                        .sync_rejected()
                                        .add_state_root(alias, event.clone()),
                                    None => private.sync_rejected().add_id_only(event.id),
                                }
                            }
                            k if private.accepts_stream_wrap_kind(k) => {
                                private
                                    .sync_rejected()
                                    .add_wrap(event.pubkey.to_hex(), event.clone());
                            }
                            _ => {}
                        }
                    }

                    ProcessResult::Rejected
                }
            }
        }
    }

    // =========================================================================
    // Consolidation System
    // =========================================================================

    /// Wait until all pending batches for a relay are complete
    ///
    /// Polls the pending_sync_index until the relay has no pending batches.
    /// Returns error if timeout (30 seconds) is exceeded.
    async fn wait_pending_complete(&self, relay_url: &str) -> Result<(), String> {
        use std::time::Duration;
        use tokio::time::{sleep, Instant};

        let start = Instant::now();
        let timeout = Duration::from_secs(CONSOLIDATION_WAIT_TIMEOUT_SECS);

        tracing::debug!(
            relay = %relay_url,
            timeout_secs = CONSOLIDATION_WAIT_TIMEOUT_SECS,
            "Waiting for pending batches to complete"
        );

        loop {
            // Check if no pending batches
            {
                let pending = self.pending_sync_index.read().await;
                if !pending.contains_key(relay_url) {
                    tracing::debug!(
                        relay = %relay_url,
                        elapsed_ms = start.elapsed().as_millis(),
                        "All pending batches complete"
                    );
                    return Ok(());
                }
            }

            // Check timeout
            if start.elapsed() > timeout {
                tracing::warn!(
                    relay = %relay_url,
                    timeout_secs = CONSOLIDATION_WAIT_TIMEOUT_SECS,
                    "Timeout waiting for pending batches"
                );
                return Err(format!(
                    "Timeout waiting for pending batches on {} after {}s",
                    relay_url, CONSOLIDATION_WAIT_TIMEOUT_SECS
                ));
            }

            // Short poll interval
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Check if consolidation is needed and trigger if threshold exceeded
    ///
    /// Compares current filter count + new filter count against the threshold.
    /// If exceeded, triggers consolidation before adding new filters.
    async fn maybe_consolidate(&mut self, relay_url: &str, new_count: usize) {
        let current_count = if let Some(connection) = self.connections.get(relay_url) {
            connection.subscription_count().await
        } else {
            0
        };

        if current_count + new_count > CONSOLIDATION_THRESHOLD {
            tracing::info!(
                relay = %relay_url,
                current_count = current_count,
                new_count = new_count,
                threshold = CONSOLIDATION_THRESHOLD,
                "Filter count exceeds threshold, consolidating"
            );

            if let Err(e) = self.consolidate(relay_url).await {
                tracing::error!(
                    relay = %relay_url,
                    error = %e,
                    "Consolidation failed"
                );
            }
        }
    }

    /// Consolidate all subscriptions for a relay
    ///
    /// This method:
    /// 1. Waits for all pending batches to complete
    /// 2. Unsubscribes from all active subscriptions
    /// 3. Rebuilds Layer 2 and Layer 3 with since filter
    ///
    /// Layer 1 (announcements) remains active and is NOT unsubscribed.
    async fn consolidate(&mut self, relay_url: &str) -> Result<(), String> {
        tracing::info!(
            relay = %relay_url,
            "Starting consolidation"
        );

        // Step 1: Wait for all pending batches to complete
        self.wait_pending_complete(relay_url).await?;

        // Step 2: Get connection and unsubscribe all
        let connection = match self.connections.get(relay_url) {
            Some(conn) => conn,
            None => {
                tracing::debug!(
                    relay = %relay_url,
                    "No connection found, skipping consolidation"
                );
                return Ok(()); // No connection, nothing to consolidate
            }
        };

        connection.unsubscribe_all().await;

        // Step 3: Rebuild all subscriptions with since filter
        let now = Timestamp::now();
        let since = Timestamp::from(now.as_secs().saturating_sub(QUICK_RECONNECT_WINDOW_SECS));

        // Re-subscribe to Layer 1 with since filter
        self.sync_generic_filters(relay_url, Some(since)).await;
        // Rebuild Layer 2 and Layer 3 with since filter
        self.rebuild_layer2_and_layer3(relay_url, Some(since)).await;

        tracing::info!(
            relay = %relay_url,
            since = %since,
            "Consolidation complete - filter count reset"
        );

        Ok(())
    }

    /// Check for relays that should be disconnected
    ///
    /// This method is called periodically by run_disconnect_checker.
    /// It identifies non-bootstrap relays that have no repos or root events
    /// to sync and disconnects them to free up resources.
    ///
    /// Bootstrap relays are NEVER disconnected, even if empty.
    async fn check_disconnects(&mut self) {
        // GRASP-P Phase 2: relays connected for private-repo sync carry no
        // public repos/root events, so the empty-relay heuristic below would
        // flap them. Keep operator-allowlisted peers connected. Empty set
        // (zero overhead) when private repos are disabled.
        let private_peer_urls: HashSet<String> = if self.config.private_repos_enable {
            private_index::configured_peer_relay_urls(
                &self.config.private_sync_peer_url_entries(),
                &self.service_domain,
            )
        } else {
            HashSet::new()
        };

        // Collect relays to disconnect
        let to_disconnect: Vec<String> = {
            let index = self.relay_sync_index.read().await;
            index
                .iter()
                .filter_map(|(relay_url, state)| {
                    // Skip bootstrap relays - they stay connected
                    if state.is_bootstrap {
                        return None;
                    }

                    // Skip private-repo peer relays (Phase 2)
                    if private_peer_urls.contains(relay_url) {
                        return None;
                    }

                    // Skip relays already disconnecting
                    if state.connection_status == ConnectionStatus::Disconnecting {
                        return None;
                    }

                    // Disconnect if no repos and no root events
                    if state.repos.is_empty() && state.root_events.is_empty() {
                        Some(relay_url.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        if to_disconnect.is_empty() {
            tracing::trace!("No empty relays to disconnect");
            return;
        }

        tracing::info!(
            count = to_disconnect.len(),
            relays = ?to_disconnect,
            "Found empty non-bootstrap relays to disconnect"
        );

        // Disconnect empty relays
        for relay_url in to_disconnect {
            self.disconnect_relay(&relay_url).await;
        }
    }

    /// Disconnect a relay and mark it for cleanup
    ///
    /// This method:
    /// - Marks the relay as Disconnecting in relay_sync_index
    /// - Initiates the connection disconnect
    /// - Final cleanup happens in handle_disconnect when event loop terminates
    ///
    /// Used by check_disconnects for cleanup of empty relays.
    async fn disconnect_relay(&mut self, relay_url: &str) {
        tracing::info!(relay = %relay_url, "Initiating disconnect for empty relay");

        // Mark relay as Disconnecting (keep state for event loop to drain)
        {
            let mut index = self.relay_sync_index.write().await;
            if let Some(state) = index.get_mut(relay_url) {
                state.connection_status = ConnectionStatus::Disconnecting;
                state.disconnected_at = Some(Timestamp::now());
                tracing::debug!(
                    relay = %relay_url,
                    "Marked relay as Disconnecting"
                );
            }
        }

        // Initiate disconnect - event loop will drain and send disconnect notification
        if let Some(connection) = self.connections.get(relay_url) {
            connection.disconnect().await;
            tracing::debug!(
                relay = %relay_url,
                "Initiated connection disconnect"
            );
        }

        // Update metrics
        if let Some(ref metrics) = self.metrics {
            metrics.record_connection_status(relay_url, ConnectionStatus::Disconnecting);
        }

        tracing::info!(relay = %relay_url, "Disconnect initiated, waiting for event loop termination");
    }

    /// Retry disconnected relays that are ready for reconnection
    ///
    /// This method is called periodically by run_disconnect_checker.
    /// It identifies relays that:
    /// - Are currently disconnected
    /// - Have repos or root events to sync (not empty)
    /// - Have passed the exponential backoff period (respects health tracker)
    ///
    /// For each eligible relay, a reconnection is attempted via try_connect_relay.
    async fn retry_disconnected_relays(&mut self) {
        // Collect relays to reconnect
        let to_reconnect: Vec<String> = {
            let index = self.relay_sync_index.read().await;
            index
                .iter()
                .filter_map(|(relay_url, state)| {
                    // Only consider disconnected relays
                    if state.connection_status != ConnectionStatus::Disconnected {
                        return None;
                    }

                    // Skip empty relays - they'll be cleaned up by check_disconnects
                    if state.repos.is_empty() && state.root_events.is_empty() {
                        return None;
                    }

                    // Check if backoff period has elapsed
                    if self.health_tracker.should_attempt_connection(relay_url) {
                        Some(relay_url.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        if to_reconnect.is_empty() {
            tracing::trace!("No disconnected relays ready for reconnection");
            return;
        }

        tracing::info!(
            count = to_reconnect.len(),
            relays = ?to_reconnect,
            "Attempting reconnection for disconnected relays"
        );

        // Reconnect eligible relays
        for relay_url in to_reconnect {
            tracing::info!(
                relay = %relay_url,
                health_state = %self.health_tracker.get_state(&relay_url),
                "Attempting reconnection"
            );
            self.try_connect_relay(&relay_url).await;
        }
    }

    /// Check for rate-limited relays that have exceeded cooldown
    ///
    /// This method is called periodically by run_rate_limit_checker (every 1 second).
    /// For each relay in RateLimited state that has exceeded the 65-second cooldown:
    /// 1. Clears the rate limit state (sets to Healthy)
    /// 2. Recomputes required actions for that relay
    /// 3. Submits those actions
    async fn check_rate_limit_recovery(&mut self) {
        use crate::sync::algorithms::{compute_actions, derive_relay_targets};

        // Exit rate limiting for relays whose cooldown has expired
        let relays_to_recover: Vec<String> = self.health_tracker.exit_expired_rate_limits();

        if relays_to_recover.is_empty() {
            return;
        }

        // Recompute actions - could optimise by adding relays: Option<&[]> to derive_relay_targets
        let repo_index = self.repo_sync_index.read().await;
        let targets = derive_relay_targets(&repo_index);
        drop(repo_index);

        for relay_url in relays_to_recover {
            tracing::info!(
                relay = %relay_url,
                "Rate limit cooldown expired, recovering"
            );

            // Clear rate limit state
            self.health_tracker.clear_rate_limit(&relay_url);

            // Only compute actions for this specific relay
            if let Some(relay_needs) = targets.get(&relay_url) {
                let mut single_relay_targets = std::collections::HashMap::new();
                single_relay_targets.insert(relay_url.clone(), relay_needs.clone());

                let pending = self.pending_sync_index.read().await;
                let confirmed = self.relay_sync_index.read().await;

                let actions = compute_actions(&single_relay_targets, &pending, &confirmed);
                drop(pending);
                drop(confirmed);

                // Submit each action
                for action in actions {
                    tracing::info!(
                        relay = %action.relay_url,
                        repo_count = action.items.repos.len(),
                        event_count = action.items.root_events.len(),
                        "Submitting recovered actions after rate limit"
                    );
                    self.handle_new_sync_filters(action).await;
                }
            }
        }
    }

    /// Subscribe to filters for live (ongoing) events - NOT tracked in PendingSyncIndex
    ///
    /// This method applies limit(0) to all filters to receive ONLY new events.
    /// Per NIP-01, limit 0 means "send no stored events, only future events", which
    /// ensures EOSE is received immediately and all subsequent events are tagged as "live"
    /// in metrics (not "startup").
    ///
    /// **Important**: Callers pass the SAME filters to both sync_live() and historic_sync().
    /// This method applies limit(0) to prevent fetching historic events.
    ///
    /// Live subscriptions are NOT tracked in PendingSyncIndex because they don't have
    /// a definite "completion" - they stay open indefinitely.
    ///
    /// Used for:
    /// - Layer 1 live subscription (new announcements after initial sync)
    /// - Layer 2+3 live subscriptions (new events after initial sync)
    ///
    /// # Arguments
    /// * `relay_url` - The relay URL to subscribe on
    /// * `filters` - Filters to subscribe to (limit(0) will be applied)
    ///
    /// # Returns
    /// Vec of subscription IDs for the live subscriptions, or empty if connection not found
    async fn sync_live(&self, relay_url: &str, filters: &[Filter]) -> Vec<SubscriptionId> {
        if filters.is_empty() {
            return vec![];
        }

        let connection = match self.connections.get(relay_url) {
            Some(conn) => conn,
            None => {
                tracing::debug!(relay = %relay_url, "No connection found for live sync");
                return vec![];
            }
        };

        let mut sub_ids = Vec::new();

        for filter in filters.iter() {
            // Live subscriptions MUST use limit(0) to receive ONLY new events
            // This prevents fetching historic events that would be miscounted as "live" in metrics
            // The caller passes the same filters to both sync_live() and historic_sync()
            // Live subscriptions do NOT auto-close - we want them to stay open for new events
            match connection
                .subscribe_filter(filter.clone().limit(0), false)
                .await
            {
                Ok(sub_id) => {
                    sub_ids.push(sub_id);
                }
                Err(e) => {
                    tracing::error!(relay = %relay_url, error = %e, "Failed to create live subscription");
                }
            }
        }

        sub_ids
    }

    /// Sync historical events and track in PendingSyncIndex
    ///
    /// This method handles historical synchronization for a set of filters,
    /// creating a PendingBatch to track completion. It dispatches to either
    /// negentropy sync or traditional REQ+EOSE based on relay capability and config.
    ///
    /// Used for:
    /// - Initial sync (no since filter)
    /// - Reconnect sync (with since filter)
    /// - Daily sync (no since filter, full re-sync)
    ///
    /// # Arguments
    /// * `relay_url` - The relay URL to sync from
    /// * `filters` - Filters to sync (will have `since` applied if provided)
    /// * `items` - Items being synced (for tracking in PendingBatch)
    /// * `since` - Optional timestamp for incremental sync
    ///
    /// # Returns
    /// * `Some(batch_id)` - Batch was created and sync initiated
    /// * `None` - No connection or sync failed to start
    async fn historic_sync(
        &mut self,
        relay_url: &str,
        filters: Vec<Filter>,
        items: PendingItems,
        since: Option<Timestamp>,
    ) -> Option<u64> {
        // DEBUG TRACING: Log all filters being passed to historic_sync
        tracing::debug!(
            relay = %relay_url,
            filter_count = filters.len(),
            filters = ?filters,
            repos_count = items.repos.len(),
            root_events_count = items.root_events.len(),
            since = ?since,
            "historic_sync called"
        );

        if filters.is_empty() && items.repos.is_empty() && items.root_events.is_empty() {
            tracing::debug!(
                relay = %relay_url,
                "historic_sync called with empty filters and items, skipping"
            );
            return None;
        }

        // Check connection exists and clone for async usage
        let connection = match self.connections.get(relay_url) {
            Some(conn) => conn.clone(),
            None => {
                tracing::warn!(
                    relay = %relay_url,
                    "No connection found for historic_sync"
                );
                return None;
            }
        };

        // Apply since filter if provided
        let filters_with_since: Vec<Filter> = if let Some(ts) = since {
            filters.into_iter().map(|f| f.since(ts)).collect()
        } else {
            filters
        };

        // Check if we should use negentropy
        let use_negentropy =
            !self.config.sync_disable_negentropy && connection.supports_negentropy().await;

        // Generate batch ID
        let batch_id = self.next_batch_id();

        // Track whether negentropy succeeded (for fallback logic)
        let mut negentropy_succeeded = false;

        if use_negentropy && !filters_with_since.is_empty() {
            // NIP-77 negentropy path
            tracing::debug!(
                relay = %relay_url,
                batch_id = batch_id,
                filter_count = filters_with_since.len(),
                repos = items.repos.len(),
                root_events = items.root_events.len(),
                "Starting historic_sync with negentropy"
            );

            // Create PendingBatch for negentropy (empty outstanding_subs and pagination_state)
            let batch = PendingBatch {
                batch_id,
                items: items.clone(),
                outstanding_subs: HashSet::new(),
                sync_method: SyncMethod::Negentropy,
                pagination_state: HashMap::new(), // Negentropy doesn't use pagination
                requested_event_ids: None,        // Will be set after negentropy diff
                received_event_ids: None,         // Will be set after negentropy diff
                retry_count: 0,
                failed: false,
            };

            // Add to pending_sync_index
            {
                let mut pending = self.pending_sync_index.write().await;
                pending
                    .entry(relay_url.to_string())
                    .or_insert_with(Vec::new)
                    .push(batch);
            }

            // Perform negentropy sync for all filters concurrently
            // Note: We sync each filter separately because negentropy works on a single filter
            let diff_futures: Vec<_> = filters_with_since
                .iter()
                .enumerate()
                .map(|(idx, filter)| {
                    let filter = filter.clone();
                    let conn = connection.clone();
                    async move { (idx, conn.negentropy_sync_diff(filter).await) }
                })
                .collect();

            let diff_results = futures_util::future::join_all(diff_futures).await;

            // Process results - collect all event IDs we need to fetch
            let mut all_remote_ids = Vec::new();
            let mut failed_count = 0;

            // Get event IDs to exclude: purgatory + rejected announcements
            let purgatory_ids = self.purgatory.event_ids();
            let rejected_ids = self.rejected_events_index.get_all_event_ids();
            let mut excluded_ids: HashSet<EventId> =
                purgatory_ids.union(&rejected_ids).cloned().collect();
            // GRASP-P Phase 2: also exclude known-rejected private events
            // (30640/30641/stream wraps) so negentropy doesn't refetch them.
            if let Some(private) = self.write_policy.private() {
                excluded_ids.extend(private.sync_rejected().all_event_ids());
            }

            for (idx, result) in diff_results {
                match result {
                    Ok(reconciliation) => {
                        let remote_excluding_ids: HashSet<EventId> = reconciliation
                            .remote
                            .keys()
                            .filter(|id| !excluded_ids.contains(id))
                            .copied()
                            .collect();
                        let remote_count = remote_excluding_ids.len();
                        tracing::debug!(
                            relay = %relay_url,
                            filter_idx = idx,
                            remote_count = remote_count,
                            local_count = reconciliation.local.len(),
                            remote_ids = ?remote_excluding_ids,
                            "[DIAG TRACE] ✓ Negentropy diff results for filter {}", idx
                        );
                        if remote_count > 0 {
                            all_remote_ids.extend(remote_excluding_ids);
                        }
                    }
                    Err(e) => {
                        failed_count += 1;
                        tracing::warn!(
                            relay = %relay_url,
                            filter_idx = idx,
                            error = %e,
                            "Negentropy diff failed for filter in historic_sync"
                        );
                    }
                }
            }

            // Require ALL filters to succeed to confirm the batch
            if failed_count > 0 {
                // Remove failed negentropy batch and fall back to REQ+EOSE
                {
                    let mut pending = self.pending_sync_index.write().await;
                    if let Some(batches) = pending.get_mut(relay_url) {
                        let batch_idx = batches.iter().position(|b| b.batch_id == batch_id);
                        if let Some(idx) = batch_idx {
                            batches.remove(idx);
                            if batches.is_empty() {
                                pending.remove(relay_url);
                            }
                        }
                    }
                }

                tracing::info!(
                    relay = %relay_url,
                    batch_id = batch_id,
                    failed_count = failed_count,
                    total_filters = filters_with_since.len(),
                    "historic_sync (negentropy) failed - falling back to REQ+EOSE"
                );

                // Fall through to REQ+EOSE path below
            } else {
                // Negentropy succeeded - mark success and process results
                negentropy_succeeded = true;

                if all_remote_ids.is_empty() {
                    // Remove batch from pending and confirm it (no items to download)
                    let completed_batch = {
                        let mut pending = self.pending_sync_index.write().await;
                        if let Some(batches) = pending.get_mut(relay_url) {
                            let batch_idx = batches.iter().position(|b| b.batch_id == batch_id);
                            if let Some(idx) = batch_idx {
                                let batch = batches.remove(idx);
                                if batches.is_empty() {
                                    pending.remove(relay_url);
                                }
                                Some(batch)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };

                    if let Some(batch) = completed_batch {
                        self.confirm_batch(relay_url, batch).await;
                    }

                    tracing::info!(
                        relay = %relay_url,
                        batch_id = batch_id,
                        total_received = 0,
                        "historic_sync (negentropy) completed - already up-to-date"
                    );

                    // Batch already confirmed, nothing more to do
                    return Some(batch_id);
                }

                // launch subscriptions to fetch missing events by id
                let ids_filters: Vec<_> = all_remote_ids
                    .chunks(300)
                    .map(|c| Filter::new().ids(c.iter().copied()))
                    .collect();

                // DEBUG TRACING: Log that we're requesting events by ID
                tracing::info!(
                    relay = %relay_url,
                    batch_id = batch_id,
                    total_event_ids = all_remote_ids.len(),
                    filter_chunks = ids_filters.len(),
                    event_ids = ?all_remote_ids,
                    "[DIAG TRACE] ✓ Creating {} subscription(s) to fetch {} missing event(s) by ID",
                    ids_filters.len(),
                    all_remote_ids.len()
                );

                let mut subscription_ids = HashSet::new();
                for (idx, filter) in ids_filters.iter().enumerate() {
                    if let Some(conn) = self.connections.get(relay_url) {
                        match conn.subscribe_filter(filter.clone(), true).await {
                            Ok(sub_id) => {
                                subscription_ids.insert(sub_id);
                            }
                            Err(e) => {
                                tracing::error!(
                                    relay = %relay_url,
                                    batch_id = batch_id,
                                    chunk_idx = idx,
                                    error = %e,
                                    "Failed to subscribe to ID filter chunk"
                                );
                            }
                        }
                    }
                }
                {
                    let mut pending = self.pending_sync_index.write().await;
                    if let Some(relay_batches) = pending.get_mut(relay_url) {
                        if let Some(batch) =
                            relay_batches.iter_mut().find(|b| b.batch_id == batch_id)
                        {
                            batch.outstanding_subs.extend(subscription_ids.clone());
                            // Store requested event IDs for validation after EOSE
                            batch.requested_event_ids =
                                Some(all_remote_ids.iter().cloned().collect());
                            batch.received_event_ids = Some(HashSet::new());
                        }
                    }
                }
                tracing::debug!(
                    relay = %relay_url,
                    batch_id = batch_id,
                    subscription_ids = subscription_ids.len(),
                    events = all_remote_ids.len(),
                    "historic_sync (Negentropy) created subscriptions to fetch missing events by id, awaiting EOSE"
                );
            }
        }

        // Use REQ+EOSE if negentropy was not attempted or failed
        if !negentropy_succeeded {
            // Traditional REQ+EOSE path
            tracing::debug!(
                relay = %relay_url,
                batch_id = batch_id,
                filter_count = filters_with_since.len(),
                repos = items.repos.len(),
                root_events = items.root_events.len(),
                use_negentropy = use_negentropy,
                "Starting historic_sync with REQ+EOSE"
            );

            // Subscribe to each filter and collect subscription IDs
            let mut subscription_ids = HashSet::new();
            let mut pagination_state = HashMap::new();

            // DEBUG TRACING: Log each filter in REQ+EOSE path
            for (idx, filter) in filters_with_since.iter().enumerate() {
                tracing::debug!(
                    relay = %relay_url,
                    batch_id = batch_id,
                    filter_idx = idx,
                    filter = ?filter,
                    "Subscribing to filter in REQ+EOSE path"
                );

                if let Some(conn) = self.connections.get(relay_url) {
                    match conn.subscribe_filter(filter.clone(), true).await {
                        Ok(sub_id) => {
                            subscription_ids.insert(sub_id.clone());
                            // Initialize pagination state for this subscription
                            pagination_state.insert(
                                sub_id,
                                PaginationState {
                                    event_count: 0,
                                    min_created_at: None,
                                    original_filter: filter.clone(),
                                },
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                relay = %relay_url,
                                error = %e,
                                "Failed to subscribe to filter in historic_sync"
                            );
                        }
                    }
                }
            }

            if subscription_ids.is_empty() && !filters_with_since.is_empty() {
                tracing::warn!(
                    relay = %relay_url,
                    "All filter subscriptions failed in historic_sync"
                );
                return None;
            }

            // Create PendingBatch for REQ+EOSE
            let batch = PendingBatch {
                batch_id,
                items,
                outstanding_subs: subscription_ids,
                sync_method: SyncMethod::ReqEose,
                pagination_state,
                requested_event_ids: None, // Not used for REQ+EOSE
                received_event_ids: None,  // Not used for REQ+EOSE
                retry_count: 0,            // Not used for REQ+EOSE
                failed: false,
            };

            // Add to pending_sync_index
            {
                let mut pending = self.pending_sync_index.write().await;
                pending
                    .entry(relay_url.to_string())
                    .or_insert_with(Vec::new)
                    .push(batch);
            }

            tracing::debug!(
                relay = %relay_url,
                batch_id = batch_id,
                "historic_sync (REQ+EOSE) batch created, awaiting EOSE"
            );
        }

        Some(batch_id)
    }

    /// Gracefully shutdown the SyncManager
    ///
    /// This method:
    /// - Sends shutdown signal to all background tasks (daily timer, disconnect checker)
    /// - Disconnects all relay connections
    /// - Clears all indices (relay_sync_index, pending_sync_index)
    ///
    /// After calling this method, the SyncManager is no longer usable.
    pub async fn shutdown(&mut self) {
        tracing::info!("Starting SyncManager shutdown");

        // 1. Send shutdown signal to all background tasks
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
            tracing::debug!("Sent shutdown signal to background tasks");
        }

        // 2. Disconnect all relay connections
        let relay_urls: Vec<String> = self.connections.keys().cloned().collect();
        for relay_url in relay_urls {
            if let Some(connection) = self.connections.remove(&relay_url) {
                tracing::debug!(relay = %relay_url, "Disconnecting relay");
                connection.disconnect().await;
            }
        }

        // 3. Clear all indices
        {
            let mut index = self.relay_sync_index.write().await;
            let count = index.len();
            index.clear();
            tracing::debug!(count = count, "Cleared relay_sync_index");
        }

        {
            let mut pending = self.pending_sync_index.write().await;
            let count = pending.len();
            pending.clear();
            tracing::debug!(count = count, "Cleared pending_sync_index");
        }

        tracing::info!("SyncManager shutdown complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rejected_events_index_tracks_announcements() {
        // Create a rejected events index with 2 minute hot cache, 7 day cold index
        let rejected_index = Arc::new(RejectedEventsIndex::new(
            Duration::from_secs(120),
            Duration::from_secs(604800),
        ));

        // Create test announcement event (kind 30617) with 'd' tag
        let keys = Keys::generate();
        let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "test content")
            .tag(nostr_sdk::prelude::Tag::custom("d", vec!["test-repo"]))
            .finalize(&keys)
            .unwrap();

        // Verify index is empty
        assert_eq!(rejected_index.hot_cache_len(), 0);
        assert_eq!(rejected_index.cold_index_len(), 0);

        // Simulate rejection by adding to index
        rejected_index.add_announcement(
            announcement.clone(),
            announcement.pubkey,
            "test-repo".to_string(),
            rejected_index::RejectionReason::DoesNotListService,
        );

        // Verify event is tracked in both tiers
        assert!(rejected_index.contains(&announcement.id));
        assert_eq!(rejected_index.hot_cache_len(), 1);
        assert_eq!(rejected_index.cold_index_len(), 1);
    }

    #[tokio::test]
    async fn test_rejected_events_excluded_from_negentropy() {
        // Create indices
        let purgatory_ids: HashSet<EventId> = HashSet::new();
        let rejected_index =
            RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));

        // Create test event IDs
        let _rejected_id =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let valid_id =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();

        // Add rejected event to index
        let keys = Keys::generate();
        let rejected_event = EventBuilder::new(Kind::GitRepoAnnouncement, "rejected")
            .tag(nostr_sdk::prelude::Tag::custom("d", vec!["rejected-repo"]))
            .finalize(&keys)
            .unwrap();

        // Override the event ID for testing (we need a specific ID)
        // Since we can't override the ID, let's use the actual event ID
        let rejected_id = rejected_event.id;
        rejected_index.add_announcement(
            rejected_event,
            keys.public_key(),
            "rejected-repo".to_string(),
            rejected_index::RejectionReason::DoesNotListService,
        );

        // Get rejected IDs from index
        let rejected_ids = rejected_index.get_all_event_ids();

        // Simulate negentropy reconciliation result
        let mut remote_ids = HashSet::new();
        remote_ids.insert(rejected_id);
        remote_ids.insert(valid_id);

        // Exclude rejected and purgatory events
        let excluded_ids: HashSet<EventId> = purgatory_ids.union(&rejected_ids).cloned().collect();
        let filtered_ids: HashSet<EventId> =
            remote_ids.difference(&excluded_ids).cloned().collect();

        // Verify rejected event is excluded
        assert!(!filtered_ids.contains(&rejected_id));
        assert!(filtered_ids.contains(&valid_id));
        assert_eq!(filtered_ids.len(), 1);
    }

    #[test]
    fn test_negentropy_missing_event_detection() {
        // Simulate scenario where relay returns fewer events than requested
        // This tests the core logic for detecting missing events

        // Requested 5 events from negentropy diff
        let mut requested: HashSet<EventId> = HashSet::new();
        for i in 1u8..=5 {
            let id = EventId::from_hex(&format!("{:0>64}", format!("{:x}", i))).unwrap();
            requested.insert(id);
        }

        // Only received 3 events (simulating relay limit)
        let mut received: HashSet<EventId> = HashSet::new();
        for i in 1u8..=3 {
            let id = EventId::from_hex(&format!("{:0>64}", format!("{:x}", i))).unwrap();
            received.insert(id);
        }

        // Calculate missing events
        let missing: Vec<EventId> = requested.difference(&received).cloned().collect();

        // Should have 2 missing events (IDs 4 and 5)
        assert_eq!(missing.len(), 2);
        assert_eq!(requested.len(), 5);
        assert_eq!(received.len(), 3);

        // Verify the specific missing IDs
        let id_4 = EventId::from_hex(&format!("{:0>64}", format!("{:x}", 4u8))).unwrap();
        let id_5 = EventId::from_hex(&format!("{:0>64}", format!("{:x}", 5u8))).unwrap();
        assert!(missing.contains(&id_4));
        assert!(missing.contains(&id_5));
    }

    #[test]
    fn test_negentropy_all_events_received() {
        // Simulate scenario where all requested events are received
        let mut requested: HashSet<EventId> = HashSet::new();
        for i in 1u8..=3 {
            let id = EventId::from_hex(&format!("{:0>64}", format!("{:x}", i))).unwrap();
            requested.insert(id);
        }

        // Received all 3 events
        let received = requested.clone();

        // Calculate missing events
        let missing: Vec<EventId> = requested.difference(&received).cloned().collect();

        // Should have no missing events
        assert!(missing.is_empty());
    }

    #[test]
    fn test_pending_batch_negentropy_fields() {
        // Test that PendingBatch properly tracks negentropy-specific fields
        let batch = PendingBatch {
            batch_id: 1,
            items: PendingItems::default(),
            outstanding_subs: HashSet::new(),
            sync_method: SyncMethod::Negentropy,
            pagination_state: HashMap::new(),
            requested_event_ids: Some(HashSet::new()),
            received_event_ids: Some(HashSet::new()),
            retry_count: 0,
            failed: false,
        };

        assert!(batch.requested_event_ids.is_some());
        assert!(batch.received_event_ids.is_some());
        assert_eq!(batch.sync_method, SyncMethod::Negentropy);
        assert_eq!(batch.retry_count, 0);
        assert!(!batch.failed);
    }

    #[test]
    fn test_pending_batch_req_eose_fields() {
        // Test that REQ+EOSE batches don't use negentropy fields
        let batch = PendingBatch {
            batch_id: 1,
            items: PendingItems::default(),
            outstanding_subs: HashSet::new(),
            sync_method: SyncMethod::ReqEose,
            pagination_state: HashMap::new(),
            requested_event_ids: None,
            received_event_ids: None,
            retry_count: 0,
            failed: false,
        };

        assert!(batch.requested_event_ids.is_none());
        assert!(batch.received_event_ids.is_none());
        assert_eq!(batch.sync_method, SyncMethod::ReqEose);
        assert!(!batch.failed);
    }

    /// FS-3 (review L2-F4): back-to-back dirty ticks produce at most one
    /// re-issue per peer per min-interval; a skipped re-issue is deferred
    /// (admitted once the interval lapses), never dropped permanently; the
    /// floor is per-peer and zero disables it; the map self-prunes.
    #[test]
    fn test_private_reissue_floor_gates_and_defers() {
        let mut floor = PrivateReissueFloor::default();
        let t0 = std::time::Instant::now();
        let f = Duration::from_secs(30);

        // First dirty tick sends; the back-to-back second tick is gated.
        assert!(floor.admit("wss://a", f, t0));
        assert!(!floor.admit("wss://a", f, t0 + Duration::from_secs(5)));

        // The floor is per-peer: another relay is unaffected.
        assert!(floor.admit("wss://b", f, t0 + Duration::from_secs(6)));

        // After the interval lapses the deferred re-issue lands — no
        // re-issue is ever dropped permanently.
        assert!(floor.admit("wss://a", f, t0 + Duration::from_secs(31)));
        assert!(!floor.admit("wss://a", f, t0 + Duration::from_secs(32)));

        // A zero floor disables gating entirely (pre-FS-3 behavior).
        assert!(floor.admit("wss://a", Duration::ZERO, t0 + Duration::from_secs(33)));

        // Self-pruning: entries older than the floor are dropped on the
        // next call, bounding the map by the recently-seen peer set.
        assert!(floor.admit("wss://c", f, t0 + Duration::from_secs(62)));
        assert!(
            floor.last_sent.len() <= 2,
            "stale entries must be pruned: {:?}",
            floor.last_sent.keys()
        );
    }
}
