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
//! See `docs/explanation/grasp-02-proactive-sync.md` for full design details.

pub mod algorithms;
pub mod filters;
pub mod health;
pub mod metrics;
pub mod missing_events;
pub mod naughty_list;
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
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use nostr_sdk::prelude::*;
use tokio::sync::{broadcast, Mutex, RwLock, Semaphore};

use crate::config::Config;
use crate::nostr::builder::Nip34WritePolicy;
use crate::nostr::SharedDatabase;
use crate::outbound::{OutboundTargetKind, OutboundTargetPolicy, RelayTargetSource};
use nostr_sdk::prelude::LocalRelay;

const MAX_PURGATORY_DEPENDENCY_EVENTS_PER_TICK: usize = 32;
const MAX_PURGATORY_FILTER_ACTIONS_PER_TICK: usize = 1;

fn purgatory_dependency_retry_after() -> Duration {
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(30)
    }
}

fn dependency_relay_retention() -> Duration {
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(60)
    }
}

fn select_purgatory_dependency_events(
    mut events: Vec<Event>,
    attempts: &mut HashMap<EventId, Instant>,
    now: Instant,
    retry_after: Duration,
    limit: usize,
) -> Vec<Event> {
    let current_ids: HashSet<EventId> = events.iter().map(|event| event.id).collect();
    attempts.retain(|event_id, _| current_ids.contains(event_id));

    events.sort_by(|left, right| {
        let left_is_new = !attempts.contains_key(&left.id);
        let right_is_new = !attempts.contains_key(&right.id);
        right_is_new
            .cmp(&left_is_new)
            .then_with(|| right.created_at.cmp(&left.created_at))
            .then_with(|| right.id.cmp(&left.id))
    });

    let selected: Vec<Event> = events
        .into_iter()
        .filter(|event| {
            attempts
                .get(&event.id)
                .is_none_or(|attempted_at| now.duration_since(*attempted_at) >= retry_after)
        })
        .take(limit)
        .collect();

    for event in &selected {
        attempts.insert(event.id, now);
    }

    selected
}

/// Return one stable identity for a relay URL throughout all sync indexes.
///
/// URL parsers represent a root path as `/`, so announcements that alternate
/// between `wss://relay.example` and `wss://relay.example/` must not create
/// separate connections and duplicate subscription work. Non-root paths remain
/// distinct relay endpoints.
pub(crate) fn canonical_relay_key(relay_url: &str) -> Result<String, String> {
    let normalized = if relay_url.starts_with("wss://") || relay_url.starts_with("ws://") {
        relay_url.to_string()
    } else {
        format!("wss://{relay_url}")
    };
    let relay = RelayUrl::parse(&normalized).map_err(|error| error.to_string())?;
    let mut canonical = relay.to_string();
    let after_scheme = canonical
        .split_once("://")
        .map(|(_, value)| value)
        .unwrap_or(canonical.as_str());
    if after_scheme.ends_with('/') && after_scheme.matches('/').count() == 1 {
        canonical.pop();
    }
    Ok(canonical)
}

fn connections_for_relay_urls<T: Clone>(
    connections: &HashMap<String, T>,
    relay_urls: &[String],
) -> Vec<(String, T)> {
    let mut seen = HashSet::new();
    relay_urls
        .iter()
        .filter_map(|relay_url| canonical_relay_key(relay_url).ok())
        .filter(|relay_url| seen.insert(relay_url.clone()))
        .filter_map(|relay_url| {
            connections
                .get(&relay_url)
                .cloned()
                .map(|connection| (relay_url, connection))
        })
        .collect()
}

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
    /// Repos we have confirmed full L2/L3 syncing from this relay
    pub repos: HashSet<String>,
    /// Repos we have confirmed state-only syncing from this relay
    pub state_only_repos: HashSet<String>,
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
            state_only_repos: HashSet::new(),
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
    /// Whether this relay has no remaining sync work and can be disconnected.
    ///
    /// A newly connected relay has no *confirmed* repos until its historic
    /// subscriptions complete. Treating that temporary state as empty races
    /// the two-second disconnect checker against the historic sync (whose
    /// completion is deliberately delayed to cover the subscriber batch
    /// window). Pending batches and an active incomplete historic sync must
    /// therefore keep the relay connected.
    fn is_disconnect_candidate(&self, has_pending_batches: bool, has_desired_work: bool) -> bool {
        if self.is_bootstrap
            || self.connection_status == ConnectionStatus::Connecting
            || self.connection_status == ConnectionStatus::Disconnecting
            || !self.repos.is_empty()
            || !self.state_only_repos.is_empty()
            || !self.root_events.is_empty()
            || has_pending_batches
            || has_desired_work
        {
            return false;
        }

        self.connection_status == ConnectionStatus::Disconnected || self.historic_sync_completed
    }

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
        self.state_only_repos.clear();
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
pub struct FilterPaginationState {
    /// Number of events received for this filter
    pub event_count: usize,
    /// Smallest created_at timestamp seen for this filter
    pub min_created_at: Option<Timestamp>,
    /// Original filter to reconstruct for next page
    pub original_filter: Filter,
}

/// Pagination state for every OR filter carried by one subscription.
#[derive(Debug, Clone)]
pub struct PaginationState {
    pub filters: Vec<FilterPaginationState>,
}

impl PaginationState {
    fn new(filters: Vec<Filter>) -> Self {
        Self {
            filters: filters
                .into_iter()
                .map(|original_filter| FilterPaginationState {
                    event_count: 0,
                    min_created_at: None,
                    original_filter,
                })
                .collect(),
        }
    }

    fn record_event(&mut self, event: &Event) {
        for state in &mut self.filters {
            if state
                .original_filter
                .match_event(event, MatchEventOptions::new())
            {
                state.event_count += 1;
                match state.min_created_at {
                    None => state.min_created_at = Some(event.created_at),
                    Some(min) if event.created_at < min => {
                        state.min_created_at = Some(event.created_at);
                    }
                    _ => {}
                }
            }
        }
    }

    fn next_page_filters(self) -> Vec<Filter> {
        self.filters
            .into_iter()
            .filter_map(|state| {
                (state.event_count >= PAGINATION_THRESHOLD)
                    .then_some(state.min_created_at)
                    .flatten()
                    .map(|min_created_at| {
                        state
                            .original_filter
                            .until(Timestamp::from(min_created_at.as_secs()))
                    })
            })
            .collect()
    }
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
    /// Repos receiving full L2/L3 sync in this batch
    pub repos: HashSet<String>,
    /// Repos receiving state-only sync in this batch
    pub state_only_repos: HashSet<String>,
    /// Root events being synced in this batch
    pub root_events: HashSet<EventId>,
}

fn take_drained_batch_as_failed(
    pending: &mut HashMap<String, Vec<PendingBatch>>,
    relay_url: &str,
    batch_id: u64,
) -> Option<PendingBatch> {
    let (batch_index, remove_relay) = {
        let batches = pending.get(relay_url)?;
        let batch_index = batches
            .iter()
            .position(|batch| batch.batch_id == batch_id)?;
        if !batches[batch_index].outstanding_subs.is_empty() {
            return None;
        }
        (batch_index, batches.len() == 1)
    };

    let mut batch = pending.get_mut(relay_url)?.remove(batch_index);
    batch.failed = true;
    if remove_relay {
        pending.remove(relay_url);
    }
    Some(batch)
}

fn mark_deferred_pagination(
    batch: &mut PendingBatch,
    completed_sub_id: &SubscriptionId,
) -> SubscriptionId {
    let deferred_sub_id = SubscriptionId::new(format!(
        "deferred-pagination-{}-{completed_sub_id}",
        batch.batch_id
    ));
    batch.outstanding_subs.insert(deferred_sub_id.clone());
    deferred_sub_id
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectAttemptToken(u64);

#[derive(Debug)]
enum ConnectAttemptOutcome {
    Connected,
    Failed(String),
}

#[derive(Debug)]
struct ConnectAttemptResult {
    relay_url: String,
    token: ConnectAttemptToken,
    outcome: ConnectAttemptOutcome,
}

/// Quick reconnect window in seconds (15 minutes)
const QUICK_RECONNECT_WINDOW_SECS: u64 = 15 * 60;

/// Maximum incremental filter fragmentation above the desired live baseline
/// before triggering consolidation.
const CONSOLIDATION_THRESHOLD: usize = 70;

/// Bound concurrent DNS and websocket handshakes so a large relay list cannot
/// exhaust network resources while keeping the sync actor responsive.
const MAX_CONCURRENT_CONNECT_ATTEMPTS: usize = 8;

/// Per-filter threshold for historic REQ+EOSE pagination.
///
/// Grouped pagination assumes that relays apply result limits independently to
/// each filter, return at least this many events for a non-exhausted filter,
/// and do not impose an additional total-result cap across the whole REQ. This
/// matches NIP-01's per-filter `limit` model and ngit-grasp's relay behavior.
/// Relays that violate these assumptions can make one filter appear exhausted
/// after another filter consumes the combined result allowance.
const PAGINATION_THRESHOLD: usize = 75;

/// Conservative number of OR filters carried by one NIP-01 REQ.
///
/// This keeps active subscription counts low without producing unusually
/// large REQ messages for relays that enforce their own per-REQ filter limits.
const MAX_FILTERS_PER_REQ: usize = 10;

/// Serialized byte budget for the filters carried by one NIP-01 REQ.
///
/// The whole REQ message must fit relay maximum message sizes (128 KB floor
/// observed via NIP-11). 96 KB of filters leaves 1.3× margin for the
/// envelope and holds three full byte-budgeted filter chunks (see
/// [`filters::FILTER_VALUE_BYTE_BUDGET`]), so grouped REQs also stay within
/// strfry's optional strict `filterValidation` limit of three filters per
/// REQ when chunks are full. See
/// docs/explanation/sync-scaling-constraints.md.
const REQ_MESSAGE_BYTE_BUDGET: usize = 96 * 1024;

/// Pack filters into REQ-sized groups.
///
/// Groups are cut when adding the next filter would exceed either the
/// serialized byte budget or the filter-count cap. A single oversized filter
/// still gets its own group, so progress is always made.
fn group_filters_for_req(filters: &[Filter]) -> Vec<Vec<Filter>> {
    let mut groups: Vec<Vec<Filter>> = Vec::new();
    let mut current: Vec<Filter> = Vec::new();
    let mut bytes = 0usize;
    for filter in filters {
        let cost = filter.as_json().len();
        if !current.is_empty()
            && (current.len() >= MAX_FILTERS_PER_REQ || bytes + cost > REQ_MESSAGE_BYTE_BUDGET)
        {
            groups.push(std::mem::take(&mut current));
            bytes = 0;
        }
        current.push(filter.clone());
        bytes += cost;
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

fn reserve_connect_attempt(
    in_flight: &mut HashMap<String, ConnectAttemptToken>,
    next_token: &mut u64,
    relay_url: &str,
) -> Option<ConnectAttemptToken> {
    if in_flight.contains_key(relay_url) {
        return None;
    }
    *next_token = next_token
        .checked_add(1)
        .expect("connect attempt token exhausted");
    let token = ConnectAttemptToken(*next_token);
    in_flight.insert(relay_url.to_string(), token);
    Some(token)
}

fn take_connect_attempt(
    in_flight: &mut HashMap<String, ConnectAttemptToken>,
    relay_url: &str,
    token: ConnectAttemptToken,
) -> bool {
    if in_flight.get(relay_url) != Some(&token) {
        return false;
    }
    in_flight.remove(relay_url);
    true
}

async fn begin_connect_attempt(
    semaphore: Arc<Semaphore>,
    health_tracker: Arc<RelayHealthTracker>,
    relay_url: &str,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let permit = semaphore.acquire_owned().await.ok()?;
    health_tracker.record_attempt(relay_url);
    Some(permit)
}

fn consolidation_fragmentation(
    current_count: usize,
    new_count: usize,
    desired_baseline: usize,
) -> usize {
    current_count
        .saturating_add(new_count)
        .saturating_sub(desired_baseline)
}

fn should_consolidate(current_count: usize, new_count: usize, desired_baseline: usize) -> bool {
    consolidation_fragmentation(current_count, new_count, desired_baseline)
        > CONSOLIDATION_THRESHOLD
}

fn grouped_subscription_count(filters: &[Filter]) -> usize {
    group_filters_for_req(filters).len()
}

#[derive(Debug, Default)]
struct DeferredConsolidations {
    relays: HashSet<String>,
}

impl DeferredConsolidations {
    fn request(&mut self, relay_url: &str, has_pending_batches: bool) -> bool {
        if has_pending_batches {
            self.relays.insert(relay_url.to_string());
            false
        } else {
            self.relays.remove(relay_url);
            true
        }
    }

    fn take_ready(&mut self, relay_url: &str, has_pending_batches: bool) -> bool {
        !has_pending_batches && self.relays.remove(relay_url)
    }

    fn contains(&self, relay_url: &str) -> bool {
        self.relays.contains(relay_url)
    }

    fn cancel(&mut self, relay_url: &str) -> bool {
        self.relays.remove(relay_url)
    }

    fn clear(&mut self) {
        self.relays.clear();
    }
}

fn notify_deferred_consolidation_after_batch_completion(
    deferred: &DeferredConsolidations,
    sender: Option<&tokio::sync::mpsc::UnboundedSender<String>>,
    relay_url: &str,
) {
    if deferred.contains(relay_url) {
        if let Some(sender) = sender {
            let _ = sender.send(relay_url.to_string());
        }
    }
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
///
/// The same tick also drives bounded recovery of events that relays reported
/// during negentropy reconciliation but failed to deliver on exact-ID fetches
/// (see [`missing_events`]). Recovery attempts are backed off per relay, so
/// the tick itself stays cheap when nothing is due.
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
                manager.tick_missing_event_recovery().await;
            }
            _ = shutdown_rx.recv() => {
                tracing::debug!("Purgatory announcement sync timer received shutdown signal");
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
    let hot_cache_interval = Duration::from_secs(60);
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
                let unrecoverable_expired = manager.rejected_events_index.cleanup_expired_unrecoverable();

                if ann_cold_expired + state_cold_expired + unrecoverable_expired > 0 {
                    tracing::info!(
                        announcements = ann_cold_expired,
                        states = state_cold_expired,
                        unrecoverable = unrecoverable_expired,
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
    /// Active relay connections - keyed by relay URL
    connections: HashMap<String, RelayConnection>,
    /// Event-directed relay targets rejected by the outbound target policy.
    ///
    /// Rejected URLs stay in `repo_sync_index` (they come from stored events),
    /// so without this memo every sync pass would re-derive, re-reject, and
    /// re-log the same forbidden target. Bounded by the set of distinct relay
    /// URLs in stored/purgatory events, which the indexes already carry.
    rejected_relay_targets: HashSet<String>,
    /// Last exact-ID dependency recovery attempt, used to bound retries.
    dependency_refetch_attempts: Arc<std::sync::Mutex<HashMap<EventId, Instant>>>,
    /// Events relays reported during negentropy reconciliation but failed to
    /// deliver on exact-ID fetches. Retried with bounded backoff by the sync
    /// maintenance timer instead of being dropped with their failed batch.
    missing_event_recovery: Arc<std::sync::Mutex<missing_events::MissingEventRecoveryIndex>>,
    /// Last dependency pass for each purgatory announcement.
    purgatory_dependency_attempts: HashMap<EventId, Instant>,
    /// Temporary source relays retained while rejected dependencies are recovered.
    dependency_relay_deadlines: HashMap<String, Instant>,
    /// Health tracker for relay connection state
    health_tracker: Arc<RelayHealthTracker>,
    /// Counter for generating unique batch IDs
    next_batch_id: u64,
    /// Monotonic identity for rejecting stale connection results.
    next_connect_attempt_token: u64,
    /// One active or queued connection attempt per canonical relay URL.
    in_flight_connect_attempts: HashMap<String, ConnectAttemptToken>,
    /// Shared bound for DNS and websocket handshakes.
    connect_attempt_semaphore: Arc<Semaphore>,
    /// Relays whose subscription consolidation waits for in-flight batches to drain.
    deferred_consolidations: DeferredConsolidations,
    /// Channel for disconnect notifications (set during run)
    disconnect_tx: Option<tokio::sync::mpsc::Sender<DisconnectNotification>>,
    /// Channel for EOSE notifications (set during run)
    eose_tx: Option<tokio::sync::mpsc::Sender<EoseNotification>>,
    /// Returns connection outcomes to the sync actor for serialized state changes.
    connect_attempt_result_tx: Option<tokio::sync::mpsc::UnboundedSender<ConnectAttemptResult>>,
    /// Wakes the actor when a batch completion may unblock consolidation.
    deferred_consolidation_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
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
            connections: HashMap::new(),
            rejected_relay_targets: HashSet::new(),
            dependency_refetch_attempts: Arc::new(std::sync::Mutex::new(HashMap::new())),
            missing_event_recovery: Arc::new(std::sync::Mutex::new(
                missing_events::MissingEventRecoveryIndex::default(),
            )),
            purgatory_dependency_attempts: HashMap::new(),
            dependency_relay_deadlines: HashMap::new(),
            health_tracker: Arc::new(RelayHealthTracker::new(config)),
            next_batch_id: 0,
            next_connect_attempt_token: 0,
            in_flight_connect_attempts: HashMap::new(),
            connect_attempt_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECT_ATTEMPTS)),
            deferred_consolidations: DeferredConsolidations::default(),
            disconnect_tx: None,
            eose_tx: None,
            connect_attempt_result_tx: None,
            deferred_consolidation_tx: None,
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
            let next_filters = pagination_state.next_page_filters();
            if !next_filters.is_empty() {
                let relay_url_for_pagination = relay_url.to_string();
                let batch_id = batch.batch_id;
                tracing::info!(
                    relay = %relay_url,
                    sub_id = %sub_id,
                    batch_id,
                    filter_count = next_filters.len(),
                    "Grouped subscription hit pagination threshold, fetching next page"
                );

                // A NOTICE can arrive immediately before this page's EOSE.
                // Keep a sentinel in the batch and let a detached worker
                // resume the exact grouped page after the cooldown.
                if self.health_tracker.is_rate_limited(relay_url) {
                    let deferred_sub_id = mark_deferred_pagination(batch, &sub_id);
                    drop(pending);

                    let Some(connection) = self.connections.get(&relay_url_for_pagination).cloned()
                    else {
                        tracing::error!(
                            relay = %relay_url_for_pagination,
                            batch_id,
                            "Cannot defer rate-limited pagination without a relay connection"
                        );
                        return;
                    };
                    Self::spawn_deferred_pagination(
                        connection,
                        self.health_tracker.clone(),
                        self.pending_sync_index.clone(),
                        relay_url_for_pagination,
                        batch_id,
                        deferred_sub_id,
                        next_filters,
                    );
                    return;
                }

                drop(pending);

                let mut next_page_started = false;
                if let Some(conn) = self.connections.get(&relay_url_for_pagination) {
                    match conn.subscribe_filters(next_filters.clone(), true).await {
                        Ok(new_sub_id) => {
                            let mut pending = self.pending_sync_index.write().await;
                            if let Some(batches) = pending.get_mut(&relay_url_for_pagination) {
                                if let Some(batch) =
                                    batches.iter_mut().find(|b| b.batch_id == batch_id)
                                {
                                    batch.outstanding_subs.insert(new_sub_id.clone());
                                    next_page_started = true;
                                    batch.pagination_state.insert(
                                        new_sub_id.clone(),
                                        PaginationState::new(next_filters),
                                    );
                                    tracing::info!(
                                        relay = %relay_url_for_pagination,
                                        new_sub_id = %new_sub_id,
                                        batch_id,
                                        "Next grouped page subscription created"
                                    );
                                }
                            }
                        }
                        Err(error) => {
                            tracing::error!(
                                relay = %relay_url_for_pagination,
                                batch_id,
                                error = %error,
                                "Failed to create grouped pagination subscription"
                            );
                        }
                    }
                }

                if !next_page_started {
                    let completed_batch = {
                        let mut pending = self.pending_sync_index.write().await;
                        take_drained_batch_as_failed(
                            &mut pending,
                            &relay_url_for_pagination,
                            batch_id,
                        )
                    };
                    if let Some(batch) = completed_batch {
                        tracing::warn!(
                            relay = %relay_url_for_pagination,
                            batch_id,
                            "Pagination could not continue; completing drained batch as failed"
                        );
                        self.confirm_batch(&relay_url_for_pagination, batch).await;
                    }
                }

                return;
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
                            missing_ids_sample = ?missing.iter().take(5).map(|id| id.to_hex()).collect::<Vec<_>>(),
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
                        let batch_full_repos = batch.items.repos.clone();
                        let batch_state_only_repos = batch.items.state_only_repos.clone();
                        let batch_root_events = batch.items.root_events.clone();
                        let missing_count = missing.len();

                        // Drop the lock before async operations
                        drop(pending);

                        // Create REQ+EOSE subscriptions using original semantic filters
                        // This queries by kind/author/tags instead of by ID, which may
                        // succeed even when ID-based queries fail.
                        // Preserve the level this batch was created with. The desired
                        // level may have advanced from StateOnly to Full while the
                        // historic request was in flight.
                        let fallback_filters = filters::build_sync_level_aware_filters(
                            &batch_full_repos,
                            &batch_state_only_repos,
                            &batch_root_events,
                            None,
                        );

                        if fallback_filters.is_empty() {
                            tracing::warn!(
                                relay = %relay_url_for_fallback,
                                batch_id = batch_id,
                                full_repos = batch_full_repos.len(),
                                state_only_repos = batch_state_only_repos.len(),
                                root_events = batch_root_events.len(),
                                "Cannot create semantic fallback filters - no repos or root_events in batch"
                            );
                            // Fall through to ID-based fallback as last resort
                        }

                        let mut new_sub_ids = HashSet::new();
                        if let Some(conn) = self.connections.get(&relay_url_for_fallback) {
                            for filter_group in group_filters_for_req(&fallback_filters) {
                                match conn.subscribe_filters(filter_group, true).await {
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
                            // No fallback subscriptions could be created (for
                            // announcement batches there is no semantic metadata
                            // at all). Finalize the batch as failed but keep the
                            // missing IDs represented so the maintenance timer
                            // retries them with bounded backoff instead of
                            // forgetting them until the next daily sync.
                            let relay_already_degraded = {
                                let index = self.relay_sync_index.read().await;
                                index
                                    .get(&relay_url_for_fallback)
                                    .map(|state| state.historic_sync_had_failures)
                                    .unwrap_or(false)
                            };
                            let register_outcome =
                                self.missing_event_recovery.lock().unwrap().register(
                                    &relay_url_for_fallback,
                                    batch_id,
                                    missing.iter().copied(),
                                    relay_already_degraded,
                                    Instant::now(),
                                );
                            tracing::error!(
                                relay = %relay_url_for_fallback,
                                batch_id = batch_id,
                                missing_count = missing_count,
                                pending_recovery = register_outcome.pending_total,
                                "Failed to create REQ+EOSE fallback subscriptions - completing batch with partial results; bounded missing-event recovery scheduled"
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
                        missing_ids_sample = ?missing.iter().take(5).map(|id| id.to_hex()).collect::<Vec<_>>(),
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
                        // Failed to create retry subscriptions. Finalize the
                        // batch as failed (an incomplete batch must not be
                        // reported as successfully complete) and keep the
                        // missing IDs represented for bounded recovery.
                        let relay_already_degraded = {
                            let index = self.relay_sync_index.read().await;
                            index
                                .get(&relay_url_for_retry)
                                .map(|state| state.historic_sync_had_failures)
                                .unwrap_or(false)
                        };
                        let register_outcome =
                            self.missing_event_recovery.lock().unwrap().register(
                                &relay_url_for_retry,
                                batch_id,
                                missing.iter().copied(),
                                relay_already_degraded,
                                Instant::now(),
                            );
                        tracing::error!(
                            relay = %relay_url_for_retry,
                            batch_id = batch_id,
                            missing_count = missing.len(),
                            pending_recovery = register_outcome.pending_total,
                            "Failed to retry missing events - confirming batch with partial results; bounded missing-event recovery scheduled"
                        );

                        // Re-acquire lock to extract the batch
                        let mut pending = self.pending_sync_index.write().await;
                        if let Some(batches) = pending.get_mut(&relay_url_for_retry) {
                            if let Some(idx) = batches.iter().position(|b| b.batch_id == batch_id) {
                                let mut completed_batch = batches.remove(idx);
                                completed_batch.failed = true;
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

    #[allow(clippy::too_many_arguments)]
    fn spawn_deferred_pagination(
        connection: RelayConnection,
        health_tracker: Arc<RelayHealthTracker>,
        pending_sync_index: PendingSyncIndex,
        relay_url: String,
        batch_id: u64,
        deferred_sub_id: SubscriptionId,
        next_filters: Vec<Filter>,
    ) {
        tokio::spawn(async move {
            tracing::info!(
                relay = %relay_url,
                batch_id,
                filter_count = next_filters.len(),
                "Rate limited during historic pagination; deferring the exact next page without blocking the sync actor"
            );

            loop {
                if let Some(remaining) = health_tracker.get_remaining_backoff(&relay_url) {
                    tokio::time::sleep(remaining + Duration::from_millis(10)).await;
                    continue;
                }

                // Hold only the pending-index lock while subscribing. This
                // prevents a very fast EOSE from reaching the actor before its
                // new subscription ID is registered, without blocking the
                // SyncManager mutex or the purgatory timer.
                let mut pending = pending_sync_index.write().await;
                let Some(batch) = pending.get_mut(&relay_url).and_then(|batches| {
                    batches.iter_mut().find(|batch| batch.batch_id == batch_id)
                }) else {
                    tracing::debug!(
                        relay = %relay_url,
                        batch_id,
                        "Deferred pagination batch no longer exists"
                    );
                    return;
                };
                if !batch.outstanding_subs.contains(&deferred_sub_id) {
                    return;
                }

                match connection
                    .subscribe_filters(next_filters.clone(), true)
                    .await
                {
                    Ok(new_sub_id) => {
                        batch.outstanding_subs.remove(&deferred_sub_id);
                        batch.outstanding_subs.insert(new_sub_id.clone());
                        batch
                            .pagination_state
                            .insert(new_sub_id.clone(), PaginationState::new(next_filters));
                        tracing::info!(
                            relay = %relay_url,
                            new_sub_id = %new_sub_id,
                            batch_id,
                            "Deferred pagination resumed after rate-limit cooldown"
                        );
                        return;
                    }
                    Err(error) => {
                        drop(pending);
                        tracing::warn!(
                            relay = %relay_url,
                            batch_id,
                            error = %error,
                            "Deferred pagination subscription failed; retrying"
                        );
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        });
    }

    /// Drive bounded recovery of events relays reported during negentropy
    /// reconciliation but failed to deliver on exact-ID fetches.
    ///
    /// Runs on the sync maintenance timer. For each relay with pending IDs:
    /// 1. IDs already present locally (live sync, user submission) are
    ///    cleared promptly without consuming attempt budget.
    /// 2. When the relay's backoff deadline has passed and it has a live
    ///    connection, one bounded exact-ID fetch is spawned. Network I/O runs
    ///    outside the sync actor lock, and per-relay single-flight keeps one
    ///    persistently incomplete relay from starving other relays or later
    ///    batches.
    async fn tick_missing_event_recovery(&mut self) {
        let idle_relays = self.missing_event_recovery.lock().unwrap().idle_relays();
        if idle_relays.is_empty() {
            return;
        }

        for relay_url in idle_relays {
            let Some(pending) = self
                .missing_event_recovery
                .lock()
                .unwrap()
                .pending_ids(&relay_url)
            else {
                continue;
            };

            // 1. Clear IDs satisfied by other means.
            let satisfied: Vec<EventId> = match self
                .database
                .query(Filter::new().ids(pending.iter().copied()))
                .await
            {
                Ok(events) => events.into_iter().map(|event| event.id).collect(),
                Err(_) => Vec::new(),
            };
            if !satisfied.is_empty() {
                let outcome = self
                    .missing_event_recovery
                    .lock()
                    .unwrap()
                    .clear_satisfied(&relay_url, &satisfied);
                tracing::info!(
                    relay = %relay_url,
                    satisfied = satisfied.len(),
                    "Pending missing events satisfied by local arrivals"
                );
                if let Some(outcome) = outcome {
                    Self::apply_recovery_outcome(
                        &relay_url,
                        outcome,
                        &self.relay_sync_index,
                        self.metrics.as_ref(),
                    )
                    .await;
                    continue;
                }
            }

            // 2. Issue a due attempt over a live connection only.
            let connection_ready = {
                let index = self.relay_sync_index.read().await;
                index
                    .get(&relay_url)
                    .map(|state| {
                        matches!(
                            state.connection_status,
                            ConnectionStatus::Syncing
                                | ConnectionStatus::Connected
                                | ConnectionStatus::ConnectedHistoricSyncFailures
                        )
                    })
                    .unwrap_or(false)
            };
            let connection = self.connections.get(&relay_url).cloned();
            let (Some(connection), true) = (connection, connection_ready) else {
                // No usable connection: postpone without consuming the
                // zero-progress budget so an unavailable relay can neither
                // expire its pending IDs nor spin in a tight loop.
                self.missing_event_recovery
                    .lock()
                    .unwrap()
                    .defer_attempt(&relay_url, Instant::now());
                continue;
            };

            let Some(attempt) = self
                .missing_event_recovery
                .lock()
                .unwrap()
                .begin_attempt(&relay_url, Instant::now())
            else {
                continue;
            };

            tokio::spawn(Self::run_missing_event_recovery_attempt(
                relay_url,
                connection,
                attempt,
                Arc::clone(&self.database),
                self.write_policy.clone(),
                self.local_relay.clone(),
                Arc::clone(&self.rejected_events_index),
                Arc::clone(&self.missing_event_recovery),
                self.relay_sync_index.clone(),
                self.metrics.clone(),
            ));
        }
    }

    /// One bounded exact-ID recovery fetch against a single relay.
    ///
    /// Runs outside the sync actor lock. Every event the relay returns is
    /// passed through the normal write policy; an ID counts as recovered once
    /// the relay has delivered the event, regardless of the policy verdict
    /// (rejected events have their own re-processing machinery).
    #[allow(clippy::too_many_arguments)]
    async fn run_missing_event_recovery_attempt(
        relay_url: String,
        connection: RelayConnection,
        attempt: missing_events::RecoveryAttempt,
        database: SharedDatabase,
        write_policy: Nip34WritePolicy,
        local_relay: LocalRelay,
        rejected_events_index: Arc<RejectedEventsIndex>,
        missing_event_recovery: Arc<std::sync::Mutex<missing_events::MissingEventRecoveryIndex>>,
        relay_index: RelaySyncIndex,
        metrics: Option<SyncMetrics>,
    ) {
        let requested: HashSet<EventId> = attempt.ids.iter().copied().collect();
        tracing::info!(
            relay = %relay_url,
            attempt = attempt.attempt_number,
            requested = requested.len(),
            "Retrying events missing from an incomplete historic sync batch"
        );

        let events = match connection
            .fetch_events(
                Filter::new().ids(attempt.ids.iter().copied()),
                Duration::from_secs(10),
            )
            .await
        {
            Ok(events) => events,
            Err(error) => {
                tracing::warn!(
                    relay = %relay_url,
                    attempt = attempt.attempt_number,
                    requested = requested.len(),
                    error = %error,
                    "Missing-event recovery fetch failed"
                );
                Vec::new()
            }
        };

        let mut recovered = HashSet::new();
        for event in events {
            if !requested.contains(&event.id) {
                continue;
            }
            // Events already tracked as rejected count as recovered without
            // re-processing: re-validation is owned by the rejected-index
            // re-processing machinery, and unrecoverable IDs never revalidate.
            if rejected_events_index.contains(&event.id) {
                tracing::debug!(
                    relay = %relay_url,
                    event_id = %event.id,
                    "Recovered missing event already tracked as rejected, skipping re-processing"
                );
                recovered.insert(event.id);
                continue;
            }
            let result = Self::process_event_static(
                &event,
                &relay_url,
                &database,
                &write_policy,
                &local_relay,
                &rejected_events_index,
                crate::nostr::persistence::SaveContext::RelaySync,
            )
            .await;
            if result == ProcessResult::Rejected {
                tracing::debug!(
                    relay = %relay_url,
                    event_id = %event.id,
                    "Recovered missing event was rejected by the write policy"
                );
            }
            recovered.insert(event.id);
        }

        let outcome = missing_event_recovery.lock().unwrap().complete_attempt(
            &relay_url,
            &recovered,
            Instant::now(),
        );
        let Some(outcome) = outcome else {
            tracing::debug!(
                relay = %relay_url,
                "Recovery attempt finished after the relay's pending work was reset"
            );
            return;
        };
        Self::apply_recovery_outcome(&relay_url, outcome, &relay_index, metrics.as_ref()).await;
    }

    /// Log a recovery outcome and, on full recovery, restore relay health.
    ///
    /// A relay is only promoted from `ConnectedHistoricSyncFailures` back to
    /// `Connected` when every registered missing ID was recovered and no
    /// unrelated batch failure was observed for the relay.
    async fn apply_recovery_outcome(
        relay_url: &str,
        outcome: missing_events::AttemptOutcome,
        relay_index: &RelaySyncIndex,
        metrics: Option<&SyncMetrics>,
    ) {
        use missing_events::AttemptOutcome;

        match outcome {
            AttemptOutcome::FullyRecovered {
                recovered,
                total_recovered,
                can_restore_health,
            } => {
                tracing::info!(
                    relay = %relay_url,
                    recovered,
                    total_recovered,
                    can_restore_health,
                    "All events missing from historic sync fully recovered"
                );
                if !can_restore_health {
                    return;
                }
                let mut index = relay_index.write().await;
                if let Some(state) = index.get_mut(relay_url) {
                    state.historic_sync_had_failures = false;
                    if state.connection_status == ConnectionStatus::ConnectedHistoricSyncFailures {
                        state.connection_status = ConnectionStatus::Connected;
                        tracing::info!(
                            relay = %relay_url,
                            "Historic sync failures resolved - relay promoted to Connected"
                        );
                        if let Some(metrics) = metrics {
                            metrics
                                .record_connection_status(relay_url, ConnectionStatus::Connected);
                        }
                    }
                }
            }
            AttemptOutcome::PartiallyRecovered {
                recovered,
                remaining,
                next_attempt_in,
            } => {
                tracing::info!(
                    relay = %relay_url,
                    recovered,
                    remaining,
                    next_attempt_in_secs = next_attempt_in.as_secs_f64(),
                    "Partially recovered events missing from historic sync - retry scheduled"
                );
            }
            AttemptOutcome::RetryScheduled {
                attempt,
                remaining,
                next_attempt_in,
            } => {
                tracing::info!(
                    relay = %relay_url,
                    attempt,
                    remaining,
                    next_attempt_in_secs = next_attempt_in.as_secs_f64(),
                    "No missing events recovered - retry scheduled with backoff"
                );
            }
            AttemptOutcome::Expired {
                remaining,
                attempts,
            } => {
                tracing::warn!(
                    relay = %relay_url,
                    remaining,
                    attempts,
                    "Missing-event recovery expired by policy after repeated zero-progress attempts - relay remains ConnectedHistoricSyncFailures until daily sync"
                );
            }
        }
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
        let full_repos_count = batch.items.repos.len();
        let state_only_repos_count = batch.items.state_only_repos.len();
        let events_count = batch.items.root_events.len();
        let sync_method = batch.sync_method;
        let is_generic_filter =
            full_repos_count == 0 && state_only_repos_count == 0 && events_count == 0;

        let mut relay_index = self.relay_sync_index.write().await;

        if let Some(state) = relay_index.get_mut(relay_url) {
            // A completed Full batch upgrades any earlier StateOnly
            // confirmation. A late StateOnly completion must not downgrade a
            // repository whose Full batch already completed.
            state
                .state_only_repos
                .retain(|repo| !batch.items.repos.contains(repo));
            state.repos.extend(batch.items.repos);
            state.state_only_repos.extend(
                batch
                    .items
                    .state_only_repos
                    .into_iter()
                    .filter(|repo| !state.repos.contains(repo)),
            );
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
                // Failures unrelated to a relay's pending missing-event
                // recovery mean full recovery must not restore its health.
                self.missing_event_recovery
                    .lock()
                    .unwrap()
                    .note_failed_batch(relay_url, batch_id);
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
                full_repos_confirmed = full_repos_count,
                state_only_repos_confirmed = state_only_repos_count,
                root_events_confirmed = events_count,
                root_events_ids = ?batch.items.root_events.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
                total_full_repos = state.repos.len(),
                total_state_only_repos = state.state_only_repos.len(),
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

        notify_deferred_consolidation_after_batch_completion(
            &self.deferred_consolidations,
            self.deferred_consolidation_tx.as_ref(),
            relay_url,
        );

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
                    full_repos_synced = state.repos.len(),
                    state_only_repos_synced = state.state_only_repos.len(),
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
        self.cancel_deferred_consolidation(relay_url, "daily sync reset");

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

        // Daily sync re-discovers everything from scratch, superseding any
        // pending missing-event recovery for this relay.
        let dropped_recovery_ids = self
            .missing_event_recovery
            .lock()
            .unwrap()
            .clear_relay(relay_url);
        if dropped_recovery_ids > 0 {
            tracing::info!(
                relay = %relay_url,
                dropped_missing_ids = dropped_recovery_ids,
                "Daily sync reset pending missing-event recovery"
            );
        }

        // Clear pending batches for this relay
        {
            let mut pending = self.pending_sync_index.write().await;
            pending.remove(relay_url);
        }

        // Get relay state and clear sync state (repos and root_events)
        {
            let mut index = self.relay_sync_index.write().await;
            if let Some(state) = index.get_mut(relay_url) {
                let repos_cleared = state.repos.len() + state.state_only_repos.len();
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
    /// 5. Handles disconnect/EOSE notifications and connection-worker results
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

        // 4. Connection workers never mutate manager state. Their unbounded
        // result channel cannot make a completed worker wait behind the actor.
        let (connect_attempt_result_tx, mut connect_attempt_result_rx) =
            mpsc::unbounded_channel::<ConnectAttemptResult>();

        // Batch completion can be synchronous, so use a non-blocking wakeup
        // instead of waiting for pending work while holding the actor lock.
        let (deferred_consolidation_tx, mut deferred_consolidation_rx) =
            mpsc::unbounded_channel::<String>();

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
        self.connect_attempt_result_tx = Some(connect_attempt_result_tx);
        self.deferred_consolidation_tx = Some(deferred_consolidation_tx);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // 6. Connect to bootstrap relay if configured
        if let Some(ref bootstrap_url) = self.bootstrap_relay_url.clone() {
            match canonical_relay_key(bootstrap_url) {
                Ok(relay_url) => {
                    if self.register_relay(relay_url.clone(), true).await {
                        self.schedule_connect_relay(&relay_url).await;
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        relay = %bootstrap_url,
                        error = %error,
                        "Rejecting invalid bootstrap relay target"
                    );
                }
            }
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

        // 12. Main loop - handle actions, lifecycle notifications, and worker results
        loop {
            // Wait for an event without holding the lock
            tokio::select! {
                action = action_rx.recv() => {
                    match action {
                        Some(add_filters) => {
                            // SelfSubscriber actions are dirty-relay signals.
                            // Recompute against current pending and confirmed
                            // state instead of trusting a queued full-index
                            // snapshot that may already be stale.
                            let mut manager = sync_manager.lock().await;
                            manager
                                .recompute_new_sync_filters_for_relay(&add_filters.relay_url)
                                .await;
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
                result = connect_attempt_result_rx.recv() => {
                    match result {
                        Some(result) => {
                            // Connection state changes remain serialized through the actor.
                            let mut manager = sync_manager.lock().await;
                            manager.handle_connect_attempt_result(result).await;
                        }
                        None => {
                            tracing::debug!("Connect attempt result channel closed");
                        }
                    }
                }
                relay_url = deferred_consolidation_rx.recv() => {
                    if let Some(relay_url) = relay_url {
                        let mut manager = sync_manager.lock().await;
                        manager.process_deferred_consolidation(&relay_url).await;
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
    async fn handle_new_sync_filters(&mut self, mut action: AddFilters) {
        action.relay_url = match canonical_relay_key(&action.relay_url) {
            Ok(relay_url) => relay_url,
            Err(error) => {
                tracing::warn!(
                    relay = %action.relay_url,
                    error = %error,
                    "Rejecting invalid sync relay target"
                );
                return;
            }
        };

        // Targets already rejected by the outbound policy stay in the sync
        // indexes (they come from stored events); skip them quietly instead
        // of re-rejecting on every recomputation.
        if self.rejected_relay_targets.contains(&action.relay_url) {
            tracing::debug!(
                relay = %action.relay_url,
                "Skipping relay target rejected by outbound policy"
            );
            return;
        }

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
                    full_repos = action.items.repos.len(),
                    state_only_repos = action.items.state_only_repos.len(),
                    "Registering and connecting to new relay"
                );

                // Register relay (creates RelayConnection, initializes RelayState, updates metrics)
                if self.register_relay(action.relay_url.clone(), false).await {
                    self.schedule_connect_relay(&action.relay_url).await;
                }
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
                full_repos = action.items.repos.len(),
                state_only_repos = action.items.state_only_repos.len(),
                root_events = action.items.root_events.len(),
                "Skipping AddFilters for rate-limited relay, will recompute after cooldown"
            );
            return;
        }

        // Step 3: Check if consolidation is needed BEFORE adding new filters
        self.maybe_consolidate(
            &action.relay_url,
            grouped_subscription_count(&action.filters),
        )
        .await;

        // Subscribe to each filter and collect subscription IDs
        tracing::info!(
            relay = %action.relay_url,
            filter_count = action.filters.len(),
            full_repo_count = action.items.repos.len(),
            state_only_repo_count = action.items.state_only_repos.len(),
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
                                        state.record_event(&event);
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
        self.cancel_deferred_consolidation(relay_url, "fresh start");

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
                let repos_cleared = state.repos.len() + state.state_only_repos.len();
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
        let filters = vec![filters::build_announcement_filter(None)];

        // Create live subscription for ongoing announcements
        let _sub_ids = self.sync_live(relay_url, &filters).await;

        // Use historic_sync with empty PendingItems for generic filters
        // Generic filters (announcements) don't have associated repos or root_events
        let items = PendingItems::default();
        let _batch_id = self.historic_sync(relay_url, filters, items, since).await;
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
        self.cancel_deferred_consolidation(relay_url, "quick reconnect");

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

    /// Rebuild level-aware repository subscriptions for a relay
    ///
    /// Uses the confirmed repos and root_events from RelayState to build filters.
    /// If since is provided, applies it to all filters for incremental sync.
    ///
    /// CRITICAL: This method now creates a PendingBatch to track subscriptions,
    /// ensuring EOSE handling works correctly for live sync scenarios.
    async fn rebuild_layer2_and_layer3(&mut self, relay_url: &str, since: Option<Timestamp>) {
        // Get confirmed state from relay_sync_index
        let (full_repos, state_only_repos, root_events) = {
            let index = self.relay_sync_index.read().await;
            match index.get(relay_url) {
                Some(state) => (
                    state.repos.clone(),
                    state.state_only_repos.clone(),
                    state.root_events.clone(),
                ),
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
        if full_repos.is_empty() && state_only_repos.is_empty() && root_events.is_empty() {
            tracing::debug!(
                relay = %relay_url,
                "No confirmed items to rebuild Layer 2/3 for"
            );
            return;
        }

        let filters = filters::build_sync_level_aware_filters(
            &full_repos,
            &state_only_repos,
            &root_events,
            since,
        );

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
    /// Does NOT connect - connection happens via the bounded scheduler.
    /// The RelayConnection persists forever and is reused on reconnects.
    ///
    /// Returns `false` when the target was rejected and no connection exists,
    /// so callers must not schedule a connection attempt. Event-directed URLs
    /// are vetted by the outbound target policy; the operator-configured
    /// bootstrap relay is exempt. An event URL identical to an already
    /// registered connection (e.g. the bootstrap relay itself) reuses that
    /// connection rather than being re-authorized, which keeps the configured
    /// exception exact: only URLs that canonicalize to the same key share it.
    async fn register_relay(&mut self, relay_url: String, is_bootstrap: bool) -> bool {
        let relay_url = match canonical_relay_key(&relay_url) {
            Ok(relay_url) => relay_url,
            Err(error) => {
                tracing::warn!(
                    relay = %relay_url,
                    error = %error,
                    "Rejecting invalid relay registration"
                );
                return false;
            }
        };

        // Create RelayConnection if not exists
        if !self.connections.contains_key(&relay_url) {
            let policy = self.outbound_target_policy();
            let source = if is_bootstrap {
                RelayTargetSource::OperatorConfigured
            } else {
                RelayTargetSource::EventDirected
            };

            // Refuse to even register unauthorized event-directed targets so
            // they never enter the reconnect lifecycle. The connection worker
            // re-checks (with DNS vetting) immediately before every dial.
            if source == RelayTargetSource::EventDirected {
                if let Err(reason) = policy.authorize(OutboundTargetKind::EventRelay, &relay_url) {
                    // Warn once per target; sync passes keep re-deriving the
                    // same URLs from stored events.
                    if self.rejected_relay_targets.insert(relay_url.clone()) {
                        tracing::warn!(
                            relay = %relay_url,
                            reason = %reason,
                            "Rejecting event-directed sync relay target"
                        );
                    }
                    return false;
                }
            }

            // Get relay owner keys for NIP-42 authentication
            let keys = self
                .config
                .relay_owner_keys()
                .expect("relay_owner_keys should be available");

            let connection = RelayConnection::new_with_database(
                relay_url.clone(),
                Arc::clone(&self.database),
                keys,
                source,
                policy,
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
                    state_only_repos: HashSet::new(),
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

        true
    }

    /// Outbound target policy derived from operator configuration.
    fn outbound_target_policy(&self) -> OutboundTargetPolicy {
        OutboundTargetPolicy {
            allow_non_global: self.config.sync_allow_non_global_targets,
        }
    }

    /// Queue one connection attempt without blocking the sync actor.
    ///
    /// DNS and the websocket handshake run in a spawned worker, bounded globally
    /// by `MAX_CONCURRENT_CONNECT_ATTEMPTS`. The actor owns every lifecycle
    /// transition when it receives the worker result.
    async fn schedule_connect_relay(&mut self, relay_url: &str) {
        let relay_url = match canonical_relay_key(relay_url) {
            Ok(relay_url) => relay_url,
            Err(error) => {
                tracing::warn!(relay = %relay_url, error = %error, "Rejecting invalid sync relay target");
                return;
            }
        };
        let Some(result_tx) = self.connect_attempt_result_tx.clone() else {
            tracing::error!(relay = %relay_url, "Connection scheduler is not running");
            return;
        };
        let Some(connection) = self.connections.get(&relay_url).cloned() else {
            tracing::error!(relay = %relay_url, "No RelayConnection registered");
            return;
        };

        let can_schedule = {
            let mut index = self.relay_sync_index.write().await;
            let can_schedule = index
                .get(&relay_url)
                .is_some_and(|state| state.connection_status == ConnectionStatus::Disconnected);
            if can_schedule {
                index
                    .get_mut(&relay_url)
                    .expect("relay state checked immediately above")
                    .connection_status = ConnectionStatus::Connecting;
            }
            can_schedule
        };
        if !can_schedule {
            tracing::trace!(relay = %relay_url, "Relay does not need another connection attempt");
            return;
        }

        let token = match reserve_connect_attempt(
            &mut self.in_flight_connect_attempts,
            &mut self.next_connect_attempt_token,
            &relay_url,
        ) {
            Some(token) => token,
            None => {
                tracing::trace!(relay = %relay_url, "Connection attempt already queued");
                return;
            }
        };

        if let Some(ref metrics) = self.metrics {
            metrics.record_connection_status(&relay_url, ConnectionStatus::Connecting);
        }

        let health_tracker = Arc::clone(&self.health_tracker);
        let semaphore = Arc::clone(&self.connect_attempt_semaphore);
        let timeout = self.health_tracker.base_backoff_secs();
        let Some(mut shutdown_rx) = self.shutdown_tx.as_ref().map(|sender| sender.subscribe())
        else {
            tracing::error!(relay = %relay_url, "Connection scheduler has no shutdown signal");
            return;
        };
        tokio::spawn(async move {
            let permit = tokio::select! {
                permit = begin_connect_attempt(semaphore, health_tracker, &relay_url) => permit,
                _ = shutdown_rx.recv() => return,
            };
            let Some(_permit) = permit else {
                return;
            };
            let outcome = tokio::select! {
                result = connection.connect(timeout) => match result {
                    Ok(()) => ConnectAttemptOutcome::Connected,
                    Err(error) => ConnectAttemptOutcome::Failed(error),
                },
                _ = shutdown_rx.recv() => {
                    connection.disconnect().await;
                    return;
                }
            };
            if result_tx
                .send(ConnectAttemptResult {
                    relay_url,
                    token,
                    outcome,
                })
                .is_err()
            {
                connection.disconnect().await;
            }
        });
    }

    async fn handle_connect_attempt_result(&mut self, result: ConnectAttemptResult) {
        if !take_connect_attempt(
            &mut self.in_flight_connect_attempts,
            &result.relay_url,
            result.token,
        ) {
            tracing::debug!(
                relay = %result.relay_url,
                token = result.token.0,
                "Ignoring stale connection attempt result"
            );
            return;
        }

        let still_connecting = self
            .relay_sync_index
            .read()
            .await
            .get(&result.relay_url)
            .is_some_and(|state| state.connection_status == ConnectionStatus::Connecting);
        if !still_connecting {
            tracing::debug!(
                relay = %result.relay_url,
                token = result.token.0,
                "Ignoring connection result after lifecycle state changed"
            );
            return;
        }

        match result.outcome {
            ConnectAttemptOutcome::Connected => {
                self.health_tracker.record_success(&result.relay_url);
                if let Some(ref metrics) = self.metrics {
                    metrics.record_connection_attempt(&result.relay_url, true);
                }
                self.handle_connect_or_reconnect(&result.relay_url).await;
            }
            ConnectAttemptOutcome::Failed(error) => {
                if let Some(category) = naughty_list::NaughtyListTracker::classify_error(&error) {
                    if let Some(ref naughty_list) = self.health_tracker.naughty_list() {
                        let is_new =
                            naughty_list.record(&result.relay_url, category, error.clone());
                        if is_new {
                            tracing::warn!(
                                relay = %result.relay_url,
                                category = ?category,
                                error = %error,
                                "Relay has persistent configuration issue, added to naughty list"
                            );
                        } else {
                            tracing::debug!(
                                relay = %result.relay_url,
                                category = ?category,
                                "Naughty relay failure (already tracked)"
                            );
                        }
                    }
                } else {
                    tracing::debug!(
                        relay = %result.relay_url,
                        error = %error,
                        "Connection failed (transient issue, backoff active)"
                    );
                }
                self.record_connection_attempt_failure(&result.relay_url)
                    .await;
            }
        }
    }

    async fn record_connection_attempt_failure(&self, relay_url: &str) {
        {
            let mut index = self.relay_sync_index.write().await;
            if let Some(state) = index.get_mut(relay_url) {
                state.connection_status = ConnectionStatus::Disconnected;
            }
        }
        self.health_tracker.record_failure(relay_url);
        if let Some(ref metrics) = self.metrics {
            metrics.record_connection_attempt(relay_url, false);
            metrics.record_connection_status(relay_url, ConnectionStatus::Disconnected);
            metrics.record_health_state(relay_url, self.health_tracker.get_state(relay_url));
        }
    }

    /// Recompute sync actions for a specific relay
    ///
    /// Uses derive_relay_targets and compute_actions to find new items
    /// that need to be synced. Processes AddFilters actions for new items.
    async fn recompute_new_sync_filters_for_relay(&mut self, relay_url: &str) {
        use crate::sync::algorithms::{compute_actions, derive_relay_targets};

        let relay_url = match canonical_relay_key(relay_url) {
            Ok(relay_url) => relay_url,
            Err(error) => {
                tracing::warn!(
                    relay = %relay_url,
                    error = %error,
                    "Ignoring invalid dirty relay signal"
                );
                return;
            }
        };

        // Get current state from indexes (need to collect to avoid holding locks)
        let all_targets = {
            let repo_index = self.repo_sync_index.read().await;
            derive_relay_targets(&repo_index)
        };

        // Filter to only targets for this specific relay
        let relay_target = match all_targets.get(&relay_url) {
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
        single_relay_targets.insert(relay_url.clone(), relay_target);

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
                new_full_repos = action.items.repos.len(),
                new_state_only_repos = action.items.state_only_repos.len(),
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
        let announcement_events = self.purgatory.announcement_events_for_sync();

        if announcements.is_empty() {
            return;
        }

        // Register any new entries in repo_sync_index as StateOnly.
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
                    entry.relays.insert(relay.clone());
                }
            }
        }

        // A maintainer announcement or state may have been fetched and rejected
        // before the reciprocal owner announcement reached this relay. Retry those
        // dependencies after connecting the owner's relay hints so cold-cache
        // misses can be fetched directly by event ID.
        let dependency_events = select_purgatory_dependency_events(
            announcement_events,
            &mut self.purgatory_dependency_attempts,
            Instant::now(),
            purgatory_dependency_retry_after(),
            MAX_PURGATORY_DEPENDENCY_EVENTS_PER_TICK,
        );
        for event in dependency_events {
            self.reprocess_purgatory_announcement_dependencies(&event)
                .await;
        }

        // Recompute all outstanding actions on every pass. A bounded pass may
        // intentionally defer some relays, so restricting this to newly seen
        // URLs would lose that work on the next tick.
        let all_targets = {
            let repo_index = self.repo_sync_index.read().await;
            derive_relay_targets(&repo_index)
        };
        let mut actions = {
            let pending_index = self.pending_sync_index.read().await;
            let relay_index = self.relay_sync_index.read().await;
            compute_actions(&all_targets, &pending_index, &relay_index)
        };
        // Policy-rejected targets must not consume the bounded per-tick
        // budget, or a stored event listing forbidden relays could starve
        // legitimate ones. Compare canonical keys: the rejected set stores
        // them, while actions still carry raw event-supplied URLs.
        actions.retain(|action| match canonical_relay_key(&action.relay_url) {
            Ok(key) => !self.rejected_relay_targets.contains(&key),
            Err(_) => false,
        });
        actions.sort_by_key(|action| {
            !self
                .dependency_relay_deadlines
                .contains_key(&action.relay_url)
        });

        for action in actions
            .into_iter()
            .take(MAX_PURGATORY_FILTER_ACTIONS_PER_TICK)
        {
            tracing::info!(
                relay = %action.relay_url,
                full_repos = action.items.repos.len(),
                state_only_repos = action.items.state_only_repos.len(),
                "Purgatory sync timer: processing one bounded relay action"
            );
            self.handle_new_sync_filters(action).await;
        }
    }

    /// Retry events whose authorization depends on a newly admitted owner announcement.
    ///
    /// This mirrors the accepted-announcement dependency handling in
    /// `process_event_static`, but runs while the owner announcement is still in
    /// purgatory. Announcement policy already treats purgatory announcements as
    /// maintainer authority; doing the retry here makes arrival order irrelevant.
    async fn reprocess_purgatory_announcement_dependencies(&mut self, event: &Event) {
        let announcement =
            match crate::nostr::events::RepositoryAnnouncement::from_event(event.clone()) {
                Ok(announcement) => announcement,
                Err(error) => {
                    tracing::warn!(
                        event_id = %event.id,
                        error = %error,
                        "Failed to parse purgatory announcement for dependency retry"
                    );
                    return;
                }
            };

        let relay_url = format!("ws://{}", self.service_domain);
        let mut dependency_refetch_ids = HashSet::new();
        let mut hot_dependency_events = Vec::new();
        let mut maintainer_queue: VecDeque<String> =
            announcement.maintainers.iter().cloned().collect();
        let mut visited_maintainers = HashSet::new();
        let mut dependency_relay_urls: HashSet<String> =
            announcement.relays.iter().cloned().collect();

        while let Some(maintainer_hex) = maintainer_queue.pop_front() {
            let maintainer_pubkey = match PublicKey::from_hex(&maintainer_hex) {
                Ok(pubkey) => pubkey,
                Err(error) => {
                    tracing::warn!(
                        maintainer_hex = %maintainer_hex,
                        error = %error,
                        "Invalid maintainer public key in purgatory announcement"
                    );
                    continue;
                }
            };
            if !visited_maintainers.insert(maintainer_pubkey) {
                continue;
            }

            for event_type in [
                rejected_index::EventType::Announcement,
                rejected_index::EventType::State,
            ] {
                dependency_relay_urls.extend(self.rejected_events_index.dependency_relay_hints(
                    &maintainer_pubkey,
                    &announcement.identifier,
                    Some(event_type),
                ));
                let (event_ids, hot_events) = self.rejected_events_index.dependency_candidates(
                    &maintainer_pubkey,
                    &announcement.identifier,
                    Some(event_type),
                );
                let hot_event_ids: HashSet<EventId> =
                    hot_events.iter().map(|candidate| candidate.id).collect();

                dependency_refetch_ids.extend(
                    event_ids
                        .into_iter()
                        .filter(|event_id| !hot_event_ids.contains(event_id)),
                );
                hot_dependency_events.extend(
                    hot_events
                        .into_iter()
                        .map(|candidate| (relay_url.clone(), candidate)),
                );
            }

            // Follow already accepted announcements so expired dependencies in
            // a transitive maintainer chain are recovered on subsequent ticks.
            match self
                .database
                .query(
                    Filter::new()
                        .kind(Kind::GitRepoAnnouncement)
                        .author(maintainer_pubkey)
                        .identifier(&announcement.identifier),
                )
                .await
            {
                Ok(events) => {
                    for accepted_event in events {
                        if let Ok(accepted_announcement) =
                            crate::nostr::events::RepositoryAnnouncement::from_event(accepted_event)
                        {
                            dependency_relay_urls.extend(accepted_announcement.relays);
                            maintainer_queue.extend(accepted_announcement.maintainers);
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        maintainer = %maintainer_hex,
                        identifier = %announcement.identifier,
                        error = %error,
                        "Failed to resolve accepted transitive maintainer announcements"
                    );
                }
            }
        }

        // The owner's state may also have arrived before their announcement.
        dependency_relay_urls.extend(self.rejected_events_index.dependency_relay_hints(
            &event.pubkey,
            &announcement.identifier,
            Some(rejected_index::EventType::State),
        ));
        let (event_ids, hot_events) = self.rejected_events_index.dependency_candidates(
            &event.pubkey,
            &announcement.identifier,
            Some(rejected_index::EventType::State),
        );
        let hot_event_ids: HashSet<EventId> =
            hot_events.iter().map(|candidate| candidate.id).collect();
        dependency_refetch_ids.extend(
            event_ids
                .into_iter()
                .filter(|event_id| !hot_event_ids.contains(event_id)),
        );
        hot_dependency_events.extend(
            hot_events
                .into_iter()
                .map(|candidate| (relay_url.clone(), candidate)),
        );

        let reserved_hot_ids = self.reserve_dependency_refetch_attempts(
            hot_dependency_events
                .iter()
                .map(|(_, candidate)| candidate.id),
        );
        hot_dependency_events.retain(|(_, candidate)| reserved_hot_ids.contains(&candidate.id));

        if !hot_dependency_events.is_empty() {
            Self::process_purgatory_dependency_events(
                hot_dependency_events,
                &announcement.identifier,
                &self.database,
                &self.write_policy,
                &self.local_relay,
                &self.rejected_events_index,
                &self.dependency_refetch_attempts,
            )
            .await;
        }

        if !dependency_refetch_ids.is_empty() {
            let mut canonical_dependency_relays = Vec::new();
            for relay_url in dependency_relay_urls {
                let relay_url = match canonical_relay_key(&relay_url) {
                    Ok(relay_url) => relay_url,
                    Err(error) => {
                        tracing::warn!(
                            relay = %relay_url,
                            error = %error,
                            "Ignoring invalid rejected dependency source relay"
                        );
                        continue;
                    }
                };
                self.dependency_relay_deadlines.insert(
                    relay_url.clone(),
                    Instant::now() + dependency_relay_retention(),
                );
                if !self.connections.contains_key(&relay_url) {
                    if !self.register_relay(relay_url.clone(), false).await {
                        continue;
                    }
                    self.schedule_connect_relay(&relay_url).await;
                }
                canonical_dependency_relays.push(relay_url);
            }

            let connected_dependency_relays: Vec<String> = {
                let relay_index = self.relay_sync_index.read().await;
                canonical_dependency_relays
                    .into_iter()
                    .filter(|relay_url| {
                        relay_index
                            .get(relay_url)
                            .is_some_and(|state| state.connection_status.is_live_sync_active())
                    })
                    .collect()
            };
            self.spawn_purgatory_dependency_refetch(
                &connected_dependency_relays,
                dependency_refetch_ids,
                &announcement.identifier,
            );
        }
    }

    /// Fetch cold-cache dependency IDs without blocking the sync manager.
    ///
    /// Candidate IDs stay in the rejected index until policy processing
    /// succeeds. Failed or empty requests are retried on a bounded cadence, and
    /// all relay requests for one repository run in parallel.
    fn spawn_purgatory_dependency_refetch(
        &self,
        relay_urls: &[String],
        event_ids: HashSet<EventId>,
        identifier: &str,
    ) {
        let connections = connections_for_relay_urls(&self.connections, relay_urls);

        if connections.is_empty() {
            tracing::debug!(
                identifier = %identifier,
                event_count = event_ids.len(),
                "Cannot refetch purgatory dependencies before a relay connection is available"
            );
            return;
        }

        let event_ids: Vec<EventId> = self
            .reserve_dependency_refetch_attempts(event_ids)
            .into_iter()
            .collect();

        if event_ids.is_empty() {
            return;
        }

        let identifier = identifier.to_string();
        let database = self.database.clone();
        let write_policy = self.write_policy.clone();
        let local_relay = self.local_relay.clone();
        let rejected_events_index = self.rejected_events_index.clone();
        let dependency_refetch_attempts = self.dependency_refetch_attempts.clone();

        tokio::spawn(async move {
            let fetches = connections.into_iter().map(|(relay_url, connection)| {
                let filter = Filter::new().ids(event_ids.clone());
                async move {
                    let result = connection
                        .fetch_events(filter, Duration::from_secs(5))
                        .await;
                    (relay_url, result)
                }
            });

            let mut fetched_events = Vec::new();
            for (relay_url, result) in join_all(fetches).await {
                match result {
                    Ok(events) => {
                        tracing::info!(
                            relay = %relay_url,
                            identifier = %identifier,
                            requested_count = event_ids.len(),
                            fetched_count = events.len(),
                            "Fetched purgatory dependencies by exact event ID"
                        );
                        fetched_events.extend(
                            events
                                .into_iter()
                                .map(|candidate| (relay_url.clone(), candidate)),
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            relay = %relay_url,
                            identifier = %identifier,
                            event_count = event_ids.len(),
                            error = %error,
                            "Failed to refetch purgatory dependencies"
                        );
                    }
                }
            }

            Self::process_purgatory_dependency_events(
                fetched_events,
                &identifier,
                &database,
                &write_policy,
                &local_relay,
                &rejected_events_index,
                &dependency_refetch_attempts,
            )
            .await;
        });
    }

    /// Reserve due dependency IDs so timer ticks cannot create retry storms.
    fn reserve_dependency_refetch_attempts(
        &self,
        event_ids: impl IntoIterator<Item = EventId>,
    ) -> HashSet<EventId> {
        let retry_after = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
            Duration::from_secs(6)
        } else {
            Duration::from_secs(30)
        };
        let now = Instant::now();
        let mut attempts = self.dependency_refetch_attempts.lock().unwrap();
        attempts.retain(|_, attempted_at| {
            now.duration_since(*attempted_at) < Duration::from_secs(3600)
        });

        event_ids
            .into_iter()
            .filter(|event_id| {
                let eligible = attempts
                    .get(event_id)
                    .is_none_or(|attempted_at| now.duration_since(*attempted_at) >= retry_after);
                if eligible {
                    attempts.insert(*event_id, now);
                }
                eligible
            })
            .collect()
    }

    /// Apply dependency events in authorization order and clear only successes.
    #[allow(clippy::too_many_arguments)]
    async fn process_purgatory_dependency_events(
        mut events: Vec<(String, Event)>,
        identifier: &str,
        database: &SharedDatabase,
        write_policy: &Nip34WritePolicy,
        local_relay: &LocalRelay,
        rejected_events_index: &Arc<RejectedEventsIndex>,
        dependency_refetch_attempts: &Arc<std::sync::Mutex<HashMap<EventId, Instant>>>,
    ) {
        // Authorization for a state can depend on the reciprocal announcement
        // returned by the same request. Relays may return matches in any order.
        events.sort_by_key(|(_, candidate)| candidate.kind != Kind::GitRepoAnnouncement);

        let mut processed_event_ids = HashSet::new();
        for (relay_url, event) in events {
            if !processed_event_ids.insert(event.id) {
                continue;
            }

            let result = Self::process_event_static(
                &event,
                &relay_url,
                database,
                write_policy,
                local_relay,
                rejected_events_index,
                crate::nostr::persistence::SaveContext::RelaySync,
            )
            .await;

            if result != ProcessResult::Rejected {
                rejected_events_index.remove(&event.id);
                dependency_refetch_attempts
                    .lock()
                    .unwrap()
                    .remove(&event.id);
            }

            if result == ProcessResult::Purgatory && event.kind == Kind::RepoState {
                write_policy.purgatory().enqueue_sync_immediate(identifier);
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
        self.cancel_deferred_consolidation(relay_url, "relay disconnect");

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

            // Drop pending missing-event recovery along with the relay.
            self.missing_event_recovery
                .lock()
                .unwrap()
                .clear_relay(relay_url);

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
                        full_repos_tracked = state.repos.len(),
                        state_only_repos_tracked = state.state_only_repos.len(),
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
            // 1. The caller has observed a newly available dependency
            // 2. Second attempt uses new context (different code path)
            // 3. A failed retry remains indexed for a later bounded attempt
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

                    // Hot-cache retries are sync-originated events. Reset any
                    // existing backoff so newly available announcement/clone
                    // metadata is acted on immediately rather than inheriting
                    // the direct-submission three-minute delay.
                    let identifier = if event.kind == Kind::RepoState {
                        event
                            .tags
                            .iter()
                            .find(|tag| tag.kind() == "d")
                            .and_then(|tag| tag.content())
                            .map(str::to_owned)
                    } else if event.kind == Kind::GitPullRequest
                        || event.kind == Kind::GitPullRequestUpdate
                    {
                        crate::git::sync::extract_identifier_from_pr_event(&event)
                    } else {
                        None
                    };

                    if let Some(identifier) = identifier {
                        write_policy.purgatory().enqueue_sync_immediate(&identifier);
                    }
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

            if reprocess_result != ProcessResult::Rejected {
                rejected_events_index.remove(&event.id);
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
        use nostr_sdk::prelude::{WritePolicy, WritePolicyResult};
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
                                            let (event_ids, hot_events) = rejected_events_index
                                                .dependency_candidates(
                                                    &maintainer_pubkey,
                                                    &announcement.identifier,
                                                    Some(rejected_index::EventType::Announcement),
                                                );

                                            if !event_ids.is_empty() {
                                                tracing::info!(
                                                    maintainer = %maintainer_hex,
                                                    identifier = %announcement.identifier,
                                                    dependency_event_count = event_ids.len(),
                                                    hot_cache_events = hot_events.len(),
                                                    "Found rejected maintainer announcement dependencies"
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
                            let (event_ids, hot_events) = rejected_events_index
                                .dependency_candidates(
                                    &event.pubkey,
                                    &announcement.identifier,
                                    Some(rejected_index::EventType::State),
                                );

                            if !event_ids.is_empty() {
                                tracing::info!(
                                    pubkey = %event.pubkey,
                                    identifier = %announcement.identifier,
                                    dependency_event_count = event_ids.len(),
                                    hot_cache_events = hot_events.len(),
                                    "Found rejected state dependencies after announcement acceptance"
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
                        let (event_ids, hot_events) = rejected_events_index.dependency_candidates(
                            &event.pubkey,
                            identifier,
                            Some(rejected_index::EventType::State),
                        );

                        if !event_ids.is_empty() {
                            tracing::info!(
                                pubkey = %event.pubkey,
                                identifier = %identifier,
                                dependency_event_count = event_ids.len(),
                                hot_cache_events = hot_events.len(),
                                "Found rejected state dependencies after git data became available"
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
                                rejected_events_index.add_state_from_relay(
                                    event.clone(),
                                    event.pubkey,
                                    identifier.to_string(),
                                    reason,
                                    Some(relay_url.to_string()),
                                );
                                tracing::debug!(
                                    event_id = %event.id,
                                    kind = %event.kind.as_u16(),
                                    identifier = %identifier,
                                    "Added rejected state event to two-tier index"
                                );
                            } else {
                                rejected_events_index.add_announcement_from_relay(
                                    event.clone(),
                                    event.pubkey,
                                    identifier.to_string(),
                                    reason,
                                    Some(relay_url.to_string()),
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
                            // No 'd' tag: structurally malformed, permanently
                            // invalid, and without a pubkey+identifier key for
                            // the two-tier index. Remember the exact ID so
                            // historic sync stops re-downloading and
                            // revalidating it. Direct live submissions never
                            // reach this sync-only path; their rejections are
                            // logged by the write policy.
                            rejected_events_index.add_unrecoverable(event.id, event.kind.as_u16());
                            tracing::warn!(
                                event_id = %event.id,
                                kind = %event.kind.as_u16(),
                                relay = %relay_url,
                                "Synced event missing 'd' tag, tracked as unrecoverable by ID"
                            );
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

    async fn has_pending_batches(&self, relay_url: &str) -> bool {
        self.pending_sync_index
            .read()
            .await
            .get(relay_url)
            .is_some_and(|batches| !batches.is_empty())
    }

    async fn desired_live_filter_count(&self, relay_url: &str) -> usize {
        let target = {
            let repo_index = self.repo_sync_index.read().await;
            algorithms::derive_relay_targets(&repo_index).remove(relay_url)
        };
        let desired_repo_filters = target.map_or_else(Vec::new, |target| {
            filters::build_sync_level_aware_filters(
                &target.repos,
                &target.state_only_repos,
                &target.root_events,
                None,
            )
        });

        // Every connected relay carries one consolidated generic announcement
        // subscription in addition to its repository-specific desired filters.
        1 + grouped_subscription_count(&desired_repo_filters)
    }

    /// Check if incremental fragmentation exceeds the consolidation threshold.
    ///
    /// The desired live set is an irreducible baseline, so a repository whose
    /// consolidated filters already exceed 70 must remain stable.
    async fn maybe_consolidate(&mut self, relay_url: &str, new_count: usize) {
        let current_count = if let Some(connection) = self.connections.get(relay_url) {
            connection.subscription_count().await
        } else {
            0
        };
        let desired_baseline = self.desired_live_filter_count(relay_url).await;
        let fragmentation = consolidation_fragmentation(current_count, new_count, desired_baseline);

        if should_consolidate(current_count, new_count, desired_baseline) {
            let has_pending_batches = self.has_pending_batches(relay_url).await;
            if !self
                .deferred_consolidations
                .request(relay_url, has_pending_batches)
            {
                tracing::info!(
                    relay = %relay_url,
                    current_count,
                    new_count,
                    desired_baseline,
                    fragmentation,
                    threshold = CONSOLIDATION_THRESHOLD,
                    "Incremental filter fragmentation exceeds threshold; deferring consolidation until pending batches drain"
                );
                return;
            }

            tracing::info!(
                relay = %relay_url,
                current_count = current_count,
                new_count = new_count,
                desired_baseline,
                fragmentation,
                threshold = CONSOLIDATION_THRESHOLD,
                "Incremental filter fragmentation exceeds threshold, consolidating"
            );

            self.consolidate(relay_url).await;
        }
    }

    async fn process_deferred_consolidation(&mut self, relay_url: &str) {
        let has_pending_batches = self.has_pending_batches(relay_url).await;
        if !self
            .deferred_consolidations
            .take_ready(relay_url, has_pending_batches)
        {
            return;
        }

        tracing::info!(
            relay = %relay_url,
            "Pending batches drained; running deferred consolidation"
        );
        self.consolidate(relay_url).await;
    }

    fn cancel_deferred_consolidation(&mut self, relay_url: &str, reason: &'static str) {
        if self.deferred_consolidations.cancel(relay_url) {
            tracing::debug!(
                relay = %relay_url,
                reason,
                "Cancelled deferred consolidation"
            );
        }
    }

    /// Consolidate all subscriptions for a relay
    ///
    /// The caller must ensure pending batches have drained so EOSE processing
    /// never waits behind the sync actor lock.
    ///
    /// Layer 1 (announcements) remains active and is NOT unsubscribed.
    async fn consolidate(&mut self, relay_url: &str) {
        tracing::info!(
            relay = %relay_url,
            "Starting consolidation"
        );

        // Get connection and unsubscribe all
        let connection = match self.connections.get(relay_url) {
            Some(conn) => conn,
            None => {
                tracing::debug!(
                    relay = %relay_url,
                    "No connection found, skipping consolidation"
                );
                return;
            }
        };

        connection.unsubscribe_all().await;

        // Rebuild all subscriptions with since filter
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
    }

    /// Check for relays that should be disconnected
    ///
    /// This method is called periodically by run_disconnect_checker.
    /// It identifies non-bootstrap relays that have no repos or root events
    /// to sync and disconnects them to free up resources.
    ///
    /// Bootstrap relays are NEVER disconnected, even if empty.
    async fn check_disconnects(&mut self) {
        let now = Instant::now();
        self.dependency_relay_deadlines
            .retain(|_, deadline| *deadline > now);

        let mut desired_relays: HashSet<String> = {
            let repo_index = self.repo_sync_index.read().await;
            algorithms::derive_relay_targets(&repo_index)
                .into_keys()
                .collect()
        };
        desired_relays.extend(self.dependency_relay_deadlines.keys().cloned());

        // Collect relays to disconnect
        let to_disconnect: Vec<String> = {
            let pending = self.pending_sync_index.read().await;
            let index = self.relay_sync_index.read().await;
            index
                .iter()
                .filter_map(|(relay_url, state)| {
                    let has_pending_batches = pending
                        .get(relay_url)
                        .is_some_and(|batches| !batches.is_empty());

                    if state.is_disconnect_candidate(
                        has_pending_batches,
                        desired_relays.contains(relay_url),
                    ) {
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
    /// For each eligible relay, a reconnection is queued via schedule_connect_relay.
    async fn retry_disconnected_relays(&mut self) {
        let desired_relays: HashSet<String> = {
            let repo_index = self.repo_sync_index.read().await;
            algorithms::derive_relay_targets(&repo_index)
                .into_keys()
                .collect()
        };

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

                    // A source can have desired StateOnly invitation work before
                    // its first successful historic batch confirms anything.
                    if state.repos.is_empty()
                        && state.state_only_repos.is_empty()
                        && state.root_events.is_empty()
                        && !desired_relays.contains(relay_url)
                    {
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
            self.schedule_connect_relay(&relay_url).await;
        }
    }

    /// Check for rate-limited relays that have exceeded cooldown
    ///
    /// This method is called by the health and metrics checker every 2 seconds.
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
                        full_repo_count = action.items.repos.len(),
                        state_only_repo_count = action.items.state_only_repos.len(),
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

        for filter_group in group_filters_for_req(&filters) {
            // Live subscriptions MUST use limit(0) to receive ONLY new events
            // This prevents fetching historic events that would be miscounted as "live" in metrics
            // The caller passes the same filters to both sync_live() and historic_sync()
            // Live subscriptions do NOT auto-close - we want them to stay open for new events
            let grouped_filters = filter_group
                .into_iter()
                .map(|filter| filter.limit(0))
                .collect();
            match connection.subscribe_filters(grouped_filters, false).await {
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
            let excluded_ids: HashSet<EventId> =
                purgatory_ids.union(&rejected_ids).cloned().collect();

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
                            "Negentropy diff completed for filter"
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

                tracing::info!(
                    relay = %relay_url,
                    batch_id = batch_id,
                    total_event_ids = all_remote_ids.len(),
                    filter_chunks = ids_filters.len(),
                    "Creating subscriptions to fetch missing events by ID"
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

            // Keep several OR filters under each relay-visible subscription.
            for (idx, filter_group) in group_filters_for_req(&filters_with_since)
                .into_iter()
                .enumerate()
            {
                tracing::debug!(
                    relay = %relay_url,
                    batch_id = batch_id,
                    group_idx = idx,
                    filter_count = filter_group.len(),
                    filters = ?filter_group,
                    "Subscribing to grouped filters in REQ+EOSE path"
                );

                if let Some(conn) = self.connections.get(relay_url) {
                    let grouped_filters = filter_group;
                    match conn.subscribe_filters(grouped_filters.clone(), true).await {
                        Ok(sub_id) => {
                            subscription_ids.insert(sub_id.clone());
                            pagination_state.insert(sub_id, PaginationState::new(grouped_filters));
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
        self.deferred_consolidations.clear();

        tracing::info!("SyncManager shutdown complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_filters_for_req_respects_count_and_byte_budgets() {
        // Many small filters group by the count cap.
        let small: Vec<Filter> = (0..25)
            .map(|i| Filter::new().id(EventId::all_zeros()).limit(i))
            .collect();
        let groups = group_filters_for_req(&small);
        assert_eq!(
            groups.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![MAX_FILTERS_PER_REQ, MAX_FILTERS_PER_REQ, 5]
        );

        // Large filters group by the byte budget instead: every group stays
        // within it (single oversized filters excepted) and below the cap.
        let ids: Vec<EventId> = (0..600u32)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[..4].copy_from_slice(&i.to_be_bytes());
                EventId::from_byte_array(bytes)
            })
            .collect();
        let root_events: std::collections::HashSet<EventId> = ids.into_iter().collect();
        let large = filters::tagged_one_of_our_root_event_filters(&root_events, None);
        assert!(large.len() > 3, "600 IDs should span multiple chunks");

        let groups = group_filters_for_req(&large);
        assert!(groups.len() > 1);
        for group in &groups {
            assert!(group.len() <= MAX_FILTERS_PER_REQ);
            let bytes: usize = group.iter().map(|f| f.as_json().len()).sum();
            assert!(
                group.len() == 1 || bytes <= REQ_MESSAGE_BYTE_BUDGET,
                "group of {} filters serializes to {} bytes",
                group.len(),
                bytes
            );
        }
        // Grouping preserves every filter exactly once.
        assert_eq!(groups.iter().map(Vec::len).sum::<usize>(), large.len());
    }

    #[test]
    fn purgatory_dependency_budget_prioritizes_a_fresh_announcement() {
        let keys = Keys::generate();
        let now = Instant::now();
        let retry_after = Duration::from_secs(30);
        let mut attempts = HashMap::new();
        let mut events = Vec::new();

        for created_at in 1..=1000 {
            let event = EventBuilder::new(Kind::GitRepoAnnouncement, "")
                .tag(Tag::identifier(format!("old-{created_at}")))
                .custom_created_at(Timestamp::from_secs(created_at))
                .finalize(&keys)
                .expect("Failed to create old purgatory announcement");
            attempts.insert(event.id, now);
            events.push(event);
        }

        let fresh = EventBuilder::new(Kind::GitRepoAnnouncement, "")
            .tag(Tag::identifier("fresh"))
            .custom_created_at(Timestamp::from_secs(1001))
            .finalize(&keys)
            .expect("Failed to create fresh purgatory announcement");
        events.push(fresh.clone());

        let selected = select_purgatory_dependency_events(
            events,
            &mut attempts,
            now,
            retry_after,
            MAX_PURGATORY_DEPENDENCY_EVENTS_PER_TICK,
        );

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, fresh.id);
        assert!(
            select_purgatory_dependency_events(
                vec![fresh],
                &mut attempts,
                now,
                retry_after,
                MAX_PURGATORY_DEPENDENCY_EVENTS_PER_TICK,
            )
            .is_empty(),
            "an attempted announcement must wait for its bounded retry deadline"
        );
    }

    #[test]
    fn connect_attempt_tokens_deduplicate_and_reject_stale_results() {
        let relay = "wss://relay.example";
        let mut in_flight = HashMap::new();
        let mut next_token = 0;

        let first = reserve_connect_attempt(&mut in_flight, &mut next_token, relay)
            .expect("first attempt should be reserved");
        assert!(
            reserve_connect_attempt(&mut in_flight, &mut next_token, relay).is_none(),
            "a queued or running relay must not be scheduled twice"
        );
        assert!(
            !take_connect_attempt(&mut in_flight, relay, ConnectAttemptToken(first.0 + 1)),
            "a stale worker result must not consume the active attempt"
        );
        assert_eq!(in_flight.get(relay), Some(&first));
        assert!(take_connect_attempt(&mut in_flight, relay, first));

        let second = reserve_connect_attempt(&mut in_flight, &mut next_token, relay)
            .expect("relay should be schedulable after completion");
        assert_ne!(first, second, "attempt identities must not be reused");
    }

    #[tokio::test]
    async fn connect_attempt_semaphore_caps_parallel_workers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const WORKERS: usize = MAX_CONCURRENT_CONNECT_ATTEMPTS * 3;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECT_ATTEMPTS));
        let release = Arc::new(Semaphore::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut workers = Vec::new();

        for _ in 0..WORKERS {
            let semaphore = Arc::clone(&semaphore);
            let release = Arc::clone(&release);
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let started_tx = started_tx.clone();
            workers.push(tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await.unwrap();
                let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(now_active, Ordering::SeqCst);
                started_tx.send(()).unwrap();
                let _release = release.acquire().await.unwrap();
                active.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        drop(started_tx);

        for _ in 0..MAX_CONCURRENT_CONNECT_ATTEMPTS {
            started_rx.recv().await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(25), started_rx.recv())
                .await
                .is_err(),
            "a ninth worker started while all eight permits were occupied"
        );

        release.add_permits(WORKERS);
        for worker in workers {
            worker.await.unwrap();
        }
        assert_eq!(
            maximum.load(Ordering::SeqCst),
            MAX_CONCURRENT_CONNECT_ATTEMPTS
        );
    }

    #[tokio::test]
    async fn queued_connect_attempt_records_health_only_when_worker_starts() {
        let relay = "wss://queued.example";
        let semaphore = Arc::new(Semaphore::new(0));
        let health_tracker = Arc::new(RelayHealthTracker::with_defaults());
        let worker_semaphore = Arc::clone(&semaphore);
        let worker_health = Arc::clone(&health_tracker);

        let worker = tokio::spawn(async move {
            begin_connect_attempt(worker_semaphore, worker_health, relay).await
        });
        tokio::task::yield_now().await;
        assert!(
            health_tracker.get_health(relay).is_none(),
            "waiting for scheduler capacity must not start backoff"
        );

        semaphore.add_permits(1);
        let _permit = worker
            .await
            .unwrap()
            .expect("worker should start after a permit becomes available");
        assert!(
            health_tracker
                .get_health(relay)
                .is_some_and(|health| health.last_attempt_time.is_some()),
            "health attempt time must be recorded when the worker starts"
        );
    }

    #[test]
    fn canonical_relay_keys_dedupe_only_the_root_slash() {
        assert_eq!(
            canonical_relay_key("wss://relay.example").unwrap(),
            "wss://relay.example"
        );
        assert_eq!(
            canonical_relay_key("wss://relay.example/").unwrap(),
            "wss://relay.example"
        );
        assert_eq!(
            canonical_relay_key("wss://relay.example/nostr/").unwrap(),
            "wss://relay.example/nostr/"
        );
        assert_eq!(
            canonical_relay_key("relay.example/").unwrap(),
            "wss://relay.example"
        );
    }

    #[test]
    fn connection_lookup_deduplicates_relay_url_variants() {
        let canonical = canonical_relay_key("wss://relay.example").unwrap();
        let connections = HashMap::from([(canonical.clone(), 7_u8)]);
        let candidates = vec![
            "wss://relay.example".to_string(),
            "wss://relay.example/".to_string(),
        ];

        assert_eq!(
            connections_for_relay_urls(&connections, &candidates),
            vec![(canonical, 7)]
        );
    }

    #[test]
    fn desired_baseline_above_threshold_does_not_reconsolidate() {
        let desired_baseline = 178;

        assert!(
            !should_consolidate(desired_baseline, 1, desired_baseline),
            "the irreducible desired set must be a stable post-rebuild baseline"
        );
        assert!(
            !should_consolidate(
                desired_baseline + CONSOLIDATION_THRESHOLD - 1,
                1,
                desired_baseline,
            ),
            "the configured fragmentation headroom is allowed above the baseline"
        );
        assert!(should_consolidate(
            desired_baseline + CONSOLIDATION_THRESHOLD,
            1,
            desired_baseline,
        ));
    }

    #[test]
    fn grouped_pagination_advances_only_filters_that_fill_a_page() {
        let keys = Keys::generate();
        let metadata_filter = Filter::new().kind(Kind::Metadata);
        let note_filter = Filter::new().kind(Kind::TextNote);
        let mut pagination =
            PaginationState::new(vec![metadata_filter.clone(), note_filter.clone()]);

        for created_at in 1..=PAGINATION_THRESHOLD {
            let event = EventBuilder::new(Kind::Metadata, created_at.to_string())
                .custom_created_at(Timestamp::from_secs(created_at as u64))
                .finalize(&keys)
                .expect("build metadata event");
            pagination.record_event(&event);
        }
        let note = EventBuilder::new(Kind::TextNote, "one note")
            .custom_created_at(Timestamp::from_secs(100))
            .finalize(&keys)
            .expect("build text note");
        pagination.record_event(&note);

        let next_filters = pagination.next_page_filters();
        assert_eq!(next_filters.len(), 1);
        assert_eq!(next_filters[0].until, Some(Timestamp::from_secs(1)));
        assert!(
            next_filters[0]
                .kinds
                .as_ref()
                .unwrap()
                .contains(&Kind::Metadata),
            "the full metadata filter should advance"
        );
        assert!(
            !next_filters[0]
                .kinds
                .as_ref()
                .unwrap()
                .contains(&Kind::TextNote),
            "the partial text-note filter should not advance"
        );
    }

    #[test]
    fn deferred_consolidation_runs_only_after_final_batch_completion() {
        let relay_url = "wss://relay.example";
        let mut deferred = DeferredConsolidations::default();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

        assert!(
            !deferred.request(relay_url, true),
            "an in-flight batch must defer instead of waiting in the sync actor"
        );
        notify_deferred_consolidation_after_batch_completion(&deferred, Some(&sender), relay_url);
        assert_eq!(
            receiver.try_recv().unwrap(),
            relay_url,
            "batch completion must wake the actor without awaiting under its lock"
        );
        assert!(
            !deferred.take_ready(relay_url, true),
            "consolidation must remain queued while another batch is pending"
        );

        notify_deferred_consolidation_after_batch_completion(&deferred, Some(&sender), relay_url);
        assert_eq!(receiver.try_recv().unwrap(), relay_url);
        assert!(
            deferred.take_ready(relay_url, false),
            "the final batch completion must make consolidation runnable"
        );
        assert!(
            !deferred.take_ready(relay_url, false),
            "taking deferred work must be idempotent"
        );
    }

    #[test]
    fn reset_or_disconnect_cancels_deferred_consolidation_and_stale_wakeup() {
        for reason in ["reset", "disconnect"] {
            let relay_url = format!("wss://{reason}.example");
            let mut deferred = DeferredConsolidations::default();
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

            assert!(!deferred.request(&relay_url, true));
            notify_deferred_consolidation_after_batch_completion(
                &deferred,
                Some(&sender),
                &relay_url,
            );
            assert!(deferred.cancel(&relay_url));
            assert_eq!(receiver.try_recv().unwrap(), relay_url);
            assert!(
                !deferred.take_ready(&relay_url, false),
                "a queued wakeup must not resurrect consolidation after {reason}"
            );
        }
    }

    #[test]
    fn failed_pagination_completes_only_a_fully_drained_batch() {
        let relay_url = "wss://pagination.example";
        let still_pending = SubscriptionId::new("still-pending");
        let make_batch = |batch_id, outstanding_subs| PendingBatch {
            batch_id,
            items: PendingItems::default(),
            outstanding_subs,
            sync_method: SyncMethod::ReqEose,
            pagination_state: HashMap::new(),
            requested_event_ids: None,
            received_event_ids: None,
            retry_count: 0,
            failed: false,
        };
        let mut pending = HashMap::from([(
            relay_url.to_string(),
            vec![
                make_batch(41, HashSet::new()),
                make_batch(42, HashSet::from([still_pending])),
            ],
        )]);

        let completed = take_drained_batch_as_failed(&mut pending, relay_url, 41)
            .expect("failed pagination must complete a drained batch");
        assert!(completed.failed);
        assert!(take_drained_batch_as_failed(&mut pending, relay_url, 42).is_none());
        assert_eq!(pending[relay_url].len(), 1);
        assert!(!pending[relay_url][0].failed);
    }

    #[test]
    fn rate_limited_pagination_keeps_batch_pending_without_actor_wait() {
        let relay_url = "wss://pagination.example";
        let completed_sub = SubscriptionId::new("completed-page");
        let mut batch = PendingBatch {
            batch_id: 73,
            items: PendingItems::default(),
            outstanding_subs: HashSet::new(),
            sync_method: SyncMethod::ReqEose,
            pagination_state: HashMap::new(),
            requested_event_ids: None,
            received_event_ids: None,
            retry_count: 0,
            failed: false,
        };

        let deferred = mark_deferred_pagination(&mut batch, &completed_sub);
        assert!(batch.outstanding_subs.contains(&deferred));

        let mut pending = HashMap::from([(relay_url.to_string(), vec![batch])]);
        assert!(
            take_drained_batch_as_failed(&mut pending, relay_url, 73).is_none(),
            "the deferred exact page must prevent a generic historic batch from being confirmed early"
        );
    }

    #[test]
    fn relay_disconnect_waits_for_pending_and_historic_sync_work() {
        let mut source = RelayState {
            connection_status: ConnectionStatus::Syncing,
            ..RelayState::default()
        };

        assert!(
            !source.is_disconnect_candidate(true, false),
            "a source with missing-ID subscriptions in flight must stay connected"
        );
        assert!(
            !source.is_disconnect_candidate(false, false),
            "the historic-sync batch window must stay connected even between batches"
        );

        source.connection_status = ConnectionStatus::Connected;
        assert!(
            !source.is_disconnect_candidate(false, false),
            "an active relay cannot be disconnected before historic sync settles"
        );

        source.historic_sync_completed = true;
        assert!(
            source.is_disconnect_candidate(false, false),
            "an empty relay can be released after historic sync settles"
        );
        assert!(
            !source.is_disconnect_candidate(true, false),
            "a later pending batch still keeps an otherwise empty relay connected"
        );
        assert!(
            !source.is_disconnect_candidate(false, true),
            "unconfirmed desired invitation work keeps its source connected"
        );

        source
            .repos
            .insert("30617:maintainer:repository".to_string());
        assert!(
            !source.is_disconnect_candidate(false, false),
            "confirmed repository work keeps the source connected"
        );
    }

    #[test]
    fn disconnected_empty_relay_can_still_be_cleaned_up() {
        let mut source = RelayState::default();

        assert!(source.is_disconnect_candidate(false, false));
        assert!(!source.is_disconnect_candidate(false, true));

        source.historic_sync_completed = true;
        source.connection_status = ConnectionStatus::Connecting;
        assert!(
            !source.is_disconnect_candidate(false, false),
            "cleanup must not race an in-flight connection worker"
        );
    }

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

    #[tokio::test]
    async fn test_missing_d_tag_event_excluded_from_refetch_after_rejection() {
        let purgatory_ids: HashSet<EventId> = HashSet::new();
        let rejected_index =
            RejectedEventsIndex::new(Duration::from_secs(120), Duration::from_secs(604800));

        // Announcement without a 'd' tag: structurally malformed, no
        // repository identifier exists to key the two-tier index with
        let keys = Keys::generate();
        let malformed = EventBuilder::new(Kind::GitRepoAnnouncement, "no d tag")
            .finalize(&keys)
            .unwrap();
        assert!(!malformed.tags.iter().any(|t| t.kind() == "d"));

        // Rejection path tracks it by exact ID
        rejected_index.add_unrecoverable(malformed.id, malformed.kind.as_u16());

        // Live/REQ path consults contains() before processing
        assert!(rejected_index.contains(&malformed.id));

        // Historic negentropy path excludes it from re-download
        let rejected_ids = rejected_index.get_all_event_ids();
        let excluded_ids: HashSet<EventId> = purgatory_ids.union(&rejected_ids).cloned().collect();
        assert!(excluded_ids.contains(&malformed.id));
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
}
