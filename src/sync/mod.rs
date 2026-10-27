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
pub mod discovery;
pub mod filters;
mod grasp_p_sync;
pub mod health;
mod history;
pub mod in_process_transport;
pub mod metrics;
pub mod missing_events;
pub mod naughty_list;
pub mod private_index;
pub mod rejected_index;
pub mod relay_connection;
pub mod self_subscriber;
pub mod target_hygiene;

// Re-export core algorithm types
pub use algorithms::{AddFilters, RelaySyncNeeds};

// Re-export metrics types
pub use metrics::SyncMetrics;

// Re-export rejected index types
pub use rejected_index::{EventType, RejectionReason};

// Re-export relay connection types
pub use relay_connection::{
    NegentropySyncResult, RelayConnection, RelayEvent, TransientRequestClass,
};

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
use crate::private::PrivateAccess;
use nostr_sdk::prelude::LocalRelay;

const MAX_PURGATORY_DEPENDENCY_EVENTS_PER_TICK: usize = 32;
const MAX_PURGATORY_FILTER_ACTIONS_PER_TICK: usize = 1;
const MAX_PURGATORY_DEPENDENCY_IDS_PER_QUERY: usize = 100;
const SEMANTIC_FALLBACK_MIN_REQUESTED_EVENTS: usize = 20;
const SEMANTIC_FALLBACK_MAX_DELIVERED_PERCENT: usize = 10;
const DESCENDANT_FALLBACK_OVERLAP_SECS: u64 = 15 * 60;
fn descendant_fallback_refresh_interval() -> Duration {
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(60)
    }
}
/// Maximum number of locally known parent/child generations expanded into a
/// relay's related-event query frontier.
const MAX_DESCENDANT_FRONTIER_DEPTH: usize = 8;

fn mailbox_probe_refresh_interval() -> Duration {
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(24 * 60 * 60)
    }
}

fn mailbox_probe_retry_interval() -> Duration {
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_millis(500)
    } else {
        Duration::from_secs(5 * 60)
    }
}

fn due_mailbox_relays(
    mailbox_roots: &HashMap<String, HashSet<EventId>>,
    mailbox_repositories: &HashMap<String, HashSet<String>>,
    next_at: &HashMap<String, Instant>,
    now: Instant,
) -> Vec<String> {
    let mut relays: HashSet<String> = mailbox_roots
        .keys()
        .chain(mailbox_repositories.keys())
        .cloned()
        .collect();
    relays.retain(|relay| next_at.get(relay).is_none_or(|due| *due <= now));
    let mut relays: Vec<String> = relays.into_iter().collect();
    relays.sort_by(|left, right| {
        let workload = |relay: &String| {
            mailbox_roots.get(relay).map_or(0, HashSet::len)
                + mailbox_repositories.get(relay).map_or(0, HashSet::len)
        };
        next_at
            .get(left)
            .copied()
            .unwrap_or(now)
            .cmp(&next_at.get(right).copied().unwrap_or(now))
            .then_with(|| workload(right).cmp(&workload(left)))
            .then_with(|| left.cmp(right))
    });
    relays
}

fn mailbox_probe_connection_ready(
    connection_status: Option<ConnectionStatus>,
    socket_connected: bool,
) -> bool {
    socket_connected && connection_status.is_some_and(|status| status.is_live_sync_active())
}

fn select_due_mailbox_relay(
    due_relays: &[String],
    active_relays: &HashSet<String>,
) -> Option<String> {
    due_relays
        .iter()
        .find(|relay| active_relays.contains(*relay))
        .or_else(|| due_relays.first())
        .cloned()
}

fn public_repository_mailbox_scope(
    private_mode: bool,
    author_repositories: HashMap<PublicKey, HashSet<String>>,
) -> HashMap<PublicKey, HashSet<String>> {
    if private_mode {
        HashMap::new()
    } else {
        author_repositories
    }
}

fn mailbox_probe_completion(
    filter_index: usize,
    filter_count: usize,
    succeeded: bool,
) -> (usize, bool, Duration) {
    let next_filter = (filter_index + 1) % filter_count.max(1);
    let completed_cycle = next_filter == 0;
    let next_probe_in = if succeeded && completed_cycle {
        mailbox_probe_refresh_interval()
    } else if succeeded {
        Duration::ZERO
    } else {
        mailbox_probe_retry_interval()
    };
    (next_filter, completed_cycle, next_probe_in)
}

fn should_continue_mailbox_probe(succeeded: bool, completed_cycle: bool) -> bool {
    succeeded && !completed_cycle
}

fn mailbox_worker_capacity_available(active_workers: usize) -> bool {
    active_workers < MAX_CONCURRENT_MAILBOX_WORKERS
}

async fn fetch_mailbox_filter(
    connection: RelayConnection,
    filter: Filter,
) -> Result<Vec<Event>, String> {
    let mut pagination = PaginationState::new(vec![filter]);
    let mut session = RelayPaginationSession::default();
    let mut events = HashMap::<EventId, Event>::new();

    loop {
        let filter = pagination
            .filters()
            .into_iter()
            .next()
            .expect("mailbox pagination always owns one filter");
        let page = connection
            .fetch_events(filter, Duration::from_secs(30))
            .await?;
        let previous_count = events.len();
        for event in page {
            pagination.record_event(&event);
            events.insert(event.id, event);
        }
        // Inclusive `until` cursors can repeat a relay's oldest timestamp.
        // Stop when a page contributes nothing instead of retaining the only
        // mailbox worker forever on a deterministic repeated page.
        if events.len() == previous_count {
            break;
        }
        let Some(next) = pagination.next_page(&mut session) else {
            break;
        };
        pagination = next;
    }

    let mut events: Vec<_> = events.into_values().collect();
    events.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(events)
}

fn should_use_semantic_fallback(requested_count: usize, received_count: usize) -> bool {
    requested_count >= SEMANTIC_FALLBACK_MIN_REQUESTED_EVENTS
        && received_count.saturating_mul(100)
            <= requested_count.saturating_mul(SEMANTIC_FALLBACK_MAX_DELIVERED_PERCENT)
}

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

fn effective_private_members(
    configured: &HashSet<PublicKey>,
    accepted_relays: &HashSet<String>,
    relay_owners: &HashMap<String, PublicKey>,
) -> HashSet<PublicKey> {
    configured
        .iter()
        .copied()
        .chain(
            relay_owners
                .iter()
                .filter_map(|(relay, owner)| accepted_relays.contains(relay).then_some(*owner)),
        )
        .collect()
}

fn byte_limited_catchup_interval() -> Duration {
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(5 * 60)
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

#[derive(Default)]
struct DependencyRelayBatch {
    event_ids: HashSet<EventId>,
    identifiers: HashSet<String>,
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

fn is_own_sync_target(relay_url: &str, service_domain: &str) -> bool {
    crate::outbound::relay_url_matches_service(relay_url, service_domain)
}

#[cfg(test)]
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

/// Compact metadata for roots observed by the self-subscription. Candidates
/// remain inert while their repository is StateOnly and become eligible for
/// NIP-65 discovery as soon as RepoSyncIndex promotes it to Full.
pub type RootCandidateIndex = Arc<RwLock<HashMap<EventId, discovery::AcceptedRoot>>>;

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

fn reconcile_purgatory_relay_ownership(
    index: &mut HashMap<String, RepoSyncNeeds>,
    announcements: &[(String, HashSet<String>)],
) -> HashSet<String> {
    let active: HashMap<&str, &HashSet<String>> = announcements
        .iter()
        .map(|(repo_id, relays)| (repo_id.as_str(), relays))
        .collect();
    let mut dirty_relays = HashSet::new();

    index.retain(|repo_id, needs| {
        if needs.sync_level == SyncLevel::Full {
            return true;
        }
        if active.contains_key(repo_id.as_str()) {
            return true;
        }
        dirty_relays.extend(needs.relays.iter().cloned());
        false
    });

    for (repo_id, relays) in announcements {
        let entry = index
            .entry(repo_id.clone())
            .or_insert_with(|| RepoSyncNeeds {
                relays: HashSet::new(),
                root_events: HashSet::new(),
                sync_level: SyncLevel::StateOnly,
            });
        if entry.sync_level == SyncLevel::StateOnly && entry.relays != *relays {
            dirty_relays.extend(entry.relays.iter().cloned());
            dirty_relays.extend(relays.iter().cloned());
            entry.relays = relays.clone();
        }
    }

    dirty_relays
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
    /// Event already existed or a newer replaceable event was retained
    Duplicate,
    /// Event added to Purgatory
    Purgatory,
    /// Event is absent by a valid persisted deletion or vanish request.
    Tombstoned,
    /// Event rejected by write policy.
    Rejected(PolicyRejection),
    /// The database could not be read or an accepted event could not be saved.
    PersistenceError,
}

/// Bounded admission-rejection classes used by hydration accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRejection {
    Blocked,
    Invalid,
    Restricted,
    Error,
    Other,
    PreviouslyRejected,
}

impl ProcessResult {
    fn hydration_outcome(self) -> &'static str {
        match self {
            Self::Saved => "saved",
            Self::Duplicate => "duplicate",
            Self::Purgatory => "purgatory",
            Self::Tombstoned => "tombstoned",
            Self::Rejected(PolicyRejection::Blocked) => "rejected_blocked",
            Self::Rejected(PolicyRejection::Invalid) => "rejected_invalid",
            Self::Rejected(PolicyRejection::Restricted) => "rejected_restricted",
            Self::Rejected(PolicyRejection::Error) => "rejected_error",
            Self::Rejected(PolicyRejection::Other) => "rejected_other",
            Self::Rejected(PolicyRejection::PreviouslyRejected) => "rejected_cached",
            Self::PersistenceError => "persistence_error",
        }
    }

    fn is_rejected(self) -> bool {
        matches!(self, Self::Rejected(_))
    }

    /// Whether transport recovery is finished, independently of local authorization.
    /// Retained dependencies can be revived by announcement changes; fetching the
    /// same immutable payload again cannot resolve their missing authority.
    fn is_hydration_accounted(
        self,
        event_id: &EventId,
        rejected_events_index: &RejectedEventsIndex,
    ) -> bool {
        self.is_terminally_accounted()
            || (self == Self::Rejected(PolicyRejection::Restricted)
                && rejected_events_index.is_dependency_pending(event_id))
    }

    /// Whether this result gives a durable explanation for the requested ID.
    ///
    /// This controls dependency-cache removal, not transport completion.
    /// Restricted, server-error, and unknown policy failures can become valid
    /// after dependencies arrive or a transient fault clears, so dependency
    /// reprocessing keeps them pending. Invalid/blocked results are permanent for
    /// the event, while purgatory and tombstones are explicit terminal states.
    fn is_terminally_accounted(self) -> bool {
        matches!(
            self,
            Self::Saved
                | Self::Duplicate
                | Self::Purgatory
                | Self::Tombstoned
                | Self::Rejected(PolicyRejection::Blocked)
                | Self::Rejected(PolicyRejection::Invalid)
                | Self::Rejected(PolicyRejection::PreviouslyRejected)
        )
    }
}

/// A low-volume summary of the per-relay data lane.
///
/// Sync bursts can contain tens of thousands of duplicates, so per-event logs
/// obscure whether time is spent waiting for the bounded channel or applying
/// policy. A periodic aggregate keeps production diagnosis cheap enough to
/// leave enabled while preserving both parts of that distinction.
#[derive(Debug)]
struct EventPipelineWindow {
    started_at: std::time::Instant,
    delivered: u64,
    saved: u64,
    duplicate: u64,
    purgatory: u64,
    tombstoned: u64,
    rejected: u64,
    persistence_error: u64,
    queue_delay: std::time::Duration,
    max_queue_delay: std::time::Duration,
    processing_time: std::time::Duration,
    max_processing_time: std::time::Duration,
}

impl Default for EventPipelineWindow {
    fn default() -> Self {
        Self {
            started_at: std::time::Instant::now(),
            delivered: 0,
            saved: 0,
            duplicate: 0,
            purgatory: 0,
            tombstoned: 0,
            rejected: 0,
            persistence_error: 0,
            queue_delay: std::time::Duration::ZERO,
            max_queue_delay: std::time::Duration::ZERO,
            processing_time: std::time::Duration::ZERO,
            max_processing_time: std::time::Duration::ZERO,
        }
    }
}

impl EventPipelineWindow {
    const REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

    fn record(
        &mut self,
        result: ProcessResult,
        queue_delay: std::time::Duration,
        processing_time: std::time::Duration,
    ) {
        self.delivered += 1;
        match result {
            ProcessResult::Saved => self.saved += 1,
            ProcessResult::Duplicate => self.duplicate += 1,
            ProcessResult::Purgatory => self.purgatory += 1,
            ProcessResult::Tombstoned => self.tombstoned += 1,
            ProcessResult::Rejected(_) => self.rejected += 1,
            ProcessResult::PersistenceError => self.persistence_error += 1,
        }
        self.queue_delay += queue_delay;
        self.max_queue_delay = self.max_queue_delay.max(queue_delay);
        self.processing_time += processing_time;
        self.max_processing_time = self.max_processing_time.max(processing_time);
    }

    fn report_if_due(&mut self, relay: &str, queue_depth: usize) {
        let elapsed = self.started_at.elapsed();
        if elapsed < Self::REPORT_INTERVAL || self.delivered == 0 {
            return;
        }

        let delivered = self.delivered as f64;
        tracing::info!(
            relay,
            window_seconds = elapsed.as_secs_f64(),
            delivered = self.delivered,
            saved = self.saved,
            duplicate = self.duplicate,
            purgatory = self.purgatory,
            tombstoned = self.tombstoned,
            rejected = self.rejected,
            persistence_error = self.persistence_error,
            events_per_second = delivered / elapsed.as_secs_f64(),
            average_queue_delay_ms = self.queue_delay.as_secs_f64() * 1000.0 / delivered,
            max_queue_delay_ms = self.max_queue_delay.as_secs_f64() * 1000.0,
            average_processing_ms = self.processing_time.as_secs_f64() * 1000.0 / delivered,
            max_processing_ms = self.max_processing_time.as_secs_f64() * 1000.0,
            queue_depth,
            queue_capacity = relay_connection::RELAY_EVENT_BUFFER_CAPACITY,
            "Relay sync event-pipeline window"
        );
        *self = Self::default();
    }
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
    /// IDs delivered on this page, retained only long enough to verify a NIP-11 hint.
    page_event_ids: HashSet<EventId>,
    /// IDs from the page which caused a one-page NIP-11 hint verification.
    verification_baseline: Option<HashSet<EventId>>,
    /// Whether the verification page delivered an ID absent from its triggering page.
    verification_productive: bool,
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
                    page_event_ids: HashSet::new(),
                    verification_baseline: None,
                    verification_productive: false,
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
                state.page_event_ids.insert(event.id);
                if state
                    .verification_baseline
                    .as_ref()
                    .is_some_and(|baseline| !baseline.contains(&event.id))
                {
                    state.verification_productive = true;
                }
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

    fn filters(&self) -> Vec<Filter> {
        self.filters
            .iter()
            .map(|state| state.original_filter.clone())
            .collect()
    }

    fn request_class(&self) -> TransientRequestClass {
        if self
            .filters
            .iter()
            .any(|state| state.verification_baseline.is_some())
        {
            TransientRequestClass::PaginationVerification
        } else {
            TransientRequestClass::PaginationPage
        }
    }

    fn next_page(mut self, session: &mut RelayPaginationSession) -> Option<Self> {
        let mut next = Vec::new();
        for mut state in self.filters.drain(..) {
            session.observe_page(state.event_count);
            let completed_verification = state.verification_baseline.is_some();

            let continue_page = if completed_verification {
                session.complete_hint_verification(state.verification_productive);
                state.verification_productive && state.event_count >= session.pagination_threshold()
            } else if state.event_count >= session.pagination_threshold() {
                true
            } else if state.event_count >= PAGINATION_THRESHOLD_FLOOR
                && (session.begin_hint_verification() || session.hint_verification_in_progress())
            {
                state.verification_baseline = Some(std::mem::take(&mut state.page_event_ids));
                true
            } else {
                false
            };
            if completed_verification {
                state.verification_baseline = None;
            }

            let Some(min_created_at) = continue_page.then_some(state.min_created_at).flatten()
            else {
                continue;
            };
            state.original_filter = state
                .original_filter
                .until(Timestamp::from(min_created_at.as_secs()));
            state.event_count = 0;
            state.min_created_at = None;
            state.page_event_ids.clear();
            state.verification_productive = false;
            next.push(state);
        }
        (!next.is_empty()).then_some(Self { filters: next })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaginationHint {
    Absent,
    Unverified(usize),
    Verifying(usize),
    Verified(usize),
    Discarded,
}

#[derive(Debug, Clone)]
struct RelayPaginationSession {
    largest_raw_page: usize,
    hint: PaginationHint,
}

impl Default for RelayPaginationSession {
    fn default() -> Self {
        Self::new(None)
    }
}

impl RelayPaginationSession {
    fn new(advertised_default_limit: Option<usize>) -> Self {
        Self {
            largest_raw_page: 0,
            hint: advertised_default_limit
                .map(PaginationHint::Unverified)
                .unwrap_or(PaginationHint::Absent),
        }
    }

    fn observe_page(&mut self, raw_count: usize) {
        self.largest_raw_page = self.largest_raw_page.max(raw_count);
    }

    fn active_hint(&self) -> Option<usize> {
        match self.hint {
            PaginationHint::Unverified(limit) | PaginationHint::Verified(limit) => Some(limit),
            PaginationHint::Absent | PaginationHint::Verifying(_) | PaginationHint::Discarded => {
                None
            }
        }
    }

    fn estimated_cap(&self) -> usize {
        self.largest_raw_page.max(self.active_hint().unwrap_or(0))
    }

    fn pagination_threshold(&self) -> usize {
        // Ten percent slack absorbs relay-side shrinkage such as expired-event filtering.
        // The floor remains below Ditto's observed 100-event omitted-limit page, the smallest
        // live default found in the relay audit. These are interoperability constants, not
        // operator policy, so deliberately do not enlarge the four-source config surface.
        PAGINATION_THRESHOLD_FLOOR.max(
            self.estimated_cap()
                .saturating_mul(PAGINATION_THRESHOLD_PERCENT)
                / 100,
        )
    }

    fn begin_hint_verification(&mut self) -> bool {
        match self.hint {
            PaginationHint::Unverified(limit) => {
                self.hint = PaginationHint::Verifying(limit);
                true
            }
            _ => false,
        }
    }

    fn hint_verification_in_progress(&self) -> bool {
        matches!(self.hint, PaginationHint::Verifying(_))
    }

    fn complete_hint_verification(&mut self, productive: bool) {
        match (self.hint, productive) {
            (PaginationHint::Verifying(_) | PaginationHint::Verified(_), true) => {
                // Several filters can share the grouped verification page. Any one of them
                // finding an unseen event disproves the relay-wide hint, even if an earlier
                // exhausted filter provisionally marked it verified.
                self.hint = PaginationHint::Discarded;
            }
            (PaginationHint::Verifying(limit), false) => {
                self.hint = PaginationHint::Verified(limit);
            }
            _ => {}
        }
    }
}

/// A batch of items pending confirmation
#[derive(Debug, Clone)]
pub struct PendingBatch {
    /// Unique ID for this batch - for debugging/logging
    pub batch_id: u64,
    /// Why this batch exists. Auxiliary descendant discovery must not mutate
    /// core historic-sync completion or health state.
    pub purpose: PendingBatchPurpose,
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
    /// First-pass advertised and delivered counts, retained while retrying a residual.
    pub initial_hydration_counts: Option<(usize, usize)>,
    /// Number of retry attempts for missing events (Negentropy only)
    /// Used to prevent infinite retry loops when relay consistently fails
    pub retry_count: usize,
    /// Whether this batch failed (completed with missing data)
    /// Set to true when retry protection triggers or other failures occur
    pub failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingBatchPurpose {
    Core,
    Announcements,
    Descendants,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DescendantFrontier {
    event_ids: HashSet<EventId>,
    coordinates: HashSet<String>,
    /// Accepted participant authors and the exact repository roots reached by
    /// their retained direct or recursive events.
    author_roots: HashMap<PublicKey, HashSet<EventId>>,
}

#[derive(Debug, Default)]
struct DescendantSyncRotation {
    coverage_fingerprint: Vec<String>,
    filters: Vec<DescendantFilterCursor>,
    next_filter: usize,
    in_flight: Option<DescendantFilterInFlight>,
    next_cycle_at: Option<Instant>,
}

#[derive(Debug)]
struct DescendantFilterCursor {
    filters: Vec<Filter>,
    last_successful_until: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy)]
struct DescendantFilterInFlight {
    batch_id: u64,
    filter_index: usize,
    until: Timestamp,
}

#[derive(Debug)]
struct DescendantLiveCoverage {
    desired_filters: HashSet<String>,
    fallback_filters: Vec<Filter>,
    subscription_ids: Vec<SubscriptionId>,
}

fn filter_group_fingerprint(filters: &[Filter]) -> String {
    filters
        .iter()
        .map(Filter::as_json)
        .collect::<Vec<_>>()
        .join("\n")
}

fn rotation_fingerprint(filters: &[Filter], max_filters_per_req: usize) -> Vec<String> {
    group_filters_for_req_with_max(filters, max_filters_per_req)
        .iter()
        .map(|group| filter_group_fingerprint(group))
        .collect()
}

impl DescendantSyncRotation {
    fn refresh(&mut self, filters: Vec<Filter>, max_filters_per_req: usize) {
        let previous: HashMap<String, Option<Timestamp>> = self
            .filters
            .drain(..)
            .map(|cursor| {
                (
                    filter_group_fingerprint(&cursor.filters),
                    cursor.last_successful_until,
                )
            })
            .collect();
        self.filters = group_filters_for_req_with_max(&filters, max_filters_per_req)
            .into_iter()
            .map(|filters| DescendantFilterCursor {
                last_successful_until: previous
                    .get(&filter_group_fingerprint(&filters))
                    .copied()
                    .flatten(),
                filters,
            })
            .collect();
        self.coverage_fingerprint = self
            .filters
            .iter()
            .map(|cursor| filter_group_fingerprint(&cursor.filters))
            .collect();
        self.next_filter = 0;
        self.in_flight = None;
        // A changed frontier needs a baseline immediately. Retained groups
        // still keep their successful overlap cursor above.
        self.next_cycle_at = None;
    }

    fn next_request(
        &self,
        now: Timestamp,
        monotonic_now: Instant,
    ) -> Option<(usize, Vec<Filter>, Timestamp)> {
        if self.in_flight.is_some()
            || self.filters.is_empty()
            || self
                .next_cycle_at
                .is_some_and(|deadline| monotonic_now < deadline)
        {
            return None;
        }
        let filter_index = self.next_filter % self.filters.len();
        let cursor = &self.filters[filter_index];
        let filters = cursor
            .filters
            .iter()
            .cloned()
            .map(|filter| {
                let filter = filter.until(now);
                match cursor.last_successful_until {
                    Some(last_until) => filter.since(Timestamp::from(
                        last_until
                            .as_secs()
                            .saturating_sub(DESCENDANT_FALLBACK_OVERLAP_SECS),
                    )),
                    None => filter,
                }
            })
            .collect();
        Some((filter_index, filters, now))
    }

    fn mark_started(&mut self, batch_id: u64, filter_index: usize, until: Timestamp) {
        self.in_flight = Some(DescendantFilterInFlight {
            batch_id,
            filter_index,
            until,
        });
    }

    fn mark_completed(&mut self, batch_id: u64, succeeded: bool, now: Instant) -> bool {
        let Some(in_flight) = self
            .in_flight
            .filter(|request| request.batch_id == batch_id)
        else {
            return false;
        };
        self.in_flight = None;
        if succeeded {
            self.filters[in_flight.filter_index].last_successful_until = Some(in_flight.until);
            self.next_filter = (in_flight.filter_index + 1) % self.filters.len();
        }
        if !succeeded || self.next_filter == 0 {
            self.next_cycle_at = Some(now + descendant_fallback_refresh_interval());
        }
        true
    }
}

fn descendant_event_coordinate(event: &Event) -> Option<String> {
    if !(event.kind.is_replaceable() || event.kind.is_addressable()) {
        return None;
    }
    let identifier = if event.kind.is_addressable() {
        event
            .tags
            .iter()
            .find(|tag| tag.kind() == "d")
            .and_then(|tag| tag.content())?
    } else {
        ""
    };
    Some(format!(
        "{}:{}:{}",
        event.kind.as_u16(),
        event.pubkey.to_hex(),
        identifier
    ))
}

fn descendant_reference_roots(
    event: &Event,
    root_events: &HashSet<EventId>,
    event_root_owners: &HashMap<EventId, HashSet<EventId>>,
    coordinate_root_owners: &HashMap<String, HashSet<EventId>>,
) -> HashSet<EventId> {
    let (coordinates, event_ids) =
        crate::nostr::policy::RelatedEventPolicy::extract_reference_tags(event);
    let mut roots: HashSet<EventId> = event_ids
        .iter()
        .filter(|event_id| root_events.contains(event_id))
        .copied()
        .collect();
    for event_id in event_ids {
        if let Some(owners) = event_root_owners.get(&event_id) {
            roots.extend(owners.iter().copied());
        }
    }
    for coordinate in coordinates {
        if let Some(owners) = coordinate_root_owners.get(&coordinate) {
            roots.extend(owners.iter().copied());
        }
    }
    roots
}

/// Derive a bounded transitive frontier from related events already accepted
/// into the local database.
///
/// A newly fetched event becomes a parent on the next reconciliation tick, so
/// remote traversal progresses without retaining another durable cursor. Both
/// event IDs and replaceable/addressable coordinates participate because
/// clients may continue a thread through either reference form.
async fn recursive_descendant_frontier(
    database: &SharedDatabase,
    root_events: &HashSet<EventId>,
    max_recursive_events_per_branch: usize,
) -> DescendantFrontier {
    recursive_descendant_frontier_with_limits(
        database,
        root_events,
        MAX_DESCENDANT_FRONTIER_DEPTH,
        max_recursive_events_per_branch,
    )
    .await
}

async fn recursive_descendant_frontier_with_limits(
    database: &SharedDatabase,
    root_events: &HashSet<EventId>,
    max_depth: usize,
    max_recursive_events_per_branch: usize,
) -> DescendantFrontier {
    let mut frontier = DescendantFrontier::default();
    if max_depth == 0 || root_events.is_empty() {
        return frontier;
    }

    // Every event directly tagging a root owns an independent recursive
    // subtree. This keeps a popular tangential branch from consuming the
    // compatibility coverage of unrelated issues, patches, or repositories.
    // Retain exact root provenance at the same time so participant mailbox
    // probes cannot leak one repository's roots into another author's scope.
    let mut direct_events = HashMap::<EventId, (Event, HashSet<EventId>)>::new();
    let mut event_root_owners = HashMap::<EventId, HashSet<EventId>>::new();
    let mut coordinate_root_owners = HashMap::<String, HashSet<EventId>>::new();
    for filter in filters::tagged_one_of_our_root_event_filters(root_events, None) {
        match database.query(filter).await {
            Ok(events) => {
                for event in events
                    .iter()
                    .filter(|event| !root_events.contains(&event.id))
                {
                    let roots = descendant_reference_roots(
                        event,
                        root_events,
                        &event_root_owners,
                        &coordinate_root_owners,
                    );
                    if roots.is_empty() {
                        continue;
                    }
                    direct_events
                        .entry(event.id)
                        .and_modify(|(_, known_roots)| {
                            known_roots.extend(roots.iter().copied());
                        })
                        .or_insert_with(|| (event.clone(), roots));
                }
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    root_event_count = root_events.len(),
                    "Failed to derive direct repository thread members"
                );
                return DescendantFrontier::default();
            }
        }
    }

    let mut direct_events: Vec<_> = direct_events.into_iter().collect();
    direct_events.sort_by(|(left_id, (left, _)), (right_id, (right, _))| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left_id.cmp(right_id))
    });
    let direct_event_ids: HashSet<_> = direct_events.iter().map(|(id, _)| *id).collect();
    let mut branch_member_counts = HashMap::<EventId, usize>::new();
    let mut event_branches = HashMap::<EventId, HashSet<EventId>>::new();
    let mut coordinate_branches = HashMap::<String, HashSet<EventId>>::new();
    let mut event_seeds = HashMap::<EventId, HashSet<EventId>>::new();
    let mut coordinate_seeds = HashMap::<String, HashSet<EventId>>::new();
    for (event_id, (event, roots)) in direct_events {
        branch_member_counts.insert(event_id, 0);
        event_branches.entry(event_id).or_default().insert(event_id);
        frontier
            .author_roots
            .entry(event.pubkey)
            .or_default()
            .extend(roots.iter().copied());
        event_root_owners.insert(event_id, roots.clone());
        event_seeds.entry(event_id).or_default().insert(event_id);
        if let Some(coordinate) = descendant_event_coordinate(&event) {
            coordinate_branches
                .entry(coordinate.clone())
                .or_default()
                .insert(event_id);
            coordinate_seeds
                .entry(coordinate.clone())
                .or_default()
                .insert(event_id);
            coordinate_root_owners
                .entry(coordinate)
                .or_default()
                .extend(roots);
        }
    }

    if max_depth == 1 || (event_seeds.is_empty() && coordinate_seeds.is_empty()) {
        frontier.event_ids.extend(event_seeds.into_keys());
        frontier.coordinates.extend(coordinate_seeds.into_keys());
        return frontier;
    }

    for depth in 2..=max_depth {
        let mut layer_events = HashMap::<EventId, (Event, HashSet<EventId>)>::new();
        let event_seed_ids: HashSet<_> = event_seeds.keys().copied().collect();
        let coordinate_seed_ids: HashSet<_> = coordinate_seeds.keys().cloned().collect();
        let mut layer_filters =
            filters::tagged_one_of_our_root_event_filters(&event_seed_ids, None);
        layer_filters.extend(filters::tagged_one_of_our_repo_event_filters(
            &coordinate_seed_ids,
            None,
        ));

        for filter in layer_filters {
            match database.query(filter).await {
                Ok(events) => {
                    for event in events.iter() {
                        if root_events.contains(&event.id) || direct_event_ids.contains(&event.id) {
                            continue;
                        }
                        let roots = descendant_reference_roots(
                            event,
                            root_events,
                            &event_root_owners,
                            &coordinate_root_owners,
                        );
                        if roots.is_empty() {
                            continue;
                        }
                        layer_events
                            .entry(event.id)
                            .and_modify(|(_, known_roots)| {
                                known_roots.extend(roots.iter().copied());
                            })
                            .or_insert_with(|| (event.clone(), roots));
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        depth,
                        event_seed_count = event_seeds.len(),
                        coordinate_seed_count = coordinate_seeds.len(),
                        direct_event_count = direct_event_ids.len(),
                        "Failed to derive recursive repository thread members"
                    );
                    return frontier;
                }
            }
        }

        let mut layer_events: Vec<_> = layer_events.into_iter().collect();
        layer_events.sort_by(|(left_id, (left, _)), (right_id, (right, _))| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left_id.cmp(right_id))
        });

        let mut next_event_seeds = HashMap::<EventId, HashSet<EventId>>::new();
        let mut next_coordinate_seeds = HashMap::<String, HashSet<EventId>>::new();
        for (event_id, (event, roots)) in layer_events {
            let (addressable_refs, event_refs) =
                crate::nostr::policy::RelatedEventPolicy::extract_reference_tags(&event);
            let mut inherited_branches = HashSet::new();
            for parent in event_refs {
                if let Some(branches) = event_branches.get(&parent) {
                    inherited_branches.extend(branches.iter().copied());
                }
            }
            for parent in addressable_refs {
                if let Some(branches) = coordinate_branches.get(&parent) {
                    inherited_branches.extend(branches.iter().copied());
                }
            }
            if let Some(existing_branches) = event_branches.get(&event_id) {
                inherited_branches.retain(|branch| !existing_branches.contains(branch));
            }

            let mut admitted_branches = HashSet::new();
            for branch in inherited_branches {
                let member_count = branch_member_counts.entry(branch).or_default();
                if *member_count < max_recursive_events_per_branch {
                    *member_count += 1;
                    admitted_branches.insert(branch);
                }
            }
            if admitted_branches.is_empty() {
                continue;
            }
            frontier
                .author_roots
                .entry(event.pubkey)
                .or_default()
                .extend(roots.iter().copied());
            event_root_owners
                .entry(event_id)
                .or_default()
                .extend(roots.iter().copied());
            event_branches
                .entry(event_id)
                .or_default()
                .extend(admitted_branches.iter().copied());
            let coordinate = descendant_event_coordinate(&event);
            if let Some(coordinate) = &coordinate {
                coordinate_branches
                    .entry(coordinate.clone())
                    .or_default()
                    .extend(admitted_branches.iter().copied());
                coordinate_root_owners
                    .entry(coordinate.clone())
                    .or_default()
                    .extend(roots.iter().copied());
            }

            let expandable_branches: HashSet<_> = admitted_branches
                .into_iter()
                .filter(|branch| branch_member_counts[branch] < max_recursive_events_per_branch)
                .collect();
            if expandable_branches.is_empty() {
                continue;
            }
            next_event_seeds.insert(event_id, expandable_branches.clone());
            if let Some(coordinate) = coordinate {
                next_coordinate_seeds.insert(coordinate, expandable_branches);
            }
        }

        if next_event_seeds.is_empty() && next_coordinate_seeds.is_empty() {
            break;
        }
        event_seeds = next_event_seeds;
        coordinate_seeds = next_coordinate_seeds;
    }

    let exhausted_branches: HashSet<_> = branch_member_counts
        .iter()
        .filter(|(_, member_count)| **member_count >= max_recursive_events_per_branch)
        .map(|(branch, _)| *branch)
        .collect();
    for (event_id, branches) in &event_branches {
        if branches
            .iter()
            .any(|branch| !exhausted_branches.contains(branch))
        {
            frontier.event_ids.insert(*event_id);
        }
    }
    for (coordinate, branches) in &coordinate_branches {
        if branches
            .iter()
            .any(|branch| !exhausted_branches.contains(branch))
        {
            frontier.coordinates.insert(coordinate.clone());
        }
    }

    tracing::debug!(
        depth_limit = max_depth,
        event_count = frontier.event_ids.len(),
        coordinate_count = frontier.coordinates.len(),
        branch_count = branch_member_counts.len(),
        exhausted_branch_count = exhausted_branches.len(),
        "Derived bounded recursive repository thread frontier"
    );
    frontier
}

#[cfg(test)]
fn descendant_frontier_filters(
    frontier: &DescendantFrontier,
    since: Option<Timestamp>,
) -> Vec<Filter> {
    let mut filters = filters::tagged_one_of_our_root_event_filters(&frontier.event_ids, since);
    filters.extend(filters::tagged_one_of_our_repo_event_filters(
        &frontier.coordinates,
        since,
    ));
    filters
}

fn mailbox_probe_filters(
    repositories: &HashSet<String>,
    root_events: &HashSet<EventId>,
    frontier: &DescendantFrontier,
) -> Vec<Filter> {
    let coordinate_values: HashSet<_> =
        repositories.union(&frontier.coordinates).cloned().collect();
    let event_values: HashSet<_> = root_events.union(&frontier.event_ids).copied().collect();
    let mut filters = filters::tagged_one_of_our_repo_event_filters(&coordinate_values, None);
    filters.extend(filters::tagged_one_of_our_root_event_filters(
        &event_values,
        None,
    ));
    filters
}

fn expand_mailbox_probe_scope(
    repository_scope: &HashSet<String>,
    root_scope: &HashSet<EventId>,
    root_repositories: &HashMap<EventId, String>,
) -> (HashSet<String>, HashSet<EventId>) {
    let mut repositories = repository_scope.clone();
    repositories.extend(
        root_scope
            .iter()
            .filter_map(|root| root_repositories.get(root).cloned()),
    );

    let mut roots = root_scope.clone();
    roots.extend(
        root_repositories.iter().filter_map(|(root, repository)| {
            repository_scope.contains(repository).then_some(*root)
        }),
    );
    (repositories, roots)
}

fn merge_repository_roots_into_mailbox_overlay(
    mailbox_roots: &mut HashMap<String, HashSet<EventId>>,
    mailbox_repositories: &HashMap<String, HashSet<String>>,
    root_repositories: &HashMap<EventId, String>,
) {
    for (relay, repositories) in mailbox_repositories {
        let roots: HashSet<EventId> = root_repositories
            .iter()
            .filter_map(|(root, repository)| repositories.contains(repository).then_some(*root))
            .collect();
        if !roots.is_empty() {
            mailbox_roots
                .entry(relay.clone())
                .or_default()
                .extend(roots);
        }
    }
}

fn packed_historic_filters(items: &PendingItems, frontier: &DescendantFrontier) -> Vec<Filter> {
    let all_repos: HashSet<_> = items
        .repos
        .union(&items.state_only_repos)
        .cloned()
        .collect();
    let mut filters = filters::state_event_filters_for_our_repos(&all_repos, None);

    let coordinate_values: HashSet<_> = items.repos.union(&frontier.coordinates).cloned().collect();
    filters.extend(filters::tagged_one_of_our_repo_event_filters(
        &coordinate_values,
        None,
    ));

    let event_values: HashSet<_> = items
        .root_events
        .union(&frontier.event_ids)
        .cloned()
        .collect();
    filters.extend(filters::tagged_one_of_our_root_event_filters(
        &event_values,
        None,
    ));
    filters
}

fn tiered_auxiliary_filters(
    repos: &HashSet<String>,
    root_events: &HashSet<EventId>,
    frontier: &DescendantFrontier,
    since: Option<Timestamp>,
) -> Vec<filters::TieredFilter> {
    let mut entries = filters::tiered_auxiliary_core_filters(repos, root_events, since);
    entries.extend(filters::tiered_root_event_filters(
        &frontier.event_ids,
        true,
        since,
    ));
    entries.extend(filters::tiered_repo_event_filters(
        &frontier.coordinates,
        true,
        since,
    ));
    entries.sort_by_key(|entry| entry.tier);
    entries
}

fn split_live_tier_prefix(
    entries: &[filters::TieredFilter],
    max_filters_per_req: usize,
    fits: impl Fn(&[Vec<Filter>]) -> bool,
) -> (Vec<Filter>, Vec<Filter>) {
    use filters::CoverageTier;

    let live_tiers = [
        CoverageTier::RootUppercase,
        CoverageTier::CoreCompatibility,
        CoverageTier::DescendantCanonical,
        CoverageTier::DescendantQuote,
    ];
    let mut live = Vec::new();
    for tier in live_tiers {
        let mut candidate = live.clone();
        candidate.extend(
            entries
                .iter()
                .filter(|entry| entry.tier == tier)
                .map(|entry| entry.filter.clone()),
        );
        let groups = live_filter_groups(&candidate, max_filters_per_req);
        if fits(&groups) {
            live = candidate;
        } else {
            break;
        }
    }
    let live_json: HashSet<_> = live.iter().map(Filter::as_json).collect();
    let rotated = entries
        .iter()
        .filter(|entry| !live_json.contains(&entry.filter.as_json()))
        .map(|entry| entry.filter.clone())
        .collect();
    (live, rotated)
}

fn complete_auxiliary_fallback(entries: &[filters::TieredFilter]) -> Vec<Filter> {
    entries.iter().map(|entry| entry.filter.clone()).collect()
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

fn take_batch_containing_subscription(
    pending: &mut HashMap<String, Vec<PendingBatch>>,
    relay_url: &str,
    subscription_id: &SubscriptionId,
) -> Option<PendingBatch> {
    let (batch_index, remove_relay) = {
        let batches = pending.get(relay_url)?;
        let batch_index = batches
            .iter()
            .position(|batch| batch.outstanding_subs.contains(subscription_id))?;
        (batch_index, batches.len() == 1)
    };

    let batch = pending.get_mut(relay_url)?.remove(batch_index);
    if remove_relay {
        pending.remove(relay_url);
    }
    Some(batch)
}

fn register_negentropy_hydration_attempt(
    batch: &mut PendingBatch,
    subscription_ids: impl IntoIterator<Item = SubscriptionId>,
    requested_event_ids: impl IntoIterator<Item = EventId>,
    is_retry: bool,
) {
    // Register the complete attempt before its first REQ is sent. A fast
    // relay can deliver events and EOSE while later paced chunks are still
    // waiting to open; pre-registration makes that whole stream attributable.
    batch.outstanding_subs.extend(subscription_ids);
    batch.requested_event_ids = Some(requested_event_ids.into_iter().collect());
    batch.received_event_ids = Some(HashSet::new());
    if is_retry {
        batch.retry_count += 1;
    }
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

#[derive(Debug)]
pub(super) struct SubscriptionClosedNotification {
    relay_url: String,
    subscription_id: SubscriptionId,
    reason: String,
    generation: Option<u64>,
    live_filter_count: Option<usize>,
    timed_out: bool,
}

// One global actor consumes terminal state changes from every outbound relay.
// A hostile peer can repeat EOSE/CLOSED indefinitely, so this queue must bound
// retained memory independently of the per-connection subscription ledger.
const LIFECYCLE_NOTIFICATION_CAPACITY: usize = 1_000;

fn lifecycle_notification_channel<T>(
) -> (tokio::sync::mpsc::Sender<T>, tokio::sync::mpsc::Receiver<T>) {
    tokio::sync::mpsc::channel(LIFECYCLE_NOTIFICATION_CAPACITY)
}

fn is_rate_limit_message(message: &str) -> bool {
    let message = message.to_lowercase();
    (message.contains("rate") && message.contains("limit"))
        || message.contains("too many")
        || message.contains("slow down")
        || message.contains("throttl")
}

fn is_filter_count_refusal(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("invalid number of filters") || message.contains("max filter count")
}

fn is_auth_required_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("auth-required") || message.contains("authentication required")
}

fn reserve_authentication_retry(
    attempts: &mut HashSet<(String, SubscriptionId)>,
    relay_url: &str,
    subscription_id: &SubscriptionId,
) -> bool {
    let attempt = (relay_url.to_string(), subscription_id.clone());
    if attempts.insert(attempt.clone()) {
        true
    } else {
        attempts.remove(&attempt);
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyRefusal {
    AuthenticationRequired,
    Blocked,
    Restricted,
    MembershipRequired,
    FilterIncompatible,
}

impl PolicyRefusal {
    fn label(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "authentication_required",
            Self::Blocked => "blocked",
            Self::Restricted => "restricted",
            Self::MembershipRequired => "membership_required",
            Self::FilterIncompatible => "filter_incompatible",
        }
    }
}

fn policy_refusal(message: &str) -> Option<PolicyRefusal> {
    if is_filter_count_refusal(message) {
        return Some(PolicyRefusal::FilterIncompatible);
    }
    if is_rate_limit_message(message) {
        return None;
    }
    let message = message.to_ascii_lowercase();
    if message.contains("unsupported filter")
        || message.contains("filter item too large")
        || message.contains("filter validation failed")
        || message.contains("unsupported: invalid filters")
        || message.contains("filter 'limit' must be a positive integer")
    {
        Some(PolicyRefusal::FilterIncompatible)
    } else if message.contains("not a member") || message.contains("membership") {
        Some(PolicyRefusal::MembershipRequired)
    } else if message.contains("restricted") {
        Some(PolicyRefusal::Restricted)
    } else if message.contains("blocked") || message.contains("request rejected") {
        Some(PolicyRefusal::Blocked)
    } else {
        None
    }
}

fn subscription_state_byte_limit(message: &str) -> Option<usize> {
    let lower = message.to_ascii_lowercase();
    let marker = "active subscriptions exceed max size ";
    let tail = lower.split_once(marker)?.1;
    let digits = tail.split_whitespace().next()?;
    digits.parse().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectAttemptToken(u64);

#[derive(Debug)]
enum ConnectAttemptOutcome {
    Connected {
        advertised_default_limit: Option<usize>,
        advertised_max_subscriptions: Option<usize>,
        advertised_owner: Option<PublicKey>,
        advertised_grasp08: bool,
    },
    /// The relay's NIP-11 advertises the GRASP-08 private-service extension
    /// while this instance is public. Detected before the WebSocket dial, so
    /// no connection or AUTH exchange ever happened.
    PrivateService,
    Failed(String),
}

#[derive(Debug)]
struct ConnectAttemptResult {
    relay_url: String,
    token: ConnectAttemptToken,
    outcome: ConnectAttemptOutcome,
}

const NIP65_DISCOVERY_BATCH_AUTHORS: usize = 100;

fn nip65_discovery_refresh_interval() -> Duration {
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(24 * 60 * 60)
    }
}

fn nip65_discovery_retry_interval() -> Duration {
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_millis(500)
    } else {
        Duration::from_secs(5 * 60)
    }
}

fn nip65_inventory_interval() -> Duration {
    if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_millis(200)
    } else {
        Duration::from_secs(60)
    }
}

fn nip65_author_retry_after(
    query_succeeded: bool,
    represented: &HashSet<PublicKey>,
    author: &PublicKey,
) -> Duration {
    if query_succeeded && represented.contains(author) {
        nip65_discovery_refresh_interval()
    } else {
        nip65_discovery_retry_interval()
    }
}

#[derive(Debug)]
struct Nip65DiscoveryResult {
    source_relay: String,
    authors: HashSet<PublicKey>,
    outcome: Result<Vec<Event>, String>,
}

#[derive(Debug)]
struct MailboxProbeResult {
    source_relay: String,
    filter_index: usize,
    filter_count: usize,
    outcome: Result<Vec<Event>, String>,
}

#[derive(Debug, Default)]
struct Nip65DiscoveryState {
    /// Roots authored by each accepted root author. These preserve the
    /// existing GRASP-03 live inbox overlay; non-root participants remain on
    /// the paced history-only mailbox path below.
    root_author_roots: HashMap<PublicKey, HashSet<EventId>>,
    author_roots: HashMap<PublicKey, HashSet<EventId>>,
    /// Public accepted repositories owned or maintained by each author. This
    /// remains empty in private mode so mailbox probes never disclose private
    /// repository coordinates to a public NIP-65 relay.
    author_repositories: HashMap<PublicKey, HashSet<String>>,
    root_repositories: HashMap<EventId, String>,
    eligible_authors: HashSet<PublicKey>,
    author_sources: HashMap<PublicKey, HashSet<String>>,
    relay_lists: HashMap<PublicKey, Event>,
    author_inboxes: HashMap<PublicKey, HashSet<String>>,
    author_mailboxes: HashMap<PublicKey, HashSet<String>>,
    /// Eligible authors for whom at least one successful index query returned
    /// no accepted relay list. They use the operator's bounded fallback set
    /// until an accepted kind 10002 arrives.
    fallback_authors: HashSet<PublicKey>,
    /// Essential live root coverage on accepted root authors' read/unmarked
    /// NIP-65 inboxes. Owner/maintainer repository scope and participant
    /// write/outbox coverage remain on the history-only mailbox path below:
    /// owning or maintaining a repository never makes an author's inbox an
    /// ordinary persistent live target.
    inbox_roots: HashMap<String, HashSet<EventId>>,
    mailbox_roots: HashMap<String, HashSet<EventId>>,
    mailbox_repositories: HashMap<String, HashSet<String>>,
    mailbox_probe_next_at: HashMap<String, Instant>,
    mailbox_probe_next_filter: HashMap<String, usize>,
    /// Failed mailbox probes back off independently of transport and live coverage.
    mailbox_probe_failure_delay: HashMap<String, Duration>,
    /// At most one ordinary fetch runs per mailbox relay. Different relays
    /// remain independent and use their own connection capacity.
    mailbox_probes_in_flight: HashSet<String>,
    in_flight: HashSet<(String, PublicKey)>,
    next_attempt_at: HashMap<(String, PublicKey), Instant>,
    /// Failed identity queries pause the source, including newly discovered authors.
    discovery_failure_backoff: HashMap<String, (Duration, Instant)>,
    next_inventory_at: Option<Instant>,
}

impl Nip65DiscoveryState {
    /// Connection ownership includes historical discovery work, even while
    /// its next query is deferred. It is not persistent subscription scope.
    fn connection_targets(&self) -> HashSet<String> {
        self.author_sources
            .values()
            .flatten()
            .chain(self.mailbox_roots.keys())
            .chain(self.mailbox_repositories.keys())
            .chain(self.mailbox_probes_in_flight.iter())
            .chain(self.in_flight.iter().map(|(relay, _)| relay))
            .cloned()
            .collect()
    }

    fn author_query_due(&self, source: &str, author: &PublicKey, now: Instant) -> bool {
        self.discovery_failure_backoff
            .get(source)
            .is_none_or(|(_, due)| *due <= now)
            && self
                .next_attempt_at
                .get(&(source.to_string(), *author))
                .is_none_or(|due| *due <= now)
    }

    fn record_discovery_outcome(
        &mut self,
        source: &str,
        succeeded: bool,
        now: Instant,
    ) -> Duration {
        if succeeded {
            self.discovery_failure_backoff.remove(source);
            return Duration::ZERO;
        }
        if !self
            .author_sources
            .values()
            .any(|sources| sources.contains(source))
        {
            return Duration::ZERO;
        }
        let (delay, due) = self
            .discovery_failure_backoff
            .entry(source.to_string())
            .and_modify(|(delay, _)| {
                *delay = delay.saturating_mul(2).min(Duration::from_secs(3600))
            })
            .or_insert((nip65_discovery_retry_interval(), now));
        *due = now + *delay;
        *delay
    }

    fn retain_discovery_backoff(&mut self) {
        let sources: HashSet<&String> = self.author_sources.values().flatten().collect();
        self.discovery_failure_backoff
            .retain(|source, _| sources.contains(source));
    }

    /// Ownership survives pauses; dialing requires due work from at least one
    /// discovery lane. Repository/live work is admitted independently.
    fn due_connection_targets(&self, now: Instant) -> HashSet<String> {
        let mut due = HashSet::new();
        for (author, sources) in &self.author_sources {
            for source in sources {
                if self.author_query_due(source, author, now) {
                    due.insert(source.clone());
                }
            }
        }
        due.extend(self.in_flight.iter().map(|(relay, _)| relay.clone()));
        due.extend(self.mailbox_probes_in_flight.iter().cloned());
        due.extend(
            self.mailbox_roots
                .keys()
                .chain(self.mailbox_repositories.keys())
                .filter(|relay| {
                    self.mailbox_probe_next_at
                        .get(*relay)
                        .is_none_or(|due| *due <= now)
                })
                .cloned(),
        );
        due
    }

    fn has_mailbox_scope(&self, relay: &str) -> bool {
        self.mailbox_roots.contains_key(relay) || self.mailbox_repositories.contains_key(relay)
    }

    fn mailbox_relay_count(&self) -> usize {
        self.mailbox_roots.len()
            + self
                .mailbox_repositories
                .keys()
                .filter(|relay| !self.mailbox_roots.contains_key(*relay))
                .count()
    }

    fn install_mailbox_overlay(
        &mut self,
        new_root_overlay: HashMap<String, HashSet<EventId>>,
        new_repository_overlay: HashMap<String, HashSet<String>>,
        now: Instant,
    ) {
        let old_root_overlay = std::mem::replace(&mut self.mailbox_roots, new_root_overlay);
        let old_repository_overlay =
            std::mem::replace(&mut self.mailbox_repositories, new_repository_overlay);
        if old_root_overlay == self.mailbox_roots
            && old_repository_overlay == self.mailbox_repositories
        {
            return;
        }
        let current_relays: HashSet<String> = self
            .mailbox_roots
            .keys()
            .chain(self.mailbox_repositories.keys())
            .cloned()
            .collect();
        self.mailbox_probe_next_at
            .retain(|relay, _| current_relays.contains(relay));
        self.mailbox_probe_next_filter
            .retain(|relay, _| current_relays.contains(relay));
        self.mailbox_probe_failure_delay
            .retain(|relay, _| current_relays.contains(relay));
        for relay in current_relays {
            if old_root_overlay.get(&relay) != self.mailbox_roots.get(&relay)
                || old_repository_overlay.get(&relay) != self.mailbox_repositories.get(&relay)
            {
                if !self.mailbox_probe_failure_delay.contains_key(&relay) {
                    self.mailbox_probe_next_at.insert(relay.clone(), now);
                }
                self.mailbox_probe_next_filter.entry(relay).or_default();
            }
        }
    }

    fn mailbox_connected(&mut self, relay: &str, now: Instant) {
        if self.has_mailbox_scope(relay) && !self.mailbox_probe_failure_delay.contains_key(relay) {
            self.mailbox_probe_next_at.insert(relay.to_string(), now);
        }
    }

    fn mailbox_retry_delay(&mut self, relay: &str, succeeded: bool) -> Duration {
        if succeeded {
            self.mailbox_probe_failure_delay.remove(relay);
            return Duration::ZERO;
        }
        if !self.has_mailbox_scope(relay) {
            return mailbox_probe_retry_interval();
        }
        let delay = self
            .mailbox_probe_failure_delay
            .entry(relay.to_string())
            .and_modify(|delay| *delay = delay.saturating_mul(2).min(Duration::from_secs(3600)))
            .or_insert_with(mailbox_probe_retry_interval);
        *delay
    }

    fn record_probe_completion(
        &mut self,
        relay: &str,
        next_filter: usize,
        next_probe_in: Duration,
        now: Instant,
    ) {
        // A relay removed from the overlay while its probe was in flight must
        // not leave orphan cursor or due-time entries; re-addition is reseeded
        // by `install_mailbox_overlay`.
        if !self.has_mailbox_scope(relay) {
            return;
        }
        self.mailbox_probe_next_filter
            .insert(relay.to_string(), next_filter);
        self.mailbox_probe_next_at
            .insert(relay.to_string(), now + next_probe_in);
    }
}

/// Quick reconnect window in seconds (15 minutes)
const QUICK_RECONNECT_WINDOW_SECS: u64 = 15 * 60;

/// Bound concurrent DNS and websocket handshakes so a large relay list cannot
/// exhaust network resources while keeping the sync actor responsive.
const MAX_CONCURRENT_CONNECT_ATTEMPTS: usize = 8;

/// Safety ceiling for independently progressing mailbox relays.
///
/// A relay owns at most one worker and drains its filter cursor without
/// returning to the global relay rotation between slices. Keep a separate,
/// generous process-wide ceiling so a peer-influenced NIP-65 inventory cannot
/// create an unbounded number of simultaneous response accumulators.
const MAX_CONCURRENT_MAILBOX_WORKERS: usize = 32;

/// Maximum number of collection members rendered in an INFO-level log field.
/// Counts remain authoritative; samples keep remotely influenced logs bounded.
const LOG_COLLECTION_SAMPLE_SIZE: usize = 5;

/// Adaptive per-relay threshold for historic REQ+EOSE pagination.
///
/// NIP-01 guarantees none of this; the model is empirical. A source audit of
/// nine relay implementations (2026-08-06, recorded with citations in
/// docs/explanation/sync-scaling-constraints.md) found result limits are
/// always applied per filter, never in aggregate across a REQ. Ditto is the
/// smallest live omitted-limit default found, at 100 events.
///
/// Every raw delivery matching a tracked filter counts, before write-policy
/// processing. Purgatory-routed, rejected, and repeated events therefore
/// consume both the relay's allowance and our page count, and the cursor is
/// derived from that same raw stream. Each connection session learns its
/// largest raw page and combines it with NIP-11 `default_limit` when present:
/// `threshold = max(90, floor(0.9 * max(observed, default_limit)))`. A hint is
/// verified once before it may stop pagination; a productive verification
/// page discards it for that session. `max_limit` is intentionally ignored
/// because these filters omit `limit`. State and NIP-11 data reset on every
/// reconnect. See "Per-query result limits and the pagination model" in
/// docs/explanation/sync-scaling-constraints.md.
const PAGINATION_THRESHOLD_FLOOR: usize = 90;
const PAGINATION_THRESHOLD_PERCENT: usize = 90;

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
/// Leave room for one maximum-sized transient REQ when a relay discloses a
/// cumulative retained-subscription byte cap. Byte-limited sessions serialize
/// transient REQs through a matching connection gate.
const SUBSCRIPTION_BYTE_RESERVED_MARGIN: usize = REQ_MESSAGE_BYTE_BUDGET + 256;

fn req_message_size(filters: &[Filter]) -> usize {
    ClientMessage::req(SubscriptionId::generate(), filters.to_vec())
        .as_json()
        .len()
}

fn groups_within_subscription_byte_limit(
    groups: Vec<Vec<Filter>>,
    limit: Option<usize>,
    already_used: usize,
) -> (Vec<Vec<Filter>>, usize) {
    let Some(limit) = limit else {
        return (groups, 0);
    };
    let live_budget = limit.saturating_sub(SUBSCRIPTION_BYTE_RESERVED_MARGIN);
    let mut admitted = Vec::new();
    let mut used = already_used;
    let mut overflow = 0usize;
    for group in groups {
        let size = req_message_size(&group);
        if used
            .checked_add(size)
            .is_some_and(|total| total <= live_budget)
        {
            used += size;
            admitted.push(group);
        } else {
            overflow += 1;
        }
    }
    (admitted, overflow)
}

/// Pack filters into REQ-sized groups.
///
/// Groups are cut when adding the next filter would exceed either the
/// serialized byte budget or the filter-count cap. A single oversized filter
/// still gets its own group, so progress is always made.
fn group_filters_for_req_with_max(filters: &[Filter], max_filters: usize) -> Vec<Vec<Filter>> {
    let mut groups: Vec<Vec<Filter>> = Vec::new();
    let mut current: Vec<Filter> = Vec::new();
    let mut bytes = 0usize;
    for filter in filters {
        let cost = filter.as_json().len();
        if !current.is_empty()
            && (current.len() >= max_filters.max(1) || bytes + cost > REQ_MESSAGE_BYTE_BUDGET)
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

fn group_filters_for_req(filters: &[Filter]) -> Vec<Vec<Filter>> {
    group_filters_for_req_with_max(filters, MAX_FILTERS_PER_REQ)
}

fn live_filter_groups(filters: &[Filter], max_filters: usize) -> Vec<Vec<Filter>> {
    group_filters_for_req_with_max(filters, max_filters)
        .into_iter()
        .map(|group| group.into_iter().map(|filter| filter.limit(0)).collect())
        .collect()
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
    pacer: Arc<Mutex<Option<tokio::time::Instant>>>,
    health_tracker: Arc<RelayHealthTracker>,
    relay_url: &str,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let permit = semaphore.acquire_owned().await.ok()?;
    pace_connection_start(&pacer).await;
    health_tracker.record_attempt(relay_url);
    Some(permit)
}

/// Space actual starts, not reservations: a stalled executor never catches up
/// with a burst of overdue dials. The concurrency permit remains held here.
async fn pace_connection_start(pacer: &Mutex<Option<tokio::time::Instant>>) {
    let mut previous = pacer.lock().await;
    if let Some(last) = *previous {
        tokio::time::sleep_until(last + Duration::from_millis(250)).await;
    }
    *previous = Some(tokio::time::Instant::now());
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
///
/// Finally, one relay's live descendant admission is reconciled and every
/// constrained relay may advance one queued descendant history query. Reusing
/// this five-second cadence avoids another scheduler or configuration surface.
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
                manager.reconcile_private_membership().await;
                manager.tick_missing_event_recovery().await;
                manager.tick_descendant_sync().await;
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
                let related_expired = manager.rejected_events_index.cleanup_expired_related();

                if ann_cold_expired + state_cold_expired + unrecoverable_expired + related_expired > 0 {
                    tracing::info!(
                        announcements = ann_cold_expired,
                        states = state_cold_expired,
                        unrecoverable = unrecoverable_expired,
                        related = related_expired,
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

                // 1. Reset failure history only after a recovered connection
                // has survived the stability period under normal sync load.
                manager.health_tracker.promote_stable_connections();

                // 2. Check for disconnects and retry disconnected relays
                manager.check_disconnects().await;
                manager.retry_disconnected_relays().await;

                // 3. Check for rate limit recovery
                manager.check_rate_limit_recovery().await;

                // 4. Keep deliberately bounded live coverage complete through
                // paced incremental history rather than retrying an impossible
                // persistent set.
                manager.sync_due_byte_limited_relay().await;

                // 5. Discover one bounded batch of participant NIP-65 mailboxes.
                // The query uses an ordinary transient ledger slot and yields
                // to historic work when no slot is immediately available.
                manager.schedule_nip65_discovery().await;

                // 6. Admit at most one new participant mailbox relay worker.
                // Once admitted, that relay drains its own history-filter
                // cursor independently, one request at a time. Mailbox
                // coverage is history-only: it does not turn every participant
                // relay into a permanent live source.
                manager.schedule_mailbox_probe().await;

                // 7. Check for naughty list expiration
                if let Some(naughty_list) = manager.health_tracker.naughty_list() {
                    let recovered = naughty_list.expire_old_entries();
                    for url in recovered {
                        tracing::info!(
                            relay = %url,
                            "Relay removed from naughty list after expiration, will retry"
                        );
                    }
                }

                // 8. Update metrics with current health states and naughty list
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

                    let (pending_batches, pending_subscriptions) = {
                        let pending = manager.pending_sync_index.read().await;
                        (
                            pending.values().map(Vec::len).sum(),
                            pending
                                .values()
                                .flatten()
                                .map(|batch| batch.outstanding_subs.len())
                                .sum(),
                        )
                    };
                    for (class, count) in [
                        ("pending_batches", pending_batches),
                        ("pending_subscriptions", pending_subscriptions),
                        ("auth_retries", manager.auth_required_attempts.len()),
                        ("queued_connection_attempts", manager.in_flight_connect_attempts.len()),
                        ("purgatory_dependencies", manager.purgatory_dependency_attempts.len()),
                        ("dependency_relays", manager.dependency_relay_deadlines.len()),
                        ("related_dependency_events", manager.rejected_events_index.related_len()),
                        ("deferred_consolidations", manager.deferred_consolidations.relays.len()),
                        ("pending_live_repairs", manager.pending_live_repairs.len()),
                        ("descendant_rotations", manager.descendant_sync_rotations.len()),
                        (
                            "nip65_eligible_authors",
                            manager.nip65_discovery.eligible_authors.len(),
                        ),
                        (
                            "mailbox_probe_relays",
                            manager.nip65_discovery.mailbox_relay_count(),
                        ),
                        (
                            "mailbox_probe_cursors",
                            manager.nip65_discovery.mailbox_probe_next_filter.len(),
                        ),
                        (
                            "mailbox_probe_active",
                            manager.nip65_discovery.mailbox_probes_in_flight.len(),
                        ),
                    ] {
                        metrics.set_retained_state(class, count);
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
    root_candidate_index: RootCandidateIndex,
    proactive_participant_authors: crate::nostr::policy::SharedProactiveParticipantAuthorIndex,
    /// GRASP-08 access shared with the inbound HTTP/WebSocket boundary.
    private_access: Option<PrivateAccess>,
    /// Confirmed GRASP-08 peers shared with the purgatory Git fetch path.
    ///
    /// Only populated on private instances (the server passes `Some`): a
    /// public mirror never presents credentials, and its GRASP-08 targets are
    /// parked pre-dial instead.
    grasp08_peers: Option<crate::private::Grasp08Peers>,
    /// Operator-configured members form the permanent base of private access.
    configured_private_members: HashSet<PublicKey>,
    /// Latest NIP-11 owner learned for each connected repository relay whose
    /// NIP-11 also advertises GRASP-08. Only private-service owners can mint
    /// derived membership: the owner of a public relay gains nothing
    /// legitimate from private membership, since their relay enforces no
    /// confidentiality for the repositories it mirrors.
    relay_owners: HashMap<String, PublicKey>,
    /// What we've confirmed syncing + connection state
    relay_sync_index: RelaySyncIndex,
    /// In-flight subscription batches
    pending_sync_index: PendingSyncIndex,
    /// Rejected events (30617/30618) - two-tier storage for re-processing
    /// Handles both announcement and state events via EventType discriminator
    rejected_events_index: Arc<RejectedEventsIndex>,
    /// Active relay connections - keyed by relay URL
    connections: HashMap<String, RelayConnection>,
    /// Connections opened only to discover accepted authors' kind 0/10002.
    ///
    /// These share the ordinary connection, safety, and reconnect machinery,
    /// but must not turn a user-index or outbox relay into a repository sync
    /// source merely because it answered a control-plane lookup.
    nip65_discovery_only_relays: HashSet<String>,
    /// Adaptive pagination learning for each relay's current connection session.
    pagination_sessions: HashMap<String, RelayPaginationSession>,
    /// Event-directed relay targets rejected by the outbound target policy.
    ///
    /// Rejected URLs stay in `repo_sync_index` (they come from stored events),
    /// so without this memo every sync pass would re-derive, re-reject, and
    /// re-log the same forbidden target. Bounded by the set of distinct relay
    /// URLs in stored/purgatory events, which the indexes already carry.
    rejected_relay_targets: HashSet<String>,
    /// Relays whose NIP-11 advertises GRASP-08 while this instance is public.
    ///
    /// Laundering guard: a public mirror must not present private credentials
    /// to such a relay nor hammer a service that will never admit it, so the
    /// target is parked before the dial (no WebSocket, no AUTH exchange).
    /// Held in memory only, re-probed at most once per process lifetime.
    private_service_relays: HashSet<String>,
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
    /// First auth-required CLOSED per subscription. rust-nostr retains the
    /// same ID while it answers NIP-42; a repeat means authentication did not
    /// authorize this query and becomes a bounded policy refusal.
    auth_required_attempts: HashSet<(String, SubscriptionId)>,
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
    connect_start_pacer: Arc<Mutex<Option<tokio::time::Instant>>>,
    history_tasks: history::HistoryTasks,
    history_result_tx: Option<tokio::sync::mpsc::Sender<history::HistoryResult>>,
    /// Relays whose subscription consolidation waits for in-flight batches to drain.
    deferred_consolidations: DeferredConsolidations,
    /// Remember refused live coverage until every overlapping pause expires.
    pending_live_repairs: HashSet<String>,
    /// Relays whose complete persistent filter set exceeds a learned remote
    /// byte cap, mapped to their next bounded catch-up deadline.
    byte_limited_live_relays: HashMap<String, Instant>,
    /// Per-relay snapshots for low-priority, EOSE-closing descendant queries.
    descendant_sync_rotations: HashMap<String, DescendantSyncRotation>,
    /// Auxiliary persistent descendant coverage, kept separate from the core
    /// desired set so it can be retired without replacing healthy core REQs.
    descendant_live_coverage: HashMap<String, DescendantLiveCoverage>,
    /// Round-robin cursor so only one relay performs descendant live-mode
    /// derivation and admission work per maintenance tick.
    descendant_relay_cursor: usize,
    /// Narrow GRASP-03 identity discovery and paced mailbox-probe state.
    nip65_discovery: Nip65DiscoveryState,
    /// Channel for disconnect notifications (set during run)
    disconnect_tx: Option<tokio::sync::mpsc::Sender<DisconnectNotification>>,
    /// Channel for EOSE notifications (set during run)
    eose_tx: Option<tokio::sync::mpsc::Sender<EoseNotification>>,
    /// Serializes CLOSED recovery and pending-batch cleanup through the actor.
    subscription_closed_tx: Option<tokio::sync::mpsc::Sender<SubscriptionClosedNotification>>,
    /// Returns connection outcomes to the sync actor for serialized state changes.
    connect_attempt_result_tx: Option<tokio::sync::mpsc::Sender<ConnectAttemptResult>>,
    nip65_discovery_result_tx: Option<tokio::sync::mpsc::Sender<Nip65DiscoveryResult>>,
    mailbox_probe_result_tx: Option<tokio::sync::mpsc::Sender<MailboxProbeResult>>,
    /// Channel for broadcasting shutdown signal to all background tasks
    shutdown_tx: Option<broadcast::Sender<()>>,
    /// Prometheus metrics for sync operations (None if metrics disabled)
    metrics: Option<SyncMetrics>,
    /// GRASP-P private-repo sync state (unused unless GRASP-P is enabled).
    grasp_p: grasp_p_sync::GraspPSyncState,
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
        private_access: Option<PrivateAccess>,
        grasp08_peers: Option<crate::private::Grasp08Peers>,
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

        let proactive_participant_authors = write_policy.proactive_participant_authors();
        let configured_private_members = config
            .parse_private_members()
            .expect("private members were validated before SyncManager construction")
            .into_iter()
            .collect();
        Self {
            bootstrap_relay_url,
            service_domain,
            database,
            write_policy,
            purgatory,
            local_relay,
            config: config.clone(),
            repo_sync_index: Arc::new(RwLock::new(HashMap::new())),
            root_candidate_index: Arc::new(RwLock::new(HashMap::new())),
            proactive_participant_authors,
            private_access,
            grasp08_peers,
            configured_private_members,
            relay_owners: HashMap::new(),
            relay_sync_index: Arc::new(RwLock::new(HashMap::new())),
            pending_sync_index: Arc::new(RwLock::new(HashMap::new())),
            rejected_events_index,
            connections: HashMap::new(),
            nip65_discovery_only_relays: HashSet::new(),
            pagination_sessions: HashMap::new(),
            rejected_relay_targets: HashSet::new(),
            private_service_relays: HashSet::new(),
            dependency_refetch_attempts: Arc::new(std::sync::Mutex::new(HashMap::new())),
            missing_event_recovery: Arc::new(std::sync::Mutex::new(
                missing_events::MissingEventRecoveryIndex::default(),
            )),
            purgatory_dependency_attempts: HashMap::new(),
            dependency_relay_deadlines: HashMap::new(),
            auth_required_attempts: HashSet::new(),
            health_tracker: Arc::new(RelayHealthTracker::new(config)),
            next_batch_id: 0,
            next_connect_attempt_token: 0,
            in_flight_connect_attempts: HashMap::new(),
            connect_attempt_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECT_ATTEMPTS)),
            connect_start_pacer: Arc::new(Mutex::new(None)),
            history_tasks: history::HistoryTasks::default(),
            history_result_tx: None,
            deferred_consolidations: DeferredConsolidations::default(),
            pending_live_repairs: HashSet::new(),
            byte_limited_live_relays: HashMap::new(),
            descendant_sync_rotations: HashMap::new(),
            descendant_live_coverage: HashMap::new(),
            descendant_relay_cursor: 0,
            nip65_discovery: Nip65DiscoveryState::default(),
            disconnect_tx: None,
            eose_tx: None,
            subscription_closed_tx: None,
            connect_attempt_result_tx: None,
            nip65_discovery_result_tx: None,
            mailbox_probe_result_tx: None,
            shutdown_tx: None,
            metrics: sync_metrics,
            grasp_p: grasp_p_sync::GraspPSyncState::default(),
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

        // A local push or another relay can persist a requested event without
        // another SDK Event notification. Snapshot only the last subscription's
        // unaccounted IDs, then release the index lock before database I/O so the
        // event processor can continue recording concurrent deliveries.
        let locally_checkable: Vec<EventId> = {
            let pending = self.pending_sync_index.read().await;
            pending
                .get(relay_url)
                .and_then(|batches| {
                    batches.iter().find(|batch| {
                        batch.sync_method == SyncMethod::Negentropy
                            && batch.outstanding_subs.len() == 1
                            && batch.outstanding_subs.contains(&sub_id)
                    })
                })
                .and_then(|batch| {
                    batch
                        .requested_event_ids
                        .as_ref()
                        .zip(batch.received_event_ids.as_ref())
                })
                .map(|(requested, received)| requested.difference(received).copied().collect())
                .unwrap_or_default()
        };
        let mut locally_stored = HashSet::new();
        // Bound each query's payload allocation, and never issue an empty ID
        // filter (which would query the entire database).
        for chunk in locally_checkable.chunks(1000) {
            match self
                .database
                .query(Filter::new().ids(chunk.iter().copied()))
                .await
            {
                Ok(events) => locally_stored.extend(events.into_iter().map(|event| event.id)),
                Err(error) => {
                    tracing::warn!(relay = %relay_url, %error,
                        "Failed to check local storage for historic hydration; unresolved IDs remain pending");
                }
            }
        }

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

        // Check for pagination using this relay connection session's observed page sizes and
        // verified NIP-11 default-limit hint.
        if let Some(pagination_state) = batch.pagination_state.remove(&sub_id) {
            let next_page = pagination_state.next_page(
                self.pagination_sessions
                    .entry(relay_url.to_string())
                    .or_default(),
            );
            if let Some(next_page) = next_page {
                let next_filters = next_page.filters();
                let relay_url_for_pagination = relay_url.to_string();
                let batch_id = batch.batch_id;
                tracing::info!(
                    relay = %relay_url,
                    sub_id = %sub_id,
                    batch_id,
                    filter_count = next_filters.len(),
                    "Grouped subscription hit pagination threshold, fetching next page"
                );

                let new_sub_id = SubscriptionId::generate();
                batch.outstanding_subs.insert(new_sub_id.clone());
                let class = next_page.request_class();
                batch.pagination_state.insert(new_sub_id.clone(), next_page);
                drop(pending);
                self.spawn_history_queries(
                    &relay_url_for_pagination,
                    batch_id,
                    vec![(new_sub_id, next_filters, class)],
                    true,
                )
                .await;
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
                (&batch.requested_event_ids, &mut batch.received_event_ids)
            {
                received.extend(locally_stored);
                // The SDK can suppress repeated Event notifications for payloads
                // it already holds. Retained policy decisions still prove these
                // IDs were delivered, even without another stream notification.
                received.extend(
                    requested
                        .iter()
                        .copied()
                        .filter(|id| self.rejected_events_index.is_dependency_pending(id)),
                );
                // GRASP-P seam: so do GRASP-P's own retained decisions.
                received.extend(self.grasp_p_settled_ids(requested));
                let missing: Vec<EventId> = requested.difference(received).cloned().collect();

                if !missing.is_empty() {
                    let requested_count = requested.len();
                    let received_count = received.len();
                    let retry_count = batch.retry_count;
                    let initial_hydration_counts = batch
                        .initial_hydration_counts
                        .unwrap_or((requested_count, received_count));
                    if retry_count == 0 {
                        batch.initial_hydration_counts = Some(initial_hydration_counts);
                    }

                    // A semantic fallback is reserved for relays whose first exact-ID fetch is
                    // materially incompatible with their advertised inventory. Small residuals
                    // can be caused by indexing lag, expiry, or concurrent deletion and must not
                    // disable NIP-77 for an otherwise healthy relay.
                    if retry_count > 0
                        && received_count == 0
                        && should_use_semantic_fallback(
                            initial_hydration_counts.0,
                            initial_hydration_counts.1,
                        )
                    {
                        tracing::info!(
                            relay = %relay_url,
                            batch_id = batch.batch_id,
                            retry_count = retry_count,
                            requested_count = requested_count,
                            missing_count = missing.len(),
                            initial_requested_count = initial_hydration_counts.0,
                            initial_received_count = initial_hydration_counts.1,
                            missing_ids_sample = ?missing.iter().take(5).map(|id| id.to_hex()).collect::<Vec<_>>(),
                            "Negentropy exact-ID hydration delivered at most 10% of a material batch. \
                             Marking relay as incompatible with negentropy hydration and falling back to REQ+EOSE."
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

                        let mut new_sub_ids = HashSet::new();
                        if let Some(conn) = self.connections.get(&relay_url_for_fallback) {
                            for filter_group in group_filters_for_req(&fallback_filters) {
                                match conn
                                    .subscribe_filters(
                                        filter_group,
                                        TransientRequestClass::NegentropyFallback,
                                    )
                                    .await
                                {
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
                            if fallback_filters.is_empty() {
                                tracing::info!(
                                    relay = %relay_url_for_fallback,
                                    batch_id,
                                    missing_count,
                                    pending_recovery = register_outcome.pending_total,
                                    "Batch has no semantic fallback filters; bounded missing-event recovery scheduled"
                                );
                            } else {
                                tracing::error!(
                                    relay = %relay_url_for_fallback,
                                    batch_id,
                                    missing_count,
                                    pending_recovery = register_outcome.pending_total,
                                    "Failed to create REQ+EOSE fallback subscriptions - completing batch with partial results; bounded missing-event recovery scheduled"
                                );
                            }

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

                    if retry_count > 0 && received_count == 0 {
                        let relay_url_for_recovery = relay_url.to_string();
                        let batch_id = batch.batch_id;
                        let missing_count = missing.len();

                        drop(pending);

                        let relay_already_degraded = {
                            let index = self.relay_sync_index.read().await;
                            index
                                .get(&relay_url_for_recovery)
                                .map(|state| state.historic_sync_had_failures)
                                .unwrap_or(false)
                        };
                        let register_outcome =
                            self.missing_event_recovery.lock().unwrap().register(
                                &relay_url_for_recovery,
                                batch_id,
                                missing.iter().copied(),
                                relay_already_degraded,
                                Instant::now(),
                            );
                        tracing::warn!(
                            relay = %relay_url_for_recovery,
                            batch_id = batch_id,
                            retry_count = retry_count,
                            missing_count = missing_count,
                            pending_recovery = register_outcome.pending_total,
                            "Negentropy residual retry made no progress; retaining NIP-77 and scheduling bounded missing-event recovery"
                        );

                        let mut pending = self.pending_sync_index.write().await;
                        if let Some(batches) = pending.get_mut(&relay_url_for_recovery) {
                            if let Some(idx) = batches.iter().position(|b| b.batch_id == batch_id) {
                                let mut completed_batch = batches.remove(idx);
                                completed_batch.failed = true;
                                if batches.is_empty() {
                                    pending.remove(&relay_url_for_recovery);
                                }
                                drop(pending);
                                self.confirm_batch(&relay_url_for_recovery, completed_batch)
                                    .await;
                            }
                        }
                        return;
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
                    let retry_subscriptions: Vec<_> = missing
                        .chunks(300)
                        .map(|chunk| {
                            (
                                SubscriptionId::generate(),
                                Filter::new().ids(chunk.iter().copied()),
                            )
                        })
                        .collect();
                    {
                        let mut pending = self.pending_sync_index.write().await;
                        if let Some(batch) =
                            pending.get_mut(&relay_url_for_retry).and_then(|batches| {
                                batches.iter_mut().find(|batch| batch.batch_id == batch_id)
                            })
                        {
                            register_negentropy_hydration_attempt(
                                batch,
                                retry_subscriptions
                                    .iter()
                                    .map(|(subscription_id, _)| subscription_id.clone()),
                                missing.iter().copied(),
                                true,
                            );
                        }
                    }

                    self.spawn_history_queries(
                        &relay_url_for_retry,
                        batch_id,
                        retry_subscriptions
                            .into_iter()
                            .map(|(id, filter)| {
                                (id, vec![filter], TransientRequestClass::NegentropyRetry)
                            })
                            .collect(),
                        false,
                    )
                    .await;
                    return;
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

    /// Drive bounded recovery of events relays reported during negentropy
    /// reconciliation but failed to deliver on exact-ID fetches.
    ///
    /// Runs on the sync maintenance timer. For each relay with pending IDs:
    /// 1. IDs already stored or retained by policy/dependency tracking are
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
            let mut satisfied: Vec<EventId> = match self
                .database
                .query(Filter::new().ids(pending.iter().copied()))
                .await
            {
                Ok(events) => events.into_iter().map(|event| event.id).collect(),
                Err(_) => Vec::new(),
            };
            satisfied.extend(
                pending
                    .iter()
                    .copied()
                    .filter(|id| self.rejected_events_index.is_dependency_pending(id)),
            );
            if !satisfied.is_empty() {
                let outcome = self
                    .missing_event_recovery
                    .lock()
                    .unwrap()
                    .clear_satisfied(&relay_url, &satisfied);
                tracing::info!(
                    relay = %relay_url,
                    satisfied = satisfied.len(),
                    "Pending missing events accounted for by local storage or retained policy decisions"
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
    /// passed through the normal write policy. An ID counts as recovered only
    /// once it has a terminal outcome or is retained for dependency recovery.
    /// Untracked policy failures and persistence errors remain pending.
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
            missing_ids_sample = ?attempt.ids.iter().take(5).map(EventId::to_hex).collect::<Vec<_>>(),
            "Retrying events missing from an incomplete historic sync batch"
        );
        if let Some(metrics) = metrics.as_ref() {
            metrics.record_hydration_events(&relay_url, "recovery", "requested", requested.len());
        }

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

        let mut delivered = HashSet::new();
        let mut recovered = HashSet::new();
        for event in events {
            if !requested.contains(&event.id) {
                continue;
            }
            if !delivered.insert(event.id) {
                continue;
            }
            if let Some(metrics) = metrics.as_ref() {
                metrics.record_hydration_events(&relay_url, "recovery", "delivered", 1);
            }
            // A retained policy decision proves delivery. Keep dependency-sensitive
            // entries for authorization-triggered reprocessing, not payload retries.
            if rejected_events_index.contains(&event.id) {
                let dependency_pending = rejected_events_index.is_dependency_pending(&event.id);
                tracing::debug!(
                    relay = %relay_url,
                    event_id = %event.id,
                    dependency_pending,
                    "Recovered missing event already tracked as rejected, skipping re-processing"
                );
                if let Some(metrics) = metrics.as_ref() {
                    metrics.record_hydration_events(&relay_url, "recovery", "rejected_cached", 1);
                }
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
            if let Some(metrics) = metrics.as_ref() {
                metrics.record_hydration_events(
                    &relay_url,
                    "recovery",
                    result.hydration_outcome(),
                    1,
                );
                if result == ProcessResult::Saved {
                    metrics.record_synced_event();
                }
            }
            if result.is_rejected() || result == ProcessResult::PersistenceError {
                tracing::debug!(
                    relay = %relay_url,
                    event_id = %event.id,
                    outcome = result.hydration_outcome(),
                    terminal = result.is_terminally_accounted(),
                    "Recovered missing event was not persisted"
                );
            }
            if result.is_hydration_accounted(&event.id, &rejected_events_index) {
                recovered.insert(event.id);
            }
        }

        if let Some(metrics) = metrics.as_ref() {
            metrics.record_hydration_events(
                &relay_url,
                "recovery",
                "not_delivered",
                requested.len().saturating_sub(delivered.len()),
            );
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
            AttemptOutcome::SomeExpired {
                expired,
                remaining,
                attempts,
                next_attempt_in,
            } => {
                tracing::warn!(
                    relay = %relay_url, expired, remaining, attempts,
                    next_attempt_in_secs = next_attempt_in.as_secs_f64(),
                    "Missing-event IDs exhausted their fetch budget; continuing recovery of younger IDs"
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
                    "Missing-event recovery expired after per-ID fetch budgets were exhausted - relay remains ConnectedHistoricSyncFailures until daily sync"
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
    async fn confirm_batch(&mut self, relay_url: &str, batch: PendingBatch) {
        let batch_id = batch.batch_id;
        let full_repos_count = batch.items.repos.len();
        let state_only_repos_count = batch.items.state_only_repos.len();
        let events_count = batch.items.root_events.len();
        let sync_method = batch.sync_method;
        let is_generic_filter = batch.purpose == PendingBatchPurpose::Announcements;

        if batch.purpose == PendingBatchPurpose::Descendants {
            let succeeded = !batch.failed;
            if let Some(rotation) = self.descendant_sync_rotations.get_mut(relay_url) {
                rotation.mark_completed(batch_id, succeeded, Instant::now());
            }
            tracing::debug!(
                relay = %relay_url,
                batch_id,
                succeeded,
                "Descendant historic query reached terminal batch state"
            );
        }

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
            if batch.failed && batch.purpose != PendingBatchPurpose::Descendants {
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

            tracing::debug!(
                relay = %relay_url,
                batch_id = batch_id,
                purpose = ?batch.purpose,
                sync_method = ?sync_method,
                full_repos_confirmed = full_repos_count,
                state_only_repos_confirmed = state_only_repos_count,
                root_events_confirmed = events_count,
                root_events_sample = ?batch.items.root_events.iter().take(LOG_COLLECTION_SAMPLE_SIZE).map(|id| id.to_hex()).collect::<Vec<_>>(),
                total_full_repos = state.repos.len(),
                total_state_only_repos = state.state_only_repos.len(),
                total_root_events = state.root_events.len(),
                all_root_events_sample = ?state.root_events.iter().take(LOG_COLLECTION_SAMPLE_SIZE).map(|id| id.to_hex()).collect::<Vec<_>>(),
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

        // Batch completion already runs inside the sync actor and all index
        // guards are released. Process a ready deferral directly instead of
        // retaining self-addressed wakeups in another queue.
        if self.deferred_consolidations.contains(relay_url) {
            // Consolidation can synchronously complete an empty historic
            // batch, so erase that finite recursive future from the type.
            Box::pin(self.process_deferred_consolidation(relay_url)).await;
        }

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
        self.history_tasks.cancel_relay(relay_url);
        tracing::info!(relay = %relay_url, "Starting daily sync");
        self.cancel_deferred_consolidation(relay_url, "daily sync reset");
        let _ = self
            .close_descendant_live_coverage(relay_url, "daily sync reset")
            .await;
        self.descendant_sync_rotations.remove(relay_url);

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
        // The independent terminal-control listener has already released
        // transient resources. These actor notifications may therefore apply
        // bounded backpressure without stranding subscription-ledger slots.
        let (eose_tx, mut eose_rx) = lifecycle_notification_channel::<EoseNotification>();
        let (subscription_closed_tx, mut subscription_closed_rx) =
            lifecycle_notification_channel::<SubscriptionClosedNotification>();

        // Connection workers never mutate manager state. At most the global
        // connection-attempt cap can complete while the actor is busy.
        let (connect_attempt_result_tx, mut connect_attempt_result_rx) =
            mpsc::channel::<ConnectAttemptResult>(MAX_CONCURRENT_CONNECT_ATTEMPTS);

        let (history_result_tx, mut history_result_rx) = mpsc::channel(8);
        self.history_result_tx = Some(history_result_tx);

        let (nip65_discovery_result_tx, mut nip65_discovery_result_rx) =
            mpsc::channel::<Nip65DiscoveryResult>(1);
        let (mailbox_probe_result_tx, mut mailbox_probe_result_rx) =
            mpsc::channel::<MailboxProbeResult>(1);

        // 4b. Create shutdown broadcast channel for graceful shutdown
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);

        // 5. Spawn self-subscriber with shutdown receiver
        let self_subscriber = SelfSubscriber::new(
            format!(
                "ws://{}{}",
                self.config.bind_address,
                self.config.public_path("/")
            ),
            self.service_domain.clone(),
            Arc::clone(&self.repo_sync_index),
            Arc::clone(&self.root_candidate_index),
            action_tx,
            self.database.clone(),
            self.local_relay.clone(),
        );
        let subscriber_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move { self_subscriber.run(Some(subscriber_shutdown)).await });

        // 5b. Store channel senders for use by handlers
        self.disconnect_tx = Some(disconnect_tx.clone());
        self.eose_tx = Some(eose_tx.clone());
        self.subscription_closed_tx = Some(subscription_closed_tx);
        self.connect_attempt_result_tx = Some(connect_attempt_result_tx);
        self.nip65_discovery_result_tx = Some(nip65_discovery_result_tx);
        self.mailbox_probe_result_tx = Some(mailbox_probe_result_tx);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // 6. Connect to bootstrap relay if configured
        if let Some(ref bootstrap_url) = self.bootstrap_relay_url.clone() {
            match canonical_relay_key(bootstrap_url) {
                Ok(relay_url) => {
                    if self.register_relay(relay_url.clone(), true, false).await {
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

        // 11b. GRASP-P registration index and full re-issue timers (only when
        // GRASP-P is enabled).
        grasp_p_sync::spawn_timers(&sync_manager, &shutdown_tx).await;

        // 12. Main loop - handle actions, lifecycle notifications, and worker results
        loop {
            // Wait for an event without holding the lock
            tokio::select! {
                // Lifecycle completions release resources and unblock later
                // work. Drain them ahead of a continuously-ready discovery
                // queue so retirement cannot remain half-finished under load.
                biased;
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
                closed = subscription_closed_rx.recv() => {
                    if let Some(notification) = closed {
                        let mut manager = sync_manager.lock().await;
                        if notification.timed_out {
                            manager.handle_request_timeout(notification).await;
                            continue;
                        }
                        // The per-relay forwarder queues EOSE before a later
                        // CLOSED, but these inboxes are selected independently.
                        // Apply queued successes first so a CLOSE acknowledgement
                        // cannot abort an already completed historic request.
                        let queued_eose = eose_rx.len();
                        for _ in 0..queued_eose {
                            let Ok(eose) = eose_rx.try_recv() else { break };
                            manager.handle_eose(&eose.relay_url, eose.sub_id).await;
                        }
                        manager.handle_subscription_closed(
                            &notification.relay_url,
                            notification.subscription_id,
                            &notification.reason,
                            notification.generation,
                            notification.live_filter_count,
                        ).await;
                    }
                }
                result = mailbox_probe_result_rx.recv() => {
                    if let Some(result) = result {
                        let mut manager = sync_manager.lock().await;
                        manager.handle_mailbox_probe_result(result).await;
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
                result = history_result_rx.recv() => {
                    if let Some(result) = result {
                        sync_manager.lock().await.handle_history_result(result).await;
                    }
                }
                result = nip65_discovery_result_rx.recv() => {
                    if let Some(result) = result {
                        let mut manager = sync_manager.lock().await;
                        manager.handle_nip65_discovery_result(result).await;
                    }
                }
                action = action_rx.recv() => {
                    match action {
                        Some(add_filters) => {
                            // SelfSubscriber actions are dirty-relay signals.
                            // Recompute against current pending and confirmed
                            // state instead of trusting a queued full-index
                            // snapshot that may already be stale.
                            let mut manager = sync_manager.lock().await;
                            // A dirty relay can contain a newly accepted root
                            // or participant. Refresh the local inventory now;
                            // the per-author retry deadlines still bound remote
                            // NIP-65 queries when only repository state changed.
                            manager.nip65_discovery.next_inventory_at = None;
                            manager
                                .recompute_new_sync_filters_for_relay(&add_filters.relay_url)
                                .await;
                            manager.schedule_nip65_discovery().await;
                        }
                        None => break,
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

        // The local self-subscriber already observes everything served here.
        // Enforce this at the shared AddFilters boundary too, because
        // purgatory recomputation creates actions without passing through the
        // self-subscriber's own-relay exclusion.
        if is_own_sync_target(&action.relay_url, &self.service_domain) {
            tracing::debug!(
                relay = %action.relay_url,
                service_domain = %self.service_domain,
                "Skipping sync action targeting this relay"
            );
            return;
        }

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

        // A relay first reached through NIP-65 may later become an ordinary
        // repository target. Promote that existing connection before reading
        // its state so subsequent reconnects and sync work use the full role.
        let promoted_from_discovery = self.nip65_discovery_only_relays.remove(&action.relay_url);
        if promoted_from_discovery {
            tracing::info!(
                relay = %action.relay_url,
                "Promoting NIP-65 discovery connection to repository sync"
            );
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
                if self
                    .register_relay(action.relay_url.clone(), false, false)
                    .await
                {
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
        if self
            .health_tracker
            .is_subscription_paused(&action.relay_url)
        {
            tracing::debug!(
                relay = %action.relay_url,
                full_repos = action.items.repos.len(),
                state_only_repos = action.items.state_only_repos.len(),
                root_events = action.items.root_events.len(),
                "Skipping AddFilters for rate-limited relay, will recompute after cooldown"
            );
            return;
        }

        // Subscribe to each filter and collect subscription IDs
        tracing::info!(
            relay = %action.relay_url,
            filter_count = action.filters.len(),
            full_repo_count = action.items.repos.len(),
            state_only_repo_count = action.items.state_only_repos.len(),
            root_event_count = action.items.root_events.len(),
            "handle_add_filters: calling sync_live and historic_sync"
        );

        let essential_live = filters::build_essential_live_filters(
            &action.items.repos,
            &action.items.state_only_repos,
            &action.items.root_events,
            None,
        );
        if let Err(error) = self.sync_live(&action.relay_url, &essential_live).await {
            tracing::warn!(
                relay = %action.relay_url,
                %error,
                "Live coverage could not be extended; continuing bounded historic sync"
            );
            if error.starts_with("Minimum-churn live extension needs")
                || error.starts_with("Minimum-churn live extension exceeds")
            {
                let has_pending_batches = self.has_pending_batches(&action.relay_url).await;
                if self
                    .deferred_consolidations
                    .request(&action.relay_url, has_pending_batches)
                {
                    let _ = self.consolidate(&action.relay_url).await;
                } else {
                    tracing::info!(
                        relay = %action.relay_url,
                        "Minimum-churn extension reached capacity; full consolidation deferred until pending batches drain"
                    );
                }
            }
        }
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

        connection.set_timeout_sender(self.subscription_closed_tx.as_ref().unwrap().clone());
        let (event_tx, mut event_rx) =
            mpsc::channel::<RelayEvent>(relay_connection::RELAY_EVENT_BUFFER_CAPACITY);

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
        let subscription_closed_tx = self.subscription_closed_tx.as_ref().unwrap().clone();
        let metrics_clone = self.metrics.clone();
        let pending_sync_index = Arc::clone(&self.pending_sync_index);
        let health_tracker = Arc::clone(&self.health_tracker);
        let rejected_events_index = Arc::clone(&self.rejected_events_index);

        tokio::spawn(async move {
            let mut disconnect_sent = false;
            let mut pipeline_window = EventPipelineWindow::default();

            while let Some(relay_event) = event_rx.recv().await {
                match relay_event {
                    RelayEvent::Event(event, subscription_id, data_lane_arrival) => {
                        let queue_delay = data_lane_arrival.elapsed();
                        let processing_started = std::time::Instant::now();
                        // Count raw deliveries before deduplication or write policy. Relays spend
                        // their result allowance on every matching delivery, including events we
                        // route to purgatory, reject, or have already stored; pagination must use
                        // that same stream for both its page count and `until` cursor.
                        {
                            let mut pending = pending_sync_index.write().await;
                            if let Some(batches) = pending.get_mut(&relay_url_clone) {
                                for batch in batches.iter_mut() {
                                    if let Some(state) =
                                        batch.pagination_state.get_mut(&subscription_id)
                                    {
                                        state.record_event(&event);
                                    }
                                }
                            }
                        }

                        // Cached decisions still account for delivery to this batch.
                        // Keep dependency entries available for later authorization changes.
                        let result = if ((event.kind == Kind::GitRepoAnnouncement
                            || event.kind == Kind::RepoState)
                            && rejected_events_index.contains(&event.id))
                            || Self::grasp_p_previously_rejected(&write_policy, &event)
                        {
                            ProcessResult::Rejected(PolicyRejection::PreviouslyRejected)
                        } else {
                            Self::process_event_static(
                                &event,
                                &relay_url_clone,
                                &database,
                                &write_policy,
                                &local_relay,
                                &rejected_events_index,
                                crate::nostr::persistence::SaveContext::RelaySync,
                            )
                            .await
                        };
                        if let Some(ref metrics) = metrics_clone {
                            metrics.record_hydration_events(
                                &relay_url_clone,
                                "stream",
                                "delivered",
                                1,
                            );
                            metrics.record_hydration_events(
                                &relay_url_clone,
                                "stream",
                                result.hydration_outcome(),
                                1,
                            );
                        }
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

                        // Account for delivered events saved locally or retained under policy.
                        // Dependency readiness is separate from the source's transport health.
                        if result.is_hydration_accounted(&event.id, &rejected_events_index) {
                            let mut pending = pending_sync_index.write().await;
                            if let Some(batches) = pending.get_mut(&relay_url_clone) {
                                for batch in batches.iter_mut() {
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
                        pipeline_window.record(result, queue_delay, processing_started.elapsed());
                        pipeline_window.report_if_due(&relay_url_clone, event_rx.len());
                    }
                    RelayEvent::EndOfStoredEvents(sub_id, data_lane_arrival) => {
                        let data_lane_delay = data_lane_arrival.elapsed();
                        if data_lane_delay >= std::time::Duration::from_secs(5) {
                            tracing::info!(
                                relay = %relay_url_clone,
                                sub_id = %sub_id,
                                data_lane_delay_seconds = data_lane_delay.as_secs_f64(),
                                queue_depth = event_rx.len(),
                                queue_capacity = relay_connection::RELAY_EVENT_BUFFER_CAPACITY,
                                "EOSE reached sync manager after data-lane delay"
                            );
                        }
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
                        if is_rate_limit_message(&notice) {
                            // The connection control lane records the cooldown;
                            // replaying it here could restart an expired episode
                            // after a delayed event queue drains.
                            tracing::debug!(
                                relay = %relay_url_clone,
                                notice = %notice,
                                "Rate limiting NOTICE detected from relay"
                            );

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
                    RelayEvent::Closed {
                        subscription_id,
                        reason,
                        live_generation,
                        live_filter_count,
                    } => {
                        // CLOSED message means one subscription was closed, not the whole connection
                        // This is normal behavior (e.g., when historic_sync completes)
                        tracing::debug!(
                            relay = %relay_url_clone,
                            sub_id = %subscription_id,
                            reason = %reason,
                            "Relay closed a subscription (not a connection close)"
                        );
                        if is_rate_limit_message(&reason)
                            && !is_filter_count_refusal(&reason)
                            && subscription_state_byte_limit(&reason).is_none()
                        {
                            tracing::debug!(
                                relay = %relay_url_clone,
                                reason = %reason,
                                "Rate limiting CLOSED detected from relay"
                            );
                            if let Some(ref metrics) = metrics_clone {
                                metrics.record_health_state(
                                    &relay_url_clone,
                                    health_tracker.get_state(&relay_url_clone),
                                );
                            }
                        }
                        let _ = subscription_closed_tx
                            .send(SubscriptionClosedNotification {
                                relay_url: relay_url_clone.clone(),
                                subscription_id,
                                reason,
                                generation: live_generation,
                                live_filter_count,
                                timed_out: false,
                            })
                            .await;
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

        if self.nip65_discovery_only_relays.contains(relay_url) {
            tracing::info!(
                relay = %relay_url,
                "NIP-65 discovery connection ready without repository sync"
            );
            return;
        }

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
        self.history_tasks.cancel_relay(relay_url);
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
        let mut filters = vec![filters::build_announcement_filter(None)];
        // GRASP-P seam: the private filters, for a configured peer only.
        filters.extend(self.grasp_p_filters_for(relay_url));

        // Create live subscription for ongoing announcements
        if self.sync_live(relay_url, &filters).await.is_err() {
            return;
        }

        // Use historic_sync with empty PendingItems for generic filters
        // Generic filters (announcements) don't have associated repos or root_events
        let items = PendingItems::default();
        let _batch_id = self
            .historic_sync_with_options(
                relay_url,
                filters,
                items,
                since,
                PendingBatchPurpose::Announcements,
                false,
            )
            .await;
    }

    async fn sync_generic_history(&mut self, relay_url: &str, since: Option<Timestamp>) {
        let mut filters = vec![filters::build_announcement_filter(None)];
        // GRASP-P seam: the private filters, for a configured peer only.
        filters.extend(self.grasp_p_filters_for(relay_url));
        let _batch_id = self
            .historic_sync_with_options(
                relay_url,
                filters,
                PendingItems::default(),
                since,
                PendingBatchPurpose::Announcements,
                false,
            )
            .await;
    }

    /// Find the bounded transitive members of repository root threads.
    async fn descendant_thread_members(
        &self,
        root_events: &HashSet<EventId>,
    ) -> DescendantFrontier {
        recursive_descendant_frontier(
            &self.database,
            root_events,
            self.config.sync_recursive_descendant_limit,
        )
        .await
    }

    async fn close_descendant_live_coverage(
        &mut self,
        relay_url: &str,
        reason: &'static str,
    ) -> bool {
        let Some(coverage) = self.descendant_live_coverage.remove(relay_url) else {
            return true;
        };
        if let Some(connection) = self.connections.get(relay_url) {
            if let Err(error) = connection
                .close_live_subscriptions(&coverage.subscription_ids)
                .await
            {
                tracing::warn!(
                    relay = %relay_url,
                    %error,
                    reason,
                    "Could not retire auxiliary descendant live coverage"
                );
                self.descendant_live_coverage
                    .insert(relay_url.to_string(), coverage);
                return false;
            }
        }
        tracing::info!(
            relay = %relay_url,
            subscription_count = coverage.subscription_ids.len(),
            reason,
            "Retired auxiliary descendant live coverage"
        );
        true
    }

    async fn reconcile_descendant_mode(
        &mut self,
        relay_url: &str,
        target: &algorithms::RelaySyncNeeds,
    ) {
        let frontier = self.descendant_thread_members(&target.root_events).await;
        let historic_entries =
            tiered_auxiliary_filters(&target.repos, &target.root_events, &frontier, None);
        let live_since = Timestamp::from(
            Timestamp::now()
                .as_secs()
                .saturating_sub(DESCENDANT_FALLBACK_OVERLAP_SECS),
        );
        if let Some(connection) = self.connections.get(relay_url).cloned() {
            let (live_filters, rotated_filters) = split_live_tier_prefix(
                &historic_entries,
                connection.max_filters_per_req(),
                |groups| connection.can_admit_auxiliary_live_groups(groups),
            );
            let desired_live_filters: HashSet<_> =
                live_filters.iter().map(Filter::as_json).collect();
            if let Some(coverage) = self.descendant_live_coverage.get_mut(relay_url) {
                if desired_live_filters == coverage.desired_filters {
                    let max_filters = connection.max_filters_per_req();
                    let rotation = self
                        .descendant_sync_rotations
                        .entry(relay_url.to_string())
                        .or_default();
                    if rotation.coverage_fingerprint
                        != rotation_fingerprint(&rotated_filters, max_filters)
                    {
                        rotation.refresh(rotated_filters, max_filters);
                    }
                    coverage.fallback_filters = complete_auxiliary_fallback(&historic_entries);
                    return;
                }
            }
            if self.descendant_live_coverage.contains_key(relay_url)
                && !self
                    .close_descendant_live_coverage(relay_url, "tiered coverage changed")
                    .await
            {
                return;
            }
            let live_filters: Vec<_> = live_filters
                .into_iter()
                .map(|filter| filter.since(live_since))
                .collect();
            let groups = live_filter_groups(&live_filters, connection.max_filters_per_req());
            if !groups.is_empty() {
                match connection
                    .subscribe_auxiliary_live_filter_groups(groups)
                    .await
                {
                    Ok(subscription_ids) => {
                        // A relay can close any one member of this live set.
                        // Keep the complete frontier ready for rotation so
                        // the CLOSED path preserves every tier immediately,
                        // including those that had been live until now.
                        let fallback_filters = complete_auxiliary_fallback(&historic_entries);
                        let filter_count = live_filters.len();
                        let event_id_count = frontier.event_ids.len();
                        let coordinate_count = frontier.coordinates.len();
                        self.descendant_live_coverage.insert(
                            relay_url.to_string(),
                            DescendantLiveCoverage {
                                desired_filters: desired_live_filters,
                                fallback_filters,
                                subscription_ids: subscription_ids.clone(),
                            },
                        );
                        tracing::info!(
                            relay = %relay_url,
                            event_id_count,
                            coordinate_count,
                            filter_count,
                            subscription_count = subscription_ids.len(),
                            rotated_filter_count = rotated_filters.len(),
                            "Installed priority-bounded auxiliary live coverage"
                        );
                        // `limit:0` protects the future only. Pair every new
                        // live frontier with a complete EOSE-closing baseline
                        // so events stored before admission are not skipped.
                        let _ = self
                            .historic_sync_with_options(
                                relay_url,
                                historic_entries
                                    .iter()
                                    .map(|entry| entry.filter.clone())
                                    .collect(),
                                PendingItems::default(),
                                None,
                                PendingBatchPurpose::Descendants,
                                true,
                            )
                            .await;
                        let rotation = self
                            .descendant_sync_rotations
                            .entry(relay_url.to_string())
                            .or_default();
                        let max_filters = connection.max_filters_per_req();
                        if rotation.coverage_fingerprint
                            != rotation_fingerprint(&rotated_filters, max_filters)
                        {
                            rotation.refresh(rotated_filters, max_filters);
                        }
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(
                            relay = %relay_url,
                            %error,
                            "Descendant live admission failed; using historic rotation"
                        );
                    }
                }
            } else {
                tracing::info!(
                    relay = %relay_url,
                    filter_count = live_filters.len(),
                    "No auxiliary live tier fits while preserving historic capacity"
                );
            }
        }

        let rotated_filters: Vec<_> = historic_entries
            .into_iter()
            .map(|entry| entry.filter)
            .collect();
        let max_filters = self
            .connections
            .get(relay_url)
            .map(|connection| connection.max_filters_per_req())
            .unwrap_or(MAX_FILTERS_PER_REQ);
        let rotation = self
            .descendant_sync_rotations
            .entry(relay_url.to_string())
            .or_default();
        if rotation.coverage_fingerprint != rotation_fingerprint(&rotated_filters, max_filters) {
            rotation.refresh(rotated_filters, max_filters);
        }
    }

    async fn start_descendant_fallback(&mut self, relay_url: &str) {
        let Some((filter_index, filters, until)) = self
            .descendant_sync_rotations
            .get(relay_url)
            .and_then(|rotation| rotation.next_request(Timestamp::now(), Instant::now()))
        else {
            return;
        };
        let filter_count = self.descendant_sync_rotations[relay_url].filters.len();
        if let Some(batch_id) = self
            .historic_sync_with_options(
                relay_url,
                filters,
                PendingItems::default(),
                None,
                PendingBatchPurpose::Descendants,
                true,
            )
            .await
        {
            if let Some(rotation) = self.descendant_sync_rotations.get_mut(relay_url) {
                rotation.mark_started(batch_id, filter_index, until);
            }
            tracing::info!(
                relay = %relay_url,
                batch_id,
                filter_index,
                filter_count,
                until = until.as_secs(),
                "Started queued descendant fallback query"
            );
        }
    }

    /// Reconcile one live-mode decision and advance every constrained relay by
    /// at most one EOSE-closing request on each five-second maintenance tick.
    async fn tick_descendant_sync(&mut self) {
        let targets = self.derive_targets().await;
        let states = self.relay_sync_index.read().await;
        let mut relay_urls: Vec<String> = targets
            .iter()
            .filter(|(relay_url, needs)| {
                (!needs.repos.is_empty() || !needs.root_events.is_empty())
                    && states.get(*relay_url).is_some_and(|state| {
                        matches!(
                            state.connection_status,
                            ConnectionStatus::Connected
                                | ConnectionStatus::ConnectedHistoricSyncFailures
                        )
                    })
                    && !self.health_tracker.is_subscription_paused(relay_url)
            })
            .map(|(relay_url, _)| relay_url.clone())
            .collect();
        drop(states);
        relay_urls.sort_unstable();
        if relay_urls.is_empty() {
            return;
        }

        let reconcile_relay = relay_urls[self.descendant_relay_cursor % relay_urls.len()].clone();
        self.descendant_relay_cursor = self.descendant_relay_cursor.wrapping_add(1);
        self.reconcile_descendant_mode(&reconcile_relay, &targets[&reconcile_relay])
            .await;

        let constrained: Vec<String> = relay_urls
            .into_iter()
            .filter(|relay_url| self.descendant_sync_rotations.contains_key(relay_url))
            .collect();
        for relay_url in constrained {
            self.start_descendant_fallback(&relay_url).await;
        }
    }

    /// Build the complete persistent coverage for one connection. L1 must be
    /// admitted in the same transaction as rebuilt L2/L3 so a tight relay
    /// budget cannot leave a successful generic REQ hiding partial repo
    /// coverage.
    async fn complete_live_filters(
        &self,
        relay_url: &str,
        since: Option<Timestamp>,
    ) -> Vec<Filter> {
        let mut filters = vec![filters::build_announcement_filter(None)];
        // GRASP-P seam: the private filters, for a configured peer only.
        filters.extend(self.grasp_p_filters_for(relay_url));
        let index = self.relay_sync_index.read().await;
        if let Some(state) = index.get(relay_url) {
            filters.extend(filters::build_essential_live_filters(
                &state.repos,
                &state.state_only_repos,
                &state.root_events,
                since,
            ));
        }
        filters
    }

    async fn desired_items_for_relay(&self, relay_url: &str) -> PendingItems {
        let target = self
            .derive_targets()
            .await
            .remove(relay_url)
            .unwrap_or_default();
        PendingItems {
            repos: target.repos,
            state_only_repos: target.state_only_repos,
            root_events: target.root_events,
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
    /// Basic connection health is managed by the connection worker and its
    /// stability timer. This method handles reconnect-specific sync and metrics.
    async fn quick_reconnect(&mut self, relay_url: &str, since: Timestamp) {
        self.history_tasks.cancel_relay(relay_url);
        self.cancel_deferred_consolidation(relay_url, "quick reconnect");

        // Step 1: Clear PendingSyncIndex for this relay
        // Old subscriptions are dead after disconnect
        {
            let mut pending = self.pending_sync_index.write().await;
            pending.remove(relay_url);
        }

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

        let complete_live = self.complete_live_filters(relay_url, Some(since)).await;
        if self.sync_live(relay_url, &complete_live).await.is_err() {
            tracing::warn!(
                relay = %relay_url,
                "Complete live coverage did not fit on reconnect; historic work deferred"
            );
            return;
        }
        self.sync_generic_history(relay_url, announcement_since)
            .await;

        // Step 4: compute_actions for any NEW items discovered while disconnected
        self.recompute_new_sync_filters_for_relay(relay_url).await;
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
    async fn register_relay(
        &mut self,
        relay_url: String,
        is_bootstrap: bool,
        nip65_discovery_only: bool,
    ) -> bool {
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

        // A GRASP-08 private service is not a sync target for a public
        // instance; never re-enter the connection lifecycle for it.
        if !self.config.private_mode && self.private_service_relays.contains(&relay_url) {
            tracing::trace!(
                relay = %relay_url,
                "Skipping registration of GRASP-08 private-service relay"
            );
            return false;
        }

        // An ordinary sync registration upgrades a connection that was first
        // opened only for NIP-65 discovery. Discovery must never downgrade an
        // existing repository source.
        if !nip65_discovery_only {
            self.nip65_discovery_only_relays.remove(&relay_url);
        }

        // Create RelayConnection if not exists
        if !self.connections.contains_key(&relay_url) {
            // GRASP-P seam: a configured peer on a private link has a policy of its own.
            let policy = self
                .grasp_p_peer_policy(&relay_url)
                .unwrap_or_else(|| self.outbound_target_policy());
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

            // The relay owner key answers outbound NIP-42 challenges. Sync
            // must keep working without it, so a missing key degrades to an
            // unauthenticated connection instead of aborting registration.
            let keys = match self.config.relay_owner_keys() {
                Ok(keys) => Some(keys),
                Err(error) => {
                    tracing::warn!(
                        relay = %relay_url,
                        error = %error,
                        "Relay owner key unavailable; outbound NIP-42 authentication disabled for this connection"
                    );
                    None
                }
            };

            let connection = RelayConnection::new_with_database(
                relay_url.clone(),
                Arc::clone(&self.database),
                keys,
                source,
                policy,
            )
            .with_health_tracker(Arc::clone(&self.health_tracker))
            // GRASP-P seam: the address check on every connection of a GRASP-P
            // node, duplicate forwarding on a configured peer's only.
            .with_grasp_p_address_check(self.config.private_repos_enable)
            .with_duplicate_event_forwarding(self.grasp_p_is_peer(&relay_url));
            self.connections.insert(relay_url.clone(), connection);
            if nip65_discovery_only {
                self.nip65_discovery_only_relays.insert(relay_url.clone());
            }
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
        if self
            .health_tracker
            .naughty_list()
            .is_some_and(|naughty_list| naughty_list.is_naughty(&relay_url))
            // GRASP-P seam: the naughty list does not mute a configured peer.
            && self.grasp_p_naughty_mute_applies(&relay_url)
        {
            tracing::debug!(
                relay = %relay_url,
                "Suppressing connection attempt for naughty relay"
            );
            return;
        }
        if !self.config.private_mode && self.private_service_relays.contains(&relay_url) {
            tracing::debug!(
                relay = %relay_url,
                "Suppressing connection attempt for GRASP-08 private-service relay"
            );
            return;
        }
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
        let start_pacer = self.connect_start_pacer.clone();
        let timeout = self.health_tracker.base_backoff_secs();
        let private_mode = self.config.private_mode;
        let Some(mut shutdown_rx) = self.shutdown_tx.as_ref().map(|sender| sender.subscribe())
        else {
            tracing::error!(relay = %relay_url, "Connection scheduler has no shutdown signal");
            return;
        };
        tokio::spawn(async move {
            let permit = tokio::select! {
                permit = begin_connect_attempt(semaphore, start_pacer, health_tracker, &relay_url) => permit,
                _ = shutdown_rx.recv() => return,
            };
            let Some(_permit) = permit else {
                return;
            };
            let outcome = tokio::select! {
                outcome = async {
                    // A GRASP-08 private service must be recognized before
                    // the dial so no WebSocket or AUTH exchange ever reaches
                    // it. Only public instances park, so only they pay the
                    // extra pre-dial probe; session hints still come from
                    // the post-connect fetch below, which runs on every
                    // attempt so they stay per-session.
                    if !private_mode && connection.preflight_limit_hints().await.grasp08 {
                        return ConnectAttemptOutcome::PrivateService;
                    }
                    match connection.connect(timeout).await {
                        Ok(()) => {
                            let hints = connection.fetch_limit_hints().await;
                            ConnectAttemptOutcome::Connected {
                                advertised_default_limit: hints.default_limit,
                                advertised_max_subscriptions: hints.max_subscriptions,
                                advertised_owner: hints.owner,
                                advertised_grasp08: hints.grasp08,
                            }
                        }
                        Err(error) => ConnectAttemptOutcome::Failed(error),
                    }
                } => outcome,
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
                .await
                .is_err()
            {
                connection.disconnect().await;
            }
        });
    }

    async fn derive_targets(&self) -> HashMap<String, RelaySyncNeeds> {
        let repo_index = self.repo_sync_index.read().await;
        let mut targets = algorithms::derive_relay_targets(&repo_index);
        discovery::merge_inbox_roots(&mut targets, &self.nip65_discovery.inbox_roots);
        targets
    }

    /// Rebuild GRASP-08 membership from accepted-announcement sync state and
    /// the latest NIP-11 owner learned for each referenced relay.
    ///
    /// Purgatory announcements are deliberately excluded: they have not yet
    /// passed repository admission and therefore cannot grant service access.
    async fn reconcile_private_membership(&self) {
        let Some(access) = &self.private_access else {
            return;
        };
        let repo_index = self.repo_sync_index.read().await;
        let accepted_relays: HashSet<String> = repo_index
            .values()
            .filter(|needs| needs.sync_level == SyncLevel::Full)
            .flat_map(|needs| needs.relays.iter())
            .filter_map(|relay| canonical_relay_key(relay).ok())
            .collect();
        drop(repo_index);
        let members = effective_private_members(
            &self.configured_private_members,
            &accepted_relays,
            &self.relay_owners,
        );
        if access.replace(members) {
            tracing::info!(
                configured_members = self.configured_private_members.len(),
                accepted_relay_count = accepted_relays.len(),
                effective_members = access.len(),
                "Reconciled GRASP-08 service membership"
            );
        }
    }

    fn configured_nip65_fallback_relays(&self) -> HashSet<String> {
        self.config
            .parse_sync_plus_fallback_relays()
            .into_iter()
            .filter_map(|url| canonical_relay_key(&url).ok())
            .collect()
    }

    async fn schedule_nip65_discovery(&mut self) {
        // GRASP-03 is an optional overlay on the always-running GRASP-02
        // manager. When disabled, do not inventory authors, retain identity
        // authority, open discovery connections, or add mailbox roots.
        if !self.config.sync_plus_enabled {
            return;
        }

        let now = Instant::now();
        if self
            .nip65_discovery
            .next_inventory_at
            .is_none_or(|due| due <= now)
        {
            let announcements = self
                .database
                .query(Filter::new().kind(Kind::GitRepoAnnouncement))
                .await
                .unwrap_or_default();
            let candidates = self.root_candidate_index.read().await;
            let repo_index = self.repo_sync_index.read().await;
            let roots = discovery::accepted_root_candidates(candidates.values(), &repo_index);
            let author_repositories = discovery::accepted_repository_author_repositories(
                announcements.iter(),
                &repo_index,
            );
            let mut eligible_authors: HashSet<PublicKey> =
                author_repositories.keys().copied().collect();
            let author_repositories =
                public_repository_mailbox_scope(self.config.private_mode, author_repositories);
            drop(candidates);
            drop(repo_index);
            let root_ids: HashSet<EventId> = roots.iter().map(|root| root.id).collect();
            self.nip65_discovery.root_repositories = roots
                .iter()
                .map(|root| (root.id, root.repository.clone()))
                .collect();
            self.nip65_discovery.root_author_roots =
                discovery::mailbox_author_roots(&roots, std::iter::empty());

            // A root may be absent from the author's write relays while a
            // participant's reaction, zap or reply is present there. Carry
            // root provenance through indirect event/address descendants so
            // each mailbox probe stays scoped to accepted threads in which
            // that author actually participated.
            let frontier = recursive_descendant_frontier(
                &self.database,
                &root_ids,
                self.config.sync_recursive_descendant_limit,
            )
            .await;
            let participant_author_count = frontier.author_roots.len();
            let author_roots = discovery::mailbox_author_roots(&roots, frontier.author_roots);
            eligible_authors.extend(author_roots.keys().copied());
            self.nip65_discovery.author_roots = author_roots;
            self.nip65_discovery.author_repositories = author_repositories;
            self.nip65_discovery.eligible_authors = eligible_authors;
            self.proactive_participant_authors
                .replace(self.nip65_discovery.eligible_authors.clone())
                .await;
            let current_authors = self.nip65_discovery.eligible_authors.clone();
            let policy = self.outbound_target_policy();

            // Rebuild mailbox ownership from already accepted local state before
            // attempting a network refresh. GRASP-03 retains kind 10002 so a
            // restart must not make conversation coverage depend on the index
            // source still being reachable.
            let retained_identity = if current_authors.is_empty() {
                Some(std::collections::BTreeSet::<Event>::new())
            } else {
                self.database
                    .query(
                        Filter::new()
                            .kinds([Kind::Metadata, Kind::RelayList])
                            .authors(current_authors.iter().copied())
                            .limit(current_authors.len().saturating_mul(2)),
                    )
                    .await
                    .ok()
            };
            if let Some(retained_identity) = retained_identity {
                let latest_identity = discovery::latest_identity_events(
                    retained_identity.iter().cloned(),
                    &current_authors,
                );
                self.nip65_discovery.relay_lists =
                    discovery::latest_relay_lists(latest_identity, &current_authors);
                self.nip65_discovery.author_inboxes = self
                    .nip65_discovery
                    .relay_lists
                    .iter()
                    .map(|(author, event)| (*author, discovery::inbox_relays(event, &policy)))
                    .collect();
                self.nip65_discovery.author_mailboxes = self
                    .nip65_discovery
                    .relay_lists
                    .iter()
                    .map(|(author, event)| (*author, discovery::mailbox_relays(event, &policy)))
                    .collect();
            }

            let mut index_relays: HashSet<String> = self
                .config
                .parse_user_index_relays()
                .into_iter()
                .filter_map(|url| canonical_relay_key(&url).ok())
                .collect();
            if let Some(bootstrap) = self
                .bootstrap_relay_url
                .as_deref()
                .and_then(|url| canonical_relay_key(url).ok())
            {
                index_relays.insert(bootstrap);
            }
            self.nip65_discovery.author_sources.clear();
            for author in &current_authors {
                let sources = self
                    .nip65_discovery
                    .author_sources
                    .entry(*author)
                    .or_default();
                if let Some(relay_list) = self.nip65_discovery.relay_lists.get(author) {
                    sources.extend(
                        discovery::outbox_relays(relay_list, &policy)
                            .into_iter()
                            .filter_map(|url| canonical_relay_key(&url).ok()),
                    );
                } else {
                    // Index/bootstrap relays only discover the first accepted
                    // list. Once present, its outboxes become the authoritative
                    // additive refresh graph and avoid redundant index traffic.
                    sources.extend(index_relays.iter().cloned());
                }
            }
            self.nip65_discovery
                .relay_lists
                .retain(|author, _| current_authors.contains(author));
            self.nip65_discovery
                .author_inboxes
                .retain(|author, _| current_authors.contains(author));
            self.nip65_discovery
                .author_mailboxes
                .retain(|author, _| current_authors.contains(author));
            self.nip65_discovery.fallback_authors.retain(|author| {
                current_authors.contains(author)
                    && !self.nip65_discovery.relay_lists.contains_key(author)
            });
            let current_sources = &self.nip65_discovery.author_sources;
            self.nip65_discovery
                .next_attempt_at
                .retain(|(relay, author), _| {
                    current_sources
                        .get(author)
                        .is_some_and(|sources| sources.contains(relay))
                });
            self.nip65_discovery.retain_discovery_backoff();
            self.nip65_discovery.next_inventory_at = Some(now + nip65_inventory_interval());
            let fallback_relays = self.configured_nip65_fallback_relays();
            let inbox_overlay = discovery::build_inbox_root_overlay(
                &self.nip65_discovery.root_author_roots,
                &self.nip65_discovery.author_inboxes,
                &self.nip65_discovery.fallback_authors,
                &fallback_relays,
            );
            let mut mailbox_overlay = discovery::build_inbox_root_overlay(
                &self.nip65_discovery.author_roots,
                &self.nip65_discovery.author_mailboxes,
                &self.nip65_discovery.fallback_authors,
                &fallback_relays,
            );
            // Owner/maintainer repository scope is historical-only, on their
            // bounded read/unmarked inbox selection: owning a repository must
            // not add an author's inboxes to persistent live targets.
            let mailbox_repository_overlay = discovery::build_mailbox_repository_overlay(
                &self.nip65_discovery.author_repositories,
                &self.nip65_discovery.author_inboxes,
                &self.nip65_discovery.fallback_authors,
                &fallback_relays,
            );
            merge_repository_roots_into_mailbox_overlay(
                &mut mailbox_overlay,
                &mailbox_repository_overlay,
                &self.nip65_discovery.root_repositories,
            );
            self.install_nip65_inbox_overlay(inbox_overlay).await;
            self.install_nip65_mailbox_overlay(mailbox_overlay, mailbox_repository_overlay);
            tracing::info!(
                root_count = root_ids.len(),
                participant_author_count,
                eligible_author_count = self.nip65_discovery.eligible_authors.len(),
                repository_mailbox_author_count = self.nip65_discovery.author_repositories.len(),
                mailbox_relay_count = self.nip65_discovery.mailbox_relay_count(),
                fallback_authors = self.nip65_discovery.fallback_authors.len(),
                "Reconciled proactive participant mailbox inventory"
            );
        }

        // Discovery is deliberately single-flight. The immediate-capacity
        // sample below can race with historic admission before fetch_events
        // acquires its permit, but that race can create at most one waiter,
        // never a maintenance-tick-sized queue of control-plane tasks.
        if !self.nip65_discovery.in_flight.is_empty() {
            return;
        }

        let mut candidates: HashMap<String, Vec<PublicKey>> = HashMap::new();
        for (author, sources) in &self.nip65_discovery.author_sources {
            for source in sources {
                let key = (source.clone(), *author);
                if self.nip65_discovery.in_flight.contains(&key)
                    || !self.nip65_discovery.author_query_due(source, author, now)
                {
                    continue;
                }
                candidates.entry(source.clone()).or_default().push(*author);
            }
        }
        let mut sources: Vec<String> = candidates.keys().cloned().collect();
        sources.sort();
        for source in sources {
            let Some(connection) = self.connections.get(&source).cloned() else {
                continue;
            };
            if !connection.has_immediate_transient_capacity().await {
                continue;
            }
            let mut authors = candidates.remove(&source).unwrap_or_default();
            authors.sort_by_key(PublicKey::to_hex);
            authors.truncate(NIP65_DISCOVERY_BATCH_AUTHORS);
            let authors: HashSet<PublicKey> = authors.into_iter().collect();
            if authors.is_empty() {
                continue;
            }
            self.nip65_discovery
                .in_flight
                .extend(authors.iter().map(|author| (source.clone(), *author)));
            let filter = Filter::new()
                .kinds([Kind::Metadata, Kind::RelayList])
                .authors(authors.iter().copied())
                .limit(authors.len().saturating_mul(2));
            let Some(result_tx) = self.nip65_discovery_result_tx.clone() else {
                return;
            };
            let source_relay = source.clone();
            tokio::spawn(async move {
                let outcome = connection
                    .fetch_events(filter, Duration::from_secs(30))
                    .await;
                let _ = result_tx
                    .send(Nip65DiscoveryResult {
                        source_relay,
                        authors,
                        outcome,
                    })
                    .await;
            });
            break;
        }

        // No connected source could accept the single discovery query. Dial
        // at most one new source per maintenance pass; registering the entire
        // NIP-65 graph at once would turn a bounded query lane into an
        // unbounded connection fan-out.
        if self.nip65_discovery.in_flight.is_empty() {
            if let Some(source) = candidates
                .keys()
                .filter(|source| !self.connections.contains_key(*source))
                .min()
                .cloned()
            {
                if self.register_relay(source.clone(), false, true).await {
                    self.schedule_connect_relay(&source).await;
                }
            }
        }
    }

    async fn install_nip65_inbox_overlay(
        &mut self,
        new_root_overlay: HashMap<String, HashSet<EventId>>,
    ) {
        let old_root_overlay =
            std::mem::replace(&mut self.nip65_discovery.inbox_roots, new_root_overlay);
        if old_root_overlay == self.nip65_discovery.inbox_roots {
            return;
        }
        let mut dirty_relays: HashSet<String> = old_root_overlay.keys().cloned().collect();
        dirty_relays.extend(self.nip65_discovery.inbox_roots.keys().cloned());

        for relay in dirty_relays {
            // Root-author inbox roots are essential live coverage. Recursive
            // descendant expansion remains auxiliary and may rotate under
            // pressure. Removal-only changes drain through the ordinary
            // coverage lifecycle instead of churning shared subscriptions.
            self.recompute_new_sync_filters_for_relay(&relay).await;
        }
    }

    fn install_nip65_mailbox_overlay(
        &mut self,
        new_root_overlay: HashMap<String, HashSet<EventId>>,
        new_repository_overlay: HashMap<String, HashSet<String>>,
    ) {
        self.nip65_discovery.install_mailbox_overlay(
            new_root_overlay,
            new_repository_overlay,
            Instant::now(),
        );
    }

    async fn schedule_mailbox_probe(&mut self) {
        if !self.config.sync_plus_enabled {
            return;
        }

        if !mailbox_worker_capacity_available(self.nip65_discovery.mailbox_probes_in_flight.len()) {
            return;
        }

        let now = Instant::now();
        let due_relays: Vec<String> = due_mailbox_relays(
            &self.nip65_discovery.mailbox_roots,
            &self.nip65_discovery.mailbox_repositories,
            &self.nip65_discovery.mailbox_probe_next_at,
            now,
        )
        .into_iter()
        .filter(|relay| {
            !self
                .nip65_discovery
                .mailbox_probes_in_flight
                .contains(relay)
        })
        .collect();
        let active_relays: HashSet<String> = self
            .relay_sync_index
            .read()
            .await
            .iter()
            .filter(|(_, state)| state.connection_status.is_live_sync_active())
            .map(|(relay, _)| relay.clone())
            .collect();
        let Some(relay) = select_due_mailbox_relay(&due_relays, &active_relays) else {
            return;
        };
        self.start_mailbox_probe(relay, now).await;
    }

    async fn start_mailbox_probe(&mut self, relay: String, now: Instant) -> bool {
        if is_own_sync_target(&relay, &self.service_domain)
            || self.rejected_relay_targets.contains(&relay)
        {
            self.nip65_discovery
                .mailbox_probe_next_at
                .insert(relay, now + mailbox_probe_refresh_interval());
            return false;
        }

        if !self.connections.contains_key(&relay) {
            if self.register_relay(relay.clone(), false, true).await {
                self.schedule_connect_relay(&relay).await;
            }
            self.defer_mailbox_relay(&relay);
            return false;
        }

        let Some(connection) = self.connections.get(&relay).cloned() else {
            self.defer_mailbox_relay(&relay);
            return false;
        };
        let socket_connected = connection.is_connected().await;
        let connection_status = self
            .relay_sync_index
            .read()
            .await
            .get(&relay)
            .map(|state| state.connection_status);
        if !mailbox_probe_connection_ready(connection_status, socket_connected) {
            if !socket_connected && self.health_tracker.should_attempt_connection(&relay) {
                self.schedule_connect_relay(&relay).await;
            } else if !socket_connected {
                self.retire_idle_nip65_discovery_source(&relay).await;
            }
            self.defer_mailbox_relay(&relay);
            return false;
        }

        let root_scope = self
            .nip65_discovery
            .mailbox_roots
            .get(&relay)
            .cloned()
            .unwrap_or_default();
        let repository_scope = self
            .nip65_discovery
            .mailbox_repositories
            .get(&relay)
            .cloned()
            .unwrap_or_default();
        let (repositories, roots) = expand_mailbox_probe_scope(
            &repository_scope,
            &root_scope,
            &self.nip65_discovery.root_repositories,
        );
        let frontier = recursive_descendant_frontier(
            &self.database,
            &roots,
            self.config.sync_recursive_descendant_limit,
        )
        .await;
        let mut filters = mailbox_probe_filters(&repositories, &roots, &frontier);
        filters.sort_by_key(Filter::as_json);
        let Some(filter_count) = (!filters.is_empty()).then_some(filters.len()) else {
            self.nip65_discovery
                .mailbox_probe_next_at
                .insert(relay.clone(), now + mailbox_probe_refresh_interval());
            self.retire_idle_nip65_discovery_source(&relay).await;
            return false;
        };
        let filter_index = self
            .nip65_discovery
            .mailbox_probe_next_filter
            .get(&relay)
            .copied()
            .unwrap_or_default()
            % filter_count;
        let filter = filters.swap_remove(filter_index);
        let Some(result_tx) = self.mailbox_probe_result_tx.clone() else {
            self.defer_mailbox_relay(&relay);
            return false;
        };
        self.nip65_discovery
            .mailbox_probes_in_flight
            .insert(relay.clone());
        let source_relay = relay.clone();
        tokio::spawn(async move {
            let outcome = fetch_mailbox_filter(connection, filter).await;
            let _ = result_tx
                .send(MailboxProbeResult {
                    source_relay,
                    filter_index,
                    filter_count,
                    outcome,
                })
                .await;
        });
        tracing::info!(
            relay = %relay,
            filter_index,
            filter_count,
            "Started bounded participant mailbox fetch"
        );
        true
    }

    fn defer_mailbox_relay(&mut self, relay: &str) {
        if self.nip65_discovery.has_mailbox_scope(relay) {
            let due = Instant::now() + mailbox_probe_retry_interval();
            self.nip65_discovery
                .mailbox_probe_next_at
                .entry(relay.to_string())
                .and_modify(|deadline| *deadline = (*deadline).max(due))
                .or_insert(due);
        }
    }

    async fn handle_mailbox_probe_result(&mut self, result: MailboxProbeResult) {
        if !self
            .nip65_discovery
            .mailbox_probes_in_flight
            .remove(&result.source_relay)
        {
            tracing::debug!(
                relay = %result.source_relay,
                "Ignoring stale participant mailbox result"
            );
            return;
        }

        let (events, succeeded) = match result.outcome {
            Ok(events) => (events, true),
            Err(error) => {
                tracing::debug!(relay = %result.source_relay, %error, "Participant mailbox fetch failed");
                (Vec::new(), false)
            }
        };
        let event_count = events.len();
        for event in events {
            let _ = Self::process_event_static(
                &event,
                &result.source_relay,
                &self.database,
                &self.write_policy,
                &self.local_relay,
                &self.rejected_events_index,
                crate::nostr::persistence::SaveContext::RelaySync,
            )
            .await;
        }

        let (next_filter, completed_cycle, mut next_probe_in) =
            mailbox_probe_completion(result.filter_index, result.filter_count, succeeded);
        let failure_delay = self
            .nip65_discovery
            .mailbox_retry_delay(&result.source_relay, succeeded);
        if !succeeded {
            next_probe_in = failure_delay;
        }
        self.nip65_discovery.record_probe_completion(
            &result.source_relay,
            next_filter,
            next_probe_in,
            Instant::now(),
        );
        tracing::info!(
            relay = %result.source_relay,
            filter_index = result.filter_index,
            filter_count = result.filter_count,
            event_count,
            succeeded,
            completed_cycle,
            next_probe_in_secs = next_probe_in.as_secs_f64(),
            "Participant mailbox fetch reached terminal state"
        );

        if should_continue_mailbox_probe(succeeded, completed_cycle)
            && self
                .start_mailbox_probe(result.source_relay.clone(), Instant::now())
                .await
        {
            return;
        }
        self.retire_idle_nip65_discovery_source(&result.source_relay)
            .await;
    }

    async fn handle_nip65_discovery_result(&mut self, result: Nip65DiscoveryResult) {
        for author in &result.authors {
            self.nip65_discovery
                .in_flight
                .remove(&(result.source_relay.clone(), *author));
        }
        let (events, query_succeeded) = match result.outcome {
            Ok(events) => (events, true),
            Err(error) => {
                tracing::debug!(relay = %result.source_relay, %error, "NIP-65 discovery query failed");
                (Vec::new(), false)
            }
        };
        let retry_after = self.nip65_discovery.record_discovery_outcome(
            &result.source_relay,
            query_succeeded,
            Instant::now(),
        );
        if !query_succeeded {
            tracing::warn!(relay = %result.source_relay, retry_secs = retry_after.as_secs_f64(),
                "NIP-65 identity query failed; backing off this discovery source");
        }
        let selected = discovery::latest_identity_events(events, &result.authors);
        let mut represented_by_source = HashSet::new();
        for event in selected {
            let process_result = Self::process_event_static(
                &event,
                &result.source_relay,
                &self.database,
                &self.write_policy,
                &self.local_relay,
                &self.rejected_events_index,
                crate::nostr::persistence::SaveContext::RelaySync,
            )
            .await;
            if event.kind == Kind::RelayList
                && matches!(
                    process_result,
                    ProcessResult::Saved | ProcessResult::Duplicate
                )
            {
                represented_by_source.insert(event.pubkey);
            }
        }
        // Drive relay ownership only from the accepted database. A source can
        // return a validly signed but policy-ineligible relay list; processing
        // its raw response must not be enough to make us dial its URLs.
        let stored_relay_lists = self
            .database
            .query(
                Filter::new()
                    .kind(Kind::RelayList)
                    .authors(result.authors.iter().copied())
                    .limit(result.authors.len()),
            )
            .await
            .unwrap_or_default();
        let latest = discovery::latest_relay_lists(stored_relay_lists, &result.authors);
        let authors_with_lists: HashSet<PublicKey> = latest.keys().copied().collect();
        let previous_fallback_authors = self.nip65_discovery.fallback_authors.clone();
        let now = Instant::now();
        for author in &result.authors {
            let retry_after =
                nip65_author_retry_after(query_succeeded, &represented_by_source, author);
            self.nip65_discovery
                .next_attempt_at
                .insert((result.source_relay.clone(), *author), now + retry_after);
            if authors_with_lists.contains(author) {
                self.nip65_discovery.fallback_authors.remove(author);
            } else if query_succeeded
                && (self.nip65_discovery.author_roots.contains_key(author)
                    || self
                        .nip65_discovery
                        .author_repositories
                        .contains_key(author))
            {
                self.nip65_discovery.fallback_authors.insert(*author);
            }
        }

        let mut changed = previous_fallback_authors != self.nip65_discovery.fallback_authors;
        let policy = self.outbound_target_policy();
        for (author, candidate) in latest {
            if !self.nip65_discovery.eligible_authors.contains(&author) {
                continue;
            }
            let replace = self
                .nip65_discovery
                .relay_lists
                .get(&author)
                .is_none_or(|current| {
                    candidate.created_at > current.created_at
                        || (candidate.created_at == current.created_at && candidate.id < current.id)
                });
            if replace {
                self.nip65_discovery
                    .author_inboxes
                    .insert(author, discovery::inbox_relays(&candidate, &policy));
                self.nip65_discovery
                    .author_mailboxes
                    .insert(author, discovery::mailbox_relays(&candidate, &policy));
                let mut index_relays: HashSet<String> = self
                    .config
                    .parse_user_index_relays()
                    .into_iter()
                    .filter_map(|url| canonical_relay_key(&url).ok())
                    .collect();
                if let Some(bootstrap) = self
                    .bootstrap_relay_url
                    .as_deref()
                    .and_then(|url| canonical_relay_key(url).ok())
                {
                    index_relays.insert(bootstrap);
                }
                let sources = self
                    .nip65_discovery
                    .author_sources
                    .entry(author)
                    .or_default();
                sources.retain(|source| !index_relays.contains(source));
                sources.extend(
                    discovery::outbox_relays(&candidate, &policy)
                        .into_iter()
                        .filter_map(|url| canonical_relay_key(&url).ok()),
                );
                self.nip65_discovery.relay_lists.insert(author, candidate);
                changed = true;
            }
        }
        if !changed {
            self.retire_idle_nip65_discovery_source(&result.source_relay)
                .await;
            self.schedule_nip65_discovery().await;
            return;
        }
        let fallback_relays = self.configured_nip65_fallback_relays();
        let inbox_overlay = discovery::build_inbox_root_overlay(
            &self.nip65_discovery.root_author_roots,
            &self.nip65_discovery.author_inboxes,
            &self.nip65_discovery.fallback_authors,
            &fallback_relays,
        );
        let mut mailbox_overlay = discovery::build_inbox_root_overlay(
            &self.nip65_discovery.author_roots,
            &self.nip65_discovery.author_mailboxes,
            &self.nip65_discovery.fallback_authors,
            &fallback_relays,
        );
        // Owner/maintainer repository scope is historical-only, on their
        // bounded read/unmarked inbox selection: owning a repository must
        // not add an author's inboxes to persistent live targets.
        let mailbox_repository_overlay = discovery::build_mailbox_repository_overlay(
            &self.nip65_discovery.author_repositories,
            &self.nip65_discovery.author_inboxes,
            &self.nip65_discovery.fallback_authors,
            &fallback_relays,
        );
        merge_repository_roots_into_mailbox_overlay(
            &mut mailbox_overlay,
            &mailbox_repository_overlay,
            &self.nip65_discovery.root_repositories,
        );
        self.install_nip65_inbox_overlay(inbox_overlay).await;
        self.install_nip65_mailbox_overlay(mailbox_overlay, mailbox_repository_overlay);
        tracing::info!(
            source = %result.source_relay,
            authors = result.authors.len(),
            mailbox_relays = self.nip65_discovery.mailbox_relay_count(),
            fallback_authors = self.nip65_discovery.fallback_authors.len(),
            "Updated proactive participant mailbox coverage from NIP-65"
        );

        self.retire_idle_nip65_discovery_source(&result.source_relay)
            .await;
        // Continue the single-flight round immediately. The health timer is a
        // safety net, but ordinary sync work may hold the actor long enough
        // that waiting for its next tick needlessly delays a newly discovered
        // outbox.
        self.schedule_nip65_discovery().await;
    }

    async fn retire_idle_nip65_discovery_source(&mut self, source: &str) {
        if !self.nip65_discovery_only_relays.contains(source) {
            return;
        }
        // Retirement forgets connection health. A failed or policy-limited
        // source must retain its session state until recovery or removal from
        // discovery ownership, otherwise the next probe bypasses its backoff.
        if self.health_tracker.get_failure_count(source) > 0
            || self.health_tracker.is_subscription_paused(source)
        {
            return;
        }
        if let Some(connection) = self.connections.get(source) {
            if !connection.is_connected().await {
                // The disconnect notification may still be queued behind a
                // fetch result. Let it record the unexpected failure instead
                // of relabeling the session as an intentional retirement.
                return;
            }
        }
        let now = Instant::now();
        let has_author_work =
            self.nip65_discovery
                .author_sources
                .iter()
                .any(|(author, sources)| {
                    sources.contains(source)
                        && (self
                            .nip65_discovery
                            .in_flight
                            .contains(&(source.to_string(), *author))
                            || self.nip65_discovery.author_query_due(source, author, now))
                });
        let has_mailbox_work = self
            .nip65_discovery
            .mailbox_probes_in_flight
            .contains(source)
            || (self.nip65_discovery.has_mailbox_scope(source)
                && self
                    .nip65_discovery
                    .mailbox_probe_next_at
                    .get(source)
                    .is_none_or(|due| *due <= now));
        if !has_author_work && !has_mailbox_work && !self.has_pending_batches(source).await {
            tracing::debug!(
                relay = %source,
                "Retiring idle NIP-65 control-plane connection"
            );
            self.disconnect_relay(source).await;
        }
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

        let outcome = if matches!(result.outcome, ConnectAttemptOutcome::Connected { .. }) {
            let still_connected = if let Some(connection) = self.connections.get(&result.relay_url)
            {
                connection.is_connected().await
            } else {
                false
            };
            if still_connected {
                result.outcome
            } else {
                tracing::warn!(
                    relay = %result.relay_url,
                    "Rejecting stale connection success after relay disconnected during setup"
                );
                ConnectAttemptOutcome::Failed(
                    "Relay disconnected before connection setup completed".to_string(),
                )
            }
        } else {
            result.outcome
        };

        match outcome {
            ConnectAttemptOutcome::Connected {
                advertised_default_limit,
                advertised_max_subscriptions,
                advertised_owner,
                advertised_grasp08,
            } => {
                // Only GRASP-08-advertising relays mint derived private
                // membership: a public relay's owner gains nothing legitimate
                // from private membership because their relay enforces no
                // confidentiality for the mirrored repositories.
                match advertised_owner.filter(|_| advertised_grasp08) {
                    Some(owner) => {
                        self.relay_owners.insert(result.relay_url.clone(), owner);
                    }
                    None => {
                        self.relay_owners.remove(&result.relay_url);
                    }
                }
                // On a private instance, remember which hosts are GRASP-08
                // peers so purgatory Git fetches from them carry the outbound
                // NIP-98 credential.
                if let Some(peers) = &self.grasp08_peers {
                    if let Some(key) = crate::private::Grasp08Peers::peer_key(&result.relay_url) {
                        if advertised_grasp08 {
                            if peers.insert(key) {
                                tracing::info!(
                                    relay = %result.relay_url,
                                    "Confirmed GRASP-08 peer; Git fetches will carry credentials"
                                );
                            }
                        } else {
                            peers.remove(&key);
                        }
                    }
                }
                self.reconcile_private_membership().await;
                if let Some(connection) = self.connections.get(&result.relay_url) {
                    connection.reset_subscription_budget(advertised_max_subscriptions);
                }
                // A session begins only after a successful WebSocket connection. Replacing this
                // entry on every connection result resets learned caps and re-applies the NIP-11
                // hint fetched for that exact session.
                self.pagination_sessions.insert(
                    result.relay_url.clone(),
                    RelayPaginationSession::new(advertised_default_limit),
                );
                self.health_tracker.record_success(&result.relay_url);
                if let Some(ref metrics) = self.metrics {
                    metrics.record_connection_attempt(&result.relay_url, true);
                }
                self.nip65_discovery
                    .mailbox_connected(&result.relay_url, Instant::now());
                self.handle_connect_or_reconnect(&result.relay_url).await;
            }
            ConnectAttemptOutcome::PrivateService => {
                if self.private_service_relays.insert(result.relay_url.clone()) {
                    tracing::warn!(
                        relay = %result.relay_url,
                        "Relay advertises GRASP-08 private service; excluding it from public sync"
                    );
                }
                // Retire the target like `complete_ended_session`, but without
                // the re-registration path: the park is permanent for this
                // process. No connected gauge to decrement - we never dialed.
                self.relay_sync_index
                    .write()
                    .await
                    .remove(&result.relay_url);
                self.pending_sync_index
                    .write()
                    .await
                    .remove(&result.relay_url);
                self.connections.remove(&result.relay_url);
                self.nip65_discovery_only_relays.remove(&result.relay_url);
                self.health_tracker.forget_relay(&result.relay_url);
                if let Some(ref metrics) = self.metrics {
                    metrics.forget_relay(&result.relay_url);
                }
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
        use crate::sync::algorithms::compute_actions;

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
        let all_targets = self.derive_targets().await;

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
        use crate::sync::algorithms::compute_actions;

        // Collect all purgatory announcements (snapshot - no async holds)
        let announcements = self.purgatory.announcements_for_sync();
        let announcement_events = self.purgatory.announcement_events_for_sync();

        // Replace StateOnly relay ownership from the current purgatory
        // snapshot and remove entries only after full expiry. Soft-expired
        // announcements remain in the snapshot for their 24-hour revival
        // window; promoted Full entries are never downgraded or removed here.
        let dirty_relays = {
            let mut index = self.repo_sync_index.write().await;
            reconcile_purgatory_relay_ownership(&mut index, &announcements)
        };
        for relay_url in dirty_relays {
            self.recompute_new_sync_filters_for_relay(&relay_url).await;
        }

        if announcements.is_empty() {
            return;
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
        let mut dependency_refetch_batches = HashMap::new();
        for event in dependency_events {
            self.reprocess_purgatory_announcement_dependencies(
                &event,
                &mut dependency_refetch_batches,
            )
            .await;
        }
        self.spawn_batched_purgatory_dependency_refetch(dependency_refetch_batches);

        // Recompute all outstanding actions on every pass. A bounded pass may
        // intentionally defer some relays, so restricting this to newly seen
        // URLs would lose that work on the next tick.
        let all_targets = self.derive_targets().await;
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
    async fn reprocess_purgatory_announcement_dependencies(
        &mut self,
        event: &Event,
        dependency_refetch_batches: &mut HashMap<String, DependencyRelayBatch>,
    ) {
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
        // Walk every currently-listed maintainer, including invited ones:
        // their announcements must be recovered so acceptance is noticed.
        let mut maintainer_queue: VecDeque<String> =
            announcement.listed_maintainers().into_iter().collect();
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
                            maintainer_queue.extend(accepted_announcement.listed_maintainers());
                            dependency_relay_urls.extend(accepted_announcement.relays);
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
                    if !self.register_relay(relay_url.clone(), false, false).await {
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
            for relay_url in connected_dependency_relays {
                let batch = dependency_refetch_batches.entry(relay_url).or_default();
                batch
                    .event_ids
                    .extend(dependency_refetch_ids.iter().copied());
                batch.identifiers.insert(announcement.identifier.clone());
            }
        }
    }

    /// Fetch cold-cache dependency IDs without blocking the sync manager.
    ///
    /// Candidate IDs stay in the rejected index until policy processing
    /// succeeds. All due repositories are combined by relay before requests
    /// are spawned, so the maintenance cadence consumes one query per bounded
    /// ID chunk rather than one query per repository and relay.
    fn spawn_batched_purgatory_dependency_refetch(
        &self,
        mut batches: HashMap<String, DependencyRelayBatch>,
    ) {
        // Paused peers cannot serve these IDs yet. Do not reserve their retries
        // or spawn fetches that the connection admission guard will reject.
        batches.retain(|relay_url, batch| {
            !batch.event_ids.is_empty()
                && self.connections.contains_key(relay_url)
                && !self.health_tracker.is_subscription_paused(relay_url)
        });
        if batches.is_empty() {
            return;
        }

        let due_event_ids = self.reserve_dependency_refetch_attempts(
            batches
                .values()
                .flat_map(|batch| batch.event_ids.iter().copied()),
        );
        if due_event_ids.is_empty() {
            return;
        }
        for batch in batches.values_mut() {
            batch
                .event_ids
                .retain(|event_id| due_event_ids.contains(event_id));
        }
        batches.retain(|_, batch| !batch.event_ids.is_empty());

        let connections = self.connections.clone();
        let database = self.database.clone();
        let write_policy = self.write_policy.clone();
        let local_relay = self.local_relay.clone();
        let rejected_events_index = self.rejected_events_index.clone();
        let dependency_refetch_attempts = self.dependency_refetch_attempts.clone();

        tokio::spawn(async move {
            let mut fetches = Vec::new();
            for (relay_url, batch) in batches {
                let Some(connection) = connections.get(&relay_url).cloned() else {
                    continue;
                };
                let event_ids: Vec<EventId> = batch.event_ids.into_iter().collect();
                let repository_count = batch.identifiers.len();
                for chunk in event_ids.chunks(MAX_PURGATORY_DEPENDENCY_IDS_PER_QUERY) {
                    let chunk = chunk.to_vec();
                    let connection = connection.clone();
                    let relay_url = relay_url.clone();
                    fetches.push(async move {
                        let result = connection
                            .fetch_events(
                                Filter::new().ids(chunk.iter().copied()).limit(chunk.len()),
                                Duration::from_secs(5),
                            )
                            .await;
                        (relay_url, repository_count, chunk.len(), result)
                    });
                }
            }

            let mut fetched_events = Vec::new();
            for (relay_url, repository_count, requested_count, result) in join_all(fetches).await {
                match result {
                    Ok(events) => {
                        tracing::info!(
                            relay = %relay_url,
                            repository_count,
                            requested_count,
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
                            repository_count,
                            event_count = requested_count,
                            error = %error,
                            "Failed to refetch batched purgatory dependencies"
                        );
                    }
                }
            }

            Self::process_purgatory_dependency_events(
                fetched_events,
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

            if result.is_terminally_accounted() {
                rejected_events_index.remove(&event.id);
                dependency_refetch_attempts
                    .lock()
                    .unwrap()
                    .remove(&event.id);
            }

            if result == ProcessResult::Purgatory && event.kind == Kind::RepoState {
                if let Some(identifier) = event
                    .tags
                    .iter()
                    .find(|tag| tag.kind() == "d")
                    .and_then(|tag| tag.content())
                {
                    write_policy.purgatory().enqueue_sync_immediate(identifier);
                }
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
        self.history_tasks.cancel_relay(relay_url);
        // Learned page sizes and NIP-11 hints belong to the ended WebSocket session.
        self.pagination_sessions.remove(relay_url);
        // A connection can end after a descendant REQ was sent but before its
        // EOSE. Restart the bounded full rotation so that page is not treated
        // as complete on the next session.
        self.descendant_sync_rotations.remove(relay_url);
        self.descendant_live_coverage.remove(relay_url);
        self.auth_required_attempts
            .retain(|(attempt_relay, _)| attempt_relay != relay_url);

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
            tracing::info!(relay = %relay_url, "Event loop terminated for intentional disconnect, completing cleanup");
            self.complete_ended_session(relay_url, true).await;
        } else {
            // Ownership changes are passive: do not disturb a healthy session.
            // Once the connection ends naturally, however, reconcile its
            // confirmed state with the latest index before deciding whether it
            // should ever reconnect.
            let desired = self.derive_targets().await.remove(relay_url).or_else(|| {
                self.nip65_discovery
                    .connection_targets()
                    .contains(relay_url)
                    .then(RelaySyncNeeds::default)
            });
            // GRASP-P seam: a configured peer is kept when its session ends.
            let desired = desired.or_else(|| self.grasp_p_peer_needs(relay_url));
            let Some(desired) = desired else {
                tracing::info!(
                    relay = %relay_url,
                    "Naturally ended relay session is no longer owned; retiring without reconnect"
                );
                self.complete_ended_session(relay_url, true).await;
                return;
            };

            // Unexpected disconnect - update state but keep for reconnection
            tracing::warn!(relay = %relay_url, "Unexpected relay disconnect detected");

            // Update RelayState in relay_sync_index
            {
                let mut index = self.relay_sync_index.write().await;
                if let Some(state) = index.get_mut(relay_url) {
                    state.repos = desired.repos;
                    state.state_only_repos = desired.state_only_repos;
                    state.root_events = desired.root_events;
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

    /// Remove all state owned by an ended session that must not reconnect.
    ///
    /// Connected sessions reach this after their event loop terminates. An
    /// already-disconnected session has no event loop left to notify us, so
    /// `disconnect_relay` calls it directly without decrementing the connected
    /// gauge a second time.
    async fn complete_ended_session(&mut self, relay_url: &str, was_connected: bool) {
        self.history_tasks.cancel_relay(relay_url);
        if let Some(ref metrics) = self.metrics {
            metrics.record_connection_status(relay_url, ConnectionStatus::Disconnected);
        }

        self.relay_sync_index.write().await.remove(relay_url);
        self.pending_sync_index.write().await.remove(relay_url);
        self.connections.remove(relay_url);
        self.nip65_discovery_only_relays.remove(relay_url);
        self.missing_event_recovery
            .lock()
            .unwrap()
            .clear_relay(relay_url);
        self.health_tracker.forget_relay(relay_url);

        if let Some(ref metrics) = self.metrics {
            if was_connected {
                metrics.dec_connected_count();
            }
            metrics.forget_relay(relay_url);
        }

        tracing::info!(relay = %relay_url, "Ended relay session cleanup complete");

        let still_desired = self.derive_targets().await.contains_key(relay_url);
        if still_desired
            && self
                .register_relay(relay_url.to_string(), false, false)
                .await
        {
            tracing::info!(
                relay = %relay_url,
                "Relay remains shared by current repository announcements; starting a clean session"
            );
            self.schedule_connect_relay(relay_url).await;
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
                ProcessResult::Tombstoned => {
                    stats.duplicate += 1;
                    tracing::debug!(
                        event_id = %event.id,
                        "{} remains absent under deletion semantics",
                        context
                    );
                }
                ProcessResult::Rejected(_) | ProcessResult::PersistenceError => {
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

            if reprocess_result.is_terminally_accounted() {
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
    fn classify_policy_result(
        prefix: &nostr_sdk::prelude::MachineReadablePrefix,
        message: &str,
        status: bool,
    ) -> ProcessResult {
        use nostr_sdk::prelude::MachineReadablePrefix;

        if status {
            return if prefix.as_str() == "purgatory" || message.contains("purgatory") {
                ProcessResult::Purgatory
            } else {
                ProcessResult::Duplicate
            };
        }

        if message == "this event is deleted" || message == "this pubkey has requested to vanish" {
            return ProcessResult::Tombstoned;
        }

        let rejection = match prefix {
            MachineReadablePrefix::Blocked => PolicyRejection::Blocked,
            MachineReadablePrefix::Invalid => PolicyRejection::Invalid,
            MachineReadablePrefix::Restricted => PolicyRejection::Restricted,
            MachineReadablePrefix::Error => PolicyRejection::Error,
            _ => PolicyRejection::Other,
        };
        ProcessResult::Rejected(rejection)
    }

    async fn process_event_static(
        event: &Event,
        relay_url: &str,
        database: &SharedDatabase,
        write_policy: &Nip34WritePolicy,
        local_relay: &LocalRelay,
        rejected_events_index: &Arc<RejectedEventsIndex>,
        save_context: crate::nostr::persistence::SaveContext,
    ) -> ProcessResult {
        Self::process_event_static_inner(
            event,
            relay_url,
            database,
            write_policy,
            local_relay,
            rejected_events_index,
            save_context,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_event_static_inner(
        event: &Event,
        relay_url: &str,
        database: &SharedDatabase,
        write_policy: &Nip34WritePolicy,
        local_relay: &LocalRelay,
        rejected_events_index: &Arc<RejectedEventsIndex>,
        save_context: crate::nostr::persistence::SaveContext,
        resolve_related_dependencies: bool,
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
                return ProcessResult::PersistenceError;
            }
            Ok(None) => {} // Continue processing
        }

        // SovTech seam: check the id and the signature here, where every synced,
        // fetched and re-processed event crosses into admission. nostr-sdk's
        // verification cache is keyed on the id an event CLAIMS, so a relay
        // that first delivers a genuine event can then send other content
        // under that id, with any author and any signature, and the SDK hands
        // it on unverified. It arrives three ways: through the SDK's fetch
        // streams, through GRASP-P's duplicate forwarding, and as an ordinary
        // RelayNotification::Event once the SDK's seen-id tracker (35,000 ids)
        // has dropped an id its verification cache (128,000 ids) still holds.
        // The write policy trusts `event.pubkey`.
        //
        // The class is Other, not Invalid: Invalid is a final verdict on the
        // id, and a forged copy says nothing about the genuine event that
        // owns it. Nothing is written to the rejected index either.
        if let Err(error) = event.verify() {
            tracing::warn!(
                event_id = %event.id,
                relay = %relay_url,
                error = %error,
                "Rejecting synced event: id or signature does not verify"
            );
            return ProcessResult::Rejected(PolicyRejection::Other);
        }
        // GRASP-P seam: GRASP-P events come by relay sync from configured peers only.
        if let Some(refused) = Self::grasp_p_gate(write_policy, event, relay_url, save_context) {
            return refused;
        }

        // Apply write policy using a dummy address (sync events aren't from network clients)
        let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let result = write_policy.admit_event(event, &dummy_addr).await;

        match result {
            WritePolicyResult::Accept => {
                // Save event to database
                match write_policy.save_accepted_event(event, save_context).await {
                    Ok(
                        crate::nostr::persistence::AcceptedEventSaveOutcome::Saved
                        | crate::nostr::persistence::AcceptedEventSaveOutcome::Duplicate,
                    ) => {}
                    Ok(crate::nostr::persistence::AcceptedEventSaveOutcome::Replaced) => {
                        tracing::trace!(
                            event_id = %event.id,
                            relay = %relay_url,
                            "Database retained a newer replaceable event during sync"
                        );
                        return ProcessResult::Duplicate;
                    }
                    Err(e) => {
                        tracing::error!(
                            event_id = %event.id,
                            relay = %relay_url,
                            error = %e,
                            "Failed to save synced event"
                        );
                        return ProcessResult::PersistenceError;
                    }
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
                            // Re-process rejected announcements from every
                            // currently-listed maintainer (invited included)
                            let listed_maintainers = announcement.listed_maintainers();
                            if !listed_maintainers.is_empty() {
                                tracing::debug!(
                                    event_id = %event.id,
                                    identifier = %announcement.identifier,
                                    maintainer_count = listed_maintainers.len(),
                                    "Owner announcement accepted, checking for rejected maintainer announcements"
                                );

                                // For each maintainer, invalidate and get their events
                                for maintainer_hex in &listed_maintainers {
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

                if resolve_related_dependencies {
                    let mut queue: VecDeque<Event> = rejected_events_index
                        .related_candidates_resolved_by(event)
                        .into_iter()
                        .collect();
                    let mut attempted = HashSet::new();
                    let mut saved = 0usize;
                    while let Some(candidate) = queue.pop_front() {
                        if attempted.len() >= rejected_index::RELATED_RETRY_CLOSURE_LIMIT
                            || !attempted.insert(candidate.id)
                        {
                            continue;
                        }
                        let outcome = Box::pin(Self::process_event_static_inner(
                            &candidate,
                            relay_url,
                            database,
                            write_policy,
                            local_relay,
                            rejected_events_index,
                            save_context,
                            false,
                        ))
                        .await;
                        if outcome.is_terminally_accounted() {
                            rejected_events_index.remove(&candidate.id);
                        }
                        if outcome == ProcessResult::Saved {
                            saved += 1;
                            queue.extend(
                                rejected_events_index.related_candidates_resolved_by(&candidate),
                            );
                        }
                    }
                    if !attempted.is_empty() {
                        tracing::info!(
                            trigger_event = %event.id,
                            attempted = attempted.len(),
                            saved,
                            remaining = rejected_events_index.related_len(),
                            "Reprocessed dependency-sensitive related-event closure"
                        );
                    }
                }

                Self::grasp_p_after_saved(
                    event,
                    relay_url,
                    database,
                    write_policy,
                    local_relay,
                    rejected_events_index,
                )
                .await;

                ProcessResult::Saved
            }
            WritePolicyResult::Reject {
                prefix,
                message,
                status,
            } => {
                let process_result = Self::classify_policy_result(&prefix, &message, status);
                if matches!(
                    process_result,
                    ProcessResult::Purgatory | ProcessResult::Duplicate
                ) {
                    tracing::debug!(
                        event_id = %event.id,
                        kind = %event.kind.as_u16(),
                        outcome = process_result.hydration_outcome(),
                        reason = %message,
                        "Event accepted without main-database persistence"
                    );
                    // Note: git data sync for state events is triggered by the policy
                    // layer when adding to purgatory (via start_state_sync)
                    process_result
                } else {
                    tracing::debug!(
                        event_id = %event.id,
                        relay = %relay_url,
                        kind = %event.kind.as_u16(),
                        outcome = process_result.hydration_outcome(),
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
                    } else if process_result == ProcessResult::Rejected(PolicyRejection::Restricted)
                        && message.contains(
                            "event must reference an accepted repository or accepted event",
                        )
                    {
                        let (addressable_refs, event_refs) =
                            crate::nostr::policy::RelatedEventPolicy::extract_reference_tags(event);
                        let retained = rejected_events_index.add_related_from_relay(
                            event.clone(),
                            event_refs.into_iter().collect(),
                            addressable_refs.into_iter().collect(),
                            Some(relay_url.to_string()),
                        );
                        tracing::debug!(
                            event_id = %event.id,
                            kind = %event.kind.as_u16(),
                            retained,
                            "Indexed dependency-sensitive related event for durable retry"
                        );
                    }
                    Self::grasp_p_after_rejected(write_policy, event, &message);

                    process_result
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
        let _ = self.consolidate(relay_url).await;
        // The AddFilters action that requested this consolidation was
        // intentionally not admitted. Re-derive it now that the deferral has
        // cleared so a quiet relay does not wait for an unrelated dirty signal.
        self.recompute_new_sync_filters_for_relay(relay_url).await;
    }

    fn cancel_deferred_consolidation(&mut self, relay_url: &str, reason: &'static str) {
        self.pending_live_repairs.remove(relay_url);
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
    async fn consolidate(&mut self, relay_url: &str) -> bool {
        tracing::info!(
            relay = %relay_url,
            "Starting consolidation"
        );

        // Descendant coverage is auxiliary and independently reconstructible.
        // Retire it before capturing the core rollback set so it can neither
        // displace newly required core coverage nor become part of that set.
        if !self
            .close_descendant_live_coverage(relay_url, "core consolidation")
            .await
        {
            return false;
        }

        let now = Timestamp::now();
        let since = Timestamp::from(now.as_secs().saturating_sub(QUICK_RECONNECT_WINDOW_SECS));
        let complete_live = self.complete_live_filters(relay_url, Some(since)).await;

        // Replace L1+L2+L3 as one reserved transaction. The connection-level
        // opener rolls every successful group back if a later group fails.
        let connection = match self.connections.get(relay_url) {
            Some(conn) => conn.clone(),
            None => {
                tracing::debug!(
                    relay = %relay_url,
                    "No connection found, skipping consolidation"
                );
                return false;
            }
        };

        let complete_group_count = grouped_subscription_count(&complete_live);
        if !connection.complete_live_set_fits(complete_group_count) {
            tracing::warn!(
                relay = %relay_url,
                complete_group_count,
                "Complete live coverage exceeds the connection budget; keeping existing coverage and deferring replacement"
            );
            return false;
        }

        let unbounded_groups = live_filter_groups(&complete_live, connection.max_filters_per_req());
        let remote_limit = connection.remote_subscription_byte_limit();
        let (complete_groups, overflow_groups) =
            groups_within_subscription_byte_limit(unbounded_groups, remote_limit, 0);
        if connection
            .replace_live_filter_groups(complete_groups)
            .await
            .is_err()
        {
            tracing::warn!(
                relay = %relay_url,
                "Complete live coverage could not be replaced; historic work deferred"
            );
            return false;
        }
        if overflow_groups > 0 {
            self.byte_limited_live_relays.insert(
                relay_url.to_string(),
                Instant::now() + byte_limited_catchup_interval(),
            );
            let items = self.desired_items_for_relay(relay_url).await;
            self.historic_sync(relay_url, complete_live, items, Some(since))
                .await;
        } else {
            self.byte_limited_live_relays.remove(relay_url);
            self.sync_generic_history(relay_url, Some(since)).await;
        }

        tracing::info!(
            relay = %relay_url,
            since = %since,
            overflow_groups,
            "Consolidation complete - filter count reset"
        );
        true
    }

    fn release_removed_descendant_batch(&mut self, relay_url: &str, batch: &PendingBatch) {
        self.history_tasks.finish(batch.batch_id);
        if batch.purpose == PendingBatchPurpose::Descendants {
            if let Some(rotation) = self.descendant_sync_rotations.get_mut(relay_url) {
                rotation.mark_completed(batch.batch_id, false, Instant::now());
            }
        }
    }

    async fn handle_request_timeout(&mut self, notification: SubscriptionClosedNotification) {
        let Some(connection) = self.connections.get(&notification.relay_url).cloned() else {
            return;
        };
        if notification.generation != Some(connection.current_subscription_generation()) {
            return;
        }
        self.retire_incomplete_request_batch(
            &notification.relay_url,
            &notification.subscription_id,
        )
        .await;
    }

    async fn retire_incomplete_request_batch(
        &mut self,
        relay_url: &str,
        subscription_id: &SubscriptionId,
    ) {
        let Some(connection) = self.connections.get(relay_url).cloned() else {
            return;
        };
        let batch = {
            let mut pending = self.pending_sync_index.write().await;
            take_batch_containing_subscription(&mut pending, relay_url, subscription_id)
        };
        let Some(batch) = batch else {
            return;
        };
        // Also covers an SDK deadline acknowledged by CLOSED before the
        // watchdog fires. Duplicate failures within this pause are coalesced.
        self.health_tracker.record_request_failure(relay_url);
        self.release_removed_descendant_batch(relay_url, &batch);
        for id in &batch.outstanding_subs {
            connection.retire_subscription(id).await;
        }
        // Leave the items unconfirmed: the regular coverage reconciler can
        // retry them. A watchdog provides no evidence of complete history.
        tracing::warn!(relay = %relay_url, batch_id = batch.batch_id,
            "Historic request ended without EOSE; retired its incomplete batch");
    }

    async fn handle_subscription_closed(
        &mut self,
        relay_url: &str,
        subscription_id: SubscriptionId,
        reason: &str,
        live_generation: Option<u64>,
        live_filter_count: Option<usize>,
    ) {
        let is_descendant_live = self
            .descendant_live_coverage
            .get(relay_url)
            .is_some_and(|coverage| coverage.subscription_ids.contains(&subscription_id));
        let policy_category = if is_auth_required_message(reason) {
            let Some(connection) = self.connections.get(relay_url) else {
                return;
            };
            if !connection.holds_subscription_permit(&subscription_id) {
                tracing::debug!(
                    relay = %relay_url,
                    sub_id = %subscription_id,
                    "Ignoring auth-required CLOSED for an unowned subscription"
                );
                return;
            }
            // A retry is only worth reserving when the SDK will actually
            // answer the challenge and resubscribe; without an authenticator
            // the subscription is already gone and a reserved retry would
            // dangle until disconnect cleanup.
            if connection.answers_auth_challenges()
                && reserve_authentication_retry(
                    &mut self.auth_required_attempts,
                    relay_url,
                    &subscription_id,
                )
            {
                tracing::info!(
                    relay = %relay_url,
                    sub_id = %subscription_id,
                    "Relay requested authentication; retaining subscription for one NIP-42 retry"
                );
                return;
            }
            connection
                .retire_auth_refused_subscription(&subscription_id)
                .await;
            Some(PolicyRefusal::AuthenticationRequired)
        } else {
            policy_refusal(reason)
        };
        if let Some(category) =
            policy_category.filter(|category| *category != PolicyRefusal::FilterIncompatible)
        {
            let removed_batch = {
                let mut pending = self.pending_sync_index.write().await;
                take_batch_containing_subscription(&mut pending, relay_url, &subscription_id)
            };
            if let Some(batch) = &removed_batch {
                self.release_removed_descendant_batch(relay_url, batch);
            }
            if is_descendant_live {
                if let Some(coverage) = self.descendant_live_coverage.remove(relay_url) {
                    if let Some(connection) = self.connections.get(relay_url) {
                        let _ = connection
                            .close_live_subscriptions(&coverage.subscription_ids)
                            .await;
                    }
                }
            }
            self.health_tracker.record_policy_refusal(relay_url);
            if let Some(metrics) = &self.metrics {
                metrics.record_policy_refusal(relay_url, category.label());
                metrics.record_health_state(relay_url, self.health_tracker.get_state(relay_url));
            }
            tracing::warn!(
                relay = %relay_url,
                sub_id = %subscription_id,
                category = category.label(),
                reason,
                retry_hours = 24,
                pending_batch_removed = removed_batch.is_some(),
                descendant_live = is_descendant_live,
                "Relay policy refused subscription; preserving connection and deferring coverage probe"
            );
            return;
        }
        if is_descendant_live {
            let coverage = self
                .descendant_live_coverage
                .remove(relay_url)
                .expect("descendant subscription belonged to tracked coverage");
            if let Some(connection) = self.connections.get(relay_url) {
                let _ = connection
                    .close_live_subscriptions(&coverage.subscription_ids)
                    .await;
            }
            let max_filters = self
                .connections
                .get(relay_url)
                .map(|connection| connection.max_filters_per_req())
                .unwrap_or(MAX_FILTERS_PER_REQ);
            self.descendant_sync_rotations
                .entry(relay_url.to_string())
                .or_default()
                .refresh(coverage.fallback_filters, max_filters);
            tracing::warn!(
                relay = %relay_url,
                sub_id = %subscription_id,
                reason,
                "Descendant live subscription closed; using historic fallback"
            );
            return;
        }

        if let Some(limit) = subscription_state_byte_limit(reason) {
            tracing::warn!(
                relay = %relay_url,
                limit,
                "Remote retained-subscription capacity exhausted; rebuilding bounded live coverage"
            );
            self.byte_limited_live_relays
                .insert(relay_url.to_string(), Instant::now());
            let removed_batch = if live_generation.is_none() {
                let mut pending = self.pending_sync_index.write().await;
                take_batch_containing_subscription(&mut pending, relay_url, &subscription_id)
            } else {
                None
            };
            if let Some(batch) = &removed_batch {
                self.release_removed_descendant_batch(relay_url, batch);
            }
            let has_pending = self.has_pending_batches(relay_url).await;
            if self.deferred_consolidations.request(relay_url, has_pending) {
                let _ = self.consolidate(relay_url).await;
            }
            return;
        }
        if is_rate_limit_message(reason) && !is_filter_count_refusal(reason) {
            let removed_batch = {
                let mut pending = self.pending_sync_index.write().await;
                take_batch_containing_subscription(&mut pending, relay_url, &subscription_id)
            };

            if let Some(batch) = removed_batch {
                self.release_removed_descendant_batch(relay_url, &batch);
                tracing::warn!(
                    relay = %relay_url,
                    sub_id = %subscription_id,
                    batch_id = batch.batch_id,
                    "Rate-limited subscription aborted its pending batch; retry deferred until cooldown"
                );
            } else if live_generation.is_some() {
                tracing::info!(
                    relay = %relay_url,
                    sub_id = %subscription_id,
                    "Rate-limited live subscription restoration deferred until cooldown"
                );
            }
            return;
        }

        // Only a filter-count refusal can be repaired by regrouping.
        // Invalid individual filters remain invalid even in one-filter REQs.
        if is_filter_count_refusal(reason) {
            let pending_filter_count = {
                let pending = self.pending_sync_index.read().await;
                let owns_pending = pending.get(relay_url).is_some_and(|batches| {
                    batches
                        .iter()
                        .any(|batch| batch.outstanding_subs.contains(&subscription_id))
                });
                // A minimum-churn replacement can retire the rejected group
                // before its CLOSED reaches the actor. That stale response
                // must not park the replacement's valid coverage for a day.
                if live_generation.is_none() && live_filter_count.is_none() && !owns_pending {
                    tracing::debug!(relay = %relay_url, sub_id = %subscription_id,
                        "Ignoring filter-count CLOSED for a retired subscription");
                    return;
                }
                pending.get(relay_url).and_then(|batches| {
                    batches.iter().find_map(|batch| {
                        batch
                            .pagination_state
                            .get(&subscription_id)
                            .map(|state| state.filters.len())
                    })
                })
            };
            if let (Some(rejected_count), Some(connection)) = (
                live_filter_count.or(pending_filter_count),
                self.connections.get(relay_url).cloned(),
            ) {
                if rejected_count > 1 {
                    let learned_limit = connection
                        .reduce_max_filters_per_req(rejected_count)
                        .unwrap_or_else(|| connection.max_filters_per_req());
                    if let Some(metrics) = &self.metrics {
                        metrics.record_policy_refusal(relay_url, "filter_count");
                    }
                    tracing::warn!(
                        relay = %relay_url,
                        rejected_filter_count = rejected_count,
                        learned_filter_count = learned_limit,
                        reason,
                        "Relay rejected filter count; regrouping complete live coverage"
                    );
                    let removed_batch = {
                        let mut pending = self.pending_sync_index.write().await;
                        take_batch_containing_subscription(
                            &mut pending,
                            relay_url,
                            &subscription_id,
                        )
                    };
                    if let Some(batch) = &removed_batch {
                        self.release_removed_descendant_batch(relay_url, batch);
                        self.recompute_new_sync_filters_for_relay(relay_url).await;
                    } else if let Some(generation) = live_generation {
                        self.restore_live_coverage_after_closed(relay_url, generation)
                            .await;
                    }
                    return;
                }
            }
        }

        if let Some(category) = policy_refusal(reason) {
            let removed_batch = {
                let mut pending = self.pending_sync_index.write().await;
                take_batch_containing_subscription(&mut pending, relay_url, &subscription_id)
            };
            if let Some(batch) = &removed_batch {
                self.release_removed_descendant_batch(relay_url, batch);
            }
            self.health_tracker.record_policy_refusal(relay_url);
            if let Some(metrics) = &self.metrics {
                metrics.record_policy_refusal(relay_url, category.label());
                metrics.record_health_state(relay_url, self.health_tracker.get_state(relay_url));
            }
            tracing::warn!(
                relay = %relay_url,
                sub_id = %subscription_id,
                category = category.label(),
                reason,
                retry_hours = 24,
                pending_batch_removed = removed_batch.is_some(),
                "Relay policy refused subscription; preserving connection and deferring coverage probe"
            );
            return;
        }

        if let Some(generation) = live_generation {
            self.health_tracker.record_rate_limit(relay_url);
            if let Some(metrics) = &self.metrics {
                metrics.record_health_state(relay_url, self.health_tracker.get_state(relay_url));
            }
            tracing::warn!(
                relay = %relay_url,
                sub_id = %subscription_id,
                generation,
                reason,
                "Unexpected live subscription closure; deferring one repair attempt until cooldown"
            );
        } else {
            // Includes CLOSED acknowledging the SDK deadline before our local
            // watchdog fires. EOSE already removes successful wire IDs.
            self.retire_incomplete_request_batch(relay_url, &subscription_id)
                .await;
        }
    }

    async fn restore_live_coverage_after_closed(&mut self, relay_url: &str, generation: u64) {
        let Some(current_generation) = self
            .connections
            .get(relay_url)
            .map(RelayConnection::current_subscription_generation)
        else {
            return;
        };
        if current_generation != generation {
            tracing::debug!(relay = %relay_url, generation, "Ignoring stale live CLOSED from retired session");
            return;
        }
        if !self
            .close_descendant_live_coverage(relay_url, "core live restoration")
            .await
        {
            return;
        }
        let now = Timestamp::now();
        let since = Timestamp::from(now.as_secs().saturating_sub(QUICK_RECONNECT_WINDOW_SECS));
        let filters = self.complete_live_filters(relay_url, Some(since)).await;
        let Some(connection) = self.connections.get(relay_url) else {
            return;
        };
        if connection.current_subscription_generation() != generation {
            return;
        }
        if let Err(error) = connection
            .replace_live_filter_groups(live_filter_groups(
                &filters,
                connection.max_filters_per_req(),
            ))
            .await
        {
            tracing::warn!(relay = %relay_url, %error, "Could not restore complete live coverage after relay CLOSED");
        } else {
            tracing::info!(relay = %relay_url, "Restored complete live coverage after relay CLOSED");
        }
    }

    async fn sync_due_byte_limited_relay(&mut self) {
        let now = Instant::now();
        let due = self
            .byte_limited_live_relays
            .iter()
            .find_map(|(relay, deadline)| (*deadline <= now).then(|| relay.clone()));
        let Some(relay_url) = due else {
            return;
        };

        if self.has_pending_batches(&relay_url).await {
            self.byte_limited_live_relays
                .insert(relay_url, now + Duration::from_secs(10));
            return;
        }

        let connected = self
            .relay_sync_index
            .read()
            .await
            .get(&relay_url)
            .is_some_and(|state| state.connection_status.is_live_sync_active());
        if !connected {
            self.byte_limited_live_relays
                .insert(relay_url, now + byte_limited_catchup_interval());
            return;
        }

        self.byte_limited_live_relays
            .insert(relay_url.clone(), now + byte_limited_catchup_interval());
        let overlap = byte_limited_catchup_interval() + Duration::from_secs(60);
        let since = Timestamp::from(Timestamp::now().as_secs().saturating_sub(overlap.as_secs()));
        let filters = self.complete_live_filters(&relay_url, Some(since)).await;
        let items = self.desired_items_for_relay(&relay_url).await;
        tracing::info!(
            relay = %relay_url,
            since = %since,
            "Starting paced catch-up for byte-limited persistent coverage"
        );
        self.historic_sync(&relay_url, filters, items, Some(since))
            .await;
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

        let mut desired_relays: HashSet<String> = self.derive_targets().await.into_keys().collect();
        desired_relays.extend(self.dependency_relay_deadlines.keys().cloned());
        desired_relays.extend(self.nip65_discovery.connection_targets());
        // GRASP-P seam: configured peers carry no public repositories; keep them.
        desired_relays.extend(self.grasp_p_peer_relays());

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
            relay_sample = ?to_disconnect.iter().take(LOG_COLLECTION_SAMPLE_SIZE).collect::<Vec<_>>(),
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
        let prior_status = {
            let index = self.relay_sync_index.read().await;
            index.get(relay_url).map(|state| state.connection_status)
        };
        if prior_status == Some(ConnectionStatus::Disconnecting) {
            tracing::debug!(
                relay = %relay_url,
                "Relay disconnect already in progress"
            );
            return;
        }

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

        // An unexpected disconnect has already ended the event loop. There is
        // no future notification to finish an intentional retirement.
        if prior_status == Some(ConnectionStatus::Disconnected) {
            self.complete_ended_session(relay_url, false).await;
            return;
        }

        tracing::info!(relay = %relay_url, "Disconnect initiated, waiting for event loop termination");
    }

    /// Retry disconnected relays that are ready for reconnection
    ///
    /// This method is called periodically by run_disconnect_checker.
    /// It identifies relays that:
    /// - Are currently disconnected
    /// - Have repos or root events to sync, or are wanted for another reason
    ///   (announcement targets, due NIP-65 work, configured GRASP-P peers)
    /// - Have passed the exponential backoff period (respects health tracker)
    ///
    /// For each eligible relay, a reconnection is queued via schedule_connect_relay.
    async fn retry_disconnected_relays(&mut self) {
        let mut desired_relays: HashSet<String> = self.derive_targets().await.into_keys().collect();
        desired_relays.extend(self.nip65_discovery.due_connection_targets(Instant::now()));
        // GRASP-P seam: a configured peer carries no public repository, so
        // without this one whose dial failed is never dialled by this loop.
        desired_relays.extend(self.grasp_p_peer_relays());

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
            relay_sample = ?to_reconnect.iter().take(LOG_COLLECTION_SAMPLE_SIZE).collect::<Vec<_>>(),
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
    /// For each relay whose adaptive subscription pause has expired:
    /// 1. Clears the rate limit state (sets to Healthy)
    /// 2. Recomputes required actions for that relay
    /// 3. Submits those actions
    async fn check_rate_limit_recovery(&mut self) {
        use crate::sync::algorithms::compute_actions;

        // Exit rate limiting for relays whose cooldown has expired
        let mut relays_to_recover: Vec<String> = self.health_tracker.exit_expired_rate_limits();
        let policy_relays = self.health_tracker.exit_expired_policy_refusals();
        for relay in policy_relays {
            if !relays_to_recover.contains(&relay) {
                relays_to_recover.push(relay);
            }
        }

        self.pending_live_repairs
            .extend(relays_to_recover.iter().cloned());
        for relay in self.health_tracker.exit_expired_request_pauses() {
            if !relays_to_recover.contains(&relay) {
                relays_to_recover.push(relay);
            }
        }
        if relays_to_recover.is_empty() {
            return;
        }

        // Recompute actions - could optimise by adding relays: Option<&[]> to derive_relay_targets
        let targets = self.derive_targets().await;

        for relay_url in relays_to_recover {
            if self.health_tracker.is_subscription_paused(&relay_url) {
                continue;
            }
            tracing::info!(relay = %relay_url, "Subscription pause expired; probing coverage");

            // A rate-limited CLOSED deliberately leaves live coverage down so
            // it cannot immediately recreate the rejected request burst.
            // Restore persistent coverage first when the relay admits work again.
            if self.pending_live_repairs.remove(&relay_url) {
                if let Some(generation) = self
                    .connections
                    .get(&relay_url)
                    .map(RelayConnection::current_subscription_generation)
                {
                    self.restore_live_coverage_after_closed(&relay_url, generation)
                        .await;
                }
            }

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
                        "Submitting recovered actions after subscription pause"
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
    async fn sync_live(
        &mut self,
        relay_url: &str,
        filters: &[Filter],
    ) -> Result<Vec<SubscriptionId>, String> {
        if filters.is_empty() {
            return Ok(vec![]);
        }

        let connection = match self.connections.get(relay_url) {
            Some(conn) => conn.clone(),
            None => {
                tracing::debug!(relay = %relay_url, "No connection found for live sync");
                return Err(format!("No connection found for live sync on {relay_url}"));
            }
        };

        let filter_groups = live_filter_groups(filters, connection.max_filters_per_req());
        let remote_limit = connection.remote_subscription_byte_limit();
        let (filter_groups, overflow_groups) = groups_within_subscription_byte_limit(
            filter_groups,
            remote_limit,
            connection.live_subscription_bytes(),
        );
        if overflow_groups > 0 {
            self.byte_limited_live_relays.insert(
                relay_url.to_string(),
                Instant::now() + byte_limited_catchup_interval(),
            );
            tracing::warn!(
                relay = %relay_url,
                remote_limit,
                overflow_groups,
                "Persistent coverage bounded by remote subscription-state limit; overflow will use paced catch-up"
            );
        }
        if filter_groups.is_empty() {
            return Ok(Vec::new());
        }
        let protected_subscription_ids = self
            .descendant_live_coverage
            .get(relay_url)
            .map(|coverage| coverage.subscription_ids.clone())
            .unwrap_or_default();
        connection
            .extend_live_filter_groups_minimally(
                filter_groups,
                &protected_subscription_ids,
            )
            .await
            .inspect_err(|error| {
                tracing::error!(relay = %relay_url, error = %error, "Failed to create complete live subscription set");
            })
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
        let filters = if items.repos.is_empty()
            && items.state_only_repos.is_empty()
            && items.root_events.is_empty()
        {
            filters
        } else {
            let frontier = self.descendant_thread_members(&items.root_events).await;
            packed_historic_filters(&items, &frontier)
        };
        self.historic_sync_with_options(
            relay_url,
            filters,
            items,
            since,
            PendingBatchPurpose::Core,
            false,
        )
        .await
    }

    async fn historic_sync_with_options(
        &mut self,
        relay_url: &str,
        filters: Vec<Filter>,
        items: PendingItems,
        since: Option<Timestamp>,
        purpose: PendingBatchPurpose,
        force_req_eose: bool,
    ) -> Option<u64> {
        if self.health_tracker.is_subscription_paused(relay_url) {
            return None;
        }
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

        let result_tx = self.history_result_tx.clone()?;
        let batch_id = self.next_batch_id();
        // A local admission barrier prevents early EOSE from confirming a batch
        // while its worker is still reconciling or admitting later paced groups.
        let barrier = SubscriptionId::generate();
        self.pending_sync_index
            .write()
            .await
            .entry(relay_url.to_owned())
            .or_default()
            .push(PendingBatch {
                batch_id,
                purpose,
                items,
                outstanding_subs: HashSet::from([barrier.clone()]),
                sync_method: SyncMethod::ReqEose,
                pagination_state: HashMap::new(),
                requested_event_ids: None,
                received_event_ids: None,
                initial_hydration_counts: None,
                retry_count: 0,
                failed: false,
            });
        self.history_tasks.spawn(
            history::HistoryJob {
                relay_url: relay_url.to_owned(),
                batch_id,
                barrier,
                connection,
                filters: filters_with_since,
                allow_negentropy: !force_req_eose && !self.config.sync_disable_negentropy,
                prepared: None,
                wait_for_cooldown: false,
                health: self.health_tracker.clone(),
                pending: self.pending_sync_index.clone(),
                purgatory: self.purgatory.clone(),
                rejected: self.rejected_events_index.clone(),
                grasp_p: self.write_policy.grasp_p().cloned(),
            },
            result_tx,
        );
        Some(batch_id)
    }

    async fn spawn_history_queries(
        &mut self,
        relay_url: &str,
        batch_id: u64,
        queries: Vec<(SubscriptionId, Vec<Filter>, TransientRequestClass)>,
        wait_for_cooldown: bool,
    ) {
        let (Some(connection), Some(result_tx)) = (
            self.connections.get(relay_url).cloned(),
            self.history_result_tx.clone(),
        ) else {
            return;
        };
        let barrier = SubscriptionId::generate();
        {
            let mut pending = self.pending_sync_index.write().await;
            let Some(batch) = pending
                .get_mut(relay_url)
                .and_then(|batches| batches.iter_mut().find(|batch| batch.batch_id == batch_id))
            else {
                return;
            };
            batch.outstanding_subs.insert(barrier.clone());
        }
        self.history_tasks.spawn(
            history::HistoryJob {
                relay_url: relay_url.to_owned(),
                batch_id,
                barrier,
                connection,
                filters: Vec::new(),
                allow_negentropy: false,
                prepared: Some(queries),
                wait_for_cooldown,
                health: self.health_tracker.clone(),
                pending: self.pending_sync_index.clone(),
                purgatory: self.purgatory.clone(),
                rejected: self.rejected_events_index.clone(),
                grasp_p: self.write_policy.grasp_p().cloned(),
            },
            result_tx,
        );
    }

    async fn handle_history_result(&mut self, result: history::HistoryResult) {
        self.history_tasks.complete(&result.barrier);
        match result.outcome {
            Ok(()) => self.handle_eose(&result.relay_url, result.barrier).await,
            Err(error) => {
                let batch = {
                    let mut pending = self.pending_sync_index.write().await;
                    take_batch_containing_subscription(
                        &mut pending,
                        &result.relay_url,
                        &result.barrier,
                    )
                };
                if let Some(batch) = batch {
                    self.release_removed_descendant_batch(&result.relay_url, &batch);
                    if let Some(connection) = self.connections.get(&result.relay_url) {
                        for id in &batch.outstanding_subs {
                            if id != &result.barrier {
                                connection.retire_subscription(id).await;
                            }
                        }
                    }
                    if batch.retry_count > 0 {
                        if let Some(requested) = &batch.requested_event_ids {
                            let received = batch
                                .received_event_ids
                                .as_ref()
                                .cloned()
                                .unwrap_or_default();
                            let missing =
                                requested.difference(&received).copied().collect::<Vec<_>>();
                            let degraded = self
                                .relay_sync_index
                                .read()
                                .await
                                .get(&result.relay_url)
                                .is_some_and(|state| state.historic_sync_had_failures);
                            self.missing_event_recovery.lock().unwrap().register(
                                &result.relay_url,
                                batch.batch_id,
                                missing,
                                degraded,
                                Instant::now(),
                            );
                        }
                        let mut batch = batch;
                        batch.failed = true;
                        self.confirm_batch(&result.relay_url, batch).await;
                    }
                    tracing::debug!(relay = %result.relay_url, batch_id = result.batch_id,
                        %error, "Historic admission interrupted");
                }
            }
        }
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
        self.pending_live_repairs.clear();
        self.history_tasks.clear();
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

    #[tokio::test(start_paused = true)]
    async fn connection_starts_are_spaced_without_catchup_bursts() {
        let pacer = Arc::new(Mutex::new(None));
        let semaphore = Arc::new(Semaphore::new(8));
        let health = Arc::new(RelayHealthTracker::with_defaults());
        let mut tasks = tokio::task::JoinSet::new();
        for n in 0..12 {
            let (pacer, semaphore, health) = (pacer.clone(), semaphore.clone(), health.clone());
            tasks.spawn(async move {
                let _permit = begin_connect_attempt(
                    semaphore,
                    pacer,
                    health,
                    &format!("wss://relay{n}.example"),
                )
                .await
                .unwrap();
                tokio::time::Instant::now()
            });
        }
        let first = tasks.join_next().await.unwrap().unwrap();
        // Simulate a long executor pause. Only one overdue attempt may start;
        // remaining workers must space themselves from the actual new start.
        tokio::time::advance(Duration::from_secs(30)).await;
        let mut previous = tasks.join_next().await.unwrap().unwrap();
        assert!(previous.duration_since(first) >= Duration::from_secs(30));
        while let Some(start) = tasks.join_next().await {
            let start = start.unwrap();
            assert!(start.duration_since(previous) >= Duration::from_millis(250));
            previous = start;
        }
    }

    #[tokio::test]
    async fn stalled_history_does_not_block_another_relays_live_startup() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::for_testing();
        config.sync_disable_negentropy = true;
        config.git_data_path = directory.path().join("git").to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let git_path = PathBuf::from(&config.git_data_path);
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_path.clone()));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .unwrap();
        let mut manager = SyncManager::new(
            None,
            "service.example".into(),
            runtime.stores.database.clone(),
            runtime.write_policy,
            runtime.relay,
            &config,
            git_path,
            None,
            None,
            None,
        );
        let (history_tx, mut history_rx) = tokio::sync::mpsc::channel(8);
        manager.history_result_tx = Some(history_tx);
        let (disconnect_tx, _disconnect_rx) = tokio::sync::mpsc::channel(100);
        let (eose_tx, mut eose_rx) = lifecycle_notification_channel();
        let (closed_tx, _closed_rx) = lifecycle_notification_channel();
        manager.disconnect_tx = Some(disconnect_tx);
        manager.eose_tx = Some(eose_tx);
        manager.subscription_closed_tx = Some(closed_tx);
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(100);
        let mut servers = tokio::task::JoinSet::new();
        let mut urls = Vec::new();
        for number in 0..2 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let observed_tx = observed_tx.clone();
            servers.spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                while let Some(Ok(frame)) = ws.next().await {
                    if !frame.is_text() {
                        continue;
                    }
                    let request: serde_json::Value =
                        serde_json::from_str(frame.to_text().unwrap()).unwrap();
                    if request[0] == "REQ" {
                        let live = request[2]["limit"] == 0;
                        observed_tx
                            .send((number, live, request[1].as_str().unwrap().to_owned()))
                            .await
                            .unwrap();
                        // Relay A never completes history. Relay B responds
                        // immediately, exercising EOSE during worker admission.
                        if live || number == 1 {
                            ws.send(Message::Text(
                                serde_json::json!(["EOSE", request[1]]).to_string().into(),
                            ))
                            .await
                            .unwrap();
                        }
                    }
                }
            });
            let connection = RelayConnection::new(
                url.clone(),
                None,
                RelayTargetSource::OperatorConfigured,
                OutboundTargetPolicy::default(),
            )
            .with_health_tracker(manager.health_tracker.clone());
            connection.connect(3).await.unwrap();
            connection.reset_subscription_budget(Some(4)); // One live and one historic slot.
            connection.reduce_max_filters_per_req(2);
            manager.connections.insert(url.clone(), connection);
            manager
                .relay_sync_index
                .write()
                .await
                .insert(url.clone(), RelayState::default());
            urls.push(url);
        }
        let mut stalled_sub = None;
        tokio::time::timeout(Duration::from_secs(5), async {
            manager.handle_connect_or_reconnect(&urls[0]).await;
            loop {
                let (number, live, id) = observed_rx.recv().await.unwrap();
                if number == 0 && !live { stalled_sub = Some(SubscriptionId::new(id)); break; }
            }
            // Admission now waits for relay A's occupied history slot. That
            // wait must not be inherited by the caller or another connection.
            manager.historic_sync_with_options(&urls[0],
                vec![Filter::new().kind(Kind::Custom(123)), Filter::new().kind(Kind::Custom(124))],
                PendingItems::default(), None, PendingBatchPurpose::Core, true).await.unwrap();
            manager.handle_connect_or_reconnect(&urls[1]).await;
            loop {
                let (number, live, _) = observed_rx.recv().await.unwrap();
                if number == 1 && live { break; }
            }
            let root = EventId::from_byte_array([0; 32]);
            let items = PendingItems { root_events: HashSet::from([root]), ..Default::default() };
            manager.historic_sync_with_options(&urls[1],
                vec![Filter::new().kind(Kind::Custom(125)), Filter::new().kind(Kind::Custom(126))],
                items, None, PendingBatchPurpose::Core, true).await.unwrap();
            // Process completions as the actor does; immediate EOSE on the
            // first group must not confirm the two-group batch prematurely.
            let mut checked_first_group = false;
            loop {
                tokio::select! {
                    Some(result) = history_rx.recv() => manager.handle_history_result(result).await,
                    Some(eose) = eose_rx.recv() => {
                        let first_group = manager.pending_sync_index.read().await.get(&eose.relay_url)
                            .into_iter().flatten().filter_map(|batch| batch.pagination_state.get(&eose.sub_id))
                            .any(|page| page.filters().iter().any(|filter| filter.kinds.as_ref().is_some_and(|kinds| kinds.contains(&Kind::Custom(125)))));
                        manager.handle_eose(&eose.relay_url, eose.sub_id).await;
                        if first_group {
                            assert!(!manager.relay_sync_index.read().await[&urls[1]].root_events.contains(&root));
                            checked_first_group = true;
                        }
                    },
                }
                if manager.relay_sync_index.read().await[&urls[1]].root_events.contains(&root) { break; }
            }
            assert!(checked_first_group);
        }).await.expect("relay B live coverage and history must not wait for relay A");
        assert!(!manager.relay_sync_index.read().await[&urls[0]].announcements_synced);
        assert!(!manager.pending_sync_index.read().await[&urls[0]].is_empty());
        let generation = manager.connections[&urls[0]].current_subscription_generation();
        let notification = |generation| SubscriptionClosedNotification {
            relay_url: urls[0].clone(),
            subscription_id: stalled_sub.clone().unwrap(),
            reason: "local request timeout".into(),
            generation: Some(generation),
            live_filter_count: None,
            timed_out: true,
        };
        manager
            .handle_request_timeout(notification(generation.wrapping_add(1)))
            .await;
        assert!(manager.pending_sync_index.read().await[&urls[0]]
            .iter()
            .any(|batch| batch.purpose == PendingBatchPurpose::Announcements));
        manager
            .handle_request_timeout(notification(generation))
            .await;
        assert!(!manager.pending_sync_index.read().await[&urls[0]]
            .iter()
            .any(|batch| batch.purpose == PendingBatchPurpose::Announcements));
        assert!(!manager.relay_sync_index.read().await[&urls[0]].announcements_synced);
        assert!(manager.relay_sync_index.read().await[&urls[1]].announcements_synced);
        // An SDK timeout can receive CLOSED before our watchdog wakes. That
        // terminal must retire pending work too, without claiming coverage.
        let closed_id = SubscriptionId::new("sdk-timeout-closed");
        let mut batch = manager.pending_sync_index.read().await[&urls[0]][0].clone();
        batch.outstanding_subs = HashSet::from([closed_id.clone()]);
        manager
            .pending_sync_index
            .write()
            .await
            .insert(urls[0].clone(), vec![batch]);
        manager
            .handle_subscription_closed(&urls[0], closed_id, "closed", None, None)
            .await;
        assert!(manager
            .pending_sync_index
            .read()
            .await
            .get(&urls[0])
            .is_none_or(Vec::is_empty));
        assert!(!manager.relay_sync_index.read().await[&urls[0]].announcements_synced);
        manager.shutdown().await;
        assert!(manager.pending_sync_index.read().await.is_empty());
        servers.abort_all();
    }

    #[tokio::test]
    async fn interrupted_historic_admission_does_not_confirm_partial_coverage() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::for_testing();
        config.git_data_path = directory.path().join("git").to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let git_path = PathBuf::from(&config.git_data_path);
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_path.clone()));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .unwrap();
        let mut manager = SyncManager::new(
            None,
            "service.example".into(),
            runtime.stores.database.clone(),
            runtime.write_policy,
            runtime.relay,
            &config,
            git_path,
            None,
            None,
            None,
        );
        let (history_tx, mut history_rx) = tokio::sync::mpsc::channel(8);
        manager.history_result_tx = Some(history_tx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let health = manager.health_tracker.clone();
        let server_url = url.clone();
        let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut complete_tx = Some(complete_tx);
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut count = 0;
            while let Some(Ok(frame)) = ws.next().await {
                if frame.is_close() {
                    break;
                }
                if !frame.is_text() {
                    continue;
                }
                let request: serde_json::Value =
                    serde_json::from_str(frame.to_text().unwrap()).unwrap();
                if request[0] == "REQ" {
                    count += 1;
                    if count == 4 {
                        complete_tx.take().unwrap().send(()).unwrap();
                    }
                    if count == 1 {
                        // The only ledger slot stays occupied until this pause
                        // is visible. Later groups cannot race past it.
                        health.record_rate_limit(&server_url);
                    }
                    ws.send(Message::Text(
                        serde_json::json!(["EOSE", request[1]]).to_string().into(),
                    ))
                    .await
                    .unwrap();
                }
            }
            count
        });
        struct AbortOnDrop(tokio::task::AbortHandle);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _server_guard = AbortOnDrop(server.abort_handle());
        let connection = RelayConnection::new(
            url.clone(),
            None,
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        )
        .with_health_tracker(manager.health_tracker.clone());
        connection.connect(3).await.unwrap();
        connection.reset_subscription_budget(Some(3)); // One usable slot.
        connection.reduce_max_filters_per_req(2); // One filter per group.
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let event_loop = tokio::spawn(connection.clone().run_event_loop(tx));
        let _event_guard = AbortOnDrop(event_loop.abort_handle());
        let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let _drain_guard = AbortOnDrop(drain.abort_handle());
        manager.connections.insert(url.clone(), connection.clone());
        let filters: Vec<_> = (1..=3)
            .map(|n| Filter::new().kind(Kind::Custom(n)))
            .collect();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            manager.historic_sync_with_options(
                &url,
                filters.clone(),
                PendingItems::default(),
                None,
                PendingBatchPurpose::Announcements,
                true,
            ),
        )
        .await
        .unwrap();
        assert!(result.is_some(), "admission runs in the background");
        let result = tokio::time::timeout(Duration::from_secs(5), history_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(result.outcome.is_err(), "partial admission must fail");
        manager.handle_history_result(result).await;
        assert!(manager.pending_sync_index.read().await.get(&url).is_none());
        assert_eq!(connection.subscription_count().await, 0);

        manager.health_tracker.clear_rate_limit(&url);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            manager.historic_sync_with_options(
                &url,
                filters,
                PendingItems::default(),
                None,
                PendingBatchPurpose::Announcements,
                true,
            ),
        )
        .await
        .unwrap();
        assert!(
            result.is_some(),
            "all groups must remain retryable after the pause"
        );
        tokio::time::timeout(Duration::from_secs(6), complete_rx)
            .await
            .unwrap()
            .unwrap();
        connection.disconnect().await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap(),
            4
        );
    }

    /// Seed both repositories before driving maintenance: sequential network
    /// publication can straddle ticks and leave their retry deadlines offset.
    #[tokio::test]
    async fn unresolved_repositories_share_one_dependency_poll_per_relay() {
        dependency_poll_regression(false).await;
    }

    #[tokio::test]
    async fn paused_dependency_peers_do_not_reserve_retries_or_block_healthy_peers() {
        dependency_poll_regression(true).await;
    }

    async fn dependency_poll_regression(exercise_pauses: bool) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve query observer listener");
        let address = listener.local_addr().unwrap();
        let relay_url = format!("ws://{address}");
        let (query_tx, query_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut query_tx = Some(query_tx);
            while let Some(frame) = socket.next().await {
                let frame = frame.unwrap();
                if !frame.is_text() {
                    continue;
                }
                let request: serde_json::Value =
                    serde_json::from_str(frame.to_text().unwrap()).unwrap();
                if request[0] == "REQ" {
                    // Observe the complete dependency exchange through its CLOSE.
                    query_tx
                        .take()
                        .expect("one batched dependency query")
                        .send(request.clone())
                        .unwrap();
                    socket
                        .send(Message::Text(
                            serde_json::json!(["EOSE", request[1]]).to_string().into(),
                        ))
                        .await
                        .unwrap();
                } else if request[0] == "CLOSE" {
                    break;
                }
            }
        });
        // Abort the owned fixture on assertion failure as well as normal exit.
        struct AbortServer(tokio::task::AbortHandle);
        impl Drop for AbortServer {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _server_guard = AbortServer(server.abort_handle());
        let directory = tempfile::tempdir().expect("create manager directory");
        let git_path = directory.path().join("git");
        let mut config = Config::for_testing();
        config.git_data_path = git_path.to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        // Cold-index behavior is the subject; no wall-clock TTL wait is needed.
        config.rejected_hot_cache_duration_secs = 0;
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_path.clone()));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory.clone(),
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .expect("create manager relay runtime");
        // Treat the observer as our own service to suppress unrelated live
        // subscriptions. Exact-ID recovery still uses its connected socket.
        let mut manager = SyncManager::new(
            None,
            address.to_string(),
            runtime.stores.database.clone(),
            runtime.write_policy,
            runtime.relay,
            &config,
            git_path.clone(),
            None,
            None,
            None,
        );
        let connection = RelayConnection::new(
            relay_url.clone(),
            None,
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection.connect(5).await.expect("connect query observer");
        manager.connections.insert(relay_url.clone(), connection);
        manager.relay_sync_index.write().await.insert(
            relay_url.clone(),
            RelayState {
                connection_status: ConnectionStatus::Connected,
                ..RelayState::default()
            },
        );
        let invitee = Keys::generate();
        let mut expected_ids = HashSet::new();
        for identifier in ["batched-dependency-one", "batched-dependency-two"] {
            let owner = Keys::generate();
            let invitation = EventBuilder::new(Kind::GitRepoAnnouncement, "Owner invitation")
                .tags([
                    Tag::identifier(identifier),
                    Tag::custom(
                        "clone",
                        [format!("https://example.invalid/{identifier}.git")],
                    ),
                    Tag::custom("relays", [relay_url.clone()]),
                    Tag::custom("maintainers", [invitee.public_key().to_hex()]),
                ])
                .finalize(&owner)
                .unwrap();
            expected_ids.insert(invitation.id.to_hex());
            manager.rejected_events_index.add_announcement_from_relay(
                invitation,
                owner.public_key(),
                identifier.into(),
                RejectionReason::DoesNotListService,
                Some(relay_url.clone()),
            );
            let acceptance = EventBuilder::new(Kind::GitRepoAnnouncement, "Invitee acceptance")
                .tags([
                    Tag::identifier(identifier),
                    Tag::custom("clone", [format!("http://{address}/{identifier}.git")]),
                    Tag::custom("relays", [relay_url.clone()]),
                    Tag::custom("maintainers", [owner.public_key().to_hex()]),
                ])
                .finalize(&invitee)
                .unwrap();
            purgatory.add_announcement(
                acceptance,
                identifier.into(),
                invitee.public_key(),
                git_path.join(identifier),
                HashSet::from([relay_url.clone()]),
            );
        }

        if exercise_pauses {
            let ids: HashSet<_> = expected_ids
                .iter()
                .map(|id| EventId::from_hex(id).unwrap())
                .collect();
            let batch = || DependencyRelayBatch {
                event_ids: ids.clone(),
                identifiers: HashSet::from(["dependency-poll".into()]),
            };
            manager.health_tracker.record_rate_limit(&relay_url);
            manager.spawn_batched_purgatory_dependency_refetch(HashMap::from([(
                relay_url.clone(),
                batch(),
            )]));
            assert!(
                manager
                    .dependency_refetch_attempts
                    .lock()
                    .unwrap()
                    .is_empty(),
                "a paused-only pass must not consume the next dependency retry"
            );

            // End the pause without waiting on a wall-clock cooldown. Recovery
            // must be immediately eligible, even inside the ID retry interval.
            manager.health_tracker.clear_rate_limit(&relay_url);
            let mut batches = HashMap::from([(relay_url.clone(), batch())]);
            let mut skipped_ids = Vec::new();
            for (n, url) in [
                "wss://policy.example",
                "wss://timeout.example",
                "wss://absent.example",
            ]
            .into_iter()
            .enumerate()
            {
                let id = EventId::from_byte_array([n as u8 + 1; 32]);
                skipped_ids.push(id);
                let mut pending = batch(); // Shared IDs must still use the healthy peer.
                pending.event_ids.insert(id);
                batches.insert(url.into(), pending);
                if n < 2 {
                    manager.connections.insert(
                        url.into(),
                        RelayConnection::new(
                            url.into(),
                            None,
                            RelayTargetSource::OperatorConfigured,
                            OutboundTargetPolicy::default(),
                        ),
                    );
                }
                if n == 0 {
                    manager.health_tracker.record_policy_refusal(url);
                } else if n == 1 {
                    manager.health_tracker.record_request_failure(url);
                }
            }
            manager.spawn_batched_purgatory_dependency_refetch(batches);
            let attempts = manager.dependency_refetch_attempts.lock().unwrap();
            assert!(ids.iter().all(|id| attempts.contains_key(id)));
            assert!(
                skipped_ids.iter().all(|id| !attempts.contains_key(id)),
                "paused and absent peers must not reserve their unique dependency IDs"
            );
        } else {
            // No background manager loop runs: this pass sees both fresh entries.
            tokio::time::timeout(
                Duration::from_secs(5),
                manager.sync_purgatory_announcements_to_index(),
            )
            .await
            .expect("maintenance must finish");
        }
        let query = tokio::time::timeout(Duration::from_secs(5), query_rx)
            .await
            .expect("dependency query deadline")
            .expect("query observer");
        assert_eq!(query.as_array().unwrap().len(), 3, "one exact-ID filter");
        let actual_ids: HashSet<String> = serde_json::from_value(query[2]["ids"].clone()).unwrap();
        assert_eq!(
            actual_ids, expected_ids,
            "both repositories share one query"
        );
        assert_eq!(query[2]["limit"], 2);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("query fixture must finish after CLOSE")
            .expect("query fixture");
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn hydration_completion_accounts_for_local_storage_but_keeps_missing_ids() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::for_testing();
        let git_path = directory.path().join("git");
        config.git_data_path = git_path.to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let runtime = crate::nostr::builder::create_relay(
            &config,
            Arc::new(crate::purgatory::Purgatory::new(git_path.clone())),
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .unwrap();
        let mut manager = SyncManager::new(
            None,
            "service.example".into(),
            runtime.stores.database.clone(),
            runtime.write_policy,
            runtime.relay,
            &config,
            git_path,
            None,
            None,
            None,
        );
        let keys = Keys::generate();
        let stored = EventBuilder::new(Kind::TextNote, "saved by a concurrent local push")
            .finalize(&keys)
            .unwrap();
        let missing = EventBuilder::new(Kind::TextNote, "not delivered")
            .finalize(&keys)
            .unwrap();
        let url = "wss://history.example";
        for include_missing in [false, true] {
            let sub = SubscriptionId::generate();
            let mut requested = HashSet::from([stored.id]);
            if include_missing {
                requested.insert(missing.id);
            }
            manager.pending_sync_index.write().await.insert(
                url.into(),
                vec![PendingBatch {
                    batch_id: u64::from(include_missing),
                    purpose: PendingBatchPurpose::Core,
                    items: PendingItems::default(),
                    outstanding_subs: HashSet::from([sub.clone()]),
                    sync_method: SyncMethod::Negentropy,
                    pagination_state: HashMap::new(),
                    requested_event_ids: Some(requested),
                    received_event_ids: Some(HashSet::new()),
                    initial_hydration_counts: Some((2, 1)),
                    retry_count: 0,
                    failed: false,
                }],
            );
            // No stream notification: persistence can happen after reconciliation,
            // outside the sync processor (for example, purgatory promotion).
            manager.database.save_event(&stored).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), manager.handle_eose(url, sub))
                .await
                .unwrap();
            if include_missing {
                let retry_sub = {
                    let pending = manager.pending_sync_index.read().await;
                    let batch = &pending[url][0];
                    assert_eq!(
                        batch.requested_event_ids,
                        Some(HashSet::from([missing.id])),
                        "the retry must exclude the locally stored event"
                    );
                    assert_eq!(batch.outstanding_subs.len(), 1);
                    batch.outstanding_subs.iter().next().unwrap().clone()
                };
                tokio::time::timeout(Duration::from_secs(5), manager.handle_eose(url, retry_sub))
                    .await
                    .unwrap();
            }
            assert!(!manager.pending_sync_index.read().await.contains_key(url));
            let pending = manager
                .missing_event_recovery
                .lock()
                .unwrap()
                .pending_ids(url);
            assert_eq!(
                pending,
                include_missing.then(|| vec![missing.id]),
                "only an actually absent ID may enter missing-event recovery"
            );
        }
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn delivered_unauthorized_state_completes_hydration_without_losing_dependency() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::for_testing();
        let git_path = directory.path().join("git");
        config.git_data_path = git_path.to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_path.clone()));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory.clone(),
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .unwrap();
        let owner = Keys::generate();
        let stranger = Keys::generate();
        // Seed a hosted coordinate with the same identifier but no relationship
        // to the other author. This is the production test3 collision.
        let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
            .tags([
                Tag::identifier("test3"),
                Tag::custom("clone", ["https://service.example/test3.git"]),
            ])
            .finalize(&owner)
            .unwrap();
        runtime
            .stores
            .database
            .save_event(&announcement)
            .await
            .unwrap();
        let event = EventBuilder::new(Kind::RepoState, "")
            .tags([
                Tag::identifier("test3"),
                Tag::custom(
                    "refs/heads/main",
                    ["1111111111111111111111111111111111111111"],
                ),
                Tag::custom("HEAD", ["ref: refs/heads/main"]),
            ])
            .finalize(&stranger)
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let served_event = event.clone();
        let mut server = tokio::task::JoinSet::new();
        server.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            while let Some(Ok(frame)) = socket.next().await {
                if !frame.is_text() {
                    continue;
                }
                let message: serde_json::Value =
                    serde_json::from_str(frame.to_text().unwrap()).unwrap();
                if message[0] == "REQ" {
                    socket
                        .send(Message::Text(
                            serde_json::json!(["EVENT", message[1], served_event])
                                .to_string()
                                .into(),
                        ))
                        .await
                        .unwrap();
                    socket
                        .send(Message::Text(
                            serde_json::json!(["EOSE", message[1]]).to_string().into(),
                        ))
                        .await
                        .unwrap();
                }
            }
        });
        let mut manager = SyncManager::new(
            None,
            "service.example".into(),
            runtime.stores.database.clone(),
            runtime.write_policy,
            runtime.relay,
            &config,
            git_path.clone(),
            None,
            None,
            None,
        );
        // Expire full payloads immediately: cold metadata must still prevent
        // transport retries and retain the ID/hint for later membership changes.
        manager.rejected_events_index = Arc::new(RejectedEventsIndex::new(
            Duration::ZERO,
            Duration::from_secs(3600),
        ));
        let connection = RelayConnection::new(
            url.clone(),
            None,
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection.connect(3).await.unwrap();
        manager.connections.insert(url.clone(), connection.clone());
        manager.nip65_discovery_only_relays.insert(url.clone());
        let (disconnect_tx, _disconnect_rx) = tokio::sync::mpsc::channel(8);
        let (eose_tx, mut eose_rx) = lifecycle_notification_channel();
        let (closed_tx, _closed_rx) = lifecycle_notification_channel();
        manager.disconnect_tx = Some(disconnect_tx);
        manager.eose_tx = Some(eose_tx);
        manager.subscription_closed_tx = Some(closed_tx);
        manager.handle_connect_or_reconnect(&url).await;
        for number in 0..2 {
            let sub = SubscriptionId::new(format!("state-{number}"));
            manager.pending_sync_index.write().await.insert(
                url.clone(),
                vec![PendingBatch {
                    batch_id: number,
                    purpose: PendingBatchPurpose::Core,
                    items: PendingItems::default(),
                    outstanding_subs: HashSet::from([sub.clone()]),
                    sync_method: SyncMethod::Negentropy,
                    pagination_state: HashMap::new(),
                    requested_event_ids: Some(HashSet::from([event.id])),
                    received_event_ids: Some(HashSet::new()),
                    initial_hydration_counts: None,
                    retry_count: 0,
                    failed: false,
                }],
            );
            connection
                .subscribe_filter_with_id(
                    Filter::new().id(event.id),
                    TransientRequestClass::NegentropyRetry,
                    sub.clone(),
                )
                .await
                .unwrap();
            let eose = tokio::time::timeout(Duration::from_secs(5), eose_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(eose.sub_id, sub);
            if number == 0 {
                assert_eq!(
                    manager.pending_sync_index.read().await[&url][0].received_event_ids,
                    Some(HashSet::from([event.id])),
                    "a delivered dependency must satisfy initial hydration"
                );
            }
            manager.handle_eose(&url, eose.sub_id).await;
            assert!(!manager.pending_sync_index.read().await.contains_key(&url));
            assert!(manager.missing_event_recovery.lock().unwrap().pending_ids(&url).is_none(),
                "cached delivery must not create missing-event recovery even if the SDK suppresses its notification");
        }
        assert!(manager
            .rejected_events_index
            .is_dependency_pending(&event.id));
        assert!(runtime
            .stores
            .database
            .event_by_id(&event.id)
            .await
            .unwrap()
            .is_none());
        assert!(
            purgatory.find_state("test3").is_empty(),
            "unauthorized state must not enter Git-fetch purgatory"
        );
        assert!(!git_path
            .join(stranger.public_key().to_bech32().unwrap())
            .exists());

        // An already-running exact-ID recovery must also finish when its
        // response is a retained dependency, without deleting that dependency.
        let now = Instant::now();
        let attempt = {
            let mut recovery = manager.missing_event_recovery.lock().unwrap();
            recovery.register(&url, 8, [event.id], false, now);
            recovery
                .begin_attempt(&url, now + Duration::from_secs(60))
                .unwrap()
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            SyncManager::run_missing_event_recovery_attempt(
                url.clone(),
                connection.clone(),
                attempt,
                manager.database.clone(),
                manager.write_policy.clone(),
                manager.local_relay.clone(),
                manager.rejected_events_index.clone(),
                manager.missing_event_recovery.clone(),
                manager.relay_sync_index.clone(),
                None,
            ),
        )
        .await
        .unwrap();
        assert!(manager
            .missing_event_recovery
            .lock()
            .unwrap()
            .pending_ids(&url)
            .is_none());
        assert!(manager
            .rejected_events_index
            .is_dependency_pending(&event.id));

        manager.missing_event_recovery.lock().unwrap().register(
            &url,
            9,
            [event.id],
            false,
            Instant::now(),
        );
        manager.tick_missing_event_recovery().await;
        assert!(manager
            .missing_event_recovery
            .lock()
            .unwrap()
            .pending_ids(&url)
            .is_none());
        assert!(
            manager
                .rejected_events_index
                .is_dependency_pending(&event.id),
            "transport completion must not remove the authorization dependency"
        );
        let (ids, hot) = manager.rejected_events_index.dependency_candidates(
            &stranger.public_key(),
            "test3",
            Some(rejected_index::EventType::State),
        );
        assert_eq!(ids, vec![event.id]);
        assert!(hot.is_empty());
        assert!(manager
            .rejected_events_index
            .dependency_relay_hints(
                &stranger.public_key(),
                "test3",
                Some(rejected_index::EventType::State)
            )
            .contains(&url));
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn accepted_dependency_reprocesses_a_synced_policy_orphan() {
        let directory = tempfile::tempdir().expect("create test directory");
        let git_data_path = directory.path().join("git");
        let mut config = Config::for_testing();
        config.git_data_path = git_data_path.to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_data_path));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .expect("create test relay runtime");
        let rejected = Arc::new(RejectedEventsIndex::new(
            Duration::from_secs(120),
            Duration::from_secs(604800),
        ));
        let keys = Keys::generate();
        let parent = EventBuilder::new(Kind::GitUserGraspList, "dependency")
            .finalize(&keys)
            .expect("build accepted dependency");
        let child = EventBuilder::new(Kind::TextNote, "dependent comment")
            .tags([Tag::event(parent.id)])
            .finalize(&keys)
            .expect("build dependent event");

        let orphan_result = SyncManager::process_event_static(
            &child,
            "wss://source.example",
            &runtime.stores.database,
            &runtime.write_policy,
            &runtime.relay,
            &rejected,
            crate::nostr::persistence::SaveContext::RelaySync,
        )
        .await;
        assert_eq!(
            orphan_result,
            ProcessResult::Rejected(PolicyRejection::Restricted)
        );
        assert!(rejected.is_dependency_pending(&child.id));
        assert!(orphan_result.is_hydration_accounted(&child.id, &rejected));
        assert!(!orphan_result.is_terminally_accounted());
        assert!(runtime
            .stores
            .database
            .event_by_id(&child.id)
            .await
            .unwrap()
            .is_none());

        let parent_result = SyncManager::process_event_static(
            &parent,
            "wss://source.example",
            &runtime.stores.database,
            &runtime.write_policy,
            &runtime.relay,
            &rejected,
            crate::nostr::persistence::SaveContext::RelaySync,
        )
        .await;
        assert_eq!(parent_result, ProcessResult::Saved);
        assert!(runtime
            .stores
            .database
            .event_by_id(&child.id)
            .await
            .unwrap()
            .is_some());
        assert!(!rejected.contains(&child.id));
    }

    #[tokio::test]
    async fn replaced_sync_event_is_reported_as_duplicate() {
        let directory = tempfile::tempdir().expect("create test directory");
        let git_data_path = directory.path().join("git");
        let mut config = Config::for_testing();
        config.git_data_path = git_data_path.to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_data_path));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .expect("create test relay runtime");
        let rejected = Arc::new(RejectedEventsIndex::new(
            Duration::from_secs(120),
            Duration::from_secs(604800),
        ));
        let keys = Keys::generate();
        let older = EventBuilder::new(Kind::GitUserGraspList, "older")
            .custom_created_at(Timestamp::from_secs(100))
            .finalize(&keys)
            .expect("build older replaceable event");
        let newer = EventBuilder::new(Kind::GitUserGraspList, "newer")
            .custom_created_at(Timestamp::from_secs(200))
            .finalize(&keys)
            .expect("build newer replaceable event");
        runtime
            .stores
            .database
            .save_event(&newer)
            .await
            .expect("save newer replaceable event");

        let result = SyncManager::process_event_static(
            &older,
            "wss://source.example",
            &runtime.stores.database,
            &runtime.write_policy,
            &runtime.relay,
            &rejected,
            crate::nostr::persistence::SaveContext::RelaySync,
        )
        .await;

        assert_eq!(result, ProcessResult::Duplicate);
        assert!(runtime
            .stores
            .database
            .event_by_id(&older.id)
            .await
            .unwrap()
            .is_none());
        assert!(runtime
            .stores
            .database
            .event_by_id(&newer.id)
            .await
            .unwrap()
            .is_some());
    }

    /// SovTech: nostr-sdk can hand sync an event it checked only by the id
    /// the event claims (its verification cache is keyed on the id), and the
    /// write policy trusts a synced event's author. Sync therefore checks id
    /// and signature itself, and a refused forgery must not settle the fate
    /// of the genuine event with that id.
    #[tokio::test]
    async fn synced_event_that_does_not_verify_is_refused_without_settling_its_id() {
        let directory = tempfile::tempdir().expect("create test directory");
        let git_data_path = directory.path().join("git");
        let mut config = Config::for_testing();
        config.git_data_path = git_data_path.to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_data_path));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .expect("create test relay runtime");
        let rejected = Arc::new(RejectedEventsIndex::new(
            Duration::from_secs(120),
            Duration::from_secs(604800),
        ));
        let genuine = EventBuilder::new(Kind::GitUserGraspList, "genuine")
            .finalize(&Keys::generate())
            .expect("build genuine event");
        // What a relay can send once the SDK has cached the genuine id: the
        // same id and signature under another author, other content, or the
        // genuine content under a signature that is not the author's. The
        // first two fail the id check; only the signature check stops the
        // third, which would otherwise be stored unservable under the id.
        let mut other_author = genuine.clone();
        other_author.pubkey = Keys::generate().public_key();
        let mut other_content = genuine.clone();
        other_content.content = "forged".to_string();
        let mut other_signature = genuine.clone();
        other_signature.sig = EventBuilder::new(Kind::GitUserGraspList, "unrelated")
            .finalize(&Keys::generate())
            .expect("build unrelated event")
            .sig;
        assert!(other_signature.verify_id());
        assert!(!other_signature.verify_signature());

        for forged in [&other_author, &other_content, &other_signature] {
            let result = SyncManager::process_event_static(
                forged,
                "wss://source.example",
                &runtime.stores.database,
                &runtime.write_policy,
                &runtime.relay,
                &rejected,
                crate::nostr::persistence::SaveContext::RelaySync,
            )
            .await;
            assert_eq!(result, ProcessResult::Rejected(PolicyRejection::Other));
            assert!(!result.is_terminally_accounted());
            assert!(!rejected.contains(&genuine.id));
        }
        assert!(runtime
            .stores
            .database
            .event_by_id(&genuine.id)
            .await
            .unwrap()
            .is_none());

        let result = SyncManager::process_event_static(
            &genuine,
            "wss://source.example",
            &runtime.stores.database,
            &runtime.write_policy,
            &runtime.relay,
            &rejected,
            crate::nostr::persistence::SaveContext::RelaySync,
        )
        .await;
        assert_eq!(result, ProcessResult::Saved);
    }

    #[test]
    fn private_members_include_only_owners_of_accepted_relays() {
        let configured = Keys::generate().public_key();
        let accepted_owner = Keys::generate().public_key();
        let unrelated_owner = Keys::generate().public_key();
        let members = effective_private_members(
            &HashSet::from([configured]),
            &HashSet::from(["wss://accepted.example/".to_string()]),
            &HashMap::from([
                ("wss://accepted.example/".to_string(), accepted_owner),
                ("wss://unrelated.example/".to_string(), unrelated_owner),
            ]),
        );

        assert_eq!(members, HashSet::from([configured, accepted_owner]));
    }

    #[test]
    fn partial_nip65_batch_retries_missing_authors_early() {
        let returned = Keys::generate().public_key();
        let missing = Keys::generate().public_key();
        let represented = HashSet::from([returned]);

        assert_eq!(
            nip65_author_retry_after(true, &represented, &returned),
            nip65_discovery_refresh_interval()
        );
        assert_eq!(
            nip65_author_retry_after(true, &represented, &missing),
            nip65_discovery_retry_interval()
        );
        assert_eq!(
            nip65_author_retry_after(false, &represented, &returned),
            nip65_discovery_retry_interval()
        );
    }

    #[test]
    fn retained_list_does_not_mask_an_empty_new_outbox_response() {
        let author_with_retained_list = Keys::generate().public_key();
        // `represented_by_source` is intentionally empty: a relay list held
        // in the local database came from an earlier source, while this newly
        // followed outbox returned no list and needs the short retry cadence.
        let represented_by_source = HashSet::new();

        assert_eq!(
            nip65_author_retry_after(true, &represented_by_source, &author_with_retained_list,),
            nip65_discovery_retry_interval()
        );
        let represented_by_source = HashSet::from([author_with_retained_list]);
        assert_eq!(
            nip65_author_retry_after(true, &represented_by_source, &author_with_retained_list,),
            nip65_discovery_refresh_interval()
        );
    }

    #[test]
    fn event_pipeline_window_separates_queue_and_processing_costs() {
        let mut window = EventPipelineWindow::default();
        window.record(
            ProcessResult::Duplicate,
            std::time::Duration::from_millis(12),
            std::time::Duration::from_millis(3),
        );
        window.record(
            ProcessResult::Saved,
            std::time::Duration::from_millis(8),
            std::time::Duration::from_millis(7),
        );

        assert_eq!(window.delivered, 2);
        assert_eq!(window.saved, 1);
        assert_eq!(window.duplicate, 1);
        assert_eq!(window.queue_delay, std::time::Duration::from_millis(20));
        assert_eq!(window.max_queue_delay, std::time::Duration::from_millis(12));
        assert_eq!(window.processing_time, std::time::Duration::from_millis(10));
        assert_eq!(
            window.max_processing_time,
            std::time::Duration::from_millis(7)
        );
    }

    #[test]
    fn hydration_outcomes_separate_terminal_and_retryable_failures() {
        use nostr::message::relay::SingleWord;
        use nostr_sdk::prelude::MachineReadablePrefix;

        let purgatory = MachineReadablePrefix::Custom(
            SingleWord::from_static("purgatory").expect("valid custom prefix"),
        );
        assert_eq!(
            SyncManager::classify_policy_result(
                &purgatory,
                "won't be served until git data arrives",
                true,
            ),
            ProcessResult::Purgatory
        );
        assert_eq!(
            SyncManager::classify_policy_result(
                &MachineReadablePrefix::Invalid,
                "this event is deleted",
                false,
            ),
            ProcessResult::Tombstoned
        );

        let invalid = SyncManager::classify_policy_result(
            &MachineReadablePrefix::Invalid,
            "malformed event",
            false,
        );
        let restricted = SyncManager::classify_policy_result(
            &MachineReadablePrefix::Restricted,
            "dependency not accepted yet",
            false,
        );
        let persistence_error = ProcessResult::PersistenceError;

        assert_eq!(invalid.hydration_outcome(), "rejected_invalid");
        assert!(invalid.is_terminally_accounted());
        assert_eq!(restricted.hydration_outcome(), "rejected_restricted");
        assert!(!restricted.is_terminally_accounted());
        assert!(!persistence_error.is_terminally_accounted());
        let rejected = RejectedEventsIndex::new(Duration::ZERO, Duration::from_secs(3600));
        let id = EventId::from_byte_array([42; 32]);
        assert!(!restricted.is_hydration_accounted(&id, &rejected));
        assert!(!persistence_error.is_hydration_accounted(&id, &rejected));
    }

    #[test]
    fn lifecycle_inbox_accepts_production_sized_terminal_burst() {
        let (tx, mut rx) = lifecycle_notification_channel::<EoseNotification>();
        for index in 0..169 {
            tx.try_send(EoseNotification {
                relay_url: "wss://relay.example".to_string(),
                sub_id: SubscriptionId::new(format!("hydration-{index}")),
            })
            .expect("the actor-side receiver remains alive");
        }

        assert_eq!(rx.len(), 169);
        for _ in 0..169 {
            rx.try_recv().expect("every terminal remains queued");
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn descendant_frontier_derives_replaceable_and_addressable_coordinates() {
        let keys = Keys::generate();
        let addressable = EventBuilder::new(Kind::Custom(30_023), "addressable")
            .tag(Tag::custom("d", ["article-name"]))
            .finalize(&keys)
            .unwrap();
        let replaceable = EventBuilder::new(Kind::Custom(10_000), "replaceable")
            .finalize(&keys)
            .unwrap();
        let regular = EventBuilder::new(Kind::TextNote, "regular")
            .finalize(&keys)
            .unwrap();
        let malformed_addressable = EventBuilder::new(Kind::Custom(30_023), "missing d")
            .finalize(&keys)
            .unwrap();

        assert_eq!(
            descendant_event_coordinate(&addressable),
            Some(format!("30023:{}:article-name", keys.public_key().to_hex()))
        );
        assert_eq!(
            descendant_event_coordinate(&replaceable),
            Some(format!("10000:{}:", keys.public_key().to_hex()))
        );
        assert_eq!(descendant_event_coordinate(&regular), None);
        assert_eq!(descendant_event_coordinate(&malformed_addressable), None);
    }

    #[tokio::test]
    async fn descendant_frontier_recurses_through_event_and_coordinate_references() {
        let keys = Keys::generate();
        let participant = Keys::generate();
        let reactor = Keys::generate();
        let root = EventBuilder::new(Kind::GitIssue, "root")
            .finalize(&keys)
            .expect("build root");
        let addressable = EventBuilder::new(Kind::Custom(30_023), "first descendant")
            .tags([Tag::identifier("thread-member"), Tag::event(root.id)])
            .finalize(&keys)
            .expect("build addressable descendant");
        let coordinate = descendant_event_coordinate(&addressable).unwrap();
        let coordinate_child = EventBuilder::new(Kind::TextNote, "coordinate child")
            .tag(Tag::custom("a", [coordinate.clone()]))
            .finalize(&participant)
            .expect("build coordinate child");
        let grandchild = EventBuilder::new(Kind::TextNote, "grandchild")
            .tag(Tag::event(coordinate_child.id))
            .finalize(&reactor)
            .expect("build grandchild");
        let unrelated = EventBuilder::new(Kind::TextNote, "unrelated")
            .finalize(&keys)
            .expect("build unrelated event");
        let database: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        for event in [
            &root,
            &addressable,
            &coordinate_child,
            &grandchild,
            &unrelated,
        ] {
            database.save_event(event).await.expect("save test event");
        }

        let frontier =
            recursive_descendant_frontier(&database, &HashSet::from([root.id]), 500).await;

        assert_eq!(
            frontier.event_ids,
            HashSet::from([addressable.id, coordinate_child.id, grandchild.id])
        );
        assert_eq!(frontier.coordinates, HashSet::from([coordinate]));
        assert_eq!(
            frontier.author_roots,
            HashMap::from([
                (keys.public_key(), HashSet::from([root.id])),
                (participant.public_key(), HashSet::from([root.id])),
                (reactor.public_key(), HashSet::from([root.id])),
            ])
        );
        assert!(!frontier.event_ids.contains(&unrelated.id));
    }

    #[tokio::test]
    async fn descendant_frontier_preserves_exact_root_provenance() {
        let owner = Keys::generate();
        let first_participant = Keys::generate();
        let second_participant = Keys::generate();
        let shared_participant = Keys::generate();
        let first_root = EventBuilder::new(Kind::GitIssue, "first root")
            .finalize(&owner)
            .expect("build first root");
        let second_root = EventBuilder::new(Kind::GitIssue, "second root")
            .finalize(&owner)
            .expect("build second root");
        let first_reply = EventBuilder::new(Kind::TextNote, "first reply")
            .tag(Tag::event(first_root.id))
            .finalize(&first_participant)
            .expect("build first reply");
        let second_reply = EventBuilder::new(Kind::TextNote, "second reply")
            .tag(Tag::event(second_root.id))
            .finalize(&second_participant)
            .expect("build second reply");
        let shared_reply = EventBuilder::new(Kind::TextNote, "shared reply")
            .tags([Tag::event(first_reply.id), Tag::event(second_reply.id)])
            .finalize(&shared_participant)
            .expect("build shared reply");
        let database: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        for event in [
            &first_root,
            &second_root,
            &first_reply,
            &second_reply,
            &shared_reply,
        ] {
            database.save_event(event).await.expect("save test event");
        }

        let frontier = recursive_descendant_frontier(
            &database,
            &HashSet::from([first_root.id, second_root.id]),
            500,
        )
        .await;

        assert_eq!(
            frontier.author_roots[&first_participant.public_key()],
            HashSet::from([first_root.id])
        );
        assert_eq!(
            frontier.author_roots[&second_participant.public_key()],
            HashSet::from([second_root.id])
        );
        assert_eq!(
            frontier.author_roots[&shared_participant.public_key()],
            HashSet::from([first_root.id, second_root.id])
        );
    }

    #[tokio::test]
    async fn descendant_frontier_stops_at_the_depth_bound() {
        let keys = Keys::generate();
        let root = EventBuilder::new(Kind::GitIssue, "root")
            .finalize(&keys)
            .expect("build root");
        let mut chain = Vec::new();
        let mut parent = root.id;
        for depth in 1..=MAX_DESCENDANT_FRONTIER_DEPTH + 1 {
            let child = EventBuilder::new(Kind::TextNote, format!("depth {depth}"))
                .tag(Tag::event(parent))
                .finalize(&keys)
                .expect("build descendant");
            parent = child.id;
            chain.push(child);
        }
        let database: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        database.save_event(&root).await.expect("save root");
        for event in &chain {
            database.save_event(event).await.expect("save descendant");
        }

        let frontier =
            recursive_descendant_frontier(&database, &HashSet::from([root.id]), 500).await;

        assert_eq!(frontier.event_ids.len(), MAX_DESCENDANT_FRONTIER_DEPTH);
        assert!(chain[..MAX_DESCENDANT_FRONTIER_DEPTH]
            .iter()
            .all(|event| frontier.event_ids.contains(&event.id)));
        assert!(!frontier
            .event_ids
            .contains(&chain[MAX_DESCENDANT_FRONTIER_DEPTH].id));
    }

    #[tokio::test]
    async fn descendant_frontier_preserves_direct_members_and_bounds_recursive_events() {
        let keys = Keys::generate();
        let root = EventBuilder::new(Kind::GitIssue, "root")
            .finalize(&keys)
            .expect("build root");
        let direct = EventBuilder::new(Kind::TextNote, "direct member")
            .tag(Tag::event(root.id))
            .custom_created_at(Timestamp::from_secs(1))
            .finalize(&keys)
            .expect("build direct member");
        let direct_siblings: Vec<Event> = (0..3)
            .map(|index| {
                EventBuilder::new(Kind::TextNote, format!("direct sibling {index}"))
                    .tag(Tag::event(root.id))
                    .custom_created_at(Timestamp::from_secs(2 + index))
                    .finalize(&keys)
                    .expect("build direct sibling")
            })
            .collect();
        let mut children = Vec::new();
        for created_at in [30, 10, 20] {
            children.push(
                EventBuilder::new(Kind::TextNote, format!("created at {created_at}"))
                    .tag(Tag::event(direct.id))
                    .custom_created_at(Timestamp::from_secs(created_at))
                    .finalize(&keys)
                    .expect("build child"),
            );
        }
        let database: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        database
            .save_event(&direct)
            .await
            .expect("save direct member");
        for event in &direct_siblings {
            database
                .save_event(event)
                .await
                .expect("save direct sibling");
        }
        for event in &children {
            database.save_event(event).await.expect("save child");
        }

        let frontier = recursive_descendant_frontier_with_limits(
            &database,
            &HashSet::from([root.id]),
            MAX_DESCENDANT_FRONTIER_DEPTH,
            2,
        )
        .await;

        assert_eq!(frontier.event_ids.len(), 3);
        assert!(!frontier.event_ids.contains(&direct.id));
        assert!(direct_siblings
            .iter()
            .all(|event| frontier.event_ids.contains(&event.id)));
        assert!(children
            .iter()
            .all(|child| !frontier.event_ids.contains(&child.id)));
    }

    #[test]
    fn descendant_frontier_queries_event_and_coordinate_tag_variants() {
        let since = Timestamp::from_secs(1234);
        let frontier = DescendantFrontier {
            event_ids: HashSet::from([EventId::from_byte_array([7; 32])]),
            coordinates: HashSet::from([format!("30023:{}:article", "a".repeat(64))]),
            ..DescendantFrontier::default()
        };
        let filters = descendant_frontier_filters(&frontier, Some(since));

        assert_eq!(filters.len(), 6, "e/E/q and a/A/q must all be covered");
        assert!(filters.iter().all(|filter| {
            serde_json::to_value(filter).unwrap()["since"] == serde_json::json!(1234)
        }));
        let serialized = filters.iter().map(Filter::as_json).collect::<Vec<_>>();
        for tag in ["#e", "#E", "#a", "#A"] {
            assert!(
                serialized.iter().any(|filter| filter.contains(tag)),
                "missing {tag} descendant filter"
            );
        }
        assert_eq!(
            serialized
                .iter()
                .filter(|filter| filter.contains("#q"))
                .count(),
            2,
            "event IDs and coordinates each require quote coverage"
        );
    }

    #[test]
    fn mailbox_probe_filters_cover_repository_roots_and_descendants() {
        let root = EventId::from_byte_array([21; 32]);
        let descendant = EventId::from_byte_array([22; 32]);
        let repository = "30617:owner:repo".to_string();
        let coordinate = "30023:participant:thread".to_string();
        let frontier = DescendantFrontier {
            event_ids: HashSet::from([descendant]),
            coordinates: HashSet::from([coordinate.clone()]),
            ..Default::default()
        };

        let filters = mailbox_probe_filters(
            &HashSet::from([repository.clone()]),
            &HashSet::from([root]),
            &frontier,
        );
        let serialized = filters.iter().map(Filter::as_json).collect::<Vec<_>>();

        assert_eq!(filters.len(), 6, "a/A/q and e/E/q must be probed");
        for value in [repository, coordinate, root.to_hex(), descendant.to_hex()] {
            assert!(serialized.iter().any(|filter| filter.contains(&value)));
        }
    }

    #[test]
    fn repository_mailbox_scope_adds_every_known_root_without_broadening_participants() {
        let first_root = EventId::from_byte_array([23; 32]);
        let second_root = EventId::from_byte_array([24; 32]);
        let participant_root = EventId::from_byte_array([25; 32]);
        let repository = "30617:owner:maintained".to_string();
        let participant_repository = "30617:owner:participant".to_string();
        let root_repositories = HashMap::from([
            (first_root, repository.clone()),
            (second_root, repository.clone()),
            (participant_root, participant_repository.clone()),
        ]);

        let (repositories, roots) = expand_mailbox_probe_scope(
            &HashSet::from([repository.clone()]),
            &HashSet::from([participant_root]),
            &root_repositories,
        );

        assert_eq!(
            repositories,
            HashSet::from([repository, participant_repository])
        );
        assert_eq!(
            roots,
            HashSet::from([first_root, second_root, participant_root])
        );

        let (_, participant_only_roots) = expand_mailbox_probe_scope(
            &HashSet::new(),
            &HashSet::from([participant_root]),
            &root_repositories,
        );
        assert_eq!(participant_only_roots, HashSet::from([participant_root]));
    }

    #[test]
    fn repository_mailbox_root_overlay_tracks_inventory_growth() {
        let relay = "wss://maintainer.example".to_string();
        let repository = "30617:owner:maintained".to_string();
        let root = EventId::from_byte_array([26; 32]);
        let mailbox_repositories =
            HashMap::from([(relay.clone(), HashSet::from([repository.clone()]))]);
        let mut mailbox_roots = HashMap::new();

        merge_repository_roots_into_mailbox_overlay(
            &mut mailbox_roots,
            &mailbox_repositories,
            &HashMap::from([(root, repository)]),
        );

        assert_eq!(mailbox_roots[&relay], HashSet::from([root]));
    }

    #[test]
    fn mailbox_probe_order_prioritizes_longest_waiting_due_source() {
        let now = Instant::now();
        let root = EventId::from_byte_array([23; 32]);
        let roots = HashMap::from([
            ("wss://old.example".to_string(), HashSet::from([root])),
            (
                "wss://large.example".to_string(),
                HashSet::from([
                    root,
                    EventId::from_byte_array([24; 32]),
                    EventId::from_byte_array([25; 32]),
                ]),
            ),
            ("wss://future.example".to_string(), HashSet::from([root])),
        ]);
        let next_at = HashMap::from([
            (
                "wss://old.example".to_string(),
                now - Duration::from_secs(10),
            ),
            (
                "wss://large.example".to_string(),
                now - Duration::from_secs(1),
            ),
            (
                "wss://future.example".to_string(),
                now + Duration::from_secs(1),
            ),
        ]);

        assert_eq!(
            due_mailbox_relays(&roots, &HashMap::new(), &next_at, now),
            vec![
                "wss://old.example".to_string(),
                "wss://large.example".to_string(),
            ]
        );
    }

    #[test]
    fn repository_only_mailbox_scope_is_due() {
        let now = Instant::now();
        let relay = "wss://maintainer.example".to_string();
        let repositories = HashMap::from([(
            relay.clone(),
            HashSet::from(["30617:owner:repo".to_string()]),
        )]);

        assert_eq!(
            due_mailbox_relays(&HashMap::new(), &repositories, &HashMap::new(), now),
            vec![relay]
        );
    }

    #[test]
    fn private_mode_does_not_export_repository_mailbox_scope() {
        let author = Keys::generate().public_key();
        let scope = HashMap::from([(author, HashSet::from(["30617:owner:private".to_string()]))]);

        assert_eq!(public_repository_mailbox_scope(false, scope.clone()), scope);
        assert!(public_repository_mailbox_scope(true, scope).is_empty());
    }

    #[test]
    fn mailbox_probe_waits_for_committed_connection_lifecycle() {
        assert!(!mailbox_probe_connection_ready(
            Some(ConnectionStatus::Connecting),
            true,
        ));
        assert!(mailbox_probe_connection_ready(
            Some(ConnectionStatus::Syncing),
            true,
        ));
        assert!(!mailbox_probe_connection_ready(
            Some(ConnectionStatus::Connected),
            false,
        ));
    }

    #[test]
    fn mailbox_probe_prefers_ready_relay_over_older_unavailable_relay() {
        let unavailable = "wss://unavailable.example".to_string();
        let ready = "wss://ready.example".to_string();
        let due = vec![unavailable.clone(), ready.clone()];

        assert_eq!(
            select_due_mailbox_relay(&due, &HashSet::from([ready.clone()])),
            Some(ready),
        );
        assert_eq!(
            select_due_mailbox_relay(&due, &HashSet::new()),
            Some(unavailable),
        );
    }

    #[test]
    fn failed_identity_source_backs_off_across_authors_without_blocking_other_work() {
        let source = "wss://denied.example".to_string();
        let healthy = "wss://healthy.example".to_string();
        let author = Keys::generate().public_key();
        let newcomer = Keys::generate().public_key();
        let mut discovery = Nip65DiscoveryState::default();
        discovery
            .author_sources
            .insert(author, HashSet::from([source.clone(), healthy.clone()]));
        let mut now = Instant::now();
        let mut expected = nip65_discovery_retry_interval();
        for _ in 0..16 {
            let delay = discovery.record_discovery_outcome(&source, false, now);
            assert_eq!(delay, expected);
            assert!(!discovery.author_query_due(&source, &author, now));
            assert!(!discovery.due_connection_targets(now).contains(&source));
            assert!(discovery.due_connection_targets(now).contains(&healthy));
            discovery
                .author_sources
                .insert(newcomer, HashSet::from([source.clone()]));
            discovery.retain_discovery_backoff();
            assert!(!discovery.author_query_due(&source, &newcomer, now));
            now += delay;
            assert!(discovery.author_query_due(&source, &author, now));
            expected = expected.saturating_mul(2).min(Duration::from_secs(3600));
        }
        discovery.record_discovery_outcome(&source, false, now);
        discovery
            .mailbox_roots
            .insert(source.clone(), HashSet::new());
        assert!(
            discovery.due_connection_targets(now).contains(&source),
            "due mailbox work remains independent"
        );
        discovery
            .mailbox_probe_next_at
            .insert(source.clone(), now + Duration::from_secs(3600));
        assert!(!discovery.due_connection_targets(now).contains(&source));
        discovery.record_discovery_outcome(&source, true, now);
        assert!(discovery.author_query_due(&source, &author, now));
        assert_eq!(
            discovery.record_discovery_outcome(&source, false, now),
            nip65_discovery_retry_interval()
        );
        discovery.author_sources.clear();
        discovery.retain_discovery_backoff();
        discovery.record_discovery_outcome(&source, false, now);
        assert!(
            discovery.discovery_failure_backoff.is_empty(),
            "late results cannot recreate retired state"
        );
    }

    #[test]
    fn mailbox_cursor_survives_inventory_growth_and_retires_with_source() {
        let relay = "wss://mailbox.example".to_string();
        let first_root = EventId::from_byte_array([31; 32]);
        let second_root = EventId::from_byte_array([32; 32]);
        let mut discovery = Nip65DiscoveryState::default();
        discovery
            .mailbox_roots
            .insert(relay.clone(), HashSet::from([first_root]));
        discovery.mailbox_probe_next_filter.insert(relay.clone(), 3);
        let now = Instant::now();

        discovery.install_mailbox_overlay(
            HashMap::from([(relay.clone(), HashSet::from([first_root, second_root]))]),
            HashMap::new(),
            now,
        );
        assert_eq!(discovery.mailbox_probe_next_filter[&relay], 3);
        assert_eq!(discovery.mailbox_probe_next_at[&relay], now);

        discovery.install_mailbox_overlay(HashMap::new(), HashMap::new(), Instant::now());
        assert!(!discovery.mailbox_probe_next_filter.contains_key(&relay));
        assert!(!discovery.mailbox_probe_next_at.contains_key(&relay));
    }

    #[test]
    fn failed_mailbox_probes_back_off_until_success_and_survive_inventory_changes() {
        let relay = "wss://denied.example".to_string();
        let root = EventId::from_byte_array([34; 32]);
        let now = Instant::now();
        let mut discovery = Nip65DiscoveryState::default();
        discovery.install_mailbox_overlay(
            HashMap::from([(relay.clone(), HashSet::from([root]))]),
            HashMap::new(),
            now,
        );
        let mut expected = mailbox_probe_retry_interval();
        for _ in 0..16 {
            assert_eq!(discovery.mailbox_retry_delay(&relay, false), expected);
            expected = expected.saturating_mul(2).min(Duration::from_secs(3600));
        }
        let deadline = now + Duration::from_secs(3600);
        discovery.record_probe_completion(&relay, 1, Duration::from_secs(3600), now);
        discovery.install_mailbox_overlay(
            HashMap::from([(
                relay.clone(),
                HashSet::from([root, EventId::from_byte_array([35; 32])]),
            )]),
            HashMap::new(),
            now,
        );
        discovery.mailbox_connected(&relay, now);
        assert!(discovery.connection_targets().contains(&relay));
        assert!(!discovery.due_connection_targets(now).contains(&relay));
        assert!(discovery.due_connection_targets(deadline).contains(&relay));
        let author = Keys::generate().public_key();
        discovery
            .author_sources
            .insert(author, HashSet::from([relay.clone()]));
        assert!(discovery.due_connection_targets(now).contains(&relay));
        discovery.author_sources.clear();
        assert_eq!(discovery.mailbox_probe_next_at[&relay], deadline);
        assert_eq!(discovery.mailbox_retry_delay(&relay, true), Duration::ZERO);
        assert_eq!(
            discovery.mailbox_retry_delay(&relay, false),
            mailbox_probe_retry_interval()
        );
        discovery.install_mailbox_overlay(HashMap::new(), HashMap::new(), now);
        discovery.mailbox_retry_delay(&relay, false);
        assert!(discovery.mailbox_probe_failure_delay.is_empty());
    }

    #[test]
    fn mailbox_completion_for_removed_relay_leaves_no_cursor_state() {
        let relay = "wss://mailbox.example".to_string();
        let root = EventId::from_byte_array([33; 32]);
        let now = Instant::now();
        let mut discovery = Nip65DiscoveryState::default();
        discovery
            .mailbox_roots
            .insert(relay.clone(), HashSet::from([root]));

        discovery.record_probe_completion(&relay, 1, Duration::from_secs(60), now);
        assert_eq!(discovery.mailbox_probe_next_filter[&relay], 1);
        assert_eq!(
            discovery.mailbox_probe_next_at[&relay],
            now + Duration::from_secs(60)
        );

        discovery.install_mailbox_overlay(HashMap::new(), HashMap::new(), now);
        discovery.record_probe_completion(&relay, 2, Duration::from_secs(60), now);
        assert!(!discovery.mailbox_probe_next_filter.contains_key(&relay));
        assert!(!discovery.mailbox_probe_next_at.contains_key(&relay));
    }

    #[test]
    fn mailbox_completion_advances_after_failure_without_ending_cycle() {
        let (next_filter, completed_cycle, retry_after) = mailbox_probe_completion(0, 2, false);
        assert_eq!(next_filter, 1);
        assert!(!completed_cycle);
        assert_eq!(retry_after, mailbox_probe_retry_interval());
        assert!(!should_continue_mailbox_probe(false, completed_cycle));

        let (next_filter, completed_cycle, refresh_after) = mailbox_probe_completion(1, 2, true);
        assert_eq!(next_filter, 0);
        assert!(completed_cycle);
        assert_eq!(refresh_after, mailbox_probe_refresh_interval());
        assert!(!should_continue_mailbox_probe(true, completed_cycle));
    }

    #[test]
    fn mailbox_worker_continues_successful_partial_cycle() {
        let (next_filter, completed_cycle, retry_after) = mailbox_probe_completion(0, 2, true);
        assert_eq!(next_filter, 1);
        assert!(!completed_cycle);
        assert_eq!(retry_after, Duration::ZERO);
        assert!(should_continue_mailbox_probe(true, completed_cycle));
    }

    #[test]
    fn mailbox_worker_capacity_is_a_process_safety_ceiling() {
        assert!(mailbox_worker_capacity_available(
            MAX_CONCURRENT_MAILBOX_WORKERS - 1
        ));
        assert!(!mailbox_worker_capacity_available(
            MAX_CONCURRENT_MAILBOX_WORKERS
        ));
    }

    #[test]
    fn own_relay_targets_are_excluded_from_sync_actions() {
        assert!(is_own_sync_target("wss://gitnostr.com", "gitnostr.com"));
        assert!(is_own_sync_target("ws://gitnostr.com", "gitnostr.com"));
        assert!(is_own_sync_target("ws://127.0.0.1:7334", "127.0.0.1:7334"));
        assert!(is_own_sync_target(
            "wss://gitnostr.com/grasp",
            "gitnostr.com/grasp"
        ));

        assert!(!is_own_sync_target(
            "wss://gitnostr.com.attacker.example",
            "gitnostr.com"
        ));
        assert!(!is_own_sync_target("ws://127.0.0.1:7335", "127.0.0.1:7334"));
        assert!(!is_own_sync_target(
            "wss://gitnostr.com",
            "gitnostr.com/grasp"
        ));
        assert!(!is_own_sync_target(
            "wss://gitnostr.com/grasp/other",
            "gitnostr.com/grasp"
        ));
    }

    #[test]
    fn semantic_fallback_requires_material_first_pass_incompatibility() {
        for (requested, received) in [(118, 115), (203, 197), (380, 301), (1818, 1420)] {
            assert!(
                !should_use_semantic_fallback(requested, received),
                "{received}/{requested} is a residual, not a hydration incompatibility"
            );
        }

        assert!(should_use_semantic_fallback(20, 0));
        assert!(should_use_semantic_fallback(20, 2));
        assert!(!should_use_semantic_fallback(20, 3));
        assert!(!should_use_semantic_fallback(19, 0));
    }

    #[test]
    fn descendant_rotation_paces_complete_cycles_but_admits_new_frontiers() {
        let start = Instant::now();
        let timestamp = Timestamp::from_secs(200_000);
        let mut rotation = DescendantSyncRotation::default();
        let mut filters = vec![
            Filter::new().kind(Kind::TextNote),
            Filter::new().kind(Kind::GitIssue),
        ];
        rotation.refresh(filters.clone(), 1);
        for index in 0..2 {
            let (actual, _, until) = rotation.next_request(timestamp, start).unwrap();
            assert_eq!(actual, index);
            rotation.mark_started(index as u64, actual, until);
            assert!(rotation.mark_completed(index as u64, true, start));
        }
        // Advancing the wall clock alone cannot bypass the monotonic deadline.
        assert!(rotation
            .next_request(Timestamp::from_secs(900_000), start)
            .is_none());
        let due = start + descendant_fallback_refresh_interval();
        assert!(rotation
            .next_request(timestamp, due - Duration::from_nanos(1))
            .is_none());
        assert!(rotation.next_request(timestamp, due).is_some());

        filters.push(Filter::new().kind(Kind::GitPatch));
        rotation.refresh(filters, 1);
        assert!(rotation.next_request(timestamp, start).is_some());
        assert!(rotation.filters[..2]
            .iter()
            .all(|cursor| cursor.last_successful_until == Some(timestamp)));
        assert!(rotation.filters[2].last_successful_until.is_none());
    }

    #[test]
    fn descendant_rotation_advances_cursor_only_after_successful_eose() {
        let member = EventId::from_byte_array([7; 32]);
        let frontier = DescendantFrontier {
            event_ids: HashSet::from([member]),
            coordinates: HashSet::new(),
            ..DescendantFrontier::default()
        };
        let now = Timestamp::from_secs(200_000);
        let start = Instant::now();
        let retry_at = start + descendant_fallback_refresh_interval();
        let mut rotation = DescendantSyncRotation::default();

        rotation.refresh(
            descendant_frontier_filters(&frontier, None),
            MAX_FILTERS_PER_REQ,
        );
        let (filter_index, first, until) = rotation.next_request(now, start).unwrap();
        assert!(first
            .iter()
            .all(|filter| { serde_json::to_value(filter).unwrap().get("since").is_none() }));
        rotation.mark_started(41, filter_index, until);
        assert!(rotation.next_request(now, start).is_none());

        assert!(rotation.mark_completed(41, false, start));
        assert!(rotation.next_request(now, start).is_none());
        let (retry_index, retry, retry_until) = rotation.next_request(now, retry_at).unwrap();
        assert_eq!(retry_index, filter_index);
        assert!(retry
            .iter()
            .all(|filter| { serde_json::to_value(filter).unwrap().get("since").is_none() }));
        rotation.mark_started(42, retry_index, retry_until);
        assert!(rotation.mark_completed(42, true, retry_at));

        // All three e/E/q variants share one relay-compatible REQ, so the
        // next turn returns to that group with its successful overlap cursor.
        let (_, recent, _) = rotation
            .next_request(
                Timestamp::from_secs(201_000),
                retry_at + descendant_fallback_refresh_interval(),
            )
            .unwrap();
        assert!(recent.iter().all(|filter| {
            serde_json::to_value(filter).unwrap()["since"]
                == serde_json::json!(now.as_secs() - DESCENDANT_FALLBACK_OVERLAP_SECS)
        }));
    }

    #[test]
    fn tier_cutoff_keeps_only_complete_priority_tiers_live() {
        use filters::{CoverageTier, TieredFilter};

        let entries = vec![
            TieredFilter {
                tier: CoverageTier::RootUppercase,
                filter: Filter::new().kind(Kind::Custom(31_001)),
            },
            TieredFilter {
                tier: CoverageTier::CoreCompatibility,
                filter: Filter::new().kind(Kind::Custom(31_002)),
            },
            TieredFilter {
                tier: CoverageTier::CoreCompatibility,
                filter: Filter::new().kind(Kind::Custom(31_003)),
            },
            TieredFilter {
                tier: CoverageTier::DescendantCanonical,
                filter: Filter::new().kind(Kind::Custom(31_004)),
            },
            TieredFilter {
                tier: CoverageTier::HistoricOnly,
                filter: Filter::new().kind(Kind::Custom(31_005)),
            },
        ];

        let (live, rotated) = split_live_tier_prefix(&entries, 2, |groups| groups.len() <= 1);
        assert_eq!(
            live.len(),
            1,
            "the two-filter compatibility tier must not be split"
        );
        assert_eq!(rotated.len(), 4);
        assert!(rotated.iter().any(|filter| {
            filter.as_json() == Filter::new().kind(Kind::Custom(31_005)).as_json()
        }));

        let fallback = complete_auxiliary_fallback(&entries);
        assert_eq!(fallback.len(), entries.len());
        assert!(live.iter().all(|live_filter| fallback
            .iter()
            .any(|filter| filter.as_json() == live_filter.as_json())));
    }

    #[test]
    fn historic_packing_unions_core_and_descendant_reference_values() {
        let root = EventId::from_byte_array([1; 32]);
        let descendant = EventId::from_byte_array([2; 32]);
        let items = PendingItems {
            repos: HashSet::from(["30617:owner:repo".to_string()]),
            state_only_repos: HashSet::new(),
            root_events: HashSet::from([root]),
        };
        let frontier = DescendantFrontier {
            event_ids: HashSet::from([descendant]),
            coordinates: HashSet::from(["1621:author:patch".to_string()]),
            ..DescendantFrontier::default()
        };

        let packed = packed_historic_filters(&items, &frontier);
        // One state filter plus one a/A/q and one e/E/q family. Appending
        // descendants separately would produce thirteen filters here.
        assert_eq!(packed.len(), 7);
        let json = packed
            .iter()
            .map(Filter::as_json)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(json.contains(&root.to_hex()));
        assert!(json.contains(&descendant.to_hex()));
        assert!(json.contains("30617:owner:repo"));
        assert!(json.contains("1621:author:patch"));
    }

    #[test]
    fn large_descendant_frontier_splits_across_live_subscriptions() {
        let members: HashSet<EventId> = (0..600u32)
            .map(|index| {
                let mut bytes = [0u8; 32];
                bytes[..4].copy_from_slice(&index.to_be_bytes());
                EventId::from_byte_array(bytes)
            })
            .collect();
        let filters = descendant_frontier_filters(
            &DescendantFrontier {
                event_ids: members,
                coordinates: HashSet::new(),
                ..DescendantFrontier::default()
            },
            None,
        );
        let groups = live_filter_groups(&filters, MAX_FILTERS_PER_REQ);

        assert!(filters.len() > 3, "the frontier must span byte chunks");
        assert!(
            groups.len() > 1,
            "large complete descendant coverage must reserve several subscriptions"
        );
        assert!(groups
            .iter()
            .all(|group| group.len() <= MAX_FILTERS_PER_REQ));
    }

    #[test]
    fn group_filters_for_req_respects_count_and_byte_budgets() {
        // Many small filters group by the count cap.
        let small: Vec<Filter> = (0..25)
            .map(|i| Filter::new().id(EventId::from_byte_array([0; 32])).limit(i))
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

    #[test]
    fn lifecycle_notifications_apply_fixed_backpressure_under_peer_repetition() {
        let (sender, mut receiver) = lifecycle_notification_channel();

        for sequence in 0..LIFECYCLE_NOTIFICATION_CAPACITY {
            sender
                .try_send(sequence)
                .expect("the documented lifecycle capacity should be usable");
        }
        assert!(
            matches!(
                sender.try_send(LIFECYCLE_NOTIFICATION_CAPACITY),
                Err(tokio::sync::mpsc::error::TrySendError::Full(_))
            ),
            "repeated peer terminals must backpressure instead of retaining unbounded memory"
        );

        assert_eq!(receiver.try_recv().unwrap(), 0);
        sender
            .try_send(LIFECYCLE_NOTIFICATION_CAPACITY)
            .expect("draining one terminal must release exactly one queue slot");
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
            begin_connect_attempt(
                worker_semaphore,
                Arc::new(Mutex::new(None)),
                worker_health,
                relay,
            )
            .await
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
    fn grouped_pagination_advances_only_filters_that_fill_a_page() {
        let keys = Keys::generate();
        let metadata_filter = Filter::new().kind(Kind::Metadata);
        let note_filter = Filter::new().kind(Kind::TextNote);
        let mut pagination =
            PaginationState::new(vec![metadata_filter.clone(), note_filter.clone()]);

        for created_at in 1..=100 {
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

        let next_filters = pagination
            .next_page(&mut RelayPaginationSession::default())
            .expect("full observed page should paginate")
            .filters();
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
    fn raw_pagination_counts_purgatory_and_rejected_deliveries() {
        let keys = Keys::generate();
        let filter = Filter::new().kinds([Kind::GitRepoAnnouncement, Kind::RepoState]);
        let mut pagination = PaginationState::new(vec![filter]);
        let deliveries = [
            (
                EventBuilder::new(Kind::GitRepoAnnouncement, "purgatory")
                    .custom_created_at(Timestamp::from_secs(20))
                    .finalize(&keys)
                    .expect("build purgatory-routed event"),
                ProcessResult::Purgatory,
            ),
            (
                EventBuilder::new(Kind::RepoState, "rejected")
                    .custom_created_at(Timestamp::from_secs(10))
                    .finalize(&keys)
                    .expect("build rejected event"),
                ProcessResult::Rejected(PolicyRejection::Restricted),
            ),
        ];

        for (event, policy_result) in deliveries {
            // The production handler records here, before it knows this result.
            pagination.record_event(&event);
            assert!(matches!(
                policy_result,
                ProcessResult::Purgatory | ProcessResult::Rejected(_)
            ));
        }

        assert_eq!(pagination.filters[0].event_count, 2);
        assert_eq!(
            pagination.filters[0].min_created_at,
            Some(Timestamp::from_secs(10))
        );
    }

    #[test]
    fn raw_pagination_counts_repeat_deliveries_at_the_boundary() {
        let keys = Keys::generate();
        let filter = Filter::new().kind(Kind::TextNote);
        let mut pagination = PaginationState::new(vec![filter]);
        let event = EventBuilder::new(Kind::TextNote, "same relay delivery")
            .custom_created_at(Timestamp::from_secs(42))
            .finalize(&keys)
            .expect("build repeated event");

        for _ in 0..PAGINATION_THRESHOLD_FLOOR {
            // Repeat deliveries each consume a result slot even though the second and later
            // process as Duplicate after the raw-delivery accounting point.
            pagination.record_event(&event);
        }

        assert_eq!(
            pagination.filters[0].event_count,
            PAGINATION_THRESHOLD_FLOOR
        );
        assert!(pagination
            .next_page(&mut RelayPaginationSession::default())
            .is_some());
    }

    #[test]
    fn raw_pagination_counts_an_event_for_each_overlapping_filter() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "overlap")
            .custom_created_at(Timestamp::from_secs(42))
            .finalize(&keys)
            .expect("build overlapping event");
        let mut pagination = PaginationState::new(vec![
            Filter::new().kind(Kind::TextNote),
            Filter::new().author(keys.public_key()),
        ]);

        pagination.record_event(&event);

        assert_eq!(pagination.filters[0].event_count, 1);
        assert_eq!(pagination.filters[1].event_count, 1);
        assert_eq!(
            pagination.filters[0].min_created_at,
            pagination.filters[1].min_created_at
        );
    }

    #[test]
    fn adaptive_threshold_selects_from_observation_and_hint() {
        let mut observed_only = RelayPaginationSession::new(None);
        observed_only.observe_page(100);
        assert_eq!(observed_only.pagination_threshold(), 90);

        let hint_only = RelayPaginationSession::new(Some(500));
        assert_eq!(hint_only.pagination_threshold(), 450);

        let mut hint_vs_observed = RelayPaginationSession::new(Some(500));
        hint_vs_observed.observe_page(600);
        assert_eq!(hint_vs_observed.pagination_threshold(), 540);

        let mut sub_floor = RelayPaginationSession::new(Some(50));
        sub_floor.observe_page(80);
        assert_eq!(sub_floor.pagination_threshold(), 90);
    }

    #[test]
    fn productive_verification_page_discards_the_hint() {
        let keys = Keys::generate();
        let mut first_page = PaginationState::new(vec![Filter::new().kind(Kind::TextNote)]);
        for created_at in 100..200 {
            let event = EventBuilder::new(Kind::TextNote, created_at.to_string())
                .custom_created_at(Timestamp::from_secs(created_at))
                .finalize(&keys)
                .expect("build first-page event");
            first_page.record_event(&event);
        }
        let mut session = RelayPaginationSession::new(Some(1000));
        let mut verification = first_page
            .next_page(&mut session)
            .expect("a suspiciously short hinted page needs verification");
        assert_eq!(session.hint, PaginationHint::Verifying(1000));
        assert_eq!(
            verification.request_class(),
            TransientRequestClass::PaginationVerification
        );

        let unseen = EventBuilder::new(Kind::TextNote, "older unseen event")
            .custom_created_at(Timestamp::from_secs(99))
            .finalize(&keys)
            .expect("build productive verification event");
        for _ in 0..100 {
            verification.record_event(&unseen);
        }

        assert!(verification.next_page(&mut session).is_some());
        assert_eq!(session.hint, PaginationHint::Discarded);
        assert_eq!(session.pagination_threshold(), 90);
    }

    #[test]
    fn empty_verification_page_confirms_the_hint_without_another_page() {
        let keys = Keys::generate();
        let mut first_page = PaginationState::new(vec![Filter::new().kind(Kind::TextNote)]);
        for created_at in 100..200 {
            let event = EventBuilder::new(Kind::TextNote, created_at.to_string())
                .custom_created_at(Timestamp::from_secs(created_at))
                .finalize(&keys)
                .expect("build first-page event");
            first_page.record_event(&event);
        }
        let mut session = RelayPaginationSession::new(Some(1000));
        let verification = first_page
            .next_page(&mut session)
            .expect("a suspiciously short hinted page needs verification");

        assert!(verification.next_page(&mut session).is_none());
        assert_eq!(session.hint, PaginationHint::Verified(1000));
        assert_eq!(session.pagination_threshold(), 900);
    }

    #[test]
    fn deferred_consolidation_runs_only_after_final_batch_completion() {
        let relay_url = "wss://relay.example";
        let mut deferred = DeferredConsolidations::default();

        assert!(
            !deferred.request(relay_url, true),
            "an in-flight batch must defer instead of waiting in the sync actor"
        );
        assert!(
            !deferred.take_ready(relay_url, true),
            "consolidation must remain queued while another batch is pending"
        );

        assert!(
            deferred.take_ready(relay_url, false),
            "the final actor-owned batch completion must make consolidation runnable"
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

            assert!(!deferred.request(&relay_url, true));
            assert!(deferred.cancel(&relay_url));
            assert!(
                !deferred.take_ready(&relay_url, false),
                "a queued wakeup must not resurrect consolidation after {reason}"
            );
        }
    }

    #[test]
    fn rate_limit_classifier_covers_notice_and_closed_reason_forms() {
        for message in [
            "rate-limited: too many queries",
            "Rate limit exceeded",
            "slow down please",
            "subscription throttled",
        ] {
            assert!(is_rate_limit_message(message), "missed: {message}");
        }
        assert!(!is_rate_limit_message("blocked: unsupported filter"));
    }

    #[tokio::test]
    async fn retired_filter_count_refusal_does_not_pause_replacement_coverage() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::for_testing();
        config.sync_disable_negentropy = true;
        config.git_data_path = directory.path().join("git").to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let git_path = PathBuf::from(&config.git_data_path);
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_path.clone()));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .unwrap();
        let mut manager = SyncManager::new(
            None,
            "service.example".into(),
            runtime.stores.database.clone(),
            runtime.write_policy,
            runtime.relay,
            &config,
            git_path,
            None,
            None,
            None,
        );

        let url = "wss://limited.example";
        manager.health_tracker.record_success(url);
        manager
            .handle_subscription_closed(
                url,
                SubscriptionId::new("retired-live-group"),
                "rate-limited: REQ exceeds max filter count 1",
                None,
                None,
            )
            .await;
        assert!(!manager.health_tracker.is_subscription_paused(url));
        assert_eq!(
            manager.health_tracker.get_state(url),
            health::HealthState::Healthy
        );
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn oversized_filter_parks_retries_without_learning_a_filter_count() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::for_testing();
        config.sync_disable_negentropy = true;
        config.git_data_path = directory.path().join("git").to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let git_path = PathBuf::from(&config.git_data_path);
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_path.clone()));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .unwrap();
        let mut manager = SyncManager::new(
            None,
            "service.example".into(),
            runtime.stores.database.clone(),
            runtime.write_policy,
            runtime.relay,
            &config,
            git_path,
            None,
            None,
            None,
        );

        let url = "wss://limited.example";
        let connection = RelayConnection::new(
            url.into(),
            None,
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        let limit = connection.max_filters_per_req();
        let generation = connection.current_subscription_generation();
        manager.connections.insert(url.into(), connection.clone());
        let id = SubscriptionId::new("oversized-filter");
        manager.pending_sync_index.write().await.insert(
            url.into(),
            vec![PendingBatch {
                batch_id: 1,
                purpose: PendingBatchPurpose::Core,
                items: PendingItems::default(),
                outstanding_subs: HashSet::from([id.clone()]),
                sync_method: SyncMethod::ReqEose,
                pagination_state: HashMap::new(),
                requested_event_ids: None,
                received_event_ids: None,
                initial_hydration_counts: None,
                retry_count: 0,
                failed: false,
            }],
        );
        manager
            .handle_subscription_closed(
                url,
                id,
                "ERROR: bad req: error parsing #a: filter item too large",
                Some(generation),
                Some(8),
            )
            .await;
        assert!(manager.health_tracker.is_subscription_paused(url));
        assert_eq!(
            connection.max_filters_per_req(),
            limit,
            "splitting groups cannot repair an oversized individual filter"
        );
        assert!(!manager.has_pending_batches(url).await);
        manager.shutdown().await;
    }

    #[test]
    fn policy_refusal_classifier_uses_bounded_categories() {
        assert_eq!(
            policy_refusal("auth-required: this relay only serves private notes"),
            None,
            "authentication gets one SDK-owned retry before it becomes a policy refusal"
        );
        assert_eq!(
            policy_refusal("restricted: this relay does not accept REQs"),
            Some(PolicyRefusal::Restricted)
        );
        assert_eq!(
            policy_refusal("restricted: you are not a member of this relay"),
            Some(PolicyRefusal::MembershipRequired)
        );
        assert_eq!(
            policy_refusal("blocked: Request rejected"),
            Some(PolicyRefusal::Blocked)
        );
        assert_eq!(
            policy_refusal("ERROR: filter validation failed: invalid number of filters: 8"),
            Some(PolicyRefusal::FilterIncompatible)
        );
        assert_eq!(
            policy_refusal("rate-limited: REQ exceeds max filter count 3"),
            Some(PolicyRefusal::FilterIncompatible)
        );
        for reason in [
            "unsupported: invalid filters",
            "ERROR: bad req: error parsing #a: filter item too large",
            "ERROR: bad req: error parsing #A: filter item too large",
            "ERROR: bad req: error parsing #q: filter item too large",
            "invalid: Filter 'limit' must be a positive integer, got 0",
        ] {
            assert_eq!(
                policy_refusal(reason),
                Some(PolicyRefusal::FilterIncompatible)
            );
        }
        assert_eq!(policy_refusal("rate-limited: too many queries"), None);
        assert_eq!(policy_refusal("error: temporary backend failure"), None);
    }

    #[test]
    fn authentication_gets_one_same_subscription_retry() {
        let relay = "wss://private.example";
        let subscription_id = SubscriptionId::new("auth-retry");
        let mut attempts = HashSet::new();

        assert!(reserve_authentication_retry(
            &mut attempts,
            relay,
            &subscription_id
        ));
        assert!(!reserve_authentication_retry(
            &mut attempts,
            relay,
            &subscription_id
        ));
        assert!(
            attempts.is_empty(),
            "a refused retry must retire its marker"
        );
    }

    #[test]
    fn subscription_state_limit_parser_is_specific_and_extracts_bytes() {
        assert_eq!(
            subscription_state_byte_limit(
                "rate-limited: active subscriptions exceed max size 1048576 bytes"
            ),
            Some(1_048_576)
        );
        assert_eq!(
            subscription_state_byte_limit("rate-limited: too many queries"),
            None
        );
    }

    #[test]
    fn learned_subscription_byte_limit_reserves_transient_capacity() {
        let first = vec![Filter::new().kind(Kind::TextNote).limit(0)];
        let second = vec![Filter::new().kind(Kind::Metadata).limit(0)];
        let limit = SUBSCRIPTION_BYTE_RESERVED_MARGIN + req_message_size(&first);

        let (admitted, overflow) =
            groups_within_subscription_byte_limit(vec![first.clone(), second], Some(limit), 0);

        assert_eq!(admitted, vec![first]);
        assert_eq!(overflow, 1);
    }

    #[test]
    fn rate_limited_closed_removes_only_its_pending_batch_for_retry() {
        let relay_url = "wss://limited.example";
        let rejected = SubscriptionId::new("rejected");
        let accepted = SubscriptionId::new("accepted");
        let make_batch = |batch_id, subscription_id| PendingBatch {
            batch_id,
            purpose: PendingBatchPurpose::Core,
            items: PendingItems::default(),
            outstanding_subs: HashSet::from([subscription_id]),
            sync_method: SyncMethod::ReqEose,
            pagination_state: HashMap::new(),
            requested_event_ids: None,
            received_event_ids: None,
            initial_hydration_counts: None,
            retry_count: 0,
            failed: false,
        };
        let mut pending = HashMap::from([(
            relay_url.to_string(),
            vec![
                make_batch(1, rejected.clone()),
                make_batch(2, accepted.clone()),
            ],
        )]);

        let removed = take_batch_containing_subscription(&mut pending, relay_url, &rejected)
            .expect("rejected subscription must release its batch for cooldown retry");
        assert_eq!(removed.batch_id, 1);
        assert_eq!(pending[relay_url].len(), 1);
        assert!(pending[relay_url][0].outstanding_subs.contains(&accepted));

        take_batch_containing_subscription(&mut pending, relay_url, &accepted)
            .expect("last batch must also be removable");
        assert!(!pending.contains_key(relay_url));
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
    fn discovery_connection_ownership_survives_retry_deadlines_and_in_flight_removal() {
        let author = Keys::generate().public_key();
        let profile = "wss://profile.example".to_string();
        let mailbox = "wss://mailbox.example".to_string();
        let retired = "wss://retired.example".to_string();
        let mut discovery = Nip65DiscoveryState::default();
        discovery
            .author_sources
            .insert(author, HashSet::from([profile.clone()]));
        discovery
            .mailbox_repositories
            .insert(mailbox.clone(), HashSet::from(["repo".into()]));
        discovery
            .mailbox_probe_next_at
            .insert(mailbox.clone(), Instant::now() + Duration::from_secs(3600));
        discovery.in_flight.insert((retired.clone(), author));

        let disconnected = RelayState::default();
        for relay in [&profile, &mailbox, &retired] {
            assert!(!disconnected
                .is_disconnect_candidate(false, discovery.connection_targets().contains(relay)));
        }
        discovery.in_flight.clear();
        assert!(!discovery.connection_targets().contains(&retired));
        discovery.author_sources.clear();
        discovery.install_mailbox_overlay(HashMap::new(), HashMap::new(), Instant::now());
        assert!(discovery.connection_targets().is_empty());
        assert!(disconnected.is_disconnect_candidate(false, false));
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

    #[test]
    fn purgatory_snapshot_replaces_state_only_relays_and_prunes_full_expiry() {
        let active = "30617:owner:active".to_string();
        let expired = "30617:owner:expired".to_string();
        let promoted = "30617:owner:promoted".to_string();
        let old = "wss://old.example".to_string();
        let new = "wss://new.example".to_string();
        let expired_relay = "wss://expired.example".to_string();
        let promoted_relay = "wss://promoted.example".to_string();
        let mut index = HashMap::from([
            (
                active.clone(),
                RepoSyncNeeds {
                    relays: HashSet::from([old.clone()]),
                    sync_level: SyncLevel::StateOnly,
                    ..Default::default()
                },
            ),
            (
                expired.clone(),
                RepoSyncNeeds {
                    relays: HashSet::from([expired_relay.clone()]),
                    sync_level: SyncLevel::StateOnly,
                    ..Default::default()
                },
            ),
            (
                promoted.clone(),
                RepoSyncNeeds {
                    relays: HashSet::from([promoted_relay.clone()]),
                    sync_level: SyncLevel::Full,
                    ..Default::default()
                },
            ),
        ]);

        let dirty = reconcile_purgatory_relay_ownership(
            &mut index,
            &[(active.clone(), HashSet::from([new.clone()]))],
        );

        assert_eq!(index[&active].relays, HashSet::from([new.clone()]));
        assert!(!index.contains_key(&expired));
        assert_eq!(index[&promoted].relays, HashSet::from([promoted_relay]));
        assert_eq!(dirty, HashSet::from([old, new, expired_relay]));
    }

    #[test]
    fn soft_expired_purgatory_entry_remains_while_present_in_snapshot() {
        let repo = "30617:owner:revivable".to_string();
        let relay = "wss://owner.example".to_string();
        let mut index = HashMap::from([(
            repo.clone(),
            RepoSyncNeeds {
                relays: HashSet::from([relay.clone()]),
                sync_level: SyncLevel::StateOnly,
                ..Default::default()
            },
        )]);

        let dirty = reconcile_purgatory_relay_ownership(
            &mut index,
            &[(repo.clone(), HashSet::from([relay]))],
        );

        assert!(index.contains_key(&repo));
        assert!(dirty.is_empty());
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
            purpose: PendingBatchPurpose::Core,
            items: PendingItems::default(),
            outstanding_subs: HashSet::new(),
            sync_method: SyncMethod::Negentropy,
            pagination_state: HashMap::new(),
            requested_event_ids: Some(HashSet::new()),
            received_event_ids: Some(HashSet::new()),
            initial_hydration_counts: None,
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
    fn hydration_attempt_registers_every_chunk_before_immediate_delivery() {
        let mut batch = PendingBatch {
            batch_id: 7,
            purpose: PendingBatchPurpose::Core,
            items: PendingItems::default(),
            outstanding_subs: HashSet::new(),
            sync_method: SyncMethod::Negentropy,
            pagination_state: HashMap::new(),
            requested_event_ids: None,
            received_event_ids: None,
            initial_hydration_counts: None,
            retry_count: 0,
            failed: false,
        };
        let subscription_ids: Vec<_> = (0..169)
            .map(|index| SubscriptionId::new(format!("hydration-{index}")))
            .collect();
        let event_ids = [
            EventId::from_byte_array([1; 32]),
            EventId::from_byte_array([2; 32]),
        ];

        register_negentropy_hydration_attempt(
            &mut batch,
            subscription_ids.iter().cloned(),
            event_ids,
            false,
        );

        assert_eq!(batch.outstanding_subs.len(), 169);
        assert_eq!(batch.requested_event_ids.as_ref().unwrap().len(), 2);
        assert_eq!(batch.received_event_ids, Some(HashSet::new()));
        for event_id in event_ids {
            if batch
                .requested_event_ids
                .as_ref()
                .unwrap()
                .contains(&event_id)
            {
                batch.received_event_ids.as_mut().unwrap().insert(event_id);
            }
        }
        assert_eq!(batch.received_event_ids.as_ref().unwrap().len(), 2);
        for subscription_id in &subscription_ids {
            assert!(
                batch.outstanding_subs.remove(subscription_id),
                "an immediate terminal signal must find its pre-registered chunk"
            );
        }
        assert!(batch.outstanding_subs.is_empty());
    }

    #[test]
    fn test_pending_batch_req_eose_fields() {
        // Test that REQ+EOSE batches don't use negentropy fields
        let batch = PendingBatch {
            batch_id: 1,
            purpose: PendingBatchPurpose::Core,
            items: PendingItems::default(),
            outstanding_subs: HashSet::new(),
            sync_method: SyncMethod::ReqEose,
            pagination_state: HashMap::new(),
            requested_event_ids: None,
            received_event_ids: None,
            initial_hydration_counts: None,
            retry_count: 0,
            failed: false,
        };

        assert!(batch.requested_event_ids.is_none());
        assert!(batch.received_event_ids.is_none());
        assert_eq!(batch.sync_method, SyncMethod::ReqEose);
        assert!(!batch.failed);
    }
}
