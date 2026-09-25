//! Relay Connection Management for Proactive Sync
//!
//! This module provides relay connection management for external relay connections.
//! Each RelayConnection manages a single connection to an external relay and handles
//! subscriptions using the three-layer sync strategy.
//!
//! ## NIP-77 Negentropy Support
//!
//! RelayConnection supports NIP-77 negentropy for efficient set reconciliation:
//! - `supports_negentropy()` - Check if remote relay supports NIP-77
//! - `negentropy_sync_filter()` - Perform negentropy sync for a filter
//!
//! When NIP-77 is supported, historical sync uses negentropy instead of REQ+EOSE,
//! significantly reducing bandwidth for relays with overlapping event sets.
//!
//! See `docs/explanation/grasp-02-proactive-sync.md` for full design details.

use futures_util::StreamExt;
use nostr_sdk::prelude::*;
use std::future::Future;
use std::time::Duration;
use tokio::sync::mpsc;

use super::health::{RelayHealthTracker, RATE_LIMIT_COOLDOWN_SECS};
use super::{
    is_filter_count_refusal, is_rate_limit_message, policy_refusal, subscription_state_byte_limit,
    PolicyRefusal,
};
use crate::nostr::SharedDatabase;
use crate::outbound::{OutboundTargetKind, OutboundTargetPolicy, RelayTargetSource};

/// Maximum wall-clock time for one dry-run NIP-77 reconciliation.
///
/// The SDK has initial-response and idle timers, but a relay can keep an
/// exchange alive indefinitely by continuing to send reconciliation messages.
const NEGENTROPY_DIFF_TIMEOUT: Duration = Duration::from_secs(15);

/// NIP-11 is advisory and must not hold up a connected relay indefinitely.
const NIP11_FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Conservative subscription budget when NIP-11 omits `max_subscriptions`.
const FALLBACK_SUBSCRIPTION_BUDGET: usize = 20;

/// Control-plane safety slots never offered to live or historic consumers.
const SUBSCRIPTION_RESERVED_MARGIN: usize = 2;

/// Initial spacing after a relay reports that its per-connection query-rate
/// allowance is exhausted.
///
/// NIP-11 cannot advertise query-rate windows. One start every 600 ms is 100
/// starts/minute, leaving operational slack below the 120/minute limit used
/// by older rust-nostr relays. This is deliberately reactive:
/// proactively pacing non-urgent history needs request-class priority so live
/// coverage is not delayed, and belongs in a separate scheduler change.
const QUERY_PACING_INITIAL_INTERVAL: Duration = Duration::from_millis(600);

/// Bound adaptive slowdown so a restrictive relay still makes progress.
const QUERY_PACING_MAX_INTERVAL: Duration = Duration::from_secs(10);

/// Multiple refusals from one already-sent burst describe one episode. A new
/// refusal after a full rate-limit window means the learned pace was too fast.
const QUERY_RATE_LIMIT_EPISODE_GAP: Duration = Duration::from_secs(60);

/// Minimum spacing between non-urgent historic and dependency query starts.
///
/// Historic completeness matters, but does not require burst throughput. One
/// background start per second is deliberately gentle to public relays and
/// leaves query capacity for live coverage. This only controls
/// application-visible starts; rust-nostr owns NIP-77 `NEG-MSG` continuations,
/// so the reactive refusal handling remains necessary.
const BACKGROUND_QUERY_INTERVAL: Duration = Duration::from_secs(1);

fn effective_subscription_budget(advertised: Option<usize>) -> usize {
    advertised.unwrap_or(FALLBACK_SUBSCRIPTION_BUDGET)
}

fn usable_subscription_slots(advertised: Option<usize>) -> usize {
    effective_subscription_budget(advertised).saturating_sub(SUBSCRIPTION_RESERVED_MARGIN)
}

fn is_query_rate_limit_message(message: &str) -> bool {
    if is_filter_count_refusal(message) {
        return false;
    }
    message.to_ascii_lowercase().contains("too many queries")
}

fn is_auth_required_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("auth-required") || message.contains("authentication required")
}

#[derive(Debug, Default)]
struct QueryPacingState {
    interval: Option<Duration>,
    last_start: Option<tokio::time::Instant>,
    last_limit_signal: Option<tokio::time::Instant>,
    paused_until: Option<tokio::time::Instant>,
}

/// Serialises query starts only after this connection has demonstrated a
/// per-minute query limit. Simultaneous subscription capacity remains owned by
/// the separate subscription ledger.
#[derive(Debug, Default)]
struct QueryStartPacer {
    gate: tokio::sync::Mutex<()>,
    state: std::sync::Mutex<QueryPacingState>,
}

/// Serialises background query starts from the beginning of each session.
/// Live subscriptions bypass this gate and therefore retain priority.
#[derive(Debug, Default)]
struct BackgroundQueryPacer {
    gate: tokio::sync::Mutex<()>,
    last_start: std::sync::Mutex<Option<tokio::time::Instant>>,
}

impl BackgroundQueryPacer {
    async fn wait_for_start(&self) {
        let _gate = self.gate.lock().await;
        let deadline = self
            .last_start
            .lock()
            .expect("background query pacing state poisoned")
            .map(|last| last + BACKGROUND_QUERY_INTERVAL);
        if let Some(deadline) = deadline {
            tokio::time::sleep_until(deadline).await;
        }
        *self
            .last_start
            .lock()
            .expect("background query pacing state poisoned") = Some(tokio::time::Instant::now());
    }

    fn reset(&self) {
        *self
            .last_start
            .lock()
            .expect("background query pacing state poisoned") = None;
    }
}

impl QueryStartPacer {
    fn record_rate_limit(&self) -> (Duration, bool) {
        let now = tokio::time::Instant::now();
        let mut state = self.state.lock().expect("query pacing state poisoned");
        let new_episode = state
            .last_limit_signal
            .is_none_or(|last| now.duration_since(last) >= QUERY_RATE_LIMIT_EPISODE_GAP);
        if new_episode {
            state.interval = Some(match state.interval {
                None => QUERY_PACING_INITIAL_INTERVAL,
                Some(current) => current.saturating_mul(2).min(QUERY_PACING_MAX_INTERVAL),
            });
            state.paused_until = Some(now + Duration::from_secs(RATE_LIMIT_COOLDOWN_SECS));
        }
        state.last_limit_signal = Some(now);
        (
            state.interval.unwrap_or(QUERY_PACING_INITIAL_INTERVAL),
            new_episode,
        )
    }

    async fn wait_for_start(&self) -> Result<(), Duration> {
        let _gate = self.gate.lock().await;
        let now = tokio::time::Instant::now();
        if let Some(paused_until) = self
            .state
            .lock()
            .expect("query pacing state poisoned")
            .paused_until
        {
            if now < paused_until {
                return Err(paused_until.duration_since(now));
            }
        }
        let deadline = {
            let state = self.state.lock().expect("query pacing state poisoned");
            state
                .interval
                .zip(state.last_start)
                .map(|(interval, last)| last + interval)
        };
        if let Some(deadline) = deadline {
            tokio::time::sleep_until(deadline).await;
        }
        let mut state = self.state.lock().expect("query pacing state poisoned");
        if state.interval.is_some() {
            state.last_start = Some(tokio::time::Instant::now());
        }
        Ok(())
    }

    fn reset(&self) {
        *self.state.lock().expect("query pacing state poisoned") = QueryPacingState::default();
    }

    #[cfg(test)]
    fn interval(&self) -> Option<Duration> {
        self.state
            .lock()
            .expect("query pacing state poisoned")
            .interval
    }
}

#[cfg(test)]
fn historic_slot_allowance(advertised: Option<usize>, live_slots: usize) -> usize {
    usable_subscription_slots(advertised)
        .saturating_sub(live_slots)
        .min(MAX_CONCURRENT_NEG_DIFFS)
}

/// Cooldown schedule for transient negentropy failures.
///
/// Indexed by the number of consecutive failed attempts (capped at the last
/// entry). Transient failures pause NIP-77 for this relay temporarily instead
/// of disabling it for the connection lifetime: a client-side channel overflow
/// or a relay rate limit says nothing about whether the relay speaks NIP-77.
const NEGENTROPY_TRANSIENT_BACKOFF: [Duration; 4] = [
    Duration::from_secs(60),
    Duration::from_secs(300),
    Duration::from_secs(1800),
    Duration::from_secs(7200),
];

/// Maximum concurrent negentropy diff rounds per relay connection.
///
/// Relays bound concurrent subscriptions per connection, and on
/// strfry-family relays negentropy views count against that same budget
/// (`maxSubsPerConnection`; nos.lol and relay.primal.net advertise 20,
/// shared with live subscriptions). Historic sync opens one diff per
/// filter, so an unbounded batch (146 filters observed in production)
/// bursts far past the tightest common budget and draws
/// "too many concurrent NEG requests" rejections. Four concurrent rounds
/// leaves the shared budget mostly available for live subscriptions; see
/// docs/explanation/sync-scaling-constraints.md.
const MAX_CONCURRENT_NEG_DIFFS: usize = 4;

/// Maximum concurrent transient (auto-close) REQ subscriptions per relay
/// connection.
///
/// Historic REQ+EOSE sync, negentropy ID fetches, missing-event retries,
/// fallback subscriptions and pagination pages each open an auto-close REQ
/// that stays open until EOSE. Relays bound concurrent subscriptions per
/// connection (`maxSubsPerConnection` on strfry-family relays; nos.lol
/// advertises 20, shared between live subscriptions, negentropy views and
/// REQs), so an unbounded startup batch bursts past the tightest common
/// budget — observed in production as "ERROR: too many concurrent REQs"
/// NOTICEs from nos.lol. Five permits alongside the four negentropy
/// permits and a two-slot margin leaves at least nine slots of that
/// budget for live subscriptions; see
/// docs/explanation/sync-scaling-constraints.md.
const MAX_CONCURRENT_TRANSIENT_REQS: usize = 5;

/// Events and lifecycle notifications waiting for the per-relay processor.
///
/// Transient permit release has a separate terminal-control listener, so this
/// remains a bounded data-processing queue rather than a lifecycle boundary.
pub(crate) const RELAY_EVENT_BUFFER_CAPACITY: usize = 1000;

/// Upper bound on how long a transient-REQ permit may be held.
///
/// Permits are normally released when the subscription's EOSE (or CLOSED)
/// arrives. A relay that never answers would otherwise pin its permits
/// forever and starve every later transient subscription on the
/// connection, so a watchdog sends CLOSE after this deadline (twice the
/// negentropy round timeout, generous for large REQ pages). The slot is
/// returned only after CLOSE is successfully enqueued; a send failure retains
/// it until ordinary connection teardown.
// Production startup pages on relay.ngit.dev legitimately exceeded 30 seconds;
// allow two minutes before treating a missing EOSE/CLOSED as a stuck session.
const TRANSIENT_REQ_PERMIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Permits held by in-flight transient REQ subscriptions, keyed by
/// subscription id and shared across connection clones.
type TransientReqPermitMap = std::sync::Arc<
    std::sync::Mutex<std::collections::HashMap<SubscriptionId, HeldTransientPermits>>,
>;

struct HeldTransientPermits {
    _class_cap: tokio::sync::OwnedSemaphorePermit,
    _ledger_slot: tokio::sync::OwnedSemaphorePermit,
    _byte_limit_gate: Option<tokio::sync::OwnedSemaphorePermit>,
    generation: u64,
    request_class: TransientRequestClass,
    opened_at: std::time::Instant,
    last_event_at: Option<std::time::Instant>,
    delivered_events: usize,
}

/// Bounded origin of an auto-close REQ, retained for watchdog diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransientRequestClass {
    HistoricPage,
    PaginationPage,
    PaginationVerification,
    NegentropyHydration,
    NegentropyRetry,
    NegentropyFallback,
}

impl TransientRequestClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HistoricPage => "historic_page",
            Self::PaginationPage => "pagination_page",
            Self::PaginationVerification => "pagination_verification",
            Self::NegentropyHydration => "negentropy_hydration",
            Self::NegentropyRetry => "negentropy_retry",
            Self::NegentropyFallback => "negentropy_fallback",
        }
    }
}

#[cfg(test)]
const TRANSIENT_REQUEST_CLASSES: [TransientRequestClass; 6] = [
    TransientRequestClass::HistoricPage,
    TransientRequestClass::PaginationPage,
    TransientRequestClass::PaginationVerification,
    TransientRequestClass::NegentropyHydration,
    TransientRequestClass::NegentropyRetry,
    TransientRequestClass::NegentropyFallback,
];

#[derive(Clone)]
struct SubscriptionLedgerSession {
    generation: u64,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
}

struct SessionPermit {
    generation: u64,
    permit: tokio::sync::OwnedSemaphorePermit,
}

struct HeldLiveSubscription {
    _ledger_slot: tokio::sync::OwnedSemaphorePermit,
    generation: u64,
    filters: Vec<Filter>,
}

#[derive(Debug)]
struct LiveTailReplacement {
    retired: Vec<(SubscriptionId, Vec<Filter>)>,
    replacement_groups: Vec<Vec<Filter>>,
}

fn plan_live_tail_extension(
    current: Vec<(SubscriptionId, Vec<Filter>)>,
    protected: &std::collections::HashSet<SubscriptionId>,
    new_groups: Vec<Vec<Filter>>,
    max_filters: usize,
) -> LiveTailReplacement {
    // Historic retries can request the same core coverage again. Only
    // core subscriptions count: auxiliary coverage can be retired separately.
    let mut installed: std::collections::HashSet<String> = current
        .iter()
        .filter(|(id, _)| !protected.contains(id))
        .flat_map(|(_, filters)| filters.iter().map(Filter::as_json))
        .collect();
    let mut new_filters: Vec<Filter> = new_groups
        .into_iter()
        .flatten()
        .filter(|filter| installed.insert(filter.as_json()))
        .collect();
    if new_filters.is_empty() {
        return LiveTailReplacement {
            retired: Vec::new(),
            replacement_groups: Vec::new(),
        };
    }
    new_filters.sort_unstable_by_key(|filter| filter.as_json());

    let max_filters = max_filters.max(1);
    let mut candidates: Vec<_> = current
        .into_iter()
        .filter(|(subscription_id, filters)| {
            !protected.contains(subscription_id) && filters.len() < max_filters
        })
        .collect();
    candidates.sort_unstable_by_key(|(subscription_id, filters)| {
        (
            filters
                .iter()
                .map(|filter| filter.as_json())
                .collect::<Vec<_>>(),
            subscription_id.to_string(),
        )
    });

    let mut all_filters = new_filters.clone();
    all_filters.extend(
        candidates
            .iter()
            .flat_map(|(_, filters)| filters.iter().cloned()),
    );
    all_filters.sort_unstable_by_key(|filter| filter.as_json());
    let all_groups = super::group_filters_for_req_with_max(&all_filters, max_filters);

    // Repacking the complete tail maximises released slots whenever it can
    // actually release one. If byte limits make the complete tail just as
    // large, retire only groups which reduce the incremental slot cost.
    if all_groups.len() < candidates.len() {
        return LiveTailReplacement {
            retired: candidates,
            replacement_groups: all_groups,
        };
    }

    let mut retired = Vec::new();
    let mut replacement_filters = new_filters;
    let mut replacement_groups =
        super::group_filters_for_req_with_max(&replacement_filters, max_filters);
    let mut net_new_slots = replacement_groups.len() as isize;
    while net_new_slots > 0 {
        let mut best = None;
        for (index, (_, filters)) in candidates.iter().enumerate() {
            let mut trial_filters = replacement_filters.clone();
            trial_filters.extend(filters.iter().cloned());
            trial_filters.sort_unstable_by_key(|filter| filter.as_json());
            let trial_groups = super::group_filters_for_req_with_max(&trial_filters, max_filters);
            let trial_net_new_slots = trial_groups.len() as isize - (retired.len() + 1) as isize;
            if trial_net_new_slots < net_new_slots
                && best
                    .as_ref()
                    .is_none_or(|(_, _, _, best_net)| trial_net_new_slots < *best_net)
            {
                best = Some((index, trial_filters, trial_groups, trial_net_new_slots));
            }
        }
        let Some((index, filters, groups, net_slots)) = best else {
            break;
        };
        retired.push(candidates.remove(index));
        replacement_filters = filters;
        replacement_groups = groups;
        net_new_slots = net_slots;
    }

    LiveTailReplacement {
        retired,
        replacement_groups,
    }
}

#[derive(Clone, Copy)]
struct ReleasedLiveSubscription {
    generation: u64,
    filter_count: usize,
}

type LiveReqPermitMap = std::sync::Arc<
    std::sync::Mutex<std::collections::HashMap<SubscriptionId, HeldLiveSubscription>>,
>;

#[derive(Debug, Clone, Copy, Default)]
pub struct RelayLimitHints {
    pub default_limit: Option<usize>,
    pub max_subscriptions: Option<usize>,
    /// Relay operator identity advertised by NIP-11. Private GRASP services
    /// grant this identity access only when the relay is referenced by an
    /// accepted repository announcement.
    pub owner: Option<PublicKey>,
    /// Whether the document's `supported_grasps` array (a GRASP extension
    /// field, parsed from the raw JSON because the SDK's NIP-11 type does not
    /// carry it) advertises the "GRASP-08" private-service extension.
    pub grasp08: bool,
}

fn parse_relay_limit_hints(body: &str) -> RelayLimitHints {
    let Some(document) = nostr::nips::nip11::RelayInformationDocument::from_json(body).ok() else {
        return RelayLimitHints::default();
    };
    let grasp08 = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value.get("supported_grasps")?.as_array().map(|grasps| {
                grasps
                    .iter()
                    .any(|grasp| grasp.as_str() == Some("GRASP-08"))
            })
        })
        .unwrap_or(false);
    let limitation = document.limitation.unwrap_or_default();
    RelayLimitHints {
        default_limit: limitation
            .default_limit
            .and_then(|limit| usize::try_from(limit).ok())
            .filter(|limit| *limit > 0),
        max_subscriptions: limitation
            .max_subscriptions
            .and_then(|limit| usize::try_from(limit).ok())
            .filter(|limit| *limit > 0),
        owner: document.pubkey,
        grasp08,
    }
}

/// How a failed negentropy diff should affect future NIP-77 attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NegentropyFailure {
    /// The relay explicitly reported that it cannot speak NIP-77.
    Unsupported,
    /// Timeouts, rate limits, client-side channel overflow and other errors
    /// that carry no information about NIP-77 support.
    Transient,
}

/// Classify a negentropy diff error string.
///
/// Only explicit "not supported" signals from the relay justify permanently
/// disabling NIP-77. Everything else is treated as transient; the relay stays
/// eligible for negentropy after a bounded cooldown.
fn classify_negentropy_failure(error: &str) -> NegentropyFailure {
    let lower = error.to_lowercase();
    if lower.contains("not support") || lower.contains("unsupported") {
        NegentropyFailure::Unsupported
    } else {
        NegentropyFailure::Transient
    }
}

/// Interval between relay-status checks while a connection attempt is in flight.
///
/// nostr-sdk may return from `try_connect_relay` while another task still has
/// the relay in `Connecting`; subscriptions must wait for actual readiness.
const CONNECTION_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(25);

async fn wait_for_connected_status<F>(mut relay_status: F) -> Result<(), RelayStatus>
where
    F: FnMut() -> RelayStatus,
{
    loop {
        let status = relay_status();
        match status {
            RelayStatus::Connected => return Ok(()),
            RelayStatus::Disconnected
            | RelayStatus::Terminated
            | RelayStatus::Banned
            | RelayStatus::Sleeping
            | RelayStatus::Shutdown => return Err(status),
            RelayStatus::Initialized | RelayStatus::Pending | RelayStatus::Connecting => {
                tokio::time::sleep(CONNECTION_STATUS_POLL_INTERVAL).await;
            }
        }
    }
}

/// Events from a relay connection
#[derive(Debug)]
pub enum RelayEvent {
    /// A new event was received (event, subscription_id, data-lane arrival).
    Event(Box<Event>, SubscriptionId, std::time::Instant),
    /// End of stored events for a subscription
    EndOfStoredEvents(SubscriptionId, std::time::Instant),
    /// NOTICE message from relay
    Notice(String),
    /// Connection was closed
    Closed {
        subscription_id: SubscriptionId,
        reason: String,
        live_generation: Option<u64>,
        live_filter_count: Option<usize>,
    },
    /// Shutdown notification
    Shutdown,
}

/// Result of a negentropy sync operation
#[derive(Debug)]
pub struct NegentropySyncResult {
    /// Event IDs that exist on remote but not locally (discovered but not fetched)
    pub remote_only: Vec<EventId>,
    /// Event IDs that exist locally but not on remote (could push)
    pub local_only: Vec<EventId>,
    /// Event IDs that were fetched during sync
    pub received: Vec<EventId>,
}

/// Manages connection to a single external relay
///
/// RelayConnection wraps a nostr-sdk Client to manage a WebSocket connection
/// to an external relay. It handles:
/// - Connection establishment
/// - Layer 1 subscription (announcements)
/// - Additional filter subscriptions (Layers 2 & 3)
/// - Event notification loop
/// - NIP-77 negentropy synchronization
///
/// # Why Client instead of Relay directly?
///
/// While it would be cleaner to hold a `Relay` directly (since we only manage
/// one relay per connection), the nostr-sdk API makes `Relay::new()` private
/// (`pub(crate)`). Relays can only be created through `Client::add_relay()` or
/// `RelayPool::add_relay()`. This is an intentional design in nostr-sdk to
/// ensure proper lifecycle management.
///
/// The Client adds minimal overhead since we configure it with a single relay,
/// and we retrieve the `Relay` reference for notification handling.
#[derive(Clone)]
pub struct RelayConnection {
    /// The relay URL this connection is for
    url: String,
    /// Whether the URL came from operator configuration or an untrusted event
    source: RelayTargetSource,
    /// Outbound target policy applied before every event-directed dial
    policy: OutboundTargetPolicy,
    /// Shared with the scheduler so queued work observes the same cooldown.
    health_tracker: std::sync::Arc<RelayHealthTracker>,
    /// The underlying nostr-sdk client
    client: Client,
    /// Whether a NIP-42 authenticator was attached to the client. Without
    /// one the SDK never answers AUTH challenges and never retains
    /// auth-refused subscriptions for a post-authentication retry.
    has_authenticator: bool,
    /// Local database for negentropy comparison (used for NIP-77 sync)
    database: Option<SharedDatabase>,
    /// Whether we've logged NIP-77 not supported for this relay (log once)
    nip77_unsupported_logged: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Whether this relay supports NIP-77 negentropy (0 = unknown, 2 = confirmed not supported)
    nip77_supported: std::sync::Arc<std::sync::atomic::AtomicU8>,
    /// Whether an in-session NIP-77 round exhausted the relay's query-rate
    /// budget. The SDK owns NEG-MSG exchange, so later work uses paced REQs.
    nip77_query_rate_limited: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Consecutive transient negentropy failures (drives the cooldown schedule)
    nip77_transient_failures: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Deadline before which negentropy is not attempted (transient-failure cooldown)
    nip77_cooldown_until: std::sync::Arc<std::sync::Mutex<Option<tokio::time::Instant>>>,
    /// Bounds concurrent negentropy diff rounds on this connection
    /// (shared across clones; see [`MAX_CONCURRENT_NEG_DIFFS`])
    neg_diff_permits: std::sync::Arc<tokio::sync::Semaphore>,
    /// One ledger shared by every relay-side subscription consumer. The
    /// semaphore contains B minus the reserved margin for this session.
    subscription_budget: std::sync::Arc<std::sync::Mutex<SubscriptionLedgerSession>>,
    /// Usable capacity configured for the current session.
    subscription_usable_slots: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Bounds concurrent transient (auto-close) REQ subscriptions on this
    /// connection (shared across clones; see
    /// [`MAX_CONCURRENT_TRANSIENT_REQS`])
    transient_req_permits: std::sync::Arc<tokio::sync::Semaphore>,
    /// Permits held by open transient subscriptions, keyed by subscription
    /// id; released on EOSE/CLOSED, connection teardown, or the watchdog
    transient_req_permits_held: TransientReqPermitMap,
    timeout_sender: std::sync::Arc<
        std::sync::Mutex<Option<mpsc::Sender<super::SubscriptionClosedNotification>>>,
    >,
    /// Ledger slots held for persistent subscriptions until CLOSE/teardown.
    live_req_permits_held: LiveReqPermitMap,
    /// Cumulative retained REQ bytes learned from a relay's CLOSED response.
    /// Zero means the relay has not exposed a limit. The value survives
    /// reconnects so a durable policy is not probed on every new session.
    remote_subscription_byte_limit: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Once a cumulative byte cap is learned, serialize transient REQs so the
    /// reserved byte margin and actual relay-side occupancy cannot diverge.
    byte_limited_transient_gate: std::sync::Arc<tokio::sync::Semaphore>,
    /// Learned per-session spacing for query starts after a query-rate refusal.
    query_start_pacer: std::sync::Arc<QueryStartPacer>,
    /// Proactive spacing for non-urgent historic and dependency query starts.
    background_query_pacer: std::sync::Arc<BackgroundQueryPacer>,
    /// Per-session ceiling learned from explicit filter-count refusals.
    max_filters_per_req: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl RelayConnection {
    pub(super) fn with_health_tracker(
        mut self,
        health_tracker: std::sync::Arc<RelayHealthTracker>,
    ) -> Self {
        self.health_tracker = health_tracker;
        self
    }

    fn ensure_query_admitted(&self) -> Result<(), String> {
        if self.health_tracker.is_rate_limited(&self.url) {
            return Err(format!(
                "Query start deferred for {}: rate-limit cooldown active",
                self.url
            ));
        }
        if self.health_tracker.is_subscription_paused(&self.url) {
            return Err(format!(
                "Query start deferred for {}: subscription cooldown active",
                self.url
            ));
        }
        Ok(())
    }

    fn record_subscription_rate_limit(&self, message: &str) {
        if is_rate_limit_message(message)
            && !is_filter_count_refusal(message)
            && subscription_state_byte_limit(message).is_none()
        {
            self.health_tracker.record_rate_limit(&self.url);
        }
        if is_query_rate_limit_message(message) {
            self.record_query_rate_limit();
        }
    }

    async fn await_query_start(&self) -> Result<(), String> {
        self.ensure_query_admitted()?;
        self.query_start_pacer
            .wait_for_start()
            .await
            .map_err(|remaining| {
                format!(
                    "Query start deferred for {}: rate-limit cooldown {:.3}s remaining",
                    self.url,
                    remaining.as_secs_f64()
                )
            })
    }

    async fn await_background_query_start(&self) {
        self.background_query_pacer.wait_for_start().await;
    }

    fn record_query_rate_limit(&self) {
        let (interval, new_episode) = self.query_start_pacer.record_rate_limit();
        if new_episode {
            tracing::info!(
                relay = %self.url,
                query_start_interval_ms = interval.as_millis(),
                "Activated adaptive query-start pacing"
            );
        }
        if self.mark_negentropy_query_rate_limited() {
            tracing::info!(
                relay = %self.url,
                "Falling back to paced REQs for the query-limited connection session"
            );
        }
    }

    fn record_subscription_byte_limit(&self, message: &str) -> Option<usize> {
        let limit = subscription_state_byte_limit(message)?;
        self.remote_subscription_byte_limit
            .store(limit, std::sync::atomic::Ordering::Relaxed);
        Some(limit)
    }

    pub fn remote_subscription_byte_limit(&self) -> Option<usize> {
        match self
            .remote_subscription_byte_limit
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            0 => None,
            limit => Some(limit),
        }
    }

    /// Normalize a relay URL to include a scheme (wss:// or ws://)
    ///
    /// If the URL already has a scheme, it's returned as-is.
    /// If no scheme is provided, wss:// is assumed (secure by default).
    ///
    /// # Arguments
    /// * `url` - The relay URL (with or without scheme)
    ///
    /// # Returns
    /// The normalized URL with scheme
    ///
    /// # Examples
    /// - `"relay.example.com"` -> `"wss://relay.example.com"`
    /// - `"wss://relay.example.com"` -> `"wss://relay.example.com"`
    /// - `"ws://relay.example.com"` -> `"ws://relay.example.com"`
    fn normalize_url(url: &str) -> String {
        if url.starts_with("wss://") || url.starts_with("ws://") {
            url.to_string()
        } else {
            format!("wss://{}", url)
        }
    }

    /// Create a new relay connection (not yet connected)
    ///
    /// # Arguments
    /// * `url` - The relay URL to connect to (with or without scheme, e.g., "relay.example.com" or "wss://relay.example.com")
    /// * `keys` - Keys for answering NIP-42 challenges (typically the relay
    ///   operator's keys); `None` disables outbound authentication entirely
    /// * `source` - Whether the URL is operator-configured or event-directed
    /// * `policy` - Outbound target policy enforced before event-directed dials
    pub fn new(
        url: String,
        keys: Option<Keys>,
        source: RelayTargetSource,
        policy: OutboundTargetPolicy,
    ) -> Self {
        let normalized_url = Self::normalize_url(&url);
        let has_authenticator = keys.is_some();
        let mut builder = Client::builder();
        if let Some(keys) = keys {
            builder = builder.authenticator(SignerAuthenticator::new(keys));
        }
        let client = builder.build();
        Self {
            url: normalized_url,
            source,
            policy,
            client,
            health_tracker: std::sync::Arc::new(RelayHealthTracker::with_defaults()),
            has_authenticator,
            database: None,
            nip77_unsupported_logged: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            nip77_supported: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            nip77_query_rate_limited: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            nip77_transient_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            nip77_cooldown_until: std::sync::Arc::new(std::sync::Mutex::new(None)),
            neg_diff_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_NEG_DIFFS,
            )),
            subscription_budget: std::sync::Arc::new(std::sync::Mutex::new(
                SubscriptionLedgerSession {
                    generation: 0,
                    semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(
                        FALLBACK_SUBSCRIPTION_BUDGET - SUBSCRIPTION_RESERVED_MARGIN,
                    )),
                },
            )),
            subscription_usable_slots: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
                FALLBACK_SUBSCRIPTION_BUDGET - SUBSCRIPTION_RESERVED_MARGIN,
            )),
            transient_req_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_TRANSIENT_REQS,
            )),
            transient_req_permits_held: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            timeout_sender: Default::default(),
            live_req_permits_held: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            remote_subscription_byte_limit: std::sync::Arc::new(
                std::sync::atomic::AtomicUsize::new(0),
            ),
            byte_limited_transient_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            query_start_pacer: std::sync::Arc::new(QueryStartPacer::default()),
            background_query_pacer: std::sync::Arc::new(BackgroundQueryPacer::default()),
            max_filters_per_req: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
                super::MAX_FILTERS_PER_REQ,
            )),
        }
    }

    /// Create a new relay connection with database for negentropy sync
    ///
    /// # Arguments
    /// * `url` - The relay URL to connect to (with or without scheme, e.g., "relay.example.com" or "wss://relay.example.com")
    /// * `database` - Shared database for local event comparison during negentropy sync
    /// * `keys` - Keys for answering NIP-42 challenges (typically the relay
    ///   operator's keys); `None` disables outbound authentication entirely
    /// * `source` - Whether the URL is operator-configured or event-directed
    /// * `policy` - Outbound target policy enforced before event-directed dials
    pub fn new_with_database(
        url: String,
        database: SharedDatabase,
        keys: Option<Keys>,
        source: RelayTargetSource,
        policy: OutboundTargetPolicy,
    ) -> Self {
        let normalized_url = Self::normalize_url(&url);
        let has_authenticator = keys.is_some();
        let mut builder = Client::builder();
        if let Some(keys) = keys {
            builder = builder.authenticator(SignerAuthenticator::new(keys));
        }
        let client = builder.build();
        Self {
            url: normalized_url,
            source,
            policy,
            client,
            health_tracker: std::sync::Arc::new(RelayHealthTracker::with_defaults()),
            has_authenticator,
            database: Some(database),
            nip77_unsupported_logged: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            nip77_supported: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            nip77_query_rate_limited: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            nip77_transient_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            nip77_cooldown_until: std::sync::Arc::new(std::sync::Mutex::new(None)),
            neg_diff_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_NEG_DIFFS,
            )),
            subscription_budget: std::sync::Arc::new(std::sync::Mutex::new(
                SubscriptionLedgerSession {
                    generation: 0,
                    semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(
                        FALLBACK_SUBSCRIPTION_BUDGET - SUBSCRIPTION_RESERVED_MARGIN,
                    )),
                },
            )),
            subscription_usable_slots: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
                FALLBACK_SUBSCRIPTION_BUDGET - SUBSCRIPTION_RESERVED_MARGIN,
            )),
            transient_req_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_TRANSIENT_REQS,
            )),
            transient_req_permits_held: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            timeout_sender: Default::default(),
            live_req_permits_held: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            remote_subscription_byte_limit: std::sync::Arc::new(
                std::sync::atomic::AtomicUsize::new(0),
            ),
            byte_limited_transient_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            query_start_pacer: std::sync::Arc::new(QueryStartPacer::default()),
            background_query_pacer: std::sync::Arc::new(BackgroundQueryPacer::default()),
            max_filters_per_req: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
                super::MAX_FILTERS_PER_REQ,
            )),
        }
    }

    /// Connect to the relay
    ///
    /// This method:
    /// 1. Adds the relay to the client
    /// 2. Establishes the WebSocket connection
    /// 3. Waits for the relay status to report `Connected`
    ///
    /// Subscriptions are handled separately via handle_connect_or_reconnect.
    ///
    /// # Arguments
    /// * `connection_timeout_secs` - Timeout for the connection attempt in seconds.
    ///   Should be no larger than base_backoff_secs to ensure the connection attempt
    ///   completes before the next retry would be scheduled.
    ///
    /// # Returns
    /// * `Ok(())` - Connection established successfully
    /// * `Err(String)` with error description on failure
    pub async fn connect(&self, connection_timeout_secs: u64) -> Result<(), String> {
        // Final authorization for event-directed targets, immediately before
        // the outbound dial so no registration path can bypass it. Runs on
        // every attempt (including reconnects) so DNS answers are re-vetted.
        if self.source == RelayTargetSource::EventDirected {
            if let Err(reason) = self
                .policy
                .authorize_resolved(OutboundTargetKind::EventRelay, &self.url)
                .await
            {
                tracing::warn!(
                    url = %self.url,
                    reason = %reason,
                    "Rejecting event-directed relay target"
                );
                return Err(format!(
                    "Outbound target policy rejected relay {}: {}",
                    self.url, reason
                ));
            }
        }

        let connection_timeout = Duration::from_secs(connection_timeout_secs);
        let connection_deadline = tokio::time::Instant::now() + connection_timeout;
        let timeout_error = || {
            format!(
                "Timed out connecting to relay {} after {} seconds",
                self.url, connection_timeout_secs
            )
        };

        let relay = tokio::time::timeout_at(connection_deadline, async {
            self.client
                .add_relay(&self.url)
                .reconnect(false)
                .await
                .map_err(|e| format!("Failed to add relay {}: {}", self.url, e))?;

            self.client
                .relay(&self.url)
                .await
                .map_err(|e| format!("Failed to get relay {}: {}", self.url, e))?
                .ok_or_else(|| format!("Relay {} was not added to the client", self.url))
        })
        .await
        .map_err(|_| timeout_error())??;

        // Use one deadline for both the SDK attempt and readiness verification.
        // Cancelling the SDK call with an outer timeout can leave its relay
        // status stranded at Connecting, so pass it the remaining budget.
        let remaining = connection_deadline.saturating_duration_since(tokio::time::Instant::now());
        self.client
            .try_connect_relay(&self.url, remaining)
            .await
            .map_err(|e| format!("Failed to connect to relay {}: {}", self.url, e))?;

        tokio::time::timeout_at(
            connection_deadline,
            wait_for_connected_status(|| relay.status()),
        )
        .await
        .map_err(|_| timeout_error())?
        .map_err(|status| {
            format!(
                "Relay {} entered terminal status {} before connecting",
                self.url, status
            )
        })?;

        tracing::info!(url = %self.url, "Connected to relay");
        Ok(())
    }

    /// Fetch the omitted-limit page-size hint advertised by this connection's relay.
    ///
    /// This is deliberately fetched for every WebSocket session rather than cached on the
    /// long-lived `RelayConnection`: operators can change their cap between reconnects.
    /// `default_limit` sizes pagination and `max_subscriptions` configures the session ledger.
    /// `max_limit` describes explicit `limit` values and is not applicable to the historic
    /// filters we intentionally send without one.
    pub async fn fetch_limit_hints(&self) -> RelayLimitHints {
        let Ok(mut document_url) = reqwest::Url::parse(&self.url) else {
            return RelayLimitHints::default();
        };
        let http_scheme = match document_url.scheme() {
            "ws" => "http",
            "wss" => "https",
            _ => return RelayLimitHints::default(),
        };
        if document_url.set_scheme(http_scheme).is_err() {
            return RelayLimitHints::default();
        }

        let fetch = async {
            let response = reqwest::Client::new()
                .get(document_url)
                .header(reqwest::header::ACCEPT, "application/nostr+json")
                .send()
                .await?;
            if !response.status().is_success() {
                tracing::debug!(
                    relay = %self.url,
                    status = %response.status(),
                    "NIP-11 fetch returned a non-success status"
                );
                return Ok(None);
            }
            response.text().await.map(Some)
        };
        let body = match tokio::time::timeout(NIP11_FETCH_TIMEOUT, fetch).await {
            Ok(Ok(Some(body))) => body,
            Ok(Ok(None)) => return RelayLimitHints::default(),
            Ok(Err(error)) => {
                tracing::debug!(relay = %self.url, error = %error, "NIP-11 fetch failed");
                return RelayLimitHints::default();
            }
            Err(_) => {
                tracing::debug!(relay = %self.url, "NIP-11 fetch timed out");
                return RelayLimitHints::default();
            }
        };
        parse_relay_limit_hints(&body)
    }

    /// Fetch NIP-11 hints before the WebSocket dial.
    ///
    /// The pre-dial NIP-11 fetch is itself an outbound TCP connection, so it
    /// must not bypass the SSRF gate: event-directed targets are authorized
    /// first, and on rejection default hints are returned without any HTTP
    /// request — the subsequent `connect()` then fails with the same policy
    /// rejection through its own pre-dial check.
    pub async fn preflight_limit_hints(&self) -> RelayLimitHints {
        if self.source == RelayTargetSource::EventDirected
            && self
                .policy
                .authorize_resolved(OutboundTargetKind::EventRelay, &self.url)
                .await
                .is_err()
        {
            return RelayLimitHints::default();
        }
        self.fetch_limit_hints().await
    }

    /// Whether the SDK still considers this relay's WebSocket established.
    ///
    /// Connection setup performs bounded HTTP work after the handshake. The
    /// peer can disappear during that window, so callers must revalidate the
    /// session before committing its successful lifecycle transition.
    pub async fn is_connected(&self) -> bool {
        self.client
            .relay(&self.url)
            .await
            .ok()
            .flatten()
            .is_some_and(|relay| relay.status() == RelayStatus::Connected)
    }

    /// Whether a control-plane query could acquire every local subscription
    /// constraint immediately on the current connected session.
    ///
    /// This is an admission sample, not a reservation: another actor may win
    /// the permits before the caller starts. It prevents maintenance ticks
    /// from spawning work that is already known to have to wait.
    pub async fn has_immediate_transient_capacity(&self) -> bool {
        if !self.is_connected().await || self.historic_capacity_consumed_by_live() {
            return false;
        }
        if self.transient_req_permits.available_permits() == 0 {
            return false;
        }
        if self.remote_subscription_byte_limit().is_some()
            && self.byte_limited_transient_gate.available_permits() == 0
        {
            return false;
        }
        self.subscription_budget
            .lock()
            .expect("subscription ledger poisoned")
            .semaphore
            .available_permits()
            > 0
    }

    /// Configure the one per-session ledger before any subscriptions open.
    pub fn reset_subscription_budget(&self, advertised: Option<usize>) {
        self.clear_subscription_permits();
        self.query_start_pacer.reset();
        self.background_query_pacer.reset();
        self.nip77_query_rate_limited
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.max_filters_per_req.store(
            super::MAX_FILTERS_PER_REQ,
            std::sync::atomic::Ordering::Relaxed,
        );
        let budget = effective_subscription_budget(advertised);
        let usable = usable_subscription_slots(advertised);
        self.subscription_usable_slots
            .store(usable, std::sync::atomic::Ordering::Relaxed);
        let mut session = self
            .subscription_budget
            .lock()
            .expect("subscription ledger poisoned");
        // Closing the retired semaphore wakes queued consumers with an error.
        // The generation check below also rejects a holder that acquired just
        // before reset but has not sent its SDK request yet.
        session.semaphore.close();
        *session = SubscriptionLedgerSession {
            generation: session.generation.wrapping_add(1),
            semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(usable)),
        };
        tracing::info!(
            relay = %self.url,
            subscription_budget = budget,
            usable_slots = usable,
            advertised = advertised.is_some(),
            "Configured per-connection subscription budget ledger"
        );
    }

    #[cfg(test)]
    fn subscription_budget(&self) -> std::sync::Arc<tokio::sync::Semaphore> {
        std::sync::Arc::clone(
            &self
                .subscription_budget
                .lock()
                .expect("subscription ledger poisoned")
                .semaphore,
        )
    }

    async fn acquire_subscription_slots(&self, count: u32) -> Result<SessionPermit, String> {
        let snapshot = self
            .subscription_budget
            .lock()
            .expect("subscription ledger poisoned")
            .clone();
        let permit = snapshot
            .semaphore
            .acquire_many_owned(count)
            .await
            .map_err(|_| format!("Subscription session retired for {}", self.url))?;
        let held = SessionPermit {
            generation: snapshot.generation,
            permit,
        };
        self.ensure_current_session(&held)?;
        Ok(held)
    }

    fn try_acquire_subscription_slot(&self) -> Result<SessionPermit, String> {
        let snapshot = self
            .subscription_budget
            .lock()
            .expect("subscription ledger poisoned")
            .clone();
        let permit = snapshot
            .semaphore
            .try_acquire_owned()
            .map_err(|_| format!("Live subscription budget exhausted for {}", self.url))?;
        let held = SessionPermit {
            generation: snapshot.generation,
            permit,
        };
        self.ensure_current_session(&held)?;
        Ok(held)
    }

    /// Acquire both transient constraints without waiting while holding only
    /// one of them. This prevents class-cap waiters from pinning ledger slots
    /// and ledger waiters from pinning the class cap.
    async fn acquire_transient_permits(
        &self,
        request_class: TransientRequestClass,
    ) -> Result<HeldTransientPermits, String> {
        let byte_limit_gate = if self.remote_subscription_byte_limit().is_some() {
            Some(
                self.byte_limited_transient_gate
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| format!("Transient byte-limit gate closed for {}", self.url))?,
            )
        } else {
            None
        };
        loop {
            let ledger_slot = self.acquire_subscription_slots(1).await?;
            if let Ok(class_cap) = self.transient_req_permits.clone().try_acquire_owned() {
                return Ok(HeldTransientPermits {
                    _class_cap: class_cap,
                    _byte_limit_gate: byte_limit_gate,
                    generation: ledger_slot.generation,
                    _ledger_slot: ledger_slot.permit,
                    request_class,
                    opened_at: std::time::Instant::now(),
                    last_event_at: None,
                    delivered_events: 0,
                });
            }
            drop(ledger_slot);

            let class_cap = self
                .transient_req_permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| format!("Transient permits closed for {}", self.url))?;
            if let Ok(ledger_slot) = self.try_acquire_subscription_slot() {
                return Ok(HeldTransientPermits {
                    _class_cap: class_cap,
                    _byte_limit_gate: byte_limit_gate,
                    generation: ledger_slot.generation,
                    _ledger_slot: ledger_slot.permit,
                    request_class,
                    opened_at: std::time::Instant::now(),
                    last_event_at: None,
                    delivered_events: 0,
                });
            }
            drop(class_cap);
            tokio::task::yield_now().await;
        }
    }

    fn ensure_current_session(&self, permit: &SessionPermit) -> Result<(), String> {
        self.ensure_current_generation(permit.generation)
    }

    fn ensure_current_generation(&self, permit_generation: u64) -> Result<(), String> {
        let generation = self
            .subscription_budget
            .lock()
            .expect("subscription ledger poisoned")
            .generation;
        if generation == permit_generation {
            Ok(())
        } else {
            Err(format!("Subscription session retired for {}", self.url))
        }
    }

    pub fn current_subscription_generation(&self) -> u64 {
        self.subscription_budget
            .lock()
            .expect("subscription ledger poisoned")
            .generation
    }

    pub fn max_filters_per_req(&self) -> usize {
        self.max_filters_per_req
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Geometrically lower the session ceiling after a relay explicitly
    /// rejects a multi-filter REQ. Rejection text often echoes the submitted
    /// count rather than disclosing the maximum, so it is never parsed as a
    /// capability claim.
    pub fn reduce_max_filters_per_req(&self, rejected_count: usize) -> Option<usize> {
        if rejected_count <= 1 {
            return None;
        }
        let candidate = (rejected_count / 2).max(1);
        let previous = self
            .max_filters_per_req
            .fetch_min(candidate, std::sync::atomic::Ordering::Relaxed);
        (candidate < previous).then_some(candidate)
    }

    pub fn live_filter_groups(&self) -> Vec<Vec<Filter>> {
        self.live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .values()
            .map(|held| held.filters.clone())
            .collect()
    }

    pub fn live_subscription_bytes(&self) -> usize {
        self.live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .values()
            .map(|held| {
                ClientMessage::req(SubscriptionId::generate(), held.filters.clone())
                    .as_json()
                    .len()
            })
            .sum()
    }

    async fn unsubscribe_live(&self) {
        let ids: Vec<_> = self
            .live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .keys()
            .cloned()
            .collect();
        for id in ids {
            if let Err(error) = self.client.unsubscribe(&id).await {
                tracing::debug!(relay = %self.url, sub_id = %id, %error, "Failed to close live subscription");
            }
            self.release_live_req_permit(&id);
        }
    }

    /// Replace persistent coverage transactionally. If the new complete set
    /// cannot be opened, restore the exact last-known-good filter grouping.
    pub async fn replace_live_filter_groups(
        &self,
        filter_groups: Vec<Vec<Filter>>,
    ) -> Result<Vec<SubscriptionId>, String> {
        self.replace_live_filter_groups_with(filter_groups, |filters, permit| {
            self.subscribe_filters_with_live_permit(filters, None, Some(permit), None)
        })
        .await
    }

    /// Extend core live coverage while preserving full groups and separately
    /// owned auxiliary subscriptions. Only core groups which can absorb at
    /// least one new filter are closed and repacked with the new filters.
    ///
    /// This is a best-effort transaction: any failure after CLOSE restores the
    /// exact retired filter groups before it returns. Admission remains subject
    /// to the connection ledger, so a caller can fall back to a full regroup
    /// when the minimally changed set cannot fit.
    pub async fn extend_live_filter_groups_minimally(
        &self,
        filter_groups: Vec<Vec<Filter>>,
        protected_subscription_ids: &[SubscriptionId],
    ) -> Result<Vec<SubscriptionId>, String> {
        self.extend_live_filter_groups_minimally_with(
            filter_groups,
            protected_subscription_ids,
            |subscription_id| async move {
                self.client
                    .unsubscribe(&subscription_id)
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("{subscription_id}: {error}"))
            },
            |filters, permit| {
                self.subscribe_filters_with_live_permit(filters, None, Some(permit), None)
            },
        )
        .await
    }

    async fn extend_live_filter_groups_minimally_with<C, CFut, F, Fut>(
        &self,
        filter_groups: Vec<Vec<Filter>>,
        protected_subscription_ids: &[SubscriptionId],
        mut close_subscription: C,
        mut subscribe_group: F,
    ) -> Result<Vec<SubscriptionId>, String>
    where
        C: FnMut(SubscriptionId) -> CFut,
        CFut: Future<Output = Result<(), String>>,
        F: FnMut(Vec<Filter>, SessionPermit) -> Fut,
        Fut: Future<Output = Result<SubscriptionId, String>>,
    {
        if filter_groups.is_empty() {
            return Ok(Vec::new());
        }
        let new_filter_count: usize = filter_groups.iter().map(Vec::len).sum();

        let current: Vec<_> = self
            .live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .iter()
            .map(|(id, held)| (id.clone(), held.filters.clone()))
            .collect();
        let protected: std::collections::HashSet<_> =
            protected_subscription_ids.iter().cloned().collect();
        let plan = plan_live_tail_extension(
            current.clone(),
            &protected,
            filter_groups,
            self.max_filters_per_req(),
        );

        if plan.retired.is_empty() && plan.replacement_groups.is_empty() {
            return Ok(Vec::new());
        }

        let preserved_count = current.len().saturating_sub(plan.retired.len());
        let retired_count = plan.retired.len();
        let replacement_count = plan.replacement_groups.len();
        let released_slot_count = retired_count.saturating_sub(replacement_count);
        let additional_slot_count = replacement_count.saturating_sub(retired_count);
        let target_count = preserved_count.saturating_add(plan.replacement_groups.len());
        let usable = self
            .subscription_usable_slots
            .load(std::sync::atomic::Ordering::Relaxed);
        if target_count > usable {
            return Err(format!(
                "Minimum-churn live extension needs {target_count} of {usable} usable slots for {}",
                self.url
            ));
        }

        if let Some(remote_limit) = self.remote_subscription_byte_limit() {
            let retired_ids: std::collections::HashSet<_> =
                plan.retired.iter().map(|(id, _)| id).collect();
            let preserved_bytes: usize = current
                .iter()
                .filter(|(id, _)| !retired_ids.contains(id))
                .map(|(_, filters)| {
                    ClientMessage::req(SubscriptionId::generate(), filters.clone())
                        .as_json()
                        .len()
                })
                .sum();
            let replacement_bytes: usize = plan
                .replacement_groups
                .iter()
                .map(|filters| {
                    ClientMessage::req(SubscriptionId::generate(), filters.clone())
                        .as_json()
                        .len()
                })
                .sum();
            if preserved_bytes
                .checked_add(replacement_bytes)
                .and_then(|used| used.checked_add(super::SUBSCRIPTION_BYTE_RESERVED_MARGIN))
                .is_none_or(|used| used > remote_limit)
            {
                return Err(format!(
                    "Minimum-churn live extension exceeds the learned subscription-state limit for {}",
                    self.url
                ));
            }
        }

        let mut close_error = None;
        for (subscription_id, _) in &plan.retired {
            if let Err(error) = close_subscription(subscription_id.clone()).await {
                close_error = Some(error);
                break;
            }
            self.release_live_req_permit(subscription_id);
        }
        if let Some(close_error) = close_error {
            let still_held: std::collections::HashSet<_> = self
                .live_req_permits_held
                .lock()
                .expect("live permit map poisoned")
                .keys()
                .cloned()
                .collect();
            let closed_groups: Vec<_> = plan
                .retired
                .iter()
                .filter(|(id, _)| !still_held.contains(id))
                .map(|(_, filters)| filters.clone())
                .collect();
            let restoration = self
                .subscribe_live_filter_groups_with(closed_groups, &mut subscribe_group)
                .await;
            return match restoration {
                Ok(_) => Err(format!(
                    "Minimum-churn CLOSE failed; prior tail restored: {close_error}"
                )),
                Err(restoration_error) => Err(format!(
                    "Minimum-churn CLOSE failed ({close_error}); prior tail restoration failed ({restoration_error})"
                )),
            };
        }

        match self
            .subscribe_live_filter_groups_with(plan.replacement_groups, &mut subscribe_group)
            .await
        {
            Ok(ids) => {
                tracing::info!(
                    relay = %self.url,
                    new_filter_count,
                    preserved_group_count = preserved_count,
                    retired_group_count = retired_count,
                    replacement_group_count = replacement_count,
                    released_slot_count,
                    additional_slot_count,
                    "Extended core live coverage with minimum churn"
                );
                Ok(ids)
            }
            Err(replacement_error) => {
                let previous_groups: Vec<_> = plan
                    .retired
                    .into_iter()
                    .map(|(_, filters)| filters)
                    .collect();
                match self
                    .subscribe_live_filter_groups_with(previous_groups, &mut subscribe_group)
                    .await
                {
                    Ok(_) => Err(format!(
                        "Minimum-churn live extension failed; prior tail restored: {replacement_error}"
                    )),
                    Err(restoration_error) => Err(format!(
                        "Minimum-churn live extension failed ({replacement_error}); prior tail restoration failed ({restoration_error})"
                    )),
                }
            }
        }
    }

    async fn replace_live_filter_groups_with<F, Fut>(
        &self,
        filter_groups: Vec<Vec<Filter>>,
        mut subscribe_group: F,
    ) -> Result<Vec<SubscriptionId>, String>
    where
        F: FnMut(Vec<Filter>, SessionPermit) -> Fut,
        Fut: Future<Output = Result<SubscriptionId, String>>,
    {
        let previous = self.live_filter_groups();
        self.unsubscribe_live().await;
        match self
            .subscribe_live_filter_groups_with(filter_groups, &mut subscribe_group)
            .await
        {
            Ok(ids) => Ok(ids),
            Err(replacement_error) => match self
                .subscribe_live_filter_groups_with(previous, &mut subscribe_group)
                .await
            {
                Ok(_) => Err(format!(
                    "Live replacement failed; previous coverage restored: {replacement_error}"
                )),
                Err(restoration_error) => Err(format!(
                    "Live replacement failed ({replacement_error}); previous coverage restoration failed ({restoration_error})"
                )),
            },
        }
    }

    fn historic_capacity_consumed_by_live(&self) -> bool {
        let usable = self
            .subscription_usable_slots
            .load(std::sync::atomic::Ordering::Relaxed);
        self.live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .len()
            >= usable
    }

    pub fn can_admit_live_slots(&self, slots: usize) -> bool {
        let usable = self
            .subscription_usable_slots
            .load(std::sync::atomic::Ordering::Relaxed);
        self.live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .len()
            .saturating_add(slots)
            <= usable
    }

    /// Whether auxiliary persistent coverage fits while preserving one usable
    /// ledger slot for transient history. The two control-plane slots have
    /// already been removed from `usable` when the session ledger was built.
    pub fn can_admit_auxiliary_live_groups(&self, filter_groups: &[Vec<Filter>]) -> bool {
        let usable = self
            .subscription_usable_slots
            .load(std::sync::atomic::Ordering::Relaxed);
        let held = self
            .live_req_permits_held
            .lock()
            .expect("live permit map poisoned");
        if held
            .len()
            .saturating_add(filter_groups.len())
            .saturating_add(1)
            > usable
        {
            return false;
        }

        let remote_limit = self.remote_subscription_byte_limit();
        if remote_limit.is_none() {
            return true;
        }
        let existing_bytes: usize = held
            .values()
            .map(|held| {
                ClientMessage::req(SubscriptionId::generate(), held.filters.clone())
                    .as_json()
                    .len()
            })
            .sum();
        let auxiliary_bytes: usize = filter_groups
            .iter()
            .map(|filters| {
                ClientMessage::req(SubscriptionId::generate(), filters.clone())
                    .as_json()
                    .len()
            })
            .sum();
        existing_bytes
            .checked_add(auxiliary_bytes)
            .and_then(|used| used.checked_add(super::SUBSCRIPTION_BYTE_RESERVED_MARGIN))
            .is_some_and(|used| used <= remote_limit.unwrap())
    }

    /// Open separately tracked auxiliary live groups. The caller must first
    /// use [`Self::can_admit_auxiliary_live_groups`] so one transient slot is
    /// preserved; the shared ledger remains the final admission authority.
    pub async fn subscribe_auxiliary_live_filter_groups(
        &self,
        filter_groups: Vec<Vec<Filter>>,
    ) -> Result<Vec<SubscriptionId>, String> {
        if !self.can_admit_auxiliary_live_groups(&filter_groups) {
            return Err(format!(
                "Auxiliary live coverage would consume historic capacity for {}",
                self.url
            ));
        }
        self.subscribe_live_filter_groups(filter_groups).await
    }

    /// Close a caller-owned subset of persistent subscriptions and return
    /// their ledger slots only after CLOSE has been accepted by the SDK.
    pub async fn close_live_subscriptions(
        &self,
        subscription_ids: &[SubscriptionId],
    ) -> Result<(), String> {
        let mut failures = Vec::new();
        for subscription_id in subscription_ids {
            if let Err(error) = self.client.unsubscribe(subscription_id).await {
                tracing::debug!(
                    relay = %self.url,
                    sub_id = %subscription_id,
                    %error,
                    "Failed to close caller-owned live subscription"
                );
                failures.push(format!("{subscription_id}: {error}"));
                continue;
            }
            self.release_live_req_permit(subscription_id);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Failed to close {} live subscriptions on {}: {}",
                failures.len(),
                self.url,
                failures.join("; ")
            ))
        }
    }

    pub fn complete_live_set_fits(&self, slots: usize) -> bool {
        slots
            <= self
                .subscription_usable_slots
                .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn needs_live_consolidation(&self, slots: usize) -> bool {
        let usable = self
            .subscription_usable_slots
            .load(std::sync::atomic::Ordering::Relaxed);
        self.live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .len()
            .saturating_add(slots)
            >= usable
    }

    /// Run the event loop, sending events through the provided channel
    ///
    /// This method blocks and processes notifications from the relay using
    /// nostr-sdk's `Relay::notifications()` channel, which provides event-driven
    /// disconnect detection via `RelayNotification::RelayStatus`.
    ///
    /// Notification types handled:
    /// - `RelayNotification::Event` -> sends `RelayEvent::Event`
    /// - `RelayNotification::Message` with EOSE -> sends `RelayEvent::EndOfStoredEvents`
    /// - `RelayNotification::RelayStatus { Disconnected }` -> terminates loop (disconnect detected)
    /// - `RelayNotification::Shutdown` -> sends `RelayEvent::Shutdown`
    ///
    /// The loop terminates when:
    /// - The sender channel is closed (receiver dropped)
    /// - A shutdown notification is received
    /// - Relay status changes to Disconnected or Terminated
    /// - An error occurs receiving notifications
    ///
    /// # Arguments
    /// * `event_sender` - Channel to send relay events through
    ///
    /// # Note
    /// This uses `Relay::notifications()` instead of `Client::notifications()` because
    /// `RelayNotification::RelayStatus` events are not forwarded to the pool-level channel.
    /// This enables immediate, event-driven disconnect detection without polling.
    ///
    /// We must retrieve the Relay from the Client because nostr-sdk does not expose
    /// `Relay::new()` publicly - relays can only be created through Client or RelayPool.
    pub async fn run_event_loop(self, event_sender: mpsc::Sender<RelayEvent>) {
        let url = self.url.clone();

        // Get the Relay from the client to access relay-level notifications
        // which include RelayStatus changes (not available at pool level)
        let relay = match self.client.relay(&self.url).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::error!(relay = %url, "Relay not found in client");
                return;
            }
            Err(e) => {
                tracing::error!(relay = %url, error = %e, "Failed to get relay from client");
                return;
            }
        };

        // Subscribe to relay-level notifications (includes RelayStatus).
        // In nostr-sdk 0.45 this returns a Stream rather than a broadcast receiver.
        let mut notifications = relay.notifications();

        // EVENT forwarding can block on the bounded processor queue. Subscribe
        // independently to control messages so rate-limit cooldowns take
        // effect and EOSE/CLOSED return slots while the data lane drains. Relay
        // notifications are broadcast, so this does not consume messages from
        // the processor-facing stream below.
        let terminal_connection = self.clone();
        // Construct the receiver before spawning so no fast terminal can race
        // task scheduling and arrive before the control lane is subscribed.
        let mut terminals = relay.notifications();
        let terminal_listener = tokio::spawn(async move {
            while let Some(notification) = terminals.next().await {
                match notification {
                    RelayNotification::Message { message } => match *message {
                        RelayMessage::Notice(message) => {
                            terminal_connection.record_subscription_rate_limit(&message);
                        }
                        RelayMessage::EndOfStoredEvents(sub_id) => {
                            terminal_connection
                                .close_and_release_transient_req_permit(&sub_id)
                                .await;
                        }
                        RelayMessage::Closed {
                            subscription_id,
                            message,
                        } => {
                            terminal_connection.record_subscription_rate_limit(&message);
                            // Mailbox fetches and queued requests can outlive
                            // the manager turn. Pause them on the control lane
                            // before releasing the refused request's capacity.
                            // Filter regrouping and the one NIP-42 retry remain
                            // manager-owned recovery decisions.
                            if !is_auth_required_message(&message)
                                && policy_refusal(&message).is_some_and(|category| {
                                    category != PolicyRefusal::FilterIncompatible
                                })
                            {
                                terminal_connection
                                    .health_tracker
                                    .record_policy_refusal(&terminal_connection.url);
                            }
                            let subscription_id = subscription_id.into_owned();
                            // An auth-required CLOSED is only a retry signal
                            // when an authenticator can actually answer the
                            // challenge; otherwise it is terminal like any
                            // other CLOSED.
                            if !terminal_connection.has_authenticator
                                || !is_auth_required_message(&message)
                            {
                                terminal_connection
                                    .retire_subscription(&subscription_id)
                                    .await;
                            }
                        }
                        _ => {}
                    },
                    RelayNotification::RelayStatus {
                        status: RelayStatus::Disconnected | RelayStatus::Terminated,
                    } => {
                        terminal_connection.clear_subscription_permits();
                        break;
                    }
                    _ => {}
                }
            }
        });

        tracing::debug!(relay = %url, "Starting event loop with relay-level notifications");

        while let Some(notification) = notifications.next().await {
            match notification {
                RelayNotification::Event {
                    event,
                    subscription_id,
                } => {
                    let data_lane_arrival = std::time::Instant::now();
                    self.record_transient_req_event(&subscription_id);
                    tracing::trace!(
                        relay = %url,
                        event_id = %event.id,
                        sub_id = %subscription_id,
                        "Received event"
                    );
                    if event_sender
                        .send(RelayEvent::Event(
                            Box::new(*event),
                            subscription_id.clone(),
                            data_lane_arrival,
                        ))
                        .await
                        .is_err()
                    {
                        tracing::debug!(relay = %url, "Event sender closed, stopping event loop");
                        break;
                    }
                }
                RelayNotification::Message { message } => match *message {
                    RelayMessage::EndOfStoredEvents(sub_id) => {
                        let data_lane_arrival = std::time::Instant::now();
                        tracing::debug!(relay = %url, sub_id = ?sub_id, "Received EOSE");
                        // Convert Cow<SubscriptionId> to owned SubscriptionId
                        let owned_sub_id = sub_id.into_owned();
                        if event_sender
                            .send(RelayEvent::EndOfStoredEvents(
                                owned_sub_id,
                                data_lane_arrival,
                            ))
                            .await
                            .is_err()
                        {
                            tracing::debug!(
                                relay = %url,
                                "Event sender closed, stopping event loop"
                            );
                            break;
                        }
                    }
                    RelayMessage::Notice(msg) => {
                        // Check if this is a negentropy-related notice
                        let is_negentropy_notice = msg.contains("envelope")
                            || msg.contains("NEG-")
                            || msg.contains("negentropy");

                        if is_negentropy_notice {
                            if self.mark_negentropy_unsupported_and_should_log() {
                                tracing::info!(
                                    relay = %url,
                                    notice = %msg,
                                    "Relay does not support NIP-77; using REQ+EOSE"
                                );
                            } else {
                                tracing::debug!(
                                    relay = %url,
                                    notice = %msg,
                                    "Relay repeated its NIP-77 unsupported notice"
                                );
                            }
                        } else {
                            tracing::debug!(relay = %url, message = %msg, "Received NOTICE");
                        }

                        let _ = event_sender.send(RelayEvent::Notice(msg.to_string())).await;
                        // Don't break - continue processing events
                    }
                    RelayMessage::Closed {
                        subscription_id,
                        message: msg,
                    } => {
                        // The terminal-control listener owns transient release;
                        // this processor-facing path retains live restoration.
                        let subscription_id = subscription_id.into_owned();
                        // rust-nostr needs the same subscription and ledger
                        // slot alive while it answers a first NIP-42
                        // challenge. Without an authenticator there is no
                        // challenge to answer, so release like any CLOSED.
                        let released_live =
                            if self.has_authenticator && is_auth_required_message(&msg) {
                                self.live_req_permits_held
                                    .lock()
                                    .expect("live permit map poisoned")
                                    .get(&subscription_id)
                                    .map(|held| ReleasedLiveSubscription {
                                        generation: held.generation,
                                        filter_count: held.filters.len(),
                                    })
                            } else {
                                self.release_live_req_permit(&subscription_id)
                            };
                        if let Some(limit) = self.record_subscription_byte_limit(&msg) {
                            tracing::warn!(
                                relay = %url,
                                limit,
                                "Learned remote cumulative subscription-state limit"
                            );
                        }
                        if is_rate_limit_message(&msg) {
                            // The sync actor emits one canonical signal and owns
                            // cooldown deduplication for a rate-limit episode.
                            tracing::debug!(relay = %url, message = %msg, "Relay closed subscription");
                        } else {
                            tracing::info!(relay = %url, message = %msg, "Relay closed subscription");
                        }
                        let _ = event_sender
                            .send(RelayEvent::Closed {
                                subscription_id,
                                reason: msg.to_string(),
                                live_generation: released_live.map(|released| released.generation),
                                live_filter_count: released_live
                                    .map(|released| released.filter_count),
                            })
                            .await;
                        // Don't break - CLOSED is subscription-specific, not connection-specific
                        // The event loop should continue running for other active subscriptions
                    }
                    _ => {}
                },
                RelayNotification::RelayStatus { status } => {
                    // Event-driven disconnect detection - no polling needed!
                    match status {
                        RelayStatus::Disconnected => {
                            tracing::info!(
                                relay = %url,
                                "Relay disconnected (detected via RelayNotification)"
                            );
                            break;
                        }
                        RelayStatus::Terminated => {
                            tracing::info!(
                                relay = %url,
                                "Relay terminated (detected via RelayNotification)"
                            );
                            break;
                        }
                        _ => {
                            // Log other status changes for debugging
                            tracing::trace!(
                                relay = %url,
                                status = ?status,
                                "Relay status changed"
                            );
                        }
                    }
                }
                RelayNotification::Authenticated => {
                    tracing::debug!(relay = %url, "Authenticated to relay (NIP-42)");
                }
                RelayNotification::AuthenticationFailed => {
                    tracing::warn!(relay = %url, "Authentication failed to relay (NIP-42)");
                    // Don't break - relay may still work for public data
                }
            }
        }

        terminal_listener.abort();

        // The connection is going away; every outstanding transient
        // subscription dies with it, so free their permits.
        self.clear_subscription_permits();

        tracing::debug!(relay = %url, "Notification stream ended, event loop terminated");
    }

    /// Add additional filter subscription (for Layer 2 + 3)
    ///
    /// Use this to subscribe to:
    /// - Layer 2: Events tagging our repos (a/A/q tags)
    /// - Layer 3: Events tagging our root events (e/E/q tags)
    ///
    /// # Arguments
    /// * `filter` - The filter to subscribe to
    /// * `request_class` - Bounded historic-sync origin retained for watchdog diagnostics.
    ///
    /// # Returns
    /// * `Ok(SubscriptionId)` - The subscription ID on success
    /// * `Err(String)` - Error description on failure
    pub async fn subscribe_filter(
        &self,
        filter: Filter,
        request_class: TransientRequestClass,
    ) -> Result<SubscriptionId, String> {
        self.subscribe_filters(vec![filter], request_class).await
    }

    /// Open a transient subscription with an ID already registered by its
    /// caller. Pending-batch owners use this to make an immediate EOSE visible
    /// before the wire request can be answered.
    pub async fn subscribe_filter_with_id(
        &self,
        filter: Filter,
        request_class: TransientRequestClass,
        subscription_id: SubscriptionId,
    ) -> Result<SubscriptionId, String> {
        self.subscribe_filters_with_live_permit(
            vec![filter],
            Some(request_class),
            None,
            Some(subscription_id),
        )
        .await
    }

    /// Subscribe to several OR filters under one NIP-01 subscription ID.
    ///
    /// Relays apply active-REQ limits to subscription IDs, not to the filters
    /// inside a REQ. Grouping related filters preserves NIP-01 semantics while
    /// avoiding one persistent subscription per GRASP tag variant.
    pub async fn subscribe_filters(
        &self,
        filters: Vec<Filter>,
        request_class: TransientRequestClass,
    ) -> Result<SubscriptionId, String> {
        self.subscribe_filters_with_live_permit(filters, Some(request_class), None, None)
            .await
    }

    /// Register grouped history with the manager before any response can arrive.
    pub(super) async fn subscribe_filters_with_id(
        &self,
        filters: Vec<Filter>,
        request_class: TransientRequestClass,
        subscription_id: SubscriptionId,
    ) -> Result<SubscriptionId, String> {
        self.subscribe_filters_with_live_permit(
            filters,
            Some(request_class),
            None,
            Some(subscription_id),
        )
        .await
    }

    /// Atomically reserve the complete live filter set before opening any REQ.
    /// This avoids partial coverage and prevents historic work from consuming
    /// slots between sequential live subscription sends.
    pub async fn subscribe_live_filter_groups(
        &self,
        filter_groups: Vec<Vec<Filter>>,
    ) -> Result<Vec<SubscriptionId>, String> {
        self.subscribe_live_filter_groups_with(filter_groups, |filters, permit| {
            self.subscribe_filters_with_live_permit(filters, None, Some(permit), None)
        })
        .await
    }

    async fn subscribe_live_filter_groups_with<F, Fut>(
        &self,
        filter_groups: Vec<Vec<Filter>>,
        mut subscribe_group: F,
    ) -> Result<Vec<SubscriptionId>, String>
    where
        F: FnMut(Vec<Filter>, SessionPermit) -> Fut,
        Fut: std::future::Future<Output = Result<SubscriptionId, String>>,
    {
        let count = u32::try_from(filter_groups.len())
            .map_err(|_| "Too many live filter groups to reserve".to_string())?;
        if !self.can_admit_live_slots(filter_groups.len()) {
            tracing::warn!(
                relay = %self.url,
                requested_live_slots = count,
                "Live coverage does not fit the per-connection budget; deferring historic work"
            );
            return Err(format!(
                "Live subscription set exceeds budget for {}",
                self.url
            ));
        }
        let mut reservation = self.acquire_subscription_slots(count).await?;

        let mut outputs = Vec::with_capacity(filter_groups.len());
        for filters in filter_groups {
            if let Err(error) = self.ensure_current_session(&reservation) {
                self.close_and_release_live_req_permits(&outputs).await;
                return Err(error);
            }
            let permit = reservation
                .permit
                .split(1)
                .expect("complete live reservation contains one permit per group");
            let permit = SessionPermit {
                generation: reservation.generation,
                permit,
            };
            match subscribe_group(filters, permit).await {
                Ok(subscription_id) => outputs.push(subscription_id),
                Err(error) => {
                    self.close_and_release_live_req_permits(&outputs).await;
                    return Err(error);
                }
            }
        }
        Ok(outputs)
    }

    async fn subscribe_filters_with_live_permit(
        &self,
        filters: Vec<Filter>,
        transient_class: Option<TransientRequestClass>,
        reserved_live_permit: Option<SessionPermit>,
        requested_subscription_id: Option<SubscriptionId>,
    ) -> Result<SubscriptionId, String> {
        if filters.is_empty() {
            return Err("Cannot subscribe with an empty filter set".to_string());
        }

        tracing::debug!(
            relay = %self.url,
            filter_count = filters.len(),
            filters = ?filters,
            auto_close = transient_class.is_some(),
            "subscribe_filters called"
        );

        // Acquire pacing before subscription/class permits: a learned remote
        // query-rate window must not turn local capacity into queued sleepers.
        self.await_query_start().await?;
        if transient_class.is_some() {
            self.await_background_query_start().await;
        }

        // Transient (auto-close) subscriptions share a bounded number of
        // per-connection slots so historic bursts queue instead of
        // exceeding relay subscription budgets. The permit is registered
        // against the subscription id on success and released when the
        // subscription's EOSE or CLOSED arrives (see run_event_loop).
        let (transient_permit, live_permit) = if let Some(request_class) = transient_class {
            if self.historic_capacity_consumed_by_live() {
                tracing::warn!(
                    relay = %self.url,
                    "Historic REQ deferred: live subscriptions consume the usable budget"
                );
                return Err(format!(
                    "No historic subscription capacity for {}",
                    self.url
                ));
            }
            (
                Some(self.acquire_transient_permits(request_class).await?),
                None,
            )
        } else {
            let acquired = match reserved_live_permit {
                Some(permit) => Ok(permit),
                None => self.try_acquire_subscription_slot(),
            };
            match acquired {
                Ok(permit) => (None, Some(permit)),
                Err(_) => {
                    tracing::warn!(
                        relay = %self.url,
                        "Live subscription deferred: per-connection budget exhausted"
                    );
                    return Err(format!(
                        "Live subscription budget exhausted for {}",
                        self.url
                    ));
                }
            }
        };

        if let Some(permit) = &live_permit {
            self.ensure_current_session(permit)?;
        }
        if let Some(permit) = &transient_permit {
            self.ensure_current_generation(permit.generation)?;
        }
        // Transient permits are acquired through the same session helper; a
        // reset closes queued acquisitions and the helper checks generation.
        // Recheck after every pacing/capacity wait, before registering ownership
        // or handing a new request to the SDK. Rejected work drops its permits.
        self.ensure_query_admitted()?;
        let retained_filters = filters.clone();
        // The relay can answer an empty or cached query before `subscribe`
        // returns. Register transient ownership against a caller-chosen ID
        // first so an immediate EOSE/CLOSED cannot race past local accounting.
        let transient_sub_id = transient_class
            .map(|_| requested_subscription_id.unwrap_or_else(SubscriptionId::generate));
        if let (Some(sub_id), Some(permit)) = (&transient_sub_id, transient_permit) {
            self.hold_transient_req_permit(sub_id.clone(), permit);
        }
        let output = if transient_class.is_some() {
            self.client
                .subscribe(filters)
                .with_id(
                    transient_sub_id
                        .clone()
                        .expect("transient subscription has a pre-registered id"),
                )
                .close_on(
                    SubscribeAutoCloseOptions::default()
                        .exit_policy(ReqExitPolicy::ExitOnEOSE)
                        .timeout(Some(TRANSIENT_REQ_PERMIT_TIMEOUT)),
                )
                .await
        } else {
            self.client.subscribe(filters).await
        };

        let output = match output {
            Ok(output) => output,
            Err(error) => {
                if let Some(sub_id) = &transient_sub_id {
                    self.release_transient_req_permit(sub_id);
                }
                return Err(format!("Failed to subscribe on {}: {}", self.url, error));
            }
        };

        if !output.failed.is_empty() {
            if let Some(sub_id) = &transient_sub_id {
                self.release_transient_req_permit(sub_id);
            }
            let failures = output
                .failed
                .values()
                .cloned()
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("Failed to subscribe on {}: {}", self.url, failures));
        }

        if transient_class.is_none() {
            let live_permit = live_permit.expect("live subscription acquired a ledger slot");
            self.live_req_permits_held
                .lock()
                .expect("live permit map poisoned")
                .insert(
                    output.value.clone(),
                    HeldLiveSubscription {
                        _ledger_slot: live_permit.permit,
                        generation: live_permit.generation,
                        filters: retained_filters,
                    },
                );
        }

        tracing::debug!(
            relay = %self.url,
            subscription_id = %output.value,
            "subscribe_filters succeeded"
        );

        Ok(output.value)
    }

    /// Fetch a bounded set of events directly from this relay.
    ///
    /// Used by small control-plane and dependency-recovery queries whose
    /// caller owns result interpretation. It still consumes the same pacing,
    /// transient-class and per-session ledger capacity as historic REQs.
    pub async fn fetch_events(
        &self,
        filter: Filter,
        timeout: Duration,
    ) -> Result<Vec<Event>, String> {
        // The SDK owns this ordinary transient REQ until EOSE/CLOSED. It must
        // share the same permit bound as historic pages, fallbacks and retries
        // rather than escaping the connection budget.
        self.await_query_start().await?;
        self.await_background_query_start().await;
        if self.historic_capacity_consumed_by_live() {
            tracing::warn!(
                relay = %self.url,
                "Control-plane query deferred: live subscriptions consume the usable budget"
            );
            return Err(format!("No transient query capacity for {}", self.url));
        }
        let _transient_cap = self
            .transient_req_permits
            .acquire()
            .await
            .map_err(|_| format!("Transient permits closed for {}", self.url))?;
        let ledger_slot = self.acquire_subscription_slots(1).await?;
        let relay = self
            .client
            .relay(&self.url)
            .await
            .map_err(|error| {
                format!(
                    "Failed to fetch events from {}: failed to resolve relay: {}",
                    self.url, error
                )
            })?
            .ok_or_else(|| {
                format!(
                    "Failed to fetch events from {}: relay is not registered",
                    self.url
                )
            })?;

        self.ensure_current_session(&ledger_slot)?;
        // The SDK event stream can end normally on timeout or disconnect,
        // returning partial history as Ok. Discovery must not mistake that
        // for a completed page (or proof that an author has no relay list).
        // Observe this exact subscription's EOSE independently, retaining SDK
        // event validation, deduplication and NIP-42 retries in the data lane.
        let subscription_id = SubscriptionId::generate();
        let mut notifications = relay.notifications();
        let fetch = async {
            self.ensure_query_admitted()?;
            let mut stream = relay
                .stream_events(filter)
                .with_id(subscription_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            let mut events = std::collections::BTreeSet::new();
            let mut received_eose = false;
            let mut drained = false;
            while !received_eose || !drained {
                tokio::select! {
                    item = stream.next(), if !drained => {
                        match item {
                            Some(Ok(event)) => {
                                // Match the SDK fetch API's existing buffer cap.
                                if events.len() >= 10_000 && !events.contains(&event) {
                                    return Err("too many fetched events".to_string());
                                }
                                events.insert(event);
                            }
                            Some(Err(error)) => return Err(error.to_string()),
                            None => drained = true,
                        }
                    }
                    notification = notifications.next(), if !received_eose => {
                        match notification {
                            Some(RelayNotification::Message { message }) => {
                                if matches!(*message, RelayMessage::EndOfStoredEvents(ref id) if id.as_ref() == &subscription_id) {
                                    received_eose = true;
                                }
                            }
                            Some(RelayNotification::RelayStatus {
                                status: RelayStatus::Disconnected | RelayStatus::Terminated | RelayStatus::Banned,
                            }) | None => {
                                return Err("relay disconnected before EOSE".to_string());
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(events.into_iter().collect())
        };
        tokio::time::timeout(timeout, fetch)
            .await
            .map_err(|_| {
                format!(
                    "Failed to fetch events from {}: timed out before complete EOSE",
                    self.url
                )
            })?
            .map_err(|error| format!("Failed to fetch events from {}: {}", self.url, error))
    }

    /// Get the relay URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether this connection can answer NIP-42 AUTH challenges.
    ///
    /// Without an authenticator the SDK removes auth-refused subscriptions
    /// instead of retaining them, so no post-authentication retry can ever
    /// happen and callers must treat auth-required CLOSED as terminal.
    pub fn answers_auth_challenges(&self) -> bool {
        self.has_authenticator
    }

    /// Get the number of active subscriptions on this connection
    ///
    /// Returns the count of subscriptions tracked by the underlying nostr-sdk client.
    /// This reflects all active REQ subscriptions on the relay, including:
    /// - Layer 1 announcement subscriptions
    /// - Layer 2 repo-tagging subscriptions
    /// - Layer 3 root-event subscriptions
    /// - Both historic (auto-close) and live subscriptions
    ///
    /// # Returns
    /// The number of active subscriptions
    pub async fn subscription_count(&self) -> usize {
        self.client.subscriptions().await.len()
    }

    /// Whether this session still owns a ledger permit for a subscription.
    ///
    /// Peer-supplied CLOSED identifiers must not create application retry
    /// state unless they name work admitted through our bounded ledger.
    pub(super) fn holds_subscription_permit(&self, subscription_id: &SubscriptionId) -> bool {
        self.transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .contains_key(subscription_id)
            || self
                .live_req_permits_held
                .lock()
                .expect("live permit map poisoned")
                .contains_key(subscription_id)
    }

    pub(super) async fn retire_subscription(&self, subscription_id: &SubscriptionId) {
        // A peer CLOSED or interrupted batch is terminal for this subscription.
        // Keep its slot until CLOSE is queued when retiring local work. In particular,
        // rust-nostr retains auth-required REQs when an authenticator is
        // configured so it can retry them after NIP-42. SyncManager owns all
        // deliberate recovery, therefore keeping that desired entry lets SDK
        // retries bypass our cooldowns and grow the registry with every
        // replacement generation.
        // SDK unsubscribe only removes persistent subscriptions. Explicitly
        // close transient siblings when aborting a batch; their SDK entries
        // expire at the configured auto-close deadline.
        let transient = self
            .transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .contains_key(subscription_id);
        if transient {
            if let Ok(Some(relay)) = self.client.relay(&self.url).await {
                if let Err(error) = relay
                    .send_msg(ClientMessage::close(subscription_id.clone()))
                    .await
                {
                    tracing::debug!(relay = %self.url, %subscription_id, %error,
                        "Failed to close retired transient subscription");
                    return;
                }
            }
        }
        if let Err(error) = self.client.unsubscribe(subscription_id).await {
            tracing::debug!(
                relay = %self.url,
                sub_id = %subscription_id,
                error = %error,
                "Failed to retire peer-closed subscription"
            );
        }
        self.release_transient_req_permit(subscription_id);
    }

    pub(super) async fn retire_auth_refused_subscription(&self, subscription_id: &SubscriptionId) {
        self.release_transient_req_permit(subscription_id);
        self.release_live_req_permit(subscription_id);
        if let Err(error) = self.client.unsubscribe(subscription_id).await {
            tracing::debug!(
                relay = %self.url,
                sub_id = %subscription_id,
                error = %error,
                "Failed to retire subscription rejected after authentication"
            );
        }
    }

    /// Disconnect from the relay
    pub async fn disconnect(&self) {
        self.client.disconnect().await;
        self.clear_subscription_permits();
        tracing::debug!(relay = %self.url, "Disconnected from relay");
    }

    /// Unsubscribe from all active subscriptions
    ///
    /// Used during consolidation to reset all subscriptions before rebuilding
    /// with consolidated filters. This sends CLOSE messages for all active
    /// subscriptions on the relay.
    pub async fn unsubscribe_all(&self) {
        if let Err(e) = self.client.unsubscribe_all().await {
            tracing::debug!(relay = %self.url, error = %e, "Failed to unsubscribe from all subscriptions");
        }
        self.clear_subscription_permits();
        tracing::debug!(relay = %self.url, "Unsubscribed from all subscriptions");
    }

    /// Register a held transient-REQ permit for `sub_id` and start its
    /// watchdog.
    fn hold_transient_req_permit(&self, sub_id: SubscriptionId, permit: HeldTransientPermits) {
        let generation = permit.generation;
        self.transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .insert(sub_id.clone(), permit);
        let connection = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(TRANSIENT_REQ_PERMIT_TIMEOUT).await;
            connection
                .expire_transient_request(sub_id, generation)
                .await;
        });
    }

    pub(super) fn set_timeout_sender(
        &self,
        sender: mpsc::Sender<super::SubscriptionClosedNotification>,
    ) {
        *self.timeout_sender.lock().expect("timeout sender poisoned") = Some(sender);
    }

    async fn expire_transient_request(&self, sub_id: SubscriptionId, generation: u64) {
        let diagnostic = self
            .transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .get(&sub_id)
            .filter(|held| held.generation == generation)
            .map(|held| {
                (
                    held.request_class,
                    held.delivered_events,
                    held.opened_at.elapsed().as_secs(),
                    held.last_event_at.map(|at| at.elapsed().as_secs()),
                )
            });
        let Some((request_class, delivered_events, open_seconds, idle_seconds)) = diagnostic else {
            return;
        };
        let Ok(Some(relay)) = self.client.relay(&self.url).await else {
            return;
        };
        let sdk_subscription_active = relay.subscription(&sub_id).await.is_some();
        // SDK unsubscribe deliberately ignores auto-closing subscriptions.
        // Their explicit close_on timeout retires the SDK registry entry;
        // this CLOSE is the local ledger boundary, even if SDK cleanup races it.
        if let Err(error) = relay.send_msg(ClientMessage::close(sub_id.clone())).await {
            tracing::warn!(relay = %self.url, %sub_id, %error,
                "Transient REQ watchdog could not send CLOSE; retaining subscription slot");
            crate::metrics::record_transient_req_watchdog(request_class.as_str(), "close_failed");
            return;
        }
        // A real EOSE/CLOSED or session reset may have won while CLOSE awaited
        // the sender. Never turn its successful completion into a timeout.
        if !Self::release_transient_req_permit_for_generation(
            &self.transient_req_permits_held,
            &sub_id,
            generation,
            || self.health_tracker.record_request_failure(&self.url),
        ) {
            return;
        }
        tracing::warn!(relay = %self.url, %sub_id, request_class = request_class.as_str(),
            sdk_subscription_active, delivered_events, open_seconds, idle_seconds,
            "Transient REQ watchdog retired timed-out request");
        crate::metrics::record_transient_req_watchdog(request_class.as_str(), "closed");
        let sender = self
            .timeout_sender
            .lock()
            .expect("timeout sender poisoned")
            .clone();
        if let Some(sender) = sender {
            // Capacity is released before bounded actor backpressure. This is
            // a failed terminal, never a synthetic successful EOSE.
            let _ = sender
                .send(super::SubscriptionClosedNotification {
                    relay_url: self.url.clone(),
                    subscription_id: sub_id,
                    reason: "local request timeout".into(),
                    generation: Some(generation),
                    live_filter_count: None,
                    timed_out: true,
                })
                .await;
        }
    }

    fn record_transient_req_event(&self, sub_id: &SubscriptionId) {
        if let Some(held) = self
            .transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .get_mut(sub_id)
        {
            held.delivered_events = held.delivered_events.saturating_add(1);
            held.last_event_at = Some(std::time::Instant::now());
        }
    }

    /// Release the transient-REQ permit held for `sub_id`, if any.
    fn release_transient_req_permit(&self, sub_id: &SubscriptionId) {
        self.transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .remove(sub_id);
    }

    fn release_transient_req_permit_for_generation(
        held: &TransientReqPermitMap,
        sub_id: &SubscriptionId,
        generation: u64,
        before_release: impl FnOnce(),
    ) -> bool {
        let mut permits = held.lock().expect("transient permit map poisoned");
        if permits
            .get(sub_id)
            .is_some_and(|permit| permit.generation == generation)
        {
            // Pause admission before releasing capacity to queued workers.
            // Stale timers and an EOSE winner must not record a failure.
            before_release();
            permits.remove(sub_id);
            true
        } else {
            false
        }
    }

    async fn close_and_release_transient_req_permit(&self, sub_id: &SubscriptionId) {
        let is_held = self
            .transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .contains_key(sub_id);
        if is_held {
            // EOSE ends the stored-event phase, but an ordinary NIP-01 REQ is
            // relay-side active until CLOSE. Wait for the SDK to enqueue CLOSE
            // before making the ledger slot available to another consumer.
            if let Ok(Some(relay)) = self.client.relay(&self.url).await {
                let _ = relay.send_msg(ClientMessage::close(sub_id.clone())).await;
            }
            self.release_transient_req_permit(sub_id);
        }
    }

    /// Release the live ledger slot held for `sub_id`, if any.
    fn release_live_req_permit(&self, sub_id: &SubscriptionId) -> Option<ReleasedLiveSubscription> {
        self.live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .remove(sub_id)
            .map(|held| ReleasedLiveSubscription {
                generation: held.generation,
                filter_count: held.filters.len(),
            })
    }

    #[cfg(test)]
    fn release_subscription_permits_on_closed(&self, sub_id: &SubscriptionId) -> Option<u64> {
        self.release_transient_req_permit(sub_id);
        self.release_live_req_permit(sub_id)
            .map(|released| released.generation)
    }

    /// Roll back a partially opened live group set. CLOSE is enqueued before
    /// the corresponding ledger slot is returned, keeping local and relay
    /// subscription accounting in lockstep.
    async fn close_and_release_live_req_permits(&self, sub_ids: &[SubscriptionId]) {
        let relay = self.client.relay(&self.url).await.ok().flatten();
        for sub_id in sub_ids {
            if let Some(relay) = &relay {
                let _ = relay.send_msg(ClientMessage::close(sub_id.clone())).await;
            }
            let _ = self.release_live_req_permit(sub_id);
        }
    }

    /// Release every held transient-REQ permit (connection teardown).
    fn clear_transient_req_permits(&self) {
        self.transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .clear();
    }

    fn clear_subscription_permits(&self) {
        self.clear_transient_req_permits();
        self.live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .clear();
    }

    // =========================================================================
    // NIP-77 Negentropy Support
    // =========================================================================

    /// Check if negentropy sync should be attempted
    ///
    /// For simplicity and robustness, we always try negentropy first. If it fails,
    /// this returns true to indicate we should try negentropy sync. The actual
    /// sync will handle failures gracefully with fallback to REQ+EOSE.
    ///
    /// # Note
    /// This uses a "try and fallback" approach because:
    /// - Some relays support NIP-77 but don't advertise it in NIP-11
    /// - Some relays claim NIP-77 support but have bugs
    /// - The nostr-sdk 0.44 API for relay document access varies
    ///
    /// # Returns
    /// * `false` if we've confirmed this relay doesn't support NIP-77, or a
    ///   transient-failure cooldown is active
    /// * `true` if unknown or supported (will attempt and handle failure)
    pub async fn supports_negentropy(&self) -> bool {
        // 0 = unknown (try it), 1 = supported, 2 = confirmed not supported
        let status = self
            .nip77_supported
            .load(std::sync::atomic::Ordering::Relaxed);

        if status == 2 {
            // We've already confirmed this relay doesn't support NIP-77
            tracing::trace!(relay = %self.url, "Skipping negentropy - relay confirmed not to support NIP-77");
            return false;
        }

        if self
            .nip77_query_rate_limited
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            tracing::trace!(relay = %self.url, "Skipping negentropy - query-rate budget was exhausted this session");
            return false;
        }

        // Transient-failure cooldown: pause negentropy without ruling it out
        let cooldown_until = *self
            .nip77_cooldown_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(cooldown_until, Some(until) if tokio::time::Instant::now() < until) {
            tracing::trace!(relay = %self.url, "Skipping negentropy - transient-failure cooldown active");
            return false;
        }

        // Unknown or supported - try it
        true
    }

    /// Mark this relay as not supporting NIP-77 negentropy
    ///
    /// Called only when the relay explicitly signals it cannot speak NIP-77
    /// (see [`classify_negentropy_failure`]), or when a material first-pass
    /// exact-ID hydration failure shows its advertised inventory is not usable.
    /// Small residuals and transient failures retain NIP-77.
    ///
    /// Future batches will skip negentropy and use REQ+EOSE directly.
    pub fn mark_negentropy_unsupported(&self) {
        self.nip77_supported
            .store(2, std::sync::atomic::Ordering::Relaxed);
    }

    /// Mark NIP-77 unsupported and return whether this is the first diagnostic
    /// emitted by any clone of this connection.
    fn mark_negentropy_unsupported_and_should_log(&self) -> bool {
        self.mark_negentropy_unsupported();
        !self
            .nip77_unsupported_logged
            .swap(true, std::sync::atomic::Ordering::Relaxed)
    }

    /// Fall back to paced REQs for the rest of this connection session.
    ///
    /// rust-nostr owns the messages within a NIP-77 round, while relays can
    /// charge every NEG-MSG against the same query-rate bucket as REQ. We can
    /// pace round starts but not those internal messages, so retrying NIP-77
    /// after cooldown can deterministically exhaust the bucket again.
    fn mark_negentropy_query_rate_limited(&self) -> bool {
        !self
            .nip77_query_rate_limited
            .swap(true, std::sync::atomic::Ordering::Relaxed)
    }

    /// Record a transient negentropy failure and start (or keep) a cooldown.
    ///
    /// Failures that arrive while a cooldown is already active come from
    /// diffs that were in flight when the cooldown started (e.g. a burst of
    /// concurrent per-filter syncs sharing one root cause); they do not
    /// escalate the backoff.
    ///
    /// # Returns
    /// The newly applied cooldown, or `None` if an existing cooldown
    /// absorbed the failure.
    fn record_negentropy_transient_failure(&self) -> Option<Duration> {
        let mut cooldown_until = self
            .nip77_cooldown_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = tokio::time::Instant::now();
        if matches!(*cooldown_until, Some(until) if now < until) {
            return None;
        }
        let failures = self
            .nip77_transient_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let index = (failures as usize).min(NEGENTROPY_TRANSIENT_BACKOFF.len() - 1);
        let cooldown = NEGENTROPY_TRANSIENT_BACKOFF[index];
        *cooldown_until = Some(now + cooldown);
        Some(cooldown)
    }

    /// Record a successful negentropy diff: clear the transient-failure state.
    fn record_negentropy_success(&self) {
        self.nip77_transient_failures
            .store(0, std::sync::atomic::Ordering::Relaxed);
        *self
            .nip77_cooldown_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    /// Perform a negentropy sync diff (dry run) to identify missing events
    ///
    /// This method performs NIP-77 negentropy reconciliation without downloading events.
    /// It returns the list of event IDs that need to be fetched. The caller should then
    /// manually fetch these events and pass them through the write policy for validation.
    ///
    /// # Arguments
    /// * `filter` - The filter to sync
    ///
    /// # Returns
    /// * `Ok(SyncSummary)` - Reconciliation result with remote/local/sent event IDs
    /// * `Err(String)` - Sync failed (relay may not support NIP-77, or other error)
    ///
    /// # Usage Pattern
    /// ```ignore
    /// // 1. Get the diff
    /// let reconciliation = conn.negentropy_sync_diff(filter).await?;
    ///
    /// // 2. Fetch missing events by ID
    /// if !reconciliation.remote.is_empty() {
    ///     let ids: Vec<EventId> = reconciliation.remote.into_iter().collect();
    ///     let filter = Filter::new().ids(ids);
    ///     conn.subscribe_filter(filter, tx).await?;
    /// }
    ///
    /// // 3. Events come through normal flow and get validated via process_event_static
    /// ```
    pub async fn negentropy_sync_diff(
        &self,
        filter: Filter,
    ) -> Result<nostr_sdk::client::SyncSummary, String> {
        // Bound concurrent rounds: historic sync opens one diff per filter,
        // and relays count each open round against a per-connection budget
        // shared with live subscriptions (see MAX_CONCURRENT_NEG_DIFFS).
        // The permit is held for the whole round, including the timeout.
        self.await_query_start().await?;
        self.await_background_query_start().await;
        if self.historic_capacity_consumed_by_live() {
            tracing::warn!(
                relay = %self.url,
                "Negentropy round deferred: live subscriptions consume the usable budget"
            );
            return Err(format!("No negentropy capacity for {}", self.url));
        }
        let _permit = self
            .neg_diff_permits
            .acquire()
            .await
            .map_err(|_| format!("Negentropy permits closed for {}", self.url))?;
        let ledger_slot = self.acquire_subscription_slots(1).await?;

        // While this round was queued, an earlier round may have started a
        // transient-failure cooldown or received an explicit unsupported
        // signal. Bail out to the per-batch REQ+EOSE fallback instead of
        // opening another round against a relay that just failed. This does
        // not record a failure, so it cannot escalate the cooldown.
        if !self.supports_negentropy().await {
            return Err(format!(
                "Negentropy skipped for {}: cooldown active or relay marked unsupported",
                self.url
            ));
        }

        // A queued refusal is not a failed NIP-77 exchange. Return before
        // entering the round's failure accounting.
        self.ensure_query_admitted()?;
        // Use dry_run to only identify differences without downloading events
        self.ensure_current_session(&ledger_slot)?;
        // Keep the SDK's seen-ID tracker separate from policy-controlled storage.
        // It has no reconciliation inventory; attaching the production database
        // to the SDK would let incoming events bypass our write policy.
        let items = match &self.database {
            Some(database) => tokio::time::timeout(
                NEGENTROPY_DIFF_TIMEOUT,
                database.negentropy_items(filter.clone()),
            )
            .await
            .map_err(|_| "Timed out loading local negentropy inventory".to_string())?
            .map_err(|error| format!("Failed to load local negentropy inventory: {error}"))?,
            None => Vec::new(),
        };
        let relay = self
            .client
            .relay(&self.url)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("Relay is not registered: {}", self.url))?;
        let sync_task = async move {
            self.ensure_query_admitted()?;
            self.ensure_current_session(&ledger_slot)?;
            let summary = relay
                .sync(filter)
                .items(items)
                .opts(SyncOptions::default().dry_run())
                .await
                .map_err(|error| error.to_string())?;
            let url = relay.url().clone();
            let with_source = |ids: std::collections::HashSet<EventId>| {
                ids.into_iter()
                    .map(|id| (id, std::collections::HashSet::from([url.clone()])))
                    .collect()
            };
            Ok(nostr_sdk::client::SyncSummary {
                local: summary.local,
                remote: with_source(summary.remote),
                sent: with_source(summary.sent),
                received: with_source(summary.received),
                send_failures: std::collections::HashMap::from([(url, summary.send_failures)]),
            })
        };

        self.run_negentropy_diff_with_timeout(sync_task, NEGENTROPY_DIFF_TIMEOUT)
            .await
    }

    async fn run_negentropy_diff_with_timeout<F>(
        &self,
        sync_task: F,
        timeout_duration: Duration,
    ) -> Result<nostr_sdk::client::SyncSummary, String>
    where
        F: Future<Output = Result<nostr_sdk::client::SyncSummary, String>>,
    {
        // Clone the atomic for the polling task
        let nip77_status = self.nip77_supported.clone();
        let url = self.url.clone();

        // Create a polling task that checks if NIP-77 support was detected as unavailable
        let poll_task = async move {
            loop {
                let status = nip77_status.load(std::sync::atomic::Ordering::Relaxed);
                if status == 2 {
                    // A concurrent sync received an explicit unsupported signal
                    return Err(format!(
                        "Relay {} was marked as not supporting NIP-77 by a concurrent sync",
                        url
                    ));
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        };

        let result = match tokio::time::timeout(timeout_duration, async {
            tokio::select! {
                poll_result = poll_task => {
                    poll_result
                }
                sync_result = sync_task => {
                    sync_result
                }
            }
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(format!(
                "Negentropy diff timed out after {:.3}s",
                timeout_duration.as_secs_f64()
            )),
        };

        match result {
            Ok(reconciliation) => {
                self.record_negentropy_success();
                tracing::debug!(
                    relay = %self.url,
                    local_count = reconciliation.local.len(),
                    remote_count = reconciliation.remote.len(),
                    "Negentropy diff completed (dry run)"
                );
                Ok(reconciliation)
            }
            Err(e) => {
                if is_query_rate_limit_message(&e) {
                    self.record_query_rate_limit();
                }
                match classify_negentropy_failure(&e) {
                    NegentropyFailure::Unsupported => {
                        if self.mark_negentropy_unsupported_and_should_log() {
                            tracing::info!(
                                relay = %self.url,
                                error = %e,
                                "Relay does not support NIP-77; using REQ+EOSE"
                            );
                        } else {
                            tracing::debug!(
                                relay = %self.url,
                                error = %e,
                                "Relay repeated its NIP-77 unsupported response"
                            );
                        }
                    }
                    NegentropyFailure::Transient => {
                        // One warning per cooldown; in-flight failures sharing
                        // the same root cause are logged at debug level
                        if let Some(cooldown) = self.record_negentropy_transient_failure() {
                            tracing::warn!(
                                relay = %self.url,
                                error = %e,
                                cooldown_secs = cooldown.as_secs(),
                                "Transient negentropy failure, pausing NIP-77 and falling back to REQ+EOSE"
                            );
                        } else {
                            tracing::debug!(
                                relay = %self.url,
                                error = %e,
                                "Negentropy diff failed during existing cooldown"
                            );
                        }
                    }
                }
                Err(e)
            }
        }
    }

    /// Check if this connection has a database configured for negentropy
    pub fn has_database(&self) -> bool {
        self.database.is_some()
    }
}

#[cfg(test)]
mod test_relay;

#[cfg(test)]
mod tests {
    use super::test_relay::TestRelay;
    use super::*;

    #[test]
    fn nip11_owner_is_retained_without_a_limitation_object() {
        let owner = Keys::generate().public_key();
        let body = format!(r#"{{"pubkey":"{}"}}"#, owner.to_hex());

        let hints = parse_relay_limit_hints(&body);

        assert_eq!(hints.owner, Some(owner));
        assert_eq!(hints.default_limit, None);
        assert_eq!(hints.max_subscriptions, None);
    }

    #[test]
    fn grasp08_flag_requires_supported_grasps_entry() {
        assert!(parse_relay_limit_hints(r#"{"supported_grasps":["GRASP-01","GRASP-08"]}"#).grasp08);
        assert!(!parse_relay_limit_hints(r#"{"supported_grasps":["GRASP-01"]}"#).grasp08);
        assert!(!parse_relay_limit_hints(r#"{"name":"relay without grasps"}"#).grasp08);
    }

    #[test]
    fn grasp08_flag_defaults_to_false_for_malformed_documents() {
        // Non-array supported_grasps and unparseable bodies both mean "not a
        // known private service", never an error.
        assert!(!parse_relay_limit_hints(r#"{"supported_grasps":"GRASP-08"}"#).grasp08);
        assert!(!parse_relay_limit_hints(r#"{"supported_grasps":8}"#).grasp08);
        assert!(!parse_relay_limit_hints("not json at all").grasp08);
    }

    /// Event-directed connection with the permissive policy used by tests
    /// that dial loopback fixtures.
    fn permissive_connection(url: &str, keys: Keys) -> RelayConnection {
        RelayConnection::new(
            url.to_string(),
            Some(keys),
            RelayTargetSource::EventDirected,
            OutboundTargetPolicy {
                allow_non_global: true,
            },
        )
    }
    use nostr_sdk::prelude::LocalRelayBuilder;
    use std::future::pending;

    #[tokio::test]
    async fn connection_readiness_waits_until_status_is_connected() {
        let mut statuses = [
            RelayStatus::Connecting,
            RelayStatus::Connecting,
            RelayStatus::Connected,
        ]
        .into_iter();

        wait_for_connected_status(|| statuses.next().expect("status sequence exhausted"))
            .await
            .expect("delayed connection should become ready");
    }

    #[tokio::test]
    async fn connection_readiness_remains_bounded_when_connecting_never_completes() {
        let result = tokio::time::timeout(
            Duration::from_millis(60),
            wait_for_connected_status(|| RelayStatus::Connecting),
        )
        .await;

        assert!(
            result.is_err(),
            "a relay stuck in Connecting must not be reported as ready"
        );
    }

    #[tokio::test]
    async fn connection_readiness_fails_on_terminal_status() {
        let mut statuses = [RelayStatus::Connecting, RelayStatus::Disconnected].into_iter();

        assert_eq!(
            wait_for_connected_status(|| statuses.next().expect("status sequence exhausted")).await,
            Err(RelayStatus::Disconnected)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hung_negentropy_diff_times_out_and_pauses_attempts_until_cooldown() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        assert!(connection.supports_negentropy().await);

        let result = connection
            .run_negentropy_diff_with_timeout(
                pending::<Result<nostr_sdk::client::SyncSummary, String>>(),
                Duration::from_millis(20),
            )
            .await;

        assert!(result
            .expect_err("a hung NIP-77 exchange must reach its local deadline")
            .contains("timed out"));
        assert!(
            !connection.supports_negentropy().await,
            "a timed-out relay must use REQ+EOSE while the cooldown is active"
        );

        tokio::time::advance(NEGENTROPY_TRANSIENT_BACKOFF[0] + Duration::from_secs(1)).await;
        assert!(
            connection.supports_negentropy().await,
            "a timeout must not disable NIP-77 permanently"
        );
    }

    /// Run a diff seeded with a fixed error and assert it surfaces as a failure.
    async fn failing_diff(connection: &RelayConnection, error: &str) {
        let error = error.to_string();
        connection
            .run_negentropy_diff_with_timeout(async move { Err(error) }, Duration::from_secs(5))
            .await
            .expect_err("diff seeded with an error must fail");
    }

    #[test]
    fn production_failure_strings_classify_as_transient_or_unsupported() {
        // Transient errors carry no information about NIP-77 support
        // (all observed on gitnostr.com, 2026-08-04)
        for error in [
            r#"Negentropy diff had failures: {RelayUrl("wss://relay.ngit.dev"): "channel lagged by 3"}"#,
            r#"Negentropy diff had failures: {RelayUrl("wss://nos.lol"): "timeout"}"#,
            r#"Negentropy diff had failures: {RelayUrl("wss://relay.cyberguy.fyi"): "blocked: too many subscriptions"}"#,
            "Negentropy diff timed out after 15.000s",
        ] {
            assert_eq!(
                classify_negentropy_failure(error),
                NegentropyFailure::Transient,
                "{error}"
            );
        }

        // Explicit unsupported signals from the relay
        for error in [
            r#"Negentropy diff had failures: {RelayUrl("wss://example.com"): "negentropy not supported"}"#,
            r#"Negentropy diff had failures: {RelayUrl("wss://example.com"): "server does not support our negentropy protocol version"}"#,
        ] {
            assert_eq!(
                classify_negentropy_failure(error),
                NegentropyFailure::Unsupported,
                "{error}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transient_diff_failure_pauses_negentropy_only_until_cooldown_elapses() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());

        failing_diff(
            &connection,
            r#"Negentropy diff had failures: {RelayUrl("wss://relay.example.com"): "channel lagged by 3"}"#,
        )
        .await;

        assert!(
            !connection.supports_negentropy().await,
            "a transient failure must pause NIP-77 while the cooldown is active"
        );

        tokio::time::advance(NEGENTROPY_TRANSIENT_BACKOFF[0] + Duration::from_secs(1)).await;
        assert!(
            connection.supports_negentropy().await,
            "a transient failure must not disable NIP-77 permanently"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_burst_of_transient_failures_does_not_escalate_backoff() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());

        for _ in 0..40 {
            failing_diff(
                &connection,
                r#"Negentropy diff had failures: {RelayUrl("wss://relay.example.com"): "timeout"}"#,
            )
            .await;
        }

        tokio::time::advance(NEGENTROPY_TRANSIENT_BACKOFF[0] + Duration::from_secs(1)).await;
        assert!(
            connection.supports_negentropy().await,
            "in-flight failures sharing one root cause must not escalate the cooldown"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_transient_failures_escalate_and_success_resets_backoff() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        let transient =
            r#"Negentropy diff had failures: {RelayUrl("wss://relay.example.com"): "timeout"}"#;

        // First failed attempt starts the first cooldown
        failing_diff(&connection, transient).await;
        tokio::time::advance(NEGENTROPY_TRANSIENT_BACKOFF[0] + Duration::from_secs(1)).await;
        assert!(connection.supports_negentropy().await);

        // Second consecutive failed attempt backs off longer
        failing_diff(&connection, transient).await;
        tokio::time::advance(NEGENTROPY_TRANSIENT_BACKOFF[0] + Duration::from_secs(1)).await;
        assert!(
            !connection.supports_negentropy().await,
            "consecutive failed attempts must back off longer"
        );
        tokio::time::advance(NEGENTROPY_TRANSIENT_BACKOFF[1]).await;
        assert!(connection.supports_negentropy().await);

        // A successful diff resets the schedule to the first cooldown
        connection
            .run_negentropy_diff_with_timeout(
                async { Ok(nostr_sdk::client::SyncSummary::default()) },
                Duration::from_secs(5),
            )
            .await
            .expect("successful diff");
        failing_diff(&connection, transient).await;
        tokio::time::advance(NEGENTROPY_TRANSIENT_BACKOFF[0] + Duration::from_secs(1)).await;
        assert!(
            connection.supports_negentropy().await,
            "a successful diff must reset the backoff schedule"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_unsupported_signal_disables_negentropy_for_the_connection() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());

        failing_diff(
            &connection,
            r#"Negentropy diff had failures: {RelayUrl("wss://relay.example.com"): "negentropy not supported"}"#,
        )
        .await;

        assert!(!connection.supports_negentropy().await);
        tokio::time::advance(Duration::from_secs(48 * 3600)).await;
        assert!(
            !connection.supports_negentropy().await,
            "an explicit unsupported signal is permanent for the connection lifetime"
        );
    }

    #[tokio::test]
    async fn concurrent_unsupported_marking_aborts_diff_without_claiming_a_notice() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.mark_negentropy_unsupported();

        let error = connection
            .run_negentropy_diff_with_timeout(
                pending::<Result<nostr_sdk::client::SyncSummary, String>>(),
                Duration::from_secs(5),
            )
            .await
            .expect_err("a relay marked unsupported must abort in-flight diffs");

        assert!(
            !error.contains("NOTICE"),
            "abort reason must not fabricate a NOTICE-based detection: {error}"
        );
    }

    #[tokio::test]
    async fn unsupported_capability_is_logged_once_across_connection_clones() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        let clone = connection.clone();

        assert!(connection.mark_negentropy_unsupported_and_should_log());
        assert!(!clone.mark_negentropy_unsupported_and_should_log());
        assert!(!connection.supports_negentropy().await);
    }

    #[tokio::test]
    async fn fetch_events_requires_eose_after_partial_delivery() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        for disconnect in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let event = EventBuilder::new(Kind::TextNote, "incomplete history")
                .finalize(&Keys::generate())
                .unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                while let Some(frame) = ws.next().await {
                    let frame = frame.unwrap();
                    if !frame.is_text() {
                        continue;
                    }
                    let request: serde_json::Value =
                        serde_json::from_str(frame.to_text().unwrap()).unwrap();
                    if request[0] != "REQ" {
                        continue;
                    }
                    ws.send(Message::Text(
                        serde_json::json!(["EVENT", request[1], event])
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                    if disconnect {
                        ws.close(None).await.unwrap();
                    } else {
                        // Stay connected without EOSE until the client's
                        // bounded fetch cancellation sends CLOSE.
                        tokio::time::timeout(Duration::from_secs(5), async {
                            while let Some(frame) = ws.next().await {
                                let Ok(frame) = frame else { break };
                                if frame.is_close()
                                    || frame.to_text().is_ok_and(|text| text.contains("CLOSE"))
                                {
                                    break;
                                }
                            }
                        })
                        .await
                        .unwrap();
                    }
                    break;
                }
            });
            let connection = permissive_connection(&url, Keys::generate());
            connection.connect(3).await.unwrap();
            let result = connection
                .fetch_events(
                    Filter::new().kind(Kind::TextNote),
                    Duration::from_millis(250),
                )
                .await;
            connection.disconnect().await;
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
            assert!(
                result.is_err(),
                "partial fetch without EOSE was accepted (disconnect={disconnect}): {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn negentropy_uses_local_inventory_without_bypassing_write_policy() {
        use nostr_sdk::prelude::NostrDatabase;
        use std::collections::HashSet;

        let remote_database = std::sync::Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let remote =
            TestRelay::start(LocalRelayBuilder::default().database(remote_database.clone())).await;
        let other = TestRelay::start(LocalRelayBuilder::default()).await;
        let database: SharedDatabase =
            std::sync::Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let keys = Keys::generate();
        let event = |content| {
            EventBuilder::new(Kind::TextNote, content)
                .finalize(&keys)
                .unwrap()
        };
        let common = event("already stored");
        let remote_only = event("must pass write policy");
        let local_only = event("must not be uploaded");
        let unrelated = event("on another relay");
        database.save_event(&common).await.unwrap();
        database.save_event(&local_only).await.unwrap();
        remote.add_event(common.clone()).await.unwrap();
        remote.add_event(remote_only.clone()).await.unwrap();
        other.add_event(unrelated.clone()).await.unwrap();
        let connection = RelayConnection::new_with_database(
            remote.url().await.to_string(),
            database.clone(),
            None,
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection.connect(3).await.unwrap();
        let other_url = other.url().await;
        connection
            .client
            .add_relay(other_url.clone())
            .await
            .unwrap();
        connection
            .client
            .try_connect_relay(other_url, Duration::from_secs(3))
            .await
            .unwrap();

        let diff = tokio::time::timeout(
            Duration::from_secs(5),
            connection.negentropy_sync_diff(Filter::new().kind(Kind::TextNote)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            diff.remote.keys().copied().collect::<HashSet<_>>(),
            HashSet::from([remote_only.id])
        );
        assert_eq!(diff.local, HashSet::from([local_only.id]));
        assert!(diff.sent.is_empty());
        assert!(diff.received.is_empty());
        assert!(
            database
                .event_by_id(&remote_only.id)
                .await
                .unwrap()
                .is_none(),
            "reconciliation must not save remote payloads outside write policy"
        );
        assert!(
            remote_database
                .event_by_id(&local_only.id)
                .await
                .unwrap()
                .is_none(),
            "dry-run reconciliation must not publish local events"
        );

        // Ordinary SDK fetching must also leave the production store untouched.
        let fetched = connection
            .fetch_events(Filter::new().id(remote_only.id), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(fetched, vec![remote_only.clone()]);
        assert!(database
            .event_by_id(&remote_only.id)
            .await
            .unwrap()
            .is_none());

        connection.disconnect().await;
        remote.shutdown();
        other.shutdown();
    }

    #[tokio::test]
    async fn fetch_events_targets_the_connections_exact_relay() {
        let configured = TestRelay::start(LocalRelayBuilder::default()).await;
        let other = TestRelay::start(LocalRelayBuilder::default()).await;

        let expected = EventBuilder::new(Kind::TextNote, "only on the other relay")
            .finalize(&Keys::generate())
            .expect("build event");
        other
            .add_event(expected.clone())
            .await
            .expect("seed other relay");

        // Operator-configured source: loopback fixtures stay dialable under
        // the strict default policy, mirroring the bootstrap-relay exception.
        let connection = RelayConnection::new(
            configured.url().await.to_string(),
            Some(Keys::generate()),
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection
            .connect(3)
            .await
            .expect("connect configured relay");
        let other_url = other.url().await;
        connection
            .client
            .add_relay(other_url.clone())
            .await
            .expect("register other relay");
        connection
            .client
            .try_connect_relay(other_url, Duration::from_secs(3))
            .await
            .expect("connect other relay");

        let fetched = connection
            .fetch_events(Filter::new().id(expected.id), Duration::from_secs(2))
            .await
            .expect("fetch from configured relay");
        assert!(
            fetched.is_empty(),
            "a relay-specific fetch must not return an event from another client relay"
        );

        connection.disconnect().await;
        configured.shutdown();
        other.shutdown();
    }

    #[tokio::test]
    async fn terminal_control_lane_releases_permits_behind_event_backpressure() {
        const AUTHORS: usize = 3;
        const EVENTS_PER_AUTHOR: usize = 400;

        let relay = TestRelay::start(LocalRelayBuilder::default()).await;
        let mut authors = Vec::with_capacity(AUTHORS);
        for author_index in 0..AUTHORS {
            let keys = Keys::generate();
            authors.push(keys.public_key());
            for event_index in 0..EVENTS_PER_AUTHOR {
                let event = EventBuilder::new(
                    Kind::TextNote,
                    format!("burst-{author_index}-{event_index}"),
                )
                .finalize(&keys)
                .expect("build burst event");
                relay.add_event(event).await.expect("seed burst event");
            }
        }

        let connection = RelayConnection::new(
            relay.url().await.to_string(),
            Some(Keys::generate()),
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection.connect(3).await.expect("connect burst relay");
        // Keep the data lane full after its first event. The independent
        // terminal listener must still observe every EOSE and release slots.
        let (event_tx, _event_rx) = tokio::sync::mpsc::channel(1);
        let event_loop = tokio::spawn(connection.clone().run_event_loop(event_tx));

        for author in authors {
            connection
                .subscribe_filter(
                    Filter::new().author(author),
                    TransientRequestClass::NegentropyHydration,
                )
                .await
                .expect("open bounded burst page");
        }

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if connection
                    .transient_req_permits_held
                    .lock()
                    .expect("transient permit map poisoned")
                    .is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the terminal lane must release permits behind blocked EVENT delivery");

        connection.disconnect().await;
        relay.shutdown();
        event_loop.abort();
    }

    #[tokio::test]
    async fn immediate_empty_eose_cannot_arrive_before_permit_registration() {
        let relay = TestRelay::start(LocalRelayBuilder::default()).await;
        let connection = RelayConnection::new(
            relay.url().await.to_string(),
            Some(Keys::generate()),
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection.connect(3).await.expect("connect empty relay");
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(RELAY_EVENT_BUFFER_CAPACITY);
        let event_loop = tokio::spawn(connection.clone().run_event_loop(event_tx));
        let drain = tokio::spawn(async move { while event_rx.recv().await.is_some() {} });

        for _ in 0..25 {
            connection
                .subscribe_filter(
                    Filter::new().kind(Kind::Custom(65_535)),
                    TransientRequestClass::NegentropyHydration,
                )
                .await
                .expect("open empty transient request");
        }

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if connection
                    .transient_req_permits_held
                    .lock()
                    .expect("transient permit map poisoned")
                    .is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("every immediate empty EOSE must release its registered permit");

        connection.disconnect().await;
        relay.shutdown();
        event_loop.abort();
        drain.abort();
    }

    #[tokio::test]
    async fn peer_closed_subscription_is_removed_from_sdk_registry() {
        let relay = TestRelay::start(LocalRelayBuilder::default()).await;
        let connection = RelayConnection::new(
            relay.url().await.to_string(),
            Some(Keys::generate()),
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection.connect(3).await.expect("connect registry relay");

        let subscription_id = connection
            .subscribe_live_filter_groups(vec![vec![Filter::new().kind(Kind::TextNote)]])
            .await
            .expect("open live subscription")
            .into_iter()
            .next()
            .expect("one live subscription");
        assert_eq!(connection.subscription_count().await, 1);

        connection.retire_subscription(&subscription_id).await;

        assert_eq!(
            connection.subscription_count().await,
            0,
            "a terminal peer CLOSED must not remain eligible for SDK replay"
        );

        connection.disconnect().await;
        relay.shutdown();
    }

    #[tokio::test]
    async fn notice_cooldown_rejects_queued_requests_before_sdk_send() {
        queued_cooldown_wire_regression(false).await;
    }

    #[tokio::test]
    async fn policy_cooldown_rejects_queued_requests_before_sdk_send() {
        queued_cooldown_wire_regression(true).await;
    }

    async fn queued_cooldown_wire_regression(policy: bool) {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        // Each request is polled into a known queue before a real wire refusal.
        // The processor queue stays full: only the control lane can pause it.
        for kind in [
            "historic",
            "historic-capacity",
            "fetch",
            "negentropy",
            "live",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let (notice_tx, notice_rx) = tokio::sync::oneshot::channel();
            let (request_tx, mut request_rx) = tokio::sync::mpsc::unbounded_channel();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                notice_rx.await.unwrap();
                let refusal = if policy {
                    serde_json::json!([
                        "CLOSED",
                        "refused-query",
                        "blocked: this is a private relay"
                    ])
                } else {
                    serde_json::json!(["NOTICE", "ERROR: too many concurrent REQs"])
                };
                for message in [serde_json::json!(["NOTICE", "queue blocker"]), refusal] {
                    ws.send(Message::Text(message.to_string().into()))
                        .await
                        .unwrap();
                }
                let mut requests = 0;
                while let Some(frame) = ws.next().await {
                    let frame = frame.unwrap();
                    if frame.is_close() {
                        break;
                    }
                    if !frame.is_text() {
                        continue;
                    }
                    let request: serde_json::Value =
                        serde_json::from_str(frame.to_text().unwrap()).unwrap();
                    if request[0] == "REQ" || request[0] == "NEG-OPEN" {
                        requests += 1;
                        request_tx.send(()).unwrap();
                    }
                }
                requests
            });
            let health = std::sync::Arc::new(RelayHealthTracker::with_defaults());
            let connection =
                permissive_connection(&url, Keys::generate()).with_health_tracker(health.clone());
            connection.connect(3).await.unwrap();
            let (event_tx, _event_rx) = tokio::sync::mpsc::channel(1);
            event_tx
                .send(RelayEvent::Notice("full queue".into()))
                .await
                .unwrap();
            let mut event_loop = Box::pin(connection.clone().run_event_loop(event_tx));
            assert!(futures_util::poll!(event_loop.as_mut()).is_pending());
            let event_loop = tokio::spawn(event_loop);

            let mut background_gate = Some(connection.background_query_pacer.gate.lock().await);
            let query_gate = if kind == "live" {
                Some(connection.query_start_pacer.gate.lock().await)
            } else {
                None
            };
            let slots = connection
                .subscription_usable_slots
                .load(std::sync::atomic::Ordering::Relaxed);
            let class_capacity = if kind == "historic-capacity" {
                Some(
                    connection
                        .transient_req_permits
                        .acquire_many(MAX_CONCURRENT_TRANSIENT_REQS as u32)
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            let capacity = if kind == "live" || kind == "historic-capacity" {
                None
            } else {
                Some(
                    connection
                        .acquire_subscription_slots(slots as u32)
                        .await
                        .unwrap(),
                )
            };
            if kind != "historic" {
                drop(background_gate.take());
            }
            let filter = Filter::new().kind(Kind::TextNote);
            let mut request: std::pin::Pin<
                Box<dyn Future<Output = Result<(), String>> + Send + '_>,
            > = match kind {
                "historic" | "historic-capacity" => Box::pin(async {
                    connection
                        .subscribe_filter(filter, TransientRequestClass::HistoricPage)
                        .await
                        .map(|_| ())
                }),
                "fetch" => Box::pin(async {
                    connection
                        .fetch_events(filter, Duration::from_secs(2))
                        .await
                        .map(|_| ())
                }),
                "negentropy" => {
                    Box::pin(async { connection.negentropy_sync_diff(filter).await.map(|_| ()) })
                }
                "live" => Box::pin(async {
                    connection
                        .subscribe_live_filter_groups(vec![vec![filter]])
                        .await
                        .map(|_| ())
                }),
                _ => unreachable!(),
            };
            assert!(
                futures_util::poll!(request.as_mut()).is_pending(),
                "{kind} must queue"
            );
            notice_tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while !health.is_subscription_paused(&connection.url) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("control lane must observe NOTICE behind blocked processor");
            assert!(
                connection.query_start_pacer.interval().is_none(),
                "concurrency refusal must not learn a query frequency"
            );
            drop(capacity);
            drop(class_capacity);
            drop(query_gate);
            drop(background_gate);
            let result = tokio::time::timeout(Duration::from_secs(3), request).await;
            let error = result
                .expect("queued work must unwind")
                .expect_err("cooldown must prevent send");
            assert!(error.contains("cooldown"), "{kind}: {error}");
            assert_eq!(
                connection
                    .nip77_transient_failures
                    .load(std::sync::atomic::Ordering::Relaxed),
                0,
                "refused admission is not a failed NIP-77 exchange"
            );
            assert!(connection
                .transient_req_permits_held
                .lock()
                .unwrap()
                .is_empty());
            assert_eq!(
                connection.transient_req_permits.available_permits(),
                MAX_CONCURRENT_TRANSIENT_REQS
            );
            assert_eq!(
                connection
                    .subscription_budget
                    .lock()
                    .unwrap()
                    .semaphore
                    .available_permits(),
                slots
            );

            assert!(
                request_rx.try_recv().is_err(),
                "no request sent during cooldown"
            );
            if policy {
                // Policy expiry itself is covered by the health tracker test.
                // Here the full wire exchange must contain no new request.
                connection.disconnect().await;
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(3), server)
                        .await
                        .unwrap()
                        .unwrap(),
                    0,
                    "policy-refused work must never reach the wire ({kind})"
                );
                event_loop.abort();
                continue;
            }
            health.clear_rate_limit(&connection.url);
            connection
                .subscribe_live_filter_groups(vec![vec![Filter::new().kind(Kind::TextNote)]])
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(3), request_rx.recv())
                .await
                .unwrap()
                .unwrap();
            connection.disconnect().await;
            let count = tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                count, 1,
                "only the post-cooldown request may reach the wire ({kind})"
            );
            event_loop.abort();
        }
    }

    #[tokio::test]
    async fn query_rate_closed_paces_later_wire_requests() {
        let relay = TestRelay::start(LocalRelayBuilder::default().queries_per_minute(1)).await;
        let connection = RelayConnection::new(
            relay.url().await.to_string(),
            Some(Keys::generate()),
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection
            .connect(3)
            .await
            .expect("connect query-limited relay");
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(RELAY_EVENT_BUFFER_CAPACITY);
        let event_loop = tokio::spawn(connection.clone().run_event_loop(event_tx));
        let drain = tokio::spawn(async move { while event_rx.recv().await.is_some() {} });

        let filter = Filter::new().kind(Kind::Custom(65_534));
        connection
            .subscribe_filter(filter.clone(), TransientRequestClass::HistoricPage)
            .await
            .expect("first query consumes the relay token");
        let _ = connection
            .subscribe_filter(filter.clone(), TransientRequestClass::HistoricPage)
            .await;

        tokio::time::timeout(Duration::from_secs(2), async {
            while connection.query_start_pacer.interval().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("rate-limited CLOSED should activate pacing");
        assert!(
            !connection.supports_negentropy().await,
            "query-limited sessions must avoid unpaced NEG-MSG traffic"
        );

        let error = connection
            .subscribe_filter(filter.clone(), TransientRequestClass::HistoricPage)
            .await
            .expect_err("work queued during cooldown must unwind");
        assert!(
            error.contains("rate-limit cooldown"),
            "unexpected deferred-query error: {error}"
        );

        connection.disconnect().await;
        relay.shutdown();
        event_loop.abort();
        drain.abort();
    }

    #[tokio::test]
    async fn fetch_events_reports_an_unregistered_exact_relay() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());

        let error = connection
            .fetch_events(
                Filter::new().kind(Kind::TextNote),
                Duration::from_millis(50),
            )
            .await
            .expect_err("an unregistered relay must fail explicitly");

        assert!(error.contains("relay is not registered"), "{error}");
        assert!(
            !error.contains("relay/s not specified"),
            "exact-relay fetch must not use an empty automatic target: {error}"
        );
    }

    #[test]
    fn test_normalize_url_with_wss_scheme() {
        let url = "wss://relay.example.com";
        assert_eq!(
            RelayConnection::normalize_url(url),
            "wss://relay.example.com"
        );
    }

    #[test]
    fn test_normalize_url_with_ws_scheme() {
        let url = "ws://relay.example.com";
        assert_eq!(
            RelayConnection::normalize_url(url),
            "ws://relay.example.com"
        );
    }

    #[test]
    fn test_normalize_url_without_scheme() {
        let url = "relay.example.com";
        assert_eq!(
            RelayConnection::normalize_url(url),
            "wss://relay.example.com"
        );
    }

    #[test]
    fn test_normalize_url_without_scheme_with_port() {
        let url = "relay.example.com:8080";
        assert_eq!(
            RelayConnection::normalize_url(url),
            "wss://relay.example.com:8080"
        );
    }

    #[test]
    fn test_normalize_url_with_path() {
        let url = "relay.example.com/nostr";
        assert_eq!(
            RelayConnection::normalize_url(url),
            "wss://relay.example.com/nostr"
        );
    }

    #[test]
    fn test_new_normalizes_url() {
        let conn = permissive_connection("relay.example.com", Keys::generate());
        assert_eq!(conn.url(), "wss://relay.example.com");
    }

    #[test]
    fn test_new_preserves_wss_scheme() {
        let conn = permissive_connection("wss://relay.example.com", Keys::generate());
        assert_eq!(conn.url(), "wss://relay.example.com");
    }

    #[test]
    fn test_new_preserves_ws_scheme() {
        let conn = permissive_connection("ws://relay.example.com", Keys::generate());
        assert_eq!(conn.url(), "ws://relay.example.com");
    }

    #[test]
    fn test_new_with_database_normalizes_url() {
        // This test just verifies the URL normalization works
        // We can't easily test with_database without a real database
        let conn = permissive_connection("git.shakespeare.diy", Keys::generate());
        assert_eq!(conn.url(), "wss://git.shakespeare.diy");
    }

    #[test]
    fn filter_count_learning_halves_and_resets_per_session() {
        let connection = permissive_connection("wss://strict.example", Keys::generate());

        assert_eq!(
            connection.max_filters_per_req(),
            super::super::MAX_FILTERS_PER_REQ
        );
        assert_eq!(connection.reduce_max_filters_per_req(8), Some(4));
        assert_eq!(connection.reduce_max_filters_per_req(4), Some(2));
        assert_eq!(connection.reduce_max_filters_per_req(2), Some(1));
        assert_eq!(connection.reduce_max_filters_per_req(1), None);
        assert_eq!(connection.reduce_max_filters_per_req(8), None);

        connection.reset_subscription_budget(None);
        assert_eq!(
            connection.max_filters_per_req(),
            super::super::MAX_FILTERS_PER_REQ
        );
    }

    #[tokio::test]
    async fn event_directed_connect_rejects_loopback_before_dialling() {
        let connection = RelayConnection::new(
            "ws://127.0.0.1:1".to_string(),
            Some(Keys::generate()),
            RelayTargetSource::EventDirected,
            OutboundTargetPolicy::default(),
        );

        let error = connection
            .connect(3)
            .await
            .expect_err("strict policy must reject an event-directed loopback dial");
        assert!(error.contains("Outbound target policy"), "{error}");
    }

    #[tokio::test]
    async fn purgatory_dependency_fetch_queues_behind_transient_req_permits() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        let occupied = connection
            .transient_req_permits
            .clone()
            .acquire_many_owned(MAX_CONCURRENT_TRANSIENT_REQS as u32)
            .await
            .expect("reserve every transient permit");

        let blocked = tokio::time::timeout(
            Duration::from_millis(50),
            connection.fetch_events(
                Filter::new().id(EventId::from_byte_array([0; 32])),
                Duration::from_secs(1),
            ),
        )
        .await;
        assert!(
            blocked.is_err(),
            "dependency fetch bypassed the transient permit queue"
        );

        drop(occupied);
        let error = connection
            .fetch_events(
                Filter::new().id(EventId::from_byte_array([0; 32])),
                Duration::from_secs(1),
            )
            .await
            .expect_err("unconnected fixture should fail after acquiring a permit");
        assert!(error.contains("relay is not registered"), "{error}");
    }

    #[test]
    fn subscription_ledger_uses_fallback_and_advertised_budgets() {
        assert_eq!(effective_subscription_budget(None), 20);
        assert_eq!(usable_subscription_slots(None), 18);

        // nostream advertises ten subscriptions per connection: advertised
        // limits override the fallback floor rather than being rounded up.
        assert_eq!(effective_subscription_budget(Some(10)), 10);
        assert_eq!(usable_subscription_slots(Some(10)), 8);
        assert_eq!(historic_slot_allowance(Some(10), 3), 4);
    }

    #[test]
    fn live_wants_everything_preserves_margin_and_defers_history() {
        assert_eq!(historic_slot_allowance(Some(10), 7), 1);
        assert_eq!(historic_slot_allowance(Some(10), 8), 0);
        assert_eq!(historic_slot_allowance(Some(10), 9), 0);
    }

    #[tokio::test]
    async fn live_set_is_rejected_atomically_when_it_wants_every_slot() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));
        let groups = (0..9)
            .map(|kind| vec![Filter::new().kind(Kind::Custom(20_000 + kind))])
            .collect();

        let error = connection
            .subscribe_live_filter_groups(groups)
            .await
            .expect_err("nine live groups must not consume an eight-slot usable budget");
        assert!(error.contains("exceeds budget"), "{error}");
        assert_eq!(connection.subscription_budget().available_permits(), 8);
    }

    #[tokio::test]
    async fn peer_subscription_identity_is_bounded_by_owned_ledger_permits() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));
        let owned = SubscriptionId::new("owned-live");
        let forged = SubscriptionId::new("peer-forged");
        let permit = connection.acquire_subscription_slots(1).await.unwrap();
        connection.live_req_permits_held.lock().unwrap().insert(
            owned.clone(),
            HeldLiveSubscription {
                generation: permit.generation,
                _ledger_slot: permit.permit,
                filters: vec![Filter::new().kind(Kind::TextNote)],
            },
        );

        assert!(connection.holds_subscription_permit(&owned));
        assert!(
            !connection.holds_subscription_permit(&forged),
            "a peer-selected CLOSED id must not become application-owned state"
        );
    }

    #[tokio::test]
    async fn auxiliary_live_admission_preserves_one_historic_slot() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));

        for index in 0..6 {
            let permit = connection.acquire_subscription_slots(1).await.unwrap();
            connection.live_req_permits_held.lock().unwrap().insert(
                SubscriptionId::new(format!("core-{index}")),
                HeldLiveSubscription {
                    generation: permit.generation,
                    _ledger_slot: permit.permit,
                    filters: vec![Filter::new().kind(Kind::Custom(20_100 + index))],
                },
            );
        }

        let one_group = vec![vec![Filter::new().kind(Kind::Custom(20_200))]];
        assert!(connection.can_admit_auxiliary_live_groups(&one_group));

        let two_groups = vec![
            vec![Filter::new().kind(Kind::Custom(20_201))],
            vec![Filter::new().kind(Kind::Custom(20_202))],
        ];
        assert!(
            !connection.can_admit_auxiliary_live_groups(&two_groups),
            "two auxiliary groups would consume the final historic slot"
        );
    }

    #[tokio::test]
    async fn failed_live_group_rolls_back_opened_groups_and_full_capacity() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let held = std::sync::Arc::clone(&connection.live_req_permits_held);
        let groups = (0..3)
            .map(|kind| vec![Filter::new().kind(Kind::Custom(21_000 + kind))])
            .collect();

        let error = connection
            .subscribe_live_filter_groups_with(groups, move |_filters, permit| {
                let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let held = std::sync::Arc::clone(&held);
                async move {
                    if attempt == 2 {
                        return Err("controlled third-group failure".to_string());
                    }
                    let sub_id = SubscriptionId::new(format!("opened-{attempt}"));
                    held.lock().expect("live permit map poisoned").insert(
                        sub_id.clone(),
                        HeldLiveSubscription {
                            generation: permit.generation,
                            _ledger_slot: permit.permit,
                            filters: _filters,
                        },
                    );
                    Ok(sub_id)
                }
            })
            .await
            .expect_err("the controlled third group must fail");

        assert_eq!(error, "controlled third-group failure");
        assert!(
            connection
                .live_req_permits_held
                .lock()
                .expect("live permit map poisoned")
                .is_empty(),
            "earlier successful live groups must be removed during rollback"
        );
        assert_eq!(connection.subscription_budget().available_permits(), 8);
    }

    #[tokio::test]
    async fn failed_live_replacement_restores_exact_previous_filter_groups() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));
        let old_filters = vec![Filter::new().kind(Kind::Custom(21_500))];
        let old_permit = connection.acquire_subscription_slots(1).await.unwrap();
        connection.live_req_permits_held.lock().unwrap().insert(
            SubscriptionId::new("old-live"),
            HeldLiveSubscription {
                generation: old_permit.generation,
                _ledger_slot: old_permit.permit,
                filters: old_filters.clone(),
            },
        );
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let held = std::sync::Arc::clone(&connection.live_req_permits_held);
        let target = (0..3)
            .map(|kind| vec![Filter::new().kind(Kind::Custom(21_600 + kind))])
            .collect();

        let error = connection
            .replace_live_filter_groups_with(target, move |filters, permit| {
                let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let held = std::sync::Arc::clone(&held);
                async move {
                    if attempt == 2 {
                        return Err("controlled third-group failure".to_string());
                    }
                    let sub_id = SubscriptionId::new(format!("replacement-{attempt}"));
                    held.lock().unwrap().insert(
                        sub_id.clone(),
                        HeldLiveSubscription {
                            generation: permit.generation,
                            _ledger_slot: permit.permit,
                            filters,
                        },
                    );
                    Ok(sub_id)
                }
            })
            .await
            .expect_err("replacement must report its controlled failure");

        assert!(error.contains("previous coverage restored"), "{error}");
        assert_eq!(connection.live_filter_groups(), vec![old_filters]);
        assert_eq!(connection.subscription_budget().available_permits(), 7);
    }

    #[test]
    fn repeated_core_filters_do_not_rely_on_auxiliary_or_different_history_bounds() {
        let filter = Filter::new().kind(Kind::GitIssue).limit(0);
        let auxiliary_id = SubscriptionId::new("auxiliary");
        let later = filter.clone().since(Timestamp::from(100));
        let plan = plan_live_tail_extension(
            vec![
                (auxiliary_id.clone(), vec![filter.clone()]),
                (SubscriptionId::new("later-core"), vec![later]),
            ],
            &std::collections::HashSet::from([auxiliary_id]),
            vec![vec![filter.clone(), filter.clone()]],
            1,
        );
        assert_eq!(plan.replacement_groups, vec![vec![filter]]);
        assert!(plan.retired.is_empty());
    }

    #[tokio::test]
    async fn historic_retries_do_not_duplicate_live_subscriptions_within_tight_budget() {
        let relay = TestRelay::start(LocalRelayBuilder::default()).await;
        let connection = permissive_connection(&relay.url().await.to_string(), Keys::generate());
        connection.connect(3).await.unwrap();
        connection.reset_subscription_budget(Some(20));
        connection.reduce_max_filters_per_req(6); // Three filters per REQ.
        let filters: Vec<_> = (0..9)
            .map(|n| Filter::new().kind(Kind::Custom(24_000 + n)).limit(0))
            .collect();
        let groups = super::super::live_filter_groups(&filters, connection.max_filters_per_req());
        let ids = connection
            .extend_live_filter_groups_minimally(groups.clone(), &[])
            .await
            .unwrap();
        assert_eq!(ids.len(), 3);
        for _ in 0..12 {
            assert!(
                connection
                    .extend_live_filter_groups_minimally(groups.clone(), &[])
                    .await
                    .unwrap()
                    .is_empty(),
                "historic retry must not open another live REQ"
            );
        }
        assert_eq!(connection.subscription_count().await, 3);
        assert_eq!(connection.subscription_budget().available_permits(), 15);
        for id in &ids {
            assert!(connection.holds_subscription_permit(id));
        }
        // Deduplication must use currently held coverage, not a remembered
        // request: closed filters need to be admitted again.
        connection
            .close_live_subscriptions(&ids[..1])
            .await
            .unwrap();
        let repaired = connection
            .extend_live_filter_groups_minimally(groups, &[])
            .await
            .unwrap();
        assert_eq!(repaired.len(), 1);
        assert_eq!(connection.subscription_count().await, 3);
        assert_eq!(connection.subscription_budget().available_permits(), 15);
        connection.disconnect().await;
        relay.shutdown();
    }

    #[test]
    fn minimum_churn_extension_preserves_full_and_auxiliary_groups() {
        let full_id = SubscriptionId::new("full-core");
        let tail_id = SubscriptionId::new("partial-core");
        let auxiliary_id = SubscriptionId::new("descendants");
        let full = vec![
            Filter::new().kind(Kind::Custom(23_000)),
            Filter::new().kind(Kind::Custom(23_001)),
            Filter::new().kind(Kind::Custom(23_002)),
        ];
        let tail = vec![Filter::new().kind(Kind::Custom(23_100))];
        let auxiliary = vec![Filter::new().kind(Kind::Custom(23_200))];
        let new = vec![vec![
            Filter::new().kind(Kind::Custom(23_300)),
            Filter::new().kind(Kind::Custom(23_301)),
        ]];
        let protected = std::collections::HashSet::from([auxiliary_id.clone()]);

        let plan = plan_live_tail_extension(
            vec![
                (full_id, full),
                (tail_id.clone(), tail),
                (auxiliary_id, auxiliary),
            ],
            &protected,
            new,
            3,
        );

        assert_eq!(plan.retired.len(), 1);
        assert_eq!(plan.retired[0].0, tail_id);
        assert_eq!(plan.replacement_groups.len(), 1);
        assert_eq!(plan.replacement_groups[0].len(), 3);
    }

    #[test]
    fn minimum_churn_extension_preserves_a_byte_full_partial_group() {
        let byte_full_id = SubscriptionId::new("byte-full-core");
        let large_value = "x".repeat(crate::sync::REQ_MESSAGE_BYTE_BUDGET);
        let byte_full = vec![Filter::new().custom_tag(SingleLetterTag::LOWERCASE_A, large_value)];
        let new_filter = Filter::new().kind(Kind::Custom(23_400));

        let plan = plan_live_tail_extension(
            vec![(byte_full_id.clone(), byte_full.clone())],
            &std::collections::HashSet::new(),
            vec![vec![new_filter.clone()]],
            10,
        );

        assert!(plan.retired.is_empty());
        assert_eq!(plan.replacement_groups, vec![vec![new_filter]]);
    }

    #[test]
    fn minimum_churn_extension_rebuilds_every_partial_tail_and_releases_slots() {
        let tails: Vec<_> = (0..13)
            .map(|index| {
                (
                    SubscriptionId::new(format!("tail-{index}")),
                    vec![Filter::new().kind(Kind::Custom(23_450 + index))],
                )
            })
            .collect();

        let plan = plan_live_tail_extension(
            tails,
            &std::collections::HashSet::new(),
            vec![vec![Filter::new().kind(Kind::Custom(23_499))]],
            10,
        );

        assert_eq!(plan.retired.len(), 13);
        assert_eq!(plan.replacement_groups.len(), 2);
        assert_eq!(
            plan.replacement_groups.iter().map(Vec::len).sum::<usize>(),
            14
        );
        assert_eq!(plan.retired.len() - plan.replacement_groups.len(), 11);
    }

    #[test]
    fn minimum_churn_extension_retires_one_byte_bound_group_to_avoid_a_new_slot() {
        let tails: Vec<_> = (0..17)
            .map(|index| {
                (
                    SubscriptionId::new(format!("byte-tail-{index}")),
                    vec![Filter::new().custom_tag(
                        SingleLetterTag::LOWERCASE_A,
                        format!("{index:02}{}", "x".repeat(60_000)),
                    )],
                )
            })
            .collect();
        let new_filter = Filter::new().custom_tag(
            SingleLetterTag::LOWERCASE_A,
            format!("00{}", "y".repeat(1_000)),
        );

        let plan = plan_live_tail_extension(
            tails,
            &std::collections::HashSet::new(),
            vec![vec![new_filter]],
            10,
        );

        assert_eq!(plan.retired.len(), 1);
        assert_eq!(plan.replacement_groups.len(), 1);
    }

    #[tokio::test]
    async fn minimum_churn_extension_keeps_full_and_auxiliary_subscriptions_open() {
        let relay = TestRelay::start(LocalRelayBuilder::default()).await;
        let connection = RelayConnection::new(
            relay.url().await.to_string(),
            Some(Keys::generate()),
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection.connect(3).await.expect("connect local relay");

        let full: Vec<_> = (0..connection.max_filters_per_req())
            .map(|index| Filter::new().kind(Kind::Custom(23_500 + index as u16)))
            .collect();
        let partial = vec![Filter::new().kind(Kind::Custom(23_600))];
        let core_ids = connection
            .subscribe_live_filter_groups(vec![full, partial])
            .await
            .expect("open initial core groups");
        let auxiliary_ids = connection
            .subscribe_auxiliary_live_filter_groups(vec![vec![
                Filter::new().kind(Kind::Custom(23_700))
            ]])
            .await
            .expect("open auxiliary group");

        let replacement_ids = connection
            .extend_live_filter_groups_minimally(
                vec![vec![
                    Filter::new().kind(Kind::Custom(23_800)),
                    Filter::new().kind(Kind::Custom(23_801)),
                ]],
                &auxiliary_ids,
            )
            .await
            .expect("extend only the mutable core tail");

        {
            let held = connection
                .live_req_permits_held
                .lock()
                .expect("live permit map poisoned");
            assert!(
                held.contains_key(&core_ids[0]),
                "full core group was replaced"
            );
            assert!(
                !held.contains_key(&core_ids[1]),
                "partial core tail was not replaced"
            );
            assert!(
                held.contains_key(&auxiliary_ids[0]),
                "auxiliary group was replaced"
            );
            assert_eq!(replacement_ids.len(), 1);
            assert_eq!(held[&replacement_ids[0]].filters.len(), 3);
        }

        connection.disconnect().await;
        relay.shutdown();
    }

    #[tokio::test]
    async fn failed_minimum_churn_extension_restores_only_the_retired_tail() {
        let relay = TestRelay::start(LocalRelayBuilder::default()).await;
        let connection = RelayConnection::new(
            relay.url().await.to_string(),
            Some(Keys::generate()),
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection.connect(3).await.expect("connect local relay");

        let full: Vec<_> = (0..connection.max_filters_per_req())
            .map(|index| Filter::new().kind(Kind::Custom(24_000 + index as u16)))
            .collect();
        let tail = vec![Filter::new().kind(Kind::Custom(24_100))];
        let core_ids = connection
            .subscribe_live_filter_groups(vec![full, tail.clone()])
            .await
            .expect("open initial core groups");
        let auxiliary_ids = connection
            .subscribe_auxiliary_live_filter_groups(vec![vec![
                Filter::new().kind(Kind::Custom(24_200))
            ]])
            .await
            .expect("open auxiliary group");

        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let held = std::sync::Arc::clone(&connection.live_req_permits_held);
        let error = connection
            .extend_live_filter_groups_minimally_with(
                vec![vec![Filter::new().kind(Kind::Custom(24_300))]],
                &auxiliary_ids,
                |subscription_id| {
                    let client = connection.client.clone();
                    async move {
                        client
                            .unsubscribe(&subscription_id)
                            .await
                            .map(|_| ())
                            .map_err(|error| error.to_string())
                    }
                },
                move |filters, permit| {
                    let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let held = std::sync::Arc::clone(&held);
                    async move {
                        if attempt == 0 {
                            return Err("controlled tail replacement failure".to_string());
                        }
                        let sub_id = SubscriptionId::new(format!("restored-tail-{attempt}"));
                        held.lock().expect("live permit map poisoned").insert(
                            sub_id.clone(),
                            HeldLiveSubscription {
                                generation: permit.generation,
                                _ledger_slot: permit.permit,
                                filters,
                            },
                        );
                        Ok(sub_id)
                    }
                },
            )
            .await
            .expect_err("controlled replacement must fail");

        assert!(error.contains("prior tail restored"), "{error}");
        {
            let held = connection
                .live_req_permits_held
                .lock()
                .expect("live permit map poisoned");
            assert!(
                held.contains_key(&core_ids[0]),
                "full core group was churned"
            );
            assert!(
                held.contains_key(&auxiliary_ids[0]),
                "auxiliary group was churned"
            );
            assert!(
                held.values()
                    .any(|subscription| subscription.filters == tail),
                "the exact retired tail was not restored"
            );
            assert_eq!(held.len(), 3);
        }

        connection.disconnect().await;
        relay.shutdown();
    }

    #[tokio::test]
    async fn partial_close_failure_restores_the_already_closed_tail_group() {
        let relay = TestRelay::start(LocalRelayBuilder::default()).await;
        let connection = RelayConnection::new(
            relay.url().await.to_string(),
            Some(Keys::generate()),
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        );
        connection.connect(3).await.expect("connect local relay");

        let first_tail = vec![Filter::new().custom_tag(
            SingleLetterTag::LOWERCASE_A,
            format!("a{}", "x".repeat(30_000)),
        )];
        let second_tail = vec![Filter::new().custom_tag(
            SingleLetterTag::LOWERCASE_A,
            format!("c{}", "x".repeat(30_000)),
        )];
        connection
            .subscribe_live_filter_groups(vec![first_tail.clone(), second_tail.clone()])
            .await
            .expect("open two partial core groups");

        let close_attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let close_client = connection.client.clone();
        let close_attempts_for_call = std::sync::Arc::clone(&close_attempts);
        let error = connection
            .extend_live_filter_groups_minimally_with(
                vec![vec![
                    Filter::new().custom_tag(
                        SingleLetterTag::LOWERCASE_A,
                        format!("b{}", "x".repeat(60_000)),
                    ),
                    Filter::new().custom_tag(
                        SingleLetterTag::LOWERCASE_A,
                        format!("d{}", "x".repeat(60_000)),
                    ),
                ]],
                &[],
                move |subscription_id| {
                    let attempt =
                        close_attempts_for_call.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let client = close_client.clone();
                    async move {
                        if attempt == 1 {
                            return Err("controlled second CLOSE failure".to_string());
                        }
                        client
                            .unsubscribe(&subscription_id)
                            .await
                            .map(|_| ())
                            .map_err(|error| error.to_string())
                    }
                },
                |filters, permit| {
                    connection.subscribe_filters_with_live_permit(filters, None, Some(permit), None)
                },
            )
            .await
            .expect_err("the controlled second CLOSE must fail");

        assert!(error.contains("prior tail restored"), "{error}");
        let held = connection.live_filter_groups();
        assert!(held.contains(&first_tail));
        assert!(held.contains(&second_tail));
        assert_eq!(held.len(), 2);
        assert_eq!(close_attempts.load(std::sync::atomic::Ordering::Relaxed), 2);

        connection.disconnect().await;
        relay.shutdown();
    }

    #[tokio::test]
    async fn complete_live_set_can_fill_usable_budget_but_history_defers() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));
        let held = std::sync::Arc::clone(&connection.live_req_permits_held);
        let groups = (0..8)
            .map(|kind| vec![Filter::new().kind(Kind::Custom(22_000 + kind))])
            .collect();

        let ids = connection
            .subscribe_live_filter_groups_with(groups, move |_filters, permit| {
                let held = std::sync::Arc::clone(&held);
                async move {
                    let sub_id = SubscriptionId::generate();
                    held.lock().expect("live permit map poisoned").insert(
                        sub_id.clone(),
                        HeldLiveSubscription {
                            generation: permit.generation,
                            _ledger_slot: permit.permit,
                            filters: _filters,
                        },
                    );
                    Ok(sub_id)
                }
            })
            .await
            .expect("exactly eight complete live groups fit the usable budget");

        assert_eq!(ids.len(), 8);
        assert_eq!(connection.subscription_budget().available_permits(), 0);
        let error = connection
            .subscribe_filter(
                Filter::new().kind(Kind::TextNote),
                TransientRequestClass::HistoricPage,
            )
            .await
            .expect_err("history must defer when complete live coverage fills usable capacity");
        assert!(
            error.contains("No historic subscription capacity"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn closed_live_subscription_restores_re_admittable_capacity() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));
        let sub_id = SubscriptionId::new("relay-closed-live");
        let permit = connection
            .subscription_budget()
            .acquire_owned()
            .await
            .expect("reserve live ledger slot");
        connection
            .live_req_permits_held
            .lock()
            .expect("live permit map poisoned")
            .insert(
                sub_id.clone(),
                HeldLiveSubscription {
                    generation: connection.current_subscription_generation(),
                    _ledger_slot: permit,
                    filters: vec![Filter::new().kind(Kind::TextNote)],
                },
            );
        assert_eq!(connection.subscription_budget().available_permits(), 7);

        assert_eq!(
            connection.release_subscription_permits_on_closed(&sub_id),
            Some(connection.current_subscription_generation()),
            "CLOSED must identify the live session for manager recovery"
        );

        assert_eq!(connection.subscription_budget().available_permits(), 8);
        let full_capacity = connection
            .subscription_budget()
            .try_acquire_many_owned(8)
            .expect("CLOSED must make the complete live budget re-admittable");
        drop(full_capacity);
    }

    #[tokio::test]
    async fn watchdog_retires_sdk_subscription_and_reports_failed_terminal() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (wire_tx, mut wire_rx) = mpsc::channel(16);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            while let Some(Ok(frame)) = ws.next().await {
                match frame {
                    Message::Text(text) => {
                        let _ = wire_tx.send(text.to_string()).await;
                    }
                    Message::Ping(bytes) => {
                        let _ = ws.send(Message::Pong(bytes)).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });
        let connection = permissive_connection(&url, Keys::generate());
        connection.connect(3).await.unwrap();
        let (tx, mut rx) = super::super::lifecycle_notification_channel();
        connection.set_timeout_sender(tx);
        let id = connection
            .subscribe_filter(
                Filter::new().kind(Kind::GitIssue),
                TransientRequestClass::HistoricPage,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !wire_rx.recv().await.unwrap().contains("REQ") {}
        })
        .await
        .unwrap();
        let generation = connection.current_subscription_generation();
        connection
            .expire_transient_request(id.clone(), generation.wrapping_add(1))
            .await;
        assert!(
            rx.try_recv().is_err(),
            "a stale timer must not close a current request"
        );
        assert!(connection.holds_subscription_permit(&id));
        let relay = connection.client.relay(&url).await.unwrap().unwrap();
        assert!(relay.subscription(&id).await.is_some());

        // Time itself is the behavior under test; no two-minute wall-clock wait.
        tokio::time::pause();
        tokio::time::advance(TRANSIENT_REQ_PERMIT_TIMEOUT + Duration::from_secs(1)).await;
        let notification = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(notification.timed_out);
        assert_eq!(notification.subscription_id, id);
        assert_eq!(notification.generation, Some(generation));
        assert!(!connection.holds_subscription_permit(&id));
        assert!(connection.health_tracker.is_subscription_paused(&url));
        assert!(connection
            .subscribe_filter(
                Filter::new().kind(Kind::GitIssue),
                TransientRequestClass::HistoricPage,
            )
            .await
            .unwrap_err()
            .contains("cooldown"));
        tokio::time::timeout(Duration::from_secs(3), async {
            while relay.subscription(&id).await.is_some() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("SDK auto-close timeout must remove the subscription registry entry");
        connection.expire_transient_request(id, generation).await;
        assert!(rx.try_recv().is_err(), "retirement must be idempotent");
        tokio::time::resume();
        connection.disconnect().await;
        server.abort();
    }

    #[tokio::test]
    async fn watchdog_release_is_scoped_to_the_subscription_generation() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));
        let sub_id = SubscriptionId::new("watchdog-retains-slot");
        let generation = connection.current_subscription_generation();
        let held = HeldTransientPermits {
            generation,
            request_class: TransientRequestClass::HistoricPage,
            opened_at: std::time::Instant::now(),
            last_event_at: None,
            delivered_events: 0,
            _byte_limit_gate: None,
            _class_cap: connection
                .transient_req_permits
                .clone()
                .acquire_owned()
                .await
                .expect("reserve transient class slot"),
            _ledger_slot: connection
                .subscription_budget()
                .acquire_owned()
                .await
                .expect("reserve ledger slot"),
        };
        connection.hold_transient_req_permit(sub_id.clone(), held);
        connection.record_transient_req_event(&sub_id);

        {
            let permits = connection
                .transient_req_permits_held
                .lock()
                .expect("transient permit map poisoned");
            let diagnostic = permits.get(&sub_id).expect("held subscription diagnostic");
            assert_eq!(diagnostic.delivered_events, 1);
            assert!(diagnostic.last_event_at.is_some());
        }

        assert!(
            !RelayConnection::release_transient_req_permit_for_generation(
                &connection.transient_req_permits_held,
                &sub_id,
                generation.wrapping_add(1),
                || panic!("stale timer must not apply a cooldown"),
            ),
            "a stale watchdog must not release a newer session's slot"
        );
        assert!(
            RelayConnection::release_transient_req_permit_for_generation(
                &connection.transient_req_permits_held,
                &sub_id,
                generation,
                || {},
            ),
            "the matching watchdog must release its closed subscription"
        );
        assert_eq!(connection.transient_req_permits.available_permits(), 5);
        assert_eq!(connection.subscription_budget().available_permits(), 8);
    }

    #[test]
    fn watchdog_deadline_allows_slow_valid_startup_pages() {
        assert_eq!(TRANSIENT_REQ_PERMIT_TIMEOUT, Duration::from_secs(120));
    }

    #[tokio::test]
    async fn queued_consumer_cannot_send_after_session_reset() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));
        let old = connection
            .acquire_subscription_slots(8)
            .await
            .expect("occupy old session");
        let sends = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waiter_connection = connection.clone();
        let waiter_sends = std::sync::Arc::clone(&sends);
        let waiter = tokio::spawn(async move {
            let permit = waiter_connection.acquire_subscription_slots(1).await?;
            waiter_connection.ensure_current_session(&permit)?;
            waiter_sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok::<_, String>(())
        });
        tokio::task::yield_now().await;

        connection.reset_subscription_budget(Some(10));
        drop(old);
        let error = waiter
            .await
            .expect("waiter task")
            .expect_err("retired-session waiter must fail");
        assert!(error.contains("session retired"), "{error}");
        assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(connection.subscription_budget().available_permits(), 8);
    }

    #[tokio::test]
    async fn transient_admission_never_waits_while_pinning_the_other_budget() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));

        let all_class = connection
            .transient_req_permits
            .clone()
            .acquire_many_owned(MAX_CONCURRENT_TRANSIENT_REQS as u32)
            .await
            .expect("occupy transient class cap");
        let class_waiter_connection = connection.clone();
        let mut class_waiter = tokio::spawn(async move {
            class_waiter_connection
                .acquire_transient_permits(TransientRequestClass::HistoricPage)
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut class_waiter)
                .await
                .is_err(),
            "consumer must remain queued while the class cap is occupied"
        );
        assert_eq!(
            connection.subscription_budget().available_permits(),
            8,
            "waiting for the class cap must return its speculative ledger slot"
        );
        drop(all_class);
        drop(class_waiter.await.expect("class waiter task").unwrap());

        let all_ledger = connection
            .subscription_budget()
            .acquire_many_owned(8)
            .await
            .expect("occupy subscription ledger");
        let ledger_waiter_connection = connection.clone();
        let mut ledger_waiter = tokio::spawn(async move {
            ledger_waiter_connection
                .acquire_transient_permits(TransientRequestClass::HistoricPage)
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut ledger_waiter)
                .await
                .is_err(),
            "consumer must remain queued while the ledger is occupied"
        );
        assert_eq!(
            connection.transient_req_permits.available_permits(),
            MAX_CONCURRENT_TRANSIENT_REQS,
            "waiting for the ledger must not pin the class cap"
        );
        drop(all_ledger);
        drop(ledger_waiter.await.expect("ledger waiter task").unwrap());

        assert_eq!(connection.subscription_budget().available_permits(), 8);
        assert_eq!(
            connection.transient_req_permits.available_permits(),
            MAX_CONCURRENT_TRANSIENT_REQS
        );
    }

    #[tokio::test]
    async fn learned_byte_limit_serializes_transient_occupancy() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection
            .remote_subscription_byte_limit
            .store(1_048_576, std::sync::atomic::Ordering::Relaxed);
        let first = connection
            .acquire_transient_permits(TransientRequestClass::HistoricPage)
            .await
            .expect("first byte-limited transient");
        let waiter_connection = connection.clone();
        let mut waiter = tokio::spawn(async move {
            waiter_connection
                .acquire_transient_permits(TransientRequestClass::HistoricPage)
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut waiter)
                .await
                .is_err(),
            "a second transient must wait while the byte margin is occupied"
        );
        drop(first);
        drop(waiter.await.expect("transient waiter task").unwrap());
    }

    #[tokio::test]
    async fn session_reset_cannot_be_inflated_by_an_old_borrower() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        let old_ledger = connection.subscription_budget();
        let old_borrow = old_ledger
            .clone()
            .acquire_owned()
            .await
            .expect("borrow from old session");

        connection.reset_subscription_budget(Some(10));
        let new_ledger = connection.subscription_budget();
        assert!(!std::sync::Arc::ptr_eq(&old_ledger, &new_ledger));
        assert_eq!(new_ledger.available_permits(), 8);

        drop(old_borrow);
        assert_eq!(
            new_ledger.available_permits(),
            8,
            "a borrower returning to the retired session must not inflate the new ledger"
        );
    }

    #[tokio::test]
    async fn live_neg_req_and_dependency_consumers_share_one_ledger() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(10));
        let ledger = connection.subscription_budget();

        let live = ledger
            .clone()
            .acquire_many_owned(3)
            .await
            .expect("reserve live groups");
        let neg_class = connection
            .neg_diff_permits
            .acquire()
            .await
            .expect("reserve NEG class slot");
        let neg = ledger
            .clone()
            .acquire_owned()
            .await
            .expect("reserve NEG ledger slot");
        let req_class = connection
            .transient_req_permits
            .acquire()
            .await
            .expect("reserve historic REQ class slot");
        let req = ledger
            .clone()
            .acquire_owned()
            .await
            .expect("reserve historic REQ ledger slot");
        let dependency_class = connection
            .transient_req_permits
            .acquire()
            .await
            .expect("reserve dependency REQ class slot");
        let dependency = ledger
            .clone()
            .acquire_owned()
            .await
            .expect("reserve dependency ledger slot");

        assert_eq!(ledger.available_permits(), 2);
        let remainder = ledger
            .clone()
            .try_acquire_many_owned(2)
            .expect("only the two remaining usable slots may be reserved");
        assert!(
            ledger.clone().try_acquire_owned().is_err(),
            "combined consumers must not overdraw the per-session ledger"
        );

        drop((
            remainder,
            dependency,
            dependency_class,
            req,
            req_class,
            neg,
            neg_class,
            live,
        ));
        assert_eq!(ledger.available_permits(), 8);
    }

    #[tokio::test]
    async fn purgatory_dependency_fetch_draws_from_shared_ledger() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        connection.reset_subscription_budget(Some(SUBSCRIPTION_RESERVED_MARGIN));

        let error = connection
            .fetch_events(
                Filter::new().id(EventId::from_byte_array([0; 32])),
                Duration::from_secs(1),
            )
            .await
            .expect_err("dependency polling must defer when the ledger has no usable slot");
        assert!(
            error.contains("No transient query capacity"),
            "unexpected dependency ledger error: {error}"
        );
    }

    #[tokio::test]
    async fn immediate_transient_capacity_rejects_a_saturated_session() {
        let relay = TestRelay::start(LocalRelayBuilder::default()).await;
        let relay_url = relay.url().await.to_string();
        let connection = permissive_connection(&relay_url, Keys::generate());
        connection.connect(3).await.expect("connect local relay");
        connection.reset_subscription_budget(Some(3));

        assert!(connection.has_immediate_transient_capacity().await);
        let ledger = connection.subscription_budget();
        let _all_slots = ledger
            .clone()
            .acquire_many_owned(ledger.available_permits() as u32)
            .await
            .expect("saturate subscription ledger");

        assert!(!connection.has_immediate_transient_capacity().await);
        assert_eq!(connection.transient_req_permits.available_permits(), 5);

        connection.disconnect().await;
        relay.shutdown();
    }

    #[test]
    fn transient_request_metric_labels_are_bounded_and_unique() {
        let labels = TRANSIENT_REQUEST_CLASSES.map(TransientRequestClass::as_str);
        let unique = labels.into_iter().collect::<std::collections::HashSet<_>>();

        assert_eq!(unique.len(), TRANSIENT_REQUEST_CLASSES.len());
        assert_eq!(
            unique,
            std::collections::HashSet::from([
                "historic_page",
                "pagination_page",
                "pagination_verification",
                "negentropy_hydration",
                "negentropy_retry",
                "negentropy_fallback",
            ])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn query_pacer_activates_only_after_query_rate_limit() {
        let pacer = std::sync::Arc::new(QueryStartPacer::default());
        pacer
            .wait_for_start()
            .await
            .expect("inactive pacer should admit immediately");
        assert_eq!(pacer.interval(), None);

        let (interval, new_episode) = pacer.record_rate_limit();
        assert!(new_episode);
        assert_eq!(interval, QUERY_PACING_INITIAL_INTERVAL);
        assert!(pacer.wait_for_start().await.is_err());
        tokio::time::advance(Duration::from_secs(RATE_LIMIT_COOLDOWN_SECS)).await;
        pacer
            .wait_for_start()
            .await
            .expect("first recovery query should start after cooldown");

        let waiting = {
            let pacer = std::sync::Arc::clone(&pacer);
            tokio::spawn(async move { pacer.wait_for_start().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        tokio::time::advance(QUERY_PACING_INITIAL_INTERVAL - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        waiting
            .await
            .expect("paced query task should complete")
            .expect("paced query start should be admitted");
    }

    #[tokio::test(start_paused = true)]
    async fn background_query_pacer_spaces_starts_from_session_beginning() {
        let pacer = std::sync::Arc::new(BackgroundQueryPacer::default());
        pacer.wait_for_start().await;

        let waiting = {
            let pacer = std::sync::Arc::clone(&pacer);
            tokio::spawn(async move { pacer.wait_for_start().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        tokio::time::advance(BACKGROUND_QUERY_INTERVAL - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        waiting.await.expect("background query should be admitted");

        pacer.reset();
        pacer.wait_for_start().await;
    }

    #[tokio::test(start_paused = true)]
    async fn query_pacer_deduplicates_bursts_and_slows_new_episodes() {
        let pacer = QueryStartPacer::default();
        assert_eq!(
            pacer.record_rate_limit(),
            (QUERY_PACING_INITIAL_INTERVAL, true)
        );
        assert_eq!(
            pacer.record_rate_limit(),
            (QUERY_PACING_INITIAL_INTERVAL, false)
        );

        tokio::time::advance(Duration::from_secs(RATE_LIMIT_COOLDOWN_SECS)).await;
        pacer
            .wait_for_start()
            .await
            .expect("a duplicate signal must not extend the cooldown");

        tokio::time::advance(QUERY_RATE_LIMIT_EPISODE_GAP).await;
        assert_eq!(
            pacer.record_rate_limit(),
            (QUERY_PACING_INITIAL_INTERVAL * 2, true)
        );
        pacer.reset();
        assert_eq!(pacer.interval(), None);
        pacer
            .wait_for_start()
            .await
            .expect("session reset should clear the cooldown");
    }

    #[tokio::test]
    async fn query_limited_negentropy_falls_back_until_session_reset() {
        let connection = permissive_connection("ws://127.0.0.1:1", Keys::generate());
        assert!(connection.supports_negentropy().await);
        assert!(connection.mark_negentropy_query_rate_limited());
        assert!(!connection.mark_negentropy_query_rate_limited());
        assert!(!connection.supports_negentropy().await);

        connection.reset_subscription_budget(None);
        assert!(connection.supports_negentropy().await);
    }

    #[test]
    fn query_pacing_classifier_excludes_subscription_capacity_limits() {
        assert!(is_query_rate_limit_message(
            "rate-limited: too many queries"
        ));
        assert!(!is_query_rate_limit_message(
            "rate-limited: too many concurrent REQs"
        ));
        assert!(!is_query_rate_limit_message(
            "rate-limited: active subscriptions exceed max size 1048576 bytes"
        ));
    }

    #[test]
    fn test_normalize_url_real_world_example() {
        // Test the exact case from the bug report
        let url = "git.shakespeare.diy";
        assert_eq!(
            RelayConnection::normalize_url(url),
            "wss://git.shakespeare.diy"
        );
    }
}
