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

use crate::nostr::SharedDatabase;
use crate::outbound::{OutboundTargetKind, OutboundTargetPolicy, RelayTargetSource};

/// Maximum wall-clock time for one dry-run NIP-77 reconciliation.
///
/// The SDK has initial-response and idle timers, but a relay can keep an
/// exchange alive indefinitely by continuing to send reconciliation messages.
const NEGENTROPY_DIFF_TIMEOUT: Duration = Duration::from_secs(15);

/// NIP-11 is advisory and must not hold up a connected relay indefinitely.
const NIP11_FETCH_TIMEOUT: Duration = Duration::from_secs(3);

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

/// Upper bound on how long a transient-REQ permit may be held.
///
/// Permits are normally released when the subscription's EOSE (or CLOSED)
/// arrives. A relay that never answers would otherwise pin its permits
/// forever and starve every later transient subscription on the
/// connection, so a watchdog reclaims the permit after this deadline
/// (twice the negentropy round timeout, generous for large REQ pages).
const TRANSIENT_REQ_PERMIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Permits held by in-flight transient REQ subscriptions, keyed by
/// subscription id and shared across connection clones.
type TransientReqPermitMap = std::sync::Arc<
    std::sync::Mutex<
        std::collections::HashMap<SubscriptionId, tokio::sync::OwnedSemaphorePermit>,
    >,
>;

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
    /// A new event was received (event, subscription_id)
    Event(Box<Event>, SubscriptionId),
    /// End of stored events for a subscription
    EndOfStoredEvents(SubscriptionId),
    /// NOTICE message from relay
    Notice(String),
    /// Connection was closed
    Closed(String),
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
    /// The underlying nostr-sdk client
    client: Client,
    /// Local database for negentropy comparison (used for NIP-77 sync)
    database: Option<SharedDatabase>,
    /// Whether we've logged NIP-77 not supported for this relay (log once)
    nip77_warning_logged: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Whether this relay supports NIP-77 negentropy (0 = unknown, 2 = confirmed not supported)
    nip77_supported: std::sync::Arc<std::sync::atomic::AtomicU8>,
    /// Consecutive transient negentropy failures (drives the cooldown schedule)
    nip77_transient_failures: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Deadline before which negentropy is not attempted (transient-failure cooldown)
    nip77_cooldown_until: std::sync::Arc<std::sync::Mutex<Option<tokio::time::Instant>>>,
    /// Bounds concurrent negentropy diff rounds on this connection
    /// (shared across clones; see [`MAX_CONCURRENT_NEG_DIFFS`])
    neg_diff_permits: std::sync::Arc<tokio::sync::Semaphore>,
    /// Bounds concurrent transient (auto-close) REQ subscriptions on this
    /// connection (shared across clones; see
    /// [`MAX_CONCURRENT_TRANSIENT_REQS`])
    transient_req_permits: std::sync::Arc<tokio::sync::Semaphore>,
    /// Permits held by open transient subscriptions, keyed by subscription
    /// id; released on EOSE/CLOSED, connection teardown, or the watchdog
    transient_req_permits_held: TransientReqPermitMap,
}

impl RelayConnection {
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
    /// * `keys` - Cryptographic keys for NIP-42 authentication (typically the relay operator's keys)
    /// * `source` - Whether the URL is operator-configured or event-directed
    /// * `policy` - Outbound target policy enforced before event-directed dials
    pub fn new(
        url: String,
        keys: Keys,
        source: RelayTargetSource,
        policy: OutboundTargetPolicy,
    ) -> Self {
        let normalized_url = Self::normalize_url(&url);
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(keys))
            .build();
        Self {
            url: normalized_url,
            source,
            policy,
            client,
            database: None,
            nip77_warning_logged: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            nip77_supported: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            nip77_transient_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            nip77_cooldown_until: std::sync::Arc::new(std::sync::Mutex::new(None)),
            neg_diff_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_NEG_DIFFS,
            )),
            transient_req_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_TRANSIENT_REQS,
            )),
            transient_req_permits_held: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Create a new relay connection with database for negentropy sync
    ///
    /// # Arguments
    /// * `url` - The relay URL to connect to (with or without scheme, e.g., "relay.example.com" or "wss://relay.example.com")
    /// * `database` - Shared database for local event comparison during negentropy sync
    /// * `keys` - Cryptographic keys for NIP-42 authentication (typically the relay operator's keys)
    /// * `source` - Whether the URL is operator-configured or event-directed
    /// * `policy` - Outbound target policy enforced before event-directed dials
    pub fn new_with_database(
        url: String,
        database: SharedDatabase,
        keys: Keys,
        source: RelayTargetSource,
        policy: OutboundTargetPolicy,
    ) -> Self {
        let normalized_url = Self::normalize_url(&url);
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(keys))
            .build();
        Self {
            url: normalized_url,
            source,
            policy,
            client,
            database: Some(database),
            nip77_warning_logged: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            nip77_supported: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            nip77_transient_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            nip77_cooldown_until: std::sync::Arc::new(std::sync::Mutex::new(None)),
            neg_diff_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_NEG_DIFFS,
            )),
            transient_req_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_TRANSIENT_REQS,
            )),
            transient_req_permits_held: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
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
    /// long-lived `RelayConnection`: operators can change their cap between reconnects. Only
    /// NIP-11 `default_limit` is returned. `max_limit` describes explicit `limit` values and is
    /// not applicable to the historic filters we intentionally send without one.
    pub async fn fetch_default_limit(&self) -> Option<usize> {
        let mut document_url = reqwest::Url::parse(&self.url).ok()?;
        let http_scheme = match document_url.scheme() {
            "ws" => "http",
            "wss" => "https",
            _ => return None,
        };
        document_url.set_scheme(http_scheme).ok()?;

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
            Ok(Ok(None)) => return None,
            Ok(Err(error)) => {
                tracing::debug!(relay = %self.url, error = %error, "NIP-11 fetch failed");
                return None;
            }
            Err(_) => {
                tracing::debug!(relay = %self.url, "NIP-11 fetch timed out");
                return None;
            }
        };
        let document = nostr::nips::nip11::RelayInformationDocument::from_json(body).ok()?;
        document
            .limitation
            .and_then(|limitation| limitation.default_limit)
            .and_then(|limit| usize::try_from(limit).ok())
            .filter(|limit| *limit > 0)
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

        tracing::debug!(relay = %url, "Starting event loop with relay-level notifications");

        while let Some(notification) = notifications.next().await {
            match notification {
                RelayNotification::Event {
                    event,
                    subscription_id,
                } => {
                    tracing::trace!(
                        relay = %url,
                        event_id = %event.id,
                        sub_id = %subscription_id,
                        "Received event"
                    );
                    if event_sender
                        .send(RelayEvent::Event(Box::new(*event), subscription_id.clone()))
                        .await
                        .is_err()
                    {
                        tracing::debug!(relay = %url, "Event sender closed, stopping event loop");
                        break;
                    }
                }
                RelayNotification::Message { message } => match *message {
                    RelayMessage::EndOfStoredEvents(sub_id) => {
                        tracing::debug!(relay = %url, sub_id = ?sub_id, "Received EOSE");
                        // Convert Cow<SubscriptionId> to owned SubscriptionId
                        let owned_sub_id = sub_id.into_owned();
                        // Release the transient permit BEFORE forwarding:
                        // the forward can block on channel backpressure and
                        // permit release must never depend on downstream
                        // consumers (the SyncManager actor may itself be
                        // waiting on a permit).
                        self.release_transient_req_permit(&owned_sub_id);
                        if event_sender
                            .send(RelayEvent::EndOfStoredEvents(owned_sub_id))
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
                            self.mark_negentropy_unsupported();

                            tracing::info!(
                                relay = %url,
                                notice = %msg,
                                "Relay does not support NIP-77 (negentropy)"
                            );
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
                        // A CLOSED subscription can no longer produce EOSE;
                        // free its transient permit if one is held.
                        self.release_transient_req_permit(subscription_id.as_ref());
                        tracing::info!(relay = %url, message = %msg, "Relay closed subscription");
                        let _ = event_sender.send(RelayEvent::Closed(msg.to_string())).await;
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

        // The connection is going away; every outstanding transient
        // subscription dies with it, so free their permits.
        self.clear_transient_req_permits();

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
    /// * `auto_close` - If true, subscription automatically closes after EOSE (for historic sync). If false, stays open for new events (for live sync).
    ///
    /// # Returns
    /// * `Ok(SubscriptionId)` - The subscription ID on success
    /// * `Err(String)` - Error description on failure
    pub async fn subscribe_filter(
        &self,
        filter: Filter,
        auto_close: bool,
    ) -> Result<SubscriptionId, String> {
        self.subscribe_filters(vec![filter], auto_close).await
    }

    /// Subscribe to several OR filters under one NIP-01 subscription ID.
    ///
    /// Relays apply active-REQ limits to subscription IDs, not to the filters
    /// inside a REQ. Grouping related filters preserves NIP-01 semantics while
    /// avoiding one persistent subscription per GRASP tag variant.
    pub async fn subscribe_filters(
        &self,
        filters: Vec<Filter>,
        auto_close: bool,
    ) -> Result<SubscriptionId, String> {
        if filters.is_empty() {
            return Err("Cannot subscribe with an empty filter set".to_string());
        }

        tracing::debug!(
            relay = %self.url,
            filter_count = filters.len(),
            filters = ?filters,
            auto_close = auto_close,
            "subscribe_filters called"
        );

        // Transient (auto-close) subscriptions share a bounded number of
        // per-connection slots so historic bursts queue instead of
        // exceeding relay subscription budgets. The permit is registered
        // against the subscription id on success and released when the
        // subscription's EOSE or CLOSED arrives (see run_event_loop).
        let permit = if auto_close {
            match self.transient_req_permits.clone().acquire_owned().await {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return Err(format!(
                        "Failed to subscribe on {}: transient permit semaphore closed",
                        self.url
                    ));
                }
            }
        } else {
            None
        };

        let output = if auto_close {
            self.client
                .subscribe(filters)
                .close_on(
                    SubscribeAutoCloseOptions::default().exit_policy(ReqExitPolicy::ExitOnEOSE),
                )
                .await
        } else {
            self.client.subscribe(filters).await
        }
        .map_err(|e| format!("Failed to subscribe on {}: {}", self.url, e))?;

        if !output.failed.is_empty() {
            let failures = output
                .failed
                .values()
                .cloned()
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("Failed to subscribe on {}: {}", self.url, failures));
        }

        if let Some(permit) = permit {
            self.hold_transient_req_permit(output.value.clone(), permit);
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
    /// This is reserved for dependency recovery where exact event IDs are
    /// already known. The caller remains responsible for applying the write
    /// policy and persistence path.
    pub async fn fetch_events(
        &self,
        filter: Filter,
        timeout: Duration,
    ) -> Result<Vec<Event>, String> {
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

        relay
            .fetch_events(filter)
            .timeout(timeout)
            .await
            .map(|events| events.into_iter().collect())
            .map_err(|error| format!("Failed to fetch events from {}: {}", self.url, error))
    }

    /// Get the relay URL
    pub fn url(&self) -> &str {
        &self.url
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

    /// Disconnect from the relay
    pub async fn disconnect(&self) {
        self.clear_transient_req_permits();
        self.client.disconnect().await;
        tracing::debug!(relay = %self.url, "Disconnected from relay");
    }

    /// Unsubscribe from all active subscriptions
    ///
    /// Used during consolidation to reset all subscriptions before rebuilding
    /// with consolidated filters. This sends CLOSE messages for all active
    /// subscriptions on the relay.
    pub async fn unsubscribe_all(&self) {
        self.clear_transient_req_permits();
        if let Err(e) = self.client.unsubscribe_all().await {
            tracing::debug!(relay = %self.url, error = %e, "Failed to unsubscribe from all subscriptions");
        }
        tracing::debug!(relay = %self.url, "Unsubscribed from all subscriptions");
    }

    /// Register a held transient-REQ permit for `sub_id` and start its
    /// watchdog.
    fn hold_transient_req_permit(
        &self,
        sub_id: SubscriptionId,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        self.transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .insert(sub_id.clone(), permit);

        // Watchdog: a relay that never sends EOSE (or CLOSED) must not pin
        // its permits forever. Dropping the permit only frees our own
        // slot; the subscription itself remains subject to the normal
        // batch and disconnect cleanup paths.
        let held = std::sync::Arc::clone(&self.transient_req_permits_held);
        let relay_url = self.url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(TRANSIENT_REQ_PERMIT_TIMEOUT).await;
            let reclaimed = held
                .lock()
                .expect("transient permit map poisoned")
                .remove(&sub_id)
                .is_some();
            if reclaimed {
                tracing::debug!(
                    relay = %relay_url,
                    sub_id = %sub_id,
                    "Transient REQ permit reclaimed by watchdog (no EOSE within deadline)"
                );
            }
        });
    }

    /// Release the transient-REQ permit held for `sub_id`, if any.
    fn release_transient_req_permit(&self, sub_id: &SubscriptionId) {
        self.transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
            .remove(sub_id);
    }

    /// Release every held transient-REQ permit (connection teardown).
    fn clear_transient_req_permits(&self) {
        self.transient_req_permits_held
            .lock()
            .expect("transient permit map poisoned")
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
        let _permit = self
            .neg_diff_permits
            .acquire()
            .await
            .map_err(|_| format!("Negentropy permits closed for {}", self.url))?;

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

        // Use dry_run to only identify differences without downloading events
        let sync_opts = SyncOptions::default().dry_run();
        let client = self.client.clone();
        let sync_task = async move {
            match client.sync(filter).opts(sync_opts).await {
                Ok(output) => {
                    if !output.failed.is_empty() {
                        Err(format!("Negentropy diff had failures: {:?}", output.failed))
                    } else {
                        Ok(output.value)
                    }
                }
                Err(error) => Err(format!("Negentropy diff failed: {}", error)),
            }
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
                match classify_negentropy_failure(&e) {
                    NegentropyFailure::Unsupported => {
                        self.mark_negentropy_unsupported();

                        // Log warning only once per relay to avoid spam
                        if !self
                            .nip77_warning_logged
                            .swap(true, std::sync::atomic::Ordering::Relaxed)
                        {
                            tracing::warn!(
                                relay = %self.url,
                                error = %e,
                                "Relay does not support NIP-77, will fall back to REQ+EOSE"
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
mod tests {
    use super::*;

    /// Event-directed connection with the permissive policy used by tests
    /// that dial loopback fixtures.
    fn permissive_connection(url: &str, keys: Keys) -> RelayConnection {
        RelayConnection::new(
            url.to_string(),
            keys,
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
    async fn fetch_events_targets_the_connections_exact_relay() {
        let configured = LocalRelayBuilder::default().build();
        configured.run().await.expect("start configured relay");
        let other = LocalRelayBuilder::default().build();
        other.run().await.expect("start other relay");

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
            Keys::generate(),
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

    #[tokio::test]
    async fn event_directed_connect_rejects_loopback_before_dialling() {
        let connection = RelayConnection::new(
            "ws://127.0.0.1:1".to_string(),
            Keys::generate(),
            RelayTargetSource::EventDirected,
            OutboundTargetPolicy::default(),
        );

        let error = connection
            .connect(3)
            .await
            .expect_err("strict policy must reject an event-directed loopback dial");
        assert!(error.contains("Outbound target policy"), "{error}");
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
