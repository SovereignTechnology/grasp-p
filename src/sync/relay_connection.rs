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

/// Maximum wall-clock time for one dry-run NIP-77 reconciliation.
///
/// The SDK has initial-response and idle timers, but a relay can keep an
/// exchange alive indefinitely by continuing to send reconciliation messages.
const NEGENTROPY_DIFF_TIMEOUT: Duration = Duration::from_secs(15);

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
    /// The underlying nostr-sdk client
    client: Client,
    /// Local database for negentropy comparison (used for NIP-77 sync)
    database: Option<SharedDatabase>,
    /// Whether we've logged NIP-77 not supported for this relay (log once)
    nip77_warning_logged: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Whether this relay supports NIP-77 negentropy (None = unknown, Some(false) = confirmed not supported)
    nip77_supported: std::sync::Arc<std::sync::atomic::AtomicU8>,
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
    pub fn new(url: String, keys: Keys) -> Self {
        let normalized_url = Self::normalize_url(&url);
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(keys))
            .build();
        Self {
            url: normalized_url,
            client,
            database: None,
            nip77_warning_logged: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            nip77_supported: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
        }
    }

    /// Create a new relay connection with database for negentropy sync
    ///
    /// # Arguments
    /// * `url` - The relay URL to connect to (with or without scheme, e.g., "relay.example.com" or "wss://relay.example.com")
    /// * `database` - Shared database for local event comparison during negentropy sync
    /// * `keys` - Cryptographic keys for NIP-42 authentication (typically the relay operator's keys)
    pub fn new_with_database(url: String, database: SharedDatabase, keys: Keys) -> Self {
        let normalized_url = Self::normalize_url(&url);
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(keys))
            .build();
        Self {
            url: normalized_url,
            client,
            database: Some(database),
            nip77_warning_logged: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            nip77_supported: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
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
                    RelayMessage::Closed { message: msg, .. } => {
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
        self.client.disconnect().await;
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
        tracing::debug!(relay = %self.url, "Unsubscribed from all subscriptions");
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
    /// * `false` if we've confirmed this relay doesn't support NIP-77
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

        // Unknown or supported - try it
        true
    }

    /// Mark this relay as not supporting NIP-77 negentropy
    ///
    /// Called when we detect negentropy isn't working for this relay:
    /// - NOTICE message contains negentropy-related error
    /// - negentropy_sync_diff() fails
    /// - Negentropy retry returns zero events
    ///
    /// Future batches will skip negentropy and use REQ+EOSE directly.
    pub fn mark_negentropy_unsupported(&self) {
        self.nip77_supported
            .store(2, std::sync::atomic::Ordering::Relaxed);
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
                    // Relay confirmed not to support NIP-77 (via NOTICE or other means)
                    return Err(format!(
                        "Relay {} does not support NIP-77 (detected via NOTICE)",
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
                tracing::debug!(
                    relay = %self.url,
                    local_count = reconciliation.local.len(),
                    remote_count = reconciliation.remote.len(),
                    "Negentropy diff completed (dry run)"
                );
                Ok(reconciliation)
            }
            Err(e) => {
                self.mark_negentropy_unsupported();

                // Log warning only once per relay to avoid spam
                if !self
                    .nip77_warning_logged
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    tracing::warn!(
                        relay = %self.url,
                        error = %e,
                        "Negentropy diff failed, will fall back to REQ+EOSE"
                    );
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
    use nostr_relay_builder::prelude::LocalRelayBuilder;
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

    #[tokio::test]
    async fn hung_negentropy_diff_times_out_and_disables_future_attempts() {
        let connection = RelayConnection::new("ws://127.0.0.1:1".to_string(), Keys::generate());
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
            "a timed-out relay must use REQ+EOSE for future historic batches"
        );
    }

    #[tokio::test]
    async fn fetch_events_targets_the_connections_exact_relay() {
        let configured = LocalRelayBuilder::default().build();
        configured.run().await.expect("start configured relay");
        let other = LocalRelayBuilder::default().build();
        other.run().await.expect("start other relay");

        let expected = EventBuilder::text_note("only on the other relay")
            .finalize(&Keys::generate())
            .expect("build event");
        other
            .add_event(expected.clone())
            .await
            .expect("seed other relay");

        let connection = RelayConnection::new(configured.url().await.to_string(), Keys::generate());
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
        let connection = RelayConnection::new("ws://127.0.0.1:1".to_string(), Keys::generate());

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
        let keys = Keys::generate();
        let conn = RelayConnection::new("relay.example.com".to_string(), keys);
        assert_eq!(conn.url(), "wss://relay.example.com");
    }

    #[test]
    fn test_new_preserves_wss_scheme() {
        let keys = Keys::generate();
        let conn = RelayConnection::new("wss://relay.example.com".to_string(), keys);
        assert_eq!(conn.url(), "wss://relay.example.com");
    }

    #[test]
    fn test_new_preserves_ws_scheme() {
        let keys = Keys::generate();
        let conn = RelayConnection::new("ws://relay.example.com".to_string(), keys);
        assert_eq!(conn.url(), "ws://relay.example.com");
    }

    #[test]
    fn test_new_with_database_normalizes_url() {
        // This test just verifies the URL normalization works
        // We can't easily test with_database without a real database
        let keys = Keys::generate();
        let conn = RelayConnection::new("git.shakespeare.diy".to_string(), keys);
        assert_eq!(conn.url(), "wss://git.shakespeare.diy");
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
