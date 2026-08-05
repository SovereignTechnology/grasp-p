//! Historic Sync Missing-Event Recovery Tests
//!
//! Regression coverage for a production failure observed on gitnostr.com:
//! NIP-77 negentropy reconciliation identifies event IDs missing locally, but
//! the relay's exact-ID REQ response returns only a subset of them. For
//! batches without repository or root-event metadata (the generic Layer-1
//! announcements batch), no semantic REQ+EOSE fallback can be constructed, and
//! the batch used to be finalized with partial results — silently dropping the
//! missing IDs until the next daily sync (23-25h later).
//!
//! Production log sequence being reproduced:
//! - "Negentropy sync incomplete - relay returned fewer events than requested"
//! - "Cannot create semantic fallback filters - no repos or root_events in batch"
//! - "Failed to create REQ+EOSE fallback subscriptions - completing batch with partial results"
//! - "Batch failed - will transition to ConnectedHistoricSyncFailures instead of Connected"
//!
//! The test drives the real sync path end to end: a genuine ngit-grasp source
//! relay (with real NIP-77 support) sits behind a censoring WebSocket proxy
//! that withholds one event's EVENT frames while letting negentropy frames
//! through, so reconciliation keeps reporting the event as available.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::censoring_proxy::CensoringProxy;
use crate::common::sync_helpers::{fetch_metrics, send_to_relay, wait_for_event_on_relay};
use crate::common::TestRelay;

/// Build a kind 10317 (GitUserGraspList) event.
///
/// Kind 10317 is part of the Layer-1 announcements filter and is stored
/// directly in the relay DB (no purgatory / git-data gating), which keeps this
/// scenario focused on the sync path rather than announcement promotion.
fn grasp_list_event(identifier: &str) -> Event {
    EventBuilder::new(Kind::GitUserGraspList, "")
        .tags(vec![Tag::identifier(identifier)])
        .finalize(&Keys::generate())
        .expect("Failed to sign grasp list event")
}

/// Read the `ngit_sync_relay_connected` gauge for the single tracked relay.
async fn connection_status_gauge(relay_url: &str) -> Option<i64> {
    let metrics = fetch_metrics(relay_url).await.ok()?;
    for line in metrics.lines() {
        if line.starts_with("ngit_sync_relay_connected{") {
            return line
                .split_whitespace()
                .last()
                .and_then(|value| value.parse::<f64>().ok())
                .map(|value| value as i64);
        }
    }
    None
}

/// Wait until the connection-status gauge reaches `expected`.
async fn wait_for_connection_status(relay_url: &str, expected: i64, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if connection_status_gauge(relay_url).await == Some(expected) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Scenario:
/// 1. Source relay holds two Layer-1 events; negentropy reports both missing.
/// 2. The proxy withholds one of them, so the exact-ID fetch returns a subset
///    and the ID-based retry returns nothing (zero progress).
/// 3. The announcements batch has no repos/root_events, so no semantic
///    fallback exists; the batch completes with failures and the relay
///    transitions to ConnectedHistoricSyncFailures (gauge value 4).
/// 4. Live sync for later unrelated events keeps working (no starvation).
/// 5. The withheld event becomes available; bounded background recovery must
///    fetch and store it without restarting the relay, after which the relay
///    is promoted to Connected (gauge value 3).
#[tokio::test]
async fn incomplete_exact_id_fetch_recovers_after_event_becomes_available() {
    // 1. Source relay with two Layer-1 events (kind 10317).
    let source = TestRelay::start().await;
    let delivered = grasp_list_event("grasp-list-delivered");
    let withheld = grasp_list_event("grasp-list-withheld");
    send_to_relay(&source, &delivered)
        .await
        .expect("send delivered event to source");
    send_to_relay(&source, &withheld)
        .await
        .expect("send withheld event to source");

    // 2. Censoring proxy in front of the source; withhold one event before
    //    the syncing relay ever connects.
    let proxy = CensoringProxy::start(source.url()).await;
    proxy.withhold(withheld.id);

    // 3. Syncing relay bootstraps through the proxy.
    let syncing = TestRelay::start_with_sync(Some(proxy.url().to_string())).await;

    // The non-withheld event flows through the initial historic sync.
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(delivered.id),
            Duration::from_secs(20),
        )
        .await,
        "delivered event should reach the syncing relay via historic sync"
    );

    // 4. The incomplete batch must complete with failures (status 4), not be
    //    reported as fully synchronized (status 3).
    assert!(
        wait_for_connection_status(syncing.url(), 4, Duration::from_secs(30)).await,
        "relay should report ConnectedHistoricSyncFailures while an event is withheld"
    );
    assert!(
        proxy.dropped_count() >= 2,
        "proxy should have censored the initial fetch and at least one retry, dropped: {}",
        proxy.dropped_count()
    );
    let syncing_log = std::fs::read_to_string(syncing.log_path())
        .expect("read syncing relay log after historic batch completion");
    assert!(
        syncing_log.contains(
            "Negentropy residual retry made no progress; retaining NIP-77 and scheduling bounded missing-event recovery"
        ),
        "a small residual must retain NIP-77 and enter bounded recovery"
    );
    assert!(
        !syncing_log.contains("Marking relay as incompatible with negentropy hydration"),
        "a one-event residual must not trigger semantic fallback"
    );
    assert!(
        !wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(withheld.id),
            Duration::from_secs(1),
        )
        .await,
        "withheld event must not have reached the syncing relay yet"
    );

    // 5. Later unrelated work is not starved: a new live event flows through
    //    the same proxied connection while the missing ID is still pending.
    let live = grasp_list_event("grasp-list-live");
    send_to_relay(&source, &live)
        .await
        .expect("send live event to source");
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(live.id),
            Duration::from_secs(20),
        )
        .await,
        "live sync should keep delivering unrelated events while recovery is pending"
    );
    assert_eq!(
        connection_status_gauge(syncing.url()).await,
        Some(4),
        "relay must remain in ConnectedHistoricSyncFailures while the event is still withheld"
    );

    // 6. The withheld event becomes available. Bounded background recovery
    //    must retry the missing ID and store the event without a restart.
    proxy.release(withheld.id);
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(withheld.id),
            Duration::from_secs(45),
        )
        .await,
        "withheld event should be recovered after it becomes available (was the missing ID dropped?)"
    );

    // 7. Once every missing ID is recovered the relay is honestly complete.
    assert!(
        wait_for_connection_status(syncing.url(), 3, Duration::from_secs(30)).await,
        "relay should transition to Connected after full recovery"
    );

    syncing.stop().await;
    proxy.stop().await;
    source.stop().await;
}
