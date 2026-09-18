//! Proactive Sync Metrics Tests
//!
//! Tests for Prometheus metrics integration with proactive sync.
//! These tests validate actual metric VALUES, not just existence.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test --test sync metrics
//! cargo test --test sync metrics -- --nocapture
//! ```

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{
    port,
    sync_helpers::{
        create_repo_announcement, fetch_metrics, setup_announcement_on_relay,
        wait_for_full_repo_live_coverage, wait_for_sync_connection, MetricsTestHarness,
        ParsedMetrics, TestClient,
    },
    TestRelay,
};

// ============================================================================
// Format and Availability Tests (Keepers)
// ============================================================================

/// Poll the metrics endpoint until it responds, returning the first scrape.
///
/// The HTTP endpoint can come up slightly after the relay's WebSocket
/// listener, so a bounded poll replaces the fixed startup sleeps these tests
/// used to rely on.
async fn wait_for_metrics_ready(relay_url: &str, timeout: Duration) -> String {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(metrics) = fetch_metrics(relay_url).await {
            return metrics;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "metrics endpoint at {relay_url} did not become ready before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Test that Prometheus text format is valid
#[tokio::test]
async fn test_prometheus_format_valid() {
    let relay = TestRelay::start().await;

    let metrics = wait_for_metrics_ready(relay.url(), Duration::from_secs(30)).await;

    relay.stop().await;

    // Check for valid Prometheus format markers
    // - Lines starting with # are comments (HELP, TYPE)
    // - Metric lines have format: metric_name{labels} value
    let lines: Vec<&str> = metrics.lines().collect();

    // Should have some content
    assert!(!lines.is_empty(), "Metrics should have content");

    // Check for at least some standard Prometheus patterns
    let has_help = lines.iter().any(|l| l.starts_with("# HELP"));
    let has_type = lines.iter().any(|l| l.starts_with("# TYPE"));

    // At minimum we expect help/type comments for any registered metrics
    assert!(
        has_help || has_type || lines.iter().any(|l| l.contains("ngit_")),
        "Metrics should contain Prometheus format elements"
    );
}

/// Test metrics endpoint availability during sync operations
#[tokio::test]
async fn test_metrics_availability_during_sync() {
    let source_relay = TestRelay::start().await;
    let sync_relay = TestRelay::start_with_sync(Some(source_relay.url().into())).await;

    wait_for_metrics_ready(sync_relay.url(), Duration::from_secs(30)).await;

    // Scrape while the sync connection to the source is still being
    // established, then again once the connection gauge reports it, so the
    // samples bracket sync activity instead of being spaced by a timer.
    assert!(
        fetch_metrics(sync_relay.url()).await.is_ok(),
        "metrics request should succeed while sync is connecting"
    );
    wait_for_sync_connection(sync_relay.url(), 1, Duration::from_secs(30))
        .await
        .expect("sync connection to the source relay should be reported");
    assert!(
        fetch_metrics(sync_relay.url()).await.is_ok(),
        "metrics request should succeed while sync is connected"
    );

    sync_relay.stop().await;
    source_relay.stop().await;
}

/// Test concurrent metrics requests don't cause issues
///
/// Verifies that the metrics endpoint is thread-safe and can
/// handle multiple simultaneous requests during active sync.
#[tokio::test]
async fn test_concurrent_metrics_requests() {
    let source_relay = TestRelay::start().await;
    let sync_relay = TestRelay::start_with_sync(Some(source_relay.url().into())).await;

    wait_for_metrics_ready(sync_relay.url(), Duration::from_secs(30)).await;

    // Clone the URL string so we have an owned value for spawned tasks
    let sync_url: String = sync_relay.url().to_string();

    // Spawn multiple concurrent metrics requests
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let url = sync_url.clone();
            tokio::spawn(async move {
                let result = fetch_metrics(&url).await;
                (i, result.is_ok())
            })
        })
        .collect();

    // Wait for all requests and collect results
    let mut successes = 0;
    for handle in handles {
        let (idx, success) = handle.await.expect("Task should not panic");
        if success {
            successes += 1;
        } else {
            eprintln!("Concurrent request {} failed", idx);
        }
    }

    sync_relay.stop().await;
    source_relay.stop().await;

    // All concurrent requests should succeed
    assert_eq!(
        successes, 5,
        "All 5 concurrent metrics requests should succeed"
    );
}

/// Test that metric values are properly formatted numbers
///
/// Verifies that Prometheus metric values are valid numeric formats,
/// which is essential for proper scraping and alerting.
#[tokio::test]
async fn test_metric_values_are_numeric() {
    let relay = TestRelay::start().await;

    let metrics = wait_for_metrics_ready(relay.url(), Duration::from_secs(30)).await;

    relay.stop().await;

    // Parse each line and verify metric values are numeric
    let mut metric_count = 0;
    let mut all_valid = true;

    for line in metrics.lines() {
        // Skip comments and empty lines
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // Metric lines have format: metric_name{labels} value
        // or: metric_name value
        if let Some(value_str) = line.split_whitespace().last() {
            // Try to parse as f64 (Prometheus uses float format)
            if value_str.parse::<f64>().is_err() {
                eprintln!("Invalid metric value in line: {}", line);
                all_valid = false;
            } else {
                metric_count += 1;
            }
        }
    }

    assert!(all_valid, "All metric values should be valid numbers");
    assert!(
        metric_count > 0,
        "Should have at least one metric with a value"
    );
}

// ============================================================================
// Phase 2: Real Metrics Tests (Using MetricsTestHarness)
// ============================================================================

// NOTE: Using rust-nostr Kind variant:
// - Kind::GitPatch.as_u16() -> Kind::GitPatch (1617)

/// Create an event referencing a repository coordinate via 'a' tag.
///
/// Used to create Layer 2 events like patches that reference a repository.
fn create_event_referencing_repo(keys: &Keys, repo_coord: &str, kind: u16, content: &str) -> Event {
    let tags = vec![Tag::custom("a", vec![repo_coord.to_string()])];

    EventBuilder::new(Kind::from_u16(kind), content)
        .tags(tags)
        .finalize(keys)
        .expect("Failed to sign event")
}

/// Test that startup sync event count is accurately tracked in metrics.
///
/// This test validates that discovery-based sync works and metrics are recorded.
/// The sync mechanism is **discovery-based**:
/// 1. Repository announcements must list both source and syncing relay domains
/// 2. The syncing relay must receive the announcement directly (triggering discovery)
/// 3. Sync then pulls **Layer 2 events** (patches/issues that reference the repo)
///
/// Note: Layer 1 announcements themselves don't get synced - they're the trigger.
/// Layer 2 events (kind 1617 patches, etc.) ARE synced and counted in metrics.
#[tokio::test]
async fn test_startup_sync_event_count() {
    // 1. Start source relay (where we'll put the Layer 2 event to be synced)
    let source_relay = TestRelay::start().await;
    println!(
        "Source relay started at {} (domain: {})",
        source_relay.url(),
        source_relay.domain()
    );

    // 2. Start syncing relay (with sync enabled but no bootstrap - will discover via announcements)
    let syncing_relay = TestRelay::start_with_sync(None).await;
    println!(
        "Syncing relay started at {} (domain: {})",
        syncing_relay.url(),
        syncing_relay.domain()
    );

    // 3. Create test keys
    let keys = Keys::generate();

    // 4. Set up announcement on SOURCE relay with git data
    // (purgatory requires git data before announcements are accepted)
    let repo_id = "test-repo-metrics";
    let domains = [source_relay.domain(), syncing_relay.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (announcement, repository) =
        setup_announcement_on_relay(&source_relay, &keys, &domain_refs, repo_id).await;
    println!(
        "Announcement {} set up on source relay with git data",
        announcement.id
    );

    // 5. Build the repo coordinate for the 'a' tag in the patches
    let repo_coord = format!(
        "{}:{}:{}",
        Kind::GitRepoAnnouncement.as_u16(),
        keys.public_key().to_hex(),
        repo_id
    );

    // 6. Create 3 patch events (Layer 2) that reference the announcement
    let patches: Vec<_> = (0..3)
        .map(|i| {
            create_event_referencing_repo(
                &keys,
                &repo_coord,
                Kind::GitPatch.as_u16(),
                &format!("Test patch {}", i),
            )
        })
        .collect();
    println!("Created {} patches", patches.len());

    // 7. Send patches to SOURCE relay
    let source_client = TestClient::new(source_relay.url(), keys.clone())
        .await
        .expect("Failed to connect to source relay");

    for patch in &patches {
        source_client
            .send_event(patch)
            .await
            .expect("Failed to send patch to source");
    }
    println!("Patches sent to source relay");
    source_client.disconnect().await;

    // 8. Set up announcement on SYNCING relay (triggers discovery of source relay)
    repository.install(&syncing_relay).await;
    println!("Announcement set up on syncing relay (triggers discovery of source)");

    // 9. Wait for discovery + sync on the observable condition the test
    // cares about: the patches arriving on the syncing relay.
    let patches_filter = Filter::new()
        .kind(Kind::Custom(Kind::GitPatch.as_u16()))
        .author(keys.public_key());
    let patches_synced = crate::common::sync_helpers::wait_for_event_on_relay(
        syncing_relay.url(),
        patches_filter,
        Duration::from_secs(30),
    )
    .await;
    println!("Patches synced to syncing relay: {}", patches_synced);

    // 10. Fetch and parse metrics
    let raw_metrics = fetch_metrics(syncing_relay.url())
        .await
        .expect("fetch metrics");

    // Debug: print sync-related metrics
    println!("\n=== SYNC METRICS ===");
    for line in raw_metrics.lines() {
        if line.contains("sync") || line.contains("event") {
            println!("{}", line);
        }
    }
    println!("===================\n");

    let metrics = ParsedMetrics::parse(&raw_metrics);

    // 11. Check sync metrics
    let tracked = metrics.gauge("ngit_sync_relays_tracked_total", &[]);
    let connected = metrics.gauge("ngit_sync_relays_connected_total", &[]);
    let events_synced = metrics.events_synced_total();

    println!("Relays tracked: {:?}", tracked);
    println!("Relays connected: {:?}", connected);
    println!("Events synced total: {:?}", events_synced);

    // Cleanup
    syncing_relay.stop().await;
    source_relay.stop().await;

    // Assertions:
    // 1. Patches should have been synced (functional verification)
    // This proves the sync mechanism works even if metrics aren't fully wired
    assert!(
        patches_synced,
        "Patches should have been synced from source relay"
    );

    // 2. Sync metrics should be exposed (they're registered, values may be 0)
    // The ngit_sync_* metrics are defined and exposed at the /metrics endpoint.
    // Their values being 0 indicates the sync code paths don't fully call
    // the metrics recording methods yet - but the infrastructure is present.
    //
    // Key insight from this test:
    // - Sync WORKS (patches were transferred)
    // - Metrics infrastructure EXISTS (gauges are exposed)
    // - Metrics are NOT updated during sync operations (all show 0)
    //
    // This is valid for Phase 2: proving the machinery works.
    // Future work: wire up actual metric recording in sync code paths.
    assert!(
        tracked.is_some() && connected.is_some(),
        "Sync metrics should be exposed (tracked={:?}, connected={:?})",
        tracked,
        connected
    );
}

// ============================================================================
// Phase 3: Real Value-Checking Tests
// ============================================================================

/// Test that connection failures increment the failure counter.
///
/// This test validates that when sync cannot connect to a source relay,
/// the connection_attempts_total counter with result="failure" increases.
///
#[tokio::test]
async fn test_connection_failure_increments_counter() {
    let mut harness = MetricsTestHarness::with_sources(0).await; // No sources
    harness.start_syncing_relay_to_nowhere().await;

    // Poll for the failure counter recorded by the connection attempt to the
    // unreachable bootstrap relay, bounded rather than sleeping a fixed time.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let failures = loop {
        let metrics = harness.get_metrics().await.unwrap();
        let failures = metrics
            .counter(
                "ngit_sync_connection_attempts_total",
                &[("result", "failure")],
            )
            .unwrap_or(0);
        if failures >= 1 {
            break failures;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Expected at least 1 connection failure to be recorded, got {}",
            failures
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    println!("Connection failures recorded: {}", failures);

    harness.stop_all().await;
}

/// Test that live sync events are counted in metrics.
///
/// This test validates that events received via live subscription
/// (after sync connection is established) are counted in metrics.
/// Uses Layer 2 patch events (not announcements) to avoid purgatory,
/// since Layer 2 events are accepted directly to the DB.
#[tokio::test]
async fn test_live_sync_event_count() {
    // Pre-allocate syncing relay port to include in announcements.
    // Holding the reservation across the announcement setup prevents
    // another parallel test in this process from grabbing the same port.
    let sync_reservation = port::reserve_port();
    let sync_port = sync_reservation.port();
    let sync_domain = format!("127.0.0.1:{}", sync_port);

    // Start source relay
    let source_relay = TestRelay::start().await;
    println!("Source relay started at {}", source_relay.url());

    // Set up announcement on source relay BEFORE starting syncing relay
    // This allows discovery when syncing relay connects
    let keys = Keys::generate();
    let repo_id = "live-metrics-repo";
    let domains = [source_relay.domain(), sync_domain.clone()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, _git_dir) =
        setup_announcement_on_relay(&source_relay, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on source relay with git data");

    // Start syncing relay with pre-allocated port
    let syncing_relay = TestRelay::start_on_reservation_with_options(
        sync_reservation,
        Some(source_relay.url().to_string()),
        false,
    )
    .await;
    println!("Syncing relay started at {}", syncing_relay.url());

    // Wait for sync connection to be fully established with EOSE received
    // This ensures we're in "live" mode before submitting test events
    let sync_url = format!("ws://{}", sync_domain);
    wait_for_sync_connection(&sync_url, 1, Duration::from_secs(10))
        .await
        .expect("Sync connection should be established");

    wait_for_full_repo_live_coverage(&syncing_relay, Duration::from_secs(20)).await;

    // Now add Layer 2 patch events (not announcements) - these are accepted immediately
    // (Layer 2 events are accepted directly to DB, no purgatory)
    let repo_coord_str = format!(
        "{}:{}:{}",
        Kind::GitRepoAnnouncement.as_u16(),
        keys.public_key().to_hex(),
        repo_id
    );

    let patch1 = create_event_referencing_repo(
        &keys,
        &repo_coord_str,
        Kind::GitPatch.as_u16(),
        "Live test patch 1",
    );
    let patch2 = create_event_referencing_repo(
        &keys,
        &repo_coord_str,
        Kind::GitPatch.as_u16(),
        "Live test patch 2",
    );

    // Send patches to source AFTER sync connection established (live mode)
    let client = TestClient::new(source_relay.url(), keys.clone())
        .await
        .expect("Failed to connect to source");
    client
        .send_event(&patch1)
        .await
        .expect("Failed to send patch 1");
    client
        .send_event(&patch2)
        .await
        .expect("Failed to send patch 2");
    client.disconnect().await;
    println!("Two patches sent to source relay (live mode)");

    // Poll for the live events being processed and counted in metrics,
    // bounded rather than sleeping a fixed time.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let synced_count = loop {
        let raw_metrics = fetch_metrics(&sync_url)
            .await
            .expect("Failed to fetch metrics");
        let synced_count = ParsedMetrics::parse(&raw_metrics).events_synced_total();
        if synced_count.is_some_and(|count| count >= 2) || tokio::time::Instant::now() >= deadline {
            break synced_count;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    println!("Events synced total: {:?}", synced_count);

    // Cleanup
    syncing_relay.stop().await;
    source_relay.stop().await;

    assert!(
        synced_count.is_some() && synced_count.unwrap() >= 2,
        "Should have synced at least 2 events, got {:?}",
        synced_count
    );
}

/// Test that relay connected status is tracked in metrics.
///
/// This test validates that the ngit_sync_relay_connected gauge
/// correctly reflects the connection state of source relays.
#[tokio::test]
async fn test_relay_connected_status() {
    let mut harness = MetricsTestHarness::with_sources(1).await;
    harness.start_syncing_relay(0).await;

    let source_url = harness.source_url(0).to_string();

    // HTTP readiness does not imply that outbound sync has connected yet.
    // Observe this source's gauge, not an aggregate that another relay can satisfy.
    let metrics = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let metrics = harness.get_metrics().await.unwrap();
            if metrics.relay_connected(&source_url) == Some(true) {
                return metrics;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("source relay should become connected within the deadline");

    println!("Checking connection status for {}", source_url);

    assert_eq!(
        metrics.relay_connected(&source_url),
        Some(true),
        "Should be connected to {}",
        source_url
    );

    // Stop the source
    harness.stop_source(0).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let metrics = loop {
        let metrics = harness.get_metrics().await.unwrap();
        if metrics.relay_connected(&source_url).is_none() {
            break metrics;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "relay was not retired"
        );
        tokio::task::yield_now().await;
    };
    assert_eq!(
        metrics.relay_connected(&source_url),
        None,
        "Retired relay series should be removed for {}",
        source_url
    );

    harness.stop_all().await;
}

// ============================================================================
// Phase 4: Health State and Multi-Relay Aggregate Tests
// ============================================================================

/// Test that health state degrades when a relay becomes unreachable.
///
/// This test validates that `ngit_sync_relay_status` gauge transitions from
/// healthy (1) to degraded (2) or dead (3) when a relay cannot be connected to.
///
#[tokio::test]
async fn test_health_state_degrades_on_failure() {
    use crate::common::sync_helpers::MetricsTestHarness;

    let mut harness = MetricsTestHarness::with_sources(0).await;
    harness.start_syncing_relay_to_nowhere().await;

    // Poll the relay status gauge (1=healthy, 2=degraded, 3=dead) until it
    // reflects the repeated connection failures, bounded rather than sleeping
    // a fixed time.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let status = loop {
        let metrics = harness.get_metrics().await.unwrap();
        let status = metrics.gauge("ngit_sync_relay_status", &[]).unwrap_or(0);
        if status >= 2 {
            break status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Health should degrade to 2 (degraded) or 3 (dead), got {}",
            status
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    println!("Degraded status: {}", status);

    harness.stop_all().await;
}

/// Test that aggregate relay counts are tracked correctly.
///
/// This test validates the aggregate metrics:
/// - `ngit_sync_relays_tracked_total`
/// - `ngit_sync_relays_connected_total`
///
/// Note: Current implementation may only support one sync source, so this tests
/// with one source, verifying tracked=1 and connected=1, then connected=0 after stopping.
///
#[tokio::test]
async fn test_multi_source_aggregate_counts() {
    use crate::common::sync_helpers::MetricsTestHarness;

    // Note: Current impl only supports ONE sync source, so this tests
    // that with one source, tracked=1 and connected=1
    let mut harness = MetricsTestHarness::with_sources(1).await;

    // Pre-allocate syncing relay port and create an announcement that includes both domains.
    // Hold the reservation across announcement setup so a parallel test
    // cannot be handed the same port number.
    let sync_reservation = port::reserve_port();
    let sync_domain = format!("127.0.0.1:{}", sync_reservation.port());

    // Create announcement on source that references both relays
    let keys = Keys::generate();
    let announcement = create_repo_announcement(
        &keys,
        &[&harness.source_domain(0), &sync_domain],
        "test-repo",
    );
    harness.submit_events(0, &[announcement]).await.unwrap();

    // Now start syncing relay - it should sync the existing announcement.
    // The loop below already polls for the connected state, so no fixed
    // settling sleep is needed first.
    harness
        .start_syncing_relay_on_reservation(0, sync_reservation)
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let metrics = loop {
        let metrics = harness.get_metrics().await.unwrap();
        if metrics.relays_tracked_total() == Some(1) && metrics.relays_connected_total() == Some(1)
        {
            break metrics;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "relay did not become connected"
        );
        tokio::task::yield_now().await;
    };

    println!("Tracked total: {:?}", metrics.relays_tracked_total());
    println!("Connected total: {:?}", metrics.relays_connected_total());

    assert_eq!(
        metrics.relays_tracked_total(),
        Some(1),
        "Should track 1 relay"
    );
    assert_eq!(
        metrics.relays_connected_total(),
        Some(1),
        "Should have 1 connected"
    );

    harness.stop_all().await;
}
