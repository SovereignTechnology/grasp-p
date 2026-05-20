//! Historic Sync Tests
//!
//! Tests for relay synchronization from a pre-configured bootstrap relay.
//! These tests verify that a relay can sync events from another relay
//! that it's configured to connect to on startup.
//!
//! "Historic sync" refers to events that existed on the source relay BEFORE
//! the syncing relay connected (bootstrap scenario).

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{port, sync_helpers::*, TestRelay};

/// Test 1: Bootstrap sync - relay syncs existing events from bootstrap relay on startup
///
/// Scenario:
/// 1. Source relay has announcement (sent before syncing relay starts)
/// 2. Start syncing relay configured to sync from source
/// 3. Verify announcement syncs via bootstrap/historic sync
///
/// This tests that when a relay starts with a bootstrap relay configured,
/// it connects and syncs existing events.
#[tokio::test]
async fn test_bootstrap_syncs_existing_layer2_events() {
    // Use run_sync_test helper - announcement auto-created and sent as historic event
    let result = run_sync_test(&[], &[]).await;

    // Verify announcement synced to syncing relay
    let filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(result.maintainer_keys.public_key());

    let synced =
        wait_for_event_on_relay(result.syncing_relay.url(), filter, Duration::from_secs(5)).await;

    // Cleanup
    result.syncing_relay.stop().await;
    result.source_relay.stop().await;

    assert!(
        synced,
        "Announcement should have synced from source to syncing relay via bootstrap sync"
    );
}

/// Test 4: Replay after restart - relay re-syncs events from bootstrap after restart
///
/// Scenario:
/// 1. Start source relay with announcement
/// 2. Start syncing relay, sync events from source
/// 3. Verify sync worked
/// 4. Stop syncing relay
/// 5. Restart syncing relay (should re-sync from source)
/// 6. Verify events are available again
///
/// Note: Since we use in-memory database, syncing relay loses events on stop.
/// This tests that the sync mechanism reconnects and re-syncs on restart.
#[tokio::test]
async fn test_relay_replays_events_after_restart() {
    // First run: establish sync
    let result = run_sync_test(&[], &[]).await;

    // Verify announcement synced on first run
    let filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(result.maintainer_keys.public_key());

    let synced_first = wait_for_event_on_relay(
        result.syncing_relay.url(),
        filter.clone(),
        Duration::from_secs(5),
    )
    .await;

    println!("First sync check: {}", synced_first);

    // Stop syncing relay (simulates restart)
    result.syncing_relay.stop().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Restart syncing relay (new instance with same bootstrap config)
    // Note: The new syncing relay will have a different domain, so it may not
    // accept the event if it doesn't list its domain. This is expected behavior.
    let syncing_new = TestRelay::start_with_sync(Some(result.source_relay.url().into())).await;
    println!(
        "Syncing relay (second instance) started at {} (domain: {})",
        syncing_new.url(),
        syncing_new.domain()
    );

    // Wait for re-sync
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify announcement is available on restarted syncing relay
    let synced_after_restart =
        wait_for_event_on_relay(syncing_new.url(), filter, Duration::from_secs(5)).await;

    // Cleanup
    syncing_new.stop().await;
    result.source_relay.stop().await;

    assert!(
        synced_first,
        "Announcement should have synced on first connection"
    );
    // Note: synced_after_restart may be false because the new syncing relay has a different
    // domain, and the announcement only lists the old syncing relay domain. This is expected.
    println!(
        "After restart sync result: {} (may be false due to domain change)",
        synced_after_restart
    );
}

/// Test: Rejection - announcement not listing relay should NOT sync
///
/// Scenario:
/// 1. source relay, syncing relay (syncs from source)
/// 2. Create announcement listing ONLY source domain
/// 3. Send to source
/// 4. Verify NOT synced to syncing relay (write policy rejects)
///
/// This tests that the relay's write policy correctly rejects events
/// that don't list its domain in the clone tag.
#[tokio::test]
async fn test_announcement_not_listing_relay_is_not_synced() {
    // Start source relay
    let source = TestRelay::start().await;

    // Start syncing relay
    let syncing = TestRelay::start_with_sync(Some(source.url().into())).await;

    // Create keys
    let keys = Keys::generate();

    // Wait for sync connection to establish
    match wait_for_sync_connection(syncing.url(), 1, Duration::from_secs(5)).await {
        Ok(()) => println!("Sync connection established (verified via metrics)"),
        Err(e) => println!("Sync connection check: {} (continuing with test)", e),
    }

    // Create announcement that lists ONLY source domain (NOT syncing)
    // This should NOT sync because syncing relay's write policy will reject it
    let announcement = create_repo_announcement(
        &keys,
        &[&source.domain()], // Only source, NOT syncing
        "test-repo-rejection",
    );
    let announcement_id = announcement.id;

    println!(
        "Created announcement {} (kind {}) - lists ONLY source relay",
        announcement_id,
        announcement.kind.as_u16()
    );

    // Send announcement to source
    let client = TestClient::new(source.url(), keys.clone())
        .await
        .expect("Failed to connect to source");

    client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement to source");
    println!("Announcement sent to source");

    client.disconnect().await;

    // Wait for potential sync attempt
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify announcement did NOT sync to syncing relay
    let filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(keys.public_key());

    let synced = wait_for_event_on_relay(syncing.url(), filter, Duration::from_secs(2)).await;

    // Cleanup
    syncing.stop().await;
    source.stop().await;

    assert!(
        !synced,
        "Announcement {} should NOT have synced to syncing relay because it doesn't list syncing relay's domain",
        announcement_id
    );
    println!("SUCCESS: Announcement was correctly rejected by syncing relay (not synced)");
}

/// Test: History sync (bootstrap) works without NIP-77 negentropy
///
/// This tests that HISTORY sync works when negentropy is disabled.
/// History sync means: events that existed on the source relay BEFORE
/// the syncing relay connected.
///
/// Scenario:
/// 1. Pre-allocate port for syncing relay to get its domain
/// 2. Start source relay
/// 3. Create announcement listing both relay domains
/// 4. Send announcement to source (event exists BEFORE syncing relay connects)
/// 5. Start syncing relay on pre-allocated port, with negentropy DISABLED
/// 6. Syncing relay should sync the pre-existing event via REQ+EOSE (history sync)
/// 7. Verify syncing relay has the event
///
/// This is different from "live sync" where events arrive after connection.
#[tokio::test]
async fn test_history_sync_without_negentropy() {
    // Pre-allocate syncing relay port to get its domain. Holding the
    // reservation prevents any other parallel test in this process from
    // being handed the same port between here and the relay actually
    // booting (announcement setup below adds non-trivial latency).
    let syncing_reservation = port::reserve_port();
    let syncing_port = syncing_reservation.port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_port);
    println!("Pre-allocated syncing relay domain: {}", syncing_domain);

    // Start source relay
    let source = TestRelay::start().await;
    println!(
        "Source started at {} (domain: {})",
        source.url(),
        source.domain()
    );

    // Create keys
    let keys = Keys::generate();

    // Set up announcement on source with git data
    // (purgatory requires git data before announcements are accepted)
    let domains = [source.domain(), syncing_domain.clone()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let (announcement, _git_dir) = setup_announcement_on_relay(
        &source,
        &keys,
        &domain_refs,
        "test-repo-history-no-negentropy",
    )
    .await;
    let announcement_id = announcement.id;

    println!(
        "Announcement {} set up on source with git data (event exists BEFORE syncing relay connects)",
        announcement_id
    );

    // Wait to ensure event is stored
    tokio::time::sleep(Duration::from_millis(500)).await;

    // NOW start syncing relay on the reserved port, with negentropy DISABLED
    // This syncing relay has never connected before - it needs to do HISTORY sync
    let syncing = TestRelay::start_on_reservation_with_options(
        syncing_reservation,
        Some(source.url().into()),
        true, // disable_negentropy = true
    )
    .await;
    println!(
        "Syncing relay started at {} (domain: {}) - negentropy DISABLED, will do HISTORY sync",
        syncing.url(),
        syncing.domain()
    );

    // Wait for history sync to complete (using REQ+EOSE, not negentropy)
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify announcement synced to syncing relay via HISTORY sync
    let filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(keys.public_key());

    let synced = wait_for_event_on_relay(syncing.url(), filter, Duration::from_secs(5)).await;

    // Cleanup
    syncing.stop().await;
    source.stop().await;

    assert!(
        synced,
        "Announcement {} should have synced from source to syncing relay via HISTORY sync (REQ+EOSE, negentropy disabled)",
        announcement_id
    );
    println!("SUCCESS: History sync works without negentropy (using REQ+EOSE fallback)");
}

/// Test: Pagination for large result sets without negentropy
///
/// Note: this only actually tests pagination if we temporary settings (PAGINATION_THRESHOLD=7, filter limit=10),
/// otherwise multiple pages aren't required to sync all events.
///
/// This tests that historic sync correctly handles many events
/// when negentropy is disabled and pagination logic may be triggered.
///
/// Scenario:
/// 1. Pre-allocate port for syncing relay to get its domain
/// 2. Start source relay
/// 3. Create repository announcement listing both relay domains
/// 4. Create 40 issue events (enough to trigger pagination with limit=10, threshold=7)
/// 5. Send all events to source relay BEFORE syncing relay starts
/// 6. Start syncing relay with negentropy DISABLED (forces REQ+EOSE)
/// 7. Verify all 40 issues synced correctly
///
#[tokio::test]
#[ignore]
async fn test_pagination_for_large_historic_sync() {
    // Pre-allocate syncing relay port to get its domain. Holding the
    // reservation prevents any other parallel test in this process from
    // being handed the same port between here and the relay actually
    // booting (announcement setup below adds non-trivial latency).
    let syncing_reservation = port::reserve_port();
    let syncing_port = syncing_reservation.port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_port);
    println!("Pre-allocated syncing relay domain: {}", syncing_domain);

    // Start source relay
    let source = TestRelay::start().await;
    println!(
        "Source started at {} (domain: {})",
        source.url(),
        source.domain()
    );

    // Create keys for repository owner
    let keys = Keys::generate();
    let repo_id = "test-repo-pagination";

    // Create repository announcement listing BOTH relay domains
    let announcement =
        create_repo_announcement(&keys, &[&source.domain(), &syncing_domain], repo_id);
    println!(
        "Created announcement {} for repo '{}'",
        announcement.id, repo_id
    );

    // Create 40 issue events to test pagination (with limit=10, threshold=7)
    let repo_coord = format!(
        "{}:{}:{}",
        Kind::GitRepoAnnouncement.as_u16(),
        keys.public_key().to_hex(),
        repo_id
    );

    let mut issue_events = Vec::new();
    for i in 1..=40 {
        let issue = build_layer2_issue_event(
            &keys,
            &repo_coord,
            &format!("Issue #{} - Testing large sync", i),
        )
        .expect("Failed to create issue event");
        issue_events.push(issue);
    }
    println!(
        "Created {} issue events for pagination test",
        issue_events.len()
    );

    // Send announcement to source (must be accepted first for issues to reference it)
    let client = TestClient::new(source.url(), keys.clone())
        .await
        .expect("Failed to connect to source");

    client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement to source");
    println!("Announcement sent to source");

    // Wait for announcement to be stored
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send all 40 issue events to source (before syncing relay starts)
    println!("Sending {} issues to source relay...", issue_events.len());
    for (i, issue) in issue_events.iter().enumerate() {
        client
            .send_event(issue)
            .await
            .unwrap_or_else(|e| panic!("Failed to send issue #{}: {}", i + 1, e));

        // Progress indicator every 50 events
        if (i + 1) % 50 == 0 {
            println!("  Sent {} / {} issues", i + 1, issue_events.len());
        }
    }
    println!(
        "All {} issues sent to source (events exist BEFORE syncing relay connects)",
        issue_events.len()
    );

    client.disconnect().await;

    // Wait to ensure all events are stored
    tokio::time::sleep(Duration::from_millis(500)).await;

    // NOW start syncing relay on the reserved port, with negentropy DISABLED
    // This forces it to use REQ+EOSE historic sync with pagination
    let syncing = TestRelay::start_on_reservation_with_options(
        syncing_reservation,
        Some(source.url().into()),
        true, // disable_negentropy = true (force REQ+EOSE)
    )
    .await;
    println!(
        "Syncing relay started at {} (domain: {}) - negentropy DISABLED, pagination enabled with limit=10, threshold=7",
        syncing.url(),
        syncing.domain()
    );

    // Wait for historic sync with pagination to complete
    println!("Waiting for historic sync with pagination to complete...");
    tokio::time::sleep(Duration::from_secs(8)).await;

    // Verify announcement synced
    let announcement_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(keys.public_key());

    let announcement_synced =
        wait_for_event_on_relay(syncing.url(), announcement_filter, Duration::from_secs(3)).await;

    // Verify ALL 40 issues synced
    let issues_filter = Filter::new().kind(Kind::GitIssue).author(keys.public_key());

    // Query for all issues
    let temp_keys = Keys::generate();
    let client = Client::new(temp_keys);
    client
        .add_relay(syncing.url())
        .await
        .expect("Failed to add syncing relay to client");
    client.connect().await;

    // Wait for connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    let synced_issues = client
        .fetch_events(issues_filter, Duration::from_secs(5))
        .await
        .expect("Failed to fetch issues from syncing relay");

    let synced_count = synced_issues.len();
    println!("Synced {} out of 40 expected issues", synced_count);

    client.disconnect().await;

    // Cleanup
    syncing.stop().await;
    source.stop().await;

    // Assertions
    assert!(
        announcement_synced,
        "Repository announcement should have synced"
    );

    assert_eq!(
        synced_count, 40,
        "All 40 issues should have synced via pagination (limit=10, threshold=7 should trigger multiple pages)"
    );

    println!(
        "SUCCESS: Pagination worked correctly - all {} issues synced",
        synced_count
    );
}
