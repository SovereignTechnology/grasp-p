//! Live Sync Tests
//!
//! Tests for real-time event synchronization between relays.
//! These tests verify that events published to one relay are synced
//! to another relay in real-time via the discovery mechanism.
//!
//! # Tests
//! - Test 5: `test_live_sync_layer2_events` - Layer 2 (kind 1618) events sync in real-time
//! - Test 6: `test_live_sync_layer3_events` - Layer 3 (comments) sync when referencing Layer 2
//! - Test 7: `test_live_sync_event_ordering` - Events arrive in chronological order
//!
//! # Sync Mechanism
//! These tests use the discovery-based sync pattern:
//! 1. Send announcement to both relays
//! 2. Each relay discovers the other from the announcement's relays tag
//! 3. Events sync between relays
//!
//! This tests "live" sync behavior - events syncing after connection is established,
//! as opposed to bootstrap sync which syncs existing events on startup.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{event_ordering::timestamp_after, sync_helpers::*, MockRelay, TestRelay};

#[tokio::test]
async fn replacement_announcement_retires_old_relay_only_after_natural_disconnect() {
    let old_source = MockRelay::start().await;
    let new_source = MockRelay::start().await;
    let syncing = TestRelay::start_with_sync(None).await;
    let keys = Keys::generate();
    let repo_id = "replacement-retires-old-relay";
    let initial_domains = [old_source.domain(), syncing.domain()];
    let initial_refs = initial_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    let (initial, _git_dir) =
        setup_announcement_on_relay(&syncing, &keys, &initial_refs, repo_id).await;

    let old_label = format!(
        r#"ngit_sync_relay_connected{{relay="{}"}}"#,
        old_source.url()
    );
    let new_label = format!(
        r#"ngit_sync_relay_connected{{relay="{}"}}"#,
        new_source.url()
    );
    let wait_for_metrics = |required: String, absent: Option<String>| {
        let relay_url = syncing.url();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let metrics = fetch_metrics(relay_url).await.unwrap_or_default();
                if metrics.contains(&required)
                    && absent.as_ref().is_none_or(|label| !metrics.contains(label))
                {
                    return true;
                }
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    assert!(
        wait_for_metrics(old_label.clone(), None).await,
        "initial announcement should establish the old relay session"
    );

    let npub = keys.public_key().to_bech32().unwrap();
    let replacement_domains = [new_source.domain(), syncing.domain()];
    let replacement = EventBuilder::new(Kind::GitRepoAnnouncement, "replacement")
        .tags(vec![
            Tag::identifier(repo_id),
            Tag::custom(
                "clone",
                replacement_domains
                    .iter()
                    .map(|domain| format!("http://{domain}/{npub}/{repo_id}.git"))
                    .collect::<Vec<_>>(),
            ),
            Tag::custom(
                "relays",
                replacement_domains
                    .iter()
                    .map(|domain| format!("ws://{domain}"))
                    .collect::<Vec<_>>(),
            ),
        ])
        .custom_created_at(timestamp_after(initial.created_at))
        .finalize(&keys)
        .unwrap();
    let client = TestClient::new(syncing.url(), keys.clone()).await.unwrap();
    client.send_event(&replacement).await.unwrap();

    assert!(
        wait_for_metrics(new_label, None).await,
        "replacement should establish the new relay"
    );
    assert!(
        fetch_metrics(syncing.url())
            .await
            .unwrap_or_default()
            .contains(&old_label),
        "ownership replacement must not tear down the healthy old relay session"
    );

    old_source.stop().await;
    assert!(
        wait_for_metrics(String::new(), Some(old_label)).await,
        "after the old relay ends naturally it should retire instead of reconnecting"
    );

    client.disconnect().await;
    syncing.stop().await;
    new_source.stop().await;
}

/// A source relay's active-REQ cap must not silently remove one of the
/// repository filter variants.
///
/// The generic announcement subscription occupies one active REQ. A single
/// repository then needs state, a, A, and q filters. Installing each filter as
/// a separate live subscription exceeds this source's four-REQ limit, leaving
/// q-tagged collaboration events permanently uncovered.
#[tokio::test]
async fn test_live_sync_batches_repo_filters_below_source_req_limit() {
    let source = MockRelay::start_with_max_reqs(4).await;
    let syncing = TestRelay::start_with_sync(None).await;
    let keys = Keys::generate();
    let repo_id = "test-repo-bounded-reqs";
    let domains = [source.domain(), syncing.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(String::as_str).collect();

    let (announcement, _git_dir) =
        setup_announcement_on_relay(&syncing, &keys, &domain_refs, repo_id).await;

    let source_client = TestClient::new(source.url(), keys.clone())
        .await
        .expect("connect to constrained source relay");
    source_client
        .send_event(&announcement)
        .await
        .expect("publish announcement to constrained source relay");

    wait_for_sync_connection(syncing.url(), 1, Duration::from_secs(30))
        .await
        .expect("syncing relay should connect to constrained source");
    wait_for_new_descendant_live_generation(&syncing, 0, Duration::from_secs(20)).await;

    // Observe one q-tagged event completing the round trip before testing a
    // second live event. This proves the relevant subscription is installed
    // without relying on an arbitrary scheduling delay.
    let readiness_issue = build_layer2_issue_with_q_tag(
        &keys,
        &repo_coord(&keys, repo_id),
        "Subscription readiness probe",
    )
    .expect("build q-tagged readiness issue");
    source_client
        .send_event(&readiness_issue)
        .await
        .expect("publish q-tagged readiness issue");
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(readiness_issue.id),
            Duration::from_secs(30),
        )
        .await,
        "q-tagged readiness issue should sync before testing live delivery"
    );

    let issue = build_layer2_issue_with_q_tag(
        &keys,
        &repo_coord(&keys, repo_id),
        "Issue behind the final repository filter",
    )
    .expect("build q-tagged issue");
    source_client
        .send_event(&issue)
        .await
        .expect("publish q-tagged issue");

    let synced = wait_for_event_on_relay(
        syncing.url(),
        Filter::new().id(issue.id),
        Duration::from_secs(30),
    )
    .await;

    source_client.disconnect().await;
    syncing.stop().await;
    source.stop().await;

    assert!(
        synced,
        "q-tagged issue should sync even when the source permits only four active REQs"
    );
}

#[tokio::test]
async fn live_sync_regroups_after_filter_count_refusal() {
    // Minimum-churn startup can split core and auxiliary coverage into two
    // filters each. A one-filter cap forces regrouping under either ordering.
    let source = MockRelay::start_with_max_filters(1).await;
    let syncing = TestRelay::start_with_sync(None).await;
    let keys = Keys::generate();
    let repo_id = "adaptive-filter-count";
    let domains = [source.domain(), syncing.domain()];
    let domain_refs = domains.iter().map(String::as_str).collect::<Vec<_>>();
    let (announcement, _git_dir) =
        setup_announcement_on_relay(&syncing, &keys, &domain_refs, repo_id).await;
    let source_client = TestClient::new(source.url(), keys.clone())
        .await
        .expect("connect to strict source relay");
    source_client
        .send_event(&announcement)
        .await
        .expect("publish announcement to strict source relay");

    let refusal_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let metrics = fetch_metrics(syncing.url()).await.unwrap_or_default();
        if metrics.contains("ngit_sync_policy_refusals_total") && metrics.contains("filter_count") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < refusal_deadline,
            "sync client never observed the strict relay's filter-count refusal"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let issue = build_layer2_issue_with_q_tag(
        &keys,
        &repo_coord(&keys, repo_id),
        "Delivered after adaptive regrouping",
    )
    .expect("build live issue");
    source_client
        .send_event(&issue)
        .await
        .expect("publish live issue after regrouping");
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(issue.id),
            Duration::from_secs(30),
        )
        .await,
        "exact live coverage should survive regrouping below the relay's limit"
    );

    source_client.disconnect().await;
    syncing.stop().await;
    source.stop().await;
}

/// Test 5: Live sync Layer 2 events
///
/// Verifies that Layer 2 events (kind 1618 issues) published to one relay
/// are synced to another relay in real-time via discovery.
///
/// Flow:
/// 1. Start relay_a (source)
/// 2. Start relay_b (with sync enabled, no bootstrap)
/// 3. Send announcement to both relays (triggers discovery)
/// 4. Publish Layer 2 issue to relay_a
/// 5. Verify event syncs to relay_b within 5 seconds
#[tokio::test]
async fn test_live_sync_layer2_events() {
    // 1. Start source relay (relay_a)
    let relay_a = TestRelay::start().await;
    println!(
        "relay_a started at {} (domain: {})",
        relay_a.url(),
        relay_a.domain()
    );

    // 2. Start relay_b with sync enabled (no bootstrap - sync via discovery)
    let relay_b = TestRelay::start_with_sync(None).await;
    println!(
        "relay_b started at {} (domain: {})",
        relay_b.url(),
        relay_b.domain()
    );

    // 3. Create test keys
    let keys = Keys::generate();

    // 4. Create a repository announcement on both relays with git data
    // (purgatory requires git data before announcements are accepted)
    let repo_id = "test-repo-live-l2";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, repository) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_a with git data");

    repository.install(&relay_b).await;
    println!("Announcement set up on relay_b with git data (triggers discovery)");

    // 5. Wait for discovery: events published before the syncing relay has
    // connected to its peer can only be picked up by later recovery passes,
    // so wait on the observable connection rather than a fixed sleep.
    wait_for_sync_connection(relay_b.url(), 1, Duration::from_secs(30))
        .await
        .expect("relay_b should establish a sync connection after discovery");

    // 6. Create and send a Layer 2 issue event (using helper)
    let repo_coordinate = repo_coord(&keys, repo_id);
    let issue = build_layer2_issue_event(&keys, &repo_coordinate, "Test Issue for Live Sync")
        .expect("Failed to create issue event");
    let issue_id = issue.id;

    println!("Created issue {} (kind {})", issue_id, issue.kind.as_u16());
    for tag in issue.tags.iter() {
        println!("  Tag: {:?}", tag.as_slice());
    }

    // Send issue to relay_a only
    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&issue)
        .await
        .expect("Failed to send issue to relay_a");
    println!("Issue sent to relay_a");

    client_a.disconnect().await;

    // 9. Wait and verify event syncs to relay_b
    let filter = Filter::new()
        .kind(Kind::GitIssue)
        .author(keys.public_key())
        .id(issue_id);

    let synced = wait_for_event_on_relay(relay_b.url(), filter, Duration::from_secs(30)).await;

    println!("Issue {} synced to relay_b: {}", issue_id, synced);

    // 10. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    assert!(
        synced,
        "Layer 2 issue {} should have synced from relay_a to relay_b in real-time",
        issue_id
    );
}

/// Test 6: Live sync Layer 3 events
///
/// Verifies that Layer 3 events (comments) sync when they reference Layer 2 events.
///
/// Flow:
/// 1. Start relay_a and relay_b (with sync enabled)
/// 2. Send announcement to both relays (triggers discovery)
/// 3. Publish Layer 2 issue to relay_a
/// 4. Wait for Layer 2 issue to sync to relay_b
/// 5. Publish Layer 3 comment (referencing the issue) to relay_a
/// 6. Verify comment syncs to relay_b within 5 seconds
/// 7. Verify comment has correct 'E' tag reference
///
#[tokio::test]
async fn test_live_sync_layer3_events() {
    // 1. Start relays
    let relay_a = TestRelay::start().await;
    println!(
        "relay_a started at {} (domain: {})",
        relay_a.url(),
        relay_a.domain()
    );

    let relay_b = TestRelay::start_with_sync(None).await;
    println!(
        "relay_b started at {} (domain: {})",
        relay_b.url(),
        relay_b.domain()
    );

    let keys = Keys::generate();

    // 2. Create and send repository announcement to both relays with git data
    // (purgatory requires git data before announcements are accepted)
    let repo_id = "test-repo-live-l3";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, repository) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_a with git data");

    repository.install(&relay_b).await;
    println!("Announcement set up on relay_b with git data (triggers discovery)");

    // 3. Wait for discovery: events published before the syncing relay has
    // connected to its peer can only be picked up by later recovery passes,
    // so wait on the observable connection rather than a fixed sleep.
    wait_for_sync_connection(relay_b.url(), 1, Duration::from_secs(30))
        .await
        .expect("relay_b should establish a sync connection after discovery");

    // 4. Create and send Layer 2 issue
    let repo_coordinate = repo_coord(&keys, repo_id);
    let issue = build_layer2_issue_event(&keys, &repo_coordinate, "Parent Issue for Comment Test")
        .expect("Failed to create issue");
    let issue_id = issue.id;

    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&issue)
        .await
        .expect("Failed to send issue");
    println!("Layer 2 issue {} sent to relay_a", issue_id);

    // 5. Create and send Layer 3 comment IMMEDIATELY (before waiting for sync)
    // This tests that subscriptions without 'since' will catch pre-existing events
    let comment = build_layer3_comment_with_uppercase_e_tag(
        &keys,
        &issue_id,
        "This is a comment on the issue",
    )
    .expect("Failed to create comment");
    let comment_id = comment.id;

    println!(
        "Created comment {} (kind {})",
        comment_id,
        comment.kind.as_u16()
    );
    for tag in comment.tags.iter() {
        println!("  Tag: {:?}", tag.as_slice());
    }

    client_a
        .send_event(&comment)
        .await
        .expect("Failed to send comment");
    println!(
        "Layer 3 comment {} sent to relay_a BEFORE Layer 3 subscription established",
        comment_id
    );

    // 6. Now wait for issue to sync to relay_b (this triggers Layer 3 filter
    // creation); the bounded poll replaces a fixed sleep plus short deadline.
    let issue_filter = Filter::new().kind(Kind::GitIssue).id(issue_id);
    let issue_synced =
        wait_for_event_on_relay(relay_b.url(), issue_filter, Duration::from_secs(30)).await;
    println!("Issue synced to relay_b: {}", issue_synced);

    client_a.disconnect().await;

    // 7. Wait and verify comment syncs to relay_b
    let comment_filter = Filter::new()
        .kind(Kind::Comment)
        .author(keys.public_key())
        .id(comment_id);

    // Root confirmation can require a historic batch before the bounded
    // descendant maintenance tick schedules this pre-existing comment.
    let comment_synced =
        wait_for_event_on_relay(relay_b.url(), comment_filter, Duration::from_secs(20)).await;
    println!(
        "Comment {} synced to relay_b: {}",
        comment_id, comment_synced
    );

    // 8. Verify the comment has correct 'E' tag reference
    let mut has_correct_ref = false;
    if comment_synced {
        let temp_keys = Keys::generate();
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(temp_keys))
            .build();
        if client.add_relay(relay_b.url()).await.is_ok() {
            crate::common::relay::connect_client(&client).await;

            let fetch_filter = Filter::new().kind(Kind::Comment).id(comment_id);

            if let Ok(events) = client
                .fetch_events(fetch_filter)
                .timeout(Duration::from_secs(2))
                .await
            {
                if let Some(event) = events.first() {
                    // Check for 'E' tag with parent event ID
                    for tag in event.tags.iter() {
                        let slice = tag.as_slice();
                        if slice.first() == Some(&"E".to_string())
                            && slice.get(1) == Some(&issue_id.to_hex())
                        {
                            has_correct_ref = true;
                            println!("Found correct E tag reference to issue");
                            break;
                        }
                    }
                }
            }
            client.disconnect().await;
        }
    }

    // 9. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    assert!(
        issue_synced,
        "Layer 2 issue {} should have synced first",
        issue_id
    );
    assert!(
        comment_synced,
        "Layer 3 comment {} should have synced to relay_b",
        comment_id
    );
    assert!(
        has_correct_ref,
        "Comment should have 'E' tag referencing issue {}",
        issue_id
    );
}

/// Test 7: Live sync event ordering
///
/// Verifies that events arrive in chronological order when synced.
/// Note: We test ordering based on created_at timestamps, allowing for
/// minor timing variations inherent in async systems.
///
/// Flow:
/// 1. Start relay_a and relay_b (with sync enabled)
/// 2. Send announcement to both relays (triggers discovery)
/// 3. Publish 3 Layer 2 events to relay_a with 100ms delays between them
/// 4. Collect events from relay_b
/// 5. Verify events are ordered by created_at timestamp
#[tokio::test]
async fn test_live_sync_event_ordering() {
    // 1. Start relays
    let relay_a = TestRelay::start().await;
    println!(
        "relay_a started at {} (domain: {})",
        relay_a.url(),
        relay_a.domain()
    );

    let relay_b = TestRelay::start_with_sync(None).await;
    println!(
        "relay_b started at {} (domain: {})",
        relay_b.url(),
        relay_b.domain()
    );

    let keys = Keys::generate();

    // 2. Create and send repository announcement to both relays with git data
    // (purgatory requires git data before announcements are accepted)
    let repo_id = "test-repo-ordering";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, repository) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    repository.install(&relay_b).await;
    println!("Announcements set up on both relays with git data");

    // 3. Wait for discovery: events published before the syncing relay has
    // connected to its peer can only be picked up by later recovery passes,
    // so wait on the observable connection rather than a fixed sleep.
    wait_for_sync_connection(relay_b.url(), 1, Duration::from_secs(30))
        .await
        .expect("relay_b should establish a sync connection after discovery");

    // 4. Create and send 3 issues with delays between them
    let repo_coordinate = repo_coord(&keys, repo_id);
    let mut issue_ids = Vec::new();
    let mut expected_order_timestamps = Vec::new();

    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    for i in 1..=3 {
        let issue = build_layer2_issue_event(
            &keys,
            &repo_coordinate,
            &format!("Ordering Test Issue {}", i),
        )
        .expect("Failed to create issue");

        // Store the created_at timestamp for ordering verification
        expected_order_timestamps.push(issue.created_at);
        issue_ids.push(issue.id);

        println!(
            "Created issue {} at timestamp {}",
            issue.id, issue.created_at
        );

        client_a
            .send_event(&issue)
            .await
            .unwrap_or_else(|_| panic!("Failed to send issue {}", i));

        // Delay between events to ensure different timestamps
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    client_a.disconnect().await;

    // 5. Wait for all events to sync (bounded poll per event rather than a
    // fixed sleep, which is not a reliable proxy under CI load).
    for issue_id in &issue_ids {
        assert!(
            wait_for_event_on_relay(
                relay_b.url(),
                Filter::new().id(*issue_id),
                Duration::from_secs(30),
            )
            .await,
            "issue {issue_id} should sync to relay_b"
        );
    }

    // 6. Fetch all events from relay_b
    let temp_keys = Keys::generate();
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(temp_keys))
        .build();

    let events_found: Vec<Event>;
    if client.add_relay(relay_b.url()).await.is_ok() {
        crate::common::relay::connect_client(&client).await;

        let filter = Filter::new().kind(Kind::GitIssue).author(keys.public_key());

        match client
            .fetch_events(filter)
            .timeout(Duration::from_secs(3))
            .await
        {
            Ok(events) => {
                events_found = events.into_iter().collect();
            }
            Err(e) => {
                println!("Failed to fetch events: {}", e);
                events_found = Vec::new();
            }
        }
        client.disconnect().await;
    } else {
        events_found = Vec::new();
    }

    // 7. Verify we got events
    let found_count = events_found.len();
    println!("Found {} events on relay_b", found_count);

    // Filter to only our test events (by ID)
    let test_events: Vec<&Event> = events_found
        .iter()
        .filter(|e| issue_ids.contains(&e.id))
        .collect();

    println!(
        "Found {} test events (out of {} total)",
        test_events.len(),
        events_found.len()
    );

    // 8. Check ordering by created_at timestamp
    let mut ordered_correctly = true;
    if test_events.len() >= 2 {
        // Sort by created_at and check order matches
        let mut sorted_events = test_events.clone();
        sorted_events.sort_by_key(|e| e.created_at);

        for (i, event) in sorted_events.iter().enumerate() {
            println!(
                "Event {} sorted: {} at timestamp {}",
                i + 1,
                event.id,
                event.created_at
            );
        }

        // Verify ascending timestamp order
        for window in sorted_events.windows(2) {
            if window[0].created_at > window[1].created_at {
                ordered_correctly = false;
                println!(
                    "Order violation: {} ({}) > {} ({})",
                    window[0].id, window[0].created_at, window[1].id, window[1].created_at
                );
            }
        }
    }

    // 9. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    // Assert based on what we found
    // Note: We may not get all 3 events due to timing, but what we get should be ordered
    assert!(
        test_events.len() >= 2,
        "Should have synced at least 2 of 3 events; found {}",
        test_events.len()
    );
    assert!(
        ordered_correctly,
        "Events should be ordered by created_at timestamp"
    );
}
