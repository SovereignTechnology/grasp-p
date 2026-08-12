//! Tag Variation Tests
//!
//! Tests for different tag types used in Layer 2 and Layer 3 events.
//! Ensures the relay correctly handles all valid NIP tag patterns.
//!
//! # Layer 2 Tag Variations (Tests 8a-c)
//! - Test 8a: Lowercase 'a' tag (standard NIP-01 addressable reference)
//! - Test 8b: Uppercase 'A' tag (NIP-33 parameterized replaceable)
//! - Test 8c: Quote 'q' tag (NIP-18 reposts/quotes)
//!
//! # Layer 3 Tag Variations (Tests 9a-c)
//! - Test 9a: Lowercase 'e' tag (standard NIP-01 event reference)
//! - Test 9b: Uppercase 'E' tag (NIP-22 comments)
//! - Test 9c: Quote 'q' tag (NIP-18 quotes)
//!
//! # Sync Mechanism
//! All tests use discovery-based sync:
//! 1. Send announcement to both relays (triggers discovery)
//! 2. Publish test event to relay_a
//! 3. Verify event syncs to relay_b

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{sync_helpers::*, TestRelay};

// ============================================================================
// Layer 2 Tag Variation Tests (Tests 8a-c)
// ============================================================================

/// Test 8a: Layer 2 sync with lowercase 'a' tag (standard NIP-01)
///
/// Verifies that Layer 2 events (kind 1618 issues) with standard lowercase 'a'
/// tags sync correctly between relays.
///
/// The lowercase 'a' tag is the standard NIP-01 way to reference addressable
/// events (those with a d-tag, like repository announcements).
#[tokio::test]
async fn test_layer2_sync_with_lowercase_a_tag() {
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
    let repo_id = "test-repo-tag-8a";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, _git_dir_a) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_a with git data");

    let (_announcement_b, _git_dir_b) =
        setup_announcement_on_relay(&relay_b, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_b with git data (triggers discovery)");

    // 3. Wait for discovery
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 4. Create and send Layer 2 issue with lowercase 'a' tag
    let repo_coordinate = repo_coord(&keys, repo_id);
    let issue =
        build_layer2_issue_event(&keys, &repo_coordinate, "Test Issue with lowercase a tag")
            .expect("Failed to create issue event");
    let issue_id = issue.id;

    println!(
        "Created issue {} (kind {}) with lowercase 'a' tag",
        issue_id,
        issue.kind.as_u16()
    );

    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&issue)
        .await
        .expect("Failed to send issue to relay_a");
    println!("Issue sent to relay_a");

    client_a.disconnect().await;

    // 5. Wait and verify event syncs to relay_b
    let filter = Filter::new()
        .kind(Kind::GitIssue)
        .author(keys.public_key())
        .id(issue_id);

    let synced = wait_for_event_on_relay(relay_b.url(), filter, Duration::from_secs(5)).await;

    println!("Issue {} synced to relay_b: {}", issue_id, synced);

    // 6. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    assert!(
        synced,
        "Layer 2 issue with lowercase 'a' tag should have synced to relay_b"
    );
}

/// Test 8b: Layer 2 sync with uppercase 'A' tag (NIP-33)
///
/// Verifies that Layer 2 events (kind 1618 issues) with uppercase 'A'
/// tags sync correctly between relays.
///
/// The uppercase 'A' tag is used in NIP-33 for parameterized replaceable
/// events references.
#[tokio::test]
async fn test_layer2_sync_with_uppercase_a_tag() {
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
    let repo_id = "test-repo-tag-8b";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, _git_dir_a) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_a with git data");

    let (_announcement_b, _git_dir_b) =
        setup_announcement_on_relay(&relay_b, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_b with git data (triggers discovery)");

    // 3. Wait for discovery
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 4. Create and send Layer 2 issue with uppercase 'A' tag
    let repo_coordinate = repo_coord(&keys, repo_id);
    let issue = build_layer2_issue_with_uppercase_a_tag(
        &keys,
        &repo_coordinate,
        "Test Issue with uppercase A tag",
    )
    .expect("Failed to create issue event");
    let issue_id = issue.id;

    println!(
        "Created issue {} (kind {}) with uppercase 'A' tag",
        issue_id,
        issue.kind.as_u16()
    );

    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&issue)
        .await
        .expect("Failed to send issue to relay_a");
    println!("Issue sent to relay_a");

    client_a.disconnect().await;

    // 5. Wait and verify event syncs to relay_b
    let filter = Filter::new()
        .kind(Kind::GitIssue)
        .author(keys.public_key())
        .id(issue_id);

    let synced = wait_for_event_on_relay(relay_b.url(), filter, Duration::from_secs(5)).await;

    println!("Issue {} synced to relay_b: {}", issue_id, synced);

    // 6. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    assert!(
        synced,
        "Layer 2 issue with uppercase 'A' tag should have synced to relay_b"
    );
}

/// Test 8c: Layer 2 sync with 'q' (quote) tag (NIP-18)
///
/// Verifies that Layer 2 events (kind 1618 issues) with 'q' (quote)
/// tags sync correctly between relays.
///
/// The 'q' tag is used in NIP-18 for reposts and quotes.
#[tokio::test]
async fn test_layer2_sync_with_q_tag() {
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
    let repo_id = "test-repo-tag-8c";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, _git_dir_a) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_a with git data");

    let (_announcement_b, _git_dir_b) =
        setup_announcement_on_relay(&relay_b, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_b with git data (triggers discovery)");

    // 3. Wait for discovery
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 4. Create and send Layer 2 issue with 'q' tag
    let repo_coordinate = repo_coord(&keys, repo_id);
    let issue = build_layer2_issue_with_q_tag(&keys, &repo_coordinate, "Test Issue with q tag")
        .expect("Failed to create issue event");
    let issue_id = issue.id;

    println!(
        "Created issue {} (kind {}) with 'q' tag",
        issue_id,
        issue.kind.as_u16()
    );

    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&issue)
        .await
        .expect("Failed to send issue to relay_a");
    println!("Issue sent to relay_a");

    client_a.disconnect().await;

    // 5. Wait and verify event syncs to relay_b
    let filter = Filter::new()
        .kind(Kind::GitIssue)
        .author(keys.public_key())
        .id(issue_id);

    let synced = wait_for_event_on_relay(relay_b.url(), filter, Duration::from_secs(5)).await;

    println!("Issue {} synced to relay_b: {}", issue_id, synced);

    // 6. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    assert!(
        synced,
        "Layer 2 issue with 'q' tag should have synced to relay_b"
    );
}

// ============================================================================
// Layer 3 Tag Variation Tests (Tests 9a-c)
// ============================================================================

/// Test 9a: Layer 3 sync with lowercase 'e' tag (standard NIP-01)
///
/// Verifies that Layer 3 events (kind 1 replies) with standard lowercase 'e'
/// tags sync correctly between relays when referencing a Layer 2 event.
///
/// The lowercase 'e' tag is the standard NIP-01 way to reference events by ID.
#[tokio::test]
async fn test_layer3_sync_with_lowercase_e_tag() {
    // Initialize tracing for debug output
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

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
    let repo_id = "test-repo-tag-9a";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, _git_dir_a) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_a with git data");

    let (_announcement_b, _git_dir_b) =
        setup_announcement_on_relay(&relay_b, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_b with git data (triggers discovery)");

    // 3. Wait for discovery
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 4. Create and send Layer 2 issue (parent event)
    let repo_coordinate = repo_coord(&keys, repo_id);
    let issue = build_layer2_issue_event(&keys, &repo_coordinate, "Parent Issue for Tag 9a Test")
        .expect("Failed to create issue");
    let issue_id = issue.id;
    let descendant_generation = descendant_live_generation(&relay_b);

    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&issue)
        .await
        .expect("Failed to send issue");
    println!("Layer 2 issue {} sent to relay_a", issue_id);

    // 5. Wait for issue to sync to relay_b
    let issue_filter = Filter::new().kind(Kind::GitIssue).id(issue_id);
    let issue_synced =
        wait_for_event_on_relay(relay_b.url(), issue_filter, Duration::from_secs(5)).await;
    println!("Issue synced to relay_b: {}", issue_synced);
    assert!(issue_synced, "Layer 2 issue should sync first");

    wait_for_new_descendant_live_generation(
        &relay_b,
        descendant_generation,
        Duration::from_secs(20),
    )
    .await;

    // 6. Create and send Layer 3 reply with lowercase 'e' tag (kind 1)
    let reply = build_layer3_reply_with_e_tag(&keys, &issue_id, "Reply with lowercase e tag")
        .expect("Failed to create reply");
    let reply_id = reply.id;

    println!(
        "Created reply {} (kind {}) with lowercase 'e' tag",
        reply_id,
        reply.kind.as_u16()
    );

    client_a
        .send_event(&reply)
        .await
        .expect("Failed to send reply");
    println!("Layer 3 reply {} sent to relay_a", reply_id);

    client_a.disconnect().await;

    // 7. Wait and verify reply syncs to relay_b
    let reply_filter = Filter::new()
        .kind(Kind::TextNote) // Kind 1
        .author(keys.public_key())
        .id(reply_id);

    let reply_synced =
        wait_for_event_on_relay(relay_b.url(), reply_filter, Duration::from_secs(5)).await;

    println!("Reply {} synced to relay_b: {}", reply_id, reply_synced);

    // 8. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    assert!(
        reply_synced,
        "Layer 3 reply with lowercase 'e' tag should have synced to relay_b"
    );
}

/// Test 9b: Layer 3 sync with uppercase 'E' tag (NIP-22)
///
/// Verifies that Layer 3 events (kind 1111 comments) with uppercase 'E'
/// tags sync correctly between relays when referencing a Layer 2 event.
///
/// The uppercase 'E' tag is used in NIP-22 for comment events.
#[tokio::test]
async fn test_layer3_sync_with_uppercase_e_tag() {
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
    let repo_id = "test-repo-tag-9b";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, _git_dir_a) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_a with git data");

    let (_announcement_b, _git_dir_b) =
        setup_announcement_on_relay(&relay_b, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_b with git data (triggers discovery)");

    // 3. Wait for discovery
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 4. Create and send Layer 2 issue (parent event)
    let repo_coordinate = repo_coord(&keys, repo_id);
    let issue = build_layer2_issue_event(&keys, &repo_coordinate, "Parent Issue for Tag 9b Test")
        .expect("Failed to create issue");
    let issue_id = issue.id;
    let descendant_generation = descendant_live_generation(&relay_b);

    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&issue)
        .await
        .expect("Failed to send issue");
    println!("Layer 2 issue {} sent to relay_a", issue_id);

    // 5. Wait for issue to sync to relay_b
    let issue_filter = Filter::new().kind(Kind::GitIssue).id(issue_id);
    let issue_synced =
        wait_for_event_on_relay(relay_b.url(), issue_filter, Duration::from_secs(5)).await;
    println!("Issue synced to relay_b: {}", issue_synced);
    assert!(issue_synced, "Layer 2 issue should sync first");

    wait_for_new_descendant_live_generation(
        &relay_b,
        descendant_generation,
        Duration::from_secs(20),
    )
    .await;

    // 6. Create and send Layer 3 comment with uppercase 'E' tag (kind 1111)
    let comment =
        build_layer3_comment_with_uppercase_e_tag(&keys, &issue_id, "Comment with uppercase E tag")
            .expect("Failed to create comment");
    let comment_id = comment.id;

    println!(
        "Created comment {} (kind {}) with uppercase 'E' tag",
        comment_id,
        comment.kind.as_u16()
    );

    client_a
        .send_event(&comment)
        .await
        .expect("Failed to send comment");
    println!("Layer 3 comment {} sent to relay_a", comment_id);

    client_a.disconnect().await;

    // 7. Wait and verify comment syncs to relay_b
    let comment_filter = Filter::new()
        .kind(Kind::Comment) // Kind 1111
        .author(keys.public_key())
        .id(comment_id);

    let comment_synced =
        wait_for_event_on_relay(relay_b.url(), comment_filter, Duration::from_secs(5)).await;

    println!(
        "Comment {} synced to relay_b: {}",
        comment_id, comment_synced
    );

    // 8. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    assert!(
        comment_synced,
        "Layer 3 comment with uppercase 'E' tag should have synced to relay_b"
    );
}

/// Test 9c: Layer 3 sync with 'q' (quote) tag (NIP-18)
///
/// Verifies that Layer 3 events (kind 1 quotes) with 'q' (quote)
/// tags sync correctly between relays when referencing a Layer 2 event.
///
/// The 'q' tag is used in NIP-18 for quotes/reposts.
#[tokio::test]
async fn test_layer3_sync_with_q_tag() {
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
    let repo_id = "test-repo-tag-9c";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (_announcement, _git_dir_a) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_a with git data");

    let (_announcement_b, _git_dir_b) =
        setup_announcement_on_relay(&relay_b, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_b with git data (triggers discovery)");

    // 3. Wait for discovery
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 4. Create and send Layer 2 issue (parent event)
    let repo_coordinate = repo_coord(&keys, repo_id);
    let issue = build_layer2_issue_event(&keys, &repo_coordinate, "Parent Issue for Tag 9c Test")
        .expect("Failed to create issue");
    let issue_id = issue.id;
    let descendant_generation = descendant_live_generation(&relay_b);

    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&issue)
        .await
        .expect("Failed to send issue");
    println!("Layer 2 issue {} sent to relay_a", issue_id);

    // 5. Wait for issue to sync to relay_b
    let issue_filter = Filter::new().kind(Kind::GitIssue).id(issue_id);
    let issue_synced =
        wait_for_event_on_relay(relay_b.url(), issue_filter, Duration::from_secs(5)).await;
    println!("Issue synced to relay_b: {}", issue_synced);
    assert!(issue_synced, "Layer 2 issue should sync first");

    wait_for_new_descendant_live_generation(
        &relay_b,
        descendant_generation,
        Duration::from_secs(20),
    )
    .await;

    // 6. Create and send Layer 3 quote with 'q' tag (kind 1)
    let quote = build_layer3_quote_with_q_tag(&keys, &issue_id, "Quote with q tag")
        .expect("Failed to create quote");
    let quote_id = quote.id;

    println!(
        "Created quote {} (kind {}) with 'q' tag",
        quote_id,
        quote.kind.as_u16()
    );

    client_a
        .send_event(&quote)
        .await
        .expect("Failed to send quote");
    println!("Layer 3 quote {} sent to relay_a", quote_id);

    client_a.disconnect().await;

    // 7. Wait and verify quote syncs to relay_b
    let quote_filter = Filter::new()
        .kind(Kind::TextNote) // Kind 1
        .author(keys.public_key())
        .id(quote_id);

    let quote_synced =
        wait_for_event_on_relay(relay_b.url(), quote_filter, Duration::from_secs(5)).await;

    println!("Quote {} synced to relay_b: {}", quote_id, quote_synced);

    // 8. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    assert!(
        quote_synced,
        "Layer 3 quote with 'q' tag should have synced to relay_b"
    );
}
