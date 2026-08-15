//! Discovery Sync Tests
//!
//! Tests for relay discovery from announcement events.
//! When a relay receives an announcement listing another relay,
//! it should discover and connect to that relay to sync events.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{sync_helpers::*, TestRelay};

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

/// Test 2: Relay discovers another relay via announcement and syncs Layer 2 events
///
/// Scenario:
/// 1. relay_a has announcement + patch event (Layer 2)
/// 2. relay_b (sync enabled, NO bootstrap) receives the announcement directly
/// 3. relay_b discovers relay_a from the announcement's relays tag
/// 4. relay_b connects to relay_a and syncs the patch event
///
/// This tests dynamic relay discovery from direct submissions.
#[tokio::test]
async fn test_discovers_layer3_via_layer2() {
    // 1. Start relay_a (source) with the patch event
    let relay_a = TestRelay::start().await;
    println!(
        "relay_a started at {} (domain: {})",
        relay_a.url(),
        relay_a.domain()
    );

    // 2. Start relay_b: sync enabled but NO bootstrap relay - will discover relay_a
    let relay_b = TestRelay::start_with_sync(None).await;
    println!(
        "relay_b started at {} (domain: {})",
        relay_b.url(),
        relay_b.domain()
    );

    // 3. Create test keys
    let keys = Keys::generate();

    // 4. Set up repository announcement on relay_a with git data
    // (purgatory requires git data before announcements are accepted)
    let repo_id = "test-repo-discovery";
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    let (announcement, _git_dir_a) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    let announcement_id = announcement.id;
    println!(
        "Announcement {} set up on relay_a with git data",
        announcement_id
    );

    // 5. Build the repo coordinate for the 'a' tag in the patch
    let repo_coord = format!(
        "{}:{}:{}",
        Kind::GitRepoAnnouncement.as_u16(),
        keys.public_key().to_hex(),
        repo_id
    );

    // 6. Create a patch event (Layer 2) that references the announcement
    let patch = create_event_referencing_repo(
        &keys,
        &repo_coord,
        Kind::GitPatch.as_u16(),
        "Test patch proposal",
    );
    let patch_id = patch.id;

    println!("Created patch {} (kind {})", patch_id, patch.kind.as_u16());

    // 7. Send patch to relay_a
    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&patch)
        .await
        .expect("Failed to send patch to relay_a");
    println!("Patch sent to relay_a");

    client_a.disconnect().await;

    // 8. Set up announcement on relay_b (triggers discovery of relay_a)
    let (_announcement_b, _git_dir_b) =
        setup_announcement_on_relay(&relay_b, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_b (should trigger discovery of relay_a)");

    // 9/10. Verify the patch syncs to relay_b. The bounded poll on the synced
    // event replaces a fixed discovery sleep, which is not a reliable proxy
    // under CI load.
    let filter = Filter::new().kind(Kind::GitPatch).author(keys.public_key());

    let patch_synced =
        wait_for_event_on_relay(relay_b.url(), filter, Duration::from_secs(30)).await;

    if patch_synced {
        println!(
            "Patch {} found on relay_b (synced from discovered relay_a)",
            patch_id
        );
    } else {
        println!("Patch {} NOT found on relay_b", patch_id);
    }

    // 11. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    assert!(
        patch_synced,
        "Patch {} should have been synced to relay_b from discovered relay_a",
        patch_id
    );
}

/// Test 3: Layer 2 discovery with full event chain
///
/// Scenario:
/// 1. relay_a has: announcement → issue (Layer 2)
/// 2. relay_b receives announcement directly
/// 3. relay_b discovers relay_a and syncs the issue (Layer 2)
///
/// This tests that Layer 2 events (issues/patches) are synced when their
/// parent repository is discovered. The chain is:
///   Layer 1 (30617): Repository announcement
///   Layer 2 (1618): Issue referencing repo
///
/// Note: Layer 3 (comments on issues) sync is tracked separately and may
/// be implemented in future phases. This test focuses on Layer 2 discovery.
#[tokio::test]
async fn test_relay_discovery_via_announcements_with_historic_sync() {
    // 1. Start relay_a (source) with the event chain
    let relay_a = TestRelay::start().await;
    println!(
        "relay_a started at {} (domain: {})",
        relay_a.url(),
        relay_a.domain()
    );

    // 2. Start relay_b: sync enabled but NO bootstrap relay
    let relay_b = TestRelay::start_with_sync(None).await;
    println!(
        "relay_b started at {} (domain: {})",
        relay_b.url(),
        relay_b.domain()
    );

    // 3. Create test keys
    let keys = Keys::generate();

    // 4. Set up repository on relay_a with git data and a Layer 2 issue

    // Layer 1: Set up announcement with git data
    let domains = [relay_a.domain(), relay_b.domain()];
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let repo_id = "test-repo-chain";

    let (announcement, _git_dir_a) =
        setup_announcement_on_relay(&relay_a, &keys, &domain_refs, repo_id).await;
    let announcement_id = announcement.id;
    println!(
        "Announcement {} set up on relay_a with git data (Layer 1)",
        announcement_id
    );

    // Build repo coordinate for Layer 2 reference
    let repo_coord = repo_coord(&keys, repo_id);

    // Layer 2: Issue referencing the repo
    let issue = build_layer2_issue_event(&keys, &repo_coord, "Test issue for chain discovery")
        .expect("Failed to create issue");
    let issue_id = issue.id;
    println!("Created issue {} (Layer 2)", issue_id);

    // 5. Send issue to relay_a
    let client_a = TestClient::new(relay_a.url(), keys.clone())
        .await
        .expect("Failed to connect to relay_a");

    client_a
        .send_event(&issue)
        .await
        .expect("Failed to send issue");

    println!("Issue sent to relay_a");
    client_a.disconnect().await;

    // 6. Set up announcement on relay_b (triggers discovery of relay_a)
    let (_announcement_b, _git_dir_b) =
        setup_announcement_on_relay(&relay_b, &keys, &domain_refs, repo_id).await;
    println!("Announcement set up on relay_b (should trigger discovery of relay_a)");

    // 7/8. Verify the Layer 2 event syncs to relay_b. The bounded poll on the
    // synced event replaces a fixed discovery sleep, which is not a reliable
    // proxy under CI load.
    let issue_filter = Filter::new().kind(Kind::GitIssue).author(keys.public_key());
    let issue_synced =
        wait_for_event_on_relay(relay_b.url(), issue_filter, Duration::from_secs(30)).await;

    println!("Sync result:");
    println!("  Issue {} synced: {}", issue_id, issue_synced);

    // 9. Cleanup
    relay_b.stop().await;
    relay_a.stop().await;

    // 10. Assert Layer 2 event synced
    assert!(
        issue_synced,
        "Issue {} (Layer 2) should have synced to relay_b via discovery",
        issue_id
    );
}
