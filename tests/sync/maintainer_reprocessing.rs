//! Integration tests for GRASP-02 PR3: Maintainer Announcement Re-Processing
//!
//! Tests the two-tier rejected events index and immediate re-processing of
//! maintainer announcements when owner announcements are accepted.
//!
//! ## Test design
//!
//! Announcements now require git data before they are released from purgatory and
//! served to other relays.  The hot-cache re-processing path we want to exercise is:
//!
//!   relay_b syncs maintainer announcement from relay_a
//!     → write policy rejects it (no owner announcement in DB yet)
//!     → event stored in hot cache
//!   owner git push to relay_b promotes owner announcement from purgatory
//!     → our new code calls rejected_events_index.invalidate_and_get()
//!     → maintainer announcement re-processed and accepted
//!
//! To guarantee the maintainer announcements arrive at relay_b *before* the owner
//! git push, relay_b is started with relay_a as its bootstrap relay.  That way
//! relay_b's SyncManager connects to relay_a immediately and syncs whatever is
//! already in relay_a's DB.  We push the maintainer git data first (so the
//! announcements are in relay_a's DB), wait briefly for the sync round-trip, then
//! send the owner announcement + git push.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{sync_helpers::*, TestRelay};

/// Test that a maintainer announcement is re-processed immediately when the owner
/// announcement is promoted from purgatory via a git push.
///
/// Flow:
/// 1. relay_a: Maintainer sends announcement + git data → accepted into relay_a's DB
/// 2. relay_b (bootstrapped from relay_a): SyncManager syncs maintainer announcement
///    → rejected by write policy (no owner in DB) → stored in hot cache
/// 3. relay_b: Owner sends announcement → purgatory (no git data yet)
/// 4. relay_b: Owner git push → owner announcement promoted from purgatory
///    → hot-cache re-processing fires → maintainer announcement accepted
/// 5. Both announcements should be in relay_b's database
#[tokio::test]
async fn test_maintainer_announcement_reprocessed_immediately() {
    // Start relay_a (where maintainer announcement will be sent)
    let relay_a = TestRelay::start().await;
    println!("relay_a started at {}", relay_a.url());

    // Create keys
    let owner_keys = Keys::generate();
    let maintainer_keys = Keys::generate();
    let identifier = "test-repo";

    // Step 1: Send maintainer announcement to relay_a then push git data so it lands in
    // relay_a's DB.  The announcement lists relay_a only (not relay_b), so relay_b's write
    // policy will reject it when it arrives via sync.
    let maintainer_npub = maintainer_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");
    let maintainer_announcement =
        EventBuilder::new(Kind::GitRepoAnnouncement, "Maintainer's repository")
            .tags(vec![
                Tag::identifier(identifier),
                Tag::custom(
                    "clone",
                    vec![format!(
                        "http://{}/{}/{}.git",
                        relay_a.domain(),
                        maintainer_npub,
                        identifier
                    )],
                ),
                Tag::custom("relays", vec![relay_a.url().to_string()]),
            ])
            .finalize(&maintainer_keys)
            .unwrap();
    send_to_relay(&relay_a, &maintainer_announcement)
        .await
        .unwrap();
    let _git_dir_maintainer =
        push_git_data_to_relay(&relay_a, &maintainer_keys, identifier, &[&relay_a.domain()]).await;
    println!("✓ Maintainer announcement + git data pushed to relay_a");

    // Step 2: Start relay_b with relay_a as bootstrap so its SyncManager connects immediately.
    // relay_b's initial negentropy sync will pick up the maintainer announcement and reject it
    // (no owner announcement in relay_b's DB yet), storing it in the hot cache.
    let relay_b = TestRelay::start_with_sync(Some(relay_a.url().to_string())).await;
    println!("relay_b started at {}", relay_b.url());

    // Give relay_b's SyncManager time to complete the initial negentropy sync with relay_a.
    tokio::time::sleep(Duration::from_secs(3)).await;
    println!("✓ relay_b synced from relay_a (maintainer announcement should be in hot cache)");

    let start = std::time::Instant::now();

    // Step 3: Send owner announcement to relay_b → goes to purgatory (no git data yet).
    // The announcement lists relay_a + relay_b and names the maintainer.
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");

    let owner_announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Owner's repository")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{}/{}.git",
                    relay_b.domain(),
                    owner_npub,
                    identifier
                )],
            ),
            Tag::custom(
                "relays",
                vec![relay_a.url().to_string(), relay_b.url().to_string()],
            ),
            Tag::custom("maintainers", vec![maintainer_keys.public_key().to_hex()]),
        ])
        .finalize(&owner_keys)
        .unwrap();

    send_to_relay(&relay_b, &owner_announcement).await.unwrap();
    println!("✓ Owner announcement sent to relay_b (now in purgatory)");

    // Step 4: Push owner git data to relay_b.
    // This promotes the owner announcement from purgatory, which triggers hot-cache
    // re-processing of the maintainer announcement via our new code path.
    let _git_dir_owner =
        push_git_data_to_relay(&relay_b, &owner_keys, identifier, &[&relay_b.domain()]).await;
    println!(
        "✓ Owner git data pushed to relay_b (owner announcement promoted, hot cache re-processed)"
    );

    // Step 5: Wait briefly for async processing to complete.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let elapsed = start.elapsed();

    // Step 6: Verify both announcements are in relay_b's database.
    let owner_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(owner_keys.public_key())
        .identifier(identifier);

    let owner_found =
        wait_for_event_on_relay(relay_b.url(), owner_filter, Duration::from_secs(2)).await;
    assert!(owner_found, "Owner announcement should be in relay_b");

    let maintainer_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(maintainer_keys.public_key())
        .identifier(identifier);

    let maintainer_found =
        wait_for_event_on_relay(relay_b.url(), maintainer_filter, Duration::from_secs(2)).await;
    assert!(
        maintainer_found,
        "Maintainer announcement should be re-processed and accepted in relay_b"
    );

    assert!(
        elapsed.as_secs() < 15,
        "Re-processing should happen in <15 seconds, took {:?}",
        elapsed
    );

    println!("✅ Maintainer announcement re-processed in {:?}", elapsed);

    relay_a.stop().await;
    relay_b.stop().await;
}

/// Test that maintainer announcements NOT in hot cache are still prevented from re-fetching
///
/// Flow:
/// 1. Maintainer announcement arrives → Rejected (added to hot cache + cold index)
/// 2. Wait for hot cache to expire (2+ minutes)
/// 3. Owner announcement arrives → Invalidates cold index
/// 4. Maintainer announcement should NOT be re-fetched (cold index prevents)
/// 5. Only owner announcement should be in database
///
/// This test verifies the cold index prevents repeated downloads after hot cache expiry.
/// Note: This test is slow (2+ minutes) so we'll skip it in normal test runs.
#[tokio::test]
#[ignore] // Skip by default due to 2+ minute duration
async fn test_maintainer_announcement_cold_index_prevents_refetch() {
    let relay = TestRelay::start().await;

    // Create keys
    let owner_keys = Keys::generate();
    let maintainer_keys = Keys::generate();

    let identifier = "test-repo-cold";

    // Create client using TestClient helper
    let client = TestClient::new(relay.url(), maintainer_keys.clone())
        .await
        .expect("Failed to connect to relay");

    // Step 1: Send maintainer announcement (will be rejected - doesn't list our relay)
    let maintainer_announcement =
        EventBuilder::new(Kind::GitRepoAnnouncement, "Maintainer's repository")
            .tags(vec![
                Tag::identifier(identifier),
                Tag::custom(
                    "clone",
                    vec![format!("https://example.com/{}.git", identifier)],
                ),
                Tag::custom("relays", vec!["wss://example.com".to_string()]),
            ])
            .finalize(&maintainer_keys)
            .unwrap();

    // Send maintainer announcement - expect it to be rejected
    let _ = client.send_event(&maintainer_announcement).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 2: Wait for hot cache to expire (default: 120 seconds)
    println!("⏳ Waiting for hot cache to expire (120 seconds)...");
    tokio::time::sleep(Duration::from_secs(125)).await;

    // Step 3: Send owner announcement (lists maintainer)
    let owner_announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Owner's repository")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![format!("https://{}/{}.git", relay.domain(), identifier)],
            ),
            Tag::custom("relays", vec![relay.url().to_string()]),
            Tag::custom("maintainers", vec![maintainer_keys.public_key().to_hex()]),
        ])
        .finalize(&owner_keys)
        .unwrap();

    client.send_event(&owner_announcement).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 4: Verify only owner announcement is in database
    let owner_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(owner_keys.public_key())
        .identifier(identifier);

    let owner_found =
        wait_for_event_on_relay(relay.url(), owner_filter, Duration::from_secs(2)).await;
    assert!(owner_found, "Owner announcement should be accepted");

    let maintainer_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(maintainer_keys.public_key())
        .identifier(identifier);

    let maintainer_found =
        wait_for_event_on_relay(relay.url(), maintainer_filter, Duration::from_millis(500)).await;
    assert!(
        !maintainer_found,
        "Maintainer announcement should NOT be re-processed (hot cache expired)"
    );

    println!("✅ Cold index prevented re-fetch after hot cache expiry");

    client.disconnect().await;
    relay.stop().await;
}

/// Test that all maintainer announcements are re-processed when the owner announcement
/// is promoted from purgatory via a git push.
///
/// Flow:
/// 1. relay_a: Three maintainers send announcements + git data → in relay_a's DB
/// 2. relay_b (bootstrapped from relay_a): SyncManager syncs all three maintainer
///    announcements → all rejected (no owner in DB) → all in hot cache
/// 3. relay_b: Owner sends announcement → purgatory
/// 4. relay_b: Owner git push → owner promoted → hot-cache re-processing fires for
///    all three maintainers
/// 5. All four announcements should be in relay_b's database
#[tokio::test]
async fn test_multiple_maintainers_all_reprocessed() {
    // Start relay_a (where maintainer announcements will be sent)
    let relay_a = TestRelay::start().await;
    println!("relay_a started at {}", relay_a.url());

    // Create keys
    let owner_keys = Keys::generate();
    let maintainer1_keys = Keys::generate();
    let maintainer2_keys = Keys::generate();
    let maintainer3_keys = Keys::generate();

    // Use a unique identifier per test run to avoid cross-test interference when
    // tests run in parallel (each test gets its own namespace on relay_a).
    let identifier = &format!(
        "multi-maintainer-repo-{}",
        &owner_keys.public_key().to_hex()[..8]
    );

    // Step 1: Send each maintainer announcement to relay_a then push git data so all three
    // land in relay_a's DB.  Each announcement lists relay_a only, so relay_b will reject
    // them when syncing (no owner announcement in relay_b's DB yet).
    let mut git_dirs = Vec::new();
    for (idx, maintainer_keys) in [&maintainer1_keys, &maintainer2_keys, &maintainer3_keys]
        .iter()
        .enumerate()
    {
        let m_npub = maintainer_keys
            .public_key()
            .to_bech32()
            .expect("Failed to get npub");
        let announcement = EventBuilder::new(
            Kind::GitRepoAnnouncement,
            format!("Maintainer {} repository", idx + 1),
        )
        .tags(vec![
            Tag::identifier(identifier.as_str()),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{}/{}.git",
                    relay_a.domain(),
                    m_npub,
                    identifier
                )],
            ),
            Tag::custom("relays", vec![relay_a.url().to_string()]),
        ])
        .finalize(*maintainer_keys)
        .unwrap();
        send_to_relay(&relay_a, &announcement).await.unwrap();
        // Use push_unique_git_data_to_relay so each maintainer gets a distinct commit
        // hash.  Identical hashes cause git to skip pack transfer when the object
        // already exists on the server, leaving the announcement in purgatory.
        let git_dir = push_unique_git_data_to_relay(
            &relay_a,
            maintainer_keys,
            identifier,
            &[&relay_a.domain()],
            &m_npub,
        )
        .await;
        git_dirs.push(git_dir);
    }
    println!("✓ Three maintainer announcements + git data pushed to relay_a");

    // Confirm all three announcements are queryable on relay_a before starting relay_b.
    // This eliminates the race between relay_a's DB writes and relay_b's initial negentropy sync.
    for (name, keys) in [
        ("maintainer1", &maintainer1_keys),
        ("maintainer2", &maintainer2_keys),
        ("maintainer3", &maintainer3_keys),
    ] {
        let filter = Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(keys.public_key())
            .identifier(identifier);
        let found = wait_for_event_on_relay(relay_a.url(), filter, Duration::from_secs(10)).await;
        assert!(
            found,
            "{} announcement should be in relay_a before starting relay_b",
            name
        );
    }
    println!("✓ All three maintainer announcements confirmed in relay_a's DB");

    // Step 2: Start relay_b with relay_a as bootstrap so its SyncManager connects immediately.
    // Because all three maintainer announcements are confirmed in relay_a's DB, relay_b's
    // initial negentropy sync will pick them all up and reject them (no owner announcement
    // in relay_b's DB yet), storing them in the hot cache.
    let relay_b = TestRelay::start_with_sync(Some(relay_a.url().to_string())).await;
    println!("relay_b started at {}", relay_b.url());

    // Give relay_b's SyncManager time to complete the initial negentropy sync with relay_a.
    // The negentropy sync completes within ~200ms (NGIT_TEST=1 sets batch window to 200ms), but we
    // allow extra time for slow CI environments.
    tokio::time::sleep(Duration::from_secs(3)).await;
    println!("✓ relay_b synced from relay_a (maintainer announcements should be in hot cache)");

    // Step 3: Send owner announcement to relay_b → goes to purgatory.
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");

    let owner_announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Owner's repository")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{}/{}.git",
                    relay_b.domain(),
                    owner_npub,
                    identifier
                )],
            ),
            Tag::custom(
                "relays",
                vec![relay_a.url().to_string(), relay_b.url().to_string()],
            ),
            Tag::custom(
                "maintainers",
                vec![
                    maintainer1_keys.public_key().to_hex(),
                    maintainer2_keys.public_key().to_hex(),
                    maintainer3_keys.public_key().to_hex(),
                ],
            ),
        ])
        .finalize(&owner_keys)
        .unwrap();

    send_to_relay(&relay_b, &owner_announcement).await.unwrap();
    println!("✓ Owner announcement sent to relay_b (now in purgatory)");

    // Step 4: Push owner git data to relay_b.
    // This promotes the owner announcement from purgatory and triggers hot-cache
    // re-processing for all three maintainer announcements.
    let _git_dir_owner =
        push_git_data_to_relay(&relay_b, &owner_keys, identifier, &[&relay_b.domain()]).await;
    println!("✓ Owner git data pushed to relay_b (hot-cache re-processing should fire)");

    // Step 5: Wait briefly for async processing to complete.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Step 6: Verify all four announcements are in relay_b's database.
    for (name, keys) in [
        ("owner", &owner_keys),
        ("maintainer1", &maintainer1_keys),
        ("maintainer2", &maintainer2_keys),
        ("maintainer3", &maintainer3_keys),
    ] {
        let filter = Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(keys.public_key())
            .identifier(identifier);

        let found = wait_for_event_on_relay(relay_b.url(), filter, Duration::from_secs(2)).await;
        assert!(found, "{} announcement should be in relay_b", name);
    }

    println!("✅ All three maintainer announcements re-processed successfully");

    relay_a.stop().await;
    relay_b.stop().await;
}

/// Test that invalid maintainer public keys don't cause panics
///
/// Flow:
/// 1. Maintainer announcement arrives → Rejected (doesn't list our relay)
/// 2. Owner announcement + git push → accepted, with INVALID maintainer hex in maintainers tag
/// 3. Owner announcement should be accepted
/// 4. Maintainer announcement should NOT be re-processed (invalid pubkey can't be parsed)
#[tokio::test]
async fn test_invalid_maintainer_pubkey_handled_gracefully() {
    let relay = TestRelay::start().await;

    // Create keys
    let owner_keys = Keys::generate();
    let maintainer_keys = Keys::generate();

    let identifier = "invalid-maintainer-repo";

    // Create client using TestClient helper
    let client = TestClient::new(relay.url(), owner_keys.clone())
        .await
        .expect("Failed to connect to relay");

    // Step 1: Send maintainer announcement (will be rejected - doesn't list our relay)
    let maintainer_announcement =
        EventBuilder::new(Kind::GitRepoAnnouncement, "Maintainer's repository")
            .tags(vec![
                Tag::identifier(identifier),
                Tag::custom(
                    "clone",
                    vec![format!("https://example.com/{}.git", identifier)],
                ),
                Tag::custom("relays", vec!["wss://example.com".to_string()]),
            ])
            .finalize(&maintainer_keys)
            .unwrap();

    // Send maintainer announcement - expect it to be rejected
    let _ = client.send_event(&maintainer_announcement).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 2: Send owner announcement with INVALID maintainer hex, then push git data.
    // The announcement goes to purgatory first; the git push promotes it.
    // The invalid maintainer hex should be handled gracefully (no panic).
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");

    let owner_announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Owner's repository")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{}/{}.git",
                    relay.domain(),
                    owner_npub,
                    identifier
                )],
            ),
            Tag::custom("relays", vec![relay.url().to_string()]),
            Tag::custom("maintainers", vec!["invalid-hex-not-a-pubkey".to_string()]),
        ])
        .finalize(&owner_keys)
        .unwrap();

    send_to_relay(&relay, &owner_announcement).await.unwrap();
    let _git_dir =
        push_git_data_to_relay(&relay, &owner_keys, identifier, &[&relay.domain()]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 3: Verify owner announcement accepted, maintainer not re-processed
    let owner_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(owner_keys.public_key())
        .identifier(identifier);

    let owner_found =
        wait_for_event_on_relay(relay.url(), owner_filter, Duration::from_secs(2)).await;
    assert!(
        owner_found,
        "Owner announcement should be accepted despite invalid maintainer"
    );

    let maintainer_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(maintainer_keys.public_key())
        .identifier(identifier);

    let maintainer_found =
        wait_for_event_on_relay(relay.url(), maintainer_filter, Duration::from_millis(500)).await;
    assert!(
        !maintainer_found,
        "Maintainer announcement should NOT be re-processed (invalid pubkey)"
    );

    println!("✅ Invalid maintainer pubkey handled gracefully without panic");

    client.disconnect().await;
    relay.stop().await;
}
