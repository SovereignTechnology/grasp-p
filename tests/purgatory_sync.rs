//! Purgatory Sync Integration Tests
//!
//! Tests that verify purgatory sync behavior:
//! - Events entering purgatory are released when git data arrives
//! - Git push triggers unified processing
//! - Remote sync fetches git data and releases events
//!
//! # Test Strategy
//!
//! These tests verify the end-to-end purgatory flow:
//! 1. State/PR events go to purgatory when git data is missing
//! 2. Git push triggers `process_newly_available_git_data`
//! 3. Events are released from purgatory when git data becomes available
//!
//! # Running Tests
//!
//! ```bash
//! # Run all purgatory sync tests
//! cargo test --test purgatory_sync
//!
//! # Run specific test
//! cargo test --test purgatory_sync test_push_triggers_unified_processing
//!
//! # With output for debugging
//! cargo test --test purgatory_sync -- --nocapture
//! ```

mod common;

use common::{
    add_commit_to_repo, build_repo_coord, check_ref_at_commit, create_pr_event,
    create_pr_event_with_clone, create_repo_announcement, create_state_event,
    create_test_repo_with_commit, port, push_ref_to_relay, push_to_relay, verify_event_not_served,
    wait_for_event_served, wait_for_sync_connection, CommitVariant, MockRelay, SmartGitServer,
    TestRelay,
};
use nostr_sdk::prelude::*;
use std::time::Duration;

/// Build a state event with a nonce that changes its ID without changing its
/// replaceable coordinate or declared repository state.
fn build_grinded_state_event(
    keys: &Keys,
    identifier: &str,
    commit_hash: &str,
    clone_url: &str,
    relay_url: &str,
    created_at: Timestamp,
    nonce: u64,
) -> Event {
    EventBuilder::new(Kind::RepoState, "")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom("clone", vec![clone_url.to_string()]),
            Tag::custom("relays", vec![relay_url.to_string()]),
            Tag::custom("refs/heads/main", vec![commit_hash.to_string()]),
            Tag::custom("HEAD", vec!["refs/heads/main".to_string()]),
            Tag::custom(
                "nonce",
                vec![
                    nonce.to_string(),
                    "0".to_string(),
                    "ngit-created-at-tiebreak".to_string(),
                ],
            ),
        ])
        .custom_created_at(created_at)
        .finalize(keys)
        .expect("build grinded state event")
}

/// Test that a git push triggers `process_newly_available_git_data` and
/// releases state events from purgatory.
///
/// Scenario:
/// 1. Start relay
/// 2. Create and send repository announcement
/// 3. Create and send state event (goes to purgatory - no git data yet)
/// 4. Verify event is NOT served (in purgatory)
/// 5. Git push the required commit
/// 6. Verify event IS now served (released from purgatory)
#[tokio::test]
async fn test_push_triggers_unified_processing() {
    // 1. Start relay
    let relay = TestRelay::start().await;
    let keys = Keys::generate();
    let identifier = "push-test-repo";

    // 2. Create test repository locally with deterministic commit
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("Failed to create test repo");

    // 3. Create and send announcement
    let announcement = create_repo_announcement(&keys, &[&relay.domain()], identifier);

    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys.clone()))
        .build();
    client
        .add_relay(relay.url())
        .await
        .expect("Failed to add relay");
    client.connect().await;

    // Send announcement
    client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement");

    // 4. Create and send state event referencing the commit
    // The state event has refs that point to commits we haven't pushed yet
    let npub = keys.public_key().to_bech32().expect("Failed to get npub");
    let clone_url = format!("http://{}/{}/{}.git", relay.domain(), npub, identifier);

    let state_event = create_state_event(
        &keys,
        identifier,
        &[("main", &commit_hash)],
        &[],
        &[&clone_url],
        &[relay.url()],
    )
    .expect("Failed to create state event");

    let state_event_id = state_event.id;
    client
        .send_event(&state_event)
        .await
        .expect("Failed to send state event");

    // 5. Verify event is NOT served yet (in purgatory). Deliberately add no
    // pacing between accepting the state event and this check or the push:
    // the post-push promotion path must handle either arrival ordering.

    verify_event_not_served(relay.url(), &state_event_id, Duration::from_secs(1))
        .await
        .expect("State event should NOT be served before git push (should be in purgatory)");

    // 6. Git push to relay (this should trigger process_newly_available_git_data)
    push_to_relay(temp_dir.path(), &relay.domain(), &npub, identifier)
        .expect("Git push should succeed");

    // 7. Verify event IS now served (released from purgatory)
    let found_event = wait_for_event_served(relay.url(), &state_event_id, Duration::from_secs(5))
        .await
        .expect("State event should be served after git push");

    // Verify it's the same event
    assert_eq!(found_event.id, state_event_id);

    // Cleanup
    client.disconnect().await;
    relay.stop().await;
}

/// Equal-timestamp state events from one author share a replaceable
/// coordinate. Both must be held while their commit is missing, then only the
/// NIP-01 winner (the lower event ID) may be promoted after the push.
#[tokio::test]
async fn same_second_same_author_states_in_purgatory_keep_nip01_lowest_id() {
    let relay = TestRelay::start().await;
    let keys = Keys::generate();
    let identifier = "same-second-purgatory-state";
    let temp_dir = tempfile::tempdir().expect("create test repository directory");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("create test repository");
    let announcement = create_repo_announcement(&keys, &[&relay.domain()], identifier);

    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys.clone()))
        .build();
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;
    client
        .send_event(&announcement)
        .await
        .expect("send announcement");

    let npub = keys.public_key().to_bech32().expect("encode public key");
    let clone_url = format!("http://{}/{}/{}.git", relay.domain(), npub, identifier);
    let created_at = Timestamp::from_secs(Timestamp::now().as_secs() + 1);
    let losing_state = build_grinded_state_event(
        &keys,
        identifier,
        &commit_hash,
        &clone_url,
        relay.url(),
        created_at,
        0,
    );
    let winning_state = (1..100_000)
        .map(|nonce| {
            build_grinded_state_event(
                &keys,
                identifier,
                &commit_hash,
                &clone_url,
                relay.url(),
                created_at,
                nonce,
            )
        })
        .find(|candidate| candidate.id < losing_state.id)
        .expect("nonce grinding must produce a lower NIP-01 event ID");

    assert_eq!(losing_state.created_at, winning_state.created_at);
    assert!(winning_state.id < losing_state.id);

    // Submit the losing state first to prove promotion does not depend on
    // arrival order when purgatory releases an equal-timestamp pair.
    client
        .send_event(&losing_state)
        .await
        .expect("send higher-ID state event");
    client
        .send_event(&winning_state)
        .await
        .expect("send lower-ID state event");

    for event_id in [losing_state.id, winning_state.id] {
        verify_event_not_served(relay.url(), &event_id, Duration::from_secs(1))
            .await
            .expect("both state events must remain in purgatory before the push");
    }

    push_to_relay(temp_dir.path(), &relay.domain(), &npub, identifier)
        .expect("push state commit to relay");

    let promoted = wait_for_event_served(relay.url(), &winning_state.id, Duration::from_secs(5))
        .await
        .expect("lower-ID state event must be promoted");
    assert_eq!(promoted.id, winning_state.id);
    verify_event_not_served(relay.url(), &losing_state.id, Duration::from_secs(1))
        .await
        .expect("higher-ID state event must not be promoted");

    client.disconnect().await;
    relay.stop().await;
}

/// Test that a state event entering purgatory triggers remote git fetch
/// and is released once the git data is available.
///
/// Scenario:
/// 1. Start source relay with git repository containing test commit
/// 2. Start syncing relay that syncs from source
/// 3. Syncing relay syncs state event (goes to purgatory - no local git data)
/// 4. Wait for sync to fetch git data from source's clone URL
/// 5. Verify state event is released and served on syncing relay
#[tokio::test]
async fn test_state_event_syncs_from_remote() {
    // 1. Start source relay
    let source_relay = TestRelay::start().await;
    let keys = Keys::generate();
    let identifier = "state-sync-test-repo";

    // Pre-allocate syncing relay port so we can include it in announcement
    let syncing_reservation = port::reserve_port();
    let syncing_port = syncing_reservation.port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_port);

    // 2. Create test repository locally with deterministic commit
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("Failed to create test repo");

    let npub = keys.public_key().to_bech32().expect("Failed to get npub");

    // 3. Create and send announcement listing BOTH relays
    // This ensures the syncing relay will accept the state event when it syncs
    let announcement = create_repo_announcement(
        &keys,
        &[&source_relay.domain(), &syncing_domain],
        identifier,
    );

    let source_client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys.clone()))
        .build();
    source_client
        .add_relay(source_relay.url())
        .await
        .expect("Failed to add source relay");
    source_client.connect().await;

    // Wait for connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send announcement to source relay
    source_client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement to source");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Create and send state event BEFORE pushing
    // The state event goes to purgatory on source relay, which authorizes the push
    let clone_urls = [
        format!(
            "http://{}/{}/{}.git",
            source_relay.domain(),
            npub,
            identifier
        ),
        format!("http://{}/{}/{}.git", syncing_domain, npub, identifier),
    ];
    let relay_urls = [
        source_relay.url().to_string(),
        format!("ws://{}", syncing_domain),
    ];

    let state_event = create_state_event(
        &keys,
        identifier,
        &[("main", &commit_hash)],
        &[],
        &[&clone_urls[0], &clone_urls[1]],
        &[&relay_urls[0], &relay_urls[1]],
    )
    .expect("Failed to create state event");

    let state_event_id = state_event.id;

    // Send state event to source relay (goes to purgatory - no git data yet)
    source_client
        .send_event(&state_event)
        .await
        .expect("Failed to send state event to source");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // 5. Push git data to source relay
    // The state event in purgatory authorizes this push
    push_to_relay(temp_dir.path(), &source_relay.domain(), &npub, identifier)
        .expect("Push to source should succeed");

    // After push, state event should be released from purgatory on source relay
    // Verify source relay is serving the state event
    wait_for_event_served(source_relay.url(), &state_event_id, Duration::from_secs(5))
        .await
        .expect("State event should be served on source relay after push");

    // 6. Start syncing relay (syncs from source)
    let syncing_relay = TestRelay::start_on_reservation_with_options(
        syncing_reservation,
        Some(source_relay.url().to_string()),
        false,
    )
    .await;

    // Wait for sync connection to establish
    wait_for_sync_connection(syncing_relay.url(), 1, Duration::from_secs(5))
        .await
        .expect("Sync connection should establish");

    // 7. Wait for state event to be released on syncing relay
    // The sync should:
    // a) Fetch the announcement and state event from source relay
    // b) Accept announcement (creates bare repo structure)
    // c) Put state event in purgatory (git data missing on syncing relay)
    // d) Fetch git data from source relay's clone URL
    // e) Release the state event from purgatory
    let found = wait_for_event_served(
        syncing_relay.url(),
        &state_event_id,
        Duration::from_secs(30), // Allow time for sync + git fetch
    )
    .await;

    assert!(
        found.is_ok(),
        "State event should be served after sync fetches git data: {:?}",
        found.err()
    );

    // 8. Verify refs are correct on syncing relay
    let ref_correct = check_ref_at_commit(
        &syncing_domain,
        &npub,
        identifier,
        "refs/heads/main",
        &commit_hash,
    )
    .await
    .expect("Failed to check ref");

    assert!(ref_correct, "main branch should point to correct commit");

    // Cleanup
    source_client.disconnect().await;
    syncing_relay.stop().await;
    source_relay.stop().await;
}

/// Test that a PR event entering purgatory triggers remote commit fetch
/// and is released once the commit is available.
///
/// Flow on source relay:
/// 1. Send announcement → purgatory (StateOnly - no git data yet)
/// 2. Send state event → purgatory (refs point to non-existent commits)
/// 3. Push git data → promotes announcement to Full + releases state event
/// 4. Send PR event → purgatory (announcement now Full, so PR events accepted)
/// 5. Push PR commit → releases PR event
///
/// Flow on syncing relay:
/// 6. Start syncing relay
/// 7. Syncs announcement → purgatory (StateOnly)
/// 8. Syncs state event → purgatory
/// 9. Fetches git data → promotes announcement (Full) + releases state event
/// 10. Syncs PR event → purgatory (announcement now Full)
/// 11. Fetches PR commit → releases PR event
#[tokio::test]
async fn test_pr_event_syncs_from_remote() {
    // 1. Start source relay
    let source_relay = TestRelay::start().await;
    let owner_keys = Keys::generate();
    let pr_author_keys = Keys::generate();
    let identifier = "pr-sync-test-repo";

    // Pre-allocate syncing relay port so we can include it in announcement
    let syncing_reservation = port::reserve_port();
    let syncing_port = syncing_reservation.port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_port);

    // 2. Create test repository locally with PR commit
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::PrTest)
        .expect("Failed to create test repo");

    let npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");

    // 3. Create announcement listing BOTH relays
    let announcement = create_repo_announcement(
        &owner_keys,
        &[&source_relay.domain(), &syncing_domain],
        identifier,
    );

    let source_client = Client::builder()
        .authenticator(SignerAuthenticator::new(owner_keys.clone()))
        .build();
    source_client
        .add_relay(source_relay.url())
        .await
        .expect("Failed to add source relay");
    source_client.connect().await;

    // Wait for connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 1: Send announcement to source relay → purgatory (StateOnly)
    source_client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement to source");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 2: Create and send state event → purgatory (no git data yet)
    let clone_urls = [
        format!(
            "http://{}/{}/{}.git",
            source_relay.domain(),
            npub,
            identifier
        ),
        format!("http://{}/{}/{}.git", syncing_domain, npub, identifier),
    ];
    let relay_urls = [
        source_relay.url().to_string(),
        format!("ws://{}", syncing_domain),
    ];

    let state_event = create_state_event(
        &owner_keys,
        identifier,
        &[("main", &commit_hash)],
        &[],
        &[&clone_urls[0], &clone_urls[1]],
        &[&relay_urls[0], &relay_urls[1]],
    )
    .expect("Failed to create state event");

    let state_event_id = state_event.id;

    source_client
        .send_event(&state_event)
        .await
        .expect("Failed to send state event to source");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 3: Push git data to source relay
    // This promotes the announcement from StateOnly to Full AND releases state event
    push_to_relay(temp_dir.path(), &source_relay.domain(), &npub, identifier)
        .expect("Push to source should succeed");

    // Wait for state event to be released from purgatory on source relay
    wait_for_event_served(source_relay.url(), &state_event_id, Duration::from_secs(5))
        .await
        .expect("State event should be served on source relay after push");

    // Step 4: Create and send PR event → purgatory
    // NOW the announcement is promoted (Full), so PR events are accepted
    let repo_coord = build_repo_coord(&owner_keys, identifier);

    let pr_event = create_pr_event(
        &pr_author_keys,
        &repo_coord,
        &commit_hash,
        "Test PR for sync",
    )
    .expect("Failed to create PR event");

    let pr_event_id = pr_event.id;

    // Send PR event to source relay using PR author's client
    let pr_client = Client::builder()
        .authenticator(SignerAuthenticator::new(pr_author_keys.clone()))
        .build();
    pr_client
        .add_relay(source_relay.url())
        .await
        .expect("Failed to add source relay for PR");
    pr_client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    pr_client
        .send_event(&pr_event)
        .await
        .expect("Failed to send PR event to source");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 5: Push PR commit to refs/nostr/<event-id> on source relay
    // This releases the PR event from purgatory
    let ref_name = format!("refs/nostr/{}", pr_event_id.to_hex());
    push_ref_to_relay(
        temp_dir.path(),
        &source_relay.domain(),
        &npub,
        identifier,
        &commit_hash,
        &ref_name,
    )
    .expect("Push to refs/nostr/<event-id> should succeed");

    // Wait for PR event to be released from purgatory on source relay
    wait_for_event_served(source_relay.url(), &pr_event_id, Duration::from_secs(5))
        .await
        .expect("PR event should be served on source relay after push");

    // Step 6: Start syncing relay (syncs from source)
    let syncing_relay = TestRelay::start_on_reservation_with_options(
        syncing_reservation,
        Some(source_relay.url().to_string()),
        false,
    )
    .await;

    // Wait for sync connection to establish
    wait_for_sync_connection(syncing_relay.url(), 1, Duration::from_secs(5))
        .await
        .expect("Sync connection should establish");

    // Steps 7-11: Syncing relay syncs events
    // The sync should:
    // a) Sync announcement → purgatory (StateOnly)
    // b) Sync state event → purgatory
    // c) Fetch git data → promotes announcement (Full) + releases state event
    // d) Sync PR event → purgatory (announcement now Full)
    // e) Fetch PR commit → releases PR event
    let found = wait_for_event_served(
        syncing_relay.url(),
        &pr_event_id,
        Duration::from_secs(30), // Allow time for sync + git fetch
    )
    .await;

    assert!(
        found.is_ok(),
        "PR event should be served after sync fetches commit: {:?}",
        found.err()
    );

    // Verify refs/nostr/<event-id> was created on syncing relay
    let ref_correct =
        check_ref_at_commit(&syncing_domain, &npub, identifier, &ref_name, &commit_hash)
            .await
            .expect("Failed to check PR ref");

    assert!(
        ref_correct,
        "refs/nostr/<event-id> should point to PR commit"
    );

    // Cleanup
    source_client.disconnect().await;
    pr_client.disconnect().await;
    syncing_relay.stop().await;
    source_relay.stop().await;
}

/// Test that concurrent state and PR events for the same repository
/// both sync correctly.
///
/// Flow on source relay:
/// 1. Send announcement → purgatory (StateOnly - no git data yet)
/// 2. Send state event → purgatory (refs point to non-existent commits)
/// 3. Push git data → promotes announcement to Full + releases state event
/// 4. THEN send PR event → purgatory (announcement now Full, so PR events accepted)
/// 5. Push PR commit → releases PR event
///
/// Flow on syncing relay:
/// 6. Start syncing relay
/// 7. Syncs announcement → purgatory (StateOnly)
/// 8. Syncs state event → purgatory
/// 9. Fetches git data → promotes announcement (Full) + releases state event
/// 10. Syncs PR event → purgatory (announcement now Full)
/// 11. Fetches PR commit → releases PR event
#[tokio::test]
async fn test_concurrent_state_and_pr_sync() {
    // 1. Start source relay
    let source_relay = TestRelay::start().await;
    let owner_keys = Keys::generate();
    let pr_author_keys = Keys::generate();
    let identifier = "concurrent-sync-test-repo";

    // Pre-allocate syncing relay port so we can include it in announcement
    let syncing_reservation = port::reserve_port();
    let syncing_port = syncing_reservation.port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_port);

    // 2. Create test repository with two commits
    // First commit establishes the repo (for state event), second commit is for PR
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let _state_commit = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("Failed to create test repo");

    // Add second commit - this is used for the PR event
    let pr_commit =
        add_commit_to_repo(temp_dir.path(), CommitVariant::PrTest).expect("Failed to add commit");

    let npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");

    // 3. Create announcement listing BOTH relays
    let announcement = create_repo_announcement(
        &owner_keys,
        &[&source_relay.domain(), &syncing_domain],
        identifier,
    );

    let source_client = Client::builder()
        .authenticator(SignerAuthenticator::new(owner_keys.clone()))
        .build();
    source_client
        .add_relay(source_relay.url())
        .await
        .expect("Failed to add source relay");
    source_client.connect().await;

    // Wait for connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 1: Send announcement to source relay → purgatory (StateOnly)
    source_client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement to source");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 2: Create and send state event → purgatory (no git data yet)
    let clone_urls = [
        format!(
            "http://{}/{}/{}.git",
            source_relay.domain(),
            npub,
            identifier
        ),
        format!("http://{}/{}/{}.git", syncing_domain, npub, identifier),
    ];
    let relay_urls = [
        source_relay.url().to_string(),
        format!("ws://{}", syncing_domain),
    ];

    // State event references main at pr_commit (HEAD after add_commit_to_repo).
    // push_to_relay uses `git push --all` which pushes main -> pr_commit (HEAD),
    // so the state event must reference pr_commit for push validation to succeed.
    let state_event = create_state_event(
        &owner_keys,
        identifier,
        &[("main", &pr_commit)],
        &[],
        &[&clone_urls[0], &clone_urls[1]],
        &[&relay_urls[0], &relay_urls[1]],
    )
    .expect("Failed to create state event");

    let state_event_id = state_event.id;

    source_client
        .send_event(&state_event)
        .await
        .expect("Failed to send state event to source");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 3: Push git data to source relay
    // This promotes the announcement from StateOnly to Full AND releases state event
    push_to_relay(temp_dir.path(), &source_relay.domain(), &npub, identifier)
        .expect("Push to source should succeed");

    // Wait for state event to be released from purgatory on source relay
    wait_for_event_served(source_relay.url(), &state_event_id, Duration::from_secs(5))
        .await
        .expect("State event should be served on source relay after push");

    // Step 4: Create and send PR event → purgatory
    // NOW the announcement is promoted (Full), so PR events are accepted
    let repo_coord = build_repo_coord(&owner_keys, identifier);

    let pr_event = create_pr_event(
        &pr_author_keys,
        &repo_coord,
        &pr_commit,
        "Test PR for concurrent sync",
    )
    .expect("Failed to create PR event");

    let pr_event_id = pr_event.id;

    // Send PR event to source relay using PR author's client
    let pr_client = Client::builder()
        .authenticator(SignerAuthenticator::new(pr_author_keys.clone()))
        .build();
    pr_client
        .add_relay(source_relay.url())
        .await
        .expect("Failed to add source relay for PR");
    pr_client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    pr_client
        .send_event(&pr_event)
        .await
        .expect("Failed to send PR event to source");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 5: Push PR commit to refs/nostr/<event-id> on source relay
    // This releases the PR event from purgatory
    let pr_ref_name = format!("refs/nostr/{}", pr_event_id.to_hex());
    push_ref_to_relay(
        temp_dir.path(),
        &source_relay.domain(),
        &npub,
        identifier,
        &pr_commit,
        &pr_ref_name,
    )
    .expect("Push PR ref to source should succeed");

    // Wait for PR event to be released from purgatory on source relay
    wait_for_event_served(source_relay.url(), &pr_event_id, Duration::from_secs(5))
        .await
        .expect("PR event should be served on source relay after push");

    // Step 6: Start syncing relay (syncs from source)
    let syncing_relay = TestRelay::start_on_reservation_with_options(
        syncing_reservation,
        Some(source_relay.url().to_string()),
        false,
    )
    .await;

    // Wait for sync connection to establish
    wait_for_sync_connection(syncing_relay.url(), 1, Duration::from_secs(5))
        .await
        .expect("Sync connection should establish");

    // Steps 7-11: Syncing relay syncs events
    // The sync should:
    // a) Sync announcement → purgatory (StateOnly)
    // b) Sync state event → purgatory
    // c) Fetch git data → promotes announcement (Full) + releases state event
    // d) Sync PR event → purgatory (announcement now Full)
    // e) Fetch PR commit → releases PR event
    let state_found = wait_for_event_served(
        syncing_relay.url(),
        &state_event_id,
        Duration::from_secs(30),
    )
    .await;

    assert!(
        state_found.is_ok(),
        "State event should be served after sync fetches git data: {:?}",
        state_found.err()
    );

    let pr_found =
        wait_for_event_served(syncing_relay.url(), &pr_event_id, Duration::from_secs(30)).await;

    assert!(
        pr_found.is_ok(),
        "PR event should be served after sync fetches commit: {:?}",
        pr_found.err()
    );

    // Verify refs are correct on syncing relay
    // Check main branch points to pr_commit (HEAD after both commits)
    let main_ref_correct = check_ref_at_commit(
        &syncing_domain,
        &npub,
        identifier,
        "refs/heads/main",
        &pr_commit, // After push, main points to pr_commit (HEAD)
    )
    .await
    .expect("Failed to check main ref");

    assert!(
        main_ref_correct,
        "main branch should point to HEAD commit ({})",
        pr_commit
    );

    // Check refs/nostr/<event-id> points to pr_commit
    let pr_ref_correct =
        check_ref_at_commit(&syncing_domain, &npub, identifier, &pr_ref_name, &pr_commit)
            .await
            .expect("Failed to check PR ref");

    assert!(
        pr_ref_correct,
        "refs/nostr/<event-id> should point to PR commit ({})",
        pr_commit
    );

    // Cleanup
    source_client.disconnect().await;
    pr_client.disconnect().await;
    syncing_relay.stop().await;
    source_relay.stop().await;
}

/// Test PR event clone tag sync with relay discovery from announcement tags and partial git data sync
/// from multiple servers (state and pr git data from different places)
///
/// This comprehensive test verifies:
/// 1. Relay discovery: syncing_relay discovers other relays from announcement's `relays` tag
/// 2. PR clone tag sync: PR events with `clone` tags have their URLs used during purgatory sync
/// 3. OID aggregation: OIDs can be aggregated from multiple sources when no single server has all data
///
/// ## Key Difference from Bootstrap-Based Sync
///
/// Unlike tests that use bootstrap relay configuration, this test:
/// - Starts syncing_relay with NO bootstrap relay
/// - Publishes announcement DIRECTLY to syncing_relay
/// - syncing_relay discovers source_grasp and mock_relay from announcement's `relays` tag
///
/// This validates the relay discovery mechanism that allows GRASP relays to find
/// and sync from other relays listed in repository announcements.
///
/// ## Architecture
///
/// ```text
/// ┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
/// │   source_grasp          │     │   mock_relay            │     │   git_server            │
/// │   (GRASP relay)         │     │   (rust-nostr relay)    │     │   (SimpleGitServer)     │
/// │                         │     │                         │     │                         │
/// │ Has:                    │     │ Has:                    │     │ Has:                    │
/// │ - Announcement          │     │ - PR event              │     │ - PR commit (commit_b)  │
/// │ - State event (served)  │     │   (served immediately,  │     │   at refs/heads/main    │
/// │ - refs/heads/main       │     │    no purgatory)        │     │                         │
/// │   → commit_a            │     │                         │     │ Does NOT have:          │
/// │                         │     │ PR event has clone tag  │     │ - commit_a              │
/// │ Does NOT have:          │     │ pointing to git_server  │     │                         │
/// │ - PR commit (commit_b)  │     │                         │     │                         │
/// └─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘
///             │                               │                               │
///             └───────────────────────────────┼───────────────────────────────┘
///                                             ▼
/// ┌─────────────────────────────────────────────────────────────────────────────────────────┐
/// │                         syncing_relay (GRASP relay under test)                          │
/// │                                                                                         │
/// │ Flow:                                                                                   │
/// │ 1. Started with NO bootstrap relay (sync enabled but no initial connections)            │
/// │ 2. Announcement published DIRECTLY to syncing_relay                                     │
/// │ 3. Relay discovers source_grasp and mock_relay from announcement's `relays` tag         │
/// │ 4. Syncs state event from source_grasp → purgatory (no commit_a locally)               │
/// │ 5. Syncs PR event from mock_relay → purgatory (no commit_b locally)                    │
/// │ 6. Purgatory sync triggers                                                              │
/// │ 7. Fetches commit_a from source_grasp clone URL (from announcement clone tag)          │
/// │ 8. Fetches commit_b from git_server (from PR event's clone tag)                        │
/// │ 9. Both events released when all OIDs available                                         │
/// │                                                                                         │
/// │ Result:                                                                                 │
/// │ - State event served                                                                    │
/// │ - PR event served                                                                       │
/// │ - refs/heads/main → commit_a (from source_grasp)                                       │
/// │ - refs/nostr/<event-id> → commit_b (from git_server via PR clone tag)                  │
/// └─────────────────────────────────────────────────────────────────────────────────────────┘
/// ```
#[tokio::test]
async fn test_pr_event_clone_tag_sync_with_partial_oid_aggregation_from_multiple_server() {
    // ========================================================================
    // Step 1: Setup Repositories
    // ========================================================================

    // Repo A: main branch with commit_a (for state event)
    let repo_a = tempfile::tempdir().expect("Failed to create temp dir for repo_a");
    let commit_a = create_test_repo_with_commit(repo_a.path(), CommitVariant::StateTest)
        .expect("Failed to create commit_a");

    // Repo B: PR commit (commit_b) - different content
    let repo_b = tempfile::tempdir().expect("Failed to create temp dir for repo_b");
    let commit_b = create_test_repo_with_commit(repo_b.path(), CommitVariant::PrTest)
        .expect("Failed to create commit_b");

    // ========================================================================
    // Step 2: Start Servers
    // ========================================================================

    // 1. source_grasp - GRASP relay with main branch data
    let source_grasp = TestRelay::start().await;

    // 2. mock_relay - rust-nostr relay for PR event (no validation, no purgatory)
    let mock_relay = MockRelay::start().await;

    // 3. git_server - SmartGitServer with PR commit only
    //    Using SmartGitServer because this fixture exercises smart HTTP fetches
    //    which requires the Git Smart HTTP protocol (not dumb HTTP)
    let git_server = SmartGitServer::start(repo_b.path()).await;

    // 4. Pre-allocate syncing_relay port for announcement tags
    let syncing_reservation = port::reserve_port();
    let syncing_port = syncing_reservation.port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_port);

    // ========================================================================
    // Step 3: Setup source_grasp with announcement and state event
    // ========================================================================

    let owner_keys = Keys::generate();
    let pr_author_keys = Keys::generate();
    let identifier = "pr-clone-partial-oid-test";
    let npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");

    // Build URLs for announcement
    // - clone tag: ONLY source_grasp (has main branch data)
    // - relays tag: source_grasp + mock_relay (mock_relay will serve PR event)
    let clone_url_source = format!(
        "http://{}/{}/{}.git",
        source_grasp.domain(),
        npub,
        identifier
    );
    let clone_url_syncing = format!("http://{}/{}/{}.git", syncing_domain, npub, identifier);

    // Create announcement with custom clone/relay URLs
    // Clone URLs: source_grasp + syncing (NOT git_server - PR commit only via PR's clone tag)
    // Relay URLs: source_grasp + mock_relay + syncing
    let announcement = nostr_sdk::prelude::EventBuilder::new(
        Kind::GitRepoAnnouncement,
        "Repository for PR clone tag + partial OID test",
    )
    .tags(vec![
        nostr_sdk::prelude::Tag::identifier(identifier),
        nostr_sdk::prelude::Tag::custom(
            "clone",
            vec![clone_url_source.clone(), clone_url_syncing.clone()],
        ),
        nostr_sdk::prelude::Tag::custom(
            "relays",
            vec![
                source_grasp.url().to_string(),
                mock_relay.url().to_string(),
                format!("ws://{}", syncing_domain),
            ],
        ),
    ])
    .finalize(&owner_keys)
    .expect("Failed to sign announcement");

    // Connect to source_grasp and send announcement
    let source_client = Client::builder()
        .authenticator(SignerAuthenticator::new(owner_keys.clone()))
        .build();
    source_client
        .add_relay(source_grasp.url())
        .await
        .expect("Failed to add source_grasp relay");
    source_client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    source_client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement to source_grasp");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create state event referencing commit_a
    let state_event = create_state_event(
        &owner_keys,
        identifier,
        &[("main", &commit_a)],
        &[],
        &[&clone_url_source, &clone_url_syncing],
        &[
            source_grasp.url(),
            mock_relay.url(),
            &format!("ws://{}", syncing_domain),
        ],
    )
    .expect("Failed to create state event");

    let state_event_id = state_event.id;

    // Send state event to source_grasp (goes to purgatory - no git data yet)
    source_client
        .send_event(&state_event)
        .await
        .expect("Failed to send state event to source_grasp");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Push main branch (commit_a) to source_grasp - releases state event
    push_to_relay(repo_a.path(), &source_grasp.domain(), &npub, identifier)
        .expect("Push to source_grasp should succeed");

    // Verify state event is served on source_grasp
    wait_for_event_served(source_grasp.url(), &state_event_id, Duration::from_secs(5))
        .await
        .expect("State event should be served on source_grasp after push");

    // ========================================================================
    // Step 4: Setup mock_relay with PR event
    // ========================================================================

    // First, send announcement to mock_relay so it has the repo context
    // This is needed because the sync system filters events based on whether
    // they reference repos that list our relay
    let mock_client = Client::builder()
        .authenticator(SignerAuthenticator::new(owner_keys.clone()))
        .build();
    mock_client
        .add_relay(mock_relay.url())
        .await
        .expect("Failed to add mock_relay for announcement");
    mock_client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    mock_client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement to mock_relay");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let repo_coord = build_repo_coord(&owner_keys, identifier);

    // Create PR event with clone tag pointing to git_server
    // This is the KEY part - the PR's clone tag provides the URL for commit_b
    let pr_event = create_pr_event_with_clone(
        &pr_author_keys,
        &repo_coord,
        &commit_b,
        "Test PR for partial OID aggregation",
        &[git_server.url()], // Clone URL points to SimpleGitServer
    )
    .expect("Failed to create PR event");

    let pr_event_id = pr_event.id;

    // Send PR event to mock_relay
    // MockRelay accepts all events without validation (no purgatory)
    let pr_client = Client::builder()
        .authenticator(SignerAuthenticator::new(pr_author_keys.clone()))
        .build();
    pr_client
        .add_relay(mock_relay.url())
        .await
        .expect("Failed to add mock_relay");
    pr_client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    pr_client
        .send_event(&pr_event)
        .await
        .expect("Failed to send PR event to mock_relay");

    // Verify PR event is served on mock_relay (immediate, no purgatory)
    wait_for_event_served(mock_relay.url(), &pr_event_id, Duration::from_secs(5))
        .await
        .expect("PR event should be served on mock_relay immediately");

    // ========================================================================
    // Step 5: Start syncing_relay with source_grasp as bootstrap
    // ========================================================================

    // Start syncing_relay with source_grasp as bootstrap relay.
    // Negentropy is disabled because MockRelay doesn't support NIP-77, and the
    // sync system doesn't properly fall back to REQ+EOSE when negentropy fails.
    //
    // We do NOT publish the announcement directly to syncing_relay. Instead,
    // syncing_relay discovers it via the bootstrap connection to source_grasp,
    // which has the promoted announcement in its database.
    let syncing_relay = TestRelay::start_on_reservation_with_options(
        syncing_reservation,
        Some(source_grasp.url().to_string()), // Bootstrap from source_grasp
        true, // Disable negentropy - MockRelay doesn't support NIP-77
    )
    .await;

    // The syncing relay will:
    // 1. Sync promoted announcement from source_grasp via bootstrap connection → purgatory (no local git data)
    // 2. EOSE triggers StateOnly subscription → syncs state event from source_grasp → purgatory sync
    // 3. Purgatory sync fetches commit_a from source_grasp clone URL → announcement + state promoted
    // 4. SelfSubscriber sees promoted announcement → upgrades to Full → connects to mock_relay
    // 5. Syncs PR event from mock_relay → purgatory (no commit_b locally)
    // 6. Purgatory sync fetches commit_b from git_server via PR clone tag
    // 7. PR event promoted → served

    // ========================================================================
    // Step 6: Verify Results
    // ========================================================================

    // Wait for state event to be served on syncing_relay
    let state_found = wait_for_event_served(
        syncing_relay.url(),
        &state_event_id,
        Duration::from_secs(30),
    )
    .await;
    assert!(
        state_found.is_ok(),
        "State event should be served on syncing_relay: {:?}",
        state_found.err()
    );

    // Wait for PR event to be served on syncing_relay
    let pr_found =
        wait_for_event_served(syncing_relay.url(), &pr_event_id, Duration::from_secs(30)).await;
    assert!(
        pr_found.is_ok(),
        "PR event should be served on syncing_relay (fetched commit_b from git_server via PR clone tag): {:?}",
        pr_found.err()
    );

    // Verify refs/heads/main → commit_a (from source_grasp)
    let main_correct = check_ref_at_commit(
        &syncing_domain,
        &npub,
        identifier,
        "refs/heads/main",
        &commit_a,
    )
    .await
    .expect("Failed to check main ref");
    assert!(
        main_correct,
        "main should point to commit_a ({}) from source_grasp",
        commit_a
    );

    // Verify refs/nostr/<event-id> → commit_b (from git_server via PR clone tag)
    let pr_ref = format!("refs/nostr/{}", pr_event_id.to_hex());
    let pr_correct = check_ref_at_commit(&syncing_domain, &npub, identifier, &pr_ref, &commit_b)
        .await
        .expect("Failed to check PR ref");
    assert!(
        pr_correct,
        "PR ref should point to commit_b ({}) fetched from git_server via PR clone tag",
        commit_b
    );

    // ========================================================================
    // Step 7: Cleanup
    // ========================================================================

    source_client.disconnect().await;
    mock_client.disconnect().await;
    pr_client.disconnect().await;
    git_server.stop().await;
    mock_relay.stop().await;
    syncing_relay.stop().await;
    source_grasp.stop().await;
}
