//! Archive GRASP Services Integration Tests
//!
//! Tests that verify archive_grasp_services filtering behavior:
//! - Announcements with matching GRASP service domains are accepted
//! - Announcements with non-matching GRASP service domains are rejected
//! - Multiple configured services work correctly
//! - Case-insensitive domain matching
//!
//! # Test Strategy
//!
//! These tests verify the GRASP-05 archive mode with grasp_services filtering:
//! 1. Configure relay with specific GRASP service domains
//! 2. Send announcements with various clone URLs
//! 3. Verify announcements are accepted/rejected based on domain matching
//! 4. Verify repositories are created only for accepted announcements
//!
//! # Running Tests
//!
//! ```bash
//! # Run all archive grasp services tests
//! cargo test --test archive_grasp_services
//!
//! # Run specific test
//! cargo test --test archive_grasp_services test_archive_accepts_matching_grasp_service
//!
//! # With output for debugging
//! cargo test --test archive_grasp_services -- --nocapture
//! ```

mod common;

use common::{
    check_ref_at_commit, create_repo_announcement, create_state_event,
    create_test_repo_with_commit, port, push_to_relay, wait_for_event_served,
    wait_for_sync_connection, CommitVariant, TestRelay,
};
use nostr_sdk::prelude::*;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Helper to start a relay with archive_grasp_services configuration
///
/// This is a specialized version of TestRelay::start_on_reservation_with_archive_and_sync
/// that adds the NGIT_ARCHIVE_GRASP_SERVICES environment variable.
async fn start_relay_with_grasp_services(services: &str) -> (Child, String, PathBuf) {
    // Reserve a port and hold the listener bound until just before the
    // subprocess spawns — mirrors the pattern in `TestRelay`. Without
    // this hold, a parallel test in this process could be handed the
    // same port between the kernel-assigned bind and ngit-grasp's own
    // bind, producing a flaky `Address already in use` failure.
    let reservation = port::reserve_port();
    let relay_port = reservation.port();
    let bind_address = format!("127.0.0.1:{}", relay_port);
    let url = format!("ws://127.0.0.1:{}", relay_port);

    // Create temporary directory for git repositories
    let git_data_dir = tempfile::tempdir().expect("Failed to create temporary git data directory");

    // Use the built binary directly
    let binary_path = std::env::current_exe()
        .expect("Failed to get current exe")
        .parent()
        .expect("Failed to get parent dir")
        .parent()
        .expect("Failed to get grandparent dir")
        .join("ngit-grasp");

    // Give the relay a stable signing identity for NIP-11 and NIP-42.
    let test_keys = nostr_sdk::prelude::Keys::generate();
    let test_nsec = test_keys
        .secret_key()
        .to_bech32()
        .expect("Failed to generate test nsec");

    // Start the relay process with archive_grasp_services
    let mut cmd = Command::new(&binary_path);
    cmd.env("NGIT_BIND_ADDRESS", &bind_address)
        .env("NGIT_DOMAIN", &bind_address)
        .env("NGIT_GIT_DATA_PATH", git_data_dir.path())
        .env("NGIT_DATABASE_BACKEND", "memory")
        .env("NGIT_RELAY_OWNER_NSEC", &test_nsec)
        .env("NGIT_ARCHIVE_GRASP_SERVICES", services)
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Release the reservation immediately before spawn so the subprocess
    // can bind the port. See `tests/common/port.rs` for the rationale.
    let _ = reservation.release();

    let process = cmd.spawn().expect("Failed to start relay process");

    // Store git data path for test assertions
    let git_data_path = git_data_dir.path().to_path_buf();

    // Wait for relay to be ready
    wait_for_relay_ready(relay_port).await;

    (process, url, git_data_path)
}

/// Wait for the relay to be ready to accept connections.
///
/// A successful TCP connect only proves the socket is bound: the accept loop
/// and HTTP service may still be coming up. Poll the relay's HTTP handler
/// instead, bounded by a deadline, so the immediately-following WebSocket
/// client is racing a relay that has already served a request.
async fn wait_for_relay_ready(port: u16) {
    common::relay::wait_for_http_ready(port, Duration::from_secs(10))
        .await
        .expect("Relay should become ready");
}

/// Test that announcements with matching GRASP service domains are accepted.
///
/// Scenario:
/// 1. Start relay with archive_grasp_services="git.example.com"
/// 2. Send announcement with clone URL from git.example.com
/// 3. Verify announcement is accepted (repository is created)
#[tokio::test]
async fn test_archive_accepts_matching_grasp_service() {
    let (mut process, url, git_data_path) =
        start_relay_with_grasp_services("git.example.com").await;
    let keys = Keys::generate();
    let identifier = "test-repo";

    // Create announcement with clone URL from git.example.com
    let npub = keys.public_key().to_bech32().expect("Failed to get npub");
    let tags = vec![
        Tag::identifier(identifier),
        Tag::custom(
            "clone",
            vec![format!("https://git.example.com/user/{}.git", identifier)],
        ),
        Tag::custom("relays", vec!["wss://relay.example.com".to_string()]),
    ];

    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Repository state")
        .tags(tags)
        .finalize(&keys)
        .expect("Failed to sign announcement");

    // Send announcement to relay
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys.clone()))
        .build();
    client.add_relay(&url).await.expect("Failed to add relay");
    common::relay::connect_client(&client).await;

    client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement");

    // The relay runs the archive write policy and creates the bare repository
    // inside event admission, before it replies. The completed send is
    // therefore the barrier: the directory already exists, or never will.
    let repo_path = git_data_path.join(format!("{}/{}.git", npub, identifier));

    assert!(
        repo_path.exists(),
        "Repository should be created for announcement with matching GRASP service domain"
    );

    // Cleanup
    client.disconnect().await;
    let _ = process.kill();
    let _ = process.wait();
}

/// Test that announcements with non-matching GRASP service domains are rejected.
///
/// Scenario:
/// 1. Start relay with archive_grasp_services="git.example.com"
/// 2. Send announcement with clone URL from github.com (not in services list)
/// 3. Verify announcement is rejected (repository is NOT created)
#[tokio::test]
async fn test_archive_rejects_non_matching_grasp_service() {
    let (mut process, url, git_data_path) =
        start_relay_with_grasp_services("git.example.com").await;
    let keys = Keys::generate();
    let identifier = "test-repo";

    // Create announcement with clone URL from github.com (NOT in services list)
    let npub = keys.public_key().to_bech32().expect("Failed to get npub");
    let tags = vec![
        Tag::identifier(identifier),
        Tag::custom(
            "clone",
            vec![format!("https://github.com/user/{}.git", identifier)],
        ),
        Tag::custom("relays", vec!["wss://relay.example.com".to_string()]),
    ];

    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Repository state")
        .tags(tags)
        .finalize(&keys)
        .expect("Failed to sign announcement");

    // Send announcement to relay
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys.clone()))
        .build();
    client.add_relay(&url).await.expect("Failed to add relay");
    common::relay::connect_client(&client).await;

    client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement");

    // Admission completes before the relay replies, and a rejected
    // announcement never reaches repository creation, so the absence check
    // needs no grace period after the send.
    let repo_path = git_data_path.join(format!("{}/{}.git", npub, identifier));

    assert!(
        !repo_path.exists(),
        "Repository should NOT be created for announcement with non-matching GRASP service domain"
    );

    // Cleanup
    client.disconnect().await;
    let _ = process.kill();
    let _ = process.wait();
}

/// Test that multiple configured GRASP services work correctly.
///
/// Scenario:
/// 1. Start relay with archive_grasp_services="git.example.com,gitlab.example.org"
/// 2. Send announcements with clone URLs from both services
/// 3. Verify both announcements are accepted
/// 4. Send announcement from non-listed service
/// 5. Verify it is rejected
#[tokio::test]
async fn test_archive_multiple_grasp_services() {
    let (mut process, url, git_data_path) =
        start_relay_with_grasp_services("git.example.com,gitlab.example.org").await;

    // Test first service (git.example.com)
    let keys1 = Keys::generate();
    let identifier1 = "test-repo-1";
    let npub1 = keys1.public_key().to_bech32().expect("Failed to get npub");

    let tags1 = vec![
        Tag::identifier(identifier1),
        Tag::custom(
            "clone",
            vec![format!("https://git.example.com/user/{}.git", identifier1)],
        ),
        Tag::custom("relays", vec!["wss://relay.example.com".to_string()]),
    ];

    let announcement1 = EventBuilder::new(Kind::GitRepoAnnouncement, "Repository state")
        .tags(tags1)
        .finalize(&keys1)
        .expect("Failed to sign announcement");

    let client1 = Client::builder()
        .authenticator(SignerAuthenticator::new(keys1.clone()))
        .build();
    client1.add_relay(&url).await.expect("Failed to add relay");
    common::relay::connect_client(&client1).await;

    client1
        .send_event(&announcement1)
        .await
        .expect("Failed to send announcement");

    // Test second service (gitlab.example.org)
    let keys2 = Keys::generate();
    let identifier2 = "test-repo-2";
    let npub2 = keys2.public_key().to_bech32().expect("Failed to get npub");

    let tags2 = vec![
        Tag::identifier(identifier2),
        Tag::custom(
            "clone",
            vec![format!(
                "https://gitlab.example.org/user/{}.git",
                identifier2
            )],
        ),
        Tag::custom("relays", vec!["wss://relay.example.com".to_string()]),
    ];

    let announcement2 = EventBuilder::new(Kind::GitRepoAnnouncement, "Repository state")
        .tags(tags2)
        .finalize(&keys2)
        .expect("Failed to sign announcement");

    let client2 = Client::builder()
        .authenticator(SignerAuthenticator::new(keys2.clone()))
        .build();
    client2.add_relay(&url).await.expect("Failed to add relay");
    common::relay::connect_client(&client2).await;

    client2
        .send_event(&announcement2)
        .await
        .expect("Failed to send announcement");

    // Test non-listed service (github.com)
    let keys3 = Keys::generate();
    let identifier3 = "test-repo-3";
    let npub3 = keys3.public_key().to_bech32().expect("Failed to get npub");

    let tags3 = vec![
        Tag::identifier(identifier3),
        Tag::custom(
            "clone",
            vec![format!("https://github.com/user/{}.git", identifier3)],
        ),
        Tag::custom("relays", vec!["wss://relay.example.com".to_string()]),
    ];

    let announcement3 = EventBuilder::new(Kind::GitRepoAnnouncement, "Repository state")
        .tags(tags3)
        .finalize(&keys3)
        .expect("Failed to sign announcement");

    let client3 = Client::builder()
        .authenticator(SignerAuthenticator::new(keys3.clone()))
        .build();
    client3.add_relay(&url).await.expect("Failed to add relay");
    common::relay::connect_client(&client3).await;

    client3
        .send_event(&announcement3)
        .await
        .expect("Failed to send announcement");

    // Each send above completed only after the relay replied, and the bare
    // repository is created inside admission, so all three outcomes are
    // already settled.
    let repo_path1 = git_data_path.join(format!("{}/{}.git", npub1, identifier1));
    assert!(
        repo_path1.exists(),
        "Repository should be created for first GRASP service (git.example.com)"
    );

    // Verify second service announcement was accepted
    let repo_path2 = git_data_path.join(format!("{}/{}.git", npub2, identifier2));
    assert!(
        repo_path2.exists(),
        "Repository should be created for second GRASP service (gitlab.example.org)"
    );

    // Verify non-listed service announcement was rejected
    let repo_path3 = git_data_path.join(format!("{}/{}.git", npub3, identifier3));
    assert!(
        !repo_path3.exists(),
        "Repository should NOT be created for non-listed service (github.com)"
    );

    // Cleanup
    client1.disconnect().await;
    client2.disconnect().await;
    client3.disconnect().await;
    let _ = process.kill();
    let _ = process.wait();
}

/// Test that archive_read_only mode creates bare git repositories and syncs data
/// via relay-to-relay sync (purgatory sync infrastructure).
///
/// Scenario:
/// 1. Start source relay with full repository (announcement + state + git data)
/// 2. Start archive relay with archive_all=true, archive_read_only=true, syncing from source
/// 3. Archive relay syncs announcement and state events from source
/// 4. State events trigger purgatory sync which fetches git data from source's clone URL
/// 5. Verify bare repository is created and git data is synced
/// 6. Verify git pushes are rejected (read-only mode)
#[tokio::test]
async fn test_archive_read_only_creates_bare_repo() {
    // 1. Start source relay
    let source_relay = TestRelay::start().await;
    let keys = Keys::generate();
    let identifier = "archive-test-repo";

    // Pre-allocate archive relay port so we can include it in
    // announcement. Hold the reservation across announcement+push setup
    // so no parallel test in this process is handed the same port.
    let archive_reservation = port::reserve_port();
    let archive_domain = format!("127.0.0.1:{}", archive_reservation.port());

    // 2. Create test repository locally with deterministic commit
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("Failed to create test repo");

    let npub = keys.public_key().to_bech32().expect("Failed to get npub");

    // 3. Create and send announcement listing BOTH relays
    // This ensures the archive relay will accept the state event when it syncs
    let announcement = create_repo_announcement(
        &keys,
        &[&source_relay.domain(), &archive_domain],
        identifier,
    );

    let source_client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys.clone()))
        .build();
    source_client
        .add_relay(source_relay.url())
        .await
        .expect("Failed to add source relay");
    common::relay::connect_client(&source_client).await;

    // Send announcement to source relay
    source_client
        .send_event(&announcement)
        .await
        .expect("Failed to send announcement to source");

    // 4. Create and send state event
    let clone_urls = [
        format!(
            "http://{}/{}/{}.git",
            source_relay.domain(),
            npub,
            identifier
        ),
        format!("http://{}/{}/{}.git", archive_domain, npub, identifier),
    ];
    let relay_urls = [
        source_relay.url().to_string(),
        format!("ws://{}", archive_domain),
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

    // 5. Push git data to source relay
    // The state event in purgatory authorizes this push
    push_to_relay(temp_dir.path(), &source_relay.domain(), &npub, identifier)
        .expect("Push to source should succeed");

    // After push, state event should be released from purgatory on source relay
    wait_for_event_served(source_relay.url(), &state_event_id, Duration::from_secs(5))
        .await
        .expect("State event should be served on source relay after push");

    // 6. Start archive relay with archive_all=true, archive_read_only=true, syncing from source
    let archive_relay = TestRelay::start_on_reservation_with_archive_and_sync(
        archive_reservation,
        Some(source_relay.url().to_string()),
        false, // negentropy enabled
        true,  // archive_all
        true,  // archive_read_only
    )
    .await;

    // Wait for sync connection to establish
    wait_for_sync_connection(archive_relay.url(), 1, Duration::from_secs(5))
        .await
        .expect("Sync connection should establish");

    // 7. Wait for state event to be released on archive relay
    // The sync should:
    // a) Fetch the announcement and state event from source relay
    // b) Accept announcement (creates bare repo structure) - via archive mode
    // c) Put state event in purgatory (git data missing on archive relay)
    // d) Fetch git data from source relay's clone URL
    // e) Release the state event from purgatory

    let found = wait_for_event_served(
        archive_relay.url(),
        &state_event_id,
        Duration::from_secs(30), // Allow time for sync + git fetch
    )
    .await;

    assert!(
        found.is_ok(),
        "State event should be served after sync fetches git data: {:?}",
        found.err()
    );

    // 8. Verify bare repository was created
    let repo_path = archive_relay
        .git_data_path()
        .join(format!("{}/{}.git", npub, identifier));

    assert!(
        repo_path.exists(),
        "Bare repository should be created at {:?} for archive announcement",
        repo_path
    );

    // 9. Verify it's a bare repository (check for config file with bare = true)
    let config_path = repo_path.join("config");
    assert!(
        config_path.exists(),
        "Git config should exist at {:?}",
        config_path
    );

    let config_content = tokio::fs::read_to_string(&config_path)
        .await
        .expect("Should read git config");
    assert!(
        config_content.contains("bare = true"),
        "Repository at {:?} should be bare (config should contain 'bare = true')",
        repo_path
    );

    // 10. Verify refs are correct on archive relay
    let ref_correct = check_ref_at_commit(
        &archive_domain,
        &npub,
        identifier,
        "refs/heads/main",
        &commit_hash,
    )
    .await
    .expect("Failed to check ref");

    assert!(ref_correct, "main branch should point to correct commit");

    // 11. Verify git pushes are rejected (read-only mode)
    // Create a new commit in the source repo
    tokio::fs::write(temp_dir.path().join("new_file.txt"), "new content")
        .await
        .expect("Failed to write new file");

    let output = tokio::process::Command::from(grasp_audit::git_command())
        .args(["add", "."])
        .current_dir(temp_dir.path())
        .output()
        .await
        .expect("Failed to git add");
    assert!(output.status.success());

    let output = tokio::process::Command::from(grasp_audit::git_command())
        .args(["commit", "-m", "New commit for push test"])
        .current_dir(temp_dir.path())
        .output()
        .await
        .expect("Failed to git commit");
    assert!(output.status.success());

    // Try to push to archive relay (should fail in read-only mode)
    let push_url = format!("http://{}/{}/{}.git", archive_domain, npub, identifier);
    let output = tokio::process::Command::from(grasp_audit::git_command())
        .args(["push", &push_url, "main"])
        .current_dir(temp_dir.path())
        .output()
        .await
        .expect("Failed to run git push");

    assert!(
        !output.status.success(),
        "Git push should be rejected in archive_read_only mode. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Cleanup
    source_client.disconnect().await;
    archive_relay.stop().await;
    source_relay.stop().await;
}
