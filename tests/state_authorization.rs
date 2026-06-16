//! Tests for state event authorization
//!
//! Verifies that state events are properly rejected when:
//! 1. No announcement exists for the repository
//! 2. Author is not in the maintainer set

mod common;

use common::relay::TestRelay;
use nostr_sdk::prelude::*;

#[tokio::test]
async fn test_reject_state_without_announcement() {
    // Start test relay
    let relay = TestRelay::start().await;

    // Create test keypair
    let keys = Keys::generate();

    // Create a state event without any announcement
    let state_event = EventBuilder::new(Kind::RepoState, "")
        .tags([
            Tag::custom("d", ["test-repo"]),
            Tag::custom("refs/heads/main", ["abc123"]),
        ])
        .finalize(&keys)
        .unwrap();

    // Connect to relay
    let client = Client::default();
    client.add_relay(relay.url()).await.unwrap();
    client.connect().await;

    // Try to send state event
    let result = client.send_event(&state_event).await;

    // Should be rejected
    match result {
        Ok(output) => {
            assert!(
                !output.success.is_empty() || !output.failed.is_empty(),
                "Event should be processed"
            );
            // Check if any relay rejected it
            let rejected = output
                .failed
                .values()
                .any(|err| err.to_string().contains("no announcement exists"));
            assert!(
                rejected,
                "Event should be rejected due to missing announcement"
            );
        }
        Err(e) => {
            // Also acceptable - relay rejected the event
            assert!(
                e.to_string().contains("no announcement exists")
                    || e.to_string().contains("rejected"),
                "Error should indicate missing announcement: {}",
                e
            );
        }
    }

    relay.stop().await;
}

#[tokio::test]
async fn test_reject_state_from_unauthorized_author() {
    // Start test relay
    let relay = TestRelay::start().await;

    // Create two keypairs: one for announcement, one for unauthorized state
    let announcement_keys = Keys::generate();
    let unauthorized_keys = Keys::generate();

    // Create announcement
    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags([
            Tag::custom("d", ["test-repo"]),
            Tag::custom("clone", [format!("https://{}/test.git", relay.domain())]),
            Tag::custom("relays", [relay.url()]),
        ])
        .finalize(&announcement_keys)
        .unwrap();

    // Connect to relay
    let client = Client::default();
    client.add_relay(relay.url()).await.unwrap();
    client.connect().await;

    // Send announcement
    client.send_event(&announcement).await.unwrap();

    // Wait for announcement to be processed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Try to send state event from unauthorized author
    let state_event = EventBuilder::new(Kind::RepoState, "")
        .tags([
            Tag::custom("d", ["test-repo"]),
            Tag::custom("refs/heads/main", ["abc123"]),
        ])
        .finalize(&unauthorized_keys)
        .unwrap();

    let result = client.send_event(&state_event).await;

    // Should be rejected
    match result {
        Ok(output) => {
            let rejected = output
                .failed
                .values()
                .any(|err| err.to_string().contains("not authorized"));
            assert!(
                rejected,
                "Event should be rejected due to unauthorized author"
            );
        }
        Err(e) => {
            assert!(
                e.to_string().contains("not authorized") || e.to_string().contains("rejected"),
                "Error should indicate unauthorized author: {}",
                e
            );
        }
    }

    relay.stop().await;
}

#[tokio::test]
async fn test_accept_state_from_announcement_author() {
    // Start test relay
    let relay = TestRelay::start().await;

    // Create keypair
    let keys = Keys::generate();

    // Create announcement
    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags([
            Tag::custom("d", ["test-repo"]),
            Tag::custom("clone", [format!("https://{}/test.git", relay.domain())]),
            Tag::custom("relays", [relay.url()]),
        ])
        .finalize(&keys)
        .unwrap();

    // Connect to relay
    let client = Client::default();
    client.add_relay(relay.url()).await.unwrap();
    client.connect().await;

    // Send announcement
    client.send_event(&announcement).await.unwrap();

    // Wait for announcement to be processed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Send state event from same author (should be accepted or go to purgatory)
    let state_event = EventBuilder::new(Kind::RepoState, "")
        .tags([
            Tag::custom("d", ["test-repo"]),
            Tag::custom("refs/heads/main", ["abc123"]),
        ])
        .finalize(&keys)
        .unwrap();

    let result = client.send_event(&state_event).await;

    // Should be accepted or go to purgatory (not permanently rejected)
    match result {
        Ok(output) => {
            // Check that it wasn't permanently rejected
            let permanently_rejected = output.failed.values().any(|err| {
                let err_str = err.to_string();
                err_str.contains("not authorized") || err_str.contains("no announcement exists")
            });
            assert!(
                !permanently_rejected,
                "Event should not be permanently rejected when author is authorized"
            );
        }
        Err(e) => {
            // Purgatory is acceptable
            assert!(
                e.to_string().contains("purgatory") || e.to_string().contains("waiting for git"),
                "Error should be about purgatory, not authorization: {}",
                e
            );
        }
    }

    relay.stop().await;
}

#[tokio::test]
async fn test_accept_state_from_maintainer() {
    // Start test relay
    let relay = TestRelay::start().await;

    // Create two keypairs: owner and maintainer
    let owner_keys = Keys::generate();
    let maintainer_keys = Keys::generate();

    // Create announcement with maintainer
    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags([
            Tag::custom("d", ["test-repo"]),
            Tag::custom("clone", [format!("https://{}/test.git", relay.domain())]),
            Tag::custom("relays", [relay.url()]),
            Tag::custom("maintainers", [maintainer_keys.public_key().to_hex()]),
        ])
        .finalize(&owner_keys)
        .unwrap();

    // Connect to relay
    let client = Client::default();
    client.add_relay(relay.url()).await.unwrap();
    client.connect().await;

    // Send announcement
    client.send_event(&announcement).await.unwrap();

    // Wait for announcement to be processed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Send state event from maintainer
    let state_event = EventBuilder::new(Kind::RepoState, "")
        .tags([
            Tag::custom("d", ["test-repo"]),
            Tag::custom("refs/heads/main", ["abc123"]),
        ])
        .finalize(&maintainer_keys)
        .unwrap();

    let result = client.send_event(&state_event).await;

    // Should be accepted or go to purgatory (not permanently rejected)
    match result {
        Ok(output) => {
            let permanently_rejected = output.failed.values().any(|err| {
                let err_str = err.to_string();
                err_str.contains("not authorized") || err_str.contains("no announcement exists")
            });
            assert!(
                !permanently_rejected,
                "Event should not be permanently rejected when maintainer is authorized"
            );
        }
        Err(e) => {
            // Purgatory is acceptable
            assert!(
                e.to_string().contains("purgatory") || e.to_string().contains("waiting for git"),
                "Error should be about purgatory, not authorization: {}",
                e
            );
        }
    }

    relay.stop().await;
}
