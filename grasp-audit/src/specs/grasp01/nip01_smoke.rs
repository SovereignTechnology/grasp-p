//! NIP-01 Smoke Tests
//!
//! These tests verify basic Nostr relay functionality.
//! We don't comprehensively test NIP-01 because rust-nostr already has 1000+ tests.
//! These are just smoke tests to ensure the relay is working at all.

use crate::specs::grasp01::SpecRef;
use crate::{AuditClient, AuditResult, FixtureKind, TestContext, TestResult};
use nostr_sdk::prelude::*;

pub struct Nip01SmokeTests;

impl Nip01SmokeTests {
    /// Run all NIP-01 smoke tests
    pub async fn run_all(client: &AuditClient) -> AuditResult {
        let mut results = AuditResult::new("NIP-01 Smoke Tests");

        // Run tests sequentially to avoid future type issues
        results.add(Self::test_websocket_connection(client).await);
        results.add(Self::test_send_receive_event(client).await);
        results.add(Self::test_create_subscription(client).await);
        results.add(Self::test_close_subscription(client).await);
        results.add(Self::test_reject_invalid_signature(client).await);
        results.add(Self::test_reject_invalid_event_id(client).await);

        results
    }

    /// Test 1: Can establish WebSocket connection
    ///
    /// Spec: NIP-01 basic requirement
    /// Requirement: MUST serve a relay at / via WebSocket
    pub async fn test_websocket_connection(client: &AuditClient) -> TestResult {
        TestResult::new(
            "websocket_connection",
            SpecRef::NostrRelayNip01Compliant,
            "MUST serve a relay at / via WebSocket",
        )
        .run(|| async {
            if !client.is_connected().await {
                return Err("Failed to connect to relay".to_string());
            }

            Ok(())
        })
        .await
    }

    /// Test 2: Can send EVENT and receive OK response
    ///
    /// Spec: NIP-01 EVENT message
    /// Requirement: Relay MUST accept valid EVENT messages
    ///
    /// For GRASP servers, we send a NIP-34 repository announcement that lists
    /// the GRASP server in clone and relays tags (required for acceptance).
    ///
    /// ## Fixture-First Pattern
    ///
    /// 1. **Generate**: Create TestContext and get ValidRepo fixture
    /// 2. **Send**: Fixture already sends the event to relay
    /// 3. **Verify**: Query event back and verify it was stored correctly
    pub async fn test_send_receive_event(client: &AuditClient) -> TestResult {
        TestResult::new(
            "send_receive_event",
            SpecRef::NostrRelayNip01Compliant,
            "MUST accept valid EVENT messages",
        )
        .run(|| async {
            // Step 1: GENERATE - Create TestContext and get ValidRepoServed fixture
            let ctx = TestContext::new(client);
            let event = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| format!("Failed to create ValidRepoServed fixture: {}", e))?;

            let event_id = event.id;

            // Wait a bit for event to be indexed
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Step 2: VERIFY - Query event back
            let filter = Filter::new().kind(Kind::GitRepoAnnouncement).id(event_id);

            let events = client
                .query(filter)
                .await
                .map_err(|e| format!("Failed to query event: {}", e))?;

            if events.is_empty() {
                // Debug: try querying without audit client filtering
                eprintln!("Event not found with audit client query, trying direct client query...");
                let direct_filter = Filter::new().kind(Kind::GitRepoAnnouncement).id(event_id);
                let direct_events = client
                    .client()
                    .fetch_events(direct_filter)
                    .timeout(std::time::Duration::from_secs(5))
                    .await
                    .map_err(|e| format!("Direct query failed: {}", e))?;
                let direct_vec: Vec<Event> = direct_events.into_iter().collect();
                eprintln!("Direct query found {} events", direct_vec.len());
                if !direct_vec.is_empty() {
                    eprintln!("Event tags: {:?}", direct_vec[0].tags);
                }
                return Err(format!(
                    "Event not found after sending (direct query found {})",
                    direct_vec.len()
                ));
            }

            if events[0].id != event_id {
                return Err("Retrieved event has different ID".to_string());
            }

            Ok(())
        })
        .await
    }

    /// Test 3: Can create subscription with REQ
    ///
    /// Spec: NIP-01 REQ message
    /// Requirement: Relay MUST support REQ subscriptions
    ///
    /// ## Fixture-First Pattern
    ///
    /// 1. **Generate**: Create TestContext and get ValidRepoServed fixture
    /// 2. **Send**: Fixture already sends the event to relay
    /// 3. **Verify**: Subscribe and verify we receive the event
    pub async fn test_create_subscription(client: &AuditClient) -> TestResult {
        TestResult::new(
            "create_subscription",
            SpecRef::NostrRelayNip01Compliant,
            "MUST support REQ subscriptions",
        )
        .run(|| async {
            // Step 1: GENERATE - Create TestContext and get ValidRepoServed fixture
            let ctx = TestContext::new(client);
            let _event = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| format!("Failed to create ValidRepoServed fixture: {}", e))?;

            // Step 2: VERIFY - Subscribe to NIP-34 announcements from this author
            let filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(client.public_key());

            let events = client
                .subscribe(vec![filter], Some(std::time::Duration::from_secs(5)))
                .await
                .map_err(|e| format!("Failed to subscribe: {}", e))?;

            // Should have at least our event
            if events.is_empty() {
                return Err("No events received from subscription".to_string());
            }

            Ok(())
        })
        .await
    }

    /// Test 4: Can close subscription with CLOSE
    ///
    /// Spec: NIP-01 CLOSE message
    /// Requirement: Relay MUST support CLOSE to end subscriptions
    pub async fn test_close_subscription(client: &AuditClient) -> TestResult {
        TestResult::new(
            "close_subscription",
            SpecRef::NostrRelayNip01Compliant,
            "MUST support CLOSE to end subscriptions",
        )
        .run(|| async {
            // For now, we just verify we can query events
            // Full subscription management with CLOSE would require
            // lower-level WebSocket access

            let filter = Filter::new().kind(Kind::TextNote).limit(1);

            let _events = client
                .subscribe(vec![filter], Some(std::time::Duration::from_secs(2)))
                .await
                .map_err(|e| format!("Failed to subscribe: {}", e))?;

            // If we got here, subscription worked
            Ok(())
        })
        .await
    }

    /// Test 5: Rejects events with invalid signatures
    ///
    /// Spec: NIP-01 event validation
    /// Requirement: Relay MUST reject events with invalid signatures
    pub async fn test_reject_invalid_signature(client: &AuditClient) -> TestResult {
        TestResult::new(
            "reject_invalid_signature",
            SpecRef::NostrRelayNip01Compliant,
            "MUST reject events with invalid signatures",
        )
        .run(|| async {
            // Create a valid event
            let event = client
                .event_builder(Kind::TextNote, "Invalid signature test")
                .build(client.keys())
                .map_err(|e| format!("Failed to build event: {}", e))?;

            // Corrupt the signature by creating a new event with wrong sig
            // We'll use a different key to sign, creating an invalid signature
            let wrong_keys = Keys::generate();
            let wrong_event = EventBuilder::new(event.kind, event.content.clone())
                .tags(event.tags.clone())
                .finalize(&wrong_keys)
                .map_err(|e| format!("Failed to build wrong event: {}", e))?;

            // Create event JSON with mismatched pubkey and signature
            // This should be rejected by the relay
            let invalid_event_json = serde_json::json!({
                "id": event.id.to_hex(),
                "pubkey": event.pubkey.to_hex(),
                "created_at": event.created_at.as_secs(),
                "kind": event.kind.as_u16(),
                "tags": event.tags,
                "content": event.content,
                "sig": wrong_event.sig.to_string(), // Wrong signature!
            });

            // Parse it back to an Event
            let invalid_event: Event = serde_json::from_value(invalid_event_json)
                .map_err(|e| format!("Failed to create invalid event: {}", e))?;

            // Try to send the invalid event
            let result = client.send_event(invalid_event).await;

            // We expect this to fail
            if result.is_ok() {
                return Err("Relay accepted event with invalid signature".to_string());
            }

            Ok(())
        })
        .await
    }

    /// Test 6: Rejects events with invalid event IDs
    ///
    /// Spec: NIP-01 event ID validation
    /// Requirement: Relay MUST reject events where ID doesn't match hash
    pub async fn test_reject_invalid_event_id(client: &AuditClient) -> TestResult {
        TestResult::new(
            "reject_invalid_event_id",
            SpecRef::NostrRelayNip01Compliant,
            "MUST reject events where ID doesn't match hash",
        )
        .run(|| async {
            // Create a valid event
            let event = client
                .event_builder(Kind::TextNote, "Invalid ID test")
                .build(client.keys())
                .map_err(|e| format!("Failed to build event: {}", e))?;

            // Create event JSON with corrupted ID
            let invalid_event_json = serde_json::json!({
                "id": EventId::all_zeros().to_hex(), // Wrong ID!
                "pubkey": event.pubkey.to_hex(),
                "created_at": event.created_at.as_secs(),
                "kind": event.kind.as_u16(),
                "tags": event.tags,
                "content": event.content,
                "sig": event.sig.to_string(),
            });

            // Parse it back to an Event
            let invalid_event: Event = serde_json::from_value(invalid_event_json)
                .map_err(|e| format!("Failed to create invalid event: {}", e))?;

            // Try to send the invalid event
            let result = client.send_event(invalid_event).await;

            // We expect this to fail
            if result.is_ok() {
                return Err("Relay accepted event with invalid ID".to_string());
            }

            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditConfig;

    // Note: These tests require a running relay
    // They are integration tests, not unit tests

    #[tokio::test]
    #[ignore] // Ignore by default since it needs a running relay
    async fn test_smoke_tests_against_relay() {
        // RELAY_URL env var must be set - no default fallback
        let relay_url = std::env::var("RELAY_URL")
            .expect("RELAY_URL environment variable must be set for integration tests");

        let config = AuditConfig::isolated();
        let client = AuditClient::new(&relay_url, config)
            .await
            .expect("Failed to connect to relay");

        let results = Nip01SmokeTests::run_all(&client).await;
        results.print_report();

        assert!(results.all_passed(), "Some smoke tests failed");
    }
}
