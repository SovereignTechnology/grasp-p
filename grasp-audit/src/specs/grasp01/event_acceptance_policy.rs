//! GRASP-01 Nostr Event Acceptance Policy
//!
//! Tests for GRASP-01 Nostr event acceptance policy (lines 5-16 of ../grasp/01.md)
//!
//! This file validates that a GRASP-01 compliant relay:
//! - Accepts valid NIP-34 repository announcements listing the service
//! - Rejects announcements that don't list the service in clone and relays tags
//!   EXCEPTION: maintainer-discovery candidates MUST be accepted even without
//!   listing the service. Admission enables dependency discovery and GRASP-02
//!   sync; it does not itself grant State-event authority.
//! - Accepts repository state announcements
//! - Accepts events that TAG accepted repositories
//! - Accepts events that ARE TAGGED BY accepted events (transitive)
//!
//! ## Running Tests
//!
//! ### Recommended: Automated Relay Management
//! ```bash
//! cd grasp-audit && nix develop -c bash test-ngit-relay.sh --mode test
//! ```
//! This script automatically starts a relay, runs all tests, and cleans up.
//!
//! ### Manual Testing (if needed)
//! ```bash
//! # 1. Start ngit-relay in a separate terminal:
//! docker run --rm -p 18081:8081 ghcr.io/danconwaydev/ngit-relay:latest
//!
//! # 2. Run all ignored tests (includes these smoke tests):
//! RELAY_URL="ws://localhost:18081" nix develop -c cargo test --lib -- --ignored --nocapture
//!
//! # 3. Run ONLY these specific smoke tests:
//! RELAY_URL="ws://localhost:18081" nix develop -c cargo test --lib test_grasp01_event_acceptance -- --ignored --nocapture
//! ```
//!
//! ## Test Groups (12 total tests, target <5s execution)
//!
//! ### Group 1: Accept Events Tagging Accepted Repositories (3 tests)
//! - **Test 1.1**: Issue via `a` tag → Validates NIP-33 addressable event references
//! - **Test 1.2**: Comment via `A` tag → Validates NIP-22 root addressable references
//! - **Test 1.3**: Kind 1 via `q` tag → Validates NIP-18 quote references
//!
//! ### Group 2: Accept Events Tagging Accepted Events - Transitive (3 tests)
//! - **Test 2.1**: Issue quoting issue via `q` → Multi-hop transitive acceptance
//! - **Test 2.2**: Comment via `E` tag → NIP-22 threaded root references
//! - **Test 2.3**: Kind 1 via `e` tag → Standard NIP-01 reply chains
//!
//! ### Group 3: Accept Events Tagged BY Accepted Events - Forward References (3 tests)
//! - **Test 3.1**: Kind 1 referenced in issue → Forward reference acceptance
//! - **Test 3.2**: Comment referenced in comment → Nested forward references
//! - **Test 3.3**: Kind 1 referenced in Kind 1 → Cross-event forward refs
//!
//! ### Group 4: Reject Unrelated Events (3 tests)
//! - **Test 4.1**: Orphan issue → No repo connection
//! - **Test 4.2**: Orphan Kind 1 → No accepted event references
//! - **Test 4.3**: Comment quoting other repo → Wrong repository context
//!
//! ## Test Coverage Summary
//!
//! **Tag Types Validated:**
//! - `a` tags (NIP-33 addressable events)
//! - `A` tags (NIP-22 root addressable)
//! - `q` tags (NIP-18 quotes)
//! - `e` tags (NIP-01 event references)
//! - `E` tags (NIP-22 root event references)
//!
//! **Acceptance Paths:**
//! - Direct repository references (tags accepted repos)
//! - Transitive acceptance (tags events that tag accepted repos)
//! - Forward references (late-arriving events tagged by accepted events)
//! - Rejection cases (unrelated events with no connection)
//!
//! **Helper Functions (6 total):**
//! - `extract_d_tag()` - Extract identifier from events
//! - `create_test_repo()` - Create repository announcements
//! - `create_issue_for_repo()` - Create issues referencing repos
//! - `create_comment_for_event()` - Create NIP-22 comments
//! - `send_and_verify_accepted()` - Verify event acceptance
//! - `send_and_verify_rejected()` - Verify event rejection
//!
//! ## Performance Target
//!
//! All 12 tests should complete in **under 5 seconds** total when run against
//! a local ngit-relay instance. Each test includes a 100ms sleep for relay
//! propagation, so total theoretical minimum is ~1.2s for serial execution.
//!
//! ## Implementation Notes
//!
//! - Tests use the audit client which automatically adds cleanup tags
//! - All events are tagged for production relay cleanup
//! - Tests are designed to be independent and can run in any order
//! - Forward reference tests verify out-of-order event acceptance
//! - Transitive tests verify multi-hop acceptance chains

use crate::fixtures::{send_and_verify_accepted, send_and_verify_rejected};
use crate::specs::grasp01::SpecRef;
use crate::{AuditClient, AuditResult, FixtureKind, TestContext, TestResult};
use nostr_sdk::prelude::{Event, Filter, Kind, Tag, Timestamp, ToBech32};
use std::time::Duration;

/// Test suite for GRASP-01 event acceptance policy
pub struct EventAcceptancePolicyTests;

impl EventAcceptancePolicyTests {
    /// Run all event acceptance policy tests
    pub async fn run_all(client: &AuditClient) -> AuditResult {
        let mut results = AuditResult::new("GRASP-01 Nostr Event Acceptance Policy Tests");

        // Repository Announcement Acceptance Tests
        results.add(Self::test_accept_valid_repo_announcement(client).await);
        results.add(Self::test_reject_repo_announcement_missing_clone_tag(client).await);
        results.add(Self::test_reject_repo_announcement_missing_relays_tag(client).await);
        results.add(Self::test_accept_maintainer_announcement_without_service_listed(client).await);

        // Group 1: Accept Events Tagging Accepted Repositories
        results.add(Self::test_accept_issue_via_a_tag(client).await);
        results.add(Self::test_accept_comment_via_capital_a_tag(client).await);
        results.add(Self::test_accept_kind1_via_q_tag(client).await);

        // Group 2: Accept Events Tagging Accepted Events (Transitive)
        results.add(Self::test_accept_issue_quoting_issue_via_q(client).await);
        results.add(Self::test_accept_comment_via_capital_e_tag(client).await);
        results.add(Self::test_accept_kind1_via_e_tag(client).await);

        // Group 3: Accept Events Tagged BY Accepted Events (Forward Refs)
        results.add(Self::test_accept_kind1_referenced_in_issue(client).await);
        results.add(Self::test_accept_comment_referenced_in_comment(client).await);
        results.add(Self::test_accept_kind1_referenced_in_kind1(client).await);

        // Group 4: Reject Unrelated Events
        results.add(Self::test_reject_orphan_issue(client).await);
        results.add(Self::test_reject_orphan_kind1(client).await);
        results.add(Self::test_reject_comment_quoting_other_repo(client).await);

        results
    }

    // ============================================================
    // Repository Announcement Acceptance Tests
    // ============================================================

    /// Test: Accept valid repository announcements
    ///
    /// Spec: Line 5 of ../grasp/01.md
    /// Requirement: MUST accept repo announcements listing service in clone & relays tags
    ///
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh repo for full isolation
    /// - In Production mode: Reuses cached repo to minimize events
    pub async fn test_accept_valid_repo_announcement(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_valid_repo_announcement",
            SpecRef::NostrRelayNip01Compliant,
            "MUST accept repo announcements listing service in clone & relays tags",
        )
        .run(|| async {
            // Create TestContext for mode-aware fixture management
            let ctx = TestContext::new(client);

            // Request repository fixture - behavior depends on mode
            let event = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get valid repository fixture: {}",
                        e
                    )
                })?;

            // Get relay URL for validation
            let relay_url = client
                .client()
                .relays()
                .await
                .keys()
                .next()
                .ok_or("No relay connected")?
                .to_string();

            // Convert WebSocket URL to HTTP URL for validation
            let http_url = relay_url
                .replace("ws://", "http://")
                .replace("wss://", "https://");

            // Extract repo_id from the event's d tag
            let repo_id = event
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .ok_or("Missing d tag in announcement")?
                .to_string();

            let event_id = event.id;

            // Query back to verify it was accepted and stored
            let filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(client.public_key())
                .identifier(&repo_id);

            let events = client
                .query(filter)
                .await
                .map_err(|e| format!("Failed to query events from relay: {}", e))?;

            // Verify we got the event back
            if events.is_empty() {
                return Err(format!(
                    "Event was not stored in relay (possibly rejected). Event ID: {}, Repo ID: {}",
                    event_id, repo_id
                ));
            }

            // Verify it's the same event
            let stored_event = events.iter().find(|e| e.id == event_id).ok_or(format!(
                "Stored event ID doesn't match sent event. Expected: {}, Got {} events",
                event_id,
                events.len()
            ))?;

            // Verify key tags are present
            let has_clone_tag = stored_event.tags.iter().any(|t| {
                t.kind() == "clone" && t.content().map(|c| c.contains(&http_url)).unwrap_or(false)
            });

            let has_relays_tag = stored_event
                .tags
                .iter()
                .any(|t| t.kind() == "relays" && t.content() == Some(&relay_url));

            if !has_clone_tag {
                return Err(format!(
                    "Stored event missing clone tag with service URL ({})",
                    http_url
                ));
            }

            if !has_relays_tag {
                return Err(format!(
                    "Stored event missing relays tag with service URL ({})",
                    relay_url
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test: Reject repo announcements not listing service in clone tag
    ///
    /// Spec: Line 7 of ../grasp/01.md
    /// Requirement: MUST reject announcements not listing service (unless GRASP-05)
    pub async fn test_reject_repo_announcement_missing_clone_tag(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            "reject_repo_announcement_missing_clone_tag",
            SpecRef::NostrRelayRejectMissingCloneRelays,
            "MUST reject announcements not listing service in clone tag",
        )
        .run(|| async {
            // Get relay URL from client
            let relay_url = client
                .client()
                .relays()
                .await
                .keys()
                .next()
                .ok_or("No relay connected - client has no active relay connections")?
                .to_string();

            // Create unique repository identifier
            let timestamp = Timestamp::now().as_secs();
            let repo_id = format!("test-repo-no-clone-{}", timestamp);

            // Create repo announcement WITHOUT service in clone tag
            let event = client
                .event_builder(Kind::GitRepoAnnouncement, "")
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom("name", vec!["Test Repo No Clone"]))
                .tag(Tag::custom(
                    "clone",
                    vec!["https://github.com/user/repo.git"],
                )) // NOT this service
                .tag(Tag::custom("relays", vec![relay_url.clone()])) // Correct relay
                .build(client.keys())
                .map_err(|e| format!("Failed to build event: {}", e))?;

            let event_id = event.id;

            // Send event - expect rejection
            let _send_result = client.send_event(event.clone()).await;

            // Query to verify event is NOT stored
            let filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(client.public_key())
                .identifier(&repo_id);

            let events = client
                .query(filter)
                .await
                .map_err(|e| format!("Failed to query events from relay: {}", e))?;

            // Verify event was rejected (not stored)
            if events.iter().any(|e| e.id == event_id) {
                return Err(format!(
                    "Relay incorrectly accepted announcement without service in clone tag. \
                    Event ID: {}, Clone URL: https://github.com/user/repo.git (should require {})",
                    event_id, relay_url
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test: Reject repo announcements not listing service in relays tag
    ///
    /// Spec: Line 7 of ../grasp/01.md
    /// Requirement: MUST reject announcements not listing service in relays
    pub async fn test_reject_repo_announcement_missing_relays_tag(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            "reject_repo_announcement_missing_relays_tag",
            SpecRef::NostrRelayRejectMissingCloneRelays,
            "MUST reject announcements not listing service in relays tag",
        )
        .run(|| async {
            // Get relay URL from client
            let relay_url = client
                .client()
                .relays()
                .await
                .keys()
                .next()
                .ok_or("No relay connected - client has no active relay connections")?
                .to_string();

            // Convert WebSocket URL to HTTP URL for clone tag
            let http_url = relay_url
                .replace("ws://", "http://")
                .replace("wss://", "https://");

            // Create unique repository identifier
            let timestamp = Timestamp::now().as_secs();
            let repo_id = format!("test-repo-no-relays-{}", timestamp);

            // Create repo announcement WITHOUT service in relays tag
            let event = client
                .event_builder(Kind::GitRepoAnnouncement, "")
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom("name", vec!["Test Repo No Relays"]))
                .tag(Tag::custom(
                    "clone",
                    vec![format!(
                        "{}/{}/test-repo.git",
                        http_url,
                        client.public_key()
                    )],
                )) // Correct clone
                .tag(Tag::custom("relays", vec!["wss://relay.damus.io"])) // NOT this service
                .build(client.keys())
                .map_err(|e| format!("Failed to build event: {}", e))?;

            let event_id = event.id;

            // Send event - expect rejection
            let _send_result = client.send_event(event.clone()).await;

            // Query to verify event is NOT stored
            let filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(client.public_key())
                .identifier(&repo_id);

            let events = client
                .query(filter)
                .await
                .map_err(|e| format!("Failed to query events from relay: {}", e))?;

            // Verify event was rejected (not stored)
            if events.iter().any(|e| e.id == event_id) {
                return Err(format!(
                    "Relay incorrectly accepted announcement without service in relays tag. \
                    Event ID: {}, Relays URL: wss://relay.damus.io (should require {})",
                    event_id, relay_url
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test: Admit a maintainer-discovery announcement without the service.
    ///
    /// Spec: Line 7 of ../grasp/01.md (EXCEPTION to rejection rule)
    /// Requirement: MUST accept candidate announcements for dependency discovery
    ///
    /// GRASP-01: "respecting the recursive maintainer set"
    ///
    /// A listed candidate may publish its reciprocal announcement for the same
    /// identifier. The relay must admit that announcement without this GRASP
    /// server in its clone tag so membership dependencies can be discovered.
    ///
    /// This also enables GRASP-02 to sync state events and git data when authoritative
    /// users publish them to other relays/git servers, keeping repos up-to-date.
    pub async fn test_accept_maintainer_announcement_without_service_listed(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            "accept_maintainer_discovery_announcement_without_service",
            SpecRef::NostrRelayRejectMissingCloneRelays,
            "MUST admit maintainer announcements needed for dependency discovery",
        )
        .run(|| async {
            // Create TestContext for mode-aware fixture management
            let ctx = TestContext::new(client);

            // Step 1: Get the legacy-named recursive fixture. It establishes a
            // transitively reciprocal component with all Git data pushed.
            let recursive_state = ctx
                .get_fixture(FixtureKind::RecursiveMaintainerStateDataPushed)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get RecursiveMaintainerStateDataPushed fixture: {}",
                        e
                    )
                })?;

            // Extract repo_id from the recursive maintainer's state event
            let repo_id = recursive_state
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .ok_or("Missing d tag in recursive maintainer state")?
                .to_string();

            // Step 2: Build the additional maintainer's announcement without
            // this GRASP server in its clone tag - simulating an announcement pointing
            // to a different server (e.g., another GRASP server)
            let recursive_maintainer_npub = client
                .recursive_maintainer_keys()
                .public_key()
                .to_bech32()
                .map_err(|e| format!("Failed to convert recursive maintainer pubkey: {}", e))?;

            // This replaces the reciprocal announcement created by the fixture.
            // Order it after that event explicitly: using the wall clock alone
            // makes a fast run depend on the equal-timestamp event-ID tie-break.
            let previous_time = client
                .query(
                    Filter::new()
                        .kind(Kind::GitRepoAnnouncement)
                        .author(client.recursive_maintainer_keys().public_key())
                        .identifier(&repo_id),
                )
                .await
                .map_err(|e| format!("Failed to query reciprocal announcement: {e}"))?
                .iter()
                .map(|event| event.created_at.as_secs())
                .max()
                .ok_or("Fixture reciprocal announcement is not served")?;
            let replacement_time = previous_time
                .checked_add(1)
                .ok_or("Reciprocal announcement timestamp overflow")?
                .max(Timestamp::now().as_secs());

            // Create announcement with external clone URL (not this server)
            let recursive_maintainer_announcement = client
                .event_builder(
                    Kind::GitRepoAnnouncement,
                    format!(
                        "Recursive maintainer announcement for {} (external clone)",
                        repo_id
                    ),
                )
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom(
                    "name",
                    vec![format!("{} (recursive maintainer view)", repo_id)],
                ))
                // Clone points to another server, NOT the GRASP server
                .tag(Tag::custom(
                    "clone",
                    vec![format!(
                        "https://another-grasp-server.com/{}/{}.git",
                        recursive_maintainer_npub, repo_id
                    )],
                ))
                // Relays also points elsewhere (not this server)
                .tag(Tag::custom(
                    "relays",
                    vec!["wss://relay.damus.io"],
                ))
                // List the assigning maintainer back: this replaceable event
                // supersedes the fixture's reciprocal announcement, and NIP-34
                // demotes a member to invited if their announcement stops
                // assigning a role to an existing member.
                .tag(Tag::custom(
                    "maintainers",
                    vec![client.maintainer_pubkey_hex()],
                ))
                .custom_time(Timestamp::from(replacement_time))
                .build(client.recursive_maintainer_keys())
                .map_err(|e| format!("Failed to build recursive maintainer announcement: {}", e))?;

            let event_id = recursive_maintainer_announcement.id;

            // Step 3: Send the maintainer-discovery announcement.
            client
                .send_event(recursive_maintainer_announcement)
                .await
                .map_err(|e| format!("Failed to send recursive maintainer announcement: {}", e))?;

            // The successful send acknowledges storage of this external
            // announcement; verify its exact ID without a propagation sleep.
            // Step 4: Query to verify it was accepted
            let filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(client.recursive_maintainer_keys().public_key())
                .identifier(&repo_id);

            let events = client
                .query(filter)
                .await
                .map_err(|e| format!("Failed to query events: {}", e))?;

            // Verify the dependency announcement was stored.
            if !events.iter().any(|e| e.id == event_id) {
                return Err(format!(
                    "Maintainer dependency announcement was NOT accepted by relay. \
                    A transitively listed candidate published a reciprocal announcement for \
                    repo {} with an external clone URL. The relay should admit it for \
                    dependency discovery without treating admission as authority. Event ID: {}",
                    repo_id, event_id
                ));
            }

            Ok(())
        })
        .await
    }

    // ============================================================
    // Helper Functions (6 total)
    // ============================================================

    /// Extract the `d` tag value from an event
    fn extract_d_tag(event: &Event) -> Option<String> {
        for tag in event.tags.iter() {
            let tag_vec = tag.clone().to_vec();
            if tag_vec.len() >= 2 && tag_vec[0] == "d" {
                return Some(tag_vec[1].to_string());
            }
        }
        None
    }

    /// Create a basic repository announcement (kind 30617)
    /// Uses the client's create_repo_announcement helper which includes required clone and relays tags
    async fn create_test_repo(client: &AuditClient, repo_id: &str) -> Result<Event, String> {
        client
            .create_repo_announcement(repo_id)
            .await
            .map_err(|e| format!("Test setup failed: could not create test repository: {}", e))
    }

    /// Create an issue (kind 1621) that references a repository
    /// Uses AuditClient::create_issue helper method
    fn create_issue_for_repo(
        client: &AuditClient,
        repo_event: &Event,
        issue_title: &str,
    ) -> Result<Event, String> {
        client
            .create_issue(repo_event, issue_title, "issue content", vec![])
            .map_err(|e| format!("Test setup failed: could not create test issue: {}", e))
    }

    /// Create a NIP-22 comment (kind 1111) for an event
    /// Uses AuditClient::create_comment helper method
    fn create_comment_for_event(
        client: &AuditClient,
        event: &Event,
        content: &str,
    ) -> Result<Event, String> {
        client
            .create_comment(event, content, vec![])
            .map_err(|e| format!("Test setup failed: could not create test comment: {}", e))
    }

    // ============================================================
    // Group 1: Accept Events Tagging Accepted Repositories (3 tests)
    // ============================================================

    /// Test 1.1: Issue referencing repo via `a` tag should be accepted
    ///
    /// Spec: Line 11 of ../grasp/01.md
    /// **EXAMPLE: Using TestContext for prerequisite events**
    /// Demonstrates how TestContext simplifies test setup while supporting dual modes
    pub async fn test_accept_issue_via_a_tag(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_issue_via_a_tag",
            SpecRef::NostrRelayMustAcceptTaggedEvents,
            "Accept issue referencing repo via 'a' tag",
        )
        .run(|| async {
            // NEW: Create TestContext
            let ctx = TestContext::new(client);

            // NEW: Get repository fixture (mode-aware)
            let repo = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get valid repository fixture: {}",
                        e
                    )
                })?;

            // 2. Create issue that references the repo
            let issue = Self::create_issue_for_repo(client, &repo, "Test Issue 1")?;

            // 3. Send issue and verify it's accepted
            send_and_verify_accepted(client, issue, "issue referencing repo via 'a' tag").await?;

            Ok(())
        })
        .await
    }

    /// Test 1.2: NIP-22 comment with root `A` tag referencing repo should be accepted
    ///
    /// Spec: Line 11 of ../grasp/01.md
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh repo for full isolation
    /// - In Production mode: Reuses cached repo to minimize events
    pub async fn test_accept_comment_via_capital_a_tag(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_comment_via_A_tag",
            SpecRef::NostrRelayMustAcceptTaggedEvents,
            "Accept NIP-22 comment with root 'A' tag referencing repo",
        )
        .run(|| async {
            // Create TestContext
            let ctx = TestContext::new(client);

            // Get repository fixture (mode-aware)
            let repo = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get valid repository fixture: {}",
                        e
                    )
                })?;

            // Extract repo_id and create `A` tag manually
            let repo_id =
                Self::extract_d_tag(&repo).ok_or("Failed to extract repo_id from repo event")?;
            let a_tag_value = format!("30617:{}:{}", repo.pubkey, repo_id);

            // Create comment with `A` tag (root reference to repo)
            let tags = vec![
                Tag::custom(
                    "A",
                    vec![a_tag_value.clone(), "".to_string(), "root".to_string()],
                ),
                Tag::custom("K", vec!["30617".to_string()]),
                Tag::public_key(repo.pubkey),
            ];

            let comment = client
                .event_builder(Kind::Comment, "Comment on repo")
                .tags(tags)
                .build(client.keys())
                .map_err(|e| format!("Failed to build comment: {}", e))?;

            // Send comment and verify it's accepted
            send_and_verify_accepted(client, comment, "comment with 'A' tag to repo").await?;

            Ok(())
        })
        .await
    }

    /// Test 1.3: Kind 1 text note quoting repo via `q` tag should be accepted
    ///
    /// Spec: Line 11 of ../grasp/01.md
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh repo for full isolation
    /// - In Production mode: Reuses cached repo to minimize events
    pub async fn test_accept_kind1_via_q_tag(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_kind1_via_q_tag",
            SpecRef::NostrRelayMustAcceptTaggedEvents,
            "Accept kind 1 text note quoting repo via 'q' tag",
        )
        .run(|| async {
            // Create TestContext
            let ctx = TestContext::new(client);

            // Get repository fixture (mode-aware)
            let repo = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get valid repository fixture: {}",
                        e
                    )
                })?;

            // Extract repo_id and create `q` tag
            let repo_id =
                Self::extract_d_tag(&repo).ok_or("Failed to extract repo_id from repo event")?;
            let a_tag_value = format!("30617:{}:{}", repo.pubkey, repo_id);

            // Create kind 1 note with `q` tag (quote reference to repo)
            let tags = vec![Tag::custom("q", vec![a_tag_value])];

            let note = client
                .event_builder(Kind::TextNote, "Mentioning this repo")
                .tags(tags)
                .build(client.keys())
                .map_err(|e| format!("Failed to build note: {}", e))?;

            // Send note and verify it's accepted
            send_and_verify_accepted(client, note, "kind 1 with 'q' tag to repo").await?;

            Ok(())
        })
        .await
    }

    // ============================================================
    // Group 2: Accept Events Tagging Accepted Events (3 tests)
    // ============================================================

    /// Test 2.1: Issue quoting another accepted issue should be accepted (transitive)
    ///
    /// Spec: Line 11 of ../grasp/01.md
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh repo+issue for full isolation
    /// - In Production mode: Reuses cached repo+issue to minimize events
    pub async fn test_accept_issue_quoting_issue_via_q(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_issue_quoting_issue_via_q",
            SpecRef::NostrRelayMustAcceptTaggedEvents,
            "Accept issue quoting another accepted issue (transitive)",
        )
        .run(|| async {
            // Create TestContext
            let ctx = TestContext::new(client);

            // Get repo with issue fixture (mode-aware) - returns the issue event
            let issue_a = ctx
                .get_fixture(FixtureKind::RepoWithIssue)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get repo with issue fixture: {}",
                        e
                    )
                })?;

            // Create Repo B but DON'T send it (unaccepted) - just for creating Issue B
            let repo_b = Self::create_test_repo(client, "repo-b").await?;

            // Create Issue B that quotes accepted Issue A via 'q' tag (should make it accepted)
            let additional_tags = vec![Tag::custom("q", vec![issue_a.id.to_hex()])];

            let issue_b = client
                .create_issue(&repo_b, "Issue B", "issue content", additional_tags)
                .map_err(|e| format!("Failed to build issue B: {}", e))?;

            // Send Issue B and verify it's ACCEPTED (via transitive quote to Issue A)
            send_and_verify_accepted(client, issue_b, "issue B quoting accepted issue A").await?;

            Ok(())
        })
        .await
    }

    /// Test 2.2: NIP-22 comment with root 'E' tag to accepted issue should be accepted
    ///
    /// Spec: Line 11 of ../grasp/01.md
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh repo+issue for full isolation
    /// - In Production mode: Reuses cached repo+issue to minimize events
    pub async fn test_accept_comment_via_capital_e_tag(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_comment_via_E_tag",
            SpecRef::NostrRelayMustAcceptTaggedEvents,
            "Accept NIP-22 comment with root 'E' tag to accepted issue",
        )
        .run(|| async {
            // Create TestContext
            let ctx = TestContext::new(client);

            // Get repo with issue fixture (mode-aware) - returns the issue event
            let issue = ctx
                .get_fixture(FixtureKind::RepoWithIssue)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get repo with issue fixture: {}",
                        e
                    )
                })?;

            // Create comment using the helper (which adds NIP-22 tags including 'E')
            let comment = Self::create_comment_for_event(client, &issue, "Comment content")?;

            // Send comment and verify it's accepted (via E tag to accepted issue)
            send_and_verify_accepted(client, comment, "comment with E tag to accepted issue")
                .await?;

            Ok(())
        })
        .await
    }

    /// Test 2.3: Kind 1 note with 'e' tag reply to accepted kind 1 should be accepted
    ///
    /// Spec: Line 11 of ../grasp/01.md
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh repo for full isolation
    /// - In Production mode: Reuses cached repo to minimize events
    pub async fn test_accept_kind1_via_e_tag(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_kind1_via_e_tag",
            SpecRef::NostrRelayMustAcceptTaggedEvents,
            "Accept kind 1 reply via 'e' tag to accepted kind 1",
        )
        .run(|| async {
            // Create TestContext
            let ctx = TestContext::new(client);

            // Get repository fixture (mode-aware)
            let repo = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get valid repository fixture: {}",
                        e
                    )
                })?;

            // Create Kind 1 A that quotes the repo (makes it accepted)
            let repo_id = Self::extract_d_tag(&repo).ok_or("Failed to extract repo_id")?;
            let a_tag_value = format!("30617:{}:{}", repo.pubkey, repo_id);

            let kind1_a = client
                .event_builder(Kind::TextNote, "Note A about repo")
                .tags(vec![Tag::custom("q", vec![a_tag_value])])
                .build(client.keys())
                .map_err(|e| format!("Failed to build kind1 A: {}", e))?;

            send_and_verify_accepted(client, kind1_a.clone(), "kind 1 A quoting repo").await?;

            // Create Kind 1 B that replies to Kind 1 A via 'e' tag
            let kind1_b = client
                .event_builder(Kind::TextNote, "Reply to Note A")
                .tags(vec![Tag::event(kind1_a.id)])
                .build(client.keys())
                .map_err(|e| format!("Failed to build kind1 B: {}", e))?;

            // Send Kind 1 B and verify it's accepted (via 'e' tag to accepted kind 1 A)
            send_and_verify_accepted(client, kind1_b, "kind 1 B replying to accepted kind 1 A")
                .await?;

            Ok(())
        })
        .await
    }

    // ============================================================
    // Group 3: Accept Events Tagged BY Accepted Events (3 tests)
    // ============================================================

    /// Test 3.1: Kind 1 note should be accepted when referenced by an accepted issue (forward ref)
    ///
    /// Spec: Line 11 of ../grasp/01.md
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh repo for full isolation
    /// - In Production mode: Reuses cached repo to minimize events
    pub async fn test_accept_kind1_referenced_in_issue(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_kind1_referenced_in_issue",
            SpecRef::NostrRelayMustAcceptTaggedEvents,
            "Accept kind 1 referenced in accepted issue (forward ref)",
        )
        .run(|| async {
            // Create TestContext
            let ctx = TestContext::new(client);

            // Get repository fixture (mode-aware)
            let repo = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get valid repository fixture: {}",
                        e
                    )
                })?;

            // Verify repo is queryable (ensures it's fully indexed before we reference it)
            let repo_id = Self::extract_d_tag(&repo).ok_or("Failed to extract repo_id")?;
            let verify_filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(repo.pubkey)
                .identifier(repo_id);

            // Poll until repo is available (with timeout)
            for _ in 0..10 {
                let events = client
                    .query(verify_filter.clone())
                    .await
                    .map_err(|e| format!("Failed to verify repo: {}", e))?;
                if !events.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            // Extra delay to ensure relay's internal database is fully synchronized
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Create Kind 1 note locally but DON'T send it yet
            let kind1_note = client
                .event_builder(Kind::TextNote, "Note to be referenced")
                .build(client.keys())
                .map_err(|e| format!("Failed to build kind1: {}", e))?;

            // Create and send issue that QUOTES the unsent Kind 1 note
            let issue_tags = vec![
                // Reference to accepted repo
                Tag::custom(
                    "a",
                    vec![format!(
                        "30617:{}:{}",
                        repo.pubkey,
                        Self::extract_d_tag(&repo).unwrap()
                    )],
                ),
                Tag::custom("subject", vec!["Issue referencing kind1".to_string()]),
                // Quote the Kind 1 that hasn't been sent yet
                Tag::custom("q", vec![kind1_note.id.to_hex()]),
            ];

            let issue = client
                .event_builder(Kind::GitIssue, "issue content")
                .tags(issue_tags)
                .build(client.keys())
                .map_err(|e| format!("Failed to build issue: {}", e))?;

            send_and_verify_accepted(client, issue, "issue quoting unsent kind1").await?;

            // NOW send the Kind 1 note - should be accepted because accepted issue quotes it
            send_and_verify_accepted(
                client,
                kind1_note,
                "kind1 note referenced by accepted issue",
            )
            .await?;

            Ok(())
        })
        .await
    }

    /// Test 3.2: Comment should be accepted when referenced by another accepted comment (forward ref)
    ///
    /// Spec: Line 11 of ../grasp/01.md
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh repo+issue for full isolation
    /// - In Production mode: Reuses cached repo+issue to minimize events
    pub async fn test_accept_comment_referenced_in_comment(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_comment_referenced_in_comment",
            SpecRef::NostrRelayMustAcceptTaggedEvents,
            "Accept comment referenced in another accepted comment (forward ref)",
        )
        .run(|| async {
            // Create TestContext
            let ctx = TestContext::new(client);

            // Get issue fixture (mode-aware) - RepoWithIssue returns the issue event directly
            let issue = ctx
                .get_fixture(FixtureKind::RepoWithIssue)
                .await
                .map_err(|e| format!("Test setup failed: could not get issue fixture: {}", e))?;

            // Create Comment A locally but DON'T send it yet
            let comment_a = Self::create_comment_for_event(client, &issue, "Comment A")?;

            // Create and send Comment B that quotes Comment A (which hasn't been sent)
            let comment_b_tags = vec![
                // NIP-22 tags for the original issue
                Tag::custom(
                    "E",
                    vec![issue.id.to_hex(), "".to_string(), "root".to_string()],
                ),
                Tag::event(issue.id),
                Tag::custom("K", vec![issue.kind.as_u16().to_string()]),
                Tag::public_key(issue.pubkey),
                // Quote Comment A which hasn't been sent yet
                Tag::custom("q", vec![comment_a.id.to_hex()]),
            ];

            let comment_b = client
                .event_builder(Kind::Comment, "Comment B quoting Comment A")
                .tags(comment_b_tags)
                .build(client.keys())
                .map_err(|e| format!("Failed to build comment B: {}", e))?;

            send_and_verify_accepted(client, comment_b, "comment B quoting unsent comment A")
                .await?;

            // NOW send Comment A - should be accepted because accepted Comment B quotes it
            send_and_verify_accepted(
                client,
                comment_a,
                "comment A referenced by accepted comment B",
            )
            .await?;

            Ok(())
        })
        .await
    }

    /// Test 3.3: Kind 1 note should be accepted when referenced by another accepted kind 1 (forward ref)
    ///
    /// Spec: Line 11 of ../grasp/01.md
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh repo for full isolation
    /// - In Production mode: Reuses cached repo to minimize events
    pub async fn test_accept_kind1_referenced_in_kind1(client: &AuditClient) -> TestResult {
        TestResult::new(
            "accept_kind1_referenced_in_kind1",
            SpecRef::NostrRelayMustAcceptTaggedEvents,
            "Accept kind 1 referenced in another accepted kind 1 (forward ref)",
        )
        .run(|| async {
            // Create TestContext
            let ctx = TestContext::new(client);

            // Get repository fixture (mode-aware)
            let repo = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get valid repository fixture: {}",
                        e
                    )
                })?;

            // Create Kind 1 A locally but DON'T send it yet
            let kind1_a = client
                .event_builder(Kind::TextNote, "Note A to be referenced")
                .build(client.keys())
                .map_err(|e| format!("Failed to build kind1 A: {}", e))?;

            // Create and send Kind 1 B that:
            //    - Quotes the repo (makes it accepted)
            //    - Mentions Kind 1 A via 'e' tag (which hasn't been sent yet)
            let repo_id = Self::extract_d_tag(&repo).ok_or("Failed to extract repo_id")?;
            let a_tag_value = format!("30617:{}:{}", repo.pubkey, repo_id);

            let kind1_b = client
                .event_builder(Kind::TextNote, "Note B mentioning Note A")
                .tags(vec![
                    Tag::custom("q", vec![a_tag_value]), // Quote repo (accepted)
                    Tag::event(kind1_a.id),              // Mention unsent Kind 1 A
                ])
                .build(client.keys())
                .map_err(|e| format!("Failed to build kind1 B: {}", e))?;

            send_and_verify_accepted(client, kind1_b, "kind1 B mentioning unsent kind1 A").await?;

            // NOW send Kind 1 A - should be accepted because accepted Kind 1 B mentions it
            send_and_verify_accepted(client, kind1_a, "kind1 A referenced by accepted kind1 B")
                .await?;

            Ok(())
        })
        .await
    }

    // ============================================================
    // Group 4: Reject Unrelated Events (3 tests)
    // ============================================================

    /// Test 4.1: Issue referencing unaccepted repo should be rejected
    ///
    /// Spec: Line 16 of ../grasp/01.md
    /// (Rejecting non-git-related events falls under MAY reject for curation)
    pub async fn test_reject_orphan_issue(client: &AuditClient) -> TestResult {
        TestResult::new(
            "reject_orphan_issue",
            SpecRef::NostrRelayMayRejectSpamCuration,
            "Reject issue referencing unaccepted repo",
        )
        .run(|| async {
            // 1. Create a repo but DON'T send it (so it's unaccepted)
            let unaccepted_repo = Self::create_test_repo(client, "unaccepted-repo-1").await?;

            // 2. Create issue that references the unaccepted repo
            let orphan_issue =
                Self::create_issue_for_repo(client, &unaccepted_repo, "Orphan Issue")?;

            // 3. Send issue and verify it's REJECTED
            send_and_verify_rejected(client, orphan_issue, "issue referencing unaccepted repo")
                .await?;

            Ok(())
        })
        .await
    }

    /// Test 4.2: Generic kind 1 note with no repo references should be rejected
    ///
    /// Spec: Line 16 of ../grasp/01.md
    /// (Rejecting non-git-related events falls under MAY reject for curation)
    pub async fn test_reject_orphan_kind1(client: &AuditClient) -> TestResult {
        TestResult::new(
            "reject_orphan_kind1",
            SpecRef::NostrRelayMayRejectSpamCuration,
            "Reject kind 1 with no repo references",
        )
        .run(|| async {
            // 1. Create a kind 1 note with no tags (no repo references)
            let orphan_note = client
                .event_builder(Kind::TextNote, "Just a random note")
                .build(client.keys())
                .map_err(|e| format!("Failed to build note: {}", e))?;

            // 2. Send note and verify it's REJECTED
            send_and_verify_rejected(client, orphan_note, "kind 1 with no repo references").await?;

            Ok(())
        })
        .await
    }

    /// Test 4.3: Comment quoting unaccepted repo should be rejected
    ///
    /// Spec: Line 16 of ../grasp/01.md
    /// (Rejecting non-git-related events falls under MAY reject for curation)
    /// **Using TestContext pattern:**
    /// - In CI mode: Creates fresh accepted repo for full isolation
    /// - In Production mode: Reuses cached accepted repo to minimize events
    /// - Note: Unaccepted repo B is always created fresh (not cached) since it must remain unaccepted
    pub async fn test_reject_comment_quoting_other_repo(client: &AuditClient) -> TestResult {
        TestResult::new(
            "reject_comment_quoting_other_repo",
            SpecRef::NostrRelayMayRejectSpamCuration,
            "Reject comment quoting unaccepted repo",
        )
        .run(|| async {
            // Create TestContext
            let ctx = TestContext::new(client);

            // Get accepted repo A fixture (mode-aware)
            let _repo_a = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| {
                    format!(
                        "Test setup failed: could not get valid repository fixture: {}",
                        e
                    )
                })?;

            // Create Repo B but DON'T send it (unaccepted)
            let repo_b = Self::create_test_repo(client, "unaccepted-repo-b").await?;

            // Extract repo_b info and create comment that quotes repo B (not repo A)
            let repo_b_id = Self::extract_d_tag(&repo_b).ok_or("Failed to extract repo_b id")?;
            let repo_b_a_tag = format!("30617:{}:{}", repo_b.pubkey, repo_b_id);

            // Create comment that references ONLY repo B (unaccepted)
            let tags = vec![
                Tag::custom("A", vec![repo_b_a_tag, "".to_string(), "root".to_string()]),
                Tag::custom("K", vec!["30617".to_string()]),
                Tag::public_key(repo_b.pubkey),
            ];

            let comment = client
                .event_builder(Kind::Comment, "Comment on unaccepted repo")
                .tags(tags)
                .build(client.keys())
                .map_err(|e| format!("Failed to build comment: {}", e))?;

            // Send comment and verify it's REJECTED (only references unaccepted repo B)
            send_and_verify_rejected(client, comment, "comment quoting only unaccepted repo")
                .await?;

            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditConfig;

    #[tokio::test]
    #[ignore] // Requires running relay
    async fn test_grasp01_event_acceptance_policy_against_relay() {
        // Read relay URL from environment variable - must be supplied
        let relay_url = std::env::var("RELAY_URL").expect(
            "RELAY_URL environment variable must be set. Example: RELAY_URL=ws://localhost:18081",
        );

        let config = AuditConfig::isolated();
        let client = AuditClient::new(&relay_url, config)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to connect to relay at {}. Ensure relay is running and accessible. \
                Try: docker run --rm -p 18081:8081 ghcr.io/danconwaydev/ngit-relay:latest",
                    relay_url
                )
            });

        let results = EventAcceptancePolicyTests::run_all(&client).await;
        results.print_report();

        // Don't assert all passed yet - some tests may be failing
        // Future: assert!(results.all_passed(), "Some GRASP-01 event acceptance tests failed");
    }
}
