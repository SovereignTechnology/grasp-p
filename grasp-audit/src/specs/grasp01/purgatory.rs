//! GRASP-01 Purgatory Tests
//!
//! Tests for the GRASP-01 purgatory mechanism where events are accepted but not
//! served until corresponding git data arrives.
//!
//! ## Purgatory Behavior (GRASP-01 Line 20)
//!
//! "Accepted repo state announcements, PRs and PR Updates
//! SHOULD be accepted with message 'purgatory: won't be served until git data arrives'
//! and kept in purgatory (not served) until the related git data arrives and otherwise
//! discarded after 30 minutes."
//!
//! ## Test Categories
//!
//! ### Announcement Purgatory (feature not yet implemented)
//! - `test_announcement_not_served_before_git_data`
//! - `test_announcement_served_after_git_push`
//! - `test_bare_repo_exists_for_purgatory_announcement`
//! - `test_state_event_accepted_for_purgatory_announcement`
//!
//! ### State Event Purgatory (already implemented)
//! - `test_state_event_not_served_before_git_data`
//! - `test_state_event_served_after_git_push`
//!
//! ### PR Purgatory (already implemented)
//! - `test_pr_event_accepted_into_purgatory` - Event accepted, not queryable
//! - `test_pr_event_in_purgatory_git_push_accepted` - Git push to refs/nostr/<event-id> succeeds
//! - `test_pr_event_served_after_git_push` - Event becomes queryable after git data

use crate::fixtures::{clone_repo, create_commit, try_push};
use crate::specs::grasp01::SpecRef;
use crate::{AuditClient, AuditResult, FixtureKind, TestContext, TestResult};
use nostr_sdk::prelude::*;
use std::fs;
use std::time::Duration;

/// Test suite for GRASP-01 purgatory behavior
pub struct PurgatoryTests;

impl PurgatoryTests {
    /// Run all purgatory tests
    pub async fn run_all(client: &AuditClient) -> AuditResult {
        let mut results = AuditResult::new("GRASP-01 Purgatory Tests");

        // Announcement purgatory tests (feature not yet implemented)
        results.add(Self::test_announcement_not_served_before_git_data(client).await);
        results.add(Self::test_announcement_served_after_git_push(client).await);
        results.add(Self::test_bare_repo_exists_for_purgatory_announcement(client).await);

        // State event purgatory tests
        results.add(Self::test_state_event_accepted_for_purgatory_announcement(client).await);
        results.add(Self::test_state_event_not_served_before_git_data(client).await);
        results.add(Self::test_state_event_served_after_git_push(client).await);

        // Deletion event tests (NIP-09)
        results.add(Self::test_deletion_by_event_id_removes_purgatory_state_event(client).await);
        results.add(Self::test_deletion_by_coordinate_removes_purgatory_state_event(client).await);

        // PR purgatory tests
        results.add(Self::test_pr_event_accepted_into_purgatory_and_isnt_served(client).await);
        results.add(Self::test_pr_event_in_purgatory_git_push_accepted(client).await);
        results.add(Self::test_pr_event_served_after_git_push(client).await);

        results
    }

    // ============================================================
    // Announcement Purgatory Tests (#[ignore] - feature not yet implemented)
    // ============================================================

    /// Test: Repository announcement not served before git data arrives
    ///
    /// Legacy relay behavior — not a current GRASP-01 requirement.
    /// Previous revisions required repository announcements to be accepted with message
    /// 'purgatory: won't be served until git data arrives' and kept in purgatory
    /// (not served) until the related git data arrives"
    ///
    /// This test verifies:
    /// 1. Send a valid repository announcement
    /// 2. Event is accepted (OK response)
    /// 3. Event is NOT queryable from the relay (in purgatory)
    ///
    /// NOTE: Announcement purgatory feature not yet implemented - test may fail
    pub async fn test_announcement_not_served_before_git_data(client: &AuditClient) -> TestResult {
        TestResult::new(
            "announcement_not_served_before_git_data",
            SpecRef::PurgatoryAcceptUntilGitData,
            "Repository announcements SHOULD be accepted but not served until git data arrives",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // Use the purgatory-specific fixture which creates its own independent repo.
            // The shared ValidRepoSent may already be promoted (served) by the time this
            // test runs if earlier specs triggered OwnerStateDataPushed. PurgatoryValidRepoSent
            // is never promoted by any other test so the announcement stays in purgatory.
            let repo = ctx
                .get_fixture(FixtureKind::PurgatoryValidRepoSent)
                .await
                .map_err(|e| format!("Failed to create repo announcement: {}", e))?;

            let repo_id = repo
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .ok_or("Missing d tag in repo announcement")?
                .to_string();

            // Query for the announcement - should NOT be served (purgatory)
            let filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(client.public_key())
                .identifier(&repo_id);

            tokio::time::sleep(Duration::from_millis(300)).await;

            let events = client
                .query(filter)
                .await
                .map_err(|e| format!("Failed to query relay: {}", e))?;

            if events.iter().any(|e| e.id == repo.id) {
                return Err(format!(
                    "Announcement was served immediately - purgatory not implemented. \
                     Event ID: {} should NOT be queryable until git data arrives",
                    repo.id
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test: Repository announcement served after git push
    ///
    /// Legacy relay behavior — not a current GRASP-01 requirement.
    /// This verifies the former repository-announcement purgatory lifecycle.
    ///
    /// This test verifies the full lifecycle:
    /// 1. Send repository announcement (enters purgatory)
    /// 2. Send state event (enters purgatory)
    /// 3. Push git data matching state event
    /// 4. Both announcement and state event are now served
    ///
    /// NOTE: Announcement purgatory feature not yet implemented - test may fail
    pub async fn test_announcement_served_after_git_push(client: &AuditClient) -> TestResult {
        TestResult::new(
            "announcement_served_after_git_push",
            SpecRef::PurgatoryAcceptUntilGitData,
            "Repository announcements SHOULD be served after git data arrives",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // PurgatoryOwnerStateDataPushed fixture handles the full lifecycle:
            // 1. Creates repo announcement (purgatory)
            // 2. Creates state event (purgatory)
            // 3. Pushes git data
            // 4. Verifies events are served
            let state_event = ctx
                .get_fixture(FixtureKind::PurgatoryOwnerStateDataPushed)
                .await
                .map_err(|e| format!("Failed to complete full lifecycle: {}", e))?;

            // Extract repo_id from state event
            let repo_id = state_event
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .ok_or("Missing d tag in state event")?
                .to_string();

            // Verify announcement is now served
            let announcement_filter = Filter::new()
                .kind(Kind::GitRepoAnnouncement)
                .author(client.public_key())
                .identifier(&repo_id);

            let announcements = client
                .query(announcement_filter)
                .await
                .map_err(|e| format!("Failed to query announcements: {}", e))?;

            if announcements.is_empty() {
                return Err(format!(
                    "Announcement not served after git push. Repo ID: {}",
                    repo_id
                ));
            }

            // Verify state event is served by querying its specific event ID.
            // We intentionally query by ID rather than kind+author+identifier because
            // other tests (e.g. push-auth) may have sent a newer replaceable state event
            // for the same repo_id, which would displace this one in an identifier query.
            let served = client
                .is_event_on_relay(state_event.id)
                .await
                .map_err(|e| format!("Failed to query state event: {}", e))?;

            if !served {
                return Err(format!(
                    "State event not served after git push. Event ID: {}",
                    state_event.id
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test: Bare repository exists for purgatory announcement
    ///
    /// Legacy relay behavior — GRASP-01 line 32 applies only to accepted
    /// "MUST serve a git repository via an unauthenticated git smart http service
    /// at `/<npub>/<percent-encoded-identifier>.git` for each accepted git repository
    /// announcement."
    ///
    /// This test verifies that git HTTP service works even for repos in purgatory.
    ///
    /// NOTE: Announcement purgatory feature not yet implemented - test may fail
    pub async fn test_bare_repo_exists_for_purgatory_announcement(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            "bare_repo_exists_for_purgatory_announcement",
            SpecRef::GitServeRepository,
            "Git HTTP service MUST work for repos in purgatory",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // Get the purgatory-specific repo announcement (never promoted by other tests)
            let repo = ctx
                .get_fixture(FixtureKind::PurgatoryValidRepoSent)
                .await
                .map_err(|e| format!("Failed to create repo announcement: {}", e))?;

            let repo_id = repo
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .ok_or("Missing d tag in repo announcement")?
                .to_string();

            let npub = client
                .public_key()
                .to_bech32()
                .map_err(|e| format!("Failed to convert pubkey: {}", e))?;

            // Get relay domain
            let relay_url = client
                .client()
                .relays()
                .await
                .keys()
                .next()
                .ok_or("No relay connected")?
                .to_string();
            let relay_domain = relay_url
                .replace("ws://", "")
                .replace("wss://", "")
                .replace(":8080", "");

            // Check git HTTP service is available
            let info_refs_url = format!(
                "http://{}/{}/{}.git/info/refs?service=git-upload-pack",
                relay_domain, npub, repo_id
            );

            let http_client = reqwest::Client::new();
            let response = http_client
                .get(&info_refs_url)
                .send()
                .await
                .map_err(|e| format!("HTTP request failed: {}", e))?;

            if !response.status().is_success() {
                return Err(format!(
                    "Git HTTP service not available for purgatory repo. \
                     URL: {}, Status: {}",
                    info_refs_url,
                    response.status()
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test: State event accepted for purgatory announcement
    ///
    /// Spec: GRASP-01 Line 20
    /// "Accepted repo state announcements... SHOULD be accepted"
    ///
    /// This test verifies that state events are accepted even when the repo
    /// announcement is in purgatory (no git data yet).
    ///
    /// NOTE: Announcement purgatory feature not yet implemented - test may fail
    pub async fn test_state_event_accepted_for_purgatory_announcement(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            "state_event_accepted_for_purgatory_announcement",
            SpecRef::PurgatoryAcceptUntilGitData,
            "State events SHOULD be accepted for repos in purgatory",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // Get the purgatory-specific repo announcement (never promoted by other tests)
            let repo = ctx
                .get_fixture(FixtureKind::PurgatoryValidRepoSent)
                .await
                .map_err(|e| format!("Failed to create repo announcement: {}", e))?;

            // Build a state event for this repo
            let repo_id = repo
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .ok_or("Missing d tag in repo announcement")?
                .to_string();

            let state_event = client
                .event_builder(Kind::RepoState, "")
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom(
                    "refs/heads/main",
                    vec!["abc123".to_string()],
                ))
                .tag(Tag::custom(
                    "HEAD",
                    vec!["ref: refs/heads/main".to_string()],
                ))
                .build(client.keys())
                .map_err(|e| format!("Failed to build state event: {}", e))?;

            // Send state event - should be accepted (even though repo is in purgatory)
            let (_, in_purgatory) = client
                .send_event_and_note_purgatory(state_event.clone())
                .await
                .map_err(|e| format!("Failed to send state event: {}", e))?;

            // Event should be accepted (either in purgatory or served)
            // We just verify it wasn't rejected
            if !in_purgatory {
                // Check if it's actually on the relay (might be served immediately)
                let filter = Filter::new()
                    .kind(Kind::RepoState)
                    .author(client.public_key())
                    .identifier(&repo_id);

                let events = client
                    .query(filter)
                    .await
                    .map_err(|e| format!("Failed to query: {}", e))?;

                if events.iter().any(|e| e.id == state_event.id) {
                    return Err(format!(
                        "State event was served immediately - repo announcement purgatory not implemented. \
                         Event ID: {} should NOT be queryable until git data arrives",
                        state_event.id
                    ));
                }

                return Err(format!(
                    "State event was neither in purgatory nor served. \
                     Event ID: {}",
                    state_event.id
                ));
            }

            // Feature IS implemented - state event in purgatory as expected
            Ok(())
        })
        .await
    }

    // ============================================================
    // State Event Purgatory Tests (non-ignored - already implemented)
    // ============================================================

    /// Test: State event not served before git data arrives
    ///
    /// Spec: GRASP-01 Line 20
    /// "repo state announcements... SHOULD be accepted with message
    /// 'purgatory: won't be served until git data arrives'"
    ///
    /// This test verifies:
    /// 1. Send state event for a repo with git data
    /// 2. State event points to a different commit than what's pushed
    /// 3. State event is NOT queryable (in purgatory)
    pub async fn test_state_event_not_served_before_git_data(client: &AuditClient) -> TestResult {
        TestResult::new(
            "state_event_not_served_before_git_data",
            SpecRef::PurgatoryAcceptUntilGitData,
            "State events SHOULD be accepted but not served until git data arrives",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // Use the isolated purgatory repo so this test's new state event
            // does not displace the shared OwnerStateDataPushed state event
            // that push-authorization tests depend on.
            let existing_state = ctx
                .get_fixture(FixtureKind::PurgatoryOwnerStateDataPushed)
                .await
                .map_err(|e| format!("Failed to get purgatory test repo: {}", e))?;

            let repo_id = existing_state
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .ok_or("Missing d tag in state event")?
                .to_string();

            // Create a NEW state event pointing to a DIFFERENT commit
            // This should enter purgatory since the commit doesn't exist
            let new_state = client
                .event_builder(Kind::RepoState, "")
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom(
                    "refs/heads/main",
                    vec!["deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()],
                ))
                .tag(Tag::custom(
                    "HEAD",
                    vec!["ref: refs/heads/main".to_string()],
                ))
                .build(client.keys())
                .map_err(|e| format!("Failed to build state event: {}", e))?;

            // Send the state event
            let (_, in_purgatory) = client
                .send_event_and_note_purgatory(new_state.clone())
                .await
                .map_err(|e| format!("Failed to send state event: {}", e))?;

            if !in_purgatory {
                return Err(format!(
                    "State event was served immediately despite pointing to \
                     non-existent commit. Event ID: {}",
                    new_state.id
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test: State event served after git push
    ///
    /// Spec: GRASP-01 Line 20
    /// "...kept in purgatory (not served) until the related git data arrives"
    ///
    /// This test verifies the full lifecycle using PurgatoryOwnerStateDataPushed fixture:
    /// 1. State event is sent (enters purgatory)
    /// 2. Git data is pushed matching the state event
    /// 3. State event is now served
    pub async fn test_state_event_served_after_git_push(client: &AuditClient) -> TestResult {
        TestResult::new(
            "state_event_served_after_git_push",
            SpecRef::PurgatoryAcceptUntilGitData,
            "State events SHOULD be served after matching git data arrives",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // PurgatoryOwnerStateDataPushed handles the full lifecycle
            let state_event = ctx
                .get_fixture(FixtureKind::PurgatoryOwnerStateDataPushed)
                .await
                .map_err(|e| format!("Failed to complete full lifecycle: {}", e))?;

            // Verify state event is served by querying its specific event ID.
            // We intentionally query by ID rather than kind+author+identifier because
            // other tests (e.g. push-auth) may have sent a newer replaceable state event
            // for the same repo_id, which would displace this one in an identifier query.
            let served = client
                .is_event_on_relay(state_event.id)
                .await
                .map_err(|e| format!("Failed to query state event: {}", e))?;

            if !served {
                return Err(format!(
                    "State event not served after git push. Event ID: {}",
                    state_event.id
                ));
            }

            Ok(())
        })
        .await
    }

    // ============================================================
    // PR Purgatory Tests
    // ============================================================

    /// Test: PR event accepted into purgatory (not served before git data)
    ///
    /// Spec: GRASP-01 Line 20
    /// "PRs and PR Updates SHOULD be accepted with message
    /// 'purgatory: won't be served until git data arrives'"
    ///
    /// This test verifies:
    /// 1. PR event is sent and relay responds OK (accepted)
    /// 2. PR event is NOT queryable (in purgatory, not served)
    ///
    /// PASS means: Relay accepted the event and is holding it in purgatory
    /// FAIL means: Either event was rejected, or served immediately (purgatory not implemented)
    ///
    /// Note: This test cannot distinguish between "event in purgatory" and
    /// "event accepted but never stored" - both result in event not being queryable.
    /// The fixture verifies the relay responded OK, which is the best we can do
    /// with black-box testing.
    pub async fn test_pr_event_accepted_into_purgatory_and_isnt_served(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            "pr_event_accepted_into_purgatory",
            SpecRef::PurgatoryAcceptUntilGitData,
            "PR event SHOULD be accepted but not served until git data arrives",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // PREvent2Sent fixture:
            // 1. Sends PR event
            // 2. Verifies relay responded OK (not rejected)
            // 3. Verifies event is NOT queryable (in purgatory)
            let pr_event = ctx
                .get_fixture(FixtureKind::PREvent2Sent)
                .await
                .map_err(|e| format!("Failed to send PR event: {}", e))?;

            // Double-check: event should not be queryable
            let filter = Filter::new()
                .kind(Kind::GitPullRequest)
                .author(client.pr_author_keys().public_key())
                .id(pr_event.id);

            tokio::time::sleep(Duration::from_millis(300)).await;

            let events = client
                .query(filter)
                .await
                .map_err(|e| format!("Failed to query PR events: {}", e))?;

            if !events.is_empty() {
                return Err(format!(
                    "PR event was served immediately - purgatory not implemented. Event ID: {}",
                    pr_event.id
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test: Git push to refs/nostr/<pr-event-id> is accepted
    ///
    /// This test verifies that pushing git data for a PR event in purgatory
    /// is accepted by the relay.
    ///
    /// PASS means: Git push succeeded, relay accepted the git data
    /// FAIL means: Git push was rejected (wrong ref, permissions, etc.)
    pub async fn test_pr_event_in_purgatory_git_push_accepted(client: &AuditClient) -> TestResult {
        TestResult::new(
            "pr_event_in_purgatory_git_push_accepted",
            SpecRef::PurgatoryAcceptUntilGitData,
            "Git push for PR event SHOULD be accepted",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // PREvent2GitDataPushed fixture:
            // 1. Gets PR event in purgatory (PREvent2Sent)
            // 2. Pushes commit to refs/nostr/<pr-event-id>
            // 3. Verifies push succeeded
            let _pr_event = ctx
                .get_fixture(FixtureKind::PREvent2GitDataPushed)
                .await
                .map_err(|e| format!("Failed to push git data for PR event: {}", e))?;

            Ok(())
        })
        .await
    }

    /// Test: PR event served after git data arrives
    ///
    /// This test verifies the full purgatory release mechanism:
    /// after git data is pushed to refs/nostr/<pr-event-id>, the event
    /// becomes queryable.
    ///
    /// PASS means: Event was released from purgatory and is now served
    /// FAIL means: Event still not queryable after git push (purgatory release broken)
    pub async fn test_pr_event_served_after_git_push(client: &AuditClient) -> TestResult {
        TestResult::new(
            "pr_event_served_after_git_push",
            SpecRef::PurgatoryAcceptUntilGitData,
            "PR event SHOULD be served after matching git data arrives",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // PREvent2Served fixture:
            // 1. Gets PR event with git data pushed (PREvent2GitDataPushed)
            // 2. Verifies event is now queryable
            let pr_event = ctx
                .get_fixture(FixtureKind::PREvent2Served)
                .await
                .map_err(|e| format!("Failed to complete purgatory release: {}", e))?;

            // Double-check: event should be queryable now
            let filter = Filter::new()
                .kind(Kind::GitPullRequest)
                .author(client.pr_author_keys().public_key())
                .id(pr_event.id);

            let events = client
                .query(filter)
                .await
                .map_err(|e| format!("Failed to query PR events: {}", e))?;

            if events.is_empty() {
                return Err(format!(
                    "PR event not served after git push. Event ID: {} should be queryable",
                    pr_event.id
                ));
            }

            Ok(())
        })
        .await
    }
    // ============================================================
    // Deletion Event Tests (NIP-09)
    // ============================================================

    /// Test: Kind 5 deletion event by event ID removes a purgatory state event
    ///
    /// Spec: NIP-09
    /// "A special event with kind 5... having a list of one or more `e` or `a` tags,
    /// each referencing an event the author is requesting to be deleted."
    ///
    /// This test verifies:
    /// 1. Get a promoted repo (PurgatoryOwnerStateDataPushed) so git pushes are possible
    /// 2. Clone the repo and create a unique commit (not yet pushed)
    /// 3. Submit a state event pointing to that unique commit (enters purgatory)
    /// 4. Send a kind 5 deletion event referencing the state event by event ID
    /// 5. Attempt to push the unique commit — MUST be rejected (no authorized state event)
    pub async fn test_deletion_by_event_id_removes_purgatory_state_event(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            "deletion_by_event_id_removes_purgatory_state_event",
            SpecRef::PurgatoryAcceptUntilGitData,
            "Kind 5 deletion by event ID SHOULD remove a purgatory state event, causing push rejection",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // Stage 1: get the isolated purgatory repo (independent from the shared
            // OwnerStateDataPushed chain that push-authorization tests depend on)
            let existing_state = ctx
                .get_fixture(FixtureKind::PurgatoryOwnerStateDataPushed)
                .await
                .map_err(|e| format!("Failed to get purgatory test repo: {}", e))?;

            let repo_id = existing_state
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .ok_or("Missing d tag in state event")?
                .to_string();

            let relay_domain = client
                .relay_url()
                .await
                .map_err(|e| e.to_string())?
                .trim_start_matches("ws://")
                .trim_start_matches("wss://")
                .to_string();

            let npub = client
                .public_key()
                .to_bech32()
                .map_err(|e| e.to_string())?;

            // Stage 2: clone the repo and create a unique commit (not pushed yet)
            let clone_path = clone_repo(&relay_domain, &npub, &repo_id)
                .map_err(|e| format!("Failed to clone repo: {}", e))?;

            let cleanup = || { let _ = fs::remove_dir_all(&clone_path); };

            let unique_commit = match create_commit(&clone_path, "deletion test unique commit") {
                Ok(h) => h,
                Err(e) => { cleanup(); return Err(format!("Failed to create commit: {}", e)); }
            };

            // Stage 3: submit a state event pointing to the unique commit (enters purgatory)
            let state_event = client
                .event_builder(Kind::RepoState, "")
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom(
                    "refs/heads/main",
                    vec![unique_commit.clone()],
                ))
                .tag(Tag::custom(
                    "HEAD",
                    vec!["ref: refs/heads/main".to_string()],
                ))
                .build(client.keys())
                .map_err(|e| { cleanup(); format!("Failed to build state event: {}", e) })?;

            let (_, in_purgatory) = client
                .send_event_and_note_purgatory(state_event.clone())
                .await
                .map_err(|e| { cleanup(); format!("Failed to send state event: {}", e) })?;

            if !in_purgatory {
                cleanup();
                return Err(format!(
                    "State event was served immediately (not in purgatory). \
                     Commit {} may already exist on relay.",
                    unique_commit
                ));
            }

            // Stage 4: send kind 5 deletion event referencing the state event by event ID
            let deletion = client
                .event_builder(Kind::EventDeletion, "")
                .tag(Tag::event(state_event.id))
                .tag(Tag::custom("k", vec!["30618"]))
                .build(client.keys())
                .map_err(|e| { cleanup(); format!("Failed to build deletion event: {}", e) })?;

            client
                .send_event(deletion)
                .await
                .map_err(|e| { cleanup(); format!("Relay rejected deletion event: {}", e) })?;

            tokio::time::sleep(Duration::from_millis(300)).await;

            // Stage 5: attempt to push the unique commit — must be rejected
            let push_result = try_push(&clone_path);
            cleanup();

            match push_result {
                Ok(false) => Ok(()), // push rejected as expected
                Ok(true) => Err(format!(
                    "Push was accepted but should have been rejected. \
                     The state event (id={}) was deleted, so commit {} \
                     should not be authorized.",
                    state_event.id, unique_commit
                )),
                Err(e) => Err(format!("Git push error: {}", e)),
            }
        })
        .await
    }

    /// Test: Kind 5 deletion event by `a` tag coordinate removes a purgatory state event
    ///
    /// Spec: NIP-09
    /// "When an `a` tag is used, relays SHOULD delete all versions of the replaceable
    /// event up to the `created_at` timestamp of the deletion request event."
    ///
    /// This test verifies:
    /// 1. Get a promoted repo (PurgatoryOwnerStateDataPushed) so git pushes are possible
    /// 2. Generate a fresh keypair for a new maintainer
    /// 3. Send a replacement owner announcement adding the new maintainer (goes to DB)
    /// 4. Send a state event signed by the new maintainer pointing to a unique commit
    ///    (enters purgatory — maintainer is authorized but commit doesn't exist yet)
    /// 5. Delete by coordinate `30618:<new_maintainer_pubkey>:<identifier>`
    /// 6. Clone repo, create that unique commit, attempt to push — MUST be rejected
    ///    (the state event was deleted, so the commit is no longer authorized)
    pub async fn test_deletion_by_coordinate_removes_purgatory_state_event(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            "deletion_by_coordinate_removes_purgatory_state_event",
            SpecRef::PurgatoryAcceptUntilGitData,
            "Kind 5 deletion by `a` coordinate SHOULD remove a purgatory state event, causing push rejection",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // Stage 1: get the isolated purgatory repo (independent from the shared
            // OwnerStateDataPushed chain that push-authorization tests depend on).
            // This test sends a replacement announcement (kind 30617) for the repo which
            // would corrupt the shared repo's maintainer set if we used OwnerStateDataPushed.
            let existing_state = ctx
                .get_fixture(FixtureKind::PurgatoryOwnerStateDataPushed)
                .await
                .map_err(|e| format!("Failed to get purgatory test repo: {}", e))?;

            let existing_announcement = ctx
                .get_fixture(FixtureKind::PurgatoryValidRepoSent)
                .await
                .map_err(|e| format!("Failed to get purgatory announcement fixture: {}", e))?;

            let repo_id = existing_state
                .tags
                .iter()
                .find(|t| t.kind() == "d")
                .and_then(|t| t.content())
                .ok_or("Missing d tag in state event")?
                .to_string();

            // Ensure replacement announcement is strictly newer than the existing
            // owner announcement for this (pubkey, d) coordinate.
            let replacement_created_at = Timestamp::from(existing_announcement.created_at.as_secs() + 1);

            // Stage 2: generate a fresh keypair for a new maintainer
            let new_maintainer_keys = Keys::generate();
            let new_maintainer_hex = new_maintainer_keys.public_key().to_hex();

            // Stage 3: send a replacement owner announcement that adds the new maintainer.
            // This is a replacement (same pubkey + identifier already in DB) so it goes
            // straight to the database without entering purgatory.
            let relay_url = client
                .relay_url()
                .await
                .map_err(|e| e.to_string())?;
            let http_url = relay_url
                .replace("ws://", "http://")
                .replace("wss://", "https://");
            let npub = client
                .public_key()
                .to_bech32()
                .map_err(|e| e.to_string())?;

            let replacement_announcement = client
                .event_builder(Kind::GitRepoAnnouncement, "")
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom(
                    "clone",
                    vec![format!("{}/{}/{}.git", http_url, npub, repo_id)],
                ))
                .tag(Tag::custom(
                    "relays",
                    vec![relay_url.clone()],
                ))
                .tag(Tag::custom(
                    "maintainers",
                    vec![new_maintainer_hex.clone()],
                ))
                .custom_time(replacement_created_at)
                .build(client.keys())
                .map_err(|e| format!("Failed to build replacement announcement: {}", e))?;

            client
                .send_event(replacement_announcement)
                .await
                .map_err(|e| format!("Relay rejected replacement announcement: {}", e))?;

            tokio::time::sleep(Duration::from_millis(200)).await;

            // Stage 4: clone the repo and create a unique commit (not pushed yet)
            let relay_domain = relay_url
                .trim_start_matches("ws://")
                .trim_start_matches("wss://")
                .to_string();

            let clone_path = clone_repo(&relay_domain, &npub, &repo_id)
                .map_err(|e| format!("Failed to clone repo: {}", e))?;

            let cleanup = || { let _ = fs::remove_dir_all(&clone_path); };

            let unique_commit = match create_commit(&clone_path, "deletion coordinate test unique commit") {
                Ok(h) => h,
                Err(e) => { cleanup(); return Err(format!("Failed to create commit: {}", e)); }
            };

            // Stage 5: submit a state event signed by the new maintainer pointing to the
            // unique commit. The new maintainer is now authorized (listed in the replacement
            // announcement), so the state event should enter purgatory (commit doesn't exist).
            let state_event = client
                .event_builder(Kind::RepoState, "")
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom(
                    "refs/heads/main",
                    vec![unique_commit.clone()],
                ))
                .tag(Tag::custom(
                    "HEAD",
                    vec!["ref: refs/heads/main".to_string()],
                ))
                .build(&new_maintainer_keys)
                .map_err(|e| { cleanup(); format!("Failed to build state event: {}", e) })?;

            let (_, in_purgatory) = client
                .send_event_and_note_purgatory(state_event.clone())
                .await
                .map_err(|e| { cleanup(); format!("Failed to send state event: {}", e) })?;

            if !in_purgatory {
                cleanup();
                return Err(format!(
                    "State event was served immediately (not in purgatory). \
                     Commit {} may already exist on relay.",
                    unique_commit
                ));
            }

            // Stage 6: send kind 5 deletion event signed by the new maintainer,
            // referencing their state event by coordinate `30618:<pubkey>:<identifier>`
            let coord = format!("30618:{}:{}", new_maintainer_hex, repo_id);

            let deletion = client
                .event_builder(Kind::EventDeletion, "")
                .tag(Tag::custom("a", vec![coord]))
                .tag(Tag::custom("k", vec!["30618"]))
                .build(&new_maintainer_keys)
                .map_err(|e| { cleanup(); format!("Failed to build deletion event: {}", e) })?;

            client
                .send_event(deletion)
                .await
                .map_err(|e| { cleanup(); format!("Relay rejected deletion event: {}", e) })?;

            tokio::time::sleep(Duration::from_millis(300)).await;

            // Stage 7: attempt to push the unique commit — must be rejected because
            // the new maintainer's state event was deleted from purgatory
            let push_result = try_push(&clone_path);
            cleanup();

            match push_result {
                Ok(false) => Ok(()), // push rejected as expected
                Ok(true) => Err(format!(
                    "Push was accepted but should have been rejected. \
                     The new maintainer's state event (id={}) was deleted by coordinate, \
                     so commit {} should not be authorized.",
                    state_event.id, unique_commit
                )),
                Err(e) => Err(format!("Git push error: {}", e)),
            }
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
    async fn test_grasp01_purgatory_against_relay() {
        let relay_url = std::env::var("RELAY_URL").expect(
            "RELAY_URL environment variable must be set. Example: RELAY_URL=ws://localhost:18081",
        );

        let config = AuditConfig::isolated();
        let client = AuditClient::new(&relay_url, config)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to connect to relay at {}. Ensure relay is running and accessible.",
                    relay_url
                )
            });

        let results = PurgatoryTests::run_all(&client).await;
        results.print_report();

        assert!(
            results.all_passed(),
            "Some purgatory tests failed. See report above."
        );
    }
}
