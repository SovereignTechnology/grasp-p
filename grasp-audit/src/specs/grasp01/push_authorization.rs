//! GRASP-01 Push Authorization Tests
//!
//! Tests that verify push authorization works correctly according to GRASP-01:
//! "MUST accept pushes via this service that match the latest repo state announcement
//! on the relay, respecting the recursive maintainer set."
//!
//! ## Test Coverage
//!
//! - Push authorized when state event matches commit being pushed
//! - Push rejected when no state event exists
//! - Push rejected when state event has different commit
//!
//! ## Running Tests
//!
//! ```bash
//! cd grasp-audit && nix develop -c bash test-ngit-relay.sh --mode test
//! ```

/// Expected hash for PR test deterministic commit
///
/// This hash is produced by creating a commit with:
/// - File: test.txt containing "PR test deterministic commit\n" (with trailing newline)
/// - Message: "PR test deterministic commit"
/// - Author: "GRASP Audit Test <test@grasp-audit.local>"
/// - Author date: 2024-01-01T00:00:00Z
/// - Committer date: 2024-01-01T00:00:00Z
/// - GPG signing: disabled
/// - Parent: none (root commit)
///
/// Run `test_pr_test_commit_hash_discovery` to discover/verify this value.
#[allow(dead_code)]
const PR_TEST_COMMIT_HASH: &str = "5a51b30e4615b572dcd5b9e487861b58605a5c21";

use crate::git_command;
use crate::specs::grasp01::SpecRef;
use crate::{
    clone_repo, create_commit, create_deterministic_commit_with_variant, try_push, try_push_to_ref,
    AuditClient, CommitVariant, FixtureKind, TestContext, TestResult,
    RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH,
};
use nostr_sdk::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ============================================================
// PR Event Test Helper Functions
// ============================================================

/// Creates a deterministic PR test commit in the specified repository.
/// Returns the commit hash which should match PR_TEST_COMMIT_HASH.
///
/// This function handles:
/// 1. Creating an orphan branch (removes all history)
/// 2. Clearing staged files
/// 3. Creating deterministic commit using PRTestCommit variant
/// 4. Replacing main branch with the orphan branch
/// 5. Verifying the commit hash matches expected value
///
/// # Arguments
/// * `clone_path` - Path to the cloned repository
///
/// # Returns
/// * `Ok(String)` - The commit hash (should match PR_TEST_COMMIT_HASH)
/// * `Err(String)` - Error message if commit creation failed
fn create_pr_test_commit(clone_path: &Path) -> Result<String, String> {
    // Step 1: Clean up any tracked files in the working directory
    // This ensures we start with a clean slate
    let _ = git_command()
        .args(["clean", "-fd"])
        .current_dir(clone_path)
        .output();

    // Step 2: Create orphan branch (removes all history)
    let output = git_command()
        .args(["checkout", "--orphan", "pr-test-branch"])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Failed to execute git checkout --orphan: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "git checkout --orphan failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Step 3: Remove ALL files from the index (staging area)
    let output = git_command()
        .args(["rm", "-rf", "--cached", "."])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Failed to execute git rm: {}", e))?;

    // Note: git rm may return error if there are no files to remove, that's OK
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "did not match any files" errors
        if !stderr.contains("did not match any files") {
            return Err(format!("git rm -rf --cached . failed: {}", stderr));
        }
    }

    // Step 4: Remove ALL files from working directory (except .git)
    // This ensures only test.txt will be in the commit
    for entry in fs::read_dir(clone_path).map_err(|e| format!("Failed to read dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name != ".git" {
            if path.is_dir() {
                fs::remove_dir_all(&path)
                    .map_err(|e| format!("Failed to remove dir {}: {}", path.display(), e))?;
            } else {
                fs::remove_file(&path)
                    .map_err(|e| format!("Failed to remove file {}: {}", path.display(), e))?;
            }
        }
    }

    // Step 5: Create deterministic commit using existing function
    let commit_hash =
        create_deterministic_commit_with_variant(clone_path, CommitVariant::PRTestCommit)?;

    // Step 6: Verify this is actually a root commit (no parent)
    let output = git_command()
        .args(["rev-list", "--max-parents=0", "HEAD"])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Failed to check root commit: {}", e))?;

    let root_commits = String::from_utf8_lossy(&output.stdout);
    if !root_commits.trim().contains(&commit_hash) {
        return Err(format!(
            "Commit {} is not a root commit (has parent). Root commits: {}",
            commit_hash,
            root_commits.trim()
        ));
    }

    // Step 7: Replace main branch with our new orphan branch
    let _ = git_command()
        .args(["branch", "-D", "main"])
        .current_dir(clone_path)
        .output();

    let output = git_command()
        .args(["branch", "-m", "main"])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Failed to rename branch: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to rename branch to main: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Step 8: Verify commit hash matches expected
    if commit_hash != PR_TEST_COMMIT_HASH {
        // Debug: Show what's in the commit
        let tree_output = git_command()
            .args(["ls-tree", "-r", "HEAD"])
            .current_dir(clone_path)
            .output();
        let tree_info = tree_output
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|_| "Failed to get tree".to_string());

        let cat_output = git_command()
            .args(["cat-file", "-p", "HEAD"])
            .current_dir(clone_path)
            .output();
        let commit_info = cat_output
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|_| "Failed to get commit".to_string());

        return Err(format!(
            "PR test commit hash mismatch: got {}, expected {}\nTree contents:\n{}\nCommit info:\n{}",
            commit_hash, PR_TEST_COMMIT_HASH, tree_info, commit_info
        ));
    }

    Ok(commit_hash)
}

/// Sets up a complete PR test repository with deterministic commit.
/// Returns: (clone_path, pr_event_id, repo_id, owner_npub)
///
/// This function handles the complete setup for PR event tests:
/// 1. Gets RepoAnnouncement and PREvent fixtures
/// 2. Extracts repo details (repo_id, owner_npub, pr_event_id)
/// 3. Clones the repository
/// 4. Creates the deterministic PR test commit
///
/// # Arguments
/// * `ctx` - The TestContext for fixture management
/// * `relay_url` - The relay URL for cloning (e.g., "localhost:7000")
///
/// # Returns
/// * `Ok((PathBuf, String, String, String))` - (clone_path, pr_event_id, repo_id, owner_npub)
/// * `Err(String)` - Error message if setup failed
#[allow(dead_code)]
async fn setup_pr_test_repo(
    ctx: &TestContext<'_>,
    relay_url: &str,
) -> Result<(PathBuf, String, String, String), String> {
    // Get fixtures
    let repo_event = ctx
        .get_fixture(FixtureKind::ValidRepoServed)
        .await
        .map_err(|e| format!("Failed to get repo announcement: {}", e))?;

    let pr_event = ctx
        .get_fixture(FixtureKind::PREvent)
        .await
        .map_err(|e| format!("Failed to get PR event: {}", e))?;

    // Extract repo details using nostr-sdk 0.43 API (field access)
    let repo_id = repo_event
        .tags
        .iter()
        .find(|t| t.kind() == "d")
        .and_then(|t| t.content())
        .ok_or("No repo identifier in announcement")?
        .to_string();

    let owner_npub = repo_event.pubkey.to_bech32().map_err(|e| e.to_string())?;
    let pr_event_id = pr_event.id.to_hex();

    // Clone the repository
    let clone_path = clone_repo(relay_url, &owner_npub, &repo_id)?;

    // Create the PR test commit
    create_pr_test_commit(&clone_path)?;

    Ok((clone_path, pr_event_id, repo_id, owner_npub))
}

// ============================================================
// PR Ref Push Test Helpers
// ============================================================

/// Creates the correct PR test commit (matching PR_TEST_COMMIT_HASH) in an existing clone.
/// Used after wrong commit was pushed to test pushing the correct commit.
#[allow(dead_code)]
fn reset_to_correct_pr_commit(clone_path: &Path) -> Result<String, String> {
    // Create the correct PR test commit (replaces current state)
    create_pr_test_commit(clone_path)
}

/// Attempts to push current HEAD to refs/nostr/<pr-event-id>.
/// Returns Ok(true) if push succeeded, Ok(false) if rejected, Err on git error.
#[allow(dead_code)]
fn push_to_pr_ref(clone_path: &Path, pr_event_id: &str) -> Result<bool, String> {
    let push_output = git_command()
        .args([
            "push",
            "--force",
            "origin",
            &format!("HEAD:refs/nostr/{}", pr_event_id),
        ])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Failed to execute git push: {}", e))?;

    Ok(push_output.status.success())
}

/// Queries the git smart HTTP info/refs endpoint to determine the default branch.
///
/// This parses the git-upload-pack service response to find the symref=HEAD capability
/// which indicates what branch HEAD points to (i.e., the default branch).
///
/// # Arguments
/// * `relay_domain` - The relay domain (e.g., "localhost:7000")
/// * `npub` - The owner's npub (bech32 public key)
/// * `repo_id` - The repository identifier
///
/// # Returns
/// * `Ok(String)` - The default branch ref (e.g., "refs/heads/main")
/// * `Err(String)` - Error message if request or parsing failed
async fn get_default_branch_from_info_refs(
    relay_domain: &str,
    npub: &str,
    repo_id: &str,
) -> Result<String, String> {
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
            "info/refs returned status {} for URL: {}",
            response.status(),
            info_refs_url
        ));
    }

    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    // Parse the git smart HTTP response to find symref=HEAD:refs/heads/xxx
    // The format is: capabilities are space-separated after the first NUL byte
    // Example line: 0000000000000000000000000000000000000000 capabilities^{}\0symref=HEAD:refs/heads/master ...
    for line in body.lines() {
        if let Some(caps_start) = line.find('\0') {
            let caps = &line[caps_start + 1..];
            for cap in caps.split(' ') {
                if cap.starts_with("symref=HEAD:") {
                    let branch = cap.trim_start_matches("symref=HEAD:");
                    return Ok(branch.to_string());
                }
            }
        }
    }

    Err("No symref=HEAD capability found in info/refs response".to_string())
}

/// Checks if a ref exists on the remote.
#[allow(dead_code)]
fn ref_exists_on_remote(clone_path: &Path, ref_name: &str) -> Result<bool, String> {
    let output = git_command()
        .args(["ls-remote", "origin", ref_name])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Failed to execute git ls-remote: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "git ls-remote failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(!stdout.trim().is_empty())
}

/// Test suite for Push Authorization operations
pub struct PushAuthorizationTests;

impl PushAuthorizationTests {
    /// Run all push authorization tests
    pub async fn run_all(client: &AuditClient, relay_domain: &str) -> crate::AuditResult {
        let mut results = crate::AuditResult::new("GRASP-01 Push Authorization Tests");

        results.add(Self::test_push_rejected_without_state_event(client, relay_domain).await);
        results.add(Self::test_push_authorized_by_owner_state(client, relay_domain).await);
        results.add(Self::test_push_rejected_wrong_commit(client, relay_domain).await);
        results.add(
            Self::test_push_authorized_by_confirmed_maintainer_state(client, relay_domain).await,
        );
        results.add(
            Self::test_push_authorized_by_recursive_maintainer_state(client, relay_domain).await,
        );
        results.add(
            Self::test_push_to_nostr_ref_with_invalid_event_id_rejected(client, relay_domain).await,
        );
        results.add(
            Self::test_pr_push_to_nostr_ref_with_wrong_commit_accepted_before_event_received(
                client,
                relay_domain,
            )
            .await,
        );
        results.add(
            Self::test_pr_event_published_removes_nostr_ref_at_incorrect_commit(
                client,
                relay_domain,
            )
            .await,
        );
        results.add(
            Self::test_push_to_nostr_ref_with_wrong_commit_after_event_received_rejected(
                client,
                relay_domain,
            )
            .await,
        );
        results.add(
            Self::test_push_to_nostr_ref_with_correct_commit_after_event_received_accepted_and_event_served(
                client,
                relay_domain,
            )
            .await,
        );
        results.add(
            Self::test_head_set_after_state_event_with_existing_commit(client, relay_domain).await,
        );
        results
            .add(Self::test_head_set_after_git_push_with_required_oids(client, relay_domain).await);

        results
    }

    /// Test that push is rejected when no state event exists
    pub async fn test_push_rejected_without_state_event(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_push_rejected_without_state_event";
        let ctx = TestContext::new(client);

        // Create repository (no state event)
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Push rejected without state event",
                )
                .fail(format!("Failed to create repo: {}", e))
            }
        };

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let repo_id = repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .unwrap()
            .to_string();
        let npub = repo.pubkey.to_bech32().unwrap();

        // Clone and create commit
        let clone_path = match clone_repo(relay_domain, &npub, &repo_id) {
            Ok(p) => p,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Push rejected without state event",
                )
                .fail(&e)
            }
        };
        let cleanup = || {
            let _ = fs::remove_dir_all(&clone_path);
        };

        if let Err(e) = create_commit(&clone_path, "Unauthorized commit") {
            cleanup();
            return TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push rejected without state event",
            )
            .fail(&e);
        }

        // Do NOT publish state event - push should be rejected
        let push_result = try_push(&clone_path);
        cleanup();

        match push_result {
            Ok(false) => TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push rejected without state event",
            )
            .pass(),
            Ok(true) => TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push rejected without state event",
            )
            .fail("Push accepted but should be rejected"),
            Err(e) => TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push rejected without state event",
            )
            .fail(&e),
        }
    }

    /// Test that push is authorized when state event matches the commit
    ///
    /// GRASP-01: "MUST accept pushes via this service that match the latest
    /// repo state announcement on the relay"
    ///
    /// This test uses the OwnerStateDataPushed fixture which handles all 4 stages:
    /// 1. **Generated**: Creates RepoState (repo announcement + state event)
    /// 2. **Sent**: Sends events to relay (returns OK, accepted but 'purgatory:...' message)
    /// 3. **Verify Not Served**: Confirms event is not served by relays
    /// 4. **DataPushed**: Clones repo, creates deterministic commit, pushes to relay
    /// 5. **Verified**: Confirms event is served by relay
    ///
    /// The test wraps the fixture result in pass/fail using the error message.
    #[allow(unused_variables)] // relay_domain is now handled by fixture
    pub async fn test_push_authorized_by_owner_state(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_push_authorized_by_owner_state";
        let ctx = TestContext::new(client);

        // The OwnerStateDataPushed fixture handles all stages:
        // Generate → Send → Verify → DataPush
        match ctx.get_fixture(FixtureKind::OwnerStateDataPushed).await {
            Ok(_state_event) => TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push authorized with matching state",
            )
            .pass(),
            Err(e) => TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push authorized with matching state",
            )
            .fail(format!("{}", e)),
        }
    }

    /// Test that push is rejected when commit doesn't match state event
    ///
    /// GRASP-01: "MUST accept pushes via this service that match the latest repo state announcement"
    /// (Conversely, MUST reject pushes that don't match)
    ///
    /// ## Fixture-First Pattern
    ///
    /// 1. **Generate**: Create TestContext and get OwnerStateDataPushed fixture
    ///    (repo announcement + state event pointing to DETERMINISTIC_COMMIT_HASH)
    /// 2. **Send**: Clone repo, create WRONG deterministic commit (Maintainer variant),
    ///    try to push
    /// 3. **Verify**: Push should be rejected because the commit doesn't match state event
    ///
    /// Note: This test directly pushes the wrong commit instead of first establishing
    /// state on the relay. The state event already authorizes DETERMINISTIC_COMMIT_HASH,
    /// but we try to push MAINTAINER_DETERMINISTIC_COMMIT_HASH which should be rejected.
    pub async fn test_push_rejected_wrong_commit(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_push_rejected_wrong_commit";

        // ============================================================
        // Step 1: GENERATE - Create TestContext and get OwnerStateDataPushed fixture
        // The state event points to DETERMINISTIC_COMMIT_HASH
        // ============================================================
        let ctx = TestContext::new(client);

        let state_event = match ctx.get_fixture(FixtureKind::OwnerStateDataPushed).await {
            Ok(e) => e,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Push rejected when commit not in state event",
                )
                .fail(format!("Failed to create RepoState fixture: {}", e));
            }
        };

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Extract repo_id and npub from state event
        let repo_id = match state_event
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
        {
            Some(id) => id.to_string(),
            None => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Push rejected when commit not in state event",
                )
                .fail("Missing repo_id in state event");
            }
        };

        let npub = match state_event.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Push rejected when commit not in state event",
                )
                .fail(format!("Failed to convert pubkey to bech32: {}", e));
            }
        };

        // ============================================================
        // Step 2: SEND - Clone repo and create an unauthorized commit
        // Any commit with a hash different from what's in the state event will work
        // ============================================================
        let clone_path = match clone_repo(relay_domain, &npub, &repo_id) {
            Ok(p) => p,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Push rejected when commit not in state event",
                )
                .fail(format!("Failed to clone repo: {}", e));
            }
        };

        // Cleanup helper
        let cleanup = || {
            let _ = fs::remove_dir_all(&clone_path);
        };

        // Create/checkout main branch
        let branch_output = git_command()
            .args(["checkout", "-B", "main"])
            .current_dir(&clone_path)
            .output();

        match branch_output {
            Err(e) => {
                cleanup();
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Push rejected when commit not in state event",
                )
                .fail(format!("Failed to create/checkout main branch: {}", e));
            }
            Ok(output) if !output.status.success() => {
                cleanup();
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Push rejected when commit not in state event",
                )
                .fail(format!(
                    "Failed to create/checkout main branch: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            _ => {}
        }

        // Create a commit that is NOT in the state event
        // Any commit hash different from what's authorized in the state event will work
        if let Err(e) = create_commit(&clone_path, "Unauthorized commit - should be rejected") {
            cleanup();
            return TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push rejected when commit not in state event",
            )
            .fail(format!("Failed to create wrong commit: {}", e));
        }

        // ============================================================
        // Step 3: VERIFY - Push should be rejected because the commit
        // doesn't match the state event
        // ============================================================
        let push_result = try_push(&clone_path);
        cleanup();

        match push_result {
            Ok(false) => TestResult::new(test_name, SpecRef::GitAcceptPushesAlignState, "Push rejected when commit not in state event").pass(),
            Ok(true) => TestResult::new(test_name, SpecRef::GitAcceptPushesAlignState, "Push rejected when commit not in state event")
                .fail("Push accepted but should be rejected. The pushed commit is not in the state event."),
            Err(e) => TestResult::new(test_name, SpecRef::GitAcceptPushesAlignState, "Push rejected when commit not in state event").fail(&e),
        }
    }

    /// Test push authorized by a reciprocally confirmed maintainer State event.
    ///
    /// GRASP-01: "respecting the recursive maintainer set"
    /// Listing alone is an invitation. The fixture publishes the maintainer's
    /// reciprocal announcement before its State event becomes authoritative.
    ///
    /// This test uses the MaintainerStateDataPushed fixture which handles all 5 stages:
    /// 1. **OwnerStateDataPushed dependency**: Owner's repo and state event already on relay, git data pushed
    /// 2. **Sent**: Sends maintainer state event to relay (returns OK, accepted but 'purgatory:...' message)
    /// 3. **Verify Not Served**: Confirms event is not served by relays
    /// 4. **DataPushed**: Clones repo, creates maintainer deterministic commit, force-pushes to relay
    /// 5. **Verified**: Confirms event is served by relay
    ///
    /// The test wraps the fixture result in pass/fail using the error message.
    #[allow(unused_variables)] // relay_domain is now handled by fixture
    pub async fn test_push_authorized_by_confirmed_maintainer_state(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_push_authorized_by_confirmed_maintainer_state";
        let ctx = TestContext::new(client);

        // The MaintainerStateDataPushed fixture handles all stages:
        // Generate → Send → Verify → DataPush
        match ctx
            .get_fixture(FixtureKind::MaintainerStateDataPushed)
            .await
        {
            Ok(_maintainer_state_event) => TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push authorized by reciprocally confirmed maintainer state",
            )
            .pass(),
            Err(e) => TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push authorized by reciprocally confirmed maintainer state",
            )
            .fail(format!("{}", e)),
        }
    }

    /// Test push authorized by a transitively confirmed maintainer State event.
    ///
    /// GRASP-01: "respecting the recursive maintainer set"
    /// The legacy fixture name describes a selected author ↔ direct maintainer
    /// ↔ additional maintainer reciprocal component.
    ///
    /// This test uses the RecursiveMaintainerStateDataPushed fixture which handles all 5 stages:
    /// 1. **Generated**: (MaintainerStateDataPushed dependency includes ValidRepo + OwnerStateDataPushed)
    ///    Creates MaintainerAnnouncement + RecursiveMaintainerState
    /// 2. **Sent**: Sends events to relay (returns OK, accepted but 'purgatory:...' message)
    /// 3. **Verify Not Served**: Confirms event is not served by relays
    /// 4. **DataPushed**: Clones repo, creates the additional maintainer's deterministic commit, pushes to relay
    /// 5. **Verified**: Confirms event is served by relay
    ///
    /// The test wraps the fixture result in pass/fail using the error message.
    #[allow(unused_variables)] // relay_domain is now handled by fixture
    pub async fn test_push_authorized_by_recursive_maintainer_state(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_push_authorized_by_recursive_maintainer_state";
        let ctx = TestContext::new(client);

        // The RecursiveMaintainerStateDataPushed fixture handles all stages:
        // Generate → Send → Verify → DataPush
        match ctx
            .get_fixture(FixtureKind::RecursiveMaintainerStateDataPushed)
            .await
        {
            Ok(_recursive_maintainer_state_event) => TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push authorized by transitively confirmed maintainer state",
            )
            .pass(),
            Err(e) => TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Push authorized by transitively confirmed maintainer state",
            )
            .fail(format!("{}", e)),
        }
    }

    /// Test that non-maintainer state event is ignored
    ///
    /// GRASP-01: "respecting the recursive maintainer set"
    /// (Conversely, state events from non-maintainers MUST be ignored)
    ///
    /// ## Fixture Compatibility
    ///
    /// This test is compatible with any descendant of `OwnerStateDataPushed`:
    /// - `OwnerStateDataPushed` - owner's state event with git data pushed
    /// - `MaintainerStateDataPushed` - maintainer's state event with git data pushed
    /// - `RecursiveMaintainerStateDataPushed` - transitively confirmed maintainer's State event with Git data pushed
    ///
    /// All of these establish valid state on the relay that a non-maintainer should NOT be able to override.
    ///
    /// ## Test Flow
    ///
    /// 1. **Setup**: Get OwnerStateDataPushed fixture (repo + state event + git data pushed)
    /// 2. **Clone**: Fresh clone of the repository
    /// 3. **Attack**: Create a new commit and a rogue state event signed by a non-maintainer
    /// 4. **Verify**: Push should be rejected because rogue state event is ignored
    pub async fn test_non_maintainer_state_rejected(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_non_maintainer_state_rejected";

        // ============================================================
        // Step 1: SETUP - Get OwnerStateDataPushed fixture
        // This establishes valid state on the relay with git data
        // ============================================================
        let ctx = TestContext::new(client);

        let state_event = match ctx.get_fixture(FixtureKind::OwnerStateDataPushed).await {
            Ok(e) => e,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Non-maintainer state events ignored",
                )
                .fail(format!("Failed to get OwnerStateDataPushed fixture: {}", e));
            }
        };

        // Extract repo_id and npub from state event
        let repo_id = match state_event
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
        {
            Some(id) => id.to_string(),
            None => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Non-maintainer state events ignored",
                )
                .fail("Missing repo_id in state event");
            }
        };

        let npub = match state_event.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Non-maintainer state events ignored",
                )
                .fail(format!("Failed to convert pubkey to bech32: {}", e));
            }
        };

        // ============================================================
        // Step 2: CLONE - Fresh clone of the repository
        // ============================================================
        let clone_path = match clone_repo(relay_domain, &npub, &repo_id) {
            Ok(p) => p,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Non-maintainer state events ignored",
                )
                .fail(format!("Failed to clone repo: {}", e));
            }
        };

        // Cleanup helper
        let cleanup = || {
            let _ = fs::remove_dir_all(&clone_path);
        };

        // ============================================================
        // Step 3: ATTACK - Create a new commit and a rogue state event
        // from a non-maintainer
        // ============================================================
        let new_commit = match create_commit(&clone_path, "New commit to push") {
            Ok(h) => h,
            Err(e) => {
                cleanup();
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Non-maintainer state events ignored",
                )
                .fail(format!("Failed to create commit: {}", e));
            }
        };

        // Create a rogue keypair (NOT the maintainer)
        let rogue_keys = Keys::generate();

        // Create a rogue state event announcing the new commit
        // This event has the correct repo_id but is signed by a non-maintainer
        let rogue_state = match client
            .event_builder(Kind::RepoState, "")
            .tag(Tag::identifier(&repo_id))
            .tag(Tag::custom("refs/heads/main", vec![new_commit.clone()]))
            .build(&rogue_keys)
        {
            Ok(e) => e,
            Err(e) => {
                cleanup();
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptPushesAlignState,
                    "Non-maintainer state events ignored",
                )
                .fail(format!("Failed to build rogue state event: {}", e));
            }
        };

        // Send the rogue state event using the raw client to bypass AuditClient's key check
        if let Err(e) = client.client().send_event(&rogue_state).await {
            cleanup();
            return TestResult::new(
                test_name,
                SpecRef::GitAcceptPushesAlignState,
                "Non-maintainer state events ignored",
            )
            .fail(format!("Failed to send rogue state event: {}", e));
        }

        // Wait for event to propagate
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // ============================================================
        // Step 4: VERIFY - Push should be rejected because rogue
        // state event is ignored
        // ============================================================
        let push_result = try_push(&clone_path);
        cleanup();

        match push_result {
            Ok(false) => TestResult::new(test_name, SpecRef::GitAcceptPushesAlignState, "Non-maintainer state events ignored").pass(),
            Ok(true) => TestResult::new(test_name, SpecRef::GitAcceptPushesAlignState, "Non-maintainer state events ignored")
                .fail(format!(
                    "Push accepted but should be rejected. A non-maintainer (pubkey: {}) published \
                    a state event announcing commit {}, but the push was accepted. The relay should \
                    only accept state events from maintainers (pubkey: {}).",
                    rogue_keys.public_key(),
                    new_commit,
                    client.public_key()
                )),
            Err(e) => TestResult::new(test_name, SpecRef::GitAcceptPushesAlignState, "Non-maintainer state events ignored").fail(&e),
        }
    }

    /// Test that push to refs/nostr/<invalid> is rejected with invalid EventId format
    ///
    /// GRASP-01: "MUST accept pushes via this service to `refs/nostr/<event-id>`"
    /// The event_id must parse as a valid rust-nostr EventId (64-char hex string).
    /// Invalid formats (too short, non-hex, etc.) should be rejected.
    ///
    /// ## Fixture-First Pattern
    ///
    /// 1. **Generate**: Create repo with ValidRepo fixture (no state event needed)
    /// 2. **Send**: Clone repo, create commit, try to push to refs/nostr/123 (invalid)
    /// 3. **Verify**: Push should be rejected because event-id format is invalid
    pub async fn test_push_to_nostr_ref_with_invalid_event_id_rejected(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_push_to_nostr_ref_with_invalid_event_id_rejected";

        // ============================================================
        // Step 1: GENERATE - Create repo (no state event needed for refs/nostr/)
        // ============================================================
        let ctx = TestContext::new(client);

        let repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptRefsNostrEventId,
                    "Push to refs/nostr/<invalid-event-id> rejected",
                )
                .fail(format!("Failed to create repo: {}", e));
            }
        };

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let repo_id = repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .unwrap()
            .to_string();
        let npub = repo.pubkey.to_bech32().unwrap();

        // ============================================================
        // Step 2: SEND - Clone repo, create commit, try push to invalid ref
        // ============================================================
        let clone_path = match clone_repo(relay_domain, &npub, &repo_id) {
            Ok(p) => p,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitAcceptRefsNostrEventId,
                    "Push to refs/nostr/<invalid-event-id> rejected",
                )
                .fail(&e);
            }
        };
        let cleanup = || {
            let _ = fs::remove_dir_all(&clone_path);
        };

        // Create a unique commit
        if let Err(e) = create_commit(&clone_path, "Test commit for invalid refs/nostr push") {
            cleanup();
            return TestResult::new(
                test_name,
                SpecRef::GitAcceptRefsNostrEventId,
                "Push to refs/nostr/<invalid-event-id> rejected",
            )
            .fail(&e);
        }

        // Use an invalid event-id (too short, not a valid 64-char hex)
        let invalid_event_id = "123";
        let ref_name = format!("refs/nostr/{}", invalid_event_id);

        // ============================================================
        // Step 3: VERIFY - Push should be rejected with invalid event-id format
        // ============================================================
        let push_result = try_push_to_ref(&clone_path, &ref_name);
        cleanup();

        match push_result {
            Ok(false) => TestResult::new(
                test_name,
                SpecRef::GitAcceptRefsNostrEventId,
                "Push to refs/nostr/<invalid-event-id> rejected",
            )
            .pass(),
            Ok(true) => TestResult::new(
                test_name,
                SpecRef::GitAcceptRefsNostrEventId,
                "Push to refs/nostr/<invalid-event-id> rejected",
            )
            .fail(format!(
                "Push to {} was accepted but should be rejected. \
                The event-id '{}' is NOT a valid 64-character hex string (EventId format). \
                The relay should reject pushes to refs/nostr/ with invalid event-id format.",
                ref_name, invalid_event_id
            )),
            Err(e) => TestResult::new(
                test_name,
                SpecRef::GitAcceptRefsNostrEventId,
                "Push to refs/nostr/<invalid-event-id> rejected",
            )
            .fail(format!("Push error: {}", e)),
        }
    }

    /// Test 1: Push wrong commit to refs/nostr/<pr-event-id> BEFORE PR event is published
    ///
    /// This test verifies that the relay accepts pushes to refs/nostr/<event-id>
    /// when no corresponding event exists yet. This is expected behavior because
    /// there's no validation event to check against.
    ///
    /// Uses `PRWrongCommitPushedBeforeEvent` fixture which handles all setup
    /// and verifies the push succeeded.
    #[allow(unused_variables)] // relay_domain is now handled by fixture
    pub async fn test_pr_push_to_nostr_ref_with_wrong_commit_accepted_before_event_received(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name =
            "test_pr_push_to_nostr_ref_with_wrong_commit_accepted_before_event_received";
        let desc = "Push wrong commit to refs/nostr/<pr-event-id> before PR event (should accept)";
        let ctx = TestContext::new(client);

        // The PRWrongCommitPushedBeforeEvent fixture handles:
        // 1. Create repo announcement
        // 2. Build PR event (but don't send it)
        // 3. Clone repo, create wrong commit, push to refs/nostr/<event-id>
        // If the push fails, the fixture will return an error
        match ctx
            .get_fixture(FixtureKind::PRWrongCommitPushedBeforeEvent)
            .await
        {
            Ok(_pr_event) => {
                TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc).pass()
            }
            Err(e) => TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                .fail(format!("{}", e)),
        }
    }

    /// Test 2: After publishing PR event, verify that incorrect refs get cleaned up
    ///
    /// This test verifies the expected behavior: when a PR event is published,
    /// the relay should validate any existing refs/nostr/<event-id> refs and
    /// delete those that don't match the commit in the PR event's `c` tag.
    ///
    /// Uses `PREventSentAfterWrongPush` fixture which builds on the wrong push fixture.
    pub async fn test_pr_event_published_removes_nostr_ref_at_incorrect_commit(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_pr_event_published_removes_nostr_ref_at_incorrect_commit";
        let desc = "Publishing PR event should trigger cleanup of incorrect refs";
        let ctx = TestContext::new(client);

        // Get fixture: wrong commit was pushed, then PR event was sent
        let pr_event = match ctx
            .get_fixture(FixtureKind::PREventSentAfterWrongPush)
            .await
        {
            Ok(e) => e,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(format!("{}", e));
            }
        };

        let pr_event_id = pr_event.id.to_hex();

        // Get repo info for cloning (fresh clone for verification)
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoServed).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(format!("{}", e));
            }
        };

        let repo_id = repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .unwrap_or("unknown")
            .to_string();

        let owner_npub = match repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(format!("Failed to get owner npub: {}", e));
            }
        };

        // Clone fresh for verification
        let clone_path = match clone_repo(relay_domain, &owner_npub, &repo_id) {
            Ok(p) => p,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(&e);
            }
        };

        // Check if the incorrect ref was deleted
        let ref_name = format!("refs/nostr/{}", pr_event_id);
        let refs_exist = match ref_exists_on_remote(&clone_path, &ref_name) {
            Ok(exists) => exists,
            Err(e) => {
                let _ = fs::remove_dir_all(&clone_path);
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(&e);
            }
        };

        let _ = fs::remove_dir_all(&clone_path);

        // Ref should be deleted since the pushed commit doesn't match the PR event's `c` tag
        if refs_exist {
            TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc).fail(format!(
                "Expected refs/nostr/{} to be deleted when PR event published with non-matching commit, \
                 but the ref still exists. The relay should delete refs that don't match the event's `c` tag.",
                pr_event_id
            ))
        } else {
            TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc).pass()
        }
    }

    /// Test 3: Push wrong commit to refs/nostr/<pr-event-id> AFTER PR event exists
    ///
    /// This test verifies that the relay rejects pushes to refs/nostr/<event-id>
    /// when a corresponding event exists but the pushed commit doesn't match
    /// the commit in the PR event's `c` tag.
    ///
    /// Uses `PREventSentAfterWrongPush` fixture, then attempts to push wrong commit again.
    pub async fn test_push_to_nostr_ref_with_wrong_commit_after_event_received_rejected(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_push_to_nostr_ref_with_wrong_commit_after_event_received_rejected";
        let desc = "Push wrong commit to refs/nostr/<pr-event-id> after PR event (should reject)";
        let ctx = TestContext::new(client);

        // Get fixture: PR event exists on relay (wrong commit was previously pushed but may have been cleaned up)
        let pr_event = match ctx
            .get_fixture(FixtureKind::PREventSentAfterWrongPush)
            .await
        {
            Ok(e) => e,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(format!("{}", e));
            }
        };

        let pr_event_id = pr_event.id.to_hex();

        // Get repo info for cloning (fresh clone for this test)
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoServed).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(format!("{}", e));
            }
        };

        let repo_id = repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .unwrap_or("unknown")
            .to_string();

        let owner_npub = match repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(format!("Failed to get owner npub: {}", e));
            }
        };

        // Clone fresh for this test
        let clone_path = match clone_repo(relay_domain, &owner_npub, &repo_id) {
            Ok(p) => p,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(&e);
            }
        };

        // Create a wrong commit (unique, not PRTestCommit) - use create_commit so it always
        // succeeds even when the clone already has the Owner deterministic content on disk.
        if let Err(e) = create_commit(&clone_path, "wrong commit - not the PR test commit") {
            let _ = fs::remove_dir_all(&clone_path);
            return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc).fail(&e);
        }

        // Try to push with wrong commit (should be rejected since PR event exists)
        let push_succeeded = match push_to_pr_ref(&clone_path, &pr_event_id) {
            Ok(success) => success,
            Err(e) => {
                let _ = fs::remove_dir_all(&clone_path);
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(&e);
            }
        };

        let _ = fs::remove_dir_all(&clone_path);

        // Should REJECT - PR event exists with different commit hash
        if push_succeeded {
            return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                .fail("Push accepted (expected rejection due to commit hash mismatch)");
        }

        TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc).pass()
    }

    /// Test 4: Push correct commit to refs/nostr/<pr-event-id> AFTER PR event exists
    ///
    /// This test verifies that the relay accepts pushes to refs/nostr/<event-id>
    /// when a corresponding event exists AND the pushed commit matches
    /// the commit in the PR event's `c` tag AND the PR event is served on relay.
    ///
    /// Uses `PREventSentAfterWrongPush` fixture, then creates correct commit and pushes.
    pub async fn test_push_to_nostr_ref_with_correct_commit_after_event_received_accepted_and_event_served(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_push_to_nostr_ref_with_correct_commit_after_event_received_accepted";
        let desc = "Push correct commit to refs/nostr/<pr-event-id> after PR event (should accept)";
        let ctx = TestContext::new(client);

        // Get fixture: PR event exists on relay
        let pr_event = match ctx
            .get_fixture(FixtureKind::PREventSentAfterWrongPush)
            .await
        {
            Ok(e) => e,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(format!("{}", e));
            }
        };

        let pr_event_id = pr_event.id.to_hex();

        // Get repo info for cloning (fresh clone for this test)
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoServed).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(format!("{}", e));
            }
        };

        let repo_id = repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .unwrap_or("unknown")
            .to_string();

        let owner_npub = match repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(format!("Failed to get owner npub: {}", e));
            }
        };

        // Clone fresh for this test
        let clone_path = match clone_repo(relay_domain, &owner_npub, &repo_id) {
            Ok(p) => p,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(&e);
            }
        };

        // Create the CORRECT PR test commit (the one expected by PR event)
        if let Err(e) = reset_to_correct_pr_commit(&clone_path) {
            let _ = fs::remove_dir_all(&clone_path);
            return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc).fail(&e);
        }

        // Check event is not yet served by relay (still in purgatory)
        match client.is_event_on_relay(pr_event.id).await {
            Ok(on_relay) => {
                if on_relay {
                    return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                        .fail("PR event not in purgatory before correct commit pushed to refs/nostr/<event-id> (the relay serve the PR event)");
                }
            }
            Err(_) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail("failed to query relay");
            }
        }

        // Push correct commit (should succeed)
        let push_succeeded = match push_to_pr_ref(&clone_path, &pr_event_id) {
            Ok(success) => success,
            Err(e) => {
                let _ = fs::remove_dir_all(&clone_path);
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail(&e);
            }
        };

        let _ = fs::remove_dir_all(&clone_path);

        // Should ACCEPT - commit matches PR event's c tag
        if !push_succeeded {
            return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                .fail("Push rejected (expected acceptance since commit matches PR event)");
        }

        // ============================================================
        // Stage 5: Verify PR event is on relay
        // ============================================================

        tokio::time::sleep(Duration::from_millis(200)).await;

        match client.is_event_on_relay(pr_event.id).await {
            Ok(on_relay) => {
                if !on_relay {
                    return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                        .fail("PR event not served after correct commit at refs/nostr/<event-id>");
                }
            }
            Err(_) => {
                return TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc)
                    .fail("failed to query relay");
            }
        }

        TestResult::new(test_name, SpecRef::GitAcceptRefsNostrEventId, desc).pass()
    }

    /// Test that HEAD is set after a state event is published with an existing commit
    ///
    /// GRASP-01: "MUST set repository HEAD per repository state announcement
    /// as soon as the git data related to that branch has been received."
    ///
    /// This test verifies the HEAD-setting behavior when:
    /// 1. Git data has already been pushed via RecursiveMaintainerStateDataPushed
    /// 2. A new state event is published with HEAD="refs/heads/develop"
    /// 3. The relay should update the repository's default branch to "develop"
    ///
    /// ## Fixture-First Pattern
    ///
    /// Uses HeadSetToDevelopBranch fixture which:
    /// 1. **Depends on**: RecursiveMaintainerStateDataPushed (all git data exists)
    /// 2. **Creates**: New state event with HEAD=refs/heads/develop
    /// 3. **Sends**: State event to relay
    /// 4. **Verify**: Query info/refs to verify HEAD symref points to refs/heads/develop
    pub async fn test_head_set_after_state_event_with_existing_commit(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_head_set_after_state_event_with_existing_commit";
        let desc = "HEAD is set when state event published with existing commit";

        // ============================================================
        // Step 1: Get HeadSetToDevelopBranch fixture
        // This sets up everything: repo, maintainer chain, git data, and state event with HEAD=develop
        // ============================================================
        let ctx = TestContext::new(client);

        let _develop_state_event = match ctx.get_fixture(FixtureKind::HeadSetToDevelopBranch).await
        {
            Ok(e) => e,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc).fail(
                    format!("Failed to create HeadSetToDevelopBranch fixture: {}", e),
                );
            }
        };

        // ============================================================
        // Step 2: Extract repo_id and owner npub from ValidRepo (cached by fixture)
        // ============================================================
        let valid_repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(e) => e,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail(format!("Failed to get ValidRepo fixture: {}", e));
            }
        };

        let repo_id = match valid_repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
        {
            Some(id) => id.to_string(),
            None => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail("Missing repo_id in ValidRepo");
            }
        };

        let npub = match valid_repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail(format!("Failed to convert pubkey to bech32: {}", e));
            }
        };

        // ============================================================
        // Step 3: VERIFY - Query info/refs to check the default branch
        // ============================================================
        let default_branch =
            match get_default_branch_from_info_refs(relay_domain, &npub, &repo_id).await {
                Ok(branch) => branch,
                Err(e) => {
                    return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                        .fail(format!("Failed to get default branch: {}", e));
                }
            };

        // Verify HEAD points to refs/heads/develop
        if default_branch == "refs/heads/develop" {
            TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc).pass()
        } else {
            TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc).fail(format!(
                "Expected HEAD to point to 'refs/heads/develop' but got '{}'. \
                GRASP-01 requires: 'MUST set repository HEAD per repository state announcement \
                as soon as the git data related to that branch has been received.'",
                default_branch
            ))
        }
    }

    /// Test that HEAD is set after git push with oids
    ///
    /// GRASP-01: "MUST set repository HEAD per repository state announcement
    /// as soon as the git data related to that branch has been received."
    ///
    /// This test verifies the HEAD-setting behavior when:
    /// 1. A new state event is published with HEAD="refs/heads/develop1" pointing to a new commit
    /// 2. The git data (the new commit) has NOT yet been pushed
    /// 3. The relay receives the git push with the required oids
    /// 4. Only AFTER the push completes should HEAD be updated to "develop1"
    ///
    /// This differs from test_head_set_after_state_event_with_existing_commit in that
    /// the git data doesn't exist yet when the state event is published.
    ///
    /// ## Fixture-First Pattern
    ///
    /// Uses HeadSetToDevelopBranch fixture as base, then:
    /// 1. **Depends on**: HeadSetToDevelopBranch (HEAD already set to develop)
    /// 2. **Clone**: Clone repo to create new local branch develop1
    /// 3. **Create unique commit**: New commit on develop1 that doesn't exist on relay
    /// 4. **Build state event**: HEAD=refs/heads/develop1 pointing to new commit
    /// 5. **Send state event**: Before git push (git data not yet on relay)
    /// 6. **Git push**: Push develop1 branch - sends required oids
    /// 7. **Verify**: HEAD should now point to refs/heads/develop1
    pub async fn test_head_set_after_git_push_with_required_oids(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_head_set_after_git_push_with_required_oids";
        let desc = "HEAD is set to match state event when git push sends required oids to formulate branch";

        // ============================================================
        // Step 1: Get HeadSetToDevelopBranch fixture as baseline
        // This establishes: repo, maintainer chain, git data, HEAD=develop
        // ============================================================
        let ctx = TestContext::new(client);

        let _develop_state = match ctx.get_fixture(FixtureKind::HeadSetToDevelopBranch).await {
            Ok(e) => e,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc).fail(
                    format!("Failed to create HeadSetToDevelopBranch fixture: {}", e),
                );
            }
        };

        // ============================================================
        // Step 2: Extract repo_id and owner npub from ValidRepo (cached by fixture)
        // ============================================================
        let valid_repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(e) => e,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail(format!("Failed to get ValidRepo fixture: {}", e));
            }
        };

        let repo_id = match valid_repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
        {
            Some(id) => id.to_string(),
            None => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail("Missing repo_id in ValidRepo");
            }
        };

        let npub = match valid_repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail(format!("Failed to convert pubkey to bech32: {}", e));
            }
        };

        // ============================================================
        // Step 3: Clone the repo to create a new local branch
        // ============================================================
        let clone_path = match clone_repo(relay_domain, &npub, &repo_id) {
            Ok(path) => path,
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail(format!("Failed to clone repo: {}", e));
            }
        };

        // ============================================================
        // Step 4: Create and checkout develop1 branch, then create unique commit
        // ============================================================
        let output = git_command()
            .args(["checkout", "-b", "develop1"])
            .current_dir(&clone_path)
            .output();

        match output {
            Err(e) => {
                let _ = fs::remove_dir_all(&clone_path);
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail(format!("Failed to create develop1 branch: {}", e));
            }
            Ok(out) if !out.status.success() => {
                let _ = fs::remove_dir_all(&clone_path);
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc).fail(
                    format!(
                        "Failed to create develop1 branch: {}",
                        String::from_utf8_lossy(&out.stderr)
                    ),
                );
            }
            Ok(_) => {}
        }

        // Create a unique commit on develop1
        let commit_hash = match create_commit(&clone_path, "Unique develop1 commit") {
            Ok(hash) => hash,
            Err(e) => {
                let _ = fs::remove_dir_all(&clone_path);
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail(format!("Failed to create commit: {}", e));
            }
        };

        // ============================================================
        // Step 5: Build and send state event with HEAD=refs/heads/develop1
        // This references a commit that doesn't yet exist on the relay
        // ============================================================
        let state_event = match client
            .event_builder(Kind::RepoState, "")
            .tag(Tag::identifier(&repo_id))
            .tag(Tag::custom("HEAD", vec!["refs/heads/develop1".to_string()]))
            .tag(Tag::custom(
                "refs/heads/develop1",
                vec![commit_hash.clone()],
            ))
            .tag(Tag::custom(
                "refs/heads/develop",
                vec![RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH.to_string()],
            ))
            .build(client.keys())
        {
            Ok(e) => e,
            Err(e) => {
                let _ = fs::remove_dir_all(&clone_path);
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail(format!("Failed to build state event: {}", e));
            }
        };

        // Send the state event (commit doesn't exist on relay yet)
        if let Err(e) = client
            .send_event_expect_purgatory_not_served(state_event)
            .await
        {
            let _ = fs::remove_dir_all(&clone_path);
            return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                .fail(format!("Failed to send state event: {}", e));
        }

        // ============================================================
        // Step 6: Push the develop1 branch - this sends the required oids
        // ============================================================
        let push_result = try_push_to_ref(&clone_path, "refs/heads/develop1");
        let _ = fs::remove_dir_all(&clone_path); // Cleanup clone

        match push_result {
            Ok(true) => { /* Push succeeded, continue to verify */ }
            Ok(false) => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail("Push to refs/heads/develop1 was rejected");
            }
            Err(e) => {
                return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                    .fail(format!("Failed to push develop1 branch: {}", e));
            }
        }

        // ============================================================
        // Step 7: VERIFY - Query info/refs to check the default branch
        // HEAD should now point to refs/heads/develop1 as git data is available
        // ============================================================
        let default_branch =
            match get_default_branch_from_info_refs(relay_domain, &npub, &repo_id).await {
                Ok(branch) => branch,
                Err(e) => {
                    return TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc)
                        .fail(format!("Failed to get default branch: {}", e));
                }
            };

        // Verify HEAD points to refs/heads/develop1
        if default_branch == "refs/heads/develop1" {
            TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc).pass()
        } else {
            TestResult::new(test_name, SpecRef::GitSetHeadOnReceive, desc).fail(format!(
                "Expected HEAD to point to 'refs/heads/develop1' but got '{}'. \
                GRASP-01 requires: 'MUST set repository HEAD per repository state announcement \
                as soon as the git data related to that branch has been received.'",
                default_branch
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test to discover the PR test commit hash
    ///
    /// This test creates a deterministic commit with PR-specific parameters
    /// and prints out the hash value. Once discovered, update PR_TEST_COMMIT_HASH.
    ///
    /// Run with: cd grasp-audit && nix develop -c cargo test --lib test_pr_test_commit_hash_discovery -- --nocapture
    #[test]
    fn test_pr_test_commit_hash_discovery() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path();

        // Initialize git repo
        let output = git_command()
            .args(["init"])
            .current_dir(path)
            .output()
            .expect("Failed to init git");
        assert!(
            output.status.success(),
            "git init failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Configure git user - use same identity as clone_repo in fixtures.rs
        let output = git_command()
            .args(["config", "user.email", "test@grasp-audit.local"])
            .current_dir(path)
            .output()
            .expect("git config email failed");
        assert!(output.status.success(), "git config email failed");

        let output = git_command()
            .args(["config", "user.name", "GRASP Audit Test"])
            .current_dir(path)
            .output()
            .expect("git config name failed");
        assert!(output.status.success(), "git config name failed");

        // Create the deterministic file content (must match CommitVariant::PRTestCommit exactly)
        let test_file = path.join("test.txt");
        fs::write(&test_file, "PR test deterministic commit\n").expect("Failed to write test file");

        // Add the file
        let output = git_command()
            .args(["add", "test.txt"])
            .current_dir(path)
            .output()
            .expect("git add failed");
        assert!(
            output.status.success(),
            "git add failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Create deterministic commit with fixed dates and GPG disabled
        let output = git_command()
            .args([
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "PR test deterministic commit",
            ])
            .env("GIT_AUTHOR_DATE", "2024-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2024-01-01T00:00:00Z")
            .current_dir(path)
            .output()
            .expect("git commit failed");
        assert!(
            output.status.success(),
            "git commit failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Get the commit hash
        let output = git_command()
            .args(["rev-parse", "HEAD"])
            .current_dir(path)
            .output()
            .expect("git rev-parse failed");
        assert!(
            output.status.success(),
            "git rev-parse failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );

        let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();

        println!("\n========================================");
        println!("PR_TEST_COMMIT_HASH should be: {}", hash);
        println!("========================================\n");

        // Verify we got a valid 40-character hex hash
        assert_eq!(hash.len(), 40, "Hash should be 40 hex chars, got: {}", hash);
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash should be hex chars only"
        );

        // If the constant is not PLACEHOLDER, verify it matches
        if PR_TEST_COMMIT_HASH != "PLACEHOLDER" {
            assert_eq!(
                hash, PR_TEST_COMMIT_HASH,
                "Commit hash mismatch! Expected {}, got {}. Update PR_TEST_COMMIT_HASH if commit parameters changed.",
                PR_TEST_COMMIT_HASH, hash
            );
        }
    }
}
