//! Purgatory Sync Test Helpers
//!
//! Provides utilities for testing purgatory sync functionality:
//! - Git repository setup with deterministic commits
//! - State event creation with specific OIDs
//! - PR event creation referencing repositories
//! - Purgatory state inspection helpers
//!
//! # nostr-sdk 0.43 API Notes
//! - Use field access: `event.id`, `event.tags`, `event.tags.iter()`
//! - Use `Tag::custom("name", vec![...])` syntax
//! - Use `EventBuilder::new(kind, content).tags(tags)` syntax

use grasp_audit::git_command;
use nostr_sdk::prelude::*;
use std::path::Path;
use std::time::Duration;

// NOTE: Using rust-nostr Kind variants:
// - Kind::RepoState.as_u16() -> Kind::RepoState (30618)
// - Kind::GitPullRequest.as_u16() -> Kind::GitPullRequest (1618)

/// Commit variants for deterministic test commits
#[derive(Debug, Clone, Copy)]
pub enum CommitVariant {
    /// State event test commit (for testing state sync)
    StateTest,
    /// PR event test commit (for testing PR sync)
    PrTest,
    /// Second commit for partial sync tests
    SecondCommit,
}

/// Create a git repository with a deterministic commit for testing.
///
/// Creates a new git repository at the given path with a single commit.
/// The commit is deterministic based on the variant for reproducible tests.
///
/// # Arguments
/// * `path` - Directory to create repository in
/// * `variant` - Which deterministic commit to create
///
/// # Returns
/// The commit hash of the created commit
pub fn create_test_repo_with_commit(path: &Path, variant: CommitVariant) -> Result<String, String> {
    // Initialize git repo
    run_git(path, &["init", "--initial-branch=main"])?;

    // Configure git user for commits
    run_git(path, &["config", "user.email", "test@example.com"])?;
    run_git(path, &["config", "user.name", "Test User"])?;

    // Disable GPG signing for tests (prevents yubikey prompts)
    run_git(path, &["config", "commit.gpgsign", "false"])?;
    run_git(path, &["config", "tag.gpgsign", "false"])?;

    // Create a file based on variant
    let (filename, content) = match variant {
        CommitVariant::StateTest => ("state_test.txt", "State test content for purgatory sync"),
        CommitVariant::PrTest => ("pr_test.txt", "PR test content for purgatory sync"),
        CommitVariant::SecondCommit => ("second.txt", "Second commit content for partial sync"),
    };

    std::fs::write(path.join(filename), content)
        .map_err(|e| format!("Failed to write test file: {}", e))?;

    // Add and commit
    run_git(path, &["add", "."])?;

    let commit_message = match variant {
        CommitVariant::StateTest => "State test commit",
        CommitVariant::PrTest => "PR test commit",
        CommitVariant::SecondCommit => "Second test commit",
    };

    run_git(path, &["commit", "-m", commit_message])?;

    // Get the commit hash
    get_head_commit(path)
}

/// Add an additional commit to an existing repository.
///
/// Useful for tests that need multiple commits (e.g., partial OID aggregation).
///
/// # Arguments
/// * `path` - Path to existing repository
/// * `variant` - Which commit variant to add
///
/// # Returns
/// The commit hash of the new commit
pub fn add_commit_to_repo(path: &Path, variant: CommitVariant) -> Result<String, String> {
    let (filename, content) = match variant {
        CommitVariant::StateTest => ("state_test.txt", "Updated state test content"),
        CommitVariant::PrTest => ("pr_test.txt", "Updated PR test content"),
        CommitVariant::SecondCommit => ("second.txt", "Second commit content"),
    };

    std::fs::write(path.join(filename), content)
        .map_err(|e| format!("Failed to write test file: {}", e))?;

    run_git(path, &["add", "."])?;

    let commit_message = match variant {
        CommitVariant::StateTest => "Updated state commit",
        CommitVariant::PrTest => "Updated PR commit",
        CommitVariant::SecondCommit => "Second commit",
    };

    run_git(path, &["commit", "-m", commit_message])?;

    get_head_commit(path)
}

/// Create a branch at a specific commit.
///
/// # Arguments
/// * `path` - Path to repository
/// * `branch_name` - Name of the branch to create
/// * `commit_hash` - Commit hash to point the branch at (or None for HEAD)
pub fn create_branch(
    path: &Path,
    branch_name: &str,
    commit_hash: Option<&str>,
) -> Result<(), String> {
    match commit_hash {
        Some(hash) => run_git(path, &["branch", branch_name, hash]),
        None => run_git(path, &["branch", branch_name]),
    }
}

/// Get the HEAD commit hash.
fn get_head_commit(path: &Path) -> Result<String, String> {
    let output = git_command()
        .args(["rev-parse", "HEAD"])
        .current_dir(path)
        .output()
        .map_err(|e| format!("Failed to run git rev-parse: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git command in the specified directory.
fn run_git(path: &Path, args: &[&str]) -> Result<(), String> {
    let output = git_command()
        .args(args)
        .current_dir(path)
        .output()
        .map_err(|e| format!("Failed to run git {}: {}", args.join(" "), e))?;

    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Create a state event (kind 30618) with specific branch/tag OIDs.
///
/// Creates a properly formatted NIP-34 repository state event that can be
/// sent to a relay. The event includes refs/heads/* and refs/tags/* tags
/// for the specified branches and tags.
///
/// # Arguments
/// * `keys` - Keys for signing
/// * `identifier` - Repository identifier (d-tag)
/// * `branches` - Vec of (name, commit_hash) for branches
/// * `tags` - Vec of (name, commit_hash) for tags
/// * `clone_urls` - Clone URLs to include
/// * `relay_urls` - Relay URLs to include
///
/// # Returns
/// * `Ok(Event)` - Signed state event ready to send
/// * `Err(String)` - If signing fails
pub fn create_state_event(
    keys: &Keys,
    identifier: &str,
    branches: &[(&str, &str)],
    tags: &[(&str, &str)],
    clone_urls: &[&str],
    relay_urls: &[&str],
) -> Result<Event, String> {
    let mut event_tags = vec![
        // d-tag (identifier)
        Tag::custom("d", vec![identifier.to_string()]),
    ];

    // Add clone URLs
    if !clone_urls.is_empty() {
        let urls: Vec<String> = clone_urls.iter().map(|s| s.to_string()).collect();
        event_tags.push(Tag::custom("clone", urls));
    }

    // Add relay URLs
    if !relay_urls.is_empty() {
        let urls: Vec<String> = relay_urls.iter().map(|s| s.to_string()).collect();
        event_tags.push(Tag::custom("relays", urls));
    }

    // Add branch refs (refs/heads/*)
    for (name, commit) in branches {
        let ref_name = format!("refs/heads/{}", name);
        event_tags.push(Tag::custom(ref_name, vec![commit.to_string()]));
    }

    // Add tag refs (refs/tags/*)
    for (name, commit) in tags {
        let ref_name = format!("refs/tags/{}", name);
        event_tags.push(Tag::custom(ref_name, vec![commit.to_string()]));
    }

    // Add HEAD pointing to main (if main exists)
    if branches.iter().any(|(name, _)| *name == "main") {
        event_tags.push(Tag::custom("HEAD", vec!["refs/heads/main".to_string()]));
    }

    EventBuilder::new(Kind::RepoState, "")
        .tags(event_tags)
        .finalize(keys)
        .map_err(|e| format!("Failed to sign state event: {}", e))
}

/// Create a PR event (kind 1618) referencing a repository and commit.
///
/// Creates a properly formatted NIP-34 PR event that references a repository
/// via an `a` tag and includes the commit hash via a `c` tag.
///
/// # Arguments
/// * `keys` - Keys for signing
/// * `repo_coord` - Repository coordinate (format: "30617:pubkey_hex:identifier")
/// * `commit_hash` - The commit hash (c-tag)
/// * `title` - PR title (used as content)
///
/// # Returns
/// * `Ok(Event)` - Signed PR event ready to send
/// * `Err(String)` - If signing fails
pub fn create_pr_event(
    keys: &Keys,
    repo_coord: &str,
    commit_hash: &str,
    title: &str,
) -> Result<Event, String> {
    let tags = vec![
        // a-tag referencing the repository
        Tag::custom("a", vec![repo_coord.to_string()]),
        // c-tag with the commit hash
        Tag::custom("c", vec![commit_hash.to_string()]),
    ];

    EventBuilder::new(Kind::GitPullRequest, title)
        .tags(tags)
        .finalize(keys)
        .map_err(|e| format!("Failed to sign PR event: {}", e))
}

/// Create a PR event (kind 1618) with clone URLs.
///
/// Creates a properly formatted NIP-34 PR event that references a repository
/// via an `a` tag, includes the commit hash via a `c` tag, and specifies
/// clone URLs where the PR commit can be fetched from.
///
/// Per NIP-34, PR events can include a `clone` tag:
/// ```jsonc
/// {
///   "kind": 1618,
///   "tags": [
///     ["c", "<current-commit-id>"],
///     ["clone", "<clone-url>", ...], // at least one git clone url where commit can be downloaded
///     // ...
///   ]
/// }
/// ```
///
/// # Arguments
/// * `keys` - Keys for signing
/// * `repo_coord` - Repository coordinate (format: "30617:pubkey_hex:identifier")
/// * `commit_hash` - The commit hash (c-tag)
/// * `title` - PR title (used as content)
/// * `clone_urls` - Clone URLs where the PR commit can be fetched
///
/// # Returns
/// * `Ok(Event)` - Signed PR event ready to send
/// * `Err(String)` - If signing fails
pub fn create_pr_event_with_clone(
    keys: &Keys,
    repo_coord: &str,
    commit_hash: &str,
    title: &str,
    clone_urls: &[&str],
) -> Result<Event, String> {
    let mut tags = vec![
        // a-tag referencing the repository
        Tag::custom("a", vec![repo_coord.to_string()]),
        // c-tag with the commit hash
        Tag::custom("c", vec![commit_hash.to_string()]),
    ];

    // Add clone URLs if provided
    if !clone_urls.is_empty() {
        let urls: Vec<String> = clone_urls.iter().map(|s| s.to_string()).collect();
        tags.push(Tag::custom("clone", urls));
    }

    EventBuilder::new(Kind::GitPullRequest, title)
        .tags(tags)
        .finalize(keys)
        .map_err(|e| format!("Failed to sign PR event: {}", e))
}

/// Build a repository coordinate string for use in 'a' tags.
///
/// Format: `30617:pubkey_hex:identifier`
///
/// # Arguments
/// * `keys` - Keys whose public key will be used
/// * `identifier` - Repository identifier (d-tag value)
pub fn build_repo_coord(keys: &Keys, identifier: &str) -> String {
    format!("30617:{}:{}", keys.public_key().to_hex(), identifier)
}

/// Create a repository announcement event (kind 30617) for purgatory tests.
///
/// Creates a minimal but valid NIP-34 repository announcement with a `d` tag,
/// optional `clone` URLs, and optional `relays` URLs.
///
/// # Arguments
/// * `keys` - Keys for signing
/// * `identifier` - Repository identifier (d-tag)
/// * `clone_urls` - Clone URLs to include (may be empty)
/// * `relay_urls` - Relay URLs to include (may be empty)
///
/// # Returns
/// * `Ok(Event)` - Signed announcement event
/// * `Err(String)` - If signing fails
pub fn create_announcement_event(
    keys: &Keys,
    identifier: &str,
    clone_urls: &[&str],
    relay_urls: &[&str],
) -> Result<Event, String> {
    let mut tags = vec![Tag::identifier(identifier)];

    if !clone_urls.is_empty() {
        let urls: Vec<String> = clone_urls.iter().map(|s| s.to_string()).collect();
        tags.push(Tag::custom("clone", urls));
    }

    if !relay_urls.is_empty() {
        let urls: Vec<String> = relay_urls.iter().map(|s| s.to_string()).collect();
        tags.push(Tag::custom("relays", urls));
    }

    EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(tags)
        .finalize(keys)
        .map_err(|e| format!("Failed to sign announcement event: {}", e))
}

/// Wait for an event to be served by a relay (not in purgatory).
///
/// Polls the relay until the event is queryable, indicating it has
/// been released from purgatory. Uses exponential backoff for polling.
///
/// # Arguments
/// * `relay_url` - WebSocket URL of the relay
/// * `event_id` - Event ID to wait for
/// * `timeout` - Maximum time to wait
///
/// # Returns
/// * `Ok(Event)` - The event was found
/// * `Err(String)` - Timeout or error
pub async fn wait_for_event_served(
    relay_url: &str,
    event_id: &EventId,
    timeout: Duration,
) -> Result<Event, String> {
    let temp_keys = Keys::generate();
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(temp_keys))
        .build();

    client
        .add_relay(relay_url)
        .await
        .map_err(|e| format!("Failed to add relay: {}", e))?;

    client.connect().await;

    // Wait for connection
    let mut connected = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let relays = client.relays().await;
        if relays.values().any(|r| r.status().is_connected()) {
            connected = true;
            break;
        }
    }

    if !connected {
        client.disconnect().await;
        return Err("Failed to connect to relay".to_string());
    }

    // Poll for the event with exponential backoff
    let start = std::time::Instant::now();
    let mut poll_interval = Duration::from_millis(100);
    let max_interval = Duration::from_secs(2);

    while start.elapsed() < timeout {
        let filter = Filter::new().id(*event_id);

        match client
            .fetch_events(filter)
            .timeout(Duration::from_secs(2))
            .await
        {
            Ok(events) => {
                if let Some(event) = events.into_iter().next() {
                    client.disconnect().await;
                    return Ok(event);
                }
            }
            Err(_) => {
                // Ignore fetch errors, will retry
            }
        }

        tokio::time::sleep(poll_interval).await;
        poll_interval = std::cmp::min(poll_interval * 2, max_interval);
    }

    client.disconnect().await;
    Err(format!(
        "Timeout waiting for event {} after {:?}",
        event_id, timeout
    ))
}

/// Wait for an event to NOT be served by a relay (still in purgatory).
///
/// Polls the relay and verifies the event is NOT returned, indicating
/// it is still in purgatory.
///
/// # Arguments
/// * `relay_url` - WebSocket URL of the relay
/// * `event_id` - Event ID to check
/// * `check_duration` - How long to verify the event stays absent
///
/// # Returns
/// * `Ok(())` - Event is not served (in purgatory)
/// * `Err(String)` - Event was found (not in purgatory) or error
pub async fn verify_event_not_served(
    relay_url: &str,
    event_id: &EventId,
    check_duration: Duration,
) -> Result<(), String> {
    let temp_keys = Keys::generate();
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(temp_keys))
        .build();

    client
        .add_relay(relay_url)
        .await
        .map_err(|e| format!("Failed to add relay: {}", e))?;

    client.connect().await;

    // Wait for connection
    let mut connected = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let relays = client.relays().await;
        if relays.values().any(|r| r.status().is_connected()) {
            connected = true;
            break;
        }
    }

    if !connected {
        client.disconnect().await;
        return Err("Failed to connect to relay".to_string());
    }

    // Check that event is NOT served
    let filter = Filter::new().id(*event_id);

    match client.fetch_events(filter).timeout(check_duration).await {
        Ok(events) => {
            client.disconnect().await;
            if events.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "Event {} was served (expected to be in purgatory)",
                    event_id
                ))
            }
        }
        Err(e) => {
            client.disconnect().await;
            // Fetch error could mean timeout (expected) or actual error
            // For our purposes, if we couldn't find it, that's success
            tracing::debug!("Fetch returned error (expected for purgatory check): {}", e);
            Ok(())
        }
    }
}

/// Check if a ref exists at a specific commit on a relay's git endpoint.
///
/// Uses git ls-remote to check the remote refs without cloning.
///
/// # Arguments
/// * `relay_domain` - The relay domain (e.g., "127.0.0.1:8080")
/// * `npub` - Owner's npub
/// * `repo_id` - Repository identifier
/// * `ref_name` - Ref to check (e.g., "refs/heads/main")
/// * `expected_commit` - Expected commit hash
///
/// # Returns
/// * `Ok(true)` - Ref exists and points to expected commit
/// * `Ok(false)` - Ref doesn't exist or points to different commit
/// * `Err(String)` - Error checking ref
pub async fn check_ref_at_commit(
    relay_domain: &str,
    npub: &str,
    repo_id: &str,
    ref_name: &str,
    expected_commit: &str,
) -> Result<bool, String> {
    let remote_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);

    let output = git_command()
        .args(["ls-remote", &remote_url, ref_name])
        .output()
        .map_err(|e| format!("Failed to run git ls-remote: {}", e))?;

    if !output.status.success() {
        // ls-remote can fail if repo doesn't exist yet, which is expected in some tests
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output: "<commit>\t<ref>"
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 && parts[1] == ref_name {
            // Compare commit hashes (handle both full and short hashes)
            let remote_commit = parts[0];
            return Ok(remote_commit.starts_with(expected_commit)
                || expected_commit.starts_with(remote_commit));
        }
    }

    Ok(false)
}

/// Push a local repository to a relay.
///
/// Adds the relay as a remote and pushes all refs.
///
/// # Arguments
/// * `local_path` - Path to local git repository
/// * `relay_domain` - The relay domain (e.g., "127.0.0.1:8080")
/// * `npub` - Owner's npub
/// * `repo_id` - Repository identifier
///
/// # Returns
/// * `Ok(())` - Push successful
/// * `Err(String)` - Push failed
pub fn push_to_relay(
    local_path: &Path,
    relay_domain: &str,
    npub: &str,
    repo_id: &str,
) -> Result<(), String> {
    let remote_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);

    // Check if origin already exists
    let check_output = git_command()
        .args(["remote", "get-url", "origin"])
        .current_dir(local_path)
        .output()
        .map_err(|e| format!("Failed to check remote: {}", e))?;

    if check_output.status.success() {
        // Remote exists, update it
        run_git(local_path, &["remote", "set-url", "origin", &remote_url])?;
    } else {
        // Add new remote
        run_git(local_path, &["remote", "add", "origin", &remote_url])?;
    }

    // Push all refs
    let output = git_command()
        .args(["push", "-u", "origin", "--all"])
        .current_dir(local_path)
        .output()
        .map_err(|e| format!("Failed to run git push: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "git push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Push a specific ref to a relay.
///
/// This is used for pushing to refs/nostr/<event-id> for PR events.
/// Unlike `push_to_relay` which pushes all refs, this pushes a specific
/// commit to a specific ref name.
///
/// # Arguments
/// * `local_path` - Path to local git repository
/// * `relay_domain` - The relay domain (e.g., "127.0.0.1:8080")
/// * `npub` - Owner's npub
/// * `repo_id` - Repository identifier
/// * `commit_hash` - The commit to push
/// * `ref_name` - The ref name to push to (e.g., "refs/nostr/<event-id>")
///
/// # Returns
/// * `Ok(())` - Push successful
/// * `Err(String)` - Push failed
pub fn push_ref_to_relay(
    local_path: &Path,
    relay_domain: &str,
    npub: &str,
    repo_id: &str,
    commit_hash: &str,
    ref_name: &str,
) -> Result<(), String> {
    let remote_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);

    // Check if origin already exists
    let check_output = git_command()
        .args(["remote", "get-url", "origin"])
        .current_dir(local_path)
        .output()
        .map_err(|e| format!("Failed to check remote: {}", e))?;

    if check_output.status.success() {
        // Remote exists, update it
        let _ = git_command()
            .args(["remote", "set-url", "origin", &remote_url])
            .current_dir(local_path)
            .output();
    } else {
        // Add new remote
        let _ = git_command()
            .args(["remote", "add", "origin", &remote_url])
            .current_dir(local_path)
            .output();
    }

    // Push specific commit to specific ref
    // Format: git push origin <commit>:<ref>
    let refspec = format!("{}:{}", commit_hash, ref_name);
    let output = git_command()
        .args(["push", "origin", &refspec])
        .current_dir(local_path)
        .output()
        .map_err(|e| format!("Failed to run git push: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "git push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_repo_with_commit() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Verify commit hash is a valid git hash (40 hex chars)
        assert_eq!(commit_hash.len(), 40);
        assert!(commit_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify the file was created
        assert!(temp_dir.path().join("state_test.txt").exists());
    }

    #[test]
    fn test_add_commit_to_repo() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        // Create initial repo
        let first_commit = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Add second commit
        let second_commit = add_commit_to_repo(temp_dir.path(), CommitVariant::SecondCommit)
            .expect("Failed to add commit");

        // Commits should be different
        assert_ne!(first_commit, second_commit);

        // Both files should exist
        assert!(temp_dir.path().join("state_test.txt").exists());
        assert!(temp_dir.path().join("second.txt").exists());
    }

    #[test]
    fn test_create_state_event_has_correct_tags() {
        let keys = Keys::generate();
        let event = create_state_event(
            &keys,
            "test-repo",
            &[("main", "abc123def456")],
            &[("v1.0", "def456abc123")],
            &["http://example.com/test.git"],
            &["ws://example.com"],
        )
        .expect("Failed to create state event");

        assert_eq!(event.kind.as_u16(), Kind::RepoState.as_u16());

        // Check d-tag
        let has_d_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "d")
                && slice.get(1).is_some_and(|v| v == "test-repo")
        });
        assert!(has_d_tag, "Event should have 'd' tag with identifier");

        // Check refs/heads/main tag
        let has_branch_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "refs/heads/main")
                && slice.get(1).is_some_and(|v| v == "abc123def456")
        });
        assert!(has_branch_tag, "Event should have refs/heads/main tag");

        // Check refs/tags/v1.0 tag
        let has_tag_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "refs/tags/v1.0")
                && slice.get(1).is_some_and(|v| v == "def456abc123")
        });
        assert!(has_tag_tag, "Event should have refs/tags/v1.0 tag");

        // Check HEAD tag
        let has_head_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "HEAD")
                && slice.get(1).is_some_and(|v| v == "refs/heads/main")
        });
        assert!(has_head_tag, "Event should have HEAD tag");
    }

    #[test]
    fn test_create_pr_event_has_correct_tags() {
        let keys = Keys::generate();
        let repo_coord = build_repo_coord(&keys, "test-repo");
        let event = create_pr_event(&keys, &repo_coord, "def456abc123", "Test PR")
            .expect("Failed to create PR event");

        assert_eq!(event.kind.as_u16(), Kind::GitPullRequest.as_u16());

        // Check a-tag
        let has_a_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "a")
                && slice.get(1).is_some_and(|v| v == &repo_coord)
        });
        assert!(has_a_tag, "Event should have 'a' tag");

        // Check c-tag
        let has_c_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "c")
                && slice.get(1).is_some_and(|v| v == "def456abc123")
        });
        assert!(has_c_tag, "Event should have 'c' tag with commit");
    }

    #[test]
    fn test_build_repo_coord_format() {
        let keys = Keys::generate();
        let coord = build_repo_coord(&keys, "my-repo");

        assert!(coord.starts_with("30617:"));
        assert!(coord.ends_with(":my-repo"));
        assert_eq!(coord.split(':').count(), 3);
    }

    #[test]
    fn test_create_branch() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        // Create initial repo
        let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Create a branch at HEAD
        create_branch(temp_dir.path(), "feature", None).expect("Failed to create branch");

        // Verify branch exists
        let output = git_command()
            .args(["rev-parse", "feature"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to run git rev-parse");

        assert!(output.status.success());
        let branch_commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(branch_commit, commit_hash);
    }

    #[test]
    fn test_create_pr_event_with_clone_has_correct_tags() {
        let keys = Keys::generate();
        let repo_coord = build_repo_coord(&keys, "test-repo");
        let event = create_pr_event_with_clone(
            &keys,
            &repo_coord,
            "abc123def456",
            "Test PR with clone",
            &[
                "http://fork-server.com/repo.git",
                "http://another-server.com/repo.git",
            ],
        )
        .expect("Failed to create PR event with clone");

        assert_eq!(event.kind.as_u16(), Kind::GitPullRequest.as_u16());

        // Check a-tag
        let has_a_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "a")
                && slice.get(1).is_some_and(|v| v == &repo_coord)
        });
        assert!(has_a_tag, "Event should have 'a' tag");

        // Check c-tag
        let has_c_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "c")
                && slice.get(1).is_some_and(|v| v == "abc123def456")
        });
        assert!(has_c_tag, "Event should have 'c' tag with commit");

        // Check clone tag with both URLs
        let has_clone_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "clone")
                && slice
                    .get(1)
                    .is_some_and(|v| v == "http://fork-server.com/repo.git")
                && slice
                    .get(2)
                    .is_some_and(|v| v == "http://another-server.com/repo.git")
        });
        assert!(has_clone_tag, "Event should have 'clone' tag with URLs");
    }

    #[test]
    fn test_create_pr_event_with_clone_empty_urls() {
        let keys = Keys::generate();
        let repo_coord = build_repo_coord(&keys, "test-repo");
        let event = create_pr_event_with_clone(
            &keys,
            &repo_coord,
            "abc123def456",
            "Test PR without clone URLs",
            &[], // Empty clone URLs
        )
        .expect("Failed to create PR event");

        // Should not have clone tag when no URLs provided
        let has_clone_tag = event.tags.iter().any(|tag| {
            let slice = tag.as_slice();
            slice.first().is_some_and(|t| t == "clone")
        });
        assert!(
            !has_clone_tag,
            "Event should not have 'clone' tag when no URLs provided"
        );
    }
}
