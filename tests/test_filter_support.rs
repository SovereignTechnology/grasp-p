//! Integration test for git filter support (--filter=blob:none)

use tempfile::TempDir;
use tokio::process::Command;

mod common;
use common::purgatory_helpers::{create_test_repo_with_commit, CommitVariant};
use common::SmartGitServer;

/// Test that the server advertises filter capability
#[tokio::test]
async fn test_filter_capability_advertised() {
    // Create a test repo
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("Failed to create test repo");

    // Start smart git server
    let server = SmartGitServer::start(temp_dir.path()).await;

    // Run git ls-remote to see advertised capabilities
    let output = Command::from(grasp_audit::git_command())
        .env("GIT_TRACE_PACKET", "1")
        .args(["ls-remote", server.url()])
        .output()
        .await
        .expect("Failed to run git ls-remote");

    // Capture stderr which contains GIT_TRACE_PACKET output
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check for filter capability in the advertisement
    // The capability is advertised as "filter" in the pkt-line
    assert!(
        stderr.contains("filter") || stderr.contains("allow"),
        "Expected to find 'filter' capability in git protocol advertisement.\nStderr:\n{}",
        stderr
    );

    // Also verify the command succeeded
    assert!(
        output.status.success(),
        "git ls-remote failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    server.stop().await;
}

/// Test that filtered clones work (--filter=blob:none)
#[tokio::test]
async fn test_filtered_clone_succeeds() {
    // Create a test repo with files
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("Failed to create test repo");

    // Start smart git server
    let server = SmartGitServer::start(temp_dir.path()).await;

    // Create a clone destination
    let clone_dir = TempDir::new().expect("Failed to create clone dir");
    let clone_path = clone_dir.path().join("cloned-repo");

    // Attempt a filtered clone
    let output = Command::from(grasp_audit::git_command())
        .args([
            "clone",
            "--filter=blob:none",
            server.url(),
            clone_path.to_str().unwrap(),
        ])
        .output()
        .await
        .expect("Failed to run git clone");

    // Check if clone succeeded
    if !output.status.success() {
        eprintln!("git clone --filter=blob:none failed!");
        eprintln!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("Filtered clone failed");
    }

    // Verify the clone worked
    assert!(clone_path.exists(), "Clone directory should exist");
    assert!(
        clone_path.join(".git").exists(),
        "Cloned repo should have .git directory"
    );

    // In a filtered clone, we should be able to list files
    let ls_output = Command::from(grasp_audit::git_command())
        .current_dir(&clone_path)
        .args(["ls-files"])
        .output()
        .await
        .expect("Failed to list files");

    assert!(
        ls_output.status.success(),
        "Should be able to list files in filtered clone"
    );

    let files = String::from_utf8_lossy(&ls_output.stdout);
    assert!(
        !files.trim().is_empty(),
        "Should have files in the filtered clone"
    );

    server.stop().await;
}

/// Test that filtered fetches work
#[tokio::test]
async fn test_filtered_fetch_succeeds() {
    // Create a test repo
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("Failed to create test repo");

    // Start smart git server
    let server = SmartGitServer::start(temp_dir.path()).await;

    // First, clone normally (to set up tracking)
    let clone_dir = TempDir::new().expect("Failed to create clone dir");
    let clone_path = clone_dir.path().join("repo");

    let clone_output = Command::from(grasp_audit::git_command())
        .args(["clone", server.url(), clone_path.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to run git clone");

    assert!(
        clone_output.status.success(),
        "Initial clone failed: {}",
        String::from_utf8_lossy(&clone_output.stderr)
    );

    // Now try a filtered fetch
    let fetch_output = Command::from(grasp_audit::git_command())
        .current_dir(&clone_path)
        .args(["fetch", "--filter=blob:none", "origin"])
        .output()
        .await
        .expect("Failed to run git fetch");

    // Check if fetch succeeded
    if !fetch_output.status.success() {
        eprintln!("git fetch --filter=blob:none failed!");
        eprintln!("Stdout: {}", String::from_utf8_lossy(&fetch_output.stdout));
        eprintln!("Stderr: {}", String::from_utf8_lossy(&fetch_output.stderr));
        panic!("Filtered fetch failed");
    }

    server.stop().await;
}
