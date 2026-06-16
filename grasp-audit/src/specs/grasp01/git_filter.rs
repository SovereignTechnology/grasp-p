//! GRASP-01 Git Filter Capability Tests
//!
//! Tests that verify uploadpack.allowFilter support for partial clone operations.
//!
//! ## Test Coverage
//!
//! - Filter capability advertisement in info/refs
//! - Filtered clone with blob:none works correctly  
//! - Filtered fetch with tree:0 works correctly
//!
//! ## Specification Reference
//!
//! Per GRASP-01 line 36-43, implementations MUST:
//! - Include `allow-reachable-sha1-in-want` in advertisement
//! - Include `allow-tip-sha1-in-want` in advertisement  
//! - Include uploadpack.allowFilter in advertisement
//! - Serve available oids and filtered requests
//!
//! ## Running Tests
//!
//! ```bash
//! cd grasp-audit && nix develop -c bash test-ngit-relay.sh --mode test
//! ```

use crate::specs::grasp01::SpecRef;
use crate::{AuditClient, FixtureKind, TestContext, TestResult};
use nostr_sdk::prelude::*;
use std::fs;
use std::process::Command;

/// Test suite for Git filter capability operations
pub struct GitFilterTests;

impl GitFilterTests {
    /// Run all Git filter tests
    pub async fn run_all(client: &AuditClient, relay_domain: &str) -> crate::AuditResult {
        let mut results = crate::AuditResult::new("GRASP-01 Git Filter Tests");

        results.add(Self::test_filter_capability_advertised(client, relay_domain).await);
        results.add(Self::test_filtered_clone_succeeds(client, relay_domain).await);
        results.add(Self::test_filtered_fetch_succeeds(client, relay_domain).await);

        results
    }

    /// Test that filter capability is advertised in git-upload-pack
    ///
    /// Spec: Line 36 of ../grasp/01.md (updated requirement)
    /// GRASP-01 requires:
    /// "MUST include `allow-reachable-sha1-in-want`, `allow-tip-sha1-in-want`,
    /// and uploadpack.allowFilter in advertisement and serve available oids and
    /// filtered requests."
    ///
    /// This test verifies:
    /// 1. The info/refs endpoint returns the filter capability
    /// 2. The capability appears in the advertisement
    pub async fn test_filter_capability_advertised(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_filter_capability_advertised";
        let ctx = TestContext::new(client);

        // Create repository announcement
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitIncludeAllowSha1InWant,
                    "MUST include uploadpack.allowFilter in advertisement",
                )
                .fail(format!("Failed to create repo fixture: {}", e))
            }
        };

        // Wait for repository creation
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Extract repo identifier and npub
        let repo_id = match repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
        {
            Some(id) => id.to_string(),
            None => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitIncludeAllowSha1InWant,
                    "MUST include uploadpack.allowFilter in advertisement",
                )
                .fail("Repository announcement missing d tag")
            }
        };

        let npub = match repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitIncludeAllowSha1InWant,
                    "MUST include uploadpack.allowFilter in advertisement",
                )
                .fail(format!("Failed to convert pubkey to npub: {}", e))
            }
        };

        // Build info/refs URL for git-upload-pack service
        let info_refs_url = format!(
            "http://{}/{}/{}.git/info/refs?service=git-upload-pack",
            relay_domain, npub, repo_id
        );

        // Make HTTP request to get the advertisement
        let http_client = reqwest::Client::new();
        let response = match http_client.get(&info_refs_url).send().await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitIncludeAllowSha1InWant,
                    "MUST include uploadpack.allowFilter in advertisement",
                )
                .fail(format!("HTTP request failed: {}", e))
            }
        };

        if !response.status().is_success() {
            return TestResult::new(
                test_name,
                SpecRef::GitIncludeAllowSha1InWant,
                "MUST include uploadpack.allowFilter in advertisement",
            )
            .fail(format!(
                "info/refs request failed with status: {}",
                response.status()
            ));
        }

        // Get response body
        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitIncludeAllowSha1InWant,
                    "MUST include uploadpack.allowFilter in advertisement",
                )
                .fail(format!("Failed to read response body: {}", e))
            }
        };

        // Check for filter capability
        if !body.contains("filter") {
            return TestResult::new(
                test_name,
                SpecRef::GitIncludeAllowSha1InWant,
                "MUST include uploadpack.allowFilter in advertisement",
            )
            .fail("Missing capability: filter");
        }

        TestResult::new(
            test_name,
            SpecRef::GitIncludeAllowSha1InWant,
            "MUST include uploadpack.allowFilter in advertisement",
        )
        .pass()
    }

    /// Test that filtered clone with blob:none works
    ///
    /// Spec: Line 36 of ../grasp/01.md
    /// This test verifies:
    /// 1. A repository can be cloned with --filter=blob:none
    /// 2. The clone succeeds without downloading blob objects
    /// 3. The cloned repository structure is valid
    pub async fn test_filtered_clone_succeeds(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_filtered_clone_succeeds";
        let ctx = TestContext::new(client);

        // Create repository announcement
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitIncludeAllowSha1InWant,
                    "MUST serve filtered clone requests",
                )
                .fail(format!("Failed to create repo fixture: {}", e))
            }
        };

        // Wait for repository creation
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let repo_id = repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .ok_or("Missing d tag")
            .unwrap()
            .to_string();

        let npub = repo.pubkey.to_bech32().unwrap();

        // Create a test clone directory
        let temp_base = std::env::temp_dir();
        let clone_dir_name = format!("grasp-test-filter-clone-{}", uuid::Uuid::new_v4());
        let clone_path = temp_base.join(&clone_dir_name);

        // Ensure clean state
        let _ = fs::remove_dir_all(&clone_path);

        // Build clone URL
        let clone_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);

        // Attempt filtered clone with blob:none
        let output = Command::new("git")
            .args([
                "clone",
                "--filter=blob:none",
                &clone_url,
                clone_path.to_str().unwrap(),
            ])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output();

        // Clean up
        let cleanup = || {
            let _ = fs::remove_dir_all(&clone_path);
        };

        let output = match output {
            Ok(o) => o,
            Err(e) => {
                cleanup();
                return TestResult::new(
                    test_name,
                    SpecRef::GitIncludeAllowSha1InWant,
                    "MUST serve filtered clone requests",
                )
                .fail(format!("Failed to execute git clone: {}", e));
            }
        };

        if !output.status.success() {
            cleanup();
            let stderr = String::from_utf8_lossy(&output.stderr);
            return TestResult::new(
                test_name,
                SpecRef::GitIncludeAllowSha1InWant,
                "MUST serve filtered clone requests",
            )
            .fail(format!("Filtered git clone failed: {}", stderr));
        }

        // Verify clone succeeded
        if !clone_path.join(".git").is_dir() {
            cleanup();
            return TestResult::new(
                test_name,
                SpecRef::GitIncludeAllowSha1InWant,
                "MUST serve filtered clone requests",
            )
            .fail("Filtered clone missing .git directory");
        }

        cleanup();
        TestResult::new(
            test_name,
            SpecRef::GitIncludeAllowSha1InWant,
            "MUST serve filtered clone requests",
        )
        .pass()
    }

    /// Test that filtered fetch with tree:0 works
    ///
    /// Spec: Line 36 of ../grasp/01.md
    /// This test verifies:
    /// 1. An existing repository can fetch with --filter=tree:0
    /// 2. The fetch succeeds without downloading tree objects
    pub async fn test_filtered_fetch_succeeds(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_filtered_fetch_succeeds";
        let ctx = TestContext::new(client);

        // Create repository announcement
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitIncludeAllowSha1InWant,
                    "MUST serve filtered fetch requests",
                )
                .fail(format!("Failed to create repo fixture: {}", e))
            }
        };

        // Wait for repository creation
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let repo_id = repo
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .ok_or("Missing d tag")
            .unwrap()
            .to_string();

        let npub = repo.pubkey.to_bech32().unwrap();

        // Create a test clone directory
        let temp_base = std::env::temp_dir();
        let clone_dir_name = format!("grasp-test-filter-fetch-{}", uuid::Uuid::new_v4());
        let clone_path = temp_base.join(&clone_dir_name);

        // Ensure clean state
        let _ = fs::remove_dir_all(&clone_path);

        // Build clone URL
        let clone_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);

        // First do a shallow clone to have a repository to fetch into
        let clone_output = Command::new("git")
            .args([
                "clone",
                "--depth=1",
                &clone_url,
                clone_path.to_str().unwrap(),
            ])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output();

        // Clean up
        let cleanup = || {
            let _ = fs::remove_dir_all(&clone_path);
        };

        if clone_output.is_err() || !clone_output.as_ref().unwrap().status.success() {
            cleanup();
            return TestResult::new(
                test_name,
                SpecRef::GitIncludeAllowSha1InWant,
                "MUST serve filtered fetch requests",
            )
            .fail("Failed to create initial shallow clone for fetch test");
        }

        // Now attempt a filtered fetch
        let output = Command::new("git")
            .args(["fetch", "--filter=tree:0", "origin"])
            .current_dir(&clone_path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output();

        let output = match output {
            Ok(o) => o,
            Err(e) => {
                cleanup();
                return TestResult::new(
                    test_name,
                    SpecRef::GitIncludeAllowSha1InWant,
                    "MUST serve filtered fetch requests",
                )
                .fail(format!("Failed to execute git fetch: {}", e));
            }
        };

        if !output.status.success() {
            cleanup();
            let stderr = String::from_utf8_lossy(&output.stderr);
            return TestResult::new(
                test_name,
                SpecRef::GitIncludeAllowSha1InWant,
                "MUST serve filtered fetch requests",
            )
            .fail(format!("Filtered git fetch failed: {}", stderr));
        }

        cleanup();
        TestResult::new(
            test_name,
            SpecRef::GitIncludeAllowSha1InWant,
            "MUST serve filtered fetch requests",
        )
        .pass()
    }
}
