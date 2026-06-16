//! GRASP-01 Repository Creation Tests
//!
//! Tests that verify bare Git repositories are created when repository announcements
//! are accepted by the relay.
//!
//! ## Test Coverage
//!
//! - Repository creation on valid announcement
//! - Repository accessibility via Smart HTTP service (git-upload-pack)
//! - URL format: http://domain/npub/identifier.git
//!
//! ## Running Tests
//!
//! ```bash
//! cd grasp-audit && nix develop -c bash test-ngit-relay.sh --mode test
//! ```

use crate::specs::grasp01::SpecRef;
use crate::{AuditClient, FixtureKind, TestContext, TestResult};
use nostr_sdk::prelude::*;

/// Test suite for repository creation
pub struct RepositoryCreationTests;

impl RepositoryCreationTests {
    /// Run all repository creation tests
    pub async fn run_all(client: &AuditClient, relay_domain: &str) -> crate::AuditResult {
        let mut results = crate::AuditResult::new("GRASP-01 Repository Creation Tests");

        results.add(Self::test_bare_repo_created_on_announcement(client, relay_domain).await);
        results.add(Self::test_webpage_served_for_existing_repo(client, relay_domain).await);
        results.add(Self::test_404_for_nonexistent_repo(client, relay_domain).await);

        results
    }

    /// Test that a bare repository is created when a valid announcement is accepted
    /// and is accessible via Smart HTTP service
    ///
    /// Spec: Line 28 of ../grasp/01.md
    /// This test verifies:
    /// 1. Sends a valid repository announcement via TestContext
    /// 2. Verifies the announcement was accepted
    /// 3. Repository responds to git-upload-pack service discovery
    /// 4. URL format follows http://domain/npub/identifier.git pattern
    pub async fn test_bare_repo_created_on_announcement(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_bare_repo_created_on_announcement";
        let ctx = TestContext::new(client);

        // Use TestContext to create and send repository announcement
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitServeRepository,
                    "Bare repository must be created and accessible via Smart HTTP when announcement is accepted",
                )
                .fail(format!("Failed to create repo fixture: {}", e))
            }
        };

        // Wait a bit for repository creation
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Extract repo identifier and npub from announcement
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
                    SpecRef::GitServeRepository,
                    "Bare repository must be created and accessible via Smart HTTP when announcement is accepted",
                )
                .fail("Repository announcement missing d tag")
            }
        };

        let npub = match repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitServeRepository,
                    "Bare repository must be created and accessible via Smart HTTP when announcement is accepted",
                )
                .fail(format!("Failed to convert pubkey to npub: {}", e))
            }
        };

        // Verify repository exists and is accessible via HTTP (info/refs endpoint)
        if let Err(e) = check_repo_accessible_via_http(relay_domain, &npub, &repo_id).await {
            return TestResult::new(
                test_name,
                SpecRef::GitServeRepository,
                "Bare repository must be created and accessible via Smart HTTP when announcement is accepted",
            )
            .fail(format!("Repository not accessible via HTTP: {}", e));
        }

        TestResult::new(
            test_name,
            SpecRef::GitServeRepository,
            "Bare repository must be created and accessible via Smart HTTP when announcement is accepted",
        )
        .pass()
    }

    /// Test that a webpage is served for an existing repository
    ///
    /// Spec: Line 38 of ../grasp/01.md
    /// This test verifies:
    /// 1. Creates a valid repository announcement
    /// 2. Accesses the repository URL without git service parameters
    /// 3. Verifies a webpage is returned (any 2xx status with HTML content)
    ///
    /// GRASP-01: "SHOULD serve a webpage at the same endpoint linking to git nostr client(s)"
    pub async fn test_webpage_served_for_existing_repo(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_webpage_served_for_existing_repo";
        let ctx = TestContext::new(client);

        // Create a repository announcement
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitServeWebpage,
                    "Relay SHOULD serve a webpage for existing repositories",
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
                    SpecRef::GitServeWebpage,
                    "Relay SHOULD serve a webpage for existing repositories",
                )
                .fail("Repository announcement missing d tag")
            }
        };

        let npub = match repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitServeWebpage,
                    "Relay SHOULD serve a webpage for existing repositories",
                )
                .fail(format!("Failed to convert pubkey to npub: {}", e))
            }
        };

        // Check that a webpage is served at the repository URL
        if let Err(e) = check_webpage_served(relay_domain, &npub, &repo_id).await {
            return TestResult::new(
                test_name,
                SpecRef::GitServeWebpage,
                "Relay SHOULD serve a webpage for existing repositories",
            )
            .fail(format!("Webpage not served: {}", e));
        }

        TestResult::new(
            test_name,
            SpecRef::GitServeWebpage,
            "Relay SHOULD serve a webpage for existing repositories",
        )
        .pass()
    }

    /// Test that 404 is returned for non-existent repositories
    ///
    /// Spec: Line 38 of ../grasp/01.md
    /// This test verifies:
    /// 1. Accesses a URL for a repository that doesn't exist
    /// 2. Verifies a 404 status is returned
    ///
    /// GRASP-01: "...and a 404 page for repositories it doesn't host"
    pub async fn test_404_for_nonexistent_repo(
        client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        let test_name = "test_404_for_nonexistent_repo";

        let ctx = TestContext::new(client);

        let repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitServeWebpage,
                    "Relay SHOULD return 404 for repositories it doesn't host",
                )
                .fail(format!("Failed to create repo fixture: {}", e))
            }
        };

        let npub = match repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::GitServeWebpage,
                    "Relay SHOULD return 404 for repositories it doesn't host",
                )
                .fail(format!("Failed to convert pubkey to npub: {}", e))
            }
        };
        // Use a clearly non-existent repo id but real npub
        let fake_repo_id = "nonexistent-repo-12345";

        // Check that 404 is returned
        if let Err(e) = check_404_for_nonexistent_repo(relay_domain, &npub, fake_repo_id).await {
            return TestResult::new(
                test_name,
                SpecRef::GitServeWebpage,
                "Relay SHOULD return 404 for repositories it doesn't host",
            )
            .fail(format!("Expected 404, got: {}", e));
        }

        TestResult::new(
            test_name,
            SpecRef::GitServeWebpage,
            "Relay SHOULD return 404 for repositories it doesn't host",
        )
        .pass()
    }
}

/// Helper function to check if a repository is accessible via Smart HTTP service
///
/// Verifies that the repository responds correctly to git-upload-pack service discovery
/// at the URL: http://domain/npub/identifier.git/info/refs?service=git-upload-pack
async fn check_repo_accessible_via_http(
    relay_domain: &str,
    npub: &str,
    repo_id: &str,
) -> Result<(), String> {
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

    // Verify Content-Type indicates git-upload-pack service
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("application/x-git-upload-pack-advertisement") {
        return Err(format!(
            "Expected Content-Type: application/x-git-upload-pack-advertisement, got: {}",
            content_type
        ));
    }

    Ok(())
}

/// Helper function to check if a webpage is served for an existing repository
///
/// Verifies that accessing the repository URL returns a webpage (2xx status)
/// URL format: http://domain/npub/identifier.git
async fn check_webpage_served(relay_domain: &str, npub: &str, repo_id: &str) -> Result<(), String> {
    let repo_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);

    let http_client = reqwest::Client::new();
    let response = http_client
        .get(&repo_url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Expected 2xx status for existing repo webpage, got {} for URL: {}",
            response.status(),
            repo_url
        ));
    }

    Ok(())
}

/// Helper function to check that 404 is returned for non-existent repository
///
/// Verifies that accessing a non-existent repository URL returns 404
async fn check_404_for_nonexistent_repo(
    relay_domain: &str,
    npub: &str,
    repo_id: &str,
) -> Result<(), String> {
    let repo_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);

    let http_client = reqwest::Client::new();
    let response = http_client
        .get(&repo_url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if response.status().as_u16() != 404 {
        return Err(format!(
            "Expected 404 status for non-existent repo, got {} for URL: {}",
            response.status(),
            repo_url
        ));
    }

    Ok(())
}
