//! GRASP-01 CORS Tests
//!
//! Tests for GRASP-01 CORS requirements (lines 40-47 of ../grasp/01.md)
//!
//! These tests validate that a GRASP-01 compliant relay implements CORS correctly:
//! - Sets `Access-Control-Allow-Origin: *` on ALL responses
//! - Sets `Access-Control-Allow-Methods: GET, POST` on ALL responses
//! - Sets `Access-Control-Allow-Headers: Content-Type` on ALL responses
//! - Responds to OPTIONS requests with 204 No Content
//!
//! ## Running Tests
//!
//! ```bash
//! cd grasp-audit && nix develop -c bash test-ngit-relay.sh --mode test
//! ```

use crate::specs::grasp01::SpecRef;
use crate::{AuditClient, AuditResult, FixtureKind, TestContext, TestResult};
use nostr_sdk::prelude::*;

pub struct CorsTests;

impl CorsTests {
    /// Run all CORS tests
    pub async fn run_all(client: &AuditClient, relay_domain: &str) -> AuditResult {
        let mut results = AuditResult::new("GRASP-01 CORS Tests");

        // CORS tests against Git HTTP endpoints
        results.add(Self::test_cors_allow_origin(client, relay_domain).await);
        results.add(Self::test_cors_allow_methods(client, relay_domain).await);
        results.add(Self::test_cors_allow_headers(client, relay_domain).await);
        results.add(Self::test_cors_options_preflight(client, relay_domain).await);

        results
    }

    // =========================================================================
    // CORS Tests
    // =========================================================================

    /// Test: Access-Control-Allow-Origin header on all responses
    ///
    /// Spec: Line 44 of ../grasp/01.md
    /// Requirement: Set `Access-Control-Allow-Origin: *` on ALL responses
    pub async fn test_cors_allow_origin(_client: &AuditClient, relay_domain: &str) -> TestResult {
        TestResult::new(
            "cors_allow_origin",
            SpecRef::CorsAllowOrigin,
            "Access-Control-Allow-Origin: * on all responses",
        )
        .run(|| {
            let relay_domain = relay_domain.to_string();
            async move {
                // Test multiple endpoints to verify "ALL responses" requirement
                let http_client = reqwest::Client::new();

                // 1. Test root endpoint
                let root_url = format!("http://{}/", relay_domain);
                let response = http_client
                    .get(&root_url)
                    .send()
                    .await
                    .map_err(|e| format!("Failed to GET root: {}", e))?;

                check_cors_allow_origin(&response, "root endpoint")?;

                // 2. Test a non-existent repo path (still should have CORS headers)
                let repo_url = format!(
                    "http://{}/npub1test/nonexistent.git/info/refs?service=git-upload-pack",
                    relay_domain
                );
                let response = http_client
                    .get(&repo_url)
                    .send()
                    .await
                    .map_err(|e| format!("Failed to GET repo endpoint: {}", e))?;

                // Even 404 responses must have CORS headers
                check_cors_allow_origin(&response, "git-upload-pack endpoint (even if 404)")?;

                Ok(())
            }
        })
        .await
    }

    /// Test: Access-Control-Allow-Methods header on all responses
    ///
    /// Spec: Line 45 of ../grasp/01.md
    /// Requirement: Set `Access-Control-Allow-Methods: GET, POST` on ALL responses
    pub async fn test_cors_allow_methods(_client: &AuditClient, relay_domain: &str) -> TestResult {
        TestResult::new(
            "cors_allow_methods",
            SpecRef::CorsAllowMethods,
            "Access-Control-Allow-Methods: GET, POST on all responses",
        )
        .run(|| {
            let relay_domain = relay_domain.to_string();
            async move {
                let http_client = reqwest::Client::new();

                // Test root endpoint
                let root_url = format!("http://{}/", relay_domain);
                let response = http_client
                    .get(&root_url)
                    .send()
                    .await
                    .map_err(|e| format!("Failed to GET root: {}", e))?;

                check_cors_allow_methods(&response, "root endpoint")?;

                // Test a repo path
                let repo_url = format!(
                    "http://{}/npub1test/nonexistent.git/info/refs?service=git-upload-pack",
                    relay_domain
                );
                let response = http_client
                    .get(&repo_url)
                    .send()
                    .await
                    .map_err(|e| format!("Failed to GET repo endpoint: {}", e))?;

                check_cors_allow_methods(&response, "git-upload-pack endpoint")?;

                Ok(())
            }
        })
        .await
    }

    /// Test: Access-Control-Allow-Headers header on all responses
    ///
    /// Spec: Line 46 of ../grasp/01.md
    /// Requirement: Set `Access-Control-Allow-Headers: Content-Type` on ALL responses
    pub async fn test_cors_allow_headers(_client: &AuditClient, relay_domain: &str) -> TestResult {
        TestResult::new(
            "cors_allow_headers",
            SpecRef::CorsAllowHeaders,
            "Access-Control-Allow-Headers: Content-Type on all responses",
        )
        .run(|| {
            let relay_domain = relay_domain.to_string();
            async move {
                let http_client = reqwest::Client::new();

                // Test root endpoint
                let root_url = format!("http://{}/", relay_domain);
                let response = http_client
                    .get(&root_url)
                    .send()
                    .await
                    .map_err(|e| format!("Failed to GET root: {}", e))?;

                check_cors_allow_headers(&response, "root endpoint")?;

                // Test a repo path
                let repo_url = format!(
                    "http://{}/npub1test/nonexistent.git/info/refs?service=git-upload-pack",
                    relay_domain
                );
                let response = http_client
                    .get(&repo_url)
                    .send()
                    .await
                    .map_err(|e| format!("Failed to GET repo endpoint: {}", e))?;

                check_cors_allow_headers(&response, "git-upload-pack endpoint")?;

                Ok(())
            }
        })
        .await
    }

    /// Test: OPTIONS preflight requests return 204 No Content
    ///
    /// Spec: Line 47 of ../grasp/01.md
    /// Requirement: Respond to OPTIONS requests with 204 No Content
    pub async fn test_cors_options_preflight(
        _client: &AuditClient,
        relay_domain: &str,
    ) -> TestResult {
        TestResult::new(
            "cors_options_preflight",
            SpecRef::CorsOptionsResponse,
            "OPTIONS requests return 204 No Content with CORS headers",
        )
        .run(|| {
            let relay_domain = relay_domain.to_string();
            async move {
                let http_client = reqwest::Client::new();

                // 1. Test OPTIONS on root endpoint
                let root_url = format!("http://{}/", relay_domain);
                let response = http_client
                    .request(reqwest::Method::OPTIONS, &root_url)
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "POST")
                    .send()
                    .await
                    .map_err(|e| format!("Failed to OPTIONS root: {}", e))?;

                check_options_response(&response, "root endpoint")?;

                // 2. Test OPTIONS on git-upload-pack endpoint
                let repo_url =
                    format!("http://{}/npub1test/test.git/git-upload-pack", relay_domain);
                let response = http_client
                    .request(reqwest::Method::OPTIONS, &repo_url)
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "POST")
                    .send()
                    .await
                    .map_err(|e| format!("Failed to OPTIONS git-upload-pack: {}", e))?;

                check_options_response(&response, "git-upload-pack endpoint")?;

                // 3. Test OPTIONS on info/refs endpoint
                let refs_url = format!("http://{}/npub1test/test.git/info/refs", relay_domain);
                let response = http_client
                    .request(reqwest::Method::OPTIONS, &refs_url)
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "GET")
                    .send()
                    .await
                    .map_err(|e| format!("Failed to OPTIONS info/refs: {}", e))?;

                check_options_response(&response, "info/refs endpoint")?;

                Ok(())
            }
        })
        .await
    }

    // =========================================================================
    // Integration test methods for use from external test files
    // These match the pattern used by GitCloneTests
    // =========================================================================

    /// Integration test: CORS Allow-Origin header with repository creation
    ///
    /// For integration tests that want to test against real repositories
    pub async fn test_cors_on_real_repo(client: &AuditClient, relay_domain: &str) -> TestResult {
        let test_name = "test_cors_on_real_repo";
        let ctx = TestContext::new(client);

        // Create repository announcement to get a real repo path
        let repo = match ctx.get_fixture(FixtureKind::ValidRepoSent).await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::CorsAllowOrigin,
                    "CORS headers on real repository endpoints",
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
                    SpecRef::CorsAllowOrigin,
                    "CORS headers on real repository endpoints",
                )
                .fail("Repository announcement missing d tag")
            }
        };

        let npub = match repo.pubkey.to_bech32() {
            Ok(n) => n,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::CorsAllowOrigin,
                    "CORS headers on real repository endpoints",
                )
                .fail(format!("Failed to convert pubkey to npub: {}", e))
            }
        };

        // Test CORS on real repo endpoint
        let http_client = reqwest::Client::new();
        let info_refs_url = format!(
            "http://{}/{}/{}.git/info/refs?service=git-upload-pack",
            relay_domain, npub, repo_id
        );

        let response = match http_client.get(&info_refs_url).send().await {
            Ok(r) => r,
            Err(e) => {
                return TestResult::new(
                    test_name,
                    SpecRef::CorsAllowOrigin,
                    "CORS headers on real repository endpoints",
                )
                .fail(format!("Failed to GET info/refs: {}", e))
            }
        };

        // Check all CORS headers
        if let Err(e) = check_cors_allow_origin(&response, "info/refs") {
            return TestResult::new(
                test_name,
                SpecRef::CorsAllowOrigin,
                "CORS headers on real repository endpoints",
            )
            .fail(&e);
        }

        if let Err(e) = check_cors_allow_methods(&response, "info/refs") {
            return TestResult::new(
                test_name,
                SpecRef::CorsAllowMethods,
                "CORS headers on real repository endpoints",
            )
            .fail(&e);
        }

        if let Err(e) = check_cors_allow_headers(&response, "info/refs") {
            return TestResult::new(
                test_name,
                SpecRef::CorsAllowHeaders,
                "CORS headers on real repository endpoints",
            )
            .fail(&e);
        }

        TestResult::new(
            test_name,
            SpecRef::CorsAllowOrigin,
            "CORS headers on real repository endpoints",
        )
        .pass()
    }
}

// =========================================================================
// Helper functions
// =========================================================================

/// Check Access-Control-Allow-Origin header
fn check_cors_allow_origin(response: &reqwest::Response, context: &str) -> Result<(), String> {
    let header = response
        .headers()
        .get("Access-Control-Allow-Origin")
        .ok_or_else(|| format!("Missing Access-Control-Allow-Origin header on {}", context))?;

    let value = header
        .to_str()
        .map_err(|e| format!("Invalid Access-Control-Allow-Origin header value: {}", e))?;

    if value != "*" {
        return Err(format!(
            "Expected Access-Control-Allow-Origin: *, got: '{}' on {}",
            value, context
        ));
    }

    Ok(())
}

/// Check Access-Control-Allow-Methods header
fn check_cors_allow_methods(response: &reqwest::Response, context: &str) -> Result<(), String> {
    let header = response
        .headers()
        .get("Access-Control-Allow-Methods")
        .ok_or_else(|| format!("Missing Access-Control-Allow-Methods header on {}", context))?;

    let value = header
        .to_str()
        .map_err(|e| format!("Invalid Access-Control-Allow-Methods header value: {}", e))?;

    // The header should contain at least GET and POST
    // Value could be "GET, POST" or "GET,POST" or include other methods
    let methods: Vec<&str> = value.split(',').map(|s| s.trim()).collect();

    if !methods.contains(&"GET") || !methods.contains(&"POST") {
        return Err(format!(
            "Expected Access-Control-Allow-Methods to include GET and POST, got: '{}' on {}",
            value, context
        ));
    }

    Ok(())
}

/// Check Access-Control-Allow-Headers header
fn check_cors_allow_headers(response: &reqwest::Response, context: &str) -> Result<(), String> {
    let header = response
        .headers()
        .get("Access-Control-Allow-Headers")
        .ok_or_else(|| format!("Missing Access-Control-Allow-Headers header on {}", context))?;

    let value = header
        .to_str()
        .map_err(|e| format!("Invalid Access-Control-Allow-Headers header value: {}", e))?;

    // The header should contain at least Content-Type (case-insensitive)
    let headers_lower = value.to_lowercase();
    if !headers_lower.contains("content-type") {
        return Err(format!(
            "Expected Access-Control-Allow-Headers to include Content-Type, got: '{}' on {}",
            value, context
        ));
    }

    Ok(())
}

/// Check OPTIONS preflight response
fn check_options_response(response: &reqwest::Response, context: &str) -> Result<(), String> {
    // 1. Verify 204 No Content status
    if response.status().as_u16() != 204 {
        return Err(format!(
            "Expected 204 No Content for OPTIONS on {}, got: {} {}",
            context,
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ));
    }

    // 2. Also verify CORS headers are present on OPTIONS response
    check_cors_allow_origin(response, &format!("OPTIONS {}", context))?;
    check_cors_allow_methods(response, &format!("OPTIONS {}", context))?;
    check_cors_allow_headers(response, &format!("OPTIONS {}", context))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditConfig;

    #[tokio::test]
    #[ignore] // Requires running relay
    async fn test_grasp01_cors_against_relay() {
        // Read relay URL from environment variable - must be supplied
        let relay_url = std::env::var("RELAY_URL").expect(
            "RELAY_URL environment variable must be set. Example: RELAY_URL=ws://localhost:18081",
        );

        // Extract domain from relay URL for HTTP requests
        let relay_domain = relay_url
            .replace("ws://", "")
            .replace("wss://", "")
            .trim_end_matches('/')
            .to_string();

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

        let results = CorsTests::run_all(&client, &relay_domain).await;
        results.print_report();

        // Assert all tests passed
        assert!(results.all_passed(), "Some GRASP-01 CORS tests failed");
    }
}
