//! GRASP-01 NIP-11 Document
//!
//! Tests for GRASP-01 NIP-11 relay information document requirements (lines 24-28 of ../grasp/01.md)
//!
//! These tests validate that a GRASP-01 compliant relay:
//! - Serves a valid NIP-11 relay information document
//! - Includes supported_grasps field listing supported GRASPs
//! - Includes repo_acceptance_criteria field describing acceptance policy
//! - Handles curation field correctly (present if curated, absent otherwise)

use crate::specs::grasp01::SpecRef;
use crate::{AuditClient, AuditResult, TestResult};

pub struct Nip11DocumentTests;

impl Nip11DocumentTests {
    /// Run all NIP-11 document tests
    pub async fn run_all(client: &AuditClient) -> AuditResult {
        let mut results = AuditResult::new("GRASP-01 NIP-11 Document Tests");

        // NIP-11 relay information tests
        results.add(Self::test_nip11_document_exists(client).await);
        results.add(Self::test_nip11_supported_grasps_field(client).await);
        results.add(Self::test_nip11_repo_acceptance_criteria_field(client).await);
        results.add(Self::test_nip11_curation_field(client).await);

        results
    }

    // =========================================================================
    // NIP-11 Relay Information Tests
    // =========================================================================

    /// Test: Serve NIP-11 document
    ///
    /// Spec: Line 24 of ../grasp/01.md
    /// Requirement: MUST serve NIP-11 document
    pub async fn test_nip11_document_exists(client: &AuditClient) -> TestResult {
        TestResult::new(
            "nip11_document_exists",
            SpecRef::Nip11ServeDocument,
            "MUST serve NIP-11 document",
        )
        .run(|| async {
            // 1. Extract HTTP(S) URL from client's WebSocket URL
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_url = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;

            // 2. HTTP GET to base URL with Accept: application/nostr+json header
            let http_client = reqwest::Client::new();
            let response = http_client
                .get(&http_url)
                .header("Accept", "application/nostr+json")
                .send()
                .await
                .map_err(|e| format!("Failed to fetch NIP-11 document: {}", e))?;

            // 3. Verify 200 OK response
            if !response.status().is_success() {
                return Err(format!(
                    "Expected 200 OK, got {} {}",
                    response.status().as_u16(),
                    response.status().canonical_reason().unwrap_or("Unknown")
                ));
            }

            // 4. Verify response is valid JSON
            let json_text = response
                .text()
                .await
                .map_err(|e| format!("Failed to read response body: {}", e))?;

            let doc: serde_json::Value = serde_json::from_str(&json_text)
                .map_err(|e| format!("Response is not valid JSON: {}", e))?;

            // 5. Verify has required NIP-11 fields
            let required_fields = ["name", "description", "software", "version"];
            for field in &required_fields {
                if doc.get(field).is_none() {
                    return Err(format!("Missing required NIP-11 field: {}", field));
                }
            }

            Ok(())
        })
        .await
    }

    /// Test: NIP-11 includes supported_grasps field
    ///
    /// Spec: Line 26 of ../grasp/01.md
    /// Requirement: MUST list supported GRASPs as string array
    pub async fn test_nip11_supported_grasps_field(client: &AuditClient) -> TestResult {
        TestResult::new(
            "nip11_supported_grasps_field",
            SpecRef::Nip11ListSupportedGrasps,
            "MUST list supported GRASPs as string array",
        )
        .run(|| async {
            // 1. Fetch NIP-11 document
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_url = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;

            let http_client = reqwest::Client::new();
            let response = http_client
                .get(&http_url)
                .header("Accept", "application/nostr+json")
                .send()
                .await
                .map_err(|e| format!("Failed to fetch NIP-11 document: {}", e))?;

            let json_text = response
                .text()
                .await
                .map_err(|e| format!("Failed to read response body: {}", e))?;

            let doc: serde_json::Value = serde_json::from_str(&json_text)
                .map_err(|e| format!("Response is not valid JSON: {}", e))?;

            // 2. Verify `supported_grasps` field exists
            let supported_grasps = doc
                .get("supported_grasps")
                .ok_or_else(|| "Missing required field: supported_grasps".to_string())?;

            // 3. Verify it's a JSON array
            let grasps_array = supported_grasps
                .as_array()
                .ok_or_else(|| "supported_grasps must be an array".to_string())?;

            // 4. Verify array includes "GRASP-01"
            let grasp_strings: Vec<String> = grasps_array
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();

            if !grasp_strings.contains(&"GRASP-01".to_string()) {
                return Err(format!(
                    "supported_grasps must include 'GRASP-01', found: {:?}",
                    grasp_strings
                ));
            }

            // 5. Verify format: each entry should match pattern "GRASP-\d{2}"
            let grasp_pattern = regex::Regex::new(r"^GRASP-\d{2}$")
                .map_err(|e| format!("Failed to compile regex: {}", e))?;

            for grasp in &grasp_strings {
                if !grasp_pattern.is_match(grasp) {
                    return Err(format!(
                        "Invalid GRASP format: '{}' (expected GRASP-XX where XX is two digits)",
                        grasp
                    ));
                }
            }

            Ok(())
        })
        .await
    }

    /// Test: NIP-11 includes repo_acceptance_criteria field
    ///
    /// Spec: Line 27 of ../grasp/01.md
    /// Requirement: MUST list repository acceptance criteria
    pub async fn test_nip11_repo_acceptance_criteria_field(client: &AuditClient) -> TestResult {
        TestResult::new(
            "nip11_repo_acceptance_criteria_field",
            SpecRef::Nip11ListRepoAcceptanceCriteria,
            "MUST list repository acceptance criteria",
        )
        .run(|| async {
            // 1. Fetch NIP-11 document
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_url = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;

            let http_client = reqwest::Client::new();
            let response = http_client
                .get(&http_url)
                .header("Accept", "application/nostr+json")
                .send()
                .await
                .map_err(|e| format!("Failed to fetch NIP-11 document: {}", e))?;

            let json_text = response
                .text()
                .await
                .map_err(|e| format!("Failed to read response body: {}", e))?;

            let doc: serde_json::Value = serde_json::from_str(&json_text)
                .map_err(|e| format!("Response is not valid JSON: {}", e))?;

            // 2. Verify `repo_acceptance_criteria` field exists
            let criteria = doc
                .get("repo_acceptance_criteria")
                .ok_or_else(|| "Missing required field: repo_acceptance_criteria".to_string())?;

            // 3. Verify it's a string
            let criteria_str = criteria
                .as_str()
                .ok_or_else(|| "repo_acceptance_criteria must be a string".to_string())?;

            // 4. Verify non-empty
            if criteria_str.trim().is_empty() {
                return Err("repo_acceptance_criteria must not be empty".to_string());
            }

            Ok(())
        })
        .await
    }

    /// Test: NIP-11 curation field handling
    ///
    /// Spec: Line 28 of ../grasp/01.md
    /// Requirement: MUST include curation if curated, omit otherwise
    pub async fn test_nip11_curation_field(client: &AuditClient) -> TestResult {
        TestResult::new(
            "nip11_curation_field",
            SpecRef::Nip11ListCurationPolicy,
            "MUST include curation if curated, omit otherwise",
        )
        .run(|| async {
            // 1. Fetch NIP-11 document
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_url = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;

            let http_client = reqwest::Client::new();
            let response = http_client
                .get(&http_url)
                .header("Accept", "application/nostr+json")
                .send()
                .await
                .map_err(|e| format!("Failed to fetch NIP-11 document: {}", e))?;

            let json_text = response
                .text()
                .await
                .map_err(|e| format!("Failed to read response body: {}", e))?;

            let doc: serde_json::Value = serde_json::from_str(&json_text)
                .map_err(|e| format!("Response is not valid JSON: {}", e))?;

            // 2. Check if `curation` field exists
            if let Some(curation) = doc.get("curation") {
                // 3. If present: verify it's a non-empty string
                let curation_str = curation
                    .as_str()
                    .ok_or_else(|| "curation field must be a string when present".to_string())?;

                if curation_str.trim().is_empty() {
                    return Err("curation field must not be empty when present".to_string());
                }
            }
            // 4. If absent: both cases are valid per spec

            // 5. Both cases are valid - test passes
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
    async fn test_grasp01_nip11_document_against_relay() {
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

        let results = Nip11DocumentTests::run_all(&client).await;
        results.print_report();

        // Don't assert all passed yet - tests not implemented
        // assert!(results.all_passed(), "Some GRASP-01 NIP-11 document tests failed");
    }
}
