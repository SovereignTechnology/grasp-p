use crate::config::Config;
/// NIP-11 Relay Information Document
///
/// Implements NIP-11 relay information endpoint with GRASP-01 extensions.
/// See: https://github.com/nostr-protocol/nips/blob/master/11.md
use serde::{Deserialize, Serialize};

/// NIP-11 Relay Information Document
///
/// This structure represents the relay metadata served at the HTTP(S) endpoint
/// when the client sends `Accept: application/nostr+json` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInformationDocument {
    /// Relay name
    pub name: String,

    /// Relay description
    pub description: String,

    /// Relay owner's public key (hex format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,

    /// Contact information for relay admin
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,

    /// List of NIPs supported by this relay
    pub supported_nips: Vec<u16>,

    /// Relay software identifier
    pub software: String,

    /// Software version
    pub version: String,

    /// Relay icon URL (NIP-11 optional field)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    // GRASP-01 Extensions (lines 11-14 of GRASP-01 spec)
    /// List of supported GRASPs (e.g., ["GRASP-01"])
    /// Required by GRASP-01 specification line 12
    pub supported_grasps: Vec<String>,

    /// Repository acceptance criteria description
    /// Required by GRASP-01 specification line 13
    pub repo_acceptance_criteria: String,

    /// Curation policy (present if curated, absent otherwise)
    /// Optional per GRASP-01 specification line 14
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curation: Option<String>,
}

impl RelayInformationDocument {
    /// Create NIP-11 relay information document from configuration
    pub fn from_config(config: &Config) -> Self {
        // Get validated configuration (config.validate() must be called at startup)
        let archive_config = config.archive_config();
        let archive_enabled = archive_config.enabled();
        let archive_read_only = archive_config.read_only;

        // Build supported_grasps list
        let mut supported_grasps = vec!["GRASP-01".to_string()];
        if archive_enabled {
            supported_grasps.push("GRASP-05".to_string());
        }
        supported_grasps.push("GRASP-02".to_string());
        if config.grasp06_enable {
            supported_grasps.push("GRASP-06".to_string());
        }

        // Build curation field for archive read-only mode or repository whitelist
        let repository_config = config.repository_config();
        let repository_whitelist_enabled = repository_config.enabled();

        let curation = if archive_read_only {
            // Archive read-only mode (GRASP-05 only)
            if archive_config.archive_all {
                Some("Read-only sync of all repositories found on network".to_string())
            } else if !archive_config.whitelist.is_empty() {
                Some("Read-only sync of whitelisted repositories and maintainers".to_string())
            } else {
                None
            }
        } else if archive_enabled && repository_whitelist_enabled {
            // Both archive (non-read-only) AND repository whitelist enabled
            Some(
                "Accepts whitelisted repositories (with or without service listing) and whitelisted repositories that list this service"
                    .to_string(),
            )
        } else if repository_whitelist_enabled {
            // Repository whitelist only
            Some(
                "Accepts only whitelisted repositories and maintainers that list this service"
                    .to_string(),
            )
        } else {
            None
        };

        Self {
            name: config.relay_name(),
            description: config.relay_description.clone(),
            pubkey: config.relay_owner_pubkey_hex().ok(),
            contact: None, // Could be added to config if needed
            supported_nips: vec![
                1,  // NIP-01: Basic protocol flow
                11, // NIP-11: Relay information document (this!)
                34, // NIP-34: Git repository announcements
                77, // NIP-77: Negentropy sync (reconciliation protocol)
            ],
            software: "https://gitworkshop.dev/danconwaydev.com/ngit-grasp".to_string(),
            version: match option_env!("GIT_COMMIT_SHORT") {
                Some(commit) => format!("{}-{}", env!("CARGO_PKG_VERSION"), commit),
                None => env!("CARGO_PKG_VERSION").to_string(),
            },
            icon: Some(format!("https://{}/icon.png", config.domain)),

            // GRASP Extensions
            supported_grasps,
            repo_acceptance_criteria: "None".to_string(),
            curation,
        }
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::nips::nip19::ToBech32;

    #[test]
    fn test_relay_information_document_structure() {
        let mut config = Config::for_testing();
        config.domain = "relay.example.com".to_string();
        config.relay_name_override = Some("Test Relay".to_string());
        config.relay_description = "A test relay".to_string();

        let doc = RelayInformationDocument::from_config(&config);

        assert_eq!(doc.name, "Test Relay");
        assert_eq!(doc.description, "A test relay");

        // Verify pubkey is present and is a valid hex string (64 chars)
        assert!(doc.pubkey.is_some());
        let pubkey = doc.pubkey.unwrap();
        assert_eq!(pubkey.len(), 64);
        assert!(pubkey.chars().all(|c| c.is_ascii_hexdigit()));

        assert!(doc.supported_nips.contains(&1));
        assert!(doc.supported_nips.contains(&11));
        assert!(doc.supported_nips.contains(&34));
        assert!(doc.supported_nips.contains(&77));
        // Without archive mode, only GRASP-01 and GRASP-02
        assert_eq!(doc.supported_grasps, vec!["GRASP-01", "GRASP-02"]);
        assert!(doc.repo_acceptance_criteria.contains("None"));
        assert!(doc.curation.is_none());
        assert_eq!(
            doc.icon,
            Some("https://relay.example.com/icon.png".to_string())
        );
    }

    #[test]
    fn test_relay_information_document_json() {
        let mut config = Config::for_testing();
        config.domain = "relay.example.com".to_string();
        config.relay_name_override = Some("Test Relay".to_string());
        config.relay_description = "A test relay".to_string();

        let doc = RelayInformationDocument::from_config(&config);
        let json = doc.to_json().expect("Failed to serialize to JSON");

        // Verify JSON contains expected fields
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"supported_nips\""));
        assert!(json.contains("\"supported_grasps\""));
        assert!(json.contains("\"repo_acceptance_criteria\""));
        assert!(json.contains("GRASP-01"));
        assert!(json.contains("GRASP-02"));

        // Verify it's valid JSON by parsing
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON");
        assert_eq!(parsed["name"], "Test Relay");
        assert_eq!(parsed["supported_grasps"][0], "GRASP-01");
        assert_eq!(parsed["supported_grasps"][1], "GRASP-02");
        assert_eq!(parsed["icon"], "https://relay.example.com/icon.png");
    }

    #[test]
    fn test_nip11_with_archive_mode() {
        let mut config = Config::for_testing();
        config.domain = "relay.example.com".to_string();
        config.relay_name_override = Some("Archive Relay".to_string());
        config.archive_all = true;
        config.archive_read_only = Some(true);

        let doc = RelayInformationDocument::from_config(&config);

        // Archive mode enabled: should include GRASP-05
        assert_eq!(
            doc.supported_grasps,
            vec!["GRASP-01", "GRASP-05", "GRASP-02"]
        );
        // Archive read-only: should have curation field
        assert!(doc.curation.is_some());
        assert!(doc
            .curation
            .unwrap()
            .contains("Read-only sync of all repositories"));
    }

    #[test]
    fn test_nip11_with_whitelist_archive() {
        let keys = nostr_sdk::prelude::Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let mut config = Config::for_testing();
        config.domain = "relay.example.com".to_string();
        config.archive_whitelist = format!("{},bitcoin-core", test_npub);

        let doc = RelayInformationDocument::from_config(&config);

        // Archive whitelist enabled: should include GRASP-05
        assert_eq!(
            doc.supported_grasps,
            vec!["GRASP-01", "GRASP-05", "GRASP-02"]
        );
        // Archive read-only defaults to true: should have curation field
        assert!(doc.curation.is_some());
        assert!(doc
            .curation
            .unwrap()
            .contains("Read-only sync of whitelisted"));
    }

    #[test]
    fn test_nip11_with_repository_whitelist() {
        let keys = nostr_sdk::prelude::Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let mut config = Config::for_testing();
        config.domain = "relay.example.com".to_string();
        config.repository_whitelist = format!("{},bitcoin-core", test_npub);

        let doc = RelayInformationDocument::from_config(&config);

        // Repository whitelist doesn't enable GRASP-05
        assert_eq!(doc.supported_grasps, vec!["GRASP-01", "GRASP-02"]);
        // Should have curation field for repository whitelist
        assert!(doc.curation.is_some());
        assert!(doc
            .curation
            .unwrap()
            .contains("Accepts only whitelisted repositories"));
    }

    #[test]
    fn test_nip11_with_archive_and_repository_whitelist() {
        let keys = nostr_sdk::prelude::Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let mut config = Config::for_testing();
        config.domain = "relay.example.com".to_string();
        config.archive_whitelist = "bitcoin-core".to_string();
        config.archive_read_only = Some(false); // Non-read-only archive mode
        config.repository_whitelist = test_npub;

        let doc = RelayInformationDocument::from_config(&config);

        // Should have GRASP-05 enabled due to archive whitelist
        assert_eq!(
            doc.supported_grasps,
            vec!["GRASP-01", "GRASP-05", "GRASP-02"]
        );
        // Should have curation field reflecting BOTH archive and repository whitelist
        assert!(doc.curation.is_some());
        let curation = doc.curation.unwrap();
        assert!(curation.contains("whitelisted repositories"));
        assert!(curation.contains("with or without service listing"));
    }

    #[test]
    fn test_nip11_grasp_06_disabled_by_default() {
        let config = Config::for_testing();
        let doc = RelayInformationDocument::from_config(&config);

        // GRASP-06 must not be advertised when the flag is off.
        assert!(!doc.supported_grasps.iter().any(|g| g == "GRASP-06"));
    }

    #[test]
    fn test_nip11_advertises_grasp_06_when_enabled() {
        let mut config = Config::for_testing();
        config.grasp06_enable = true;

        let doc = RelayInformationDocument::from_config(&config);

        // GRASP-06 must be advertised when the flag is on, alongside the
        // standard GRASP-01 / GRASP-02 entries. Order is "GRASP-06 last"
        // to match the insertion order in from_config().
        assert_eq!(
            doc.supported_grasps,
            vec!["GRASP-01", "GRASP-02", "GRASP-06"]
        );
    }
}
