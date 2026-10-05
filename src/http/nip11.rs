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

    /// Standard NIP-11 limits enforced by the embedded relay.
    pub limitation: RelayLimitation,

    // GRASP-01 Extensions (lines 24-28 of GRASP-01 spec)
    /// List of supported GRASPs (e.g., ["GRASP-01"])
    /// Required by GRASP-01 specification line 26
    pub supported_grasps: Vec<String>,

    /// Repository acceptance criteria description
    /// Required by GRASP-01 specification line 27
    pub repo_acceptance_criteria: String,

    /// Curation policy (present if curated, absent otherwise)
    /// Required by GRASP-01 specification line 28 when events are curated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curation: Option<String>,

    /// GRASP-P private repositories advert (present only when
    /// NGIT_GRASP_P_REPOS_ENABLE=true). Blossom-subset blob routes are
    /// HTTP-side (BUDs), not NIPs — deliberately not in supported_nips.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_repos: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayLimitation {
    pub max_message_length: usize,
    pub max_subscriptions: usize,
    pub max_limit: usize,
    pub max_subid_length: usize,
    pub default_limit: usize,
    pub restricted_writes: bool,
}

impl RelayInformationDocument {
    /// Create a NIP-11 document for the configured public mount path.
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
        if config.sync_plus_enabled {
            supported_grasps.push("GRASP-03".to_string());
        }
        if config.grasp06_enable {
            supported_grasps.push("GRASP-06".to_string());
        }
        if config.private_mode {
            supported_grasps.push("GRASP-08".to_string());
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
            supported_nips: {
                let mut nips = vec![
                    1,  // NIP-01: Basic protocol flow
                    11, // NIP-11: Relay information document (this!)
                    34, // NIP-34: Git repository announcements
                    77, // NIP-77: Negentropy sync (reconciliation protocol)
                ];
                if config.is_domain_root() {
                    nips.push(5); // NIP-05: Root-domain identity
                }
                // NIP-09 (deletion) and NIP-62 (request to vanish) are honoured
                // only when not running as an archival "disrespector" relay. When
                // disrespector mode is on the relay stores but ignores deletion /
                // vanish requests, so we must not advertise NIP-09 or NIP-62
                // support — clients can then discover that this relay does not
                // honour deletions.
                if !config.deletion_request_disrespector {
                    nips.push(9); // NIP-09: Event deletion requests
                    nips.push(62); // NIP-62: Request to vanish
                }
                if config.private_mode {
                    nips.push(42); // NIP-42: relay client authentication
                    nips.push(98); // NIP-98: HTTP authentication
                }
                nips.sort_unstable();
                nips
            },
            software: "https://gitworkshop.dev/danconwaydev.com/ngit-grasp".to_string(),
            version: match option_env!("GIT_COMMIT_SHORT") {
                Some(commit) => format!("{}-{}", env!("CARGO_PKG_VERSION"), commit),
                None => env!("CARGO_PKG_VERSION").to_string(),
            },
            icon: Some(format!("https://{}/icon.png", config.service_address())),
            limitation: RelayLimitation {
                max_message_length: 5 * 1024 * 1024,
                max_subscriptions: config.relay_max_subscriptions,
                max_limit: config.relay_filter_limit,
                max_subid_length: 250,
                default_limit: config.relay_filter_limit,
                restricted_writes: true,
            },

            // GRASP Extensions
            supported_grasps,
            repo_acceptance_criteria: "None".to_string(),
            curation,

            // GRASP-P private repositories
            private_repos: crate::grasp_p::nip11_private_repos_from_config(config),
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
        assert!(doc.supported_nips.contains(&5));
        assert!(doc.supported_nips.contains(&11));
        assert!(doc.supported_nips.contains(&34));
        assert!(doc.supported_nips.contains(&77));
        // NIP-09 (deletion) and NIP-62 (vanish) advertised by default
        // (disrespector off).
        assert!(doc.supported_nips.contains(&9));
        assert!(doc.supported_nips.contains(&62));
        assert_eq!(
            doc.supported_grasps,
            vec!["GRASP-01", "GRASP-02", "GRASP-03"]
        );
        assert!(doc.repo_acceptance_criteria.contains("None"));
        assert!(doc.curation.is_none());
        assert_eq!(
            doc.icon,
            Some("https://relay.example.com/icon.png".to_string())
        );
        assert_eq!(doc.limitation.max_subscriptions, 500);
        assert_eq!(doc.limitation.max_limit, 500);
        assert_eq!(doc.limitation.default_limit, 500);
        assert_eq!(doc.limitation.max_message_length, 5 * 1024 * 1024);
        assert!(doc.limitation.restricted_writes);
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
        assert_eq!(parsed["supported_grasps"][2], "GRASP-03");
        assert_eq!(parsed["icon"], "https://relay.example.com/icon.png");
        assert_eq!(parsed["limitation"]["max_subscriptions"], 500);
        assert_eq!(parsed["limitation"]["max_limit"], 500);
        assert_eq!(parsed["limitation"]["default_limit"], 500);
    }

    #[test]
    fn test_nip11_advertises_configured_sync_limits() {
        let mut config = Config::for_testing();
        config.relay_max_subscriptions = 20;
        config.relay_filter_limit = 300;

        let doc = RelayInformationDocument::from_config(&config);

        assert_eq!(doc.limitation.max_subscriptions, 20);
        assert_eq!(doc.limitation.max_limit, 300);
        assert_eq!(doc.limitation.default_limit, 300);
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
            vec!["GRASP-01", "GRASP-05", "GRASP-02", "GRASP-03"]
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
            vec!["GRASP-01", "GRASP-05", "GRASP-02", "GRASP-03"]
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
        assert_eq!(
            doc.supported_grasps,
            vec!["GRASP-01", "GRASP-02", "GRASP-03"]
        );
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
            vec!["GRASP-01", "GRASP-05", "GRASP-02", "GRASP-03"]
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
            vec!["GRASP-01", "GRASP-02", "GRASP-03", "GRASP-06"]
        );
    }

    #[test]
    fn test_nip11_omits_grasp_03_when_sync_plus_is_disabled() {
        let mut config = Config::for_testing();
        config.sync_plus_enabled = false;

        let doc = RelayInformationDocument::from_config(&config);

        assert_eq!(doc.supported_grasps, vec!["GRASP-01", "GRASP-02"]);
    }

    #[test]
    fn test_nip11_advertises_deletion_by_default() {
        let config = Config::for_testing();
        let doc = RelayInformationDocument::from_config(&config);

        // NIP-09 (deletion) and NIP-62 (vanish) are honoured (and advertised)
        // by default.
        assert!(doc.supported_nips.contains(&9));
        assert!(doc.supported_nips.contains(&62));
    }

    #[test]
    fn test_nip11_advertises_nip05_only_at_domain_root() {
        let root_config = Config::for_testing();
        let nested_config = Config {
            base_path: "/relay".to_string(),
            ..Config::for_testing()
        };

        let root_doc = RelayInformationDocument::from_config(&root_config);
        let nested_doc = RelayInformationDocument::from_config(&nested_config);

        assert!(root_doc.supported_nips.contains(&5));
        assert!(!nested_doc.supported_nips.contains(&5));
        assert_eq!(
            nested_doc.icon.as_deref(),
            Some("https://localhost:7334/relay/icon.png")
        );
    }

    #[test]
    fn test_nip11_omits_deletion_in_disrespector_mode() {
        let mut config = Config::for_testing();
        config.deletion_request_disrespector = true;

        let doc = RelayInformationDocument::from_config(&config);

        // Archival relays do not honour deletions, so NIP-09 and NIP-62 must
        // not be advertised.
        assert!(!doc.supported_nips.contains(&9));
        assert!(!doc.supported_nips.contains(&62));
        // Other NIPs are unaffected.
        assert!(doc.supported_nips.contains(&1));
        assert!(doc.supported_nips.contains(&34));
    }
}
