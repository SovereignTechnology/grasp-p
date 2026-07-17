//! GRASP-01 Specification Requirements
//!
//! Embedded specification requirements from the GRASP-01 spec document.
//! This is the single source of truth for spec text displayed in audit reports.

/// GRASP spec repository commit ID that this version is based on
pub const GRASP_COMMIT_ID: &str = "4eeee96ffefeec8fd80a320d944f5b5e89171f0b";

/// Reference to a specific GRASP-01 specification requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecRef {
    NostrRelayNip01Compliant,
    NostrRelayRejectMissingCloneRelays,
    NostrRelayMayRejectOtherCriteria,
    NostrRelayMustAcceptTaggedEvents,
    NostrRelayMayRejectSpamCuration,
    PurgatoryAcceptUntilGitData,
    Nip11ServeDocument,
    Nip11ListSupportedGrasps,
    Nip11ListRepoAcceptanceCriteria,
    Nip11ListCurationPolicy,
    GitServeRepository,
    GitAcceptPushesAlignState,
    GitSetHeadOnReceive,
    GitAcceptRefsNostrEventId,
    GitIncludeAllowSha1InWant,
    GitServeWebpage,
    CorsAllowOrigin,
    CorsAllowMethods,
    CorsAllowHeaders,
    CorsOptionsResponse,
}

/// A single specification requirement
#[derive(Debug, Clone)]
pub struct SpecRequirement {
    /// Unique reference to this requirement
    pub spec_ref: SpecRef,
    /// Line number in the spec document
    pub line: u32,
    /// Section name (e.g., "Nostr Relay", "Git Smart HTTP Service", "CORS Support")
    pub section: &'static str,
    /// The full requirement text
    pub text: &'static str,
    /// Requirement level: MUST, SHOULD, or MAY
    pub level: RequirementLevel,
}

/// Requirement level per RFC 2119
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

impl std::fmt::Display for RequirementLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequirementLevel::Must => write!(f, "MUST"),
            RequirementLevel::Should => write!(f, "SHOULD"),
            RequirementLevel::May => write!(f, "MAY"),
        }
    }
}

impl SpecRef {
    /// Get the spec reference string in format "GRASP-01:section:line"
    pub fn spec_ref_string(self) -> &'static str {
        match self {
            SpecRef::NostrRelayNip01Compliant => "GRASP-01:nostr-relay:5",
            SpecRef::NostrRelayRejectMissingCloneRelays => "GRASP-01:nostr-relay:7",
            SpecRef::NostrRelayMayRejectOtherCriteria => "GRASP-01:nostr-relay:9",
            SpecRef::NostrRelayMustAcceptTaggedEvents => "GRASP-01:nostr-relay:11",
            SpecRef::NostrRelayMayRejectSpamCuration => "GRASP-01:nostr-relay:16",
            SpecRef::PurgatoryAcceptUntilGitData => "GRASP-01:purgatory:20",
            SpecRef::Nip11ServeDocument => "GRASP-01:nip-11:24",
            SpecRef::Nip11ListSupportedGrasps => "GRASP-01:nip-11:26",
            SpecRef::Nip11ListRepoAcceptanceCriteria => "GRASP-01:nip-11:27",
            SpecRef::Nip11ListCurationPolicy => "GRASP-01:nip-11:28",
            SpecRef::GitServeRepository => "GRASP-01:git-http:32",
            SpecRef::GitAcceptPushesAlignState => "GRASP-01:git-http:34",
            SpecRef::GitSetHeadOnReceive => "GRASP-01:git-http:36",
            SpecRef::GitAcceptRefsNostrEventId => "GRASP-01:git-http:38",
            SpecRef::GitIncludeAllowSha1InWant => "GRASP-01:git-http:40",
            SpecRef::GitServeWebpage => "GRASP-01:git-http:42",
            SpecRef::CorsAllowOrigin => "GRASP-01:cors:48",
            SpecRef::CorsAllowMethods => "GRASP-01:cors:49",
            SpecRef::CorsAllowHeaders => "GRASP-01:cors:50",
            SpecRef::CorsOptionsResponse => "GRASP-01:cors:51",
        }
    }
}

impl crate::result::SpecRefStr for SpecRef {
    fn spec_ref_string(&self) -> &'static str {
        SpecRef::spec_ref_string(*self)
    }
}

/// All GRASP-01 specification requirements
pub const GRASP_01_REQUIREMENTS: &[SpecRequirement] = &[
    // Nostr Relay section
    SpecRequirement {
        spec_ref: SpecRef::NostrRelayNip01Compliant,
        line: 5,
        section: "Nostr Relay",
        text: "MUST serve a NIP-01 compliant nostr relay at `/` that accepts git repository announcements and their corresponding repo state announcements.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::NostrRelayRejectMissingCloneRelays,
        line: 7,
        section: "Nostr Relay",
        text: "MUST reject git repository announcements that do not list the service in both `clone` and `relays` tags unless implementing `GRASP-05`.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::NostrRelayMayRejectOtherCriteria,
        line: 9,
        section: "Nostr Relay",
        text: "MAY reject git repository announcements based on other criteria such as pre-payment, quotas, WoT, whitelist, SPAM prevention, etc.",
        level: RequirementLevel::May,
    },
    SpecRequirement {
        spec_ref: SpecRef::NostrRelayMustAcceptTaggedEvents,
        line: 11,
        section: "Nostr Relay",
        text: "MUST accept other events that tag, or are tagged by, either: 1. accepted git repository announcements; or 2. accepted issues or patches",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::NostrRelayMayRejectSpamCuration,
        line: 16,
        section: "Nostr Relay",
        text: "MAY reject or delete events for generic SPAM prevention reasons or curation eg. WoT, whitelist, user bans and banned topics.",
        level: RequirementLevel::May,
    },
    SpecRequirement {
        spec_ref: SpecRef::PurgatoryAcceptUntilGitData,
        line: 20,
        section: "Purgatory",
        text: "Accepted repo state announcements, PRs and PR Updates SHOULD be accepted with message \"purgatory: won't be served until git data arrives\" and kept in purgatory (not served) until the related git data arrives and otherwise discarded after 30 minutes.",
        level: RequirementLevel::Should,
    },
    SpecRequirement {
        spec_ref: SpecRef::Nip11ServeDocument,
        line: 24,
        section: "NIP-11",
        text: "MUST serve a NIP-11 document",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::Nip11ListSupportedGrasps,
        line: 26,
        section: "NIP-11",
        text: "MUST list each supported GRASP under `supported_grasps` in format `GRASP-XX` eg `GRASP-01` as a string array",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::Nip11ListRepoAcceptanceCriteria,
        line: 27,
        section: "NIP-11",
        text: "MUST list repository acceptance criteria under `repo_acceptance_criteria` as a human readable string",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::Nip11ListCurationPolicy,
        line: 28,
        section: "NIP-11",
        text: "MUST list brief summary of curation policy under `curation` if events are curated beyond generic SPAM prevention; otherwise `curation` MUST be omitted",
        level: RequirementLevel::Must,
    },
    // Git Smart HTTP Service section
    SpecRequirement {
        spec_ref: SpecRef::GitServeRepository,
        line: 32,
        section: "Git Smart HTTP Service",
        text: "MUST serve a git repository via an unauthenticated git smart http service at `/<npub>/<percent-encoded-identifier>.git` for each accepted git repository announcement.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::GitAcceptPushesAlignState,
        line: 34,
        section: "Git Smart HTTP Service",
        text: "MUST accept pushes via this service that match the latest repo state announcement on the relay, respecting the recursive maintainer set.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::GitSetHeadOnReceive,
        line: 36,
        section: "Git Smart HTTP Service",
        text: "MUST set repository HEAD per repo state announcement as soon as the git data related to that branch has been received.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::GitAcceptRefsNostrEventId,
        line: 38,
        section: "Git Smart HTTP Service",
        text: "MUST accept pushes via this service to `refs/nostr/<event-id>` but SHOULD reject if event exists on relay listing a different tip and MAY reject based on criteria such as size, SPAM prevention, etc. SHOULD delete and MAY garbage collect these refs if no corresponding git PR event or git PR update event, with a `c` tag that matches the ref tip, is accepted by relay within 20 minutes.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::GitIncludeAllowSha1InWant,
        line: 40,
        section: "Git Smart HTTP Service",
        text: "MUST include `allow-reachable-sha1-in-want`, `allow-tip-sha1-in-want`, and `uploadpack.allowFilter` in advertisement and serve available oids and filtered requests.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::GitServeWebpage,
        line: 42,
        section: "Git Smart HTTP Service",
        text: "SHOULD serve a webpage at the same endpoint linking to git nostr client(s) to browse the repository and a 404 page for repositories it doesn't host.",
        level: RequirementLevel::Should,
    },
    // CORS Support section
    SpecRequirement {
        spec_ref: SpecRef::CorsAllowOrigin,
        line: 48,
        section: "CORS Support",
        text: "Set `Access-Control-Allow-Origin: *` on ALL responses",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::CorsAllowMethods,
        line: 49,
        section: "CORS Support",
        text: "Set `Access-Control-Allow-Methods: GET, POST` on ALL responses",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::CorsAllowHeaders,
        line: 50,
        section: "CORS Support",
        text: "Set `Access-Control-Allow-Headers: Content-Type` on ALL responses",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::CorsOptionsResponse,
        line: 51,
        section: "CORS Support",
        text: "Respond to OPTIONS requests with 204 No Content",
        level: RequirementLevel::Must,
    },
];

/// Get a requirement by line number
pub fn get_requirement(line: u32) -> Option<&'static SpecRequirement> {
    GRASP_01_REQUIREMENTS.iter().find(|r| r.line == line)
}

/// Get a requirement by its SpecRef
pub fn get_requirement_by_ref(spec_ref: SpecRef) -> Option<&'static SpecRequirement> {
    GRASP_01_REQUIREMENTS
        .iter()
        .find(|r| r.spec_ref == spec_ref)
}

/// Get all requirements for a section
pub fn get_requirements_for_section(section: &str) -> Vec<&'static SpecRequirement> {
    GRASP_01_REQUIREMENTS
        .iter()
        .filter(|r| r.section == section)
        .collect()
}

/// Get all unique section names in order
pub fn get_sections() -> Vec<&'static str> {
    let mut sections = Vec::new();
    for req in GRASP_01_REQUIREMENTS {
        if !sections.contains(&req.section) {
            sections.push(req.section);
        }
    }
    sections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_requirement() {
        let req = get_requirement(5).expect("Line 5 should exist");
        assert_eq!(req.section, "Nostr Relay");
        assert!(req.text.contains("NIP-01"));
    }

    #[test]
    fn test_get_requirement_by_ref() {
        let req = get_requirement_by_ref(SpecRef::NostrRelayNip01Compliant)
            .expect("SpecRef should exist");
        assert_eq!(req.line, 5);
        assert_eq!(req.spec_ref, SpecRef::NostrRelayNip01Compliant);
    }

    #[test]
    fn test_get_sections() {
        let sections = get_sections();
        assert_eq!(sections.len(), 5);
        assert_eq!(sections[0], "Nostr Relay");
        assert_eq!(sections[1], "Purgatory");
        assert_eq!(sections[2], "NIP-11");
        assert_eq!(sections[3], "Git Smart HTTP Service");
        assert_eq!(sections[4], "CORS Support");
    }

    #[test]
    fn test_requirement_count() {
        assert_eq!(GRASP_01_REQUIREMENTS.len(), 20);
    }

    #[test]
    fn test_spec_ref_unique() {
        let mut refs = std::collections::HashSet::new();
        for req in GRASP_01_REQUIREMENTS {
            assert!(
                refs.insert(req.spec_ref),
                "Duplicate SpecRef found: {:?}",
                req.spec_ref
            );
        }
    }
}
