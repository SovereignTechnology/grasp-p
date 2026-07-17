//! GRASP-06 Specification Requirements
//!
//! Embedded specification requirements from the GRASP-06 spec document.
//! Spec: <https://github.com/DanConwayDev/grasp/blob/main/06.md>
//!
//! This is the single source of truth for spec text displayed in audit reports.

use crate::specs::grasp01::RequirementLevel;

/// GRASP spec repository commit ID this version is based on.
///
/// Update this when bumping to a newer spec revision so reports indicate
/// which spec line numbers are being referenced.
pub const GRASP_06_COMMIT_ID: &str = "4eeee96ffefeec8fd80a320d944f5b5e89171f0b";

/// Reference to a specific GRASP-06 specification requirement.
///
/// Each variant maps 1:1 to a single MUST/SHOULD line in `06.md`, or to an
/// audit-derived invariant that follows directly from the spec (e.g. the
/// "advertise-or-404" gate, which is implied by NIP-11 discovery semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecRef {
    /// Audit-derived: if NIP-11 does not advertise GRASP-06, the /prs/ namespace
    /// must 404 so clients can rely on NIP-11 for capability discovery.
    Grasp06NotAdvertised404,
    /// Audit-derived (implementation plan, Phase 9): when the relay is
    /// configured with GRASP-06 enabled, NIP-11 `supported_grasps` MUST
    /// include `"GRASP-06"` so clients can discover the capability.
    Grasp06AdvertisedWhenEnabled,
    /// 06.md line 11 — MUST respond to upload-pack on any well-formed path as
    /// if serving an empty bare repository.
    Grasp06FetchEmptyRepo,
    /// 06.md line 13 — MUST accept pushes to `refs/nostr/<event-id>`.
    Grasp06AcceptRefsNostrPush,
    /// 06.md line 13 — MUST reject pushes to any other ref namespace.
    Grasp06RejectNonNostrRefs,
    /// 06.md lines 19–22 — MUST accept PR/PR-Update events that would otherwise
    /// be rejected by GRASP-01, when they carry a matching `a` tag AND a `clone`
    /// tag naming this relay's /prs/ endpoint.
    Grasp06RelaxAcceptPrEvent,
    /// 06.md line 22 — the relaxation applies only when the event's `clone`
    /// tag names this relay's /prs/ endpoint; otherwise the event is rejected.
    Grasp06RelaxRequiresCloneTag,
    /// Design-doc derived (docs/explanation/grasp-06-contributor-pr-submission.md
    /// "Cross-service mirror") — refs accepted via /prs/ are mirrored into any
    /// matching accepted-announcement repos on this relay.
    Grasp06MirrorToAnnouncedRepo,
    /// Design-doc derived — the reverse direction does NOT mirror: a push to
    /// the standard `/<npub>/<id>.git` endpoint must not appear under /prs/.
    Grasp06NoReverseMirror,
    /// Design-doc push semantics (line 96): when a push arrives at /prs/ and
    /// the matching event's `c` tag does not equal the pushed commit, the ref
    /// MUST be deleted and the event MUST NOT be promoted out of purgatory.
    Grasp06CommitMismatchDeletesRef,
}

/// Synthetic "line numbers" used for the audit report grouping.
///
/// The two audit-derived requirements (`Grasp06NotAdvertised404` and
/// `Grasp06AdvertisedWhenEnabled`) follow from the spec but do not map to a
/// single spec line. They are grouped under the "NIP-11 Discovery" section
/// with negative synthetic line numbers (`-1`, `-2`) so they sort to the top
/// of the report and remain visually distinct from real spec lines.
mod synthetic_lines {
    pub const NOT_ADVERTISED_404: i32 = -1;
    pub const ADVERTISED_WHEN_ENABLED: i32 = -2;
}

impl SpecRef {
    /// Get the spec reference string in format "GRASP-06:section:line".
    ///
    /// When two requirements share a spec line (e.g. 06.md line 15 carries
    /// BOTH "MUST accept refs/nostr/<event-id>" AND "MUST reject other ref
    /// namespaces"), they MUST still produce distinct strings here — the
    /// report renderer keys tests by the full string. Use a `-<sibling>`
    /// suffix on the section token to disambiguate; [`parse_spec_line`]
    /// still recovers the integer line from the third component.
    pub fn spec_ref_string(self) -> &'static str {
        match self {
            SpecRef::Grasp06NotAdvertised404 => "GRASP-06:nip-11-discovery:-1",
            SpecRef::Grasp06AdvertisedWhenEnabled => "GRASP-06:nip-11-discovery:-2",
            SpecRef::Grasp06FetchEmptyRepo => "GRASP-06:git-http:11",
            SpecRef::Grasp06AcceptRefsNostrPush => "GRASP-06:git-http-accept:13",
            SpecRef::Grasp06RejectNonNostrRefs => "GRASP-06:git-http-reject:13",
            SpecRef::Grasp06RelaxAcceptPrEvent => "GRASP-06:event-acceptance:19",
            SpecRef::Grasp06RelaxRequiresCloneTag => "GRASP-06:event-acceptance:22",
            SpecRef::Grasp06MirrorToAnnouncedRepo => "GRASP-06:mirror-forward:design",
            SpecRef::Grasp06NoReverseMirror => "GRASP-06:mirror-reverse:design",
            SpecRef::Grasp06CommitMismatchDeletesRef => "GRASP-06:commit-mismatch:design",
        }
    }
}

impl crate::result::SpecRefStr for SpecRef {
    fn spec_ref_string(&self) -> &'static str {
        SpecRef::spec_ref_string(*self)
    }
}

/// A single GRASP-06 specification requirement.
///
/// Mirrors the GRASP-01 `SpecRequirement` shape but uses `i32` for `line`
/// so audit-derived requirements can use negative synthetic line numbers
/// without conflicting with real spec lines.
#[derive(Debug, Clone)]
pub struct SpecRequirement {
    pub spec_ref: SpecRef,
    pub line: i32,
    pub section: &'static str,
    pub text: &'static str,
    pub level: RequirementLevel,
}

/// All GRASP-06 specification requirements (and audit-derived invariants).
pub const GRASP_06_REQUIREMENTS: &[SpecRequirement] = &[
    // NIP-11 Discovery (audit-derived: bridges NIP-11 capability advertisement
    // with /prs/ endpoint availability — clients must be able to rely on NIP-11
    // alone for capability discovery).
    SpecRequirement {
        spec_ref: SpecRef::Grasp06NotAdvertised404,
        line: synthetic_lines::NOT_ADVERTISED_404,
        section: "NIP-11 Discovery",
        text: "When NIP-11 supported_grasps does NOT include 'GRASP-06', the /prs/<npub>/<id>.git namespace MUST return 404 (audit-derived from NIP-11 capability discovery semantics)",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::Grasp06AdvertisedWhenEnabled,
        line: synthetic_lines::ADVERTISED_WHEN_ENABLED,
        section: "NIP-11 Discovery",
        text: "When the relay is configured with GRASP-06 enabled, NIP-11 supported_grasps MUST include 'GRASP-06' so clients can discover the capability (implementation plan Phase 9)",
        level: RequirementLevel::Must,
    },
    // Git Smart HTTP Service
    SpecRequirement {
        spec_ref: SpecRef::Grasp06FetchEmptyRepo,
        line: 11,
        section: "Git Smart HTTP Service",
        text: "MUST respond to upload-pack requests for any well-formed path as if serving an empty bare repository until at least one `refs/nostr/<event-id>` has been accepted for that path.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::Grasp06AcceptRefsNostrPush,
        line: 13,
        section: "Git Smart HTTP Service",
        text: "MUST accept pushes to `refs/nostr/<event-id>`. MAY reject based on size, SPAM prevention, allowlists, pre-payment, PoW, or similar policy.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::Grasp06RejectNonNostrRefs,
        line: 13,
        section: "Git Smart HTTP Service",
        text: "MUST reject pushes to any other ref namespace (only `refs/nostr/<event-id>` is accepted).",
        level: RequirementLevel::Must,
    },
    // Event Acceptance
    SpecRequirement {
        spec_ref: SpecRef::Grasp06RelaxAcceptPrEvent,
        line: 19,
        section: "Event Acceptance",
        text: "MUST accept PRs and PR Updates that would otherwise be rejected under GRASP-01 for not referencing an accepted repository announcement, provided the event has an `a` tag of the form `30617:<pubkey>:<identifier>` AND a `clone` tag naming this service's /prs/<signer-npub>/<identifier>.git endpoint.",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::Grasp06RelaxRequiresCloneTag,
        line: 22,
        section: "Event Acceptance",
        text: "The relaxation applies ONLY when the event's `clone` tag names this relay's /prs/ endpoint. PR events without a matching clone tag remain subject to GRASP-01 rejection.",
        level: RequirementLevel::Must,
    },
    // Cross-service mirror (design-doc derived — not in the spec, but follows
    // from the design choice that PR refs at /prs/ become discoverable at the
    // announced repo on the same relay).
    SpecRequirement {
        spec_ref: SpecRef::Grasp06MirrorToAnnouncedRepo,
        line: 100, // synthetic — design-doc requirement, no spec line
        section: "Cross-Service Mirror",
        text: "Refs accepted via /prs/ MUST be mirrored into any matching accepted-announcement repos on this relay (design-doc: docs/explanation/grasp-06-contributor-pr-submission.md \"Cross-service mirror\").",
        level: RequirementLevel::Must,
    },
    SpecRequirement {
        spec_ref: SpecRef::Grasp06NoReverseMirror,
        line: 101, // synthetic
        section: "Cross-Service Mirror",
        text: "The reverse direction MUST NOT mirror: a push to the standard /<npub>/<id>.git endpoint must not appear under /prs/.",
        level: RequirementLevel::Must,
    },
    // Push validation (design-doc derived — line 96 of the push semantics table)
    SpecRequirement {
        spec_ref: SpecRef::Grasp06CommitMismatchDeletesRef,
        line: 102, // synthetic
        section: "Push Validation",
        text: "When a push arrives at /prs/ and the matching event's `c` tag does not equal \
               the pushed commit, the ref MUST be deleted and the event MUST NOT be promoted \
               out of purgatory (design-doc push semantics: \"commit ≠ event's c tag → delete ref\").",
        level: RequirementLevel::Must,
    },
];

/// Parse line number from a "GRASP-06:section:line" spec_ref string.
///
/// Returns `None` if the spec_ref is not a GRASP-06 ref or the line component
/// can't be parsed as an integer.
pub fn parse_spec_line(spec_ref: &str) -> Option<i32> {
    if !spec_ref.starts_with("GRASP-06:") {
        return None;
    }
    let parts: Vec<&str> = spec_ref.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    parts.last().and_then(|s| s.parse::<i32>().ok())
}

/// Get all unique section names in the order they first appear.
pub fn get_sections() -> Vec<&'static str> {
    let mut sections = Vec::new();
    for req in GRASP_06_REQUIREMENTS {
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
    fn test_spec_ref_unique() {
        let mut refs = std::collections::HashSet::new();
        for req in GRASP_06_REQUIREMENTS {
            assert!(
                refs.insert(req.spec_ref),
                "Duplicate SpecRef found: {:?}",
                req.spec_ref
            );
        }
    }

    #[test]
    fn test_parse_spec_line_real() {
        assert_eq!(parse_spec_line("GRASP-06:git-http:11"), Some(11));
        assert_eq!(parse_spec_line("GRASP-06:git-http:13"), Some(13));
    }

    #[test]
    fn test_parse_spec_line_synthetic() {
        assert_eq!(parse_spec_line("GRASP-06:nip-11-discovery:-1"), Some(-1));
    }

    #[test]
    fn test_parse_spec_line_non_grasp06() {
        assert_eq!(parse_spec_line("GRASP-01:nostr-relay:5"), None);
        assert_eq!(parse_spec_line("NIP-01:basic:1"), None);
    }

    #[test]
    fn test_sections_order() {
        let sections = get_sections();
        assert_eq!(sections[0], "NIP-11 Discovery");
        assert!(sections.contains(&"Git Smart HTTP Service"));
        assert!(sections.contains(&"Event Acceptance"));
        assert!(sections.contains(&"Cross-Service Mirror"));
        assert!(sections.contains(&"Push Validation"));
    }
}
