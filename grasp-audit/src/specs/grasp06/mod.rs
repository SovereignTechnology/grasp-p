//! GRASP-06 specification tests
//!
//! Spec: <https://github.com/DanConwayDev/grasp/blob/main/06.md>
//!
//! ## Test Suites
//!
//! - [`PrsEndpointTests`] - `/prs/<npub>/<id>.git` endpoint behaviour
//!   (discovery gate, empty-repo fetch, push acceptance/rejection)
//! - [`Nip11Tests`] - NIP-11 advertisement of GRASP-06 capability
//! - [`EventAcceptanceTests`] - PR/PR-Update event-acceptance relaxation
//!   (06.md lines 19–22)
//! - [`MirroringTests`] - cross-service mirror: `/prs/` → announced repo
//!   (forward), and announced repo ↛ `/prs/` (reverse must not fire).
//!   Design-doc derived.
//!
//! ## Shared fixtures
//!
//! [`fixtures`] holds non-Event prerequisites shared across the suite
//! (currently the NIP-11 document). New checks needing the doc should reuse
//! [`fixtures::advertises_grasp`] rather than re-fetching.
//!
//! ## Suite-level orchestration: [`Grasp06Tests`]
//!
//! Use [`Grasp06Tests::run_all`] to run the full GRASP-06 suite. It
//! transparently handles the NIP-11 discovery gate:
//!
//! - The "off-contract" discovery gate test always runs.
//! - If NIP-11 advertises `GRASP-06`, the "on-contract" tests run normally.
//! - If NIP-11 does not advertise it (or the NIP-11 fetch fails), the
//!   on-contract tests are emitted as **skipped** results — visible in the
//!   audit report in grey, with a reason — so the suite never accidentally
//!   reports a red failure for a feature the relay never claimed to support.
//!
//! [`Grasp06Tests::print_report`] renders the GRASP-06-specific report block.
//! The CLI prints it separately from the GRASP-01 block (when running
//! `--spec all`), so each spec family gets its own header and section walk.

pub mod event_acceptance;
pub mod fixtures;
pub mod mirroring;
pub mod nip11;
pub mod prs_endpoint;
pub mod spec_requirements;

pub use event_acceptance::EventAcceptanceTests;
pub use mirroring::MirroringTests;
pub use nip11::Nip11Tests;
pub use prs_endpoint::{PrsEndpointTests, PushValidationTests};
pub use spec_requirements::{SpecRef, GRASP_06_COMMIT_ID};

use crate::{AuditClient, AuditResult, TestContext, TestResult};
use spec_requirements::{get_sections, GRASP_06_REQUIREMENTS};
use std::collections::BTreeMap;

/// Stable GRASP-06 test identifiers shared by executable tests and the
/// placeholders emitted when the capability is not advertised.
pub(crate) mod test_ids {
    pub const NAMESPACE_404_WHEN_NOT_ADVERTISED: &str =
        "prs_namespace_404_when_grasp06_not_advertised";
    pub const NIP11_ADVERTISED_WHEN_ENABLED: &str = "nip11_advertises_grasp_06_when_enabled";
    pub const FETCH_UNKNOWN_PATH: &str = "prs_fetch_unknown_path_serves_empty_repo";
    pub const PUSH_NOSTR_REF: &str = "prs_push_refs_nostr_event_id_accepted";
    pub const REJECT_OTHER_REFS: &str = "prs_push_other_refs_rejected";
    pub const ACCEPT_EVENT_FOR_PRS_ENDPOINT: &str =
        "pr_event_accepted_when_clone_tag_names_prs_endpoint";
    pub const HOLD_RELAXED_EVENT_IN_PURGATORY: &str =
        "pr_event_accepted_via_relaxation_is_held_in_purgatory";
    pub const REJECT_EVENT_FOR_OTHER_ENDPOINT: &str =
        "pr_event_rejected_when_clone_tag_does_not_name_prs_endpoint";
    pub const MIRROR_PRS_PUSH: &str = "prs_push_mirrors_to_announced_repo";
    pub const PROMOTE_AND_MIRROR_GIT_FIRST: &str = "prs_push_then_pr_event_promotes_and_mirrors";
    pub const NO_REVERSE_MIRROR: &str = "standard_push_does_not_mirror_to_prs";
    pub const DELETE_COMMIT_MISMATCH: &str = "commit_mismatch_deletes_ref_and_blocks_promotion";
}

// ANSI colour codes — duplicated locally (same constants as result.rs) rather
// than re-exported, to keep the renderer self-contained.
const GREEN: &str = "\x1b[1;92m";
const RED: &str = "\x1b[1;91m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";
const GREY: &str = "\x1b[90m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

/// Aggregator for the GRASP-06 audit test suite.
///
/// See [module docs](self) for the gating model.
pub struct Grasp06Tests;

impl Grasp06Tests {
    /// Run the full GRASP-06 audit suite against `client`.
    ///
    /// Always runs the NIP-11 discovery-gate test. Branches once on the
    /// relay's NIP-11 `supported_grasps` field:
    ///
    /// - If `GRASP-06` is advertised → runs the on-contract tests.
    /// - If not (or NIP-11 fetch fails) → emits skipped placeholders for the
    ///   on-contract tests so the report still shows what wasn't run.
    pub async fn run_all(client: &AuditClient) -> AuditResult {
        let mut results = AuditResult::new("GRASP-06 Compliance Tests");

        // (1) Discovery gate — always runs. Trivially passes when GRASP-06
        //     IS advertised (precondition not met); enforces /prs/ -> 404
        //     when it isn't.
        results.add(
            PrsEndpointTests::test_prs_namespace_404_when_grasp06_not_advertised(client).await,
        );

        // (2) Branch once. NIP-11 fetch failures are treated conservatively
        //     as "not advertised": we cannot confirm the feature is enabled.
        let ctx = TestContext::new(client);
        let advertised = fixtures::advertises_grasp(&ctx, "GRASP-06")
            .await
            .unwrap_or(false);

        if advertised {
            // (3a) On-contract tests run with real assertions.
            results.add(Nip11Tests::test_nip11_advertises_grasp_06_when_enabled(client).await);
            results
                .add(PrsEndpointTests::test_prs_fetch_unknown_path_serves_empty_repo(client).await);
            results.add(PrsEndpointTests::test_prs_push_refs_nostr_event_id_accepted(client).await);
            results.add(PrsEndpointTests::test_prs_push_other_refs_rejected(client).await);
            results.add(
                EventAcceptanceTests::test_pr_event_accepted_when_clone_tag_names_prs_endpoint(
                    client,
                )
                .await,
            );
            results.add(
                EventAcceptanceTests::test_pr_event_accepted_via_relaxation_is_held_in_purgatory(
                    client,
                )
                .await,
            );
            results.add(
                EventAcceptanceTests::test_pr_event_rejected_when_clone_tag_does_not_name_prs_endpoint(
                    client,
                )
                .await,
            );
            // Cross-service mirror — design-doc derived contract. Forward
            // direction (test 7) verifies /prs/ → announced repo. Reverse
            // direction (test 8) verifies the inverse must NOT mirror.
            results.add(MirroringTests::test_prs_push_mirrors_to_announced_repo(client).await);
            results.add(
                MirroringTests::test_prs_push_then_pr_event_promotes_and_mirrors(client).await,
            );
            results.add(MirroringTests::test_standard_push_does_not_mirror_to_prs(client).await);
            results.add(
                PushValidationTests::test_commit_mismatch_deletes_ref_and_blocks_promotion(client)
                    .await,
            );
        } else {
            // (3b) Visible skipped stubs — same SpecRef and requirement text
            //      as the real tests, so they show up in the report under the
            //      same spec lines but rendered grey with a reason.
            let reason = "GRASP-06 not advertised in NIP-11";
            results.add(
                TestResult::new(
                    test_ids::NIP11_ADVERTISED_WHEN_ENABLED,
                    SpecRef::Grasp06AdvertisedWhenEnabled,
                    "NIP-11 supported_grasps MUST include 'GRASP-06' when feature is enabled",
                )
                .skip(reason),
            );
            results.add(
                TestResult::new(
                    test_ids::FETCH_UNKNOWN_PATH,
                    SpecRef::Grasp06FetchEmptyRepo,
                    "MUST serve empty bare repo on fetch for any well-formed /prs/ path \
                     until refs/nostr/<event-id> has been accepted",
                )
                .skip(reason),
            );
            results.add(
                TestResult::new(
                    test_ids::PUSH_NOSTR_REF,
                    SpecRef::Grasp06AcceptRefsNostrPush,
                    "MUST accept pushes to refs/nostr/<event-id> on /prs/<npub>/<id>.git",
                )
                .skip(reason),
            );
            results.add(
                TestResult::new(
                    test_ids::REJECT_OTHER_REFS,
                    SpecRef::Grasp06RejectNonNostrRefs,
                    "MUST reject pushes to anything other than refs/nostr/<64-hex-event-id> \
                     on /prs/<npub>/<id>.git",
                )
                .skip(reason),
            );
            // Event-acceptance tests are also skipped when GRASP-06 isn't
            // advertised. The "accept" side (test 5) is obvious: the
            // relaxation cannot fire without the feature. The "reject" side
            // (test 6) is subtler — a rejection would happen today via the
            // baseline GRASP-01 PR policy, so the test would pass trivially
            // and tell us nothing about the GRASP-06 host-check invariant.
            // Reporting it as skipped keeps the audit honest about what is
            // and isn't being verified.
            results.add(
                TestResult::new(
                    test_ids::ACCEPT_EVENT_FOR_PRS_ENDPOINT,
                    SpecRef::Grasp06RelaxAcceptPrEvent,
                    "MUST accept PR event for un-announced coord when its clone tag names \
                     this relay's /prs/<signer-npub>/<identifier>.git endpoint",
                )
                .skip(reason),
            );
            results.add(
                TestResult::new(
                    test_ids::HOLD_RELAXED_EVENT_IN_PURGATORY,
                    SpecRef::Grasp06RelaxAcceptPrEvent,
                    "PR event accepted under the GRASP-06 relaxation MUST be held in purgatory \
                     until matching git data arrives",
                )
                .skip(reason),
            );
            results.add(
                TestResult::new(
                    test_ids::REJECT_EVENT_FOR_OTHER_ENDPOINT,
                    SpecRef::Grasp06RelaxRequiresCloneTag,
                    "MUST NOT relax PR acceptance when the event's clone tag does not name \
                     this relay's /prs/<signer-npub>/<identifier>.git endpoint",
                )
                .skip(reason),
            );
            // Mirror tests are also skipped when GRASP-06 isn't advertised.
            // The forward direction (test 7) cannot fire without the
            // feature. The reverse direction (test 8) would pass trivially
            // — a non-existent /prs/ ENDPOINT is necessarily an absent
            // mirror — but that says nothing about whether the
            // implementation correctly DECLINES to mirror in reverse once
            // /prs/ exists. Skipping keeps the report honest.
            results.add(
                TestResult::new(
                    test_ids::MIRROR_PRS_PUSH,
                    SpecRef::Grasp06MirrorToAnnouncedRepo,
                    "refs accepted via /prs/ MUST be mirrored into any matching \
                     accepted-announcement repos on this relay",
                )
                .skip(reason),
            );
            results.add(
                TestResult::new(
                    test_ids::PROMOTE_AND_MIRROR_GIT_FIRST,
                    SpecRef::Grasp06MirrorToAnnouncedRepo,
                    "git-first ordering: when a /prs/ push arrives before the PR event, the \
                     event MUST still be promoted out of purgatory on arrival and the mirror \
                     MUST still fire",
                )
                .skip(reason),
            );
            results.add(
                TestResult::new(
                    test_ids::NO_REVERSE_MIRROR,
                    SpecRef::Grasp06NoReverseMirror,
                    "the reverse direction MUST NOT mirror: a push to /<npub>/<id>.git must \
                     not appear under /prs/",
                )
                .skip(reason),
            );
            results.add(
                TestResult::new(
                    test_ids::DELETE_COMMIT_MISMATCH,
                    SpecRef::Grasp06CommitMismatchDeletesRef,
                    "when the pushed commit does not match the PR event's `c` tag, the ref \
                     MUST be deleted and the event MUST NOT be promoted out of purgatory",
                )
                .skip(reason),
            );
        }

        results
    }

    /// Print the GRASP-06 audit report block for `results`.
    ///
    /// Walks the [`GRASP_06_REQUIREMENTS`] table, groups tests by spec line,
    /// and renders each section. Skipped tests are shown in grey with their
    /// reason; passes in green; failures in red.
    ///
    /// Use this instead of [`AuditResult::print_report`] when the results
    /// come from [`Self::run_all`] — the default `print_report` is
    /// GRASP-01-specific and would not display GRASP-06 sections.
    pub fn print_report(results: &AuditResult) {
        println!();
        println!(
            "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
            BOLD, RESET
        );
        println!("{}GRASP-06 Compliance Report{}", BOLD, RESET);
        println!(
            "Source: github.com/DanConwayDev/grasp/blob/main/06.md (commit: {})",
            GRASP_06_COMMIT_ID
        );
        println!(
            "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
            BOLD, RESET
        );

        // Group tests by their full spec_ref string, not just by line.
        //
        // Two GRASP-06 requirements can legitimately share a spec line — for
        // example 06.md line 13 carries both "MUST accept refs/nostr/<event-id>"
        // and "MUST reject other ref namespaces". Grouping by line would
        // duplicate tests under every same-line requirement, which is
        // misleading. Grouping by the full spec_ref string matches each test
        // 1:1 against its declared requirement; same-line siblings get
        // disambiguated via the section component (see
        // [`SpecRef::spec_ref_string`]).
        //
        // "Is this a GRASP-06 ref?" is just a prefix check — we don't need
        // [`parse_spec_line`] to succeed, since some legitimate refs (mirror
        // requirements) use synthetic non-numeric "line" tokens like
        // `"design"`.
        let mut tests_by_ref: BTreeMap<&str, Vec<&TestResult>> = BTreeMap::new();
        let mut unknown_refs: Vec<&TestResult> = Vec::new();
        for r in &results.results {
            if r.spec_ref.starts_with("GRASP-06:") {
                tests_by_ref.entry(r.spec_ref.as_str()).or_default().push(r);
            } else {
                unknown_refs.push(r);
            }
        }

        let mut tested_requirements = 0usize;
        let total_requirements = GRASP_06_REQUIREMENTS.len();

        for section in get_sections() {
            println!();
            println!("{}{}## {}{}", CYAN, BOLD, section, RESET);

            for req in GRASP_06_REQUIREMENTS
                .iter()
                .filter(|r| r.section == section)
            {
                println!();
                println!("{}📘 {}{}", BLUE, req.text, RESET);

                if let Some(tests) = tests_by_ref.get(req.spec_ref.spec_ref_string()) {
                    tested_requirements += 1;
                    for test in tests {
                        render_test(test);
                    }
                } else {
                    println!("  {}⚠️  No Tests Implemented{}", YELLOW, RESET);
                }
            }
        }

        // Surface any tests whose spec_ref didn't match a known GRASP-06 line
        // — usually a programming error in a new test.
        if !unknown_refs.is_empty() {
            println!();
            println!(
                "{}{}## Uncategorised Tests (spec_ref not in GRASP_06_REQUIREMENTS){}",
                CYAN, BOLD, RESET
            );
            for t in unknown_refs {
                render_test(t);
            }
        }

        println!();
        println!(
            "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
            BOLD, RESET
        );

        let passed = results.passed_count();
        let failed = results.failed_count();
        let skipped = results.skipped_count();
        let total_tests = results.total_count();

        let spec_coverage = if total_requirements > 0 {
            (tested_requirements as f64 / total_requirements as f64) * 100.0
        } else {
            0.0
        };

        let summary_color = if failed == 0 && tested_requirements == total_requirements {
            GREEN
        } else if failed == 0 {
            YELLOW
        } else {
            RED
        };

        println!(
            "{}Spec coverage: {}/{} requirements tested ({:.1}%){}",
            summary_color, tested_requirements, total_requirements, spec_coverage, RESET
        );
        if skipped > 0 {
            println!(
                "{}Test results:  {} passed, {} failed, {} skipped (of {} total){}",
                summary_color, passed, failed, skipped, total_tests, RESET
            );
        } else {
            let pass_rate = if total_tests > 0 {
                (passed as f64 / total_tests as f64) * 100.0
            } else {
                0.0
            };
            println!(
                "{}Test results:  {}/{} tests passed ({:.1}%){}",
                summary_color, passed, total_tests, pass_rate, RESET
            );
        }
        println!(
            "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
            BOLD, RESET
        );
        println!();
    }
}

fn render_test(test: &TestResult) {
    let (color, status) = if test.skipped {
        (GREY, "⏭")
    } else if test.passed {
        (GREEN, "✓")
    } else {
        (RED, "✗")
    };
    if test.skipped {
        let reason = test.skip_reason.as_deref().unwrap_or("skipped");
        println!(
            "  {}{} {} (skip: {}){}",
            color, status, test.name, reason, RESET
        );
    } else {
        println!("  {}{} {}{}", color, status, test.name, RESET);
    }
    if let Some(error) = &test.error {
        let truncated = if error.len() > 100 {
            format!("{}...", &error[..100])
        } else {
            error.clone()
        };
        println!("    {}Error: {}{}", RED, truncated, RESET);
    }
}
