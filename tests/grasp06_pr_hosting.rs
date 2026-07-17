//! GRASP-06 contributor PR hosting integration tests
//!
//! Spec: <https://github.com/DanConwayDev/grasp/blob/main/06.md>
//!
//! Each test is driven by one of two macros depending on whether the relay
//! under test has GRASP-06 enabled:
//!
//! - [`isolated_test_no_grasp_06!`] — relay started with the default config
//!   (GRASP-06 disabled). Tests assert the "off" contract: NIP-11 must not
//!   advertise GRASP-06, and `/prs/*` must 404.
//! - [`isolated_test_with_grasp_06!`] — relay started with
//!   `NGIT_GRASP06_ENABLE=true`. Tests assert the "on" contract.
//!
//! ## TDD
//!
//! These tests are written before the implementation. They are expected to
//! pass against the current (no-GRASP-06) relay because the discovery-gate
//! contract is satisfied trivially when neither NIP-11 advertisement nor
//! `/prs/` routing exists. They become regression guards once the feature
//! lands — if a future change enables `/prs/` without updating NIP-11
//! (or vice versa), these tests will catch it.
//!
//! ## Running
//!
//! ```bash
//! cargo test --test grasp06_pr_hosting
//! cargo test --test grasp06_pr_hosting -- --nocapture
//! ```

mod common;

use common::TestRelay;
use grasp_audit::*;

/// Generate an integration test that runs against a fresh relay started with
/// the default config (GRASP-06 disabled).
macro_rules! isolated_test_no_grasp_06 {
    ($test_name:ident, $spec_suite:ident :: $test_fn:ident) => {
        #[tokio::test]
        async fn $test_name() {
            let relay = TestRelay::start().await;
            let config = AuditConfig::isolated();
            let client = AuditClient::new(relay.url(), config)
                .await
                .expect("Failed to create audit client");

            let result = specs::$spec_suite::$test_fn(&client).await;

            relay.stop().await;

            assert!(
                result.passed,
                "{} failed: {}",
                stringify!($test_name),
                result.error.as_deref().unwrap_or("unknown error")
            );
        }
    };
}

/// Generate an integration test that runs against a fresh relay started with
/// `NGIT_GRASP06_ENABLE=true`.
macro_rules! isolated_test_with_grasp_06 {
    ($test_name:ident, $spec_suite:ident :: $test_fn:ident) => {
        #[tokio::test]
        async fn $test_name() {
            let relay = TestRelay::start_with_grasp_06_enabled().await;
            let config = AuditConfig::isolated();
            let client = AuditClient::new(relay.url(), config)
                .await
                .expect("Failed to create audit client");

            let result = specs::$spec_suite::$test_fn(&client).await;

            relay.stop().await;

            assert!(
                result.passed,
                "{} failed: {}",
                stringify!($test_name),
                result.error.as_deref().unwrap_or("unknown error")
            );
        }
    };
}

// =============================================================================
// Test 1: Discovery gate — /prs/ MUST 404 when GRASP-06 is not advertised
// =============================================================================
//
// Spec: GRASP-06 06.md (audit-derived from NIP-11 capability semantics)
//
// Contract: if NIP-11 does NOT list "GRASP-06" in supported_grasps, the
// /prs/<npub>/<id>.git namespace MUST return 404. This lets clients rely on
// NIP-11 alone for capability discovery.
//
// Wired only as `no_grasp_06`: the test asserts the "off" contract. The
// matching "on" contract (NIP-11 advertises when feature is enabled) is a
// distinct invariant and lives in its own test below.

isolated_test_no_grasp_06!(
    test_prs_namespace_404_when_grasp06_not_advertised_no_grasp_06,
    PrsEndpointTests::test_prs_namespace_404_when_grasp06_not_advertised
);

// =============================================================================
// Test 2: NIP-11 MUST advertise GRASP-06 when the feature is enabled
// =============================================================================
//
// Spec: implementation plan Phase 9 (positive companion to test 1)
//
// Contract: a relay started with NGIT_GRASP06_ENABLE=true MUST include
// "GRASP-06" in its NIP-11 supported_grasps array. Without this, the
// capability is invisible to clients and /prs/ is effectively unreachable.
//
// Wired only as `with_grasp_06`. Pre-implementation this test FAILS (TDD
// red) — the relay binary ignores the env var and NIP-11 doesn't advertise.
// Once Phase 9 lands the test turns green and becomes the regression guard.

isolated_test_with_grasp_06!(
    test_nip11_advertises_grasp_06_when_enabled,
    Nip11Tests::test_nip11_advertises_grasp_06_when_enabled
);

// =============================================================================
// Test 3: Empty-bare-repo fetch for any well-formed /prs/<npub>/<id>.git
// =============================================================================
//
// Spec: GRASP-06 06.md line 11
//
// Contract: when GRASP-06 is enabled on the relay, a fetch against any
// well-formed /prs/<npub>/<id>.git path that has no accepted
// refs/nostr/<event-id> MUST respond as if serving an empty bare repository.
// In practice: `git clone` must succeed and the resulting working copy must
// have zero refs.
//
// Wired only as `with_grasp_06`. The test asserts the invariant
// unconditionally — gating on NIP-11 advertisement is a caller concern, not
// part of the spec assertion. Pre-implementation this FAILS (TDD red): the
// relay has no `/prs/` route, so the clone gets 404. Once the feature lands
// and the empty-repo synthesis is implemented, this turns green.

isolated_test_with_grasp_06!(
    test_prs_fetch_unknown_path_serves_empty_repo_with_grasp_06,
    PrsEndpointTests::test_prs_fetch_unknown_path_serves_empty_repo
);

// =============================================================================
// Test 4: /prs/ MUST accept pushes to refs/nostr/<event-id>
// =============================================================================
//
// Spec: GRASP-06 06.md line 13
//
// Contract: a `git push` of refs/nostr/<event-id> to /prs/<npub>/<id>.git
// MUST succeed, even when there is no prior state on the path and no matching
// PR/PR-Update event in the relay's DB. (Whether the ref later gets GC'd by
// the spec's 20-minute SHOULD is out of scope here — only the push acceptance
// contract is asserted.)
//
// Wired only as `with_grasp_06`. Pre-implementation this FAILS — the relay
// has no /prs/ receive-pack handler, so the push gets 404. Once Phase 3+4
// land (routing + receive handler) it goes green.

isolated_test_with_grasp_06!(
    test_prs_push_refs_nostr_event_id_accepted_with_grasp_06,
    PrsEndpointTests::test_prs_push_refs_nostr_event_id_accepted
);

// =============================================================================
// Test 5: /prs/ MUST reject pushes to anything else
// =============================================================================
//
// Spec: GRASP-06 06.md line 13
//
// Contract: pushes to ref names that don't match refs/nostr/<64-hex-event-id>
// MUST be rejected. Two sub-assertions inside one test:
//   - refs/heads/main             (wrong top-level namespace)
//   - refs/nostr/<not-a-valid-id> (right prefix, wrong event-id shape)
//
// Wired only as `with_grasp_06`. Pre-implementation this also FAILS as a 404,
// but the test stays meaningful once /prs/ exists: it catches a regression
// where the receive handler exists but the ref-name validator is missing or
// over-permissive.

isolated_test_with_grasp_06!(
    test_prs_push_other_refs_rejected_with_grasp_06,
    PrsEndpointTests::test_prs_push_other_refs_rejected
);

// =============================================================================
// Test 6: PR for un-announced coord MUST be accepted when clone tag names /prs/
// =============================================================================
//
// Spec: GRASP-06 06.md lines 19–22
//
// Contract: a PR event (kind 1618) for a coord this relay has NO accepted
// announcement for MUST be accepted (purgatory or served) when the event
// carries:
//   - an `a` tag of the form `30617:<pubkey>:<identifier>`, AND
//   - a `clone` tag naming this relay's /prs/<signer-npub>/<identifier>.git
//     endpoint.
//
// Wired only as `with_grasp_06`. Pre-implementation this FAILS (TDD red) —
// the relay's GRASP-01 PR policy rejects PR events without a matching
// accepted announcement, and the relaxation branch (Phase 6) is not yet
// implemented. Once that branch lands and the relaxation correctly fires
// for matching `clone` tags, this turns green.

isolated_test_with_grasp_06!(
    test_pr_event_accepted_when_clone_tag_names_prs_endpoint_with_grasp_06,
    EventAcceptanceTests::test_pr_event_accepted_when_clone_tag_names_prs_endpoint
);

// =============================================================================
// Test 6b: Relaxation-accepted PR MUST stay in purgatory until git data arrives
// =============================================================================
//
// Spec: GRASP-06 06.md lines 19–22, in combination with GRASP-01 line 20
// (the purgatory rule).
//
// Contract: a PR event accepted under the GRASP-06 relaxation (un-announced
// coord, clone tag names this relay's /prs/ endpoint) MUST be held in
// purgatory and MUST NOT be broadcast until the matching `refs/nostr/<id>`
// push arrives. The acceptance message must be `OK true "purgatory: ..."`,
// not `OK true` for an immediately served event.
//
// Why a separate test from 6: test 6 only asserts the relay returned OK,
// discarding the served-vs-purgatory bit. A future regression that
// short-circuited the relaxation to `WritePolicyResult::Accept` would still
// pass test 6 but quietly leak orphan PR events without their git data.
// This test guards that boundary.
//
// Wired only as `with_grasp_06`. Once the relaxation is in place this is
// green and stays green as long as the relaxation routes through purgatory.

isolated_test_with_grasp_06!(
    test_pr_event_accepted_via_relaxation_is_held_in_purgatory_with_grasp_06,
    EventAcceptanceTests::test_pr_event_accepted_via_relaxation_is_held_in_purgatory
);

// =============================================================================
// Test 7: Relaxation MUST NOT apply when clone tag does not name this relay
// =============================================================================
//
// Spec: GRASP-06 06.md line 22
//
// Contract: the same un-announced-coord PR event, but with a `clone` tag
// pointing at a foreign host, MUST remain rejected. The relaxation is gated
// on the `clone` tag naming this specific relay's /prs/ endpoint — without
// that check, every GRASP-06 relay would accept every matching PR event,
// fanning out abuse across the network.
//
// Wired only as `with_grasp_06`. Today this test PASSES trivially —
// GRASP-01's PR policy already rejects PR events without a matching
// accepted announcement, regardless of clone-tag content. Once Phase 6's
// relaxation branch lands the test stays green: the relaxation must check
// the clone tag's host and decline to fire when it doesn't match. If a
// future change accidentally widens the relaxation, this test will catch
// it.
//
// In the audit CLI report this test is reported as Skipped when GRASP-06
// isn't advertised: a rejection there can only mean GRASP-01 rejected, not
// that the GRASP-06 host-check is wired correctly. Only meaningful with
// the feature enabled.

isolated_test_with_grasp_06!(
    test_pr_event_rejected_when_clone_tag_does_not_name_prs_endpoint_with_grasp_06,
    EventAcceptanceTests::test_pr_event_rejected_when_clone_tag_does_not_name_prs_endpoint
);

// =============================================================================
// Test 8: /prs/ push MUST be mirrored into the announced repo
// =============================================================================
//
// Spec: design-doc "Cross-service mirror" — refs accepted via /prs/<...>/<id>.git
// MUST be mirrored into any accepted-announcement repos on this relay whose
// coord appears in the PR event's `a` tag. The mirror is what makes a
// contributor PR submitted via /prs/ visible at the maintainer's URL.
//
// Wired only as `with_grasp_06`. Pre-implementation this FAILS — the /prs/
// push gets 404 so there's nothing to mirror. Once Phases 4 + 7 land
// (receive-pack + mirror hook), the test goes green.

isolated_test_with_grasp_06!(
    test_prs_push_mirrors_to_announced_repo_with_grasp_06,
    MirroringTests::test_prs_push_mirrors_to_announced_repo
);

// =============================================================================
// Test 8b: git-first ordering — PR event arriving after a matching /prs/ push
//          MUST be promoted from purgatory and mirrored
// =============================================================================
//
// Spec: design doc `docs/explanation/grasp-06-contributor-pr-submission.md`
//       "Git-first" flow (lines 204–218).
//
// Contract: in the reverse ordering of test 8 (push first, event second),
// the mirror contract still holds. When the PR event arrives matching a
// scoped placeholder created by an earlier `/prs/` push, the relay MUST
// promote the event out of purgatory (save to DB, broadcast) AND fire the
// cross-service mirror into matching announced repos. Test 8 alone does
// not cover this: the event-first path triggers promotion via
// `process_newly_available_git_data` on push, while git-first relies on the
// PR-event policy doing the same work on event arrival.
//
// Wired only as `with_grasp_06`. Today this fails: the policy in
// `src/nostr/policy/pr_event.rs::git_data_check` matches the scoped
// placeholder but then falls through to `find_relevant_repo_paths` which
// returns empty for un-announced coords; the function returns `Ok(false)`
// and the builder re-purgatorises the event without mirroring. Once that
// gap is closed, the test goes green and stays green as the regression
// guard for git-first promotion.

isolated_test_with_grasp_06!(
    test_prs_push_then_pr_event_promotes_and_mirrors_with_grasp_06,
    MirroringTests::test_prs_push_then_pr_event_promotes_and_mirrors
);

// =============================================================================
// Test 9: Standard endpoint push MUST NOT mirror into /prs/
// =============================================================================
//
// Spec: design-doc "Cross-service mirror", reverse direction. /prs/ is a
// contributor-submission side-channel; it must never carry refs that the
// maintainer pushed to their own standard `<npub>/<id>.git` endpoint.
//
// Reuses the existing PREvent2Served fixture — that fixture already drives
// the full standard-endpoint PR cycle (event published, refs/nostr/<id>
// pushed via `<owner>/<repo-id>.git`, event served). All this test does on
// top of that is `git ls-remote` the contributor's /prs/ URL with a
// refname filter and assert empty.
//
// Wired only as `with_grasp_06`. Pre-implementation this can't make its
// assertion (the /prs/ endpoint 404s) and reports a setup failure with a
// pointer to the 06.md line 11 endpoint-reachability requirement. Once
// /prs/ becomes reachable, the test goes green and stays green as long as
// no one adds a reverse-mirror branch.

isolated_test_with_grasp_06!(
    test_standard_push_does_not_mirror_to_prs_with_grasp_06,
    MirroringTests::test_standard_push_does_not_mirror_to_prs
);

// =============================================================================
// Test 10: commit mismatch MUST delete the ref and MUST NOT promote the event
// =============================================================================
//
// Spec: design-doc push semantics table, line 96:
//   "commit ≠ event's c tag → delete ref"
//
// Contract: when a push arrives at /prs/<npub>/<id>.git with a commit that
// does NOT match the `c` tag of the matching PR event, the relay MUST:
//   1. Delete the ref (refs/nostr/<event-id> must be absent afterwards).
//   2. NOT promote the event out of purgatory.
//
// This is the correctness invariant that makes refs/nostr/<event-id>
// self-verifying: the ref name is the event-id, the event's `c` tag pins
// the commit, and the relay enforces the binding. Without this check an
// attacker could substitute arbitrary commits under a foreign event-id.
//
// Wired only as `with_grasp_06`. Pre-implementation this fails in one of
// two ways: if the /prs/ endpoint doesn't exist the push fails and the
// ls-remote check trivially passes (but the test surfaces a setup error);
// if the endpoint exists but the mismatch check is missing, the ref
// survives and the test fails. Once the mismatch branch is implemented
// correctly, the test goes green and stays green as the regression guard.

isolated_test_with_grasp_06!(
    test_commit_mismatch_deletes_ref_and_blocks_promotion_with_grasp_06,
    PushValidationTests::test_commit_mismatch_deletes_ref_and_blocks_promotion
);
