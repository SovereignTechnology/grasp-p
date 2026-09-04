//! GRASP-06 NIP-11 advertisement tests
//!
//! Spec: <https://gitworkshop.dev/danconwaydev.com/grasp/tree/master/06.md>
//!
//! These tests cover the discovery-gate contract from the "on" side: when
//! the relay opts into GRASP-06, its NIP-11 document MUST advertise the
//! capability so clients can find it.
//!
//! The complementary "off" side (no advertisement => /prs/ MUST 404) lives
//! in [`super::prs_endpoint`].

use crate::specs::grasp06::fixtures::advertises_grasp;
use crate::specs::grasp06::SpecRef;
use crate::{AuditClient, TestContext, TestResult};

pub struct Nip11Tests;

impl Nip11Tests {
    /// Test: when GRASP-06 is enabled on the relay, NIP-11 MUST advertise it.
    ///
    /// Implementation plan, Phase 9: a relay running with `NGIT_GRASP06_ENABLE=true`
    /// MUST include `"GRASP-06"` in its NIP-11 `supported_grasps` array.
    /// Without this, clients have no way to discover the capability — the
    /// `/prs/` endpoint exists but is invisible.
    ///
    /// This is the positive companion to
    /// [`super::prs_endpoint::PrsEndpointTests::test_prs_namespace_404_when_grasp06_not_advertised`]:
    /// together they assert that NIP-11 advertisement and `/prs/` availability
    /// must move in lockstep.
    ///
    /// Note: this test is only meaningful when run against a relay that has
    /// the feature enabled. It is therefore wired only into the
    /// `isolated_test_with_grasp_06!` harness. Pre-implementation it WILL
    /// fail (TDD red); once Phase 9 lands it becomes the regression guard.
    pub async fn test_nip11_advertises_grasp_06_when_enabled(client: &AuditClient) -> TestResult {
        TestResult::new(
            super::test_ids::NIP11_ADVERTISED_WHEN_ENABLED,
            SpecRef::Grasp06AdvertisedWhenEnabled,
            "NIP-11 supported_grasps MUST include 'GRASP-06' when feature is enabled",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            let advertised = advertises_grasp(&ctx, "GRASP-06")
                .await
                .map_err(|e| format!("Failed to inspect NIP-11 supported_grasps: {}", e))?;

            if !advertised {
                return Err("NIP-11 supported_grasps does not include 'GRASP-06' \
                     even though the relay was started with the feature enabled"
                    .to_string());
            }

            Ok(())
        })
        .await
    }
}
