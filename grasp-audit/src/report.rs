//! Stable, serializable results for compliance audit consumers.
//!
//! These types describe completed spec and test results. They deliberately do
//! not include invocation details such as the relay URL, run timestamps, or a
//! top-level schema version; a CLI machine-output contract can wrap them later
//! without changing the audit domain model.

use crate::result::{AuditResult, TestResult};
use crate::specs::grasp01::GRASP_COMMIT_ID;
use crate::specs::grasp06::GRASP_06_COMMIT_ID;
use serde::Serialize;
use std::time::Duration;

/// Maximum UTF-8 byte length retained for failures and skip reasons.
pub const MAX_RESULT_MESSAGE_BYTES: usize = 4096;

/// Specification family exercised by an audit suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AuditSpec {
    #[serde(rename = "GRASP-01")]
    Grasp01,
    #[serde(rename = "GRASP-06")]
    Grasp06,
}

impl AuditSpec {
    /// Stable specification identifier used in machine-readable results.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Grasp01 => "GRASP-01",
            Self::Grasp06 => "GRASP-06",
        }
    }

    /// Exact upstream specification revision exercised by this build.
    pub const fn revision(self) -> &'static str {
        match self {
            Self::Grasp01 => GRASP_COMMIT_ID,
            Self::Grasp06 => GRASP_06_COMMIT_ID,
        }
    }
}

/// Stable identity and specification association of an audit suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditSuite {
    Nip01Smoke,
    Nip11Document,
    EventAcceptance,
    Cors,
    GitClone,
    GitFilter,
    PushAuthorization,
    RepositoryCreation,
    Purgatory,
    Grasp01All,
    Grasp06All,
}

impl AuditSuite {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Nip01Smoke => "nip01-smoke",
            Self::Nip11Document => "nip11-document",
            Self::EventAcceptance => "event-acceptance",
            Self::Cors => "cors",
            Self::GitClone => "git-clone",
            Self::GitFilter => "git-filter",
            Self::PushAuthorization => "push-authorization",
            Self::RepositoryCreation => "repository-creation",
            Self::Purgatory => "purgatory",
            Self::Grasp01All => "grasp01-all",
            Self::Grasp06All => "grasp06-all",
        }
    }

    pub const fn spec(self) -> AuditSpec {
        match self {
            Self::Grasp06All => AuditSpec::Grasp06,
            _ => AuditSpec::Grasp01,
        }
    }
}

/// Outcome of a completed specification suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Pass,
    Fail,
}

/// Outcome of a single audit test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestOutcome {
    Pass,
    Fail,
    Skipped,
}

/// Counts for a completed specification suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ResultCounts {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub total: usize,
}

/// Stable result of one audit test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestReport {
    /// Stable test identifier. This is not a human-readable title.
    pub id: String,
    pub spec_ref: String,
    pub requirement: String,
    pub outcome: TestOutcome,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

/// Stable result of one audit suite, including its pinned specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecReport {
    pub id: &'static str,
    pub revision: &'static str,
    pub suite: &'static str,
    pub outcome: AuditOutcome,
    pub counts: ResultCounts,
    pub tests: Vec<TestReport>,
}

impl SpecReport {
    /// Convert runtime results using the central metadata for `suite`.
    pub fn from_result(suite: AuditSuite, result: &AuditResult) -> Self {
        let counts = ResultCounts {
            passed: result.passed_count(),
            failed: result.failed_count(),
            skipped: result.skipped_count(),
            total: result.total_count(),
        };

        Self {
            id: suite.spec().id(),
            revision: suite.spec().revision(),
            suite: suite.id(),
            outcome: if result.all_passed() {
                AuditOutcome::Pass
            } else {
                AuditOutcome::Fail
            },
            counts,
            tests: result.results.iter().map(TestReport::from).collect(),
        }
    }
}

impl From<&TestResult> for TestReport {
    fn from(result: &TestResult) -> Self {
        let outcome = if result.skipped {
            TestOutcome::Skipped
        } else if result.passed {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        };

        Self {
            id: result.name.clone(),
            spec_ref: result.spec_ref.clone(),
            requirement: result.requirement.clone(),
            outcome,
            duration_ms: duration_ms(result.duration),
            failure: result.error.as_deref().map(bounded_message),
            skip_reason: result.skip_reason.as_deref().map(bounded_message),
        }
    }
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn bounded_message(value: &str) -> String {
    if value.len() <= MAX_RESULT_MESSAGE_BYTES {
        return value.to_owned();
    }

    let mut end = MAX_RESULT_MESSAGE_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::TestResult;
    use crate::specs::grasp01::{SpecRef, GRASP_COMMIT_ID};

    #[test]
    fn report_has_stable_identity_counts_and_outcomes() {
        let mut result = AuditResult::new("All GRASP-01 Tests");
        result.add(TestResult::new("passes", SpecRef::NostrRelayNip01Compliant, "passes").pass());
        result.add(
            TestResult::new("skips", SpecRef::NostrRelayNip01Compliant, "skips")
                .skip("not enabled"),
        );
        result.add(
            TestResult::new("fails", SpecRef::NostrRelayNip01Compliant, "fails").fail("broken"),
        );

        let report = SpecReport::from_result(AuditSuite::Grasp01All, &result);
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(report.id, "GRASP-01");
        assert_eq!(report.revision, GRASP_COMMIT_ID);
        assert_eq!(report.suite, "grasp01-all");
        assert_eq!(report.outcome, AuditOutcome::Fail);
        assert_eq!(report.counts.passed, 1);
        assert_eq!(report.counts.failed, 1);
        assert_eq!(report.counts.skipped, 1);
        assert_eq!(json["tests"][0]["outcome"], "pass");
        assert_eq!(json["tests"][1]["outcome"], "skipped");
        assert_eq!(json["tests"][1]["skip_reason"], "not enabled");
        assert_eq!(json["tests"][2]["outcome"], "fail");
        assert_eq!(json["tests"][2]["failure"], "broken");
    }

    #[test]
    fn messages_are_utf8_safe_and_bounded() {
        let result = TestResult::new(
            "fails",
            SpecRef::NostrRelayNip01Compliant,
            "failure is bounded",
        )
        .fail("é".repeat(MAX_RESULT_MESSAGE_BYTES));

        let report = TestReport::from(&result);
        assert!(report.failure.unwrap().len() <= MAX_RESULT_MESSAGE_BYTES);
    }

    #[test]
    fn durations_serialize_as_saturating_milliseconds() {
        let mut result = TestResult::new(
            "timed",
            SpecRef::NostrRelayNip01Compliant,
            "duration is milliseconds",
        )
        .pass();
        result.duration = Duration::from_micros(42_900);

        assert_eq!(TestReport::from(&result).duration_ms, 42);
    }
}
