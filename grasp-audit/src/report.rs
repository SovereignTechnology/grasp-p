//! Stable, serializable results for compliance audit consumers.
//!
//! [`SpecReport`] and [`TestReport`] describe completed audit results, while
//! [`AuditReport`] adds the versioned run metadata used by the CLI's machine
//! output contract.

use crate::result::{AuditResult, TestResult};
use crate::specs::grasp01::GRASP_COMMIT_ID;
use crate::specs::grasp06::GRASP_06_COMMIT_ID;
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Version of the full-audit JSON document emitted by the CLI.
pub const AUDIT_REPORT_SCHEMA_VERSION: u16 = 1;

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

/// Outcome of a full audit invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRunOutcome {
    Pass,
    Fail,
    Error,
}

/// Identity of the tool that produced a full audit report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub version: &'static str,
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

/// Stable machine-readable envelope for one full audit CLI invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditReport {
    pub schema_version: u16,
    pub tool: ToolInfo,
    pub relay_url: String,
    pub run_id: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub duration_ms: u64,
    pub outcome: AuditRunOutcome,
    pub specs: Vec<SpecReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuditReport {
    /// Build a report for an audit that reached test execution.
    pub fn completed(
        relay_url: impl Into<String>,
        run_id: impl Into<String>,
        started_at: u64,
        duration: Duration,
        specs: Vec<SpecReport>,
    ) -> Self {
        let outcome = if specs.iter().all(|spec| spec.outcome == AuditOutcome::Pass) {
            AuditRunOutcome::Pass
        } else {
            AuditRunOutcome::Fail
        };

        Self {
            schema_version: AUDIT_REPORT_SCHEMA_VERSION,
            tool: tool_info(),
            relay_url: relay_url.into(),
            run_id: run_id.into(),
            started_at,
            finished_at: unix_timestamp(),
            duration_ms: duration_ms(duration),
            outcome,
            specs,
            error: None,
        }
    }

    /// Build a report for a parse, setup, or runtime error.
    pub fn error(
        relay_url: impl Into<String>,
        run_id: impl Into<String>,
        started_at: u64,
        duration: Duration,
        error: impl AsRef<str>,
    ) -> Self {
        Self {
            schema_version: AUDIT_REPORT_SCHEMA_VERSION,
            tool: tool_info(),
            relay_url: relay_url.into(),
            run_id: run_id.into(),
            started_at,
            finished_at: unix_timestamp(),
            duration_ms: duration_ms(duration),
            outcome: AuditRunOutcome::Error,
            specs: Vec::new(),
            error: Some(bounded_message(error.as_ref())),
        }
    }
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

/// Current Unix timestamp in seconds.
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn tool_info() -> ToolInfo {
    ToolInfo {
        name: "grasp-audit",
        version: env!("CARGO_PKG_VERSION"),
    }
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

    #[test]
    fn audit_report_wraps_stable_spec_reports() {
        let mut passing = AuditResult::new("passing");
        passing.add(TestResult::new("passes", SpecRef::NostrRelayNip01Compliant, "passes").pass());
        let mut failing = AuditResult::new("failing");
        failing.add(
            TestResult::new("fails", SpecRef::NostrRelayNip01Compliant, "fails").fail("broken"),
        );

        let report = AuditReport::completed(
            "wss://relay.example",
            "audit-1",
            1,
            Duration::from_millis(42),
            vec![
                SpecReport::from_result(AuditSuite::Grasp01All, &passing),
                SpecReport::from_result(AuditSuite::Grasp06All, &failing),
            ],
        );
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json["schema_version"], AUDIT_REPORT_SCHEMA_VERSION);
        assert_eq!(json["tool"]["name"], "grasp-audit");
        assert_eq!(json["relay_url"], "wss://relay.example");
        assert_eq!(json["run_id"], "audit-1");
        assert_eq!(json["duration_ms"], 42);
        assert_eq!(json["outcome"], "fail");
        assert_eq!(json["specs"][0]["suite"], "grasp01-all");
        assert_eq!(json["specs"][1]["suite"], "grasp06-all");
        assert!(json.get("error").is_none());
    }

    #[test]
    fn audit_error_reports_are_bounded_and_have_no_specs() {
        let report = AuditReport::error(
            "wss://relay.example",
            "audit-1",
            1,
            Duration::ZERO,
            "é".repeat(MAX_RESULT_MESSAGE_BYTES),
        );

        assert_eq!(report.outcome, AuditRunOutcome::Error);
        assert!(report.specs.is_empty());
        assert!(report.error.unwrap().len() <= MAX_RESULT_MESSAGE_BYTES);
    }
}
