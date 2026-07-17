//! Test result types

use crate::specs::grasp01::{get_sections, GRASP_01_REQUIREMENTS, GRASP_COMMIT_ID};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Trait implemented by per-spec SpecRef enums so `TestResult::new` can accept
/// requirements from any GRASP spec module (grasp01, grasp06, ...).
pub trait SpecRefStr {
    fn spec_ref_string(&self) -> &'static str;
}

// ANSI color codes
const GREEN: &str = "\x1b[1;92m"; // Bold bright green - ANSI standard for high visibility
const RED: &str = "\x1b[1;91m"; // Bold bright red - ANSI standard for high visibility
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";
const GREY: &str = "\x1b[90m"; // Bright black / grey — used for skipped tests
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

/// Parse line number(s) from a spec_ref string
/// Returns a vector of line numbers that this spec_ref covers
///
/// Examples:
/// - "GRASP-01:nostr-relay:5" -> [5]
/// - "GRASP-01:nostr-relay:5-7" -> [5, 6, 7]
/// - "NIP-01:basic:2" -> []  (not a GRASP-01 ref)
fn parse_spec_lines(spec_ref: &str) -> Vec<u32> {
    // Only parse GRASP-01 refs
    if !spec_ref.starts_with("GRASP-01:") {
        return vec![];
    }

    // Get the last part after the last colon
    let parts: Vec<&str> = spec_ref.split(':').collect();
    if parts.len() < 3 {
        return vec![];
    }

    let line_part = parts.last().unwrap();

    // Handle range format like "7-9"
    if line_part.contains('-') {
        let range_parts: Vec<&str> = line_part.split('-').collect();
        if range_parts.len() == 2 {
            if let (Ok(start), Ok(end)) =
                (range_parts[0].parse::<u32>(), range_parts[1].parse::<u32>())
            {
                return (start..=end).collect();
            }
        }
        return vec![];
    }

    // Handle single line number
    if let Ok(line) = line_part.parse::<u32>() {
        return vec![line];
    }

    vec![]
}

/// Result of a single test
#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub spec_ref: String,
    pub requirement: String,
    pub passed: bool,
    /// True if the test was skipped (e.g. precondition not met).
    ///
    /// Skipped tests also have `passed = true` so they do not cause
    /// [`AuditResult::all_passed`] to fail, but they are reported separately
    /// with a grey marker so it is obvious which assertions actually ran.
    pub skipped: bool,
    /// Human-readable reason for the skip, displayed next to the test name
    /// in the report. Only meaningful when `skipped == true`.
    pub skip_reason: Option<String>,
    pub error: Option<String>,
    pub duration: Duration,
}

impl TestResult {
    /// Create a new test result
    ///
    /// # Arguments
    /// * `name` - Test name identifier
    /// * `spec_ref` - Reference to the spec requirement being tested
    ///   (any type implementing `SpecRefStr`, e.g. `grasp01::SpecRef`)
    /// * `requirement` - Human-readable description of what this test validates
    ///   (can be more specific than the general spec text)
    pub fn new<R: SpecRefStr>(name: &str, spec_ref: R, requirement: &str) -> Self {
        TestResult {
            name: name.to_string(),
            spec_ref: spec_ref.spec_ref_string().to_string(),
            requirement: requirement.to_string(),
            passed: false,
            skipped: false,
            skip_reason: None,
            error: None,
            duration: Duration::default(),
        }
    }

    /// Run a test function and capture the result
    pub async fn run<F, Fut>(mut self, test_fn: F) -> Self
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let start = Instant::now();

        match test_fn().await {
            Ok(()) => {
                self.passed = true;
            }
            Err(e) => {
                self.passed = false;
                self.error = Some(e);
            }
        }

        self.duration = start.elapsed();
        self
    }

    /// Mark test as passed
    pub fn pass(mut self) -> Self {
        self.passed = true;
        self
    }

    /// Mark test as failed with error
    pub fn fail(mut self, error: impl Into<String>) -> Self {
        self.passed = false;
        self.error = Some(error.into());
        self
    }

    /// Mark this test as skipped with a human-readable reason.
    ///
    /// Skipped tests also have `passed = true` so they don't cause
    /// [`AuditResult::all_passed`] to return false, but they are rendered
    /// distinctly (grey, with the reason) in audit reports.
    pub fn skip(mut self, reason: impl Into<String>) -> Self {
        self.skipped = true;
        self.passed = true;
        self.skip_reason = Some(reason.into());
        self.error = None;
        self
    }
}

/// Collection of test results for a spec
#[derive(Debug, Clone)]
pub struct AuditResult {
    pub spec: String,
    pub results: Vec<TestResult>,
}

impl AuditResult {
    /// Create a new audit result
    pub fn new(spec: impl Into<String>) -> Self {
        Self {
            spec: spec.into(),
            results: Vec::new(),
        }
    }

    /// Add a test result
    pub fn add(&mut self, result: TestResult) {
        self.results.push(result);
    }

    /// Merge another audit result
    pub fn merge(&mut self, other: AuditResult) {
        self.results.extend(other.results);
    }

    /// Check if all tests passed (skipped tests count as passed)
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    /// Get count of tests that ran and passed (excludes skipped)
    pub fn passed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.passed && !r.skipped)
            .count()
    }

    /// Get count of failed tests
    pub fn failed_count(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    /// Get count of skipped tests
    pub fn skipped_count(&self) -> usize {
        self.results.iter().filter(|r| r.skipped).count()
    }

    /// Get total count of tests
    pub fn total_count(&self) -> usize {
        self.results.len()
    }

    /// Print a detailed report aligned to GRASP-01 specification
    pub fn print_report(&self) {
        println!();
        println!(
            "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
            BOLD, RESET
        );
        println!("{}GRASP-01 Compliance Report{}", BOLD, RESET);
        println!(
            "Source: github.com/nostr-protocol/grasp (commit: {})",
            GRASP_COMMIT_ID
        );
        println!(
            "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
            BOLD, RESET
        );

        // Build a map of spec line -> tests that cover it
        let mut tests_by_line: BTreeMap<u32, Vec<&TestResult>> = BTreeMap::new();
        for result in &self.results {
            let lines = parse_spec_lines(&result.spec_ref);
            for line in lines {
                tests_by_line.entry(line).or_default().push(result);
            }
        }

        // Track how many spec requirements have tests
        let mut tested_requirements = 0;
        let total_requirements = GRASP_01_REQUIREMENTS.len();

        // Print results organized by section and spec line
        for section in get_sections() {
            println!();
            println!("{}{}## {}{}", CYAN, BOLD, section, RESET);

            for req in GRASP_01_REQUIREMENTS
                .iter()
                .filter(|r| r.section == section)
            {
                println!();
                // Print spec requirement in blue
                println!("{}📘 Line {}: {}{}", BLUE, req.line, req.text, RESET);

                // Get tests for this line
                if let Some(tests) = tests_by_line.get(&req.line) {
                    tested_requirements += 1;
                    for test in tests {
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
                            // Truncate long errors
                            let error_display = if error.len() > 100 {
                                format!("{}...", &error[..100])
                            } else {
                                error.clone()
                            };
                            println!("    {}Error: {}{}", RED, error_display, RESET);
                        }
                    }
                } else {
                    println!("  {}⚠️  No Tests Implemented{}", YELLOW, RESET);
                }
            }
        }

        println!();
        println!(
            "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
            BOLD, RESET
        );

        // Summary statistics
        let passed = self.passed_count();
        let failed = self.failed_count();
        let skipped = self.skipped_count();
        let total_tests = self.total_count();

        let spec_coverage = if total_requirements > 0 {
            (tested_requirements as f64 / total_requirements as f64) * 100.0
        } else {
            0.0
        };

        let pass_rate = if total_tests > 0 {
            (passed as f64 / total_tests as f64) * 100.0
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
                "{}Test results:  {}/{} tests passed ({:.1}%), {} failed, {} skipped{}",
                summary_color, passed, total_tests, pass_rate, failed, skipped, RESET
            );
        } else {
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

    /// Get a summary string
    pub fn summary(&self) -> String {
        format!(
            "{}: {}/{} passed",
            self.spec,
            self.passed_count(),
            self.total_count()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::specs::grasp01::SpecRef;

    #[tokio::test]
    async fn test_result_pass() {
        let result = TestResult::new(
            "test",
            SpecRef::NostrRelayNip01Compliant,
            "Test requirement",
        )
        .run(|| async { Ok(()) })
        .await;

        assert!(result.passed);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_result_fail() {
        let result = TestResult::new(
            "test",
            SpecRef::NostrRelayNip01Compliant,
            "Test requirement",
        )
        .run(|| async { Err("Failed".to_string()) })
        .await;

        assert!(!result.passed);
        assert_eq!(result.error, Some("Failed".to_string()));
    }

    #[test]
    fn test_audit_result() {
        let mut audit = AuditResult::new("Test Spec");

        audit.add(TestResult::new("test1", SpecRef::NostrRelayNip01Compliant, "Test 1").pass());
        audit.add(
            TestResult::new(
                "test2",
                SpecRef::NostrRelayRejectMissingCloneRelays,
                "Test 2",
            )
            .fail("Error"),
        );

        assert_eq!(audit.total_count(), 2);
        assert_eq!(audit.passed_count(), 1);
        assert_eq!(audit.failed_count(), 1);
        assert_eq!(audit.skipped_count(), 0);
        assert!(!audit.all_passed());
    }

    #[tokio::test]
    async fn test_result_skip() {
        let result = TestResult::new(
            "test_skipped",
            SpecRef::NostrRelayNip01Compliant,
            "Test requirement",
        )
        .skip("precondition not met");

        assert!(result.skipped);
        assert!(result.passed, "skipped tests must also count as passed");
        assert_eq!(result.skip_reason.as_deref(), Some("precondition not met"));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_audit_result_with_skipped() {
        let mut audit = AuditResult::new("Test Spec");

        audit.add(TestResult::new("test1", SpecRef::NostrRelayNip01Compliant, "Test 1").pass());
        audit.add(
            TestResult::new(
                "test2",
                SpecRef::NostrRelayRejectMissingCloneRelays,
                "Test 2",
            )
            .skip("precondition not met"),
        );

        assert_eq!(audit.total_count(), 2);
        assert_eq!(audit.passed_count(), 1, "skipped not counted as passed");
        assert_eq!(audit.failed_count(), 0);
        assert_eq!(audit.skipped_count(), 1);
        assert!(audit.all_passed(), "skipped tests must not fail the suite");
    }

    #[test]
    fn test_parse_spec_lines_single() {
        assert_eq!(parse_spec_lines("GRASP-01:nostr-relay:5"), vec![5]);
        assert_eq!(parse_spec_lines("GRASP-01:git-http:32"), vec![32]);
    }

    #[test]
    fn test_parse_spec_lines_range() {
        assert_eq!(parse_spec_lines("GRASP-01:nostr-relay:5-7"), vec![5, 6, 7]);
        assert_eq!(
            parse_spec_lines("GRASP-01:cors:48-51"),
            vec![48, 49, 50, 51]
        );
    }

    #[test]
    fn test_parse_spec_lines_non_grasp() {
        assert_eq!(parse_spec_lines("NIP-01:basic:1"), Vec::<u32>::new());
        assert_eq!(parse_spec_lines("OTHER:spec:5"), Vec::<u32>::new());
    }

    #[test]
    fn test_parse_spec_lines_invalid() {
        assert_eq!(parse_spec_lines("GRASP-01:invalid"), Vec::<u32>::new());
        assert_eq!(parse_spec_lines("GRASP-01:test:abc"), Vec::<u32>::new());
    }
}
