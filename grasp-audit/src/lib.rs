//! GRASP Audit Tool
//!
//! A reusable compliance and audit testing tool for GRASP protocol implementations.
//!
//! # Features
//!
//! - **Isolated Testing**: Tests run in parallel with unique audit IDs
//! - **Production Audit**: Test live services with minimal impact
//! - **Clean Audit Events**: Special tags for easy cleanup without deletion trails
//! - **Spec-Mirrored Tests**: Test structure matches GRASP protocol exactly
//!
//! # Usage
//!
//! ```no_run
//! use grasp_audit::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create audit client with shared fixtures (default for CLI)
//!     let config = AuditConfig::shared();
//!     let client = AuditClient::new("ws://localhost:7000", config).await?;
//!
//!     // Run smoke tests
//!     let results = specs::Nip01SmokeTests::run_all(&client).await;
//!     results.print_report();
//!
//!     Ok(())
//! }
//! ```

pub mod audit;
pub mod client;
pub mod fixtures;
pub mod git;
pub mod isolation;
pub mod probe;
pub mod report;
pub mod result;
pub mod specs;

pub use audit::{AuditConfig, AuditEventBuilder, AuditMode};
pub use client::AuditClient;
pub use fixtures::{
    // Git operation helpers
    clone_repo,
    create_commit,
    create_deterministic_commit,
    create_deterministic_commit_with_variant,
    init_local_repo,
    // Verification helpers
    send_and_verify_accepted,
    send_and_verify_rejected,
    try_push,
    try_push_to_ref,
    // Types and constants
    CommitVariant,
    ContextMode,
    Fixture,
    FixtureKind,
    TestContext,
    TypedFixtureCache,
    DETERMINISTIC_COMMIT_HASH,
    MAINTAINER_DETERMINISTIC_COMMIT_HASH,
    PR_TEST_COMMIT_HASH,
    RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH,
};
pub use git::{git_command, GRASP_AUDIT_NSEC_ENV};
pub use probe::{run_probe, ProbeCheck, ProbeCheckName, ProbeReport};
pub use report::{
    AuditOutcome, AuditSpec, AuditSuite, ResultCounts, SpecReport, TestOutcome, TestReport,
};
pub use result::{AuditResult, TestResult};

// Re-export commonly used types
pub use anyhow::{anyhow, Result};
pub use nostr_sdk::prelude::*;
