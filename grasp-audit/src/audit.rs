//! Audit configuration and event tagging

use nostr_sdk::prelude::*;

/// Audit configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Unique ID for this audit run
    pub run_id: String,

    /// Mode: CI (isolated) or Production (live)
    pub mode: AuditMode,

    /// Cleanup timestamp (events can be cleaned after this)
    pub cleanup_after: Timestamp,

    /// Whether to actually create events or just query
    pub read_only: bool,
}

/// Audit mode for fixture management
///
/// Controls how test fixtures are cached and shared between tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditMode {
    /// Isolated mode - each test creates fresh fixtures
    ///
    /// Use this mode when running tests in parallel (e.g., `cargo test`)
    /// where each test needs complete isolation from other tests.
    /// Each TestContext gets its own local cache.
    Isolated,

    /// Shared mode - fixtures are cached and reused across tests
    ///
    /// Use this mode when running the CLI audit tool where tests run
    /// sequentially and build on each other's fixtures. This is more
    /// efficient as it avoids re-creating the same prerequisite events.
    /// All TestContexts share the client's cache.
    Shared,
}

impl AuditConfig {
    /// Create config for isolated testing (e.g., cargo test)
    ///
    /// Each test creates fresh fixtures for complete test isolation.
    /// Use this when running tests in parallel.
    pub fn isolated() -> Self {
        let run_id = format!("isolated-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        Self {
            run_id,
            mode: AuditMode::Isolated,
            cleanup_after: Timestamp::now() + 3600, // 1 hour from now
            read_only: false,
        }
    }

    /// Create config for shared fixture mode (default for CLI)
    ///
    /// Fixtures are cached and reused across tests. Use this when
    /// running the CLI audit tool where tests run sequentially.
    pub fn shared() -> Self {
        let run_id = format!("audit-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        Self {
            run_id,
            mode: AuditMode::Shared,
            cleanup_after: Timestamp::now() + 3600, // 1 hour from now
            read_only: false,
        }
    }

    /// Create config for probe/smoke test mode
    ///
    /// Identical to `isolated()` but uses a `probe-` prefix for the run ID,
    /// making probe events easy to distinguish from regular audit events.
    pub fn probe() -> Self {
        let run_id = format!("probe-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        Self {
            run_id,
            mode: AuditMode::Isolated,
            cleanup_after: Timestamp::now() + 3600, // 1 hour from now
            read_only: false,
        }
    }

    /// Create config with custom run ID
    pub fn with_run_id(run_id: String, mode: AuditMode) -> Self {
        Self {
            run_id,
            mode,
            cleanup_after: Timestamp::now() + 3600,
            read_only: false,
        }
    }

    /// Get audit tags that are automatically added to all events
    ///
    /// These tags are automatically added to all events created via [`AuditEventBuilder`].
    /// They provide isolation, cleanup scheduling, and easy discovery of audit events.
    ///
    /// # Tag Format
    ///
    /// All tags use the `"t"` (hashtag) format for maximum relay compatibility:
    ///
    /// 1. `["t", "grasp-audit-test-event"]` - Identifies all audit-related events
    /// 2. `["t", "audit-{run_id}"]` - Unique identifier for this audit run
    ///    - Isolated mode: `audit-isolated-{uuid}`
    ///    - Shared mode: `audit-audit-{uuid}`
    /// 3. `["t", "audit-cleanup-after-{unix_timestamp}"]` - Cleanup timestamp
    ///    - Default: Current time + 3600 seconds (1 hour)
    ///
    /// # Purpose
    ///
    /// - **Isolation**: Each test run has a unique ID for event filtering in CI mode
    /// - **Cleanup**: Events marked for cleanup after timestamp (enables direct DB cleanup)
    /// - **Discovery**: Easy to query all audit events via hashtag
    /// - **No deletion trails**: Avoids NIP-09 deletion events by using direct cleanup
    ///
    /// # Example
    ///
    /// ```rust
    /// use grasp_audit::AuditConfig;
    ///
    /// let config = AuditConfig::isolated();
    /// let tags = config.audit_tags();
    ///
    /// // Tags will look like:
    /// // [
    /// //   ["t", "grasp-audit-test-event"],
    /// //   ["t", "audit-ci-a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    /// //   ["t", "audit-cleanup-after-1730822334"]
    /// // ]
    /// ```
    pub fn audit_tags(&self) -> Vec<Tag> {
        // Use "t" tags for categorization (standard NIP-01 hashtag type)
        vec![
            Tag::custom("t", vec!["grasp-audit-test-event"]),
            Tag::custom("t", vec![format!("audit-{}", self.run_id)]),
            Tag::custom(
                "t",
                vec![format!(
                    "audit-cleanup-after-{}",
                    self.cleanup_after.as_secs()
                )],
            ),
        ]
    }
}

/// Builder for audit events
pub struct AuditEventBuilder {
    kind: Kind,
    content: String,
    tags: Vec<Tag>,
    config: AuditConfig,
    custom_timestamp: Option<Timestamp>,
}

impl AuditEventBuilder {
    /// Create a new audit event builder
    pub fn new(kind: Kind, content: impl Into<String>, config: AuditConfig) -> Self {
        Self {
            kind,
            content: content.into(),
            tags: Vec::new(),
            config,
            custom_timestamp: None,
        }
    }

    /// Add a tag
    pub fn tag(mut self, tag: Tag) -> Self {
        self.tags.push(tag);
        self
    }

    /// Add multiple tags
    pub fn tags(mut self, tags: Vec<Tag>) -> Self {
        self.tags.extend(tags);
        self
    }

    /// Set a custom timestamp for the event
    ///
    /// By default, events use the current time. Use this method to create
    /// events with a specific timestamp, which is useful for testing
    /// timestamp-based prioritization logic.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nostr_sdk::prelude::*;
    /// use grasp_audit::{AuditConfig, AuditEventBuilder};
    ///
    /// let config = AuditConfig::isolated();
    /// let keys = Keys::generate();
    ///
    /// // Create an event with a past timestamp
    /// let past_event = AuditEventBuilder::new(Kind::TextNote, "test", config)
    ///     .custom_time(Timestamp::from(1700000000))
    ///     .build(&keys)
    ///     .unwrap();
    ///
    /// assert_eq!(past_event.created_at, Timestamp::from(1700000000));
    /// ```
    pub fn custom_time(mut self, timestamp: Timestamp) -> Self {
        self.custom_timestamp = Some(timestamp);
        self
    }

    /// Build the event with audit tags
    pub fn build(self, keys: &Keys) -> anyhow::Result<Event> {
        let mut all_tags = self.tags;
        all_tags.extend(self.config.audit_tags());

        let builder = EventBuilder::new(self.kind, self.content).tags(all_tags);

        // Apply custom timestamp if set
        let builder = if let Some(timestamp) = self.custom_timestamp {
            builder.custom_created_at(timestamp)
        } else {
            builder
        };

        let event = builder.finalize(keys)?;

        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolated_config() {
        let config = AuditConfig::isolated();
        assert_eq!(config.mode, AuditMode::Isolated);
        assert!(!config.read_only);
        assert!(config.run_id.starts_with("isolated-"));
    }

    #[test]
    fn test_shared_config() {
        let config = AuditConfig::shared();
        assert_eq!(config.mode, AuditMode::Shared);
        assert!(!config.read_only);
        assert!(config.run_id.starts_with("audit-"));
    }

    #[test]
    fn test_audit_tags() {
        let config = AuditConfig::isolated();
        let tags = config.audit_tags();

        assert_eq!(tags.len(), 3);

        // All tags should be "t" tags (hashtags)
        for tag in &tags {
            assert_eq!(tag.kind(), "t", "Expected 't' (SingleLetter) tag");
        }

        // Check for "t" tag with "grasp-audit-test-event"
        assert!(tags
            .iter()
            .any(|t| { t.content() == Some("grasp-audit-test-event") }));

        // Check for "t" tag with "audit-{run_id}"
        assert!(tags.iter().any(|t| {
            t.content()
                .map(|c| c.starts_with("audit-isolated-"))
                .unwrap_or(false)
        }));

        // Check for "t" tag with "audit-cleanup-after-{timestamp}"
        assert!(tags.iter().any(|t| {
            t.content()
                .map(|c| c.starts_with("audit-cleanup-after-"))
                .unwrap_or(false)
        }));
    }

    #[test]
    fn test_audit_event_builder() {
        let config = AuditConfig::isolated();
        let keys = Keys::generate();

        let event = AuditEventBuilder::new(Kind::TextNote, "test", config.clone())
            .tag(Tag::custom("test", vec!["value"]))
            .build(&keys)
            .unwrap();

        // Should have our custom tag + 3 audit tags
        assert!(event.tags.len() >= 4);

        // Verify event is valid
        assert!(event.verify().is_ok());
    }

    #[test]
    fn test_custom_timestamp_applied() {
        let config = AuditConfig::isolated();
        let keys = Keys::generate();
        let custom_ts = Timestamp::from(1700000000);

        // Build event with custom timestamp
        let event = AuditEventBuilder::new(Kind::TextNote, "test with custom time", config.clone())
            .custom_time(custom_ts)
            .build(&keys)
            .unwrap();

        // Verify the custom timestamp was applied
        assert_eq!(event.created_at, custom_ts);

        // Verify event is still valid
        assert!(event.verify().is_ok());
    }

    #[test]
    fn test_default_timestamp_uses_current_time() {
        let config = AuditConfig::isolated();
        let keys = Keys::generate();

        let before = Timestamp::now();
        let event = AuditEventBuilder::new(Kind::TextNote, "test default time", config.clone())
            .build(&keys)
            .unwrap();
        let after = Timestamp::now();

        // Event timestamp should be between before and after (inclusive)
        assert!(event.created_at.as_secs() >= before.as_secs());
        assert!(event.created_at.as_secs() <= after.as_secs());
    }
}
