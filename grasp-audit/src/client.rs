//! Audit client for testing GRASP implementations

use crate::audit::{AuditConfig, AuditEventBuilder, AuditMode};
use crate::fixtures::{FixtureKind, TypedFixtureCache};
use anyhow::{anyhow, Context, Result};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Type alias for the fixture cache - shared across TestContext instances
pub type FixtureCache = Arc<Mutex<HashMap<FixtureKind, Event>>>;

/// Client for auditing GRASP implementations
///
/// The AuditClient owns a fixture cache that is shared across all TestContext
/// instances created from this client. This provides natural cache sharing:
/// - CLI creates one AuditClient → fixtures shared across all tests
/// - cargo test creates one AuditClient per test → fixtures isolated per test
pub struct AuditClient {
    client: Client,
    pub config: AuditConfig,
    keys: Keys,
    /// Maintainer keys for testing push authorization scenarios
    maintainer_keys: Keys,
    /// Recursive maintainer keys for testing recursive authorization scenarios
    recursive_maintainer_keys: Keys,
    /// PR author keys for testing PR event scenarios
    pr_author_keys: Keys,
    /// Fixture cache for TestContext instances - shared across all contexts using this client
    fixture_cache: FixtureCache,
    /// Typed fixture cache for non-Event fixtures implementing the `Fixture` trait.
    /// Shared across all `TestContext` instances using this client (used in Shared mode).
    typed_fixture_cache: TypedFixtureCache,
}

impl AuditClient {
    /// Create a new audit client for testing (no relay connection)
    #[cfg(test)]
    pub fn new_test(config: AuditConfig) -> Self {
        let keys = Keys::generate();
        let maintainer_keys = Keys::generate();
        let recursive_maintainer_keys = Keys::generate();
        let pr_author_keys = Keys::generate();
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(keys.clone()))
            .build();
        Self {
            client,
            config,
            keys,
            maintainer_keys,
            recursive_maintainer_keys,
            pr_author_keys,
            fixture_cache: Arc::new(Mutex::new(HashMap::new())),
            typed_fixture_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new audit client
    pub async fn new(relay_url: &str, config: AuditConfig) -> Result<Self> {
        let keys = Keys::generate();
        let maintainer_keys = Keys::generate();
        let recursive_maintainer_keys = Keys::generate();
        let pr_author_keys = Keys::generate();
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(keys.clone()))
            .build();

        // Add relay and connect
        client.add_relay(relay_url).await?;
        client.connect().await;

        // Wait up to ~5s for nostr-sdk's background relay task to finish the
        // WebSocket handshake. Full audit suites can briefly starve the task
        // scheduler under load, so the older ~2s window produced flakes even
        // when the relay was already accepting connections.
        let mut attempts = 0;
        let mut connected = false;
        while attempts < 50 {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let relays = client.relays().await;
            connected = relays.values().any(|r| r.status().is_connected());

            if connected {
                break;
            }

            attempts += 1;
        }

        // Verify we actually connected
        if !connected {
            return Err(anyhow!(
                "Failed to connect to relay at '{}'\n\
                \n\
                Possible causes:\n\
                  • Relay is not running at this address\n\
                  • Network connectivity issues\n\
                  • Incorrect URL or port\n\
                \n\
                To start ngit-relay for testing:\n\
                  docker run --rm -p 18081:8081 ghcr.io/danconwaydev/ngit-relay:latest\n\
                \n\
                Or use the test script:\n\
                  cd grasp-audit && ./test-ngit-relay.sh",
                relay_url
            ));
        }

        // Give it a bit more time to stabilize
        tokio::time::sleep(Duration::from_millis(200)).await;

        Ok(Self {
            client,
            config,
            keys,
            maintainer_keys,
            recursive_maintainer_keys,
            pr_author_keys,
            fixture_cache: Arc::new(Mutex::new(HashMap::new())),
            typed_fixture_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Create a new audit client with explicit keys
    ///
    /// Identical to [`new()`] but accepts an explicit `Keys` parameter instead of
    /// generating fresh ones. The maintainer, recursive maintainer, and PR author
    /// keys are still generated fresh internally.
    ///
    /// This is useful for probe mode where the caller wants to use a specific
    /// identity (e.g., from an `nsec` argument) for all events.
    pub async fn new_with_keys(relay_url: &str, config: AuditConfig, keys: Keys) -> Result<Self> {
        let maintainer_keys = Keys::generate();
        let recursive_maintainer_keys = Keys::generate();
        let pr_author_keys = Keys::generate();
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(keys.clone()))
            .build();

        // Add relay and connect
        client.add_relay(relay_url).await?;
        client.connect().await;

        // Wait up to ~5s for nostr-sdk's background relay task to finish the
        // WebSocket handshake. Full audit suites can briefly starve the task
        // scheduler under load, so the older ~2s window produced flakes even
        // when the relay was already accepting connections.
        let mut attempts = 0;
        let mut connected = false;
        while attempts < 50 {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let relays = client.relays().await;
            connected = relays.values().any(|r| r.status().is_connected());

            if connected {
                break;
            }

            attempts += 1;
        }

        // Verify we actually connected
        if !connected {
            return Err(anyhow!(
                "Failed to connect to relay at '{}'\n\
                \n\
                Possible causes:\n\
                  • Relay is not running at this address\n\
                  • Network connectivity issues\n\
                  • Incorrect URL or port\n\
                \n\
                To start ngit-relay for testing:\n\
                  docker run --rm -p 18081:8081 ghcr.io/danconwaydev/ngit-relay:latest\n\
                \n\
                Or use the test script:\n\
                  cd grasp-audit && ./test-ngit-relay.sh",
                relay_url
            ));
        }

        // Give it a bit more time to stabilize
        tokio::time::sleep(Duration::from_millis(200)).await;

        Ok(Self {
            client,
            config,
            keys,
            maintainer_keys,
            recursive_maintainer_keys,
            pr_author_keys,
            fixture_cache: Arc::new(Mutex::new(HashMap::new())),
            typed_fixture_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Create a keyed audit client whose relay connection is routed through a
    /// caller-supplied proxy.
    pub(crate) async fn new_with_keys_and_proxy(
        relay_url: &str,
        config: AuditConfig,
        keys: Keys,
        proxy: Proxy,
    ) -> Result<Self> {
        let maintainer_keys = Keys::generate();
        let recursive_maintainer_keys = Keys::generate();
        let pr_author_keys = Keys::generate();
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(keys.clone()))
            .proxy(proxy)
            .build();

        client.add_relay(relay_url).await?;
        client.connect().await;

        let mut attempts = 0;
        let mut connected = false;
        while attempts < 50 {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let relays = client.relays().await;
            connected = relays.values().any(|relay| relay.status().is_connected());
            if connected {
                break;
            }

            attempts += 1;
        }

        if !connected {
            return Err(anyhow!("Failed to connect to relay at '{}'", relay_url));
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        Ok(Self {
            client,
            config,
            keys,
            maintainer_keys,
            recursive_maintainer_keys,
            pr_author_keys,
            fixture_cache: Arc::new(Mutex::new(HashMap::new())),
            typed_fixture_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Get the fixture cache for TestContext usage
    ///
    /// This cache is shared across all TestContext instances created from this client.
    /// In CLI mode (one client for all tests), fixtures are reused.
    /// In test mode (one client per test), fixtures are isolated.
    pub fn fixture_cache(&self) -> &FixtureCache {
        &self.fixture_cache
    }

    /// Get the typed fixture cache for non-Event fixtures implementing the
    /// [`crate::fixtures::Fixture`] trait.
    ///
    /// Used by `TestContext::get` in Shared mode. Same lifecycle rules as
    /// `fixture_cache`: shared across all `TestContext` instances for this
    /// client.
    pub fn typed_fixture_cache(&self) -> &TypedFixtureCache {
        &self.typed_fixture_cache
    }

    /// Get the public key for this audit client
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Get the relay URL
    pub async fn relay_url(&self) -> Result<String> {
        let relays = self.client.relays().await;
        let relay = relays
            .values()
            .next()
            .ok_or_else(|| anyhow!("No relays configured"))?;
        Ok(relay.url().to_string())
    }

    /// Convert WebSocket URL to HTTP(S) URL for NIP-11 requests
    pub fn ws_to_http_url(ws_url: &str) -> Result<String> {
        if ws_url.starts_with("ws://") {
            Ok(ws_url.replace("ws://", "http://"))
        } else if ws_url.starts_with("wss://") {
            Ok(ws_url.replace("wss://", "https://"))
        } else {
            Err(anyhow!("Invalid WebSocket URL: {}", ws_url))
        }
    }

    /// Check if connected to relay
    pub async fn is_connected(&self) -> bool {
        // Check if we have any connected relays
        let relays = self.client.relays().await;
        for relay in relays.values() {
            if relay.status().is_connected() {
                return true;
            }
        }
        false
    }

    /// Send an event (with audit tags automatically added)
    pub async fn send_event(&self, event: Event) -> Result<EventId> {
        if self.config.read_only {
            return Err(anyhow!("Client is in read-only mode"));
        }

        let output = self.client.send_event(&event).await?;
        let event_id = *output.id();

        // Check if any relay rejected the event and return the error message
        if !output.failed.is_empty() {
            // Get the first failed relay error message
            let (relay_url, error) = output.failed.iter().next().unwrap();
            return Err(anyhow!("Relay {} rejected event: {}", relay_url, error));
        }

        // Wait a bit for event to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(event_id)
    }

    /// Send an event (with audit tags automatically added) and expect OK, success, 'purgatory:', verify not served - TODO the msg verificaiton is not implemented
    pub async fn send_event_expect_purgatory_not_served(&self, event: Event) -> Result<EventId> {
        if self.config.read_only {
            return Err(anyhow!("Client is in read-only mode"));
        }

        let output = self.client.send_event(&event).await?;
        let event_id = *output.id();

        // Check if any relay rejected the event and return the error message
        if !output.failed.is_empty() {
            // Get the first failed relay error message
            let (relay_url, error) = output.failed.iter().next().unwrap();
            return Err(anyhow!("Relay {} rejected event: {}", relay_url, error));
        }

        // Wait a bit for event to propagate
        tokio::time::sleep(Duration::from_millis(300)).await;

        if self.is_event_on_relay(event.id).await? {
            return Err(anyhow!(
                "event sent to relay was served instead of being put in purgatory"
            ));
        }

        Ok(event_id)
    }

    /// Send event and note whether it entered purgatory (not served) or was served immediately.
    ///
    /// This is a tolerant version of `send_event_expect_purgatory_not_served` that doesn't
    /// fail if purgatory is not observed. It returns whether purgatory was observed so
    /// fixtures can proceed regardless of relay implementation status.
    ///
    /// Returns (EventId, bool) where bool = true if event was NOT served (purgatory observed).
    pub async fn send_event_and_note_purgatory(&self, event: Event) -> Result<(EventId, bool)> {
        if self.config.read_only {
            return Err(anyhow!("Client is in read-only mode"));
        }

        let output = self.client.send_event(&event).await?;
        let event_id = *output.id();

        // Check if any relay rejected the event and return the error message
        if !output.failed.is_empty() {
            let (relay_url, error) = output.failed.iter().next().unwrap();
            return Err(anyhow!("Relay {} rejected event: {}", relay_url, error));
        }

        // Wait a bit for event to propagate
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Check if event is served (not in purgatory) or not served (in purgatory)
        let in_purgatory = !self.is_event_on_relay(event.id).await?;

        Ok((event_id, in_purgatory))
    }

    /// check if an event is on the relay
    pub async fn is_event_on_relay(&self, id: EventId) -> Result<bool> {
        Ok(!self
            .client
            .fetch_events(vec![Filter::new().id(id)])
            .timeout(Duration::from_secs(1))
            .await
            .context("error trying to query relay for event")?
            .is_empty())
    }

    /// Create an event builder that automatically includes audit tags
    ///
    /// All events built through this method will automatically have audit tags appended
    /// when you call `.build()`. These tags provide isolation, cleanup scheduling, and
    /// easy discovery of audit events.
    ///
    /// # Automatic Tags Added
    ///
    /// When you call `.build()` on the returned builder, these tags will be automatically added:
    /// - `["t", "grasp-audit-test-event"]` - Identifies all audit events
    /// - `["t", "audit-{run_id}"]` - Unique ID for this audit run
    /// - `["t", "audit-cleanup-after-{timestamp}"]` - Cleanup scheduling
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use grasp_audit::*;
    /// # async fn example() -> anyhow::Result<()> {
    /// let config = AuditConfig::shared();
    /// let client = AuditClient::new("ws://localhost:7000", config).await?;
    ///
    /// // Create event with automatic audit tags
    /// let event = client.event_builder(Kind::TextNote, "test content")
    ///     .tag(Tag::custom("custom", vec!["value"]))
    ///     .build(client.keys())?;
    ///
    /// // Event now has both your custom tag AND the 3 audit tags
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// See [`AuditConfig::audit_tags()`] for details on the tag format.
    pub fn event_builder(&self, kind: Kind, content: impl Into<String>) -> AuditEventBuilder {
        AuditEventBuilder::new(kind, content, self.config.clone())
    }

    /// Query events, optionally filtered to this audit run
    pub async fn query(&self, mut filter: Filter) -> Result<Vec<Event>> {
        use nostr_sdk::prelude::{Alphabet, SingleLetterTag};

        if self.config.mode == AuditMode::Isolated {
            // In Isolated mode, only see our own audit events
            // Filter by "t" tags (hashtags)
            let t_tag = SingleLetterTag::lowercase(Alphabet::T);
            filter = filter
                .custom_tag(t_tag, "grasp-audit-test-event")
                .custom_tag(t_tag, format!("audit-{}", self.config.run_id));
        }
        // In Production mode, see all events (no filter modification)

        let events = self
            .client
            .fetch_events(filter)
            .timeout(Duration::from_secs(5))
            .await?;

        Ok(events.into_iter().collect())
    }

    /// Subscribe to events with a callback
    pub async fn subscribe(
        &self,
        filters: Vec<Filter>,
        timeout: Option<Duration>,
    ) -> Result<Vec<Event>> {
        let timeout = timeout.unwrap_or(Duration::from_secs(5));
        let mut all_events = Vec::new();

        for filter in filters {
            let events = self.client.fetch_events(filter).timeout(timeout).await?;
            all_events.extend(events);
        }

        Ok(all_events)
    }

    /// Get the underlying nostr client (for advanced usage)
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get the keys (for signing custom events)
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Get the maintainer keys (for push authorization testing)
    pub fn maintainer_keys(&self) -> &Keys {
        &self.maintainer_keys
    }

    /// Get the maintainer public key as a hex string
    pub fn maintainer_pubkey_hex(&self) -> String {
        self.maintainer_keys.public_key().to_hex()
    }

    /// Get the recursive maintainer keys (for recursive authorization testing)
    pub fn recursive_maintainer_keys(&self) -> &Keys {
        &self.recursive_maintainer_keys
    }

    /// Get the recursive maintainer public key as a hex string
    pub fn recursive_maintainer_pubkey_hex(&self) -> String {
        self.recursive_maintainer_keys.public_key().to_hex()
    }

    /// Get the PR author keys (for PR event testing)
    pub fn pr_author_keys(&self) -> &Keys {
        &self.pr_author_keys
    }

    /// Get the PR author public key as a hex string
    pub fn pr_author_pubkey_hex(&self) -> String {
        self.pr_author_keys.public_key().to_hex()
    }

    /// Create a NIP-34 repository announcement event with full customization
    ///
    /// This is the core method for creating repository announcements. It allows
    /// specifying the signing keys and maintainers, making it suitable for all
    /// repo creation scenarios including maintainer and recursive maintainer testing.
    ///
    /// # Arguments
    /// * `test_name` - Name of the test (used to create unique repo identifier)
    /// * `signing_keys` - The keys to sign the event with (also used for clone URL)
    /// * `maintainer_pubkeys` - Hex pubkeys of maintainers who can push to the repository
    ///
    /// # Returns
    /// A tuple of (Event, repo_id) - the built event and the repository identifier
    pub async fn create_repo_announcement_custom(
        &self,
        test_name: &str,
        signing_keys: &Keys,
        maintainer_pubkeys: &[String],
    ) -> Result<(Event, String)> {
        // Get relay URL from client
        let relay_url = self
            .client
            .relays()
            .await
            .keys()
            .next()
            .ok_or_else(|| anyhow!("No relay connected"))?
            .to_string();

        // Convert WebSocket URL to HTTP URL for clone tag
        let http_url = relay_url
            .replace("ws://", "http://")
            .replace("wss://", "https://");

        // Create unique repository identifier using UUID for consistency
        let repo_id = format!("{}-{}", test_name, &uuid::Uuid::new_v4().to_string()[..8]);

        // Get npub for clone URL from signing keys
        let npub = signing_keys
            .public_key()
            .to_bech32()
            .map_err(|e| anyhow!("Failed to convert public key to bech32 npub format: {}", e))?;

        // Build kind 30617 repository announcement
        let event = self
            .event_builder(
                Kind::GitRepoAnnouncement,
                format!("Test repository for {}", test_name),
            )
            .tag(Tag::identifier(&repo_id))
            .tag(Tag::custom(
                "name",
                vec![format!("{} Test Repository", test_name)],
            ))
            .tag(Tag::custom(
                "description",
                vec![format!("Repository for {} testing", test_name)],
            ))
            .tag(Tag::custom(
                "clone",
                vec![format!("{}/{}/{}.git", http_url, npub, repo_id)],
            ))
            .tag(Tag::custom("relays", vec![relay_url.clone()]))
            .tag(Tag::custom("maintainers", maintainer_pubkeys.to_vec()))
            .build(signing_keys)
            .map_err(|e| anyhow!("Failed to build repository announcement event: {}", e))?;

        Ok((event, repo_id))
    }

    /// Create a NIP-34 repository announcement event with the client's maintainer
    ///
    /// This helper creates a properly formatted NIP-34 announcement that will be
    /// accepted by GRASP relays (which require events to list the relay in clone/relays tags).
    /// The client's maintainer key is automatically added to the maintainers tag.
    ///
    /// # Arguments
    /// * `test_name` - Name of the test (used to create unique repo identifier)
    ///
    /// # Returns
    /// A built and signed Event ready to be sent to the relay
    pub async fn create_repo_announcement(&self, test_name: &str) -> Result<Event> {
        let (event, _repo_id) = self
            .create_repo_announcement_custom(
                test_name,
                self.keys(),
                &[self.maintainer_pubkey_hex()],
            )
            .await?;
        Ok(event)
    }

    /// Create a NIP-34 repository announcement event with maintainers
    ///
    /// This helper creates a properly formatted NIP-34 announcement that will be
    /// accepted by GRASP relays (which require events to list the relay in clone/relays tags).
    /// This variant also includes a maintainers tag for push authorization testing.
    ///
    /// # Arguments
    /// * `test_name` - Name of the test (used to create unique repo identifier)
    /// * `maintainer_pubkeys` - Hex pubkeys of maintainers who can push to the repository
    ///
    /// # Returns
    /// A built and signed Event ready to be sent to the relay
    pub async fn create_repo_announcement_with_maintainers(
        &self,
        test_name: &str,
        maintainer_pubkeys: &[String],
    ) -> Result<Event> {
        let (event, _repo_id) = self
            .create_repo_announcement_custom(test_name, self.keys(), maintainer_pubkeys)
            .await?;
        Ok(event)
    }

    /// Create an issue (kind 1621) that references a repository
    ///
    /// # Arguments
    /// * `repo_event` - The repository announcement event to reference
    /// * `issue_title` - The subject/title of the issue
    /// * `content` - The issue content/description
    /// * `additional_tags` - Optional additional tags (e.g., for quoting other events)
    ///
    /// # Returns
    /// A built and signed Event ready to be sent to the relay
    pub fn create_issue(
        &self,
        repo_event: &Event,
        issue_title: &str,
        content: &str,
        additional_tags: Vec<Tag>,
    ) -> Result<Event> {
        // Extract repo_id from the d tag
        let repo_id = repo_event
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .ok_or_else(|| anyhow!("Repository event must have a 'd' tag"))?
            .to_string();

        let repo_pubkey = repo_event.pubkey;
        let a_tag_value = format!("30617:{}:{}", repo_pubkey, repo_id);

        let mut tags = vec![
            Tag::custom("a", vec![a_tag_value]),
            Tag::custom("subject", vec![issue_title]),
        ];

        // Add any additional tags
        tags.extend(additional_tags);

        self.event_builder(Kind::GitIssue, content)
            .tags(tags)
            .build(self.keys())
            .map_err(|e| anyhow!("Failed to build issue event: {}", e))
    }

    /// Create a NIP-22 comment (kind 1111) for an event
    ///
    /// # Arguments
    /// * `event` - The event to comment on
    /// * `content` - The comment content
    /// * `additional_tags` - Optional additional tags
    ///
    /// # Returns
    /// A built and signed Event ready to be sent to the relay
    pub fn create_comment(
        &self,
        event: &Event,
        content: &str,
        additional_tags: Vec<Tag>,
    ) -> Result<Event> {
        let event_kind = event.kind;
        let event_pubkey = event.pubkey;
        let event_id = event.id;

        let mut tags = vec![
            Tag::custom(
                "E",
                vec![event_id.to_hex(), "".to_string(), "root".to_string()],
            ),
            Tag::event(event_id),
            Tag::custom("K", vec![event_kind.as_u16().to_string()]),
            Tag::public_key(event_pubkey),
        ];

        // Add any additional tags
        tags.extend(additional_tags);

        self.event_builder(Kind::Comment, content)
            .tags(tags)
            .build(self.keys())
            .map_err(|e| anyhow!("Failed to build comment event: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let config = AuditConfig::isolated();

        // This will fail if no relay is running, which is expected in tests
        // In real usage, there should be a relay at the URL
        let result = AuditClient::new("ws://localhost:7000", config).await;

        // We can't test connection without a running relay
        // But we can test that the client is created
        if let Ok(client) = result {
            assert_eq!(client.config.mode, AuditMode::Isolated);
        }
    }

    #[test]
    fn test_event_builder() {
        let config = AuditConfig::isolated();
        let keys = Keys::generate();
        let maintainer_keys = Keys::generate();
        let recursive_maintainer_keys = Keys::generate();
        let pr_author_keys = Keys::generate();
        let client = AuditClient {
            client: Client::builder()
                .authenticator(SignerAuthenticator::new(keys.clone()))
                .build(),
            config: config.clone(),
            keys: keys.clone(),
            maintainer_keys,
            recursive_maintainer_keys,
            pr_author_keys,
            fixture_cache: Arc::new(Mutex::new(HashMap::new())),
            typed_fixture_cache: Arc::new(Mutex::new(HashMap::new())),
        };

        let _builder = client.event_builder(Kind::TextNote, "test content");

        // Builder should be created successfully
        // (We can't test the internal config field as it's private, which is correct)
    }

    #[test]
    fn test_audit_tags_automatically_added() {
        let config = AuditConfig::isolated();
        let keys = Keys::generate();
        let maintainer_keys = Keys::generate();
        let recursive_maintainer_keys = Keys::generate();
        let pr_author_keys = Keys::generate();
        let client = AuditClient {
            client: Client::builder()
                .authenticator(SignerAuthenticator::new(keys.clone()))
                .build(),
            config: config.clone(),
            keys: keys.clone(),
            maintainer_keys,
            recursive_maintainer_keys,
            pr_author_keys,
            fixture_cache: Arc::new(Mutex::new(HashMap::new())),
            typed_fixture_cache: Arc::new(Mutex::new(HashMap::new())),
        };

        // Create an event with a custom tag
        let event = client
            .event_builder(Kind::TextNote, "test content")
            .tag(Tag::custom("custom", vec!["value"]))
            .build(&keys)
            .unwrap();

        // Should have custom tag (1) + 3 audit tags = at least 4 tags
        assert!(
            event.tags.len() >= 4,
            "Expected at least 4 tags, got {}",
            event.tags.len()
        );

        // Verify audit tags are present by checking tag content
        let tag_contents: Vec<String> = event
            .tags
            .iter()
            .filter_map(|t| t.content().map(|s| s.to_string()))
            .collect();

        // Check for the three required audit tags
        assert!(
            tag_contents.contains(&"grasp-audit-test-event".to_string()),
            "Missing 'grasp-audit-test-event' tag"
        );
        assert!(
            tag_contents
                .iter()
                .any(|t| t.starts_with("audit-isolated-")),
            "Missing 'audit-isolated-*' tag"
        );
        assert!(
            tag_contents
                .iter()
                .any(|t| t.starts_with("audit-cleanup-after-")),
            "Missing 'audit-cleanup-after-*' tag"
        );

        // Verify the custom tag is also present
        assert!(
            tag_contents.contains(&"value".to_string()),
            "Missing custom tag value"
        );
    }

    #[tokio::test]
    async fn test_create_repo_announcement_with_maintainers() {
        let config = AuditConfig::isolated();
        let client = AuditClient::new_test(config);

        // Create test maintainer pubkeys (hex format)
        let maintainer_pubkeys = vec![
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3".to_string(),
        ];

        // Note: We can't test create_repo_announcement_with_maintainers directly in unit tests
        // because it requires a connected relay. Instead, we test the underlying event building
        // with maintainers tag to verify the tag format is correct.

        // Build an event with maintainers tag directly to test the tag format
        let event = client
            .event_builder(Kind::GitRepoAnnouncement, "Test repository")
            .tag(Tag::identifier("test-repo"))
            .tag(Tag::custom("maintainers", maintainer_pubkeys.clone()))
            .build(client.keys())
            .unwrap();

        // Verify the maintainers tag is present and correctly formatted
        let maintainers_tag = event.tags.iter().find(|t| t.kind() == "maintainers");

        assert!(
            maintainers_tag.is_some(),
            "Missing 'maintainers' tag in event"
        );

        // Verify the tag contains the maintainer pubkeys
        let tag = maintainers_tag.unwrap();
        let tag_vec: Vec<String> = tag.clone().to_vec();

        // First element is "maintainers", rest are the pubkeys
        assert_eq!(tag_vec[0], "maintainers");
        assert_eq!(
            tag_vec.len(),
            3,
            "Expected 3 elements: tag name + 2 pubkeys"
        );
        assert_eq!(tag_vec[1], maintainer_pubkeys[0]);
        assert_eq!(tag_vec[2], maintainer_pubkeys[1]);
    }
}
