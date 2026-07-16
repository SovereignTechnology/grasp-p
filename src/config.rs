use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS: u64 =
    180 * 24 * 60 * 60;
// Retention months are fixed 30-day periods, avoiding calendar-month ambiguity.
const DEFAULT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS: u64 = 270 * 24 * 60 * 60;
const DEFAULT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS: u64 =
    90 * 24 * 60 * 60;

/// Whitelist entry for repository/archive filtering
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WhitelistEntry {
    /// All repos from this pubkey: "npub1..."
    Pubkey(String),

    /// Specific repo: "npub1.../identifier"
    Repository { npub: String, identifier: String },

    /// Any repo with this identifier: "identifier"
    Identifier(String),
}

impl WhitelistEntry {
    /// Parse a whitelist entry from string
    ///
    /// Formats:
    /// - "npub1..." -> Pubkey
    /// - "npub1.../identifier" -> Repository
    /// - "identifier" -> Identifier
    ///
    /// Validates npub format at parse time (fail fast)
    pub fn parse(s: &str) -> Result<Self> {
        let trimmed = s.trim();

        if trimmed.contains('/') {
            // Format: npub1.../identifier
            let parts: Vec<&str> = trimmed.split('/').collect();
            if parts.len() != 2 {
                return Err(anyhow!(
                    "Invalid whitelist entry format '{}'. Expected 'npub/identifier'",
                    s
                ));
            }

            let npub = parts[0];
            let identifier = parts[1];

            // Validate npub format (fail fast)
            if !npub.starts_with("npub1") {
                return Err(anyhow!(
                    "Invalid whitelist entry '{}'. First part must be npub",
                    s
                ));
            }

            PublicKey::from_bech32(npub)
                .context(format!("Invalid npub in whitelist entry '{}'", s))?;

            Ok(Self::Repository {
                npub: npub.to_string(),
                identifier: identifier.to_string(),
            })
        } else if trimmed.starts_with("npub1") {
            // Format: npub1...
            // Validate npub format (fail fast)
            PublicKey::from_bech32(trimmed)
                .context(format!("Invalid npub in whitelist entry '{}'", s))?;

            Ok(Self::Pubkey(trimmed.to_string()))
        } else {
            // Format: identifier
            Ok(Self::Identifier(trimmed.to_string()))
        }
    }

    /// Check if this entry matches the given npub and identifier
    pub fn matches(&self, npub: &str, identifier: &str) -> bool {
        match self {
            Self::Pubkey(p) => npub == p,
            Self::Repository {
                npub: p,
                identifier: i,
            } => npub == p && identifier == i,
            Self::Identifier(i) => identifier == i,
        }
    }

    /// Parse whitelist from comma-separated string
    ///
    /// Skips invalid entries with warnings instead of failing.
    /// This allows the config to load even if some whitelist entries are malformed.
    pub fn parse_whitelist(input: &str) -> Vec<Self> {
        if input.trim().is_empty() {
            return Vec::new();
        }

        input
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| match Self::parse(s) {
                Ok(entry) => Some(entry),
                Err(e) => {
                    tracing::warn!("Skipping invalid whitelist entry '{}': {}", s, e);
                    None
                }
            })
            .collect()
    }
}

/// GRASP-05 Archive mode configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArchiveConfig {
    /// Accept all repository announcements (no filtering)
    ///
    /// WARNING: Setting this to true allows anyone to mirror any repository
    /// to this relay, potentially causing storage/bandwidth exhaustion.
    #[serde(default)]
    pub archive_all: bool,

    /// Whitelist entries for selective archiving
    ///
    /// If empty and archive_all is false, GRASP-05 is disabled (GRASP-01 strict mode).
    #[serde(default)]
    pub whitelist: Vec<WhitelistEntry>,

    /// GRASP server domains to archive (archive all repositories from these domains)
    ///
    /// If non-empty, archives all repositories from the specified GRASP server domains.
    #[serde(default)]
    pub grasp_services: Vec<String>,

    /// Read-only archive mode: relay is a read-only sync of archived repositories
    ///
    /// When true, the relay ONLY accepts announcements matching the archive whitelist/all.
    /// Announcements listing the relay but not in the whitelist are rejected.
    /// When false, the relay operates in GRASP-01 mode for unwhitelisted repos.
    #[serde(default)]
    pub read_only: bool,
}

impl ArchiveConfig {
    /// Check if GRASP-05 is enabled (either archive_all, non-empty whitelist, or non-empty grasp_services)
    pub fn enabled(&self) -> bool {
        self.archive_all || !self.whitelist.is_empty() || !self.grasp_services.is_empty()
    }

    /// Check if an announcement matches the archive configuration
    ///
    /// Returns true if:
    /// - archive_all is true, OR
    /// - announcement matches any whitelist entry
    ///
    /// Note: grasp_services matching is handled via matches_grasp_services()
    pub fn matches(&self, npub: &str, identifier: &str) -> bool {
        if self.archive_all {
            return true;
        }

        self.whitelist
            .iter()
            .any(|entry| entry.matches(npub, identifier))
    }

    /// Check if any of the given domains match the configured grasp_services
    ///
    /// Returns true if any domain in the list matches any configured grasp_services entry.
    pub fn matches_grasp_services(&self, domains: &[String]) -> bool {
        if self.grasp_services.is_empty() {
            return false;
        }

        domains
            .iter()
            .any(|domain| self.grasp_services.iter().any(|service| service == domain))
    }
}

/// Repository whitelist configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepositoryConfig {
    /// Whitelist entries for selective repository acceptance
    ///
    /// If empty, all repositories listing the service are accepted (GRASP-01 mode).
    #[serde(default)]
    pub whitelist: Vec<WhitelistEntry>,
}

impl RepositoryConfig {
    /// Check if repository whitelist is enabled (non-empty whitelist)
    pub fn enabled(&self) -> bool {
        !self.whitelist.is_empty()
    }

    /// Check if an announcement matches the repository whitelist
    ///
    /// Returns true if announcement matches any whitelist entry
    pub fn matches(&self, npub: &str, identifier: &str) -> bool {
        self.whitelist
            .iter()
            .any(|entry| entry.matches(npub, identifier))
    }
}

/// Repository blacklist configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlacklistConfig {
    /// Blacklist entries for blocking specific repositories
    ///
    /// If empty, no repositories are blacklisted.
    /// Blacklist takes precedence over both archive and repository whitelists.
    #[serde(default)]
    pub blacklist: Vec<WhitelistEntry>,
}

impl BlacklistConfig {
    /// Check if repository blacklist is enabled (non-empty blacklist)
    pub fn enabled(&self) -> bool {
        !self.blacklist.is_empty()
    }

    /// Check if an announcement matches the repository blacklist
    ///
    /// Returns Some(reason) if blacklisted, None if not blacklisted.
    /// The reason indicates what type of match occurred (npub, npub/identifier, or identifier).
    pub fn check(&self, npub: &str, identifier: &str) -> Option<String> {
        for entry in &self.blacklist {
            if entry.matches(npub, identifier) {
                let reason = match entry {
                    WhitelistEntry::Pubkey(_) => {
                        format!("Repository owner {} is blacklisted", npub)
                    }
                    WhitelistEntry::Repository { .. } => {
                        format!("Repository {}/{} is blacklisted", npub, identifier)
                    }
                    WhitelistEntry::Identifier(_) => {
                        format!("Repository identifier {} is blacklisted", identifier)
                    }
                };
                return Some(reason);
            }
        }
        None
    }
}

/// Event blacklist configuration for blocking events by author npub
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventBlacklistConfig {
    /// Blacklisted npubs - events from these authors are rejected
    ///
    /// If empty, no events are blacklisted by author.
    /// Applies to ALL event types, preventing events from reaching both the relay and purgatory.
    #[serde(default)]
    pub blacklisted_npubs: Vec<String>,
}

impl EventBlacklistConfig {
    /// Check if event blacklist is enabled (non-empty blacklist)
    pub fn enabled(&self) -> bool {
        !self.blacklisted_npubs.is_empty()
    }

    /// Check if an event author is blacklisted
    ///
    /// Returns Some(reason) if blacklisted, None if not blacklisted.
    pub fn check(&self, npub: &str) -> Option<String> {
        if self.blacklisted_npubs.contains(&npub.to_string()) {
            Some(format!("Event author {} is blacklisted", npub))
        } else {
            None
        }
    }
}

/// Database backend type for the relay
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseBackend {
    /// LMDB backend (persistent, general purpose)
    #[default]
    Lmdb,
    /// In-memory database (fastest, no persistence - uses temp directory for git data)
    Memory,
}

impl std::fmt::Display for DatabaseBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "memory"),
            Self::Lmdb => write!(f, "lmdb"),
        }
    }
}

/// ngit-grasp - A GRASP (Git Relays Authorized via Signed-Nostr Proofs) implementation
///
/// Configuration is loaded with the following priority (highest to lowest):
/// 1. CLI flags (e.g., --domain example.com)
/// 2. Environment variables (e.g., NGIT_DOMAIN=example.com)
/// 3. .env file (loaded automatically if present)
/// 4. Built-in defaults
#[derive(Debug, Clone, Serialize, Deserialize, Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Config {
    /// Domain where this instance is hosted (required, used in GRASP validation)
    #[arg(long, env = "NGIT_DOMAIN")]
    pub domain: String,

    /// Relay operator's nsec (private key) for signing and authentication
    ///
    /// Used for:
    /// - NIP-11 relay information document (pubkey field derived from this nsec)
    /// - NIP-42 authentication when syncing from other relays
    /// - Future: signing events, WoT-based rate limiting of syncing relays
    ///
    /// If not provided via CLI/env, will be loaded from/saved to `.relay-owner.nsec` file
    /// in the current directory. If the file doesn't exist, a new key will be generated
    /// and saved automatically.
    #[arg(long, env = "NGIT_RELAY_OWNER_NSEC")]
    pub relay_owner_nsec: Option<String>,

    /// Relay name for NIP-11 information document (defaults to "${domain} grasp relay")
    #[arg(long = "relay-name", env = "NGIT_RELAY_NAME")]
    pub relay_name_override: Option<String>,

    /// Relay description for NIP-11 information document
    #[arg(
        long,
        env = "NGIT_RELAY_DESCRIPTION",
        default_value = "Git Nostr Relay - a grasp implementation"
    )]
    pub relay_description: String,

    /// Path to store Git repositories
    #[arg(long, env = "NGIT_GIT_DATA_PATH", default_value = "./data/git")]
    pub git_data_path: String,

    /// Path to store Nostr relay data
    #[arg(long, env = "NGIT_RELAY_DATA_PATH", default_value = "./data/relay")]
    pub relay_data_path: String,

    /// Server bind address (IP:PORT)
    #[arg(long, env = "NGIT_BIND_ADDRESS", default_value = "127.0.0.1:7334")]
    pub bind_address: String,

    /// Database backend type
    #[arg(long, env = "NGIT_DATABASE_BACKEND", value_enum, default_value_t = DatabaseBackend::Lmdb)]
    pub database_backend: DatabaseBackend,

    /// Enable Prometheus metrics endpoint
    #[arg(long, env = "NGIT_METRICS_ENABLED", default_value_t = true)]
    pub metrics_enabled: bool,

    /// Connections per IP before flagging as potential abuse in metrics (display only, no rate limiting)
    #[arg(
        long = "metrics-connection-per-ip-abuse-threshold",
        env = "NGIT_METRICS_CONNECTION_PER_IP_ABUSE_THRESHOLD",
        default_value_t = 10
    )]
    pub metrics_connection_per_ip_abuse_threshold: u32,

    /// Number of top bandwidth repos to track in metrics
    #[arg(
        long = "metrics-top-n-repos",
        env = "NGIT_METRICS_TOP_N_REPOS",
        default_value_t = 10
    )]
    pub metrics_top_n_repos: usize,

    /// URL of bootstrap relay to sync from on startup (optional)
    /// Sync discovers additional relays from repository announcements that list our service
    /// If no scheme is provided (wss:// or ws://), wss:// is assumed
    /// Examples: "relay.example.com" -> "wss://relay.example.com", "wss://relay.example.com" -> unchanged
    #[arg(long, env = "NGIT_SYNC_BOOTSTRAP_RELAY_URL")]
    pub sync_bootstrap_relay_url: Option<String>,

    /// Maximum backoff time in seconds for sync relay reconnection (default: 3600 = 1 hour)
    #[arg(long, env = "NGIT_SYNC_MAX_BACKOFF_SECS", default_value_t = 3600)]
    pub sync_max_backoff_secs: u64,

    /// Interval in seconds for checking disconnected relays and attempting reconnection (default: 60)
    /// Set to lower value for faster reconnection testing
    #[arg(
        long,
        env = "NGIT_SYNC_DISCONNECT_CHECK_INTERVAL_SECS",
        default_value_t = 60
    )]
    pub sync_disconnect_check_interval_secs: u64,

    /// Base backoff time in seconds for relay reconnection (default: 5)
    /// Used for exponential backoff: base * 2^(failures-1)
    /// Set to 1 for faster test cycles
    /// Note: The connection timeout is capped at this value
    #[arg(long, env = "NGIT_SYNC_BASE_BACKOFF_SECS", default_value_t = 5)]
    pub sync_base_backoff_secs: u64,

    /// Disable NIP-77 negentropy sync (default: false)
    /// When enabled, sync will use REQ+EOSE instead of negentropy for history sync.
    /// Primarily useful for testing that sync works without negentropy support.
    #[arg(long, env = "NGIT_SYNC_DISABLE_NEGENTROPY", default_value_t = false)]
    pub sync_disable_negentropy: bool,

    /// Hot cache duration in seconds for rejected announcements (default: 120 = 2 minutes)
    /// Stores full event objects for immediate re-processing when dependencies resolve.
    /// Too short (<30s): Miss events from slow relays
    /// Too long (>5min): Waste memory
    #[arg(
        long,
        env = "NGIT_REJECTED_HOT_CACHE_DURATION_SECS",
        default_value_t = 120
    )]
    pub rejected_hot_cache_duration_secs: u64,

    /// Cold index expiry in seconds for rejected announcements (default: 604800 = 7 days)
    /// Stores metadata only to prevent repeated downloads of rejected events.
    #[arg(
        long,
        env = "NGIT_REJECTED_COLD_INDEX_EXPIRY_SECS",
        default_value_t = 604800
    )]
    pub rejected_cold_index_expiry_secs: u64,

    /// Hours before removing relay from naughty list (default: 12)
    /// Relays with persistent infrastructure issues (DNS, TLS, protocol errors) are
    /// tracked separately and retried after this expiration period.
    #[arg(long, env = "NGIT_NAUGHTY_LIST_EXPIRATION_HOURS", default_value_t = 12)]
    pub naughty_list_expiration_hours: u64,

    /// Retention window in seconds for deleted events kept in holding DB.
    #[arg(
        long,
        env = "NGIT_HOLDING_RETENTION_SECS",
        default_value_t = crate::nostr::lifecycle::DEFAULT_RETENTION.as_secs()
    )]
    pub holding_retention_secs: u64,

    /// Interval in seconds between background holding cleanup passes.
    #[arg(
        long,
        env = "NGIT_HOLDING_CLEANUP_INTERVAL_SECS",
        default_value_t = crate::nostr::lifecycle::DEFAULT_CLEANUP_INTERVAL.as_secs()
    )]
    pub holding_cleanup_interval_secs: u64,

    /// How long an unused deletion or vanish request remains served after relay-observed first_seen_at.
    #[arg(
        long = "deletion-request-retention-unused-served-secs",
        env = "NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS",
        default_value_t = DEFAULT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS
    )]
    pub deletion_request_retention_unused_served_secs: u64,

    /// Additional time an unused deletion or vanish request remains unserved but eligible to gate.
    #[arg(
        long = "deletion-request-retention-unused-unserved-gating-additional-secs",
        env = "NGIT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS",
        default_value_t = DEFAULT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS
    )]
    pub deletion_request_retention_unused_unserved_gating_additional_secs: u64,

    /// Normal-mode time a used deletion or vanish request remains served after last_used_at.
    #[arg(
        long = "deletion-request-retention-used-served-after-last-used-secs",
        env = "NGIT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS",
        default_value_t = DEFAULT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS
    )]
    pub deletion_request_retention_used_served_after_last_used_secs: u64,

    /// Additional normal-mode time a used request remains unserved but continues gating after serving ends.
    #[arg(
        long = "deletion-request-retention-used-unserved-gating-additional-secs",
        env = "NGIT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS",
        default_value_t = DEFAULT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS
    )]
    pub deletion_request_retention_used_unserved_gating_additional_secs: u64,

    /// Enable GRASP-05 archive mode: accept all announcements regardless of listing (WARNING: storage risk)
    #[arg(long, env = "NGIT_ARCHIVE_ALL", default_value_t = false)]
    pub archive_all: bool,

    /// GRASP-05 archive whitelist: comma-separated list of npub/identifier/npub/identifier entries
    /// Formats: "npub1...", "npub1.../identifier", "identifier"
    #[arg(long, env = "NGIT_ARCHIVE_WHITELIST", default_value = "")]
    pub archive_whitelist: String,

    /// GRASP-05 archive GRASP services: comma-separated list of GRASP server domains to archive
    /// When set, archives all repositories from the specified GRASP server domains
    /// Mutually exclusive with archive_all and archive_whitelist
    #[arg(long, env = "NGIT_ARCHIVE_GRASP_SERVICES", default_value = "")]
    pub archive_grasp_services: String,

    /// Archive read-only mode: relay is a read-only sync of archived repositories
    /// Defaults to true if archive_all, archive_whitelist, or archive_grasp_services is set, false otherwise
    /// Throws error if set to true without archive_all, archive_whitelist, or archive_grasp_services
    #[arg(long, env = "NGIT_ARCHIVE_READ_ONLY")]
    pub archive_read_only: Option<bool>,

    /// Enable GRASP-06 contributor PR submission endpoint at /prs/<npub>/<identifier>.git
    ///
    /// When enabled, the relay exposes an unauthenticated PR submission endpoint
    /// at `/prs/<npub>/<identifier>.git` that accepts pushes of `refs/nostr/<event-id>`
    /// from any contributor. Security relies on the signed PR/PR-Update events
    /// the refs reference, not on HTTP-level auth.
    ///
    /// Default: false. This is an opt-in feature that adds an unauthenticated
    /// write surface; operators must understand the tradeoffs (see GRASP-06 spec
    /// and `docs/explanation/grasp-06-contributor-pr-submission.md`) before
    /// enabling it.
    #[arg(long, env = "NGIT_GRASP06_ENABLE", default_value_t = false)]
    pub grasp06_enable: bool,

    /// Repository whitelist: comma-separated list of npub/identifier/npub/identifier entries
    /// Formats: "npub1...", "npub1.../identifier", "identifier"
    /// When set, only announcements matching the whitelist AND listing the service are accepted
    #[arg(long, env = "NGIT_REPOSITORY_WHITELIST", default_value = "")]
    pub repository_whitelist: String,

    /// Repository blacklist: comma-separated list of npub/identifier/npub/identifier entries to reject
    /// Formats: "npub1...", "npub1.../identifier", "identifier"
    /// Blacklist takes precedence over all whitelists (archive and repository)
    #[arg(long, env = "NGIT_REPOSITORY_BLACKLIST", default_value = "")]
    pub repository_blacklist: String,

    /// Automatically restore blacklist-deleted repositories on startup when
    /// they are no longer blacklisted and still within holding retention.
    #[arg(long, env = "NGIT_BLACKLIST_AUTO_RESTORE", default_value_t = false)]
    pub blacklist_auto_restore: bool,

    /// Event blacklist: comma-separated list of npubs whose events are rejected
    /// All events from these authors are blocked from both relay storage and purgatory
    #[arg(long, env = "NGIT_EVENT_BLACKLIST", default_value = "")]
    pub event_blacklist: String,

    /// Deletion request disrespector: ignore NIP-09 deletion requests (archival mode)
    ///
    /// When `true`, the relay stores incoming NIP-09 (kind 5) deletion requests but
    /// does NOT act on them: targeted events remain fully accessible. This makes the
    /// relay an archival server, preventing "left-pad" scenarios by ensuring at least
    /// some relays preserve deleted content.
    ///
    /// This setting ONLY affects NIP-09 user-initiated deletions. Policy-driven
    /// blacklist/whitelist deletion flows still run because they enforce local
    /// relay serving policy rather than client deletion requests.
    ///
    /// When `true`, NIP-09 (`"deletion"`) is NOT advertised in the NIP-11 supported
    /// NIPs list so clients can discover that the relay does not honour deletions.
    #[arg(
        long,
        env = "NGIT_DELETION_REQUEST_DISRESPECTOR",
        default_value_t = false
    )]
    pub deletion_request_disrespector: bool,

    /// Maximum total connections to the relay (default: unlimited, defers to OS/infrastructure limits)
    #[arg(long, env = "NGIT_MAX_CONNECTIONS")]
    pub max_connections: Option<usize>,

    /// Log level for application logging
    #[arg(long, env = "NGIT_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
}

impl Config {
    /// Path to the relay owner key file
    const RELAY_OWNER_KEY_FILE: &'static str = ".relay-owner.nsec";

    /// Load configuration from CLI args, environment variables, and defaults.
    ///
    /// Priority (highest to lowest):
    /// 1. CLI flags
    /// 2. Environment variables
    /// 3. .env file
    /// 4. Built-in defaults
    pub fn load() -> Result<Self> {
        // Load .env file if present (before clap parses, so env vars are available)
        dotenvy::dotenv().ok();

        // Parse CLI args (clap automatically handles env var fallback)
        let mut config = Self::parse();

        // If relay_owner_nsec not provided, load from file or generate
        if config.relay_owner_nsec.is_none() {
            config.relay_owner_nsec = Some(Self::load_or_generate_relay_owner_key()?);
        } else {
            // If provided via CLI/env, trim any whitespace (newlines, spaces, etc.)
            // This handles cases where the value is read from a file with trailing newline
            config.relay_owner_nsec = config.relay_owner_nsec.map(|s| s.trim().to_string());
        }

        Ok(config)
    }

    /// Load relay owner key from file, or generate and save a new one
    pub fn load_or_generate_relay_owner_key() -> Result<String> {
        let key_path = PathBuf::from(Self::RELAY_OWNER_KEY_FILE);

        // Try to load existing key
        if key_path.exists() {
            let nsec = fs::read_to_string(&key_path)
                .context("Failed to read relay owner key file")?
                .trim()
                .to_string();

            // Validate it's a valid nsec
            Keys::parse(&nsec).context("Invalid nsec in relay owner key file")?;

            tracing::info!("Loaded relay owner key from {}", key_path.display());
            return Ok(nsec);
        }

        // Generate new key
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32()?;

        // Save to file
        fs::write(&key_path, &nsec).context("Failed to write relay owner key file")?;

        tracing::info!(
            "Generated new relay owner key and saved to {}",
            key_path.display()
        );

        Ok(nsec)
    }

    /// Get the relay owner's Keys object
    pub fn relay_owner_keys(&self) -> Result<Keys> {
        let nsec = self
            .relay_owner_nsec
            .as_ref()
            .context("relay_owner_nsec not set (should be set by Config::load())")?;
        Keys::parse(nsec).context("Invalid relay_owner_nsec")
    }

    /// Get the relay owner's public key (hex format) for NIP-11
    pub fn relay_owner_pubkey_hex(&self) -> Result<String> {
        let keys = self.relay_owner_keys()?;
        Ok(keys.public_key().to_hex())
    }

    /// Get the relay owner's public key (npub format)
    pub fn relay_owner_npub(&self) -> Result<String> {
        let keys = self.relay_owner_keys()?;
        Ok(keys.public_key().to_bech32()?)
    }

    /// Get relay name (defaults to "${domain} grasp relay" if not set)
    pub fn relay_name(&self) -> String {
        self.relay_name_override
            .clone()
            .unwrap_or_else(|| format!("{} grasp relay", self.domain))
    }

    /// Get effective git data path
    /// Returns a temp directory when using memory backend with default path, otherwise the configured path
    pub fn effective_git_data_path(&self) -> String {
        if self.database_backend == DatabaseBackend::Memory && self.git_data_path == "./data/git" {
            // Only use default temp directory if git_data_path is still the default value
            std::env::temp_dir()
                .join("ngit-grasp-git")
                .to_string_lossy()
                .into_owned()
        } else {
            self.git_data_path.clone()
        }
    }

    /// Validate configuration and return fatal errors
    ///
    /// This should be called immediately after Config::load() to fail fast on config errors.
    /// Recoverable issues (e.g., malformed whitelist entries) are logged as warnings and skipped.
    pub fn validate(&self) -> Result<()> {
        // Validate relay owner nsec (should always be set by Config::load())
        let nsec = self
            .relay_owner_nsec
            .as_ref()
            .context("relay_owner_nsec not set (should be set by Config::load())")?;
        Keys::parse(nsec).context("Invalid relay_owner_nsec format")?;

        // Validate archive configuration
        let archive_whitelist = WhitelistEntry::parse_whitelist(&self.archive_whitelist);
        let archive_grasp_services = self.parse_archive_grasp_services();
        let archive_enabled =
            self.archive_all || !archive_whitelist.is_empty() || !archive_grasp_services.is_empty();

        // Fatal error: archive_grasp_services cannot be used with archive_all or archive_whitelist
        if !archive_grasp_services.is_empty() {
            if self.archive_all {
                return Err(anyhow!(
                    "NGIT_ARCHIVE_GRASP_SERVICES cannot be used with NGIT_ARCHIVE_ALL=true. \
                     These options are mutually exclusive."
                ));
            }
            if !archive_whitelist.is_empty() {
                return Err(anyhow!(
                    "NGIT_ARCHIVE_GRASP_SERVICES cannot be used with NGIT_ARCHIVE_WHITELIST. \
                     These options are mutually exclusive."
                ));
            }
        }

        // Fatal error: archive_read_only=true without archive mode enabled
        if let Some(true) = self.archive_read_only {
            if !archive_enabled {
                return Err(anyhow!(
                    "NGIT_ARCHIVE_READ_ONLY=true requires either NGIT_ARCHIVE_ALL=true, \
                     NGIT_ARCHIVE_WHITELIST, or NGIT_ARCHIVE_GRASP_SERVICES to be set"
                ));
            }
        }

        // Validate repository whitelist configuration
        let repository_whitelist = WhitelistEntry::parse_whitelist(&self.repository_whitelist);

        if self.holding_retention_secs == 0 {
            return Err(anyhow!(
                "NGIT_HOLDING_RETENTION_SECS must be greater than 0"
            ));
        }

        if self.holding_cleanup_interval_secs == 0 {
            return Err(anyhow!(
                "NGIT_HOLDING_CLEANUP_INTERVAL_SECS must be greater than 0"
            ));
        }

        Self::validate_deletion_request_retention_duration(
            self.deletion_request_retention_unused_served_secs,
            "NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS",
        )?;
        Self::validate_deletion_request_retention_duration(
            self.deletion_request_retention_unused_unserved_gating_additional_secs,
            "NGIT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS",
        )?;
        Self::validate_deletion_request_retention_duration(
            self.deletion_request_retention_used_served_after_last_used_secs,
            "NGIT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS",
        )?;
        Self::validate_deletion_request_retention_duration(
            self.deletion_request_retention_used_unserved_gating_additional_secs,
            "NGIT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS",
        )?;

        Self::validate_deletion_request_retention_deadline(
            self.deletion_request_retention_unused_served_secs,
            self.deletion_request_retention_unused_unserved_gating_additional_secs,
            "unused",
        )?;
        Self::validate_deletion_request_retention_deadline(
            self.deletion_request_retention_used_served_after_last_used_secs,
            self.deletion_request_retention_used_unserved_gating_additional_secs,
            "used",
        )?;

        // Fatal error: repository_whitelist with archive_read_only=true (incompatible)
        if !repository_whitelist.is_empty() {
            let read_only = self.archive_read_only.unwrap_or(archive_enabled);
            if read_only {
                return Err(anyhow!(
                    "NGIT_REPOSITORY_WHITELIST cannot be used with NGIT_ARCHIVE_READ_ONLY=true. \
                     Archive read-only mode rejects announcements that don't match the archive whitelist, \
                     regardless of service listing. Either set NGIT_ARCHIVE_READ_ONLY=false or use \
                     NGIT_ARCHIVE_WHITELIST instead of NGIT_REPOSITORY_WHITELIST."
                ));
            }
        }

        Ok(())
    }

    /// Parse archive GRASP services from comma-separated string
    ///
    /// Returns a list of domain names (GRASP server domains to archive).
    /// Whitespace is trimmed and empty entries are ignored.
    pub fn parse_archive_grasp_services(&self) -> Vec<String> {
        if self.archive_grasp_services.trim().is_empty() {
            return Vec::new();
        }

        self.archive_grasp_services
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    /// Get parsed archive configuration with computed read-only mode
    ///
    /// Read-only mode defaults to true if archive mode is enabled, false otherwise.
    /// This method assumes config has been validated - call Config::validate() first!
    pub fn archive_config(&self) -> ArchiveConfig {
        let whitelist = WhitelistEntry::parse_whitelist(&self.archive_whitelist);
        let archive_grasp_services = self.parse_archive_grasp_services();
        let archive_enabled =
            self.archive_all || !whitelist.is_empty() || !archive_grasp_services.is_empty();

        let read_only = match self.archive_read_only {
            Some(true) => true, // Already validated in validate()
            Some(false) => false,
            None => {
                // Default: true if archive mode enabled, false otherwise
                archive_enabled
            }
        };

        ArchiveConfig {
            archive_all: self.archive_all,
            whitelist,
            grasp_services: archive_grasp_services,
            read_only,
        }
    }

    /// Get parsed repository whitelist configuration
    ///
    /// This method assumes config has been validated - call Config::validate() first!
    pub fn repository_config(&self) -> RepositoryConfig {
        let whitelist = WhitelistEntry::parse_whitelist(&self.repository_whitelist);
        RepositoryConfig { whitelist }
    }

    /// Get parsed repository blacklist configuration
    ///
    /// This method assumes config has been validated - call Config::validate() first!
    pub fn blacklist_config(&self) -> BlacklistConfig {
        let blacklist = WhitelistEntry::parse_whitelist(&self.repository_blacklist);
        BlacklistConfig { blacklist }
    }

    /// Get parsed event blacklist configuration
    ///
    /// This method assumes config has been validated - call Config::validate() first!
    pub fn event_blacklist_config(&self) -> EventBlacklistConfig {
        let blacklisted_npubs: Vec<String> = self
            .event_blacklist
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        EventBlacklistConfig { blacklisted_npubs }
    }

    /// Holding DB retention as a duration.
    pub fn holding_retention(&self) -> Duration {
        Duration::from_secs(self.holding_retention_secs)
    }

    /// Holding DB periodic cleanup interval as a duration.
    pub fn holding_cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.holding_cleanup_interval_secs)
    }

    /// How long an unused request remains served from relay-observed first_seen_at.
    pub fn deletion_request_retention_unused_served(&self) -> Duration {
        Duration::from_secs(self.deletion_request_retention_unused_served_secs)
    }

    /// Additional time an unused request remains unserved but eligible to gate.
    pub fn deletion_request_retention_unused_unserved_gating_additional(&self) -> Duration {
        Duration::from_secs(self.deletion_request_retention_unused_unserved_gating_additional_secs)
    }

    /// Normal-mode time a used request remains served after last_used_at.
    pub fn deletion_request_retention_used_served_after_last_used(&self) -> Duration {
        Duration::from_secs(self.deletion_request_retention_used_served_after_last_used_secs)
    }

    /// Additional normal-mode time a used request remains unserved but continues gating.
    pub fn deletion_request_retention_used_unserved_gating_additional(&self) -> Duration {
        Duration::from_secs(self.deletion_request_retention_used_unserved_gating_additional_secs)
    }

    fn validate_deletion_request_retention_duration(value: u64, name: &str) -> Result<()> {
        if value == 0 {
            return Err(anyhow!("{name} must be greater than 0"));
        }
        Ok(())
    }

    fn validate_deletion_request_retention_deadline(
        served_secs: u64,
        additional_gating_secs: u64,
        lifecycle: &str,
    ) -> Result<()> {
        if served_secs.checked_add(additional_gating_secs).is_none() {
            return Err(anyhow!(
                "{lifecycle} deletion-request retention served and additional gating durations must not overflow when combined"
            ));
        }
        Ok(())
    }

    /// Create config for testing
    #[cfg(test)]
    pub fn for_testing() -> Self {
        // Generate a test key deterministically for consistent tests
        let keys = Keys::generate();
        let nsec = keys
            .secret_key()
            .to_bech32()
            .expect("Failed to generate test nsec");

        Self {
            domain: "localhost:7334".to_string(),
            relay_owner_nsec: Some(nsec),
            relay_name_override: Some("test relay".to_string()),
            relay_description: "test description".to_string(),
            git_data_path: "./test_data/git".to_string(),
            relay_data_path: "./test_data/relay".to_string(),
            bind_address: "127.0.0.1:7334".to_string(),
            database_backend: DatabaseBackend::Memory,
            metrics_enabled: true,
            metrics_connection_per_ip_abuse_threshold: 10,
            metrics_top_n_repos: 10,
            sync_bootstrap_relay_url: None,
            sync_max_backoff_secs: 3600,
            sync_disconnect_check_interval_secs: 60,
            sync_base_backoff_secs: 5,
            sync_disable_negentropy: false,
            rejected_hot_cache_duration_secs: 120,
            rejected_cold_index_expiry_secs: 604800,
            naughty_list_expiration_hours: 12,
            holding_retention_secs: crate::nostr::lifecycle::DEFAULT_RETENTION.as_secs(),
            holding_cleanup_interval_secs: crate::nostr::lifecycle::DEFAULT_CLEANUP_INTERVAL
                .as_secs(),
            deletion_request_retention_unused_served_secs:
                DEFAULT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS,
            deletion_request_retention_unused_unserved_gating_additional_secs:
                DEFAULT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS,
            deletion_request_retention_used_served_after_last_used_secs:
                DEFAULT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS,
            deletion_request_retention_used_unserved_gating_additional_secs:
                DEFAULT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS,
            archive_all: false,
            archive_whitelist: String::new(),
            archive_grasp_services: String::new(),
            archive_read_only: None,
            grasp06_enable: false,
            repository_whitelist: String::new(),
            repository_blacklist: String::new(),
            blacklist_auto_restore: false,
            event_blacklist: String::new(),
            deletion_request_disrespector: false,
            max_connections: None,
            log_level: "debug".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static CONFIG_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_values() {
        let config = Config::for_testing();
        assert_eq!(config.domain, "localhost:7334");
        assert_eq!(config.bind_address, "127.0.0.1:7334");
        // for_testing() uses Memory, but the actual default is Lmdb
        assert_eq!(config.database_backend, DatabaseBackend::Memory);
    }

    #[test]
    fn test_deletion_request_retention_cli_defaults() {
        let _environment_guard = CONFIG_ENV_LOCK.lock().expect("lock must not be poisoned");
        let config = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("default deletion-request retention configuration should parse");

        assert_eq!(
            config.deletion_request_retention_unused_served(),
            Duration::from_secs(2_592_000)
        );
        assert_eq!(
            config.deletion_request_retention_unused_unserved_gating_additional(),
            Duration::from_secs(15_552_000)
        );
        assert_eq!(
            config.deletion_request_retention_used_served_after_last_used(),
            Duration::from_secs(23_328_000)
        );
        assert_eq!(
            config.deletion_request_retention_used_unserved_gating_additional(),
            Duration::from_secs(7_776_000)
        );
    }

    #[test]
    fn test_deletion_request_retention_cli_overrides() {
        let config = Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--deletion-request-retention-unused-served-secs",
            "1",
            "--deletion-request-retention-unused-unserved-gating-additional-secs",
            "2",
            "--deletion-request-retention-used-served-after-last-used-secs",
            "3",
            "--deletion-request-retention-used-unserved-gating-additional-secs",
            "4",
        ])
        .expect("custom deletion-request retention configuration should parse");

        assert_eq!(config.deletion_request_retention_unused_served_secs, 1);
        assert_eq!(
            config.deletion_request_retention_unused_unserved_gating_additional_secs,
            2
        );
        assert_eq!(
            config.deletion_request_retention_used_served_after_last_used_secs,
            3
        );
        assert_eq!(
            config.deletion_request_retention_used_unserved_gating_additional_secs,
            4
        );
    }

    #[test]
    fn test_deletion_request_retention_environment_override() {
        let _environment_guard = CONFIG_ENV_LOCK.lock().expect("lock must not be poisoned");
        const VARIABLE: &str = "NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS";
        let original = std::env::var_os(VARIABLE);
        std::env::set_var(VARIABLE, "42");

        let config = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("environment deletion-request retention configuration should parse");

        match original {
            Some(value) => std::env::set_var(VARIABLE, value),
            None => std::env::remove_var(VARIABLE),
        }

        assert_eq!(config.deletion_request_retention_unused_served_secs, 42);
    }

    #[test]
    fn test_deletion_request_retention_rejects_zero_durations() {
        let cases = [
            (
                "NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS",
                Config {
                    deletion_request_retention_unused_served_secs: 0,
                    ..Config::for_testing()
                },
            ),
            (
                "NGIT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS",
                Config {
                    deletion_request_retention_unused_unserved_gating_additional_secs: 0,
                    ..Config::for_testing()
                },
            ),
            (
                "NGIT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS",
                Config {
                    deletion_request_retention_used_served_after_last_used_secs: 0,
                    ..Config::for_testing()
                },
            ),
            (
                "NGIT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS",
                Config {
                    deletion_request_retention_used_unserved_gating_additional_secs: 0,
                    ..Config::for_testing()
                },
            ),
        ];

        for (variable, config) in cases {
            let error = config.validate().expect_err("zero duration must fail");
            assert!(error.to_string().contains(variable));
        }
    }

    #[test]
    fn test_deletion_request_retention_rejects_deadline_overflow() {
        let config = Config {
            deletion_request_retention_unused_served_secs: u64::MAX,
            deletion_request_retention_unused_unserved_gating_additional_secs: 1,
            ..Config::for_testing()
        };

        let error = config
            .validate()
            .expect_err("combined duration overflow must fail");
        assert!(error
            .to_string()
            .contains("unused deletion-request retention"));
    }

    #[test]
    fn test_lmdb_is_default() {
        // Verify the actual default via the enum's Default trait
        assert_eq!(DatabaseBackend::default(), DatabaseBackend::Lmdb);
    }

    #[test]
    fn test_memory_backend_uses_temp_dir_with_default_path() {
        // When git_data_path is the default value, memory backend uses temp dir
        let config = Config {
            database_backend: DatabaseBackend::Memory,
            git_data_path: "./data/git".to_string(), // Default value
            ..Config::for_testing()
        };
        let git_path = config.effective_git_data_path();
        assert!(git_path.contains("ngit-grasp-git"));
    }

    #[test]
    fn test_memory_backend_respects_custom_path() {
        // When git_data_path is explicitly set, memory backend respects it
        let config = Config {
            database_backend: DatabaseBackend::Memory,
            git_data_path: "./custom/git/path".to_string(),
            ..Config::for_testing()
        };
        let git_path = config.effective_git_data_path();
        assert_eq!(git_path, "./custom/git/path");
    }

    #[test]
    fn test_lmdb_backend_uses_configured_path() {
        let config = Config {
            database_backend: DatabaseBackend::Lmdb,
            git_data_path: "./my/git/path".to_string(),
            relay_data_path: "./my/relay/path".to_string(),
            ..Config::for_testing()
        };
        assert_eq!(config.effective_git_data_path(), "./my/git/path");
    }

    #[test]
    fn test_database_backend_display() {
        assert_eq!(DatabaseBackend::Memory.to_string(), "memory");
        assert_eq!(DatabaseBackend::Lmdb.to_string(), "lmdb");
    }

    #[test]
    fn test_relay_name_default() {
        let config = Config {
            domain: "example.com".to_string(),
            relay_name_override: None,
            ..Config::for_testing()
        };
        assert_eq!(config.relay_name(), "example.com grasp relay");
    }

    #[test]
    fn test_relay_name_override() {
        let config = Config {
            domain: "example.com".to_string(),
            relay_name_override: Some("My Custom Relay".to_string()),
            ..Config::for_testing()
        };
        assert_eq!(config.relay_name(), "My Custom Relay");
    }

    #[test]
    fn test_relay_owner_keys() {
        let config = Config::for_testing();
        let keys = config.relay_owner_keys().expect("Should have valid keys");
        let npub = config.relay_owner_npub().expect("Should derive npub");

        // Verify the npub matches the keys
        assert_eq!(npub, keys.public_key().to_bech32().unwrap());
        assert!(npub.starts_with("npub1"));
    }

    #[test]
    fn test_relay_owner_nsec_trims_whitespace() {
        // Test that Config::load() trims whitespace from provided nsec
        // This simulates what happens when nsec is read from a file with trailing newline
        let nsec_clean = "nsec1rt5f3gfnktvd77fdarg00ff94l8j833y778ym3xlzkx89g9v5zvq4y2qee";
        let nsec_with_newline = format!("{}\n", nsec_clean);
        let nsec_with_spaces = format!("  {}  ", nsec_clean);

        // Test that trimming happens by directly creating config with whitespace
        let mut config1 = Config::for_testing();
        config1.relay_owner_nsec = Some(nsec_with_newline.clone());
        // Simulate what Config::load() does
        config1.relay_owner_nsec = config1.relay_owner_nsec.map(|s| s.trim().to_string());

        let mut config2 = Config::for_testing();
        config2.relay_owner_nsec = Some(nsec_with_spaces.clone());
        config2.relay_owner_nsec = config2.relay_owner_nsec.map(|s| s.trim().to_string());

        // Both should parse successfully after trimming
        assert!(config1.relay_owner_keys().is_ok());
        assert!(config2.relay_owner_keys().is_ok());

        // Both should produce the same public key
        let keys1 = config1.relay_owner_keys().unwrap();
        let keys2 = config2.relay_owner_keys().unwrap();
        assert_eq!(keys1.public_key(), keys2.public_key());

        // Verify trimmed nsec equals clean nsec
        assert_eq!(config1.relay_owner_nsec.unwrap(), nsec_clean);
        assert_eq!(config2.relay_owner_nsec.unwrap(), nsec_clean);
    }

    #[test]
    fn test_metrics_config_defaults() {
        let config = Config::for_testing();
        assert!(config.metrics_enabled);
        assert_eq!(config.metrics_connection_per_ip_abuse_threshold, 10);
        assert_eq!(config.metrics_top_n_repos, 10);
    }

    #[test]
    fn test_metrics_config_custom_values() {
        let config = Config {
            metrics_enabled: false,
            metrics_connection_per_ip_abuse_threshold: 50,
            metrics_top_n_repos: 25,
            ..Config::for_testing()
        };
        assert!(!config.metrics_enabled);
        assert_eq!(config.metrics_connection_per_ip_abuse_threshold, 50);
        assert_eq!(config.metrics_top_n_repos, 25);
    }

    #[test]
    fn test_parse_whitelist_entry_pubkey() {
        // Generate a valid test npub
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let entry = WhitelistEntry::parse(&test_npub).unwrap();
        assert!(matches!(entry, WhitelistEntry::Pubkey(_)));
        if let WhitelistEntry::Pubkey(npub) = entry {
            assert_eq!(npub, test_npub);
        }
    }

    #[test]
    fn test_parse_whitelist_entry_repository() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let entry = WhitelistEntry::parse(&format!("{}/linux", test_npub)).unwrap();
        assert!(matches!(entry, WhitelistEntry::Repository { .. }));
        if let WhitelistEntry::Repository { npub, identifier } = entry {
            assert_eq!(npub, test_npub);
            assert_eq!(identifier, "linux");
        }
    }

    #[test]
    fn test_parse_whitelist_entry_identifier() {
        let entry = WhitelistEntry::parse("bitcoin-core").unwrap();
        assert!(matches!(entry, WhitelistEntry::Identifier(_)));
        if let WhitelistEntry::Identifier(id) = entry {
            assert_eq!(id, "bitcoin-core");
        }
    }

    #[test]
    fn test_parse_whitelist_entry_invalid_npub() {
        let result = WhitelistEntry::parse("npub1invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_whitelist_entry_matches() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let entry = WhitelistEntry::Pubkey(test_npub.clone());
        assert!(entry.matches(&test_npub, "any-identifier"));
        assert!(!entry.matches("npub1different", "any-identifier"));
    }

    #[test]
    fn test_whitelist_entry_matches_repository() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let entry = WhitelistEntry::Repository {
            npub: test_npub.clone(),
            identifier: "linux".to_string(),
        };
        assert!(entry.matches(&test_npub, "linux"));
        assert!(!entry.matches(&test_npub, "bitcoin"));
        assert!(!entry.matches("npub1different", "linux"));
    }

    #[test]
    fn test_whitelist_entry_matches_identifier() {
        let entry = WhitelistEntry::Identifier("bitcoin-core".to_string());
        assert!(entry.matches("npub1alice", "bitcoin-core"));
        assert!(entry.matches("npub1bob", "bitcoin-core"));
        assert!(!entry.matches("npub1alice", "other-repo"));
    }

    #[test]
    fn test_archive_config_enabled() {
        let config = ArchiveConfig::default();
        assert!(!config.enabled());

        let config = ArchiveConfig {
            archive_all: true,
            whitelist: Vec::new(),
            grasp_services: Vec::new(),
            read_only: true,
        };
        assert!(config.enabled());

        let config = ArchiveConfig {
            archive_all: false,
            whitelist: vec![WhitelistEntry::Identifier("test".into())],
            grasp_services: Vec::new(),
            read_only: true,
        };
        assert!(config.enabled());
    }

    #[test]
    fn test_archive_config_matches() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = ArchiveConfig {
            archive_all: false,
            whitelist: vec![
                WhitelistEntry::Pubkey(test_npub.clone()),
                WhitelistEntry::Identifier("bitcoin-core".into()),
            ],
            grasp_services: Vec::new(),
            read_only: false,
        };

        assert!(config.matches(&test_npub, "any-repo"));
        assert!(config.matches("npub1bob", "bitcoin-core"));
        assert!(!config.matches("npub1bob", "other-repo"));
    }

    #[test]
    fn test_archive_config_matches_archive_all() {
        let config = ArchiveConfig {
            archive_all: true,
            whitelist: Vec::new(),
            grasp_services: Vec::new(),
            read_only: true,
        };

        assert!(config.matches("npub1alice", "any-repo"));
        assert!(config.matches("npub1bob", "other-repo"));
    }

    #[test]
    fn test_parse_whitelist_empty() {
        let whitelist = WhitelistEntry::parse_whitelist("");
        assert!(whitelist.is_empty());

        let whitelist = WhitelistEntry::parse_whitelist("   ");
        assert!(whitelist.is_empty());
    }

    #[test]
    fn test_parse_whitelist_multiple() {
        let keys1 = Keys::generate();
        let keys2 = Keys::generate();
        let test_npub1 = keys1.public_key().to_bech32().unwrap();
        let test_npub2 = keys2.public_key().to_bech32().unwrap();
        let whitelist = WhitelistEntry::parse_whitelist(&format!(
            "{},bitcoin-core,{}/linux",
            test_npub1, test_npub2
        ));
        assert_eq!(whitelist.len(), 3);
    }

    #[test]
    fn test_parse_whitelist_invalid_npub_skipped() {
        // Invalid entries should be skipped with warnings, not fail
        let whitelist = WhitelistEntry::parse_whitelist("npub1invalid,bitcoin-core");
        assert_eq!(whitelist.len(), 1); // Only bitcoin-core should be parsed
        assert!(matches!(
            &whitelist[0],
            WhitelistEntry::Identifier(id) if id == "bitcoin-core"
        ));
    }

    #[test]
    fn test_archive_config_parsing() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = Config {
            archive_whitelist: format!("{},bitcoin-core", test_npub),
            ..Config::for_testing()
        };
        let archive_config = config.archive_config();
        assert_eq!(archive_config.whitelist.len(), 2);
    }

    #[test]
    fn test_archive_read_only_defaults() {
        // Default: false when no archive mode
        let config = Config::for_testing();
        assert!(!config.archive_config().read_only);

        // Default: true when archive_all is set
        let config = Config {
            archive_all: true,
            ..Config::for_testing()
        };
        assert!(config.archive_config().read_only);

        // Default: true when archive_whitelist is set
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = Config {
            archive_whitelist: test_npub,
            ..Config::for_testing()
        };
        assert!(config.archive_config().read_only);
    }

    #[test]
    fn test_archive_read_only_explicit() {
        // Explicit true with archive_all
        let config = Config {
            archive_all: true,
            archive_read_only: Some(true),
            ..Config::for_testing()
        };
        assert!(config.archive_config().read_only);

        // Explicit false with archive_all (unusual but allowed)
        let config = Config {
            archive_all: true,
            archive_read_only: Some(false),
            ..Config::for_testing()
        };
        assert!(!config.archive_config().read_only);

        // Explicit false without archive mode
        let config = Config {
            archive_read_only: Some(false),
            ..Config::for_testing()
        };
        assert!(!config.archive_config().read_only);
    }

    #[test]
    fn test_archive_read_only_validation_error() {
        // Error: true without archive mode should fail validation
        let config = Config {
            archive_read_only: Some(true),
            ..Config::for_testing()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires either"));
    }

    #[test]
    fn test_repository_whitelist_parsing() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = Config {
            repository_whitelist: format!("{},bitcoin-core", test_npub),
            ..Config::for_testing()
        };
        let repo_config = config.repository_config();
        assert_eq!(repo_config.whitelist.len(), 2);
        assert!(repo_config.enabled());
    }

    #[test]
    fn test_repository_whitelist_empty() {
        let config = Config::for_testing();
        let repo_config = config.repository_config();
        assert!(repo_config.whitelist.is_empty());
        assert!(!repo_config.enabled());
    }

    #[test]
    fn test_repository_whitelist_validation_incompatible_with_archive_read_only() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = Config {
            archive_all: true,
            archive_read_only: Some(true),
            repository_whitelist: test_npub,
            ..Config::for_testing()
        };
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot be used with"));
        assert!(err.contains("NGIT_ARCHIVE_READ_ONLY=true"));
    }

    #[test]
    fn test_repository_whitelist_compatible_with_archive_read_only_false() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = Config {
            archive_all: true,
            archive_read_only: Some(false),
            repository_whitelist: test_npub,
            ..Config::for_testing()
        };
        // Should not error on validation
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_repository_config_matches() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = RepositoryConfig {
            whitelist: vec![
                WhitelistEntry::Pubkey(test_npub.clone()),
                WhitelistEntry::Identifier("bitcoin-core".into()),
            ],
        };

        assert!(config.matches(&test_npub, "any-repo"));
        assert!(config.matches("npub1bob", "bitcoin-core"));
        assert!(!config.matches("npub1bob", "other-repo"));
    }

    #[test]
    fn test_validate_success_with_valid_config() {
        // Valid config should pass validation
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = Config {
            archive_whitelist: format!("{},bitcoin-core", test_npub),
            archive_read_only: Some(false),
            repository_whitelist: "rust".to_string(),
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_with_all_invalid_whitelist_entries() {
        // All invalid entries should be skipped with warnings, but validation should succeed
        let config = Config {
            archive_whitelist: "npub1invalid,npub1bad,npub1wrong".to_string(),
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
        // All entries should be skipped
        let archive_config = config.archive_config();
        assert_eq!(archive_config.whitelist.len(), 0);
        assert!(!archive_config.enabled());
    }

    #[test]
    fn test_validate_with_mixed_valid_invalid_entries() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        // Mixed valid and invalid entries - should keep valid ones
        let config = Config {
            repository_whitelist: format!("npub1invalid,{},bitcoin-core,npub1bad", test_npub),
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
        let repo_config = config.repository_config();
        // Should have 2 valid entries: the test_npub and bitcoin-core
        assert_eq!(repo_config.whitelist.len(), 2);
    }

    #[test]
    fn test_whitelist_entry_with_extra_whitespace() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        // Whitespace should be trimmed
        let whitelist =
            WhitelistEntry::parse_whitelist(&format!("  {} , bitcoin-core  ,  rust  ", test_npub));
        assert_eq!(whitelist.len(), 3);
    }

    #[test]
    fn test_archive_config_with_all_invalid_entries_not_enabled() {
        // If all whitelist entries are invalid, archive mode should not be enabled
        let config = Config {
            archive_whitelist: "npub1invalid,npub1bad".to_string(),
            ..Config::for_testing()
        };
        let archive_config = config.archive_config();
        assert!(!archive_config.enabled());
        assert_eq!(archive_config.whitelist.len(), 0);
    }

    #[test]
    fn test_validate_detects_invalid_relay_owner_nsec() {
        // Invalid nsec should fail validation
        let config = Config {
            relay_owner_nsec: Some("nsec1invalid".to_string()),
            ..Config::for_testing()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid relay_owner_nsec"));
    }

    #[test]
    fn test_validate_requires_relay_owner_nsec() {
        // Missing nsec should fail validation
        let config = Config {
            relay_owner_nsec: None,
            ..Config::for_testing()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("relay_owner_nsec not set"));
    }

    #[test]
    fn test_blacklist_config_parsing() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = Config {
            repository_blacklist: format!("{},bitcoin-core", test_npub),
            ..Config::for_testing()
        };
        let blacklist_config = config.blacklist_config();
        assert_eq!(blacklist_config.blacklist.len(), 2);
        assert!(blacklist_config.enabled());
    }

    #[test]
    fn test_blacklist_config_empty() {
        let config = Config::for_testing();
        let blacklist_config = config.blacklist_config();
        assert!(blacklist_config.blacklist.is_empty());
        assert!(!blacklist_config.enabled());
    }

    #[test]
    fn test_blacklist_check_npub() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = BlacklistConfig {
            blacklist: vec![WhitelistEntry::Pubkey(test_npub.clone())],
        };

        let result = config.check(&test_npub, "any-repo");
        assert!(result.is_some());
        let reason = result.unwrap();
        assert!(reason.contains("owner"));
        assert!(reason.contains(&test_npub));
    }

    #[test]
    fn test_blacklist_check_identifier() {
        let config = BlacklistConfig {
            blacklist: vec![WhitelistEntry::Identifier("banned-repo".to_string())],
        };

        let result = config.check("npub1alice", "banned-repo");
        assert!(result.is_some());
        let reason = result.unwrap();
        assert!(reason.contains("identifier"));
        assert!(reason.contains("banned-repo"));
    }

    #[test]
    fn test_blacklist_check_repository() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = BlacklistConfig {
            blacklist: vec![WhitelistEntry::Repository {
                npub: test_npub.clone(),
                identifier: "specific-repo".to_string(),
            }],
        };

        let result = config.check(&test_npub, "specific-repo");
        assert!(result.is_some());
        let reason = result.unwrap();
        assert!(reason.contains(&test_npub));
        assert!(reason.contains("specific-repo"));
    }

    #[test]
    fn test_blacklist_check_not_blacklisted() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = BlacklistConfig {
            blacklist: vec![WhitelistEntry::Identifier("banned-repo".to_string())],
        };

        let result = config.check(&test_npub, "allowed-repo");
        assert!(result.is_none());
    }

    #[test]
    fn test_event_blacklist_config_parsing() {
        let keys1 = Keys::generate();
        let keys2 = Keys::generate();
        let npub1 = keys1.public_key().to_bech32().unwrap();
        let npub2 = keys2.public_key().to_bech32().unwrap();
        let config = Config {
            event_blacklist: format!("{},{}", npub1, npub2),
            ..Config::for_testing()
        };
        let event_blacklist_config = config.event_blacklist_config();
        assert_eq!(event_blacklist_config.blacklisted_npubs.len(), 2);
        assert!(event_blacklist_config.enabled());
        assert!(event_blacklist_config.blacklisted_npubs.contains(&npub1));
        assert!(event_blacklist_config.blacklisted_npubs.contains(&npub2));
    }

    #[test]
    fn test_event_blacklist_config_empty() {
        let config = Config::for_testing();
        let event_blacklist_config = config.event_blacklist_config();
        assert!(event_blacklist_config.blacklisted_npubs.is_empty());
        assert!(!event_blacklist_config.enabled());
    }

    #[test]
    fn test_deletion_request_disrespector_default() {
        let config = Config::for_testing();
        assert!(!config.deletion_request_disrespector);
    }

    #[test]
    fn test_deletion_request_disrespector_enabled() {
        let config = Config {
            deletion_request_disrespector: true,
            ..Config::for_testing()
        };
        assert!(config.deletion_request_disrespector);
    }

    #[test]
    fn test_event_blacklist_check_blacklisted() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = EventBlacklistConfig {
            blacklisted_npubs: vec![test_npub.clone()],
        };

        let result = config.check(&test_npub);
        assert!(result.is_some());
        let reason = result.unwrap();
        assert!(reason.contains("author"));
        assert!(reason.contains(&test_npub));
    }

    #[test]
    fn test_event_blacklist_check_not_blacklisted() {
        let keys1 = Keys::generate();
        let keys2 = Keys::generate();
        let banned_npub = keys1.public_key().to_bech32().unwrap();
        let allowed_npub = keys2.public_key().to_bech32().unwrap();
        let config = EventBlacklistConfig {
            blacklisted_npubs: vec![banned_npub],
        };

        let result = config.check(&allowed_npub);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_archive_grasp_services_empty() {
        let config = Config::for_testing();
        let services = config.parse_archive_grasp_services();
        assert!(services.is_empty());

        let config = Config {
            archive_grasp_services: "   ".to_string(),
            ..Config::for_testing()
        };
        let services = config.parse_archive_grasp_services();
        assert!(services.is_empty());
    }

    #[test]
    fn test_parse_archive_grasp_services_single() {
        let config = Config {
            archive_grasp_services: "git.example.com".to_string(),
            ..Config::for_testing()
        };
        let services = config.parse_archive_grasp_services();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0], "git.example.com");
    }

    #[test]
    fn test_parse_archive_grasp_services_multiple() {
        let config = Config {
            archive_grasp_services: "git.example.com,git.nostr.dev,relay.gitnostr.com".to_string(),
            ..Config::for_testing()
        };
        let services = config.parse_archive_grasp_services();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0], "git.example.com");
        assert_eq!(services[1], "git.nostr.dev");
        assert_eq!(services[2], "relay.gitnostr.com");
    }

    #[test]
    fn test_parse_archive_grasp_services_with_whitespace() {
        let config = Config {
            archive_grasp_services: "  git.example.com , git.nostr.dev  ,  relay.gitnostr.com  "
                .to_string(),
            ..Config::for_testing()
        };
        let services = config.parse_archive_grasp_services();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0], "git.example.com");
        assert_eq!(services[1], "git.nostr.dev");
        assert_eq!(services[2], "relay.gitnostr.com");
    }

    #[test]
    fn test_archive_grasp_services_validation_error_with_archive_all() {
        let config = Config {
            archive_all: true,
            archive_grasp_services: "git.example.com".to_string(),
            ..Config::for_testing()
        };
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("NGIT_ARCHIVE_GRASP_SERVICES"));
        assert!(err.contains("NGIT_ARCHIVE_ALL"));
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn test_archive_grasp_services_validation_error_with_archive_whitelist() {
        let keys = Keys::generate();
        let test_npub = keys.public_key().to_bech32().unwrap();
        let config = Config {
            archive_whitelist: test_npub,
            archive_grasp_services: "git.example.com".to_string(),
            ..Config::for_testing()
        };
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("NGIT_ARCHIVE_GRASP_SERVICES"));
        assert!(err.contains("NGIT_ARCHIVE_WHITELIST"));
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn test_archive_grasp_services_enables_archive_mode() {
        let config = Config {
            archive_grasp_services: "git.example.com".to_string(),
            ..Config::for_testing()
        };
        let archive_config = config.archive_config();
        assert!(archive_config.enabled());
        assert!(archive_config.read_only); // Default to true
    }

    #[test]
    fn test_archive_grasp_services_read_only_default() {
        // Default: true when archive_grasp_services is set
        let config = Config {
            archive_grasp_services: "git.example.com".to_string(),
            ..Config::for_testing()
        };
        assert!(config.archive_config().read_only);
    }

    #[test]
    fn test_archive_grasp_services_read_only_explicit_false() {
        // Explicit false should be respected
        let config = Config {
            archive_grasp_services: "git.example.com".to_string(),
            archive_read_only: Some(false),
            ..Config::for_testing()
        };
        assert!(!config.archive_config().read_only);
    }

    #[test]
    fn test_archive_read_only_validation_with_grasp_services() {
        // Should succeed with archive_grasp_services set
        let config = Config {
            archive_grasp_services: "git.example.com".to_string(),
            archive_read_only: Some(true),
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_archive_config_matches_grasp_services() {
        let config = ArchiveConfig {
            archive_all: false,
            whitelist: Vec::new(),
            grasp_services: vec!["git.example.com".to_string(), "gitlab.org".to_string()],
            read_only: true,
        };

        // Should match configured services
        assert!(config.matches_grasp_services(&["git.example.com".to_string()]));
        assert!(config.matches_grasp_services(&["gitlab.org".to_string()]));

        // Should not match unconfigured services
        assert!(!config.matches_grasp_services(&["github.com".to_string()]));
        assert!(!config.matches_grasp_services(&["other.com".to_string()]));
    }

    #[test]
    fn test_archive_config_matches_grasp_services_empty() {
        let config = ArchiveConfig {
            archive_all: false,
            whitelist: Vec::new(),
            grasp_services: Vec::new(),
            read_only: true,
        };

        // Should not match anything when grasp_services is empty
        assert!(!config.matches_grasp_services(&["git.example.com".to_string()]));
        assert!(!config.matches_grasp_services(&[]));
    }

    #[test]
    fn test_archive_config_matches_grasp_services_multiple_domains() {
        let config = ArchiveConfig {
            archive_all: false,
            whitelist: Vec::new(),
            grasp_services: vec!["git.example.com".to_string()],
            read_only: true,
        };

        // Should match if any domain matches
        assert!(config.matches_grasp_services(&[
            "github.com".to_string(),
            "git.example.com".to_string(),
            "gitlab.org".to_string(),
        ]));

        // Should not match if no domain matches
        assert!(
            !config.matches_grasp_services(&["github.com".to_string(), "gitlab.org".to_string(),])
        );
    }
}
