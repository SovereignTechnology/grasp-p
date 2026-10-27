use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use ipnet::IpNet;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

const RELAY_OWNER_NSEC_ENV: &str = "NGIT_RELAY_OWNER_NSEC";
const RELAY_OWNER_NSEC_CREDENTIAL: &str = "relay_owner_nsec";
const DEFAULT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS: u64 =
    180 * 24 * 60 * 60;
// Retention months are fixed 30-day periods, avoiding calendar-month ambiguity.
const DEFAULT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS: u64 = 270 * 24 * 60 * 60;
const DEFAULT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS: u64 =
    90 * 24 * 60 * 60;
const DEFAULT_USER_INDEX_RELAYS: &str =
    "wss://purplepag.es,wss://index.hzrd149.com,wss://indexer.coracle.social";
const DEFAULT_SYNC_PLUS_FALLBACK_RELAYS: &str =
    "wss://relay.ditto.pub,wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net";

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

/// GRASP-P private-repo registration admission mode for NEW aliases.
///
/// The shipped default is Whitelist (locked operator decision, server issue
/// !7: in open mode any fresh key receives the full per-tenant blob quota,
/// so ~50 pseudonymous tenants can lawfully exhaust the 50 GiB global
/// budget). Open is intended for staging/self-use only and must be selected
/// explicitly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationMode {
    /// Accept any tenant's new alias registrations (staging/self-use only).
    Open,
    /// Only tenants in NGIT_GRASP_P_TENANT_WHITELIST may register new aliases.
    #[default]
    Whitelist,
    /// New-alias 30640 events must carry NIP-13 proof of work.
    Pow,
    /// Paid registration (not yet available; selecting it fails validation).
    Paid,
}

impl std::fmt::Display for RegistrationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Whitelist => write!(f, "whitelist"),
            Self::Pow => write!(f, "pow"),
            Self::Paid => write!(f, "paid"),
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

    /// Public URL path where this instance is mounted.
    ///
    /// Use `/` for a domain-root deployment or an absolute path such as
    /// `/grasp` when sharing a domain with another service.
    #[arg(long, env = "NGIT_BASE_PATH", default_value = "/")]
    pub base_path: String,

    /// Relay operator's nsec (private key) for signing and authentication.
    ///
    /// Used for:
    /// - NIP-05 `_@domain` well-known identity when served at the domain root
    /// - Signing the minimal kind-0 bot profile and kind-10002 relay list published at startup
    /// - Trusted admission of service events authored by this identity (for example, ngit-ci)
    /// - NIP-11 relay information document (pubkey field derived from this nsec)
    /// - NIP-42 authentication when syncing from other relays
    /// - Future: WoT-based rate limiting of syncing relays
    ///
    /// Loaded from the `relay_owner_nsec` systemd credential,
    /// `NGIT_RELAY_OWNER_NSEC`, or `.relay-owner.nsec`; never accepted on argv.
    #[arg(skip)]
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

    /// Restrict automatic startup integrity passes to these repository identifiers.
    ///
    /// Empty by default, which checks every installed identifier family. This is
    /// intended only for staged validation before a full production sweep.
    #[arg(
        long,
        env = "NGIT_STARTUP_INTEGRITY_IDENTIFIERS",
        value_delimiter = ','
    )]
    pub startup_integrity_identifiers: Vec<String>,

    /// Server bind address (IP:PORT)
    #[arg(long, env = "NGIT_BIND_ADDRESS", default_value = "127.0.0.1:7334")]
    pub bind_address: String,

    /// Proxy address ranges allowed to supply client IP forwarding headers.
    ///
    /// Empty by default so forwarded headers from direct clients are ignored.
    #[arg(long, env = "NGIT_TRUSTED_PROXY_CIDRS", value_delimiter = ',')]
    pub trusted_proxy_cidrs: Vec<IpNet>,

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

    /// Enable GRASP-03 Sync+ mailbox discovery on top of proactive GRASP-02 sync.
    #[arg(
        long,
        env = "NGIT_SYNC_PLUS_ENABLED",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub sync_plus_enabled: bool,

    /// Comma-separated relays used to publish the relay-owner identity and to discover
    /// eligible accepted repository participants' NIP-65 relay lists.
    #[arg(
        long,
        env = "NGIT_USER_INDEX_RELAYS",
        default_value = DEFAULT_USER_INDEX_RELAYS
    )]
    pub user_index_relays: String,

    /// Comma-separated inbox fallbacks for eligible authors whose NIP-65 relay list is absent.
    #[arg(
        long,
        env = "NGIT_SYNC_PLUS_FALLBACK_RELAYS",
        default_value = DEFAULT_SYNC_PLUS_FALLBACK_RELAYS
    )]
    pub sync_plus_fallback_relays: String,

    /// Soft limit on recursive query-frontier members below each event which directly tags
    /// a repository root. Direct root-tagging events are not counted.
    #[arg(
        long,
        env = "NGIT_SYNC_RECURSIVE_DESCENDANT_LIMIT",
        default_value_t = 500
    )]
    pub sync_recursive_descendant_limit: usize,

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

    /// Allow event-directed sync targets that are not globally reachable (default: false)
    ///
    /// Repository announcements and PR events are untrusted; by default their
    /// relay and clone URLs may only point at globally reachable hosts.
    /// Loopback, private, link-local and other special-purpose addresses,
    /// local hostnames, and hosts resolving to such addresses are rejected
    /// before any outbound connection or git fetch (SSRF protection).
    ///
    /// Setting this to true disables the reachability checks. Intended only
    /// for integration tests and closed development networks; production
    /// relays must leave it false. The operator-configured bootstrap relay is
    /// always allowed regardless of this setting.
    #[arg(
        long,
        env = "NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS",
        default_value_t = false
    )]
    pub sync_allow_non_global_targets: bool,

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

    // Retention is expressed in seconds for configuration consistency and short
    // tests. Production deployments are expected to use periods of at least one
    // day, comfortably exceeding worst-case deletion/archive processing time.
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

    /// Enable GRASP-08 private-service authentication.
    ///
    /// When enabled, every Nostr WebSocket session must authenticate with
    /// NIP-42 and every standard Git Smart HTTP request must carry the
    /// GRASP-08 repository-scoped NIP-98 credential.
    #[arg(long, env = "NGIT_PRIVATE_MODE", default_value_t = false)]
    pub private_mode: bool,

    /// Permanently configured GRASP-08 members as comma-separated npubs.
    ///
    /// The effective whitelist also includes NIP-11 owners of relays referenced
    /// by accepted repository announcements. Required and fail-closed when
    /// private mode is enabled.
    #[arg(long, env = "NGIT_PRIVATE_MEMBERS", default_value = "")]
    pub private_members: String,

    /// Canonical externally visible origin used by GRASP-08 NIP-98 `u` tags.
    ///
    /// Set this when TLS terminates upstream or a non-loopback deployment uses
    /// plain HTTP. When empty, the origin is inferred from `NGIT_DOMAIN`.
    #[arg(long, env = "NGIT_PRIVATE_PUBLIC_ORIGIN", default_value = "")]
    pub private_public_origin: String,

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

    /// Deletion request disrespector: ignore NIP-09 and NIP-62 requests (archival mode)
    ///
    /// When `true`, the relay stores incoming NIP-09 (kind 5) deletion requests and
    /// NIP-62 request-to-vanish events but does NOT act on them: their targets remain
    /// fully accessible. This makes the relay an archival server, preventing
    /// "left-pad" scenarios by ensuring at least some relays preserve deleted content.
    ///
    /// This setting ONLY affects NIP-09 and NIP-62 user-initiated requests.
    /// Policy-driven blacklist/whitelist deletion flows still run because they
    /// enforce local relay serving policy rather than client requests.
    ///
    /// When `true`, NIP-09 (`"deletion"`) and NIP-62 (`"request to vanish"`) are NOT
    /// advertised in the NIP-11 supported NIPs list so clients can discover that the
    /// relay does not honour either request type.
    #[arg(
        long,
        env = "NGIT_DELETION_REQUEST_DISRESPECTOR",
        default_value_t = false
    )]
    pub deletion_request_disrespector: bool,

    /// Maximum total connections to the relay (default: unlimited, defers to OS/infrastructure limits)
    #[arg(long, env = "NGIT_MAX_CONNECTIONS")]
    pub max_connections: Option<usize>,

    /// Maximum active REQ subscriptions per WebSocket connection
    #[arg(long, env = "NGIT_RELAY_MAX_SUBSCRIPTIONS", default_value_t = 500)]
    pub relay_max_subscriptions: usize,

    /// Maximum serialized event size in bytes
    #[arg(
        long,
        env = "NGIT_RELAY_MAX_EVENT_SIZE_BYTES",
        default_value_t = 192 * 1024
    )]
    pub relay_max_event_size_bytes: usize,

    /// Per-filter result cap, including when a filter omits limit
    #[arg(long, env = "NGIT_RELAY_FILTER_LIMIT", default_value_t = 500)]
    pub relay_filter_limit: usize,

    /// Application log level or an explicit tracing filter expression.
    /// Bare levels keep dependency logging at warn.
    #[arg(long, env = "NGIT_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    // ------------------------------------------------------------------
    // GRASP-P private repositories (all no-ops unless enable=true)
    // ------------------------------------------------------------------
    /// GRASP-P master switch: enable private repository hosting
    /// (30640/30641 + stream wraps 3359/23359, and 1059/21059 while
    /// NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND is on, + blob routes)
    #[arg(long, env = "NGIT_GRASP_P_REPOS_ENABLE", default_value_t = false)]
    pub private_repos_enable: bool,

    /// Admission mode for NEW private-repo aliases (open|whitelist|pow|paid).
    /// Defaults to whitelist (safe "accept nothing without an explicit
    /// tenant list" posture); open is staging/self-use only.
    #[arg(long, env = "NGIT_GRASP_P_REGISTRATION_MODE", value_enum, default_value_t = RegistrationMode::Whitelist)]
    pub private_registration_mode: RegistrationMode,

    /// NIP-13 bits required on kind-30640 registrations when mode=pow
    #[arg(long, env = "NGIT_GRASP_P_POW_BITS", default_value_t = 20)]
    pub private_pow_bits: u8,

    /// Comma-separated npubs allowed to register new aliases when mode=whitelist
    #[arg(long, env = "NGIT_GRASP_P_TENANT_WHITELIST", default_value = "")]
    pub private_tenant_whitelist: String,

    /// Per-blob size cap in bytes (enforced pre- and mid-stream)
    #[arg(
        long,
        env = "NGIT_GRASP_P_MAX_BLOB_BYTES",
        default_value_t = 268_435_456
    )]
    pub private_max_blob_bytes: u64,

    /// Serialized-JSON size cap for private-repo events (30640/30641 +
    /// stream wraps 3359/23359 and legacy 1059/21059)
    #[arg(long, env = "NGIT_GRASP_P_MAX_EVENT_BYTES", default_value_t = 131_072)]
    pub private_max_event_bytes: u64,

    /// Per hosting-npub total quota in bytes (events + blobs)
    #[arg(
        long,
        env = "NGIT_GRASP_P_QUOTA_TENANT_BYTES",
        default_value_t = 1_073_741_824
    )]
    pub private_quota_tenant_bytes: u64,

    /// Per-alias total quota in bytes (events + blobs)
    #[arg(
        long,
        env = "NGIT_GRASP_P_QUOTA_REPO_BYTES",
        default_value_t = 536_870_912
    )]
    pub private_quota_repo_bytes: u64,

    /// Whole private-subsystem storage cap in bytes
    #[arg(
        long,
        env = "NGIT_GRASP_P_GLOBAL_BUDGET_BYTES",
        default_value_t = 53_687_091_200
    )]
    pub private_global_budget_bytes: u64,

    /// Maximum registrations (aliases) per hosting npub
    #[arg(
        long,
        env = "NGIT_GRASP_P_MAX_ALIASES_PER_TENANT",
        default_value_t = 64
    )]
    pub private_max_aliases_per_tenant: u32,

    /// Maximum `w` + `aux` keys per alias registration
    #[arg(
        long,
        env = "NGIT_GRASP_P_MAX_WRITE_KEYS_PER_ALIAS",
        default_value_t = 64
    )]
    pub private_max_write_keys_per_alias: u32,

    /// Kind-30641 edition ring depth kept in the private meta store (G7 amendment)
    #[arg(
        long,
        env = "NGIT_GRASP_P_STATE_HISTORY_EDITIONS",
        default_value_t = 16
    )]
    pub private_state_history_editions: u32,

    /// Grace period in seconds before an unreferenced blob may be deleted by GC
    #[arg(long, env = "NGIT_GRASP_P_GC_GRACE_SECS", default_value_t = 86_400)]
    pub private_gc_grace_secs: u64,

    /// Interval in seconds between private blob GC passes
    #[arg(long, env = "NGIT_GRASP_P_GC_INTERVAL_SECS", default_value_t = 3_600)]
    pub private_gc_interval_secs: u64,

    /// Tombstoned-alias purge delay in seconds; not enforced yet (issue 1)
    #[arg(
        long,
        env = "NGIT_GRASP_P_OFFBOARD_RETENTION_SECS",
        default_value_t = 2_592_000
    )]
    pub private_offboard_retention_secs: u64,

    /// Blob store root (defaults to <relay_data_path>/blobs)
    #[arg(long, env = "NGIT_GRASP_P_BLOB_DATA_PATH")]
    pub private_blob_data_path: Option<String>,

    /// Private meta store (heed env) root (defaults to <relay_data_path>/private-meta)
    #[arg(long, env = "NGIT_GRASP_P_META_DATA_PATH")]
    pub private_meta_data_path: Option<String>,

    /// Optional denylist file(s): comma-separated paths, one sha256 per
    /// line; matching blob GETs return 451. A missing file is tolerated
    /// (warn + treated as empty) so per-jurisdiction lists can be mounted
    /// per node; a present-but-unreadable file is a hard boot error. Each
    /// file is capped (64 MiB / 1M lines); an over-cap file is a hard boot
    /// error and keeps its last-known entries on reload. Writers MUST
    /// update files atomically (write-temp-then-rename): the reload keys
    /// off mtime and a torn write is a known staleness window.
    #[arg(long, env = "NGIT_GRASP_P_DENYLIST_PATH")]
    pub private_denylist_path: Option<String>,

    /// Interval in seconds between denylist file reloads (0 = reload
    /// disabled; the boot-time set is kept). Hashes newly present after a
    /// reload trigger an immediate purge of the stored bytes; removed
    /// hashes unblock reads but purged bytes stay gone (re-upload needed).
    #[arg(long, env = "NGIT_GRASP_P_DENYLIST_RELOAD_SECS", default_value_t = 60)]
    pub private_denylist_reload_secs: u64,

    /// Private-repo mirroring (Phase 2; knob exists, unused in Phase 1)
    #[arg(long, env = "NGIT_GRASP_P_MIRROR_ENABLE", default_value_t = false)]
    pub private_mirror_enable: bool,

    /// Comma-separated peer blob-server base URLs for the Phase-2 mirror.
    /// Default (unset): derive peers from each registration's `server` tags
    /// (minus this node's own domain).
    #[arg(long, env = "NGIT_GRASP_P_MIRROR_PEER_URLS")]
    pub private_mirror_peer_urls: Option<String>,

    /// Maximum concurrent blob mirror fetches. One account holds at most
    /// half of them (rounded down, at least one).
    #[arg(long, env = "NGIT_GRASP_P_MIRROR_MAX_CONCURRENCY", default_value_t = 4)]
    pub private_mirror_max_concurrency: u32,

    /// How long, in seconds, a mirror peer may take to answer a request,
    /// and how long it may send nothing in the middle of a body. One
    /// request as a whole gets this time plus the blob's length divided by
    /// 256 KiB/s.
    #[arg(
        long,
        env = "NGIT_GRASP_P_MIRROR_FETCH_TIMEOUT_SECS",
        default_value_t = 120
    )]
    pub private_mirror_fetch_timeout_secs: u64,

    /// Comma-separated relay URLs of the nodes this one replicates private
    /// repositories with. GRASP-P events travel between these peers alone:
    /// only they are sent the private sync filters, and a GRASP-P event that
    /// relay sync brings from any other relay is refused. Tenant 30640
    /// `relays` tags are advisory metadata and never trigger a connection
    /// (SSRF / membership-map-leak guard). The relay in
    /// NGIT_SYNC_BOOTSTRAP_RELAY_URL is a peer only when it is listed here
    /// too. Unset (default): no peers, so no private-repo replication.
    #[arg(long, env = "NGIT_GRASP_P_SYNC_PEER_URLS")]
    pub private_sync_peer_urls: Option<String>,

    /// The pair's link is private: allow the blob mirror to fetch from peers
    /// that resolve to loopback/private/link-local IPs (and over plain http),
    /// and the relay connection to a configured private-sync peer over plain
    /// ws:// or on an internal IP. Only that connection is exempt from the
    /// outbound target policy. Default false: such peers are dropped and the
    /// node fetches only over https/wss from public hosts. Set true for a
    /// pair on a private network or for local testing. Set
    /// NGIT_GRASP_P_MIRROR_PEER_URLS with it: without that list the mirror
    /// takes its peers from registrations' `server` tags, which could then
    /// name an internal host.
    #[arg(
        long,
        env = "NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS",
        default_value_t = false
    )]
    pub private_mirror_allow_private_ips: bool,

    /// Also accept the LEGACY stream-wrap kinds 1059/21059 alongside the
    /// dedicated CORD stream-wrap kinds 3359/23359. Default true: a node
    /// must accept 3359 BEFORE any client emits it, and legacy wraps
    /// already published (or held for out-of-order reprocess) must keep
    /// draining. Set false only once every client on this node has
    /// migrated — the legacy kinds are then RETIRED: while private repos
    /// are enabled a 1059/21059 is refused outright ("restricted: legacy
    /// stream-wrap kind is not accepted on this node"). It is deliberately
    /// NOT reclassified onto the public related-event path: that path would
    /// store an `a`/`e`-tagged 1059 from ANY key — no §3.2 registered-key
    /// gate, no private_max_event_bytes cap, no private quota charge, never
    /// swept by the private GC — i.e. WIDER than the default, which rejects
    /// unregistered 1059s outright. Nodes with private repos disabled are
    /// unaffected (1059 keeps its vanilla public handling).
    /// Cross-node acceptance knob — part of the policy_fingerprint
    /// preimage (v3).
    #[arg(
        long,
        env = "NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND",
        default_value_t = true
    )]
    pub private_accept_legacy_wrap_kind: bool,

    /// Per-write-key token bucket capacity for CLIENT-submitted private
    /// writes (kind 30641 + stream-wrap events + blob PUTs). 0 = unlimited
    /// (limiter disabled). The default is deliberately generous: legitimate
    /// client flows — including cord-git widen→narrow key rotations — must
    /// never trip it; only abuse floods (e.g. quota-uncharged ephemeral
    /// stream-wrap spam) get capped. Node-local DoS protection only: synced/replayed traffic
    /// bypasses it, so it has no cross-node convergence impact.
    #[arg(long, env = "NGIT_GRASP_P_WRITE_RATE_CAPACITY", default_value_t = 120)]
    pub private_write_rate_capacity: u32,

    /// Refill rate (tokens per minute) for the per-write-key client write
    /// bucket. Must be > 0 when NGIT_GRASP_P_WRITE_RATE_CAPACITY is non-zero.
    #[arg(
        long,
        env = "NGIT_GRASP_P_WRITE_RATE_REFILL_PER_MIN",
        default_value_t = 60
    )]
    pub private_write_rate_refill_per_min: u32,

    /// Blob uploads one account may have in flight at the same time, counted
    /// by the tenant key of the alias the upload's authorization names. One
    /// more is refused with 429 and Retry-After until one of the account's
    /// uploads ends. 0 = no cap per account. The node as a whole serves at
    /// most 64 client uploads at once (not configurable; a full node answers
    /// 503 with Retry-After), so a value of 64 or more lets one account take
    /// every slot. The blob mirror is not counted. Node-local protection: it
    /// changes when a client is told to wait, never what the node accepts, so
    /// it is NOT part of the policy_fingerprint preimage.
    #[arg(long, env = "NGIT_GRASP_P_MAX_UPLOADS_PER_TENANT", default_value_t = 8)]
    pub private_max_uploads_per_tenant: u32,

    /// Slowest average rate, in bytes per second, at which the body of a
    /// PUT /upload may arrive. An upload gets 30 seconds plus its declared
    /// length divided by this rate, and is cut with 408 when that time is
    /// up. 0 = no such deadline. Separately, and whatever this value, an
    /// upload that sends nothing for 30 seconds is cut. Node-local
    /// protection: NOT part of the policy_fingerprint preimage.
    #[arg(
        long,
        env = "NGIT_GRASP_P_UPLOAD_MIN_BYTES_PER_SEC",
        default_value_t = 16384
    )]
    pub private_upload_min_bytes_per_sec: u64,

    /// Per-(tenant, alias) token bucket capacity for same-tenant kind-30640
    /// REPLACEMENTS (free addressable replacements re-trigger sync index
    /// rebuilds + filter re-issues to all peers within seconds). 0 =
    /// unlimited. The burst MUST stay >= 4: a §3.3 revocation rotation is
    /// widen->narrow = 2 replacements in quick succession, plus client error
    /// retries. A rejected replacement is HELD locally and retried after
    /// bucket refill (the hourly re-issue is the backstop healer).
    /// Cross-node acceptance knob — part of the policy_fingerprint
    /// preimage (v3).
    #[arg(
        long,
        env = "NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY",
        default_value_t = 8
    )]
    pub private_registration_replace_capacity: u32,

    /// Refill rate (replacements per hour) for the per-(tenant, alias)
    /// replacement bucket — bounds SUSTAINED replacement floods. Must be > 0
    /// when NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY is non-zero.
    #[arg(
        long,
        env = "NGIT_GRASP_P_REGISTRATION_REPLACE_REFILL_PER_HOUR",
        default_value_t = 4
    )]
    pub private_registration_replace_refill_per_hour: u32,

    /// Interval (seconds) for the periodic since=None full re-issue of the
    /// private sync filters (Layer-1 kind-30640 + the current derived
    /// 30641/1059 filters) to every live peer, with a small random jitter to
    /// avoid cross-node lockstep. Heals delivery gaps that otherwise only a
    /// reconnect or daily_sync fixes: expired rejected-hot-cache entries,
    /// negentropy blind spots, and cadence-limited 30640 rejections (WP-A
    /// A2) that deliberately rely on redelivery. 0 = disabled. Node-local
    /// recovery knob only — acceptance is unaffected, so it is NOT part of
    /// the policy_fingerprint preimage.
    #[arg(
        long,
        env = "NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS",
        default_value_t = 3600
    )]
    pub private_full_reissue_interval_secs: u64,

    /// Minimum interval (seconds) between private sync-filter re-issues to
    /// the same peer, across BOTH triggers (PrivateSyncIndex-change-derived
    /// filter pushes and the hourly full re-issue). Bounds how often a
    /// churning derived-filter set can force a full consolidate
    /// (unsubscribe-all + resubscribe + since=None backfill) on a peer:
    /// past CONSOLIDATION_THRESHOLD derived filters, every index-dirty 5s
    /// tick used to consolidate again (~near-continuous at 128 aliases x
    /// 4/hour cadence). A re-issue skipped by this floor is retried once
    /// the interval lapses (never dropped). 0 = unlimited (pre-FS-3
    /// behavior). Node-local recovery knob only — acceptance is unaffected,
    /// so it is NOT part of the policy_fingerprint preimage.
    #[arg(
        long,
        env = "NGIT_GRASP_P_REISSUE_MIN_INTERVAL_SECS",
        default_value_t = 30
    )]
    pub private_reissue_min_interval_secs: u64,

    /// Base delay (seconds) for the blob mirror's per-blob exponential
    /// retry backoff: after n consecutive fetch failures the next attempt
    /// waits base * 2^(n-1) (capped at NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS,
    /// ±20% jitter). Every failed fetch is retried on a schedule. This one
    /// is for failures that may heal by themselves or by a change on this
    /// node (transport errors, any peer status but 404, no peer, quota,
    /// reserve, sink, write, store); the others (404 from every peer,
    /// blocked, verify, too_large) always wait the max interval. Node-local
    /// recovery knob — NOT part of the policy_fingerprint preimage.
    #[arg(
        long,
        env = "NGIT_GRASP_P_MIRROR_RETRY_BASE_SECS",
        default_value_t = 60
    )]
    pub private_mirror_retry_base_secs: u64,

    /// Cap (seconds) for the blob mirror retry backoff; also the fixed
    /// retry interval for the failures that do not heal by themselves (404
    /// from every peer, blocked, verify, too_large). Must be at least
    /// NGIT_GRASP_P_MIRROR_RETRY_BASE_SECS.
    #[arg(
        long,
        env = "NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS",
        default_value_t = 3600
    )]
    pub private_mirror_retry_max_secs: u64,

    /// Blobs the mirror may start fetching per minute, over all accounts
    /// together. One attempt is one missing blob tried against its peers.
    /// The node may start that many at once after a quiet spell and that
    /// many per minute from then on; a blob that has to wait is fetched as
    /// soon as the budget allows, never dropped. 0 = unlimited. It bounds
    /// what retries cost when many blobs keep failing; the retry backoff
    /// bounds each blob by itself. Node-local: it decides when this node
    /// fetches, never what it accepts, so it is NOT part of the
    /// policy_fingerprint preimage.
    #[arg(
        long,
        env = "NGIT_GRASP_P_MIRROR_MAX_ATTEMPTS_PER_MIN",
        default_value_t = 600
    )]
    pub private_mirror_max_attempts_per_min: u32,

    /// Loopback address (IP:PORT, for example 127.0.0.1:9464) on which a
    /// node with GRASP-P enabled serves its Prometheus scrape. Such a node
    /// never answers /metrics on the public listener: the scrape counts
    /// private repositories, stored bytes, takedowns and reports. Unset
    /// (default) or empty: the metrics are collected and served nowhere.
    /// Must be an IP literal on loopback, never a host name, and needs
    /// NGIT_METRICS_ENABLED=true; anything else is a startup error, and so
    /// is an address that cannot be bound. Ignored while GRASP-P is
    /// disabled. Loopback is not authentication: any local process can read
    /// the scrape. The scrape is answered only when the Host header of the
    /// request is a loopback address or localhost, and a connection that
    /// sends no request for 30 seconds is closed. Node-local, so it is NOT
    /// part of the policy_fingerprint preimage.
    #[arg(long, env = "NGIT_GRASP_P_METRICS_BIND")]
    pub private_metrics_bind: Option<String>,
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

        config.relay_owner_nsec = Some(Self::load_relay_owner_key()?);

        Ok(config)
    }

    /// Load the relay owner key without ever accepting the secret on argv.
    ///
    /// A systemd credential is the most deliberate provision, followed by the
    /// environment (including `.env` loaded by [`Self::load`]), then the
    /// persistent `.relay-owner.nsec` file.
    pub fn load_relay_owner_key() -> Result<String> {
        let credentials_dir = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
        let env_value = std::env::var(RELAY_OWNER_NSEC_ENV).ok();
        Self::load_relay_owner_key_from_sources(
            credentials_dir.as_deref(),
            env_value,
            Self::load_or_generate_relay_owner_key,
        )
    }

    fn load_relay_owner_key_from_sources<F>(
        credentials_dir: Option<&Path>,
        env_value: Option<String>,
        fallback: F,
    ) -> Result<String>
    where
        F: FnOnce() -> Result<String>,
    {
        if let Some(dir) = credentials_dir {
            if let Some(nsec) = Self::load_relay_owner_key_credential_from_dir(dir)? {
                Self::validate_relay_owner_nsec(&nsec, "relay_owner_nsec credential")?;
                tracing::info!(
                    credential = RELAY_OWNER_NSEC_CREDENTIAL,
                    "Loaded relay owner key"
                );
                return Ok(nsec);
            }
        }

        if let Some(nsec) = Self::relay_owner_key_from_env_value(env_value)? {
            Self::validate_relay_owner_nsec(&nsec, RELAY_OWNER_NSEC_ENV)?;
            tracing::info!(env = RELAY_OWNER_NSEC_ENV, "Loaded relay owner key");
            return Ok(nsec);
        }

        fallback()
    }

    fn load_relay_owner_key_credential_from_dir(dir: &Path) -> Result<Option<String>> {
        let key_path = dir.join(RELAY_OWNER_NSEC_CREDENTIAL);
        if !key_path.exists() {
            return Ok(None);
        }
        if !key_path
            .metadata()
            .with_context(|| format!("stat relay owner credential '{}'", key_path.display()))?
            .is_file()
        {
            return Err(anyhow!(
                "Relay owner credential '{}' is not a regular file",
                key_path.display()
            ));
        }
        let nsec = fs::read_to_string(&key_path)
            .with_context(|| format!("read relay owner credential '{}'", key_path.display()))?
            .trim()
            .to_string();
        if nsec.is_empty() {
            return Err(anyhow!(
                "Relay owner credential '{}' is empty",
                key_path.display()
            ));
        }
        Ok(Some(nsec))
    }

    fn relay_owner_key_from_env_value(value: Option<String>) -> Result<Option<String>> {
        let Some(raw) = value else {
            return Ok(None);
        };
        let nsec = raw.trim().to_string();
        if nsec.is_empty() {
            return Err(anyhow!(
                "{RELAY_OWNER_NSEC_ENV} is set but empty; unset it to load/generate \
                 {key_file}, or provide a valid nsec",
                key_file = Self::RELAY_OWNER_KEY_FILE
            ));
        }
        Ok(Some(nsec))
    }

    fn validate_relay_owner_nsec(nsec: &str, source: &str) -> Result<()> {
        Keys::parse(nsec).with_context(|| format!("Invalid relay owner nsec in {source}"))?;
        Ok(())
    }

    /// Load relay owner key from file, or generate and save a new one
    pub fn load_or_generate_relay_owner_key() -> Result<String> {
        let key_path = PathBuf::from(Self::RELAY_OWNER_KEY_FILE);
        Self::load_or_generate_relay_owner_key_at(&key_path)
    }

    fn load_or_generate_relay_owner_key_at(key_path: &Path) -> Result<String> {
        // Try to load existing key
        if key_path.exists() {
            secure_secret_file_permissions(key_path).with_context(|| {
                format!(
                    "Failed to secure relay owner key file {}",
                    key_path.display()
                )
            })?;

            let nsec = fs::read_to_string(key_path)
                .context("Failed to read relay owner key file")?
                .trim()
                .to_string();

            Self::validate_relay_owner_nsec(
                &nsec,
                &format!("relay owner key file {}", key_path.display()),
            )?;

            tracing::info!("Loaded relay owner key from {}", key_path.display());
            return Ok(nsec);
        }

        // Generate new key
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32()?;

        write_secret_file(key_path, &nsec).context("Failed to write relay owner key file")?;

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

    /// Whether the public relay endpoint is mounted at the domain root.
    pub fn is_domain_root(&self) -> bool {
        self.base_path == "/"
    }

    /// Scheme-less public service address used in GRASP event matching.
    ///
    /// Root deployments return just the configured authority. Path-mounted
    /// deployments append their canonical base path.
    pub fn service_address(&self) -> String {
        let domain = self.domain.trim().trim_end_matches('/');
        if self.is_domain_root() {
            domain.to_string()
        } else {
            format!("{domain}{}", self.base_path)
        }
    }

    /// Remove the configured public mount prefix from an incoming URL path.
    ///
    /// The returned path always starts with `/`. The exact non-root mount
    /// path and its trailing-slash form both map to `/`; sibling prefixes do
    /// not match.
    pub fn strip_base_path<'a>(&self, request_path: &'a str) -> Option<&'a str> {
        if self.is_domain_root() {
            return Some(request_path);
        }
        if request_path == self.base_path
            || request_path.strip_suffix('/') == Some(self.base_path.as_str())
        {
            return Some("/");
        }
        request_path.strip_prefix(&self.base_path).and_then(|rest| {
            if rest.starts_with('/') {
                Some(rest)
            } else {
                None
            }
        })
    }

    /// Prefix one root-relative application route with the public mount path.
    pub fn public_path(&self, route: &str) -> String {
        debug_assert!(route.starts_with('/'));
        if self.is_domain_root() {
            route.to_string()
        } else if route == "/" {
            self.base_path.clone()
        } else {
            format!("{}{route}", self.base_path)
        }
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

        let normalized_base_path = Url::parse(&format!(
            "https://base-path-validation.invalid{}",
            self.base_path
        ))
        .ok()
        .map(|url| url.path().to_string());
        if !self.base_path.starts_with('/')
            || (self.base_path.len() > 1 && self.base_path.ends_with('/'))
            || self.base_path.contains("//")
            || self.base_path.contains(['?', '#'])
            || self
                .base_path
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
            || normalized_base_path.as_deref() != Some(self.base_path.as_str())
        {
            return Err(anyhow!(
                "NGIT_BASE_PATH must be '/' or a normalized absolute URL path without a trailing slash, empty segment, query, fragment, '.' or '..'"
            ));
        }

        let mut startup_integrity_identifiers = std::collections::HashSet::new();
        for identifier in &self.startup_integrity_identifiers {
            if !crate::git::validate_repository_identifier(identifier) {
                return Err(anyhow!(
                    "NGIT_STARTUP_INTEGRITY_IDENTIFIERS contains invalid repository identifier {:?}",
                    identifier
                ));
            }
            if !startup_integrity_identifiers.insert(identifier) {
                return Err(anyhow!(
                    "NGIT_STARTUP_INTEGRITY_IDENTIFIERS contains duplicate repository identifier {:?}",
                    identifier
                ));
            }
        }

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

        let private_members = self.parse_private_members()?;
        if self.private_mode && private_members.is_empty() {
            return Err(anyhow!(
                "NGIT_PRIVATE_MODE=true requires at least one npub in NGIT_PRIVATE_MEMBERS"
            ));
        }
        if !self.private_mode && !private_members.is_empty() {
            return Err(anyhow!(
                "NGIT_PRIVATE_MEMBERS requires NGIT_PRIVATE_MODE=true"
            ));
        }
        if self.private_mode && self.grasp06_enable {
            return Err(anyhow!(
                "NGIT_PRIVATE_MODE=true cannot be combined with NGIT_GRASP06_ENABLE=true because \
                 the GRASP-06 contributor endpoint is intentionally unauthenticated"
            ));
        }
        if !self.private_public_origin.trim().is_empty() {
            let origin = Url::parse(self.private_public_origin.trim())
                .context("NGIT_PRIVATE_PUBLIC_ORIGIN must be an absolute URL")?;
            if !matches!(origin.scheme(), "http" | "https")
                || origin.host_str().is_none()
                || origin.path() != "/"
                || origin.query().is_some()
                || origin.fragment().is_some()
            {
                return Err(anyhow!(
                    "NGIT_PRIVATE_PUBLIC_ORIGIN must be an http(s) origin without a path, query, or fragment"
                ));
            }
        }

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

        if self.sync_recursive_descendant_limit == 0 {
            return Err(anyhow!(
                "NGIT_SYNC_RECURSIVE_DESCENDANT_LIMIT must be greater than 0"
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

        let relay_limits = [
            ("NGIT_RELAY_MAX_SUBSCRIPTIONS", self.relay_max_subscriptions),
            (
                "NGIT_RELAY_MAX_EVENT_SIZE_BYTES",
                self.relay_max_event_size_bytes,
            ),
            ("NGIT_RELAY_FILTER_LIMIT", self.relay_filter_limit),
        ];
        if let Some((name, _)) = relay_limits.iter().find(|(_, value)| *value == 0) {
            return Err(anyhow!("{name} must be greater than 0"));
        }

        if self.relay_max_event_size_bytes > 5 * 1024 * 1024 {
            return Err(anyhow!(
                "NGIT_RELAY_MAX_EVENT_SIZE_BYTES must not exceed the 5 MiB WebSocket message limit"
            ));
        }

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

        // GRASP-P private repositories (only validated when enabled)
        if self.private_repos_enable {
            // GRASP-08 puts a NIP-42 gate in front of every read, which
            // breaks GRASP-P's anonymous-read design: one node runs one or
            // the other.
            if self.private_mode {
                return Err(anyhow!(
                    "NGIT_GRASP_P_REPOS_ENABLE=true cannot be combined with NGIT_PRIVATE_MODE=true: \
                     GRASP-P private repositories rely on anonymous reads, which GRASP-08 \
                     private mode gates behind NIP-42"
                ));
            }
            if self.private_registration_mode == RegistrationMode::Paid {
                return Err(anyhow!(
                    "NGIT_GRASP_P_REGISTRATION_MODE=paid: paid registration mode is not yet available"
                ));
            }
            // Whitelist mode with an empty whitelist is a valid
            // "accept nothing" posture (it is the shipped default), but an
            // operator who expected open mode must see it immediately.
            if self.private_registration_mode == RegistrationMode::Whitelist
                && self.private_tenant_whitelist_entries().is_empty()
            {
                tracing::warn!(
                    "NGIT_GRASP_P_REGISTRATION_MODE=whitelist with an empty \
                     NGIT_GRASP_P_TENANT_WHITELIST: all new private-repo \
                     registrations will be rejected (existing registrations \
                     are unaffected)"
                );
            }
            // Upstream's relay refuses any event above its own ceiling before
            // GRASP-P sees it, so a larger GRASP-P cap could never apply.
            if self.private_max_event_bytes > self.relay_max_event_size_bytes as u64 {
                tracing::warn!(
                    grasp_p_max_event_bytes = self.private_max_event_bytes,
                    relay_max_event_size_bytes = self.relay_max_event_size_bytes,
                    "NGIT_GRASP_P_MAX_EVENT_BYTES exceeds NGIT_RELAY_MAX_EVENT_SIZE_BYTES: \
                     the relay ceiling is the effective limit"
                );
            }
            if !(1..=40).contains(&self.private_pow_bits) {
                return Err(anyhow!("NGIT_GRASP_P_POW_BITS must be between 1 and 40"));
            }
            if self.private_state_history_editions < 1 {
                return Err(anyhow!(
                    "NGIT_GRASP_P_STATE_HISTORY_EDITIONS must be at least 1"
                ));
            }
            for (value, name) in [
                (self.private_max_blob_bytes, "NGIT_GRASP_P_MAX_BLOB_BYTES"),
                (self.private_max_event_bytes, "NGIT_GRASP_P_MAX_EVENT_BYTES"),
                (
                    self.private_quota_tenant_bytes,
                    "NGIT_GRASP_P_QUOTA_TENANT_BYTES",
                ),
                (
                    self.private_quota_repo_bytes,
                    "NGIT_GRASP_P_QUOTA_REPO_BYTES",
                ),
                (
                    self.private_global_budget_bytes,
                    "NGIT_GRASP_P_GLOBAL_BUDGET_BYTES",
                ),
            ] {
                if value == 0 {
                    return Err(anyhow!("{name} must be greater than 0"));
                }
            }
            if self.private_quota_repo_bytes > self.private_quota_tenant_bytes {
                return Err(anyhow!(
                    "NGIT_GRASP_P_QUOTA_REPO_BYTES must not exceed NGIT_GRASP_P_QUOTA_TENANT_BYTES"
                ));
            }
            if self.private_quota_tenant_bytes > self.private_global_budget_bytes {
                return Err(anyhow!(
                    "NGIT_GRASP_P_QUOTA_TENANT_BYTES must not exceed NGIT_GRASP_P_GLOBAL_BUDGET_BYTES"
                ));
            }
            if self.effective_private_blob_path().trim().is_empty() {
                return Err(anyhow!("NGIT_GRASP_P_BLOB_DATA_PATH must not be empty"));
            }
            if self.effective_private_meta_path().trim().is_empty() {
                return Err(anyhow!("NGIT_GRASP_P_META_DATA_PATH must not be empty"));
            }
            if self.private_mirror_enable {
                if self.private_mirror_max_concurrency == 0 {
                    return Err(anyhow!(
                        "NGIT_GRASP_P_MIRROR_MAX_CONCURRENCY must be greater than 0"
                    ));
                }
                if self.private_mirror_fetch_timeout_secs == 0 {
                    return Err(anyhow!(
                        "NGIT_GRASP_P_MIRROR_FETCH_TIMEOUT_SECS must be greater than 0"
                    ));
                }
                if self.private_mirror_retry_base_secs == 0 {
                    return Err(anyhow!(
                        "NGIT_GRASP_P_MIRROR_RETRY_BASE_SECS must be greater than 0"
                    ));
                }
                if self.private_mirror_retry_max_secs < self.private_mirror_retry_base_secs {
                    return Err(anyhow!(
                        "NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS must be greater than or equal to \
                         NGIT_GRASP_P_MIRROR_RETRY_BASE_SECS"
                    ));
                }
            }
            if self.private_write_rate_capacity > 0 && self.private_write_rate_refill_per_min == 0 {
                return Err(anyhow!(
                    "NGIT_GRASP_P_WRITE_RATE_REFILL_PER_MIN must be greater than 0 when \
                     NGIT_GRASP_P_WRITE_RATE_CAPACITY is non-zero"
                ));
            }
            // Every value of the two upload limits is usable, 0 included
            // (it turns the limit off), so neither can stop the node from
            // starting. A cap per account that is not below the node's own
            // cap limits nothing, and an operator who set one is told. 0 is
            // the stated way to switch the cap off and draws no warning.
            if self.private_max_uploads_per_tenant >= crate::grasp_p::MAX_CONCURRENT_UPLOADS {
                tracing::warn!(
                    grasp_p_max_uploads_per_tenant = self.private_max_uploads_per_tenant,
                    node_upload_slots = crate::grasp_p::MAX_CONCURRENT_UPLOADS,
                    "NGIT_GRASP_P_MAX_UPLOADS_PER_TENANT is not below the node's upload \
                     slots: one account can take every slot"
                );
            }
            if self.private_registration_replace_capacity > 0
                && self.private_registration_replace_refill_per_hour == 0
            {
                return Err(anyhow!(
                    "NGIT_GRASP_P_REGISTRATION_REPLACE_REFILL_PER_HOUR must be greater than 0 \
                     when NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY is non-zero"
                ));
            }
            // The scrape of a node with private repositories is not public,
            // so its address has to be loopback, and a listener with no
            // metrics behind it would only look like monitoring.
            if self.private_metrics_bind_addr()?.is_some() && !self.metrics_enabled {
                return Err(anyhow!(
                    "NGIT_GRASP_P_METRICS_BIND is set while NGIT_METRICS_ENABLED=false: \
                     there are no metrics to serve. Unset it, or enable metrics"
                ));
            }
        }

        Ok(())
    }

    /// Effective blob store root for GRASP-P private repos.
    ///
    /// Defaults to `<relay_data_path>/blobs` so TestRelay tempdir isolation
    /// holds without extra env vars.
    pub fn effective_private_blob_path(&self) -> String {
        self.private_blob_data_path.clone().unwrap_or_else(|| {
            PathBuf::from(&self.relay_data_path)
                .join("blobs")
                .to_string_lossy()
                .into_owned()
        })
    }

    /// Effective private meta store (heed env) root for GRASP-P private repos.
    ///
    /// Defaults to `<relay_data_path>/private-meta`.
    pub fn effective_private_meta_path(&self) -> String {
        self.private_meta_data_path.clone().unwrap_or_else(|| {
            PathBuf::from(&self.relay_data_path)
                .join("private-meta")
                .to_string_lossy()
                .into_owned()
        })
    }

    /// Parsed NGIT_GRASP_P_TENANT_WHITELIST (npub bech32 strings, CSV).
    pub fn private_tenant_whitelist_entries(&self) -> Vec<String> {
        self.private_tenant_whitelist
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    /// Parsed NGIT_GRASP_P_MIRROR_PEER_URLS (base URLs, CSV). `None` when
    /// unset or empty — the mirror then derives peers from each
    /// registration's `server` tags.
    pub fn private_mirror_peer_url_entries(&self) -> Option<Vec<String>> {
        let raw = self.private_mirror_peer_urls.as_ref()?;
        let entries: Vec<String> = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if entries.is_empty() {
            None
        } else {
            Some(entries)
        }
    }

    /// Parsed NGIT_GRASP_P_DENYLIST_PATH (file paths, CSV). Empty when
    /// unset — the denylist is then empty and no reload task runs.
    pub fn private_denylist_paths(&self) -> Vec<String> {
        self.private_denylist_path
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    /// Parsed NGIT_GRASP_P_SYNC_PEER_URLS (relay URLs, CSV). Empty when
    /// unset — the sync layer then initiates NO private peer connections;
    /// tenant 30640 `relays` tags are never a connection source.
    pub fn private_sync_peer_url_entries(&self) -> Vec<String> {
        self.private_sync_peer_urls
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    /// Parsed NGIT_GRASP_P_METRICS_BIND. `None` when unset or empty: the
    /// node then has no metrics endpoint. A value that is not a loopback IP
    /// address and port is an error that names the setting.
    pub fn private_metrics_bind_addr(&self) -> Result<Option<std::net::SocketAddr>> {
        match self.private_metrics_bind.as_deref().map(str::trim) {
            None | Some("") => Ok(None),
            Some(value) => crate::grasp_p::metrics_endpoint::parse_bind(value)
                .map(Some)
                .map_err(anyhow::Error::msg),
        }
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

    /// Parse the comma-separated user-index relay URLs.
    pub fn parse_user_index_relays(&self) -> Vec<String> {
        self.user_index_relays
            .split(',')
            .map(str::trim)
            .filter(|relay| !relay.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Parse the comma-separated Sync+ fallback relay URLs.
    pub fn parse_sync_plus_fallback_relays(&self) -> Vec<String> {
        self.sync_plus_fallback_relays
            .split(',')
            .map(str::trim)
            .filter(|relay| !relay.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Parse the GRASP-08 service-wide member whitelist.
    ///
    /// Unlike repository/archive curation lists, malformed private members are
    /// fatal: skipping an access-control entry would silently lock a user out.
    pub fn parse_private_members(&self) -> Result<Vec<PublicKey>> {
        self.private_members
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                if !value.starts_with("npub1") {
                    return Err(anyhow!(
                        "Invalid NGIT_PRIVATE_MEMBERS entry '{value}': expected an npub"
                    ));
                }
                PublicKey::from_bech32(value).with_context(|| {
                    format!("Invalid npub in NGIT_PRIVATE_MEMBERS entry '{value}'")
                })
            })
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
            base_path: "/".to_string(),
            relay_owner_nsec: Some(nsec),
            relay_name_override: Some("test relay".to_string()),
            relay_description: "test description".to_string(),
            git_data_path: "./test_data/git".to_string(),
            relay_data_path: "./test_data/relay".to_string(),
            startup_integrity_identifiers: Vec::new(),
            bind_address: "127.0.0.1:7334".to_string(),
            trusted_proxy_cidrs: Vec::new(),
            database_backend: DatabaseBackend::Memory,
            metrics_enabled: true,
            metrics_connection_per_ip_abuse_threshold: 10,
            metrics_top_n_repos: 10,
            sync_bootstrap_relay_url: None,
            sync_plus_enabled: true,
            user_index_relays: DEFAULT_USER_INDEX_RELAYS.to_string(),
            sync_plus_fallback_relays: DEFAULT_SYNC_PLUS_FALLBACK_RELAYS.to_string(),
            sync_recursive_descendant_limit: 500,
            sync_max_backoff_secs: 3600,
            sync_disconnect_check_interval_secs: 60,
            sync_base_backoff_secs: 5,
            sync_disable_negentropy: false,
            sync_allow_non_global_targets: false,
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
            private_mode: false,
            private_members: String::new(),
            private_public_origin: String::new(),
            repository_whitelist: String::new(),
            repository_blacklist: String::new(),
            blacklist_auto_restore: false,
            event_blacklist: String::new(),
            deletion_request_disrespector: false,
            max_connections: None,
            relay_max_subscriptions: 500,
            relay_max_event_size_bytes: 192 * 1024,
            relay_filter_limit: 500,
            log_level: "debug".to_string(),
            private_repos_enable: false,
            private_registration_mode: RegistrationMode::Open,
            private_pow_bits: 20,
            private_tenant_whitelist: String::new(),
            private_max_blob_bytes: 268_435_456,
            private_max_event_bytes: 131_072,
            private_quota_tenant_bytes: 1_073_741_824,
            private_quota_repo_bytes: 536_870_912,
            private_global_budget_bytes: 53_687_091_200,
            private_max_aliases_per_tenant: 64,
            private_max_write_keys_per_alias: 64,
            private_state_history_editions: 16,
            private_gc_grace_secs: 86_400,
            private_gc_interval_secs: 3_600,
            private_offboard_retention_secs: 2_592_000,
            private_blob_data_path: None,
            private_meta_data_path: None,
            private_denylist_path: None,
            private_denylist_reload_secs: 60,
            private_mirror_enable: false,
            private_mirror_peer_urls: None,
            private_sync_peer_urls: None,
            private_mirror_max_concurrency: 4,
            private_mirror_fetch_timeout_secs: 120,
            private_mirror_allow_private_ips: false,
            private_accept_legacy_wrap_kind: true,
            private_write_rate_capacity: 120,
            private_write_rate_refill_per_min: 60,
            private_max_uploads_per_tenant: 8,
            private_upload_min_bytes_per_sec: 16384,
            private_registration_replace_capacity: 8,
            private_registration_replace_refill_per_hour: 4,
            private_full_reissue_interval_secs: 3600,
            private_reissue_min_interval_secs: 30,
            private_mirror_retry_base_secs: 60,
            private_mirror_retry_max_secs: 3600,
            private_mirror_max_attempts_per_min: 600,
            private_metrics_bind: None,
        }
    }
}

fn write_secret_file(path: &Path, contents: &str) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

fn secure_secret_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to inspect secret file {}", path.display()))?;
        let mut permissions = metadata.permissions();
        if permissions.mode() & 0o777 != 0o600 {
            permissions.set_mode(0o600);
            fs::set_permissions(path, permissions).with_context(|| {
                format!(
                    "Failed to restrict secret file {} to mode 0600",
                    path.display()
                )
            })?;
        }
    }

    #[cfg(not(unix))]
    let _ = path;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Mutex;

    static CONFIG_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_values() {
        let config = Config::for_testing();
        assert_eq!(config.domain, "localhost:7334");
        assert_eq!(config.base_path, "/");
        assert_eq!(config.bind_address, "127.0.0.1:7334");
        assert!(config.trusted_proxy_cidrs.is_empty());
        assert!(config.startup_integrity_identifiers.is_empty());
        // for_testing() uses Memory, but the actual default is Lmdb
        assert_eq!(config.database_backend, DatabaseBackend::Memory);
    }

    /// Wire-kind migration: legacy stream-wrap acceptance defaults ON (a
    /// node must accept 3359 before any client emits it, and in-flight
    /// 1059s must keep draining), and the env var must be able to turn it
    /// OFF — a default-true clap bool silently ignoring `=false` would
    /// make the migration's final step a no-op.
    #[test]
    fn test_private_accept_legacy_wrap_kind_default_and_env_override() {
        let _environment_guard = CONFIG_ENV_LOCK.lock().expect("lock must not be poisoned");
        const VARIABLE: &str = "NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND";
        let original = std::env::var_os(VARIABLE);
        std::env::remove_var(VARIABLE);

        let config = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("default configuration should parse");
        assert!(
            config.private_accept_legacy_wrap_kind,
            "legacy wrap-kind acceptance must default to true"
        );
        assert!(
            Config::for_testing().private_accept_legacy_wrap_kind,
            "for_testing() must match the shipped default"
        );

        std::env::set_var(VARIABLE, "false");
        let config = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("env-disabled configuration should parse");
        assert!(
            !config.private_accept_legacy_wrap_kind,
            "NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND=false must turn legacy accept off"
        );

        match original {
            Some(value) => std::env::set_var(VARIABLE, value),
            None => std::env::remove_var(VARIABLE),
        }
    }

    #[test]
    fn startup_integrity_scope_parses_and_validates() {
        let config = Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--startup-integrity-identifiers",
            "repo-one,repo-two",
        ])
        .expect("startup integrity scope should parse");

        assert_eq!(
            config.startup_integrity_identifiers,
            ["repo-one", "repo-two"]
        );

        let invalid = Config {
            startup_integrity_identifiers: vec!["../escape".to_owned()],
            ..Config::for_testing()
        };
        assert!(invalid.validate().is_err());

        let duplicate = Config {
            startup_integrity_identifiers: vec!["repo".to_owned(), "repo".to_owned()],
            ..Config::for_testing()
        };
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn base_path_parses_and_builds_public_routes() {
        let config = Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--base-path",
            "/services/grasp",
        ])
        .expect("base path should parse");

        assert_eq!(config.base_path, "/services/grasp");
        assert_eq!(config.service_address(), "example.com/services/grasp");
        assert_eq!(config.public_path("/"), "/services/grasp");
        assert_eq!(
            config.public_path("/npub/repo.git"),
            "/services/grasp/npub/repo.git"
        );
        assert_eq!(config.strip_base_path("/services/grasp"), Some("/"));
        assert_eq!(
            config.strip_base_path("/services/grasp/npub/repo.git"),
            Some("/npub/repo.git")
        );
        assert_eq!(config.strip_base_path("/services/graspy"), None);
    }

    #[test]
    fn base_path_validation_rejects_ambiguous_paths() {
        for base_path in [
            "grasp",
            "/grasp/",
            "/grasp//relay",
            "/grasp/../relay",
            "/grasp/%2e%2e/relay",
            "/grasp?mode=relay",
            "/grasp#relay",
        ] {
            let config = Config {
                base_path: base_path.to_string(),
                ..Config::for_testing()
            };
            let error = config
                .validate()
                .expect_err("ambiguous base path must fail validation");
            assert!(error.to_string().contains("NGIT_BASE_PATH"), "{base_path}");
        }
    }

    #[test]
    fn test_trusted_proxy_cidrs_parse_from_cli() {
        let config = Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--trusted-proxy-cidrs",
            "127.0.0.1/32,10.0.0.0/8,2001:db8::/32",
        ])
        .expect("trusted proxy CIDRs should parse");

        assert_eq!(config.trusted_proxy_cidrs.len(), 3);
        assert!(config.trusted_proxy_cidrs[0].contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(config.trusted_proxy_cidrs[1].contains(&"10.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(config.trusted_proxy_cidrs[2].contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_trusted_proxy_cidrs_reject_invalid_networks() {
        let error = Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--trusted-proxy-cidrs",
            "127.0.0.1/32,not-a-network",
        ])
        .expect_err("invalid trusted proxy CIDRs must stop startup");

        assert!(error.to_string().contains("not-a-network"));
    }

    #[test]
    fn test_trusted_proxy_cidrs_parse_from_environment() {
        const VARIABLE: &str = "NGIT_TRUSTED_PROXY_CIDRS";
        let _environment_guard = CONFIG_ENV_LOCK.lock().expect("lock must not be poisoned");
        let original = std::env::var_os(VARIABLE);
        std::env::set_var(VARIABLE, "127.0.0.1/32,::1/128");

        let result = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"]);

        match original {
            Some(value) => std::env::set_var(VARIABLE, value),
            None => std::env::remove_var(VARIABLE),
        }

        let config = result.expect("trusted proxy CIDRs should parse from the environment");
        assert_eq!(config.trusted_proxy_cidrs.len(), 2);
    }

    #[test]
    fn relay_hardening_defaults_are_explicit() {
        let config = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("relay hardening defaults should parse");

        assert_eq!(config.relay_max_subscriptions, 500);
        assert_eq!(config.relay_max_event_size_bytes, 192 * 1024);
        assert_eq!(config.relay_filter_limit, 500);
    }

    #[test]
    fn user_index_relay_defaults_are_explicit() {
        let config = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("user-index relay defaults should parse");

        assert_eq!(
            config.parse_user_index_relays(),
            vec![
                "wss://purplepag.es",
                "wss://index.hzrd149.com",
                "wss://indexer.coracle.social",
            ]
        );
    }

    #[test]
    fn sync_plus_fallback_defaults_and_empty_override_are_explicit() {
        let default = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("Sync+ fallback defaults should parse");
        assert_eq!(
            default.parse_sync_plus_fallback_relays(),
            vec![
                "wss://relay.ditto.pub",
                "wss://relay.damus.io",
                "wss://nos.lol",
                "wss://relay.primal.net",
            ]
        );

        let disabled = Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--sync-plus-fallback-relays=",
        ])
        .expect("empty Sync+ fallback override should parse");
        assert!(disabled.parse_sync_plus_fallback_relays().is_empty());
    }

    #[test]
    fn sync_plus_is_enabled_by_default_and_can_be_disabled() {
        let default = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("Sync+ default should parse");
        assert!(default.sync_plus_enabled);

        let disabled = Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--sync-plus-enabled=false",
        ])
        .expect("Sync+ opt-out should parse");
        assert!(!disabled.sync_plus_enabled);
    }

    #[test]
    fn recursive_descendant_limit_defaults_to_500_and_accepts_small_soak_values() {
        let default = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("recursive descendant default should parse");
        assert_eq!(default.sync_recursive_descendant_limit, 500);

        let tiny = Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--sync-recursive-descendant-limit=3",
        ])
        .expect("tiny recursive descendant limit should parse");
        assert_eq!(tiny.sync_recursive_descendant_limit, 3);
    }

    #[test]
    fn recursive_descendant_limit_must_be_positive() {
        let mut config = Config::for_testing();
        config.sync_recursive_descendant_limit = 0;

        let error = config.validate().expect_err("zero limit must be rejected");
        assert!(error
            .to_string()
            .contains("NGIT_SYNC_RECURSIVE_DESCENDANT_LIMIT must be greater than 0"));
    }

    #[test]
    fn user_index_relays_parse_cli_list_and_ignore_empty_entries() {
        let config = Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--user-index-relays",
            " wss://one.example ,, wss://two.example, ",
        ])
        .expect("user-index relay override should parse");

        assert_eq!(
            config.parse_user_index_relays(),
            vec!["wss://one.example", "wss://two.example"]
        );
    }

    #[test]
    fn event_limit_cannot_exceed_websocket_limit() {
        let mut config = Config::for_testing();
        config.relay_max_event_size_bytes = 5 * 1024 * 1024 + 1;

        let error = config
            .validate()
            .expect_err("inconsistent size limits must fail");
        assert!(error
            .to_string()
            .contains("NGIT_RELAY_MAX_EVENT_SIZE_BYTES must not exceed"));
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
    fn test_private_registration_mode_shipped_default_is_whitelist() {
        // WP-E / server issue !7: the shipped default admission mode is
        // whitelist (open is staging/self-use only and must be opted into).
        // Pin it so a regression of the clap/derive default fails loudly.
        let _environment_guard = CONFIG_ENV_LOCK.lock().expect("lock must not be poisoned");
        const VARIABLE: &str = "NGIT_GRASP_P_REGISTRATION_MODE";
        let original = std::env::var_os(VARIABLE);
        std::env::remove_var(VARIABLE);

        let config = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("default private registration mode configuration should parse");

        match original {
            Some(value) => std::env::set_var(VARIABLE, value),
            None => std::env::remove_var(VARIABLE),
        }

        assert_eq!(
            config.private_registration_mode,
            RegistrationMode::Whitelist,
            "shipped default registration mode must be whitelist (open is opt-in only)"
        );
        assert_eq!(RegistrationMode::default(), RegistrationMode::Whitelist);
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
    fn relay_owner_nsec_is_not_accepted_on_argv() {
        let nsec = Keys::generate().secret_key().to_bech32().unwrap();
        assert!(Config::try_parse_from([
            "ngit-grasp",
            "--domain",
            "example.com",
            "--relay-owner-nsec",
            nsec.as_str(),
        ])
        .is_err());
    }

    #[test]
    fn relay_owner_nsec_credential_is_loaded_and_trimmed() {
        let tempdir = tempfile::tempdir().unwrap();
        let nsec = Keys::generate().secret_key().to_bech32().unwrap();
        fs::write(
            tempdir.path().join(RELAY_OWNER_NSEC_CREDENTIAL),
            format!(" {nsec}\n"),
        )
        .unwrap();

        let loaded = Config::load_relay_owner_key_credential_from_dir(tempdir.path())
            .unwrap()
            .unwrap();
        assert_eq!(loaded, nsec);
    }

    #[test]
    fn relay_owner_nsec_credential_rejects_empty_and_invalid_files() {
        let tempdir = tempfile::tempdir().unwrap();
        let credential = tempdir.path().join(RELAY_OWNER_NSEC_CREDENTIAL);
        fs::write(&credential, "\n").unwrap();
        assert!(Config::load_relay_owner_key_credential_from_dir(tempdir.path()).is_err());

        fs::write(&credential, "nsec1invalid").unwrap();
        let error = Config::load_relay_owner_key_from_sources(
            Some(tempdir.path()),
            None,
            || -> Result<String> { panic!("invalid credential must not fall through") },
        )
        .unwrap_err();
        assert!(error.to_string().contains("relay_owner_nsec credential"));
    }

    #[test]
    fn relay_owner_nsec_credential_takes_precedence_over_environment() {
        let tempdir = tempfile::tempdir().unwrap();
        let credential_nsec = Keys::generate().secret_key().to_bech32().unwrap();
        fs::write(
            tempdir.path().join(RELAY_OWNER_NSEC_CREDENTIAL),
            &credential_nsec,
        )
        .unwrap();

        let loaded = Config::load_relay_owner_key_from_sources(
            Some(tempdir.path()),
            Some("nsec1invalid".to_string()),
            || -> Result<String> { panic!("credential must prevent fallback") },
        )
        .unwrap();
        assert_eq!(loaded, credential_nsec);
    }

    #[test]
    fn relay_owner_nsec_environment_is_trimmed_and_precedes_fallback() {
        let nsec = Keys::generate().secret_key().to_bech32().unwrap();
        let loaded = Config::load_relay_owner_key_from_sources(
            None,
            Some(format!(" {nsec}\n")),
            || -> Result<String> { panic!("environment must prevent fallback") },
        )
        .unwrap();
        assert_eq!(loaded, nsec);
    }

    #[test]
    fn relay_owner_nsec_environment_rejects_empty_and_invalid_values() {
        for raw in ["", " ", "\n"] {
            assert!(
                Config::relay_owner_key_from_env_value(Some(raw.to_string())).is_err(),
                "{raw:?} should be rejected"
            );
        }

        let error = Config::load_relay_owner_key_from_sources(
            None,
            Some("nsec1invalid".to_string()),
            || -> Result<String> { panic!("invalid environment must not fall through") },
        )
        .unwrap_err();
        assert!(error.to_string().contains(RELAY_OWNER_NSEC_ENV));
    }

    #[test]
    fn relay_owner_nsec_missing_sources_use_persistent_fallback() {
        let fallback_nsec = Keys::generate().secret_key().to_bech32().unwrap();
        let loaded =
            Config::load_relay_owner_key_from_sources(None, None, || Ok(fallback_nsec.clone()))
                .unwrap();
        assert_eq!(loaded, fallback_nsec);
    }

    #[cfg(unix)]
    #[test]
    fn generated_relay_owner_key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let key_path = tempdir.path().join(".relay-owner.nsec");
        write_secret_file(&key_path, "secret").unwrap();

        assert_eq!(
            fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_relay_owner_key_file_permissions_are_repaired_before_loading() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let key_path = tempdir.path().join(".relay-owner.nsec");
        let nsec = Keys::generate().secret_key().to_bech32().unwrap();
        fs::write(&key_path, &nsec).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

        let loaded = Config::load_or_generate_relay_owner_key_at(&key_path).unwrap();

        assert_eq!(loaded, nsec);
        assert_eq!(
            fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
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

    #[test]
    fn test_grasp_p_and_grasp08_private_mode_are_mutually_exclusive() {
        let member = Keys::generate().public_key().to_bech32().unwrap();
        let grasp08 = Config {
            private_mode: true,
            private_members: member,
            ..Config::for_testing()
        };
        assert!(grasp08.validate().is_ok());

        let both = Config {
            private_repos_enable: true,
            ..grasp08
        };
        let error = both
            .validate()
            .expect_err("GRASP-P with GRASP-08 must fail");
        assert!(
            error.to_string().contains("NGIT_PRIVATE_MODE"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_private_write_rate_validation() {
        // Defaults (enabled, generous) validate.
        let config = Config {
            private_repos_enable: true,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());

        // capacity = 0 disables the limiter; refill is then unconstrained.
        let config = Config {
            private_repos_enable: true,
            private_write_rate_capacity: 0,
            private_write_rate_refill_per_min: 0,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());

        // Non-zero capacity with zero refill is a misconfiguration.
        let config = Config {
            private_repos_enable: true,
            private_write_rate_capacity: 120,
            private_write_rate_refill_per_min: 0,
            ..Config::for_testing()
        };
        let error = config.validate().expect_err("zero refill must fail");
        assert!(
            error
                .to_string()
                .contains("NGIT_GRASP_P_WRITE_RATE_REFILL_PER_MIN"),
            "unexpected error: {error}"
        );

        // The knobs are only validated when the subsystem is enabled.
        let config = Config {
            private_repos_enable: false,
            private_write_rate_capacity: 120,
            private_write_rate_refill_per_min: 0,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
    }

    /// Neither upload limit has a value that stops the node: 0 turns a
    /// limit off, and a cap per account that reaches the node's slots only
    /// warns.
    #[test]
    fn test_private_upload_limits_validation() {
        for (per_tenant, min_rate) in [(8, 16384), (0, 0), (1, 1), (u32::MAX, u64::MAX)] {
            let config = Config {
                private_repos_enable: true,
                private_max_uploads_per_tenant: per_tenant,
                private_upload_min_bytes_per_sec: min_rate,
                ..Config::for_testing()
            };
            assert!(
                config.validate().is_ok(),
                "per account {per_tenant}, minimum rate {min_rate}"
            );
        }
        let defaults = Config::for_testing();
        assert_eq!(defaults.private_max_uploads_per_tenant, 8);
        assert_eq!(defaults.private_upload_min_bytes_per_sec, 16384);
    }

    /// The mirror's attempt budget has the documented default, is read from
    /// the environment like its neighbours, and has no value that stops the
    /// node: 0 turns it off.
    #[test]
    fn grasp_p_mirror_attempt_budget_default_and_env_override() {
        let _environment_guard = CONFIG_ENV_LOCK.lock().expect("lock must not be poisoned");
        const VARIABLE: &str = "NGIT_GRASP_P_MIRROR_MAX_ATTEMPTS_PER_MIN";
        let original = std::env::var_os(VARIABLE);
        std::env::remove_var(VARIABLE);

        let config = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("default configuration should parse");
        assert_eq!(config.private_mirror_max_attempts_per_min, 600);
        assert_eq!(
            Config::for_testing().private_mirror_max_attempts_per_min,
            600,
            "for_testing() must match the shipped default"
        );

        std::env::set_var(VARIABLE, "0");
        let config = Config::try_parse_from(["ngit-grasp", "--domain", "example.com"])
            .expect("a budget of 0 should parse");
        assert_eq!(config.private_mirror_max_attempts_per_min, 0);

        match original {
            Some(value) => std::env::set_var(VARIABLE, value),
            None => std::env::remove_var(VARIABLE),
        }

        for budget in [0, 1, 600, u32::MAX] {
            let config = Config {
                private_repos_enable: true,
                private_mirror_enable: true,
                private_mirror_max_attempts_per_min: budget,
                ..Config::for_testing()
            };
            assert!(config.validate().is_ok(), "attempt budget {budget}");
        }
    }

    #[test]
    fn test_private_registration_replace_validation() {
        // Defaults (capacity 8, refill 4/hour) validate.
        let config = Config {
            private_repos_enable: true,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());

        // capacity = 0 disables the cadence limiter; refill is then
        // unconstrained.
        let config = Config {
            private_repos_enable: true,
            private_registration_replace_capacity: 0,
            private_registration_replace_refill_per_hour: 0,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());

        // Non-zero capacity with zero refill is a misconfiguration.
        let config = Config {
            private_repos_enable: true,
            private_registration_replace_capacity: 8,
            private_registration_replace_refill_per_hour: 0,
            ..Config::for_testing()
        };
        let error = config.validate().expect_err("zero refill must fail");
        assert!(
            error
                .to_string()
                .contains("NGIT_GRASP_P_REGISTRATION_REPLACE_REFILL_PER_HOUR"),
            "unexpected error: {error}"
        );

        // Only validated when the subsystem is enabled.
        let config = Config {
            private_repos_enable: false,
            private_registration_replace_capacity: 8,
            private_registration_replace_refill_per_hour: 0,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_private_full_reissue_interval_validation() {
        // Default (3600s) validates.
        let config = Config {
            private_repos_enable: true,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
        assert_eq!(config.private_full_reissue_interval_secs, 3600);

        // 0 disables the timer and is always valid.
        let config = Config {
            private_repos_enable: true,
            private_full_reissue_interval_secs: 0,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());

        // Any positive interval is valid (no constraint to violate).
        let config = Config {
            private_repos_enable: true,
            private_full_reissue_interval_secs: 1,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_private_mirror_retry_validation() {
        // Defaults (base 60, max 3600) validate.
        let config = Config {
            private_repos_enable: true,
            private_mirror_enable: true,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());

        // Zero base is a misconfiguration (would hot-loop retries).
        let config = Config {
            private_repos_enable: true,
            private_mirror_enable: true,
            private_mirror_retry_base_secs: 0,
            ..Config::for_testing()
        };
        let error = config.validate().expect_err("zero base must fail");
        assert!(
            error
                .to_string()
                .contains("NGIT_GRASP_P_MIRROR_RETRY_BASE_SECS"),
            "unexpected error: {error}"
        );

        // max < base is a misconfiguration.
        let config = Config {
            private_repos_enable: true,
            private_mirror_enable: true,
            private_mirror_retry_base_secs: 120,
            private_mirror_retry_max_secs: 60,
            ..Config::for_testing()
        };
        let error = config.validate().expect_err("max < base must fail");
        assert!(
            error
                .to_string()
                .contains("NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS"),
            "unexpected error: {error}"
        );

        // Only validated when the mirror is enabled.
        let config = Config {
            private_repos_enable: true,
            private_mirror_enable: false,
            private_mirror_retry_base_secs: 0,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_private_denylist_path_parsing() {
        // Unset → no paths.
        let config = Config::for_testing();
        assert!(config.private_denylist_paths().is_empty());

        // Single path.
        let config = Config {
            private_denylist_path: Some("/etc/ngit/denylist.txt".to_string()),
            ..Config::for_testing()
        };
        assert_eq!(
            config.private_denylist_paths(),
            vec!["/etc/ngit/denylist.txt".to_string()]
        );

        // Comma-separated multi-path: whitespace trimmed, empty segments
        // dropped. (Long line left as-is: rustfmt's 100-col split hurts
        // the readability of this fixture.)
        let config = Config {
            private_denylist_path: Some(" /a/deny.txt ,/b/deny.txt,,  /c/deny.txt  ,".to_string()),
            ..Config::for_testing()
        };
        assert_eq!(
            config.private_denylist_paths(),
            vec![
                "/a/deny.txt".to_string(),
                "/b/deny.txt".to_string(),
                "/c/deny.txt".to_string()
            ]
        );

        // Set-but-empty / all-separators → no paths.
        for raw in ["", ",", " , , "] {
            let config = Config {
                private_denylist_path: Some(raw.to_string()),
                ..Config::for_testing()
            };
            assert!(
                config.private_denylist_paths().is_empty(),
                "raw={raw:?} must yield no paths"
            );
        }
    }

    #[test]
    fn test_private_denylist_reload_secs_validation() {
        // Default (60s) validates.
        let config = Config {
            private_repos_enable: true,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
        assert_eq!(config.private_denylist_reload_secs, 60);

        // 0 disables the reload task and is always valid.
        let config = Config {
            private_repos_enable: true,
            private_denylist_reload_secs: 0,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());

        // Any other u64 is valid (no constraint to violate).
        let config = Config {
            private_repos_enable: true,
            private_denylist_reload_secs: u64::MAX,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_grasp_p_metrics_bind_must_be_loopback() {
        for accepted in ["127.0.0.1:9464", "[::1]:9464", "127.0.0.1:0"] {
            let config = Config {
                private_repos_enable: true,
                private_metrics_bind: Some(accepted.to_string()),
                ..Config::for_testing()
            };
            config
                .validate()
                .unwrap_or_else(|error| panic!("{accepted} must validate: {error}"));
            let address = config
                .private_metrics_bind_addr()
                .expect("a loopback address parses")
                .expect("a set address is not unset");
            assert_eq!(
                address,
                accepted
                    .parse::<std::net::SocketAddr>()
                    .expect("test address")
            );
        }

        for refused in [
            "0.0.0.0:9464",
            "10.0.0.1:9464",
            "[::]:9464",
            "[::ffff:127.0.0.1]:9464",
            "localhost:9464",
            "127.0.0.1",
        ] {
            let config = Config {
                private_repos_enable: true,
                private_metrics_bind: Some(refused.to_string()),
                ..Config::for_testing()
            };
            let error = config
                .validate()
                .expect_err("an address that is not loopback must fail");
            assert!(
                error.to_string().contains("NGIT_GRASP_P_METRICS_BIND"),
                "{refused}: the error must name the setting: {error}"
            );

            // With GRASP-P off the value is never read: such a node keeps
            // upstream's public route and has no endpoint of this kind.
            let config = Config {
                private_repos_enable: false,
                private_metrics_bind: Some(refused.to_string()),
                ..Config::for_testing()
            };
            assert!(config.validate().is_ok(), "{refused} with GRASP-P off");
        }
    }

    #[test]
    fn test_grasp_p_metrics_bind_requires_metrics_enabled() {
        let config = Config {
            private_repos_enable: true,
            metrics_enabled: false,
            private_metrics_bind: Some("127.0.0.1:9464".to_string()),
            ..Config::for_testing()
        };
        let error = config
            .validate()
            .expect_err("an endpoint with no metrics to serve must fail");
        let message = error.to_string();
        assert!(
            message.contains("NGIT_GRASP_P_METRICS_BIND")
                && message.contains("NGIT_METRICS_ENABLED"),
            "unexpected error: {message}"
        );

        // Metrics off with no endpoint is an ordinary configuration.
        let config = Config {
            private_repos_enable: true,
            metrics_enabled: false,
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());

        // The pair is not looked at while GRASP-P is off.
        let config = Config {
            private_repos_enable: false,
            metrics_enabled: false,
            private_metrics_bind: Some("127.0.0.1:9464".to_string()),
            ..Config::for_testing()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_grasp_p_metrics_bind_empty_is_unset() {
        assert!(Config::for_testing().private_metrics_bind.is_none());

        for unset in [None, Some(""), Some("   ")] {
            // Metrics off as well: an empty value must not count as a bind
            // address there, or it would trip the check above.
            for metrics_enabled in [true, false] {
                let config = Config {
                    private_repos_enable: true,
                    metrics_enabled,
                    private_metrics_bind: unset.map(str::to_string),
                    ..Config::for_testing()
                };
                assert!(
                    config.validate().is_ok(),
                    "{unset:?} with metrics_enabled={metrics_enabled}"
                );
                assert!(
                    config
                        .private_metrics_bind_addr()
                        .expect("an unset address is not an error")
                        .is_none(),
                    "{unset:?} must read as unset"
                );
            }
        }
    }
}
