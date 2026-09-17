//! Probe/smoke-test logic for GRASP relay health checks
//!
//! The probe runs a series of checks against a relay and reports results in
//! human-readable or JSON format. It is designed to be fast and non-destructive
//! when run in read-only mode.

mod state;

use crate::audit::AuditConfig;
use crate::client::AuditClient;
use crate::fixtures::{create_commit, init_local_repo, try_push};
use crate::pinned_proxy::PinnedSocksProxy;
use nostr_sdk::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Derive refs from one complete state snapshot: newest timestamp, then lowest ID.
/// The caller supplies the states fetched for the probed repository.
fn expected_state_refs<'a>(
    state_events: impl IntoIterator<Item = &'a Event>,
) -> std::collections::HashMap<String, String> {
    let winner = state_events.into_iter().max_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    let Some(winner) = winner else {
        return std::collections::HashMap::new();
    };
    winner
        .tags
        .iter()
        .filter_map(|tag| {
            let name = tag.kind().to_string();
            if name.starts_with("refs/heads/") || name.starts_with("refs/tags/") {
                tag.content().map(|hash| (name, hash.to_string()))
            } else {
                None
            }
        })
        .collect()
}

const MAX_NIP11_BODY_BYTES: usize = 256 * 1024;
const MAX_GIT_ADVERTISEMENT_BYTES: usize = 1024 * 1024;

/// Stable identifiers for probe checks, in execution order.
///
/// The enum is the only catalog of check names. Probe JSON retains its
/// existing string-valued `name` field for compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeCheckName {
    Prepare,
    ConnectWebsocket,
    Nip11Fetch,
    PublishEvents,
    GitRepoInitialised,
    GitPush,
    ServesLatestAnnouncement,
    GitFetchRefs,
    GitRefsMatchState,
}

impl ProbeCheckName {
    /// Checks that make up an operational probe, excluding offline setup.
    pub fn operational() -> impl Iterator<Item = Self> {
        std::iter::successors(Some(Self::ConnectWebsocket), |name| name.next())
    }

    fn after_connection_failure() -> impl Iterator<Item = Self> {
        [
            Self::Nip11Fetch,
            Self::PublishEvents,
            Self::GitRepoInitialised,
            Self::GitPush,
            Self::GitFetchRefs,
        ]
        .into_iter()
    }

    const fn next(self) -> Option<Self> {
        match self {
            Self::Prepare => Some(Self::ConnectWebsocket),
            Self::ConnectWebsocket => Some(Self::Nip11Fetch),
            Self::Nip11Fetch => Some(Self::PublishEvents),
            Self::PublishEvents => Some(Self::GitRepoInitialised),
            Self::GitRepoInitialised => Some(Self::GitPush),
            Self::GitPush => Some(Self::ServesLatestAnnouncement),
            Self::ServesLatestAnnouncement => Some(Self::GitFetchRefs),
            Self::GitFetchRefs => Some(Self::GitRefsMatchState),
            Self::GitRefsMatchState => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::ConnectWebsocket => "connect_websocket",
            Self::Nip11Fetch => "nip11_fetch",
            Self::PublishEvents => "publish_events",
            Self::GitRepoInitialised => "git_repo_initialised",
            Self::GitPush => "git_push",
            Self::ServesLatestAnnouncement => "serves_latest_announcement",
            Self::GitFetchRefs => "git_fetch_refs",
            Self::GitRefsMatchState => "git_refs_match_state",
        }
    }
}

// ============================================================
// Result types
// ============================================================

/// Result of a single probe check
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeCheck {
    pub name: &'static str,
    pub passed: bool,
    pub skipped: bool,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Full probe report containing all check results
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeReport {
    pub relay_url: String,
    pub timestamp: String,
    pub all_passed: bool,
    pub total_duration_ms: u64,
    pub checks: Vec<ProbeCheck>,
}

impl ProbeReport {
    /// Print a human-readable report with ANSI colours
    pub fn print_human(&self) {
        let green = "\x1b[1;92m";
        let red = "\x1b[1;91m";
        let yellow = "\x1b[33m";
        let bold = "\x1b[1m";
        let reset = "\x1b[0m";
        let sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";

        println!(
            "{}GRASP Probe{} — {}  [{}]",
            bold, reset, self.relay_url, self.timestamp
        );
        println!("{}", sep);

        for check in &self.checks {
            if check.skipped {
                // Don't list checks skipped due to read-only mode — they are
                // not applicable, not failures.  Only show skips caused by
                // earlier check failures so the user can see the causal chain.
                if check.error.as_deref() == Some("read-only mode") {
                    continue;
                }
                let reason = check.error.as_deref().unwrap_or("skipped");
                println!(
                    "{}→{}  {:<28} skipped  {}({}){} ",
                    yellow, reset, check.name, yellow, reason, reset
                );
            } else if check.passed {
                let detail_str = check
                    .detail
                    .as_deref()
                    .map(|d| format!("  {}", d))
                    .unwrap_or_default();
                println!(
                    "{}✓{}  {:<28} {}ms{}",
                    green, reset, check.name, check.duration_ms, detail_str
                );
            } else {
                let detail_str = check
                    .detail
                    .as_deref()
                    .map(|d| format!("  {}", d))
                    .unwrap_or_default();
                println!(
                    "{}✗{}  {:<28} {}ms{}",
                    red, reset, check.name, check.duration_ms, detail_str
                );
                if let Some(ref err) = check.error {
                    println!("     {}↳ {}{}", red, err, reset);
                }
            }
        }

        println!("{}", sep);

        if self.all_passed {
            println!(
                "{}All checks passed{}  total: {}ms",
                green, reset, self.total_duration_ms
            );
        } else {
            println!(
                "{}Some checks failed{}  total: {}ms",
                red, reset, self.total_duration_ms
            );
        }
    }

    /// Print machine-readable JSON
    pub fn print_json(&self) {
        // Exclude checks skipped due to read-only mode — they are not
        // applicable and would clutter automated consumers.
        let filtered = ProbeReport {
            checks: self
                .checks
                .iter()
                .filter(|c| !(c.skipped && c.error.as_deref() == Some("read-only mode")))
                .cloned()
                .collect(),
            ..self.clone()
        };
        println!("{}", serde_json::to_string(&filtered).unwrap());
    }
}

// ============================================================
// Helpers
// ============================================================

/// Build a skipped ProbeCheck
fn skipped(name: ProbeCheckName, reason: &str) -> ProbeCheck {
    ProbeCheck {
        name: name.as_str(),
        passed: false,
        skipped: true,
        duration_ms: 0,
        detail: None,
        error: Some(reason.to_string()),
    }
}

/// Format current time as ISO 8601 UTC (YYYY-MM-DDTHH:MM:SSZ)
fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Integer arithmetic to decompose Unix timestamp into date/time components
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400; // days since 1970-01-01

    // Compute year, month, day from days since epoch
    // Using the algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month of year [0, 11] (March=0)
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let mo = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let yr = if mo <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", yr, mo, d, h, m, s)
}

/// Optional network policy for probes.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProbeOptions {
    /// Reject non-public targets, cross-origin clone URLs, redirects, and
    /// oversized HTTP bodies. Disabled by default so local development
    /// targets remain usable.
    pub harden_network: bool,
}

async fn validate_public_url(url: &reqwest::Url, deadline: Instant) -> Result<(), String> {
    if url.query().is_some() || url.fragment().is_some() {
        return Err("URL query strings and fragments are not allowed".to_string());
    }
    resolve_public_url(url, deadline).await.map(|_| ())
}

async fn resolve_public_url(
    url: &reqwest::Url,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, String> {
    if !matches!(url.scheme(), "wss" | "https") {
        return Err("network hardening requires wss/https".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL credentials are not allowed".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "URL has no usable port".to_string())?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(ip) {
            return Err(format!("non-public target address is not allowed: {ip}"));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(format!("overall timeout before resolving {host}"));
    }
    let timeout = remaining.min(Duration::from_secs(5));
    let resolved = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| {
            if Instant::now() >= deadline {
                format!("overall timeout while resolving {host}")
            } else {
                format!("timed out resolving {host}")
            }
        })?
        .map_err(|error| format!("failed to resolve {host}: {error}"))?;
    let addresses: Vec<_> = resolved.collect();
    if addresses.is_empty() {
        return Err(format!("{host} resolved to no addresses"));
    }
    if let Some(address) = addresses.iter().find(|address| !is_public_ip(address.ip())) {
        return Err(format!(
            "{host} resolved to prohibited address {}",
            address.ip()
        ));
    }
    Ok(addresses)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }

    // Public relay targets must be in the currently allocated global-unicast
    // space (2000::/3) and outside every special-purpose range within it.
    // This intentionally fails closed for future allocations. Keep this list
    // aligned with the IANA IPv6 Special-Purpose Address Registry.
    const SPECIAL_PURPOSE: &[(u128, u8)] = &[
        (0x2001_0000_0000_0000_0000_0000_0000_0000, 23), // IETF protocols
        (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // documentation
        (0x2002_0000_0000_0000_0000_0000_0000_0000, 16), // 6to4
        (0x2620_004f_8000_0000_0000_0000_0000_0000, 48), // AS112
        (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20), // documentation
    ];

    ipv6_has_prefix(ip, 0x2000_0000_0000_0000_0000_0000_0000_0000, 3)
        && !SPECIAL_PURPOSE
            .iter()
            .any(|(network, prefix)| ipv6_has_prefix(ip, *network, *prefix))
}

fn ipv6_has_prefix(ip: Ipv6Addr, network: u128, prefix_len: u8) -> bool {
    let shift = 128 - u32::from(prefix_len);
    (u128::from(ip) >> shift) == (network >> shift)
}

fn same_origin(left: &reqwest::Url, right: &reqwest::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

async fn probe_http_client(
    url: &reqwest::Url,
    harden_network: bool,
    deadline: Instant,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder();
    if harden_network {
        let addresses = resolve_public_url(url, deadline).await?;
        let host = url
            .host_str()
            .ok_or_else(|| "URL has no host".to_string())?;
        builder = builder.redirect(reqwest::redirect::Policy::none());
        builder = builder.resolve_to_addrs(host, &addresses);
    }
    builder.build().map_err(|error| error.to_string())
}

async fn read_limited_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(format!("response exceeds {max_bytes} byte limit"));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!("response exceeds {max_bytes} byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_probe_body(
    response: reqwest::Response,
    max_bytes: Option<usize>,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    tokio::time::timeout(timeout, async {
        match max_bytes {
            Some(max_bytes) => read_limited_body(response, max_bytes).await,
            None => response
                .bytes()
                .await
                .map(|bytes| bytes.to_vec())
                .map_err(|error| error.to_string()),
        }
    })
    .await
    .map_err(|_| "timeout reading response body".to_string())?
}

// ============================================================
// Main probe function
// ============================================================

/// Run a probe against a GRASP relay and return a full report.
///
/// # Arguments
/// * `relay_url` - WebSocket URL of the relay (e.g. `ws://localhost:7000`)
/// * `keys` - Optional keypair to use; `None` generates fresh keys
/// * `read_only` - When `true`, skip write steps and only check existing repos
/// * `timeout_secs` - Per-step timeout in seconds
/// * `overall_secs` - Hard cap on total probe duration; remaining checks are
///   marked skipped with reason "overall timeout" if the deadline fires
pub async fn run_probe(
    relay_url: &str,
    keys: Option<Keys>,
    read_only: bool,
    timeout_secs: u64,
    overall_secs: u64,
) -> ProbeReport {
    run_probe_with_options(
        relay_url,
        keys,
        read_only,
        timeout_secs,
        overall_secs,
        ProbeOptions::default(),
    )
    .await
}

/// Run a probe with an explicit network policy.
pub async fn run_probe_with_options(
    relay_url: &str,
    keys: Option<Keys>,
    read_only: bool,
    timeout_secs: u64,
    overall_secs: u64,
    options: ProbeOptions,
) -> ProbeReport {
    let total_start = Instant::now();
    let deadline = total_start + Duration::from_secs(overall_secs);
    let timestamp = now_iso8601();
    let mut checks: Vec<ProbeCheck> = Vec::new();

    if options.harden_network && !read_only {
        return ProbeReport {
            relay_url: relay_url.to_string(),
            timestamp,
            all_passed: false,
            total_duration_ms: total_start.elapsed().as_millis() as u64,
            checks: vec![ProbeCheck {
                name: ProbeCheckName::Prepare.as_str(),
                passed: false,
                skipped: false,
                duration_ms: 0,
                detail: None,
                error: Some("--harden-network cannot be combined with --create-repo".to_string()),
            }],
        };
    }

    let pinned_proxy = if options.harden_network {
        match reqwest::Url::parse(relay_url) {
            Ok(url) => {
                let result = async {
                    if url.query().is_some() || url.fragment().is_some() {
                        return Err("URL query strings and fragments are not allowed".to_string());
                    }
                    let addresses = resolve_public_url(&url, deadline).await?;
                    let host = url
                        .host_str()
                        .ok_or_else(|| "URL has no host".to_string())?;
                    let port = url
                        .port_or_known_default()
                        .ok_or_else(|| "URL has no usable port".to_string())?;
                    PinnedSocksProxy::start(host.to_string(), port, addresses)
                        .await
                        .map_err(|error| format!("failed to start hardened connection: {error}"))
                }
                .await;
                match result {
                    Ok(proxy) => Some(proxy),
                    Err(error) => {
                        return ProbeReport {
                            relay_url: relay_url.to_string(),
                            timestamp,
                            all_passed: false,
                            total_duration_ms: total_start.elapsed().as_millis() as u64,
                            checks: vec![ProbeCheck {
                                name: ProbeCheckName::Prepare.as_str(),
                                passed: false,
                                skipped: false,
                                duration_ms: 0,
                                detail: None,
                                error: Some(error),
                            }],
                        };
                    }
                }
            }
            Err(error) => {
                return ProbeReport {
                    relay_url: relay_url.to_string(),
                    timestamp,
                    all_passed: false,
                    total_duration_ms: total_start.elapsed().as_millis() as u64,
                    checks: vec![ProbeCheck {
                        name: ProbeCheckName::Prepare.as_str(),
                        passed: false,
                        skipped: false,
                        duration_ms: 0,
                        detail: None,
                        error: Some(format!("invalid relay URL: {error}")),
                    }],
                };
            }
        }
    } else {
        None
    };

    /// Fill all check names not yet present in `checks` as skipped with the
    /// given reason, then return a finished ProbeReport.
    ///
    /// The deadline fired before `$timed_out_name` could start.  Diagnose
    /// whether a single prior check dominated the budget (>50%) or whether
    /// the relay was generally slow across multiple steps.
    macro_rules! deadline_return {
        ($relay_url:expr, $timestamp:expr, $total_start:expr, $overall_secs:expr, $checks:expr, $timed_out_name:expr) => {{
            let timed_out_name = $timed_out_name;
            let total_ms = $total_start.elapsed().as_millis() as u64;
            let budget_ms = ($overall_secs as u64) * 1000;

            // Find the single check that consumed the most time, if it took
            // more than half the overall budget it is the likely culprit.
            let slowest = $checks
                .iter()
                .filter(|c| !c.skipped)
                .max_by_key(|c| c.duration_ms);

            let error_msg = match slowest {
                Some(c) if c.duration_ms > budget_ms / 2 => {
                    format!("overall timeout (likely caused by slow {})", c.name)
                }
                _ => "overall timeout (cumulative slowness across checks)".to_string(),
            };

            // The step that couldn't start due to the deadline
            $checks.push(ProbeCheck {
                name: timed_out_name.as_str(),
                passed: false,
                skipped: false,
                duration_ms: 0,
                detail: None,
                error: Some(error_msg),
            });
            // Skip all subsequent checks
            let already: std::collections::HashSet<&str> = $checks.iter().map(|c| c.name).collect();
            for name in ProbeCheckName::operational() {
                if !already.contains(name.as_str()) {
                    $checks.push(skipped(name, "overall timeout"));
                }
            }
            let all_passed = $checks.iter().all(|c| c.passed || c.skipped);
            return ProbeReport {
                relay_url: $relay_url.to_string(),
                timestamp: $timestamp,
                all_passed,
                total_duration_ms: total_ms,
                checks: $checks,
            };
        }};
    }

    // ============================================================
    // PREPARE (offline)
    // ============================================================
    let keys = keys.unwrap_or_else(Keys::generate);
    let npub = match keys.public_key().to_bech32() {
        Ok(n) => n,
        Err(e) => {
            // Can't proceed without npub
            return ProbeReport {
                relay_url: relay_url.to_string(),
                timestamp,
                all_passed: false,
                total_duration_ms: total_start.elapsed().as_millis() as u64,
                checks: vec![ProbeCheck {
                    name: ProbeCheckName::Prepare.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: 0,
                    detail: None,
                    error: Some(format!("Failed to derive npub: {}", e)),
                }],
            };
        }
    };

    let repo_id = format!("probe-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let _relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .trim_end_matches('/')
        .to_string();
    let http_base = relay_url
        .replace("ws://", "http://")
        .replace("wss://", "https://")
        .trim_end_matches('/')
        .to_string();
    let clone_url = format!("{}/{}/{}.git", http_base, npub, repo_id);

    // Create temp dir for local repo
    let local_repo_path =
        std::env::temp_dir().join(format!("grasp-probe-{}", uuid::Uuid::new_v4()));

    // Initialise local repo (offline)
    let init_result = init_local_repo(&local_repo_path, &clone_url);
    let commit_hash = if init_result.is_ok() {
        create_commit(&local_repo_path, "GRASP probe commit").ok()
    } else {
        None
    };

    // Build announcement and state events (not sent yet)
    let config = AuditConfig::probe();
    let announcement_event_opt: Option<Event>;
    let state_event_opt: Option<Event>;

    {
        use nostr_sdk::prelude::*;

        let ann_result = crate::audit::AuditEventBuilder::new(
            Kind::GitRepoAnnouncement,
            "GRASP probe repository",
            config.clone(),
        )
        .tag(Tag::identifier(&repo_id))
        .tag(Tag::custom("name", vec!["GRASP Probe Repository"]))
        .tag(Tag::custom("clone", vec![clone_url.clone()]))
        .tag(Tag::custom("relays", vec![relay_url.to_string()]))
        .build(&keys);

        announcement_event_opt = ann_result.ok();

        let state_result = if let Some(ref ch) = commit_hash {
            crate::audit::AuditEventBuilder::new(Kind::RepoState, "", config.clone())
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom("refs/heads/main", vec![ch.clone()]))
                .tag(Tag::custom(
                    "HEAD",
                    vec!["ref: refs/heads/main".to_string()],
                ))
                .build(&keys)
                .ok()
        } else {
            None
        };

        state_event_opt = state_result;
    }

    // ============================================================
    // Step 1: connect_websocket
    // ============================================================
    if Instant::now() >= deadline {
        deadline_return!(
            relay_url,
            timestamp,
            total_start,
            overall_secs,
            checks,
            ProbeCheckName::ConnectWebsocket
        );
    }
    let step1_start = Instant::now();
    let connect = async {
        match pinned_proxy.as_ref() {
            Some(proxy) => {
                AuditClient::new_with_keys_and_proxy(
                    relay_url,
                    config.clone(),
                    keys.clone(),
                    Proxy::all(proxy.address()),
                )
                .await
            }
            None => AuditClient::new_with_keys(relay_url, config.clone(), keys.clone()).await,
        }
    };
    let client_result =
        tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), connect)
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("overall timeout")));
    let step1_ms = step1_start.elapsed().as_millis() as u64;

    let client = match client_result {
        Ok(c) => {
            checks.push(ProbeCheck {
                name: ProbeCheckName::ConnectWebsocket.as_str(),
                passed: true,
                skipped: false,
                duration_ms: step1_ms,
                detail: None,
                error: None,
            });
            c
        }
        Err(e) => {
            checks.push(ProbeCheck {
                name: ProbeCheckName::ConnectWebsocket.as_str(),
                passed: false,
                skipped: false,
                duration_ms: step1_ms,
                detail: None,
                error: Some(e.to_string()),
            });
            // Skip all remaining steps
            for name in ProbeCheckName::after_connection_failure() {
                checks.push(skipped(name, "connect_websocket failed"));
            }
            let _ = std::fs::remove_dir_all(&local_repo_path);
            return ProbeReport {
                relay_url: relay_url.to_string(),
                timestamp,
                all_passed: false,
                total_duration_ms: total_start.elapsed().as_millis() as u64,
                checks,
            };
        }
    };

    // ============================================================
    // Step 2: nip11_fetch (independent — always runs if step 1 passed)
    // ============================================================
    {
        if Instant::now() >= deadline {
            deadline_return!(
                relay_url,
                timestamp,
                total_start,
                overall_secs,
                checks,
                ProbeCheckName::Nip11Fetch
            );
        }
        let step2_start = Instant::now();
        let http_url = reqwest::Url::parse(&http_base);
        let http_client = match http_url {
            Ok(ref url) => probe_http_client(url, options.harden_network, deadline).await,
            Err(error) => Err(format!("invalid NIP-11 URL: {error}")),
        };
        let nip11_result = tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(timeout_secs)),
            async {
                http_client?
                    .get(&http_base)
                    .header("Accept", "application/nostr+json")
                    .send()
                    .await
                    .map_err(|error| error.to_string())
            },
        )
        .await;

        let step2_ms = step2_start.elapsed().as_millis() as u64;

        match nip11_result {
            Ok(Ok(resp)) if resp.status().is_success() => {
                let body = read_probe_body(
                    resp,
                    options.harden_network.then_some(MAX_NIP11_BODY_BYTES),
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_secs(timeout_secs)),
                )
                .await;
                match body {
                    Ok(body) => {
                        let detail =
                            serde_json::from_slice::<serde_json::Value>(&body)
                                .ok()
                                .map(|value| {
                                    let name = value
                                        .get("name")
                                        .and_then(|name| name.as_str())
                                        .unwrap_or("unknown");
                                    let software = value
                                        .get("software")
                                        .and_then(|software| software.as_str())
                                        .map(|software| {
                                            software
                                                .trim_end_matches('/')
                                                .rsplit('/')
                                                .next()
                                                .unwrap_or(software)
                                        })
                                        .unwrap_or("unknown");
                                    let version = value
                                        .get("version")
                                        .and_then(|version| version.as_str())
                                        .unwrap_or("unknown");
                                    format!("{name} ({software} v{version})")
                                });
                        checks.push(ProbeCheck {
                            name: ProbeCheckName::Nip11Fetch.as_str(),
                            passed: true,
                            skipped: false,
                            duration_ms: step2_ms,
                            detail,
                            error: None,
                        });
                    }
                    Err(error) => checks.push(ProbeCheck {
                        name: ProbeCheckName::Nip11Fetch.as_str(),
                        passed: false,
                        skipped: false,
                        duration_ms: step2_ms,
                        detail: None,
                        error: Some(error),
                    }),
                }
            }
            Ok(Ok(resp)) => {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::Nip11Fetch.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: step2_ms,
                    detail: None,
                    error: Some(format!("HTTP {}", resp.status())),
                });
            }
            Ok(Err(e)) => {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::Nip11Fetch.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: step2_ms,
                    detail: None,
                    error: Some(e.to_string()),
                });
            }
            Err(_) => {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::Nip11Fetch.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: step2_ms,
                    detail: None,
                    error: Some("timeout".to_string()),
                });
            }
        }
    }

    // ============================================================
    // Step 3: publish_events (requires step 1; skipped in read_only)
    // ============================================================
    let mut write_succeeded = false;

    if Instant::now() >= deadline {
        deadline_return!(
            relay_url,
            timestamp,
            total_start,
            overall_secs,
            checks,
            ProbeCheckName::PublishEvents
        );
    }

    if read_only {
        checks.push(skipped(ProbeCheckName::PublishEvents, "read-only mode"));
        checks.push(skipped(
            ProbeCheckName::GitRepoInitialised,
            "read-only mode",
        ));
        checks.push(skipped(ProbeCheckName::GitPush, "read-only mode"));
    } else {
        let step3_start = Instant::now();

        let send_result = match (&announcement_event_opt, &state_event_opt) {
            (Some(ann), Some(state)) => {
                let r1 = client.send_event(ann.clone()).await;
                let r2 = if r1.is_ok() {
                    client.send_event(state.clone()).await
                } else {
                    r1.map(|_| EventId::from_byte_array([0; 32]))
                };
                r2
            }
            _ => Err(anyhow::anyhow!(
                "Events could not be built (local repo init failed)"
            )),
        };

        let step3_ms = step3_start.elapsed().as_millis() as u64;

        match send_result {
            Ok(_) => {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::PublishEvents.as_str(),
                    passed: true,
                    skipped: false,
                    duration_ms: step3_ms,
                    detail: None,
                    error: None,
                });
                write_succeeded = true;
            }
            Err(e) => {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::PublishEvents.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: step3_ms,
                    detail: None,
                    error: Some(e.to_string()),
                });
                // Skip steps 4 and 5; step 6 will use fallback
                checks.push(skipped(
                    ProbeCheckName::GitRepoInitialised,
                    "publish_events failed",
                ));
                checks.push(skipped(ProbeCheckName::GitPush, "publish_events failed"));
            }
        }

        // ============================================================
        // Step 4: git_repo_initialised (requires step 3)
        // ============================================================
        if write_succeeded {
            if Instant::now() >= deadline {
                deadline_return!(
                    relay_url,
                    timestamp,
                    total_start,
                    overall_secs,
                    checks,
                    ProbeCheckName::GitRepoInitialised
                );
            }
            let step4_start = Instant::now();
            let poll_url = format!("{}/info/refs?service=git-upload-pack", clone_url);
            let http_client = reqwest::Client::new();
            // Cap the poll deadline at both 15s and the overall deadline
            let poll_deadline = (Instant::now() + Duration::from_secs(15)).min(deadline);
            let mut repo_ready = false;

            loop {
                if Instant::now() >= poll_deadline {
                    break;
                }
                match http_client.get(&poll_url).send().await {
                    Ok(resp) if resp.status().as_u16() != 404 => {
                        repo_ready = true;
                        break;
                    }
                    _ => {}
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            let step4_ms = step4_start.elapsed().as_millis() as u64;

            if repo_ready {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::GitRepoInitialised.as_str(),
                    passed: true,
                    skipped: false,
                    duration_ms: step4_ms,
                    detail: None,
                    error: None,
                });
            } else {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::GitRepoInitialised.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: step4_ms,
                    detail: None,
                    error: Some("timeout waiting for repo to be initialised (15s)".to_string()),
                });
                write_succeeded = false;
                checks.push(skipped(
                    ProbeCheckName::GitPush,
                    "git_repo_initialised timed out",
                ));
            }
        }

        // ============================================================
        // Step 5: git_push (requires step 4)
        // ============================================================
        if write_succeeded {
            if Instant::now() >= deadline {
                deadline_return!(
                    relay_url,
                    timestamp,
                    total_start,
                    overall_secs,
                    checks,
                    ProbeCheckName::GitPush
                );
            }
            let step5_start = Instant::now();
            let push_result = try_push(&local_repo_path);
            let step5_ms = step5_start.elapsed().as_millis() as u64;

            match push_result {
                Ok(true) => {
                    checks.push(ProbeCheck {
                        name: ProbeCheckName::GitPush.as_str(),
                        passed: true,
                        skipped: false,
                        duration_ms: step5_ms,
                        detail: None,
                        error: None,
                    });
                }
                Ok(false) => {
                    checks.push(ProbeCheck {
                        name: ProbeCheckName::GitPush.as_str(),
                        passed: false,
                        skipped: false,
                        duration_ms: step5_ms,
                        detail: None,
                        error: Some("push rejected by relay".to_string()),
                    });
                    write_succeeded = false;
                }
                Err(e) => {
                    checks.push(ProbeCheck {
                        name: ProbeCheckName::GitPush.as_str(),
                        passed: false,
                        skipped: false,
                        duration_ms: step5_ms,
                        detail: None,
                        error: Some(e),
                    });
                    write_succeeded = false;
                }
            }
        }
    }

    // ============================================================
    // Step 6: git_fetch_refs
    // ============================================================
    // Two paths:
    //   write_succeeded=true  → check our own repo; compare refs against our state event
    //   write_succeeded=false → find any existing kind 30617; just verify refs are readable
    //
    // In read-only mode we also run a find_announcement check first.

    // Helper: parse pkt-line body into a map of refname -> commit hash,
    // excluding refs/nostr/* entries (only branches and tags).
    fn parse_refs(body: &str) -> Vec<(String, String)> {
        let mut refs = Vec::new();
        for line in body.lines() {
            // pkt-line: 4-hex-char length prefix, then "<hash> <refname>\0<caps>" or "<hash> <refname>"
            let content = if line.len() > 4 { &line[4..] } else { continue };
            // Strip NUL and everything after (capabilities on first line)
            let content = content.split('\0').next().unwrap_or(content).trim();
            // Skip flush packets and service lines
            if content.starts_with('#') || content.is_empty() || content == "0000" {
                continue;
            }
            let mut parts = content.splitn(2, ' ');
            let hash = match parts.next() {
                Some(h) if h.len() == 40 => h,
                _ => continue,
            };
            let refname = match parts.next() {
                Some(r) => r.trim(),
                None => continue,
            };
            // Skip refs/nostr/* — only branches (refs/heads/*) and tags (refs/tags/*)
            if refname.starts_with("refs/nostr/") {
                continue;
            }
            refs.push((refname.to_string(), hash.to_string()));
        }
        refs
    }

    if write_succeeded {
        // ---- Write path ----
        // Step 6a: git_fetch_refs — just verify the endpoint returns 200
        if Instant::now() >= deadline {
            deadline_return!(
                relay_url,
                timestamp,
                total_start,
                overall_secs,
                checks,
                ProbeCheckName::GitFetchRefs
            );
        }
        let refs_url = format!("{}/info/refs?service=git-upload-pack", clone_url);
        let http_client = reqwest::Client::new();

        let step6_start = Instant::now();
        let refs_result = tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(timeout_secs)),
            http_client.get(&refs_url).send(),
        )
        .await;
        let step6_ms = step6_start.elapsed().as_millis() as u64;

        // Capture body for the next check; only proceed to match check if fetch succeeded
        let refs_body: Option<String> = match refs_result {
            Ok(Ok(resp)) if resp.status().is_success() => {
                let body = resp.text().await.unwrap_or_default();
                checks.push(ProbeCheck {
                    name: ProbeCheckName::GitFetchRefs.as_str(),
                    passed: true,
                    skipped: false,
                    duration_ms: step6_ms,
                    detail: None,
                    error: None,
                });
                Some(body)
            }
            Ok(Ok(resp)) => {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::GitFetchRefs.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: step6_ms,
                    detail: None,
                    error: Some(format!("HTTP {}", resp.status())),
                });
                None
            }
            Ok(Err(e)) => {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::GitFetchRefs.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: step6_ms,
                    detail: None,
                    error: Some(e.to_string()),
                });
                None
            }
            Err(_) => {
                checks.push(ProbeCheck {
                    name: ProbeCheckName::GitFetchRefs.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: step6_ms,
                    detail: None,
                    error: Some("timeout".to_string()),
                });
                None
            }
        };

        // Step 6b: git_refs_match_state — compare fetched refs against our state event
        match refs_body {
            None => {
                checks.push(skipped(
                    ProbeCheckName::GitRefsMatchState,
                    "git_fetch_refs failed",
                ));
            }
            Some(body) => {
                let fetched_refs = parse_refs(&body);
                let expected = expected_state_refs(state_event_opt.iter());
                let mismatches = state::ref_mismatches(&expected, &fetched_refs);

                checks.push(ProbeCheck {
                    name: ProbeCheckName::GitRefsMatchState.as_str(),
                    passed: mismatches.is_empty(),
                    skipped: false,
                    duration_ms: 0, // no extra network call; cost already in git_fetch_refs
                    detail: None,
                    error: if mismatches.is_empty() {
                        None
                    } else {
                        Some(mismatches.join("; "))
                    },
                });
            }
        }
    } else {
        // ---- Fallback path: find any existing kind 30617, check refs readable ----

        // In read-only mode: first check that at least one announcement exists
        if Instant::now() >= deadline {
            deadline_return!(
                relay_url,
                timestamp,
                total_start,
                overall_secs,
                checks,
                ProbeCheckName::ServesLatestAnnouncement
            );
        }
        let filter = Filter::new().kind(Kind::GitRepoAnnouncement).limit(1);
        let existing = client
            .client()
            .fetch_events(filter)
            .timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(5)),
            )
            .await
            .unwrap_or_default();

        let found_event = existing.into_iter().next();

        if read_only {
            // Explicit check: was an announcement found?
            match &found_event {
                Some(ev) => {
                    let ann_npub = ev.pubkey.to_bech32().unwrap_or_else(|_| ev.pubkey.to_hex());
                    let ann_id = ev
                        .tags
                        .iter()
                        .find(|t| t.kind() == "d")
                        .and_then(|t| t.content())
                        .unwrap_or("unknown")
                        .to_string();
                    checks.push(ProbeCheck {
                        name: ProbeCheckName::ServesLatestAnnouncement.as_str(),
                        passed: true,
                        skipped: false,
                        duration_ms: 0,
                        detail: Some(format!("{}/{}", ann_npub, ann_id)),
                        error: None,
                    });
                }
                None => {
                    checks.push(ProbeCheck {
                        name: ProbeCheckName::ServesLatestAnnouncement.as_str(),
                        passed: false,
                        skipped: false,
                        duration_ms: 0,
                        detail: None,
                        error: Some("no kind:30617 announcements found on relay".to_string()),
                    });
                    let _ = std::fs::remove_dir_all(&local_repo_path);
                    let all_passed = checks.iter().all(|c| c.passed || c.skipped);
                    return ProbeReport {
                        relay_url: relay_url.to_string(),
                        timestamp,
                        all_passed,
                        total_duration_ms: total_start.elapsed().as_millis() as u64,
                        checks,
                    };
                }
            }
        }

        // Now fetch refs from the found repo
        match found_event {
            Some(ev) => {
                let ann_npub = ev.pubkey.to_bech32().unwrap_or_else(|_| ev.pubkey.to_hex());
                let ann_id = ev
                    .tags
                    .iter()
                    .find(|t| t.kind() == "d")
                    .and_then(|t| t.content())
                    .unwrap_or("unknown")
                    .to_string();

                // Prefer the clone tag URL; fall back to constructing from relay
                let fetch_url = ev
                    .tags
                    .iter()
                    .find(|t| t.kind() == "clone")
                    .and_then(|t| t.content())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("{}/{}/{}.git", http_base, ann_npub, ann_id));

                if Instant::now() >= deadline {
                    deadline_return!(
                        relay_url,
                        timestamp,
                        total_start,
                        overall_secs,
                        checks,
                        ProbeCheckName::GitFetchRefs
                    );
                }
                let step6_start = Instant::now();
                let refs_url = format!("{}/info/refs?service=git-upload-pack", fetch_url);
                let fetch_url_parsed = reqwest::Url::parse(&fetch_url);
                let refs_url_parsed = reqwest::Url::parse(&refs_url);
                let http_base_parsed = reqwest::Url::parse(&http_base);
                let http_client = match (&fetch_url_parsed, &refs_url_parsed, &http_base_parsed) {
                    (Ok(fetch), Ok(url), Ok(base))
                        if !options.harden_network || same_origin(fetch, base) =>
                    {
                        if options.harden_network {
                            match validate_public_url(fetch, deadline).await {
                                Ok(()) => probe_http_client(url, true, deadline).await,
                                Err(error) => Err(error),
                            }
                        } else {
                            probe_http_client(url, false, deadline).await
                        }
                    }
                    (Ok(_), Ok(_), Ok(_)) => {
                        Err("announcement clone URL leaves audited service origin".to_string())
                    }
                    (Err(error), _, _) => Err(format!("invalid clone URL: {error}")),
                    (_, Err(error), _) => Err(format!("invalid Git URL: {error}")),
                    (_, _, Err(error)) => Err(format!("invalid service URL: {error}")),
                };
                let refs_result = tokio::time::timeout(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_secs(timeout_secs)),
                    async {
                        http_client?
                            .get(&refs_url)
                            .send()
                            .await
                            .map_err(|error| error.to_string())
                    },
                )
                .await;
                let step6_ms = step6_start.elapsed().as_millis() as u64;

                // Capture body for git_refs_match_state if fetch succeeds
                let refs_body_fallback: Option<String> = match refs_result {
                    Ok(Ok(resp)) if resp.status().is_success() => {
                        let body = read_probe_body(
                            resp,
                            options
                                .harden_network
                                .then_some(MAX_GIT_ADVERTISEMENT_BYTES),
                            deadline
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_secs(timeout_secs)),
                        )
                        .await
                        .map(|body| String::from_utf8_lossy(&body).into_owned());
                        match body {
                            Ok(body) => {
                                checks.push(ProbeCheck {
                                    name: ProbeCheckName::GitFetchRefs.as_str(),
                                    passed: true,
                                    skipped: false,
                                    duration_ms: step6_ms,
                                    detail: None,
                                    error: None,
                                });
                                Some(body)
                            }
                            Err(error) => {
                                checks.push(ProbeCheck {
                                    name: ProbeCheckName::GitFetchRefs.as_str(),
                                    passed: false,
                                    skipped: false,
                                    duration_ms: step6_ms,
                                    detail: None,
                                    error: Some(error),
                                });
                                None
                            }
                        }
                    }
                    Ok(Ok(resp)) => {
                        checks.push(ProbeCheck {
                            name: ProbeCheckName::GitFetchRefs.as_str(),
                            passed: false,
                            skipped: false,
                            duration_ms: step6_ms,
                            detail: None,
                            error: Some(format!("HTTP {}", resp.status())),
                        });
                        None
                    }
                    Ok(Err(e)) => {
                        checks.push(ProbeCheck {
                            name: ProbeCheckName::GitFetchRefs.as_str(),
                            passed: false,
                            skipped: false,
                            duration_ms: step6_ms,
                            detail: None,
                            error: Some(e.to_string()),
                        });
                        None
                    }
                    Err(_) => {
                        checks.push(ProbeCheck {
                            name: ProbeCheckName::GitFetchRefs.as_str(),
                            passed: false,
                            skipped: false,
                            duration_ms: step6_ms,
                            detail: None,
                            error: Some("timeout".to_string()),
                        });
                        None
                    }
                };

                // git_refs_match_state: fetch all served kind 30618 state events for this
                // repo (by #d tag), select the newest complete state snapshot
                // (lowest event ID breaks timestamp ties), then compare its refs.
                match refs_body_fallback {
                    None => {
                        checks.push(skipped(
                            ProbeCheckName::GitRefsMatchState,
                            "git_fetch_refs failed",
                        ));
                    }
                    Some(body) => {
                        let fetched_refs = parse_refs(&body);

                        // Fetch all state events for this repo_id from the relay.
                        // The relay only serves state events authorized by a selected
                        // coordinate's resolved reciprocal component.
                        let state_filter = Filter::new().kind(Kind::RepoState).custom_tag(
                            nostr_sdk::prelude::SingleLetterTag::LOWERCASE_D,
                            ann_id.clone(),
                        );
                        let state_events = client
                            .client()
                            .fetch_events(state_filter)
                            .timeout(
                                deadline
                                    .saturating_duration_since(Instant::now())
                                    .min(Duration::from_secs(5)),
                            )
                            .await
                            .unwrap_or_default();

                        if state_events.is_empty() {
                            checks.push(ProbeCheck {
                                name: ProbeCheckName::GitRefsMatchState.as_str(),
                                passed: false,
                                skipped: false,
                                duration_ms: 0,
                                detail: None,
                                error: Some(
                                    "no kind:30618 state events found for this repo".to_string(),
                                ),
                            });
                        } else {
                            let expected = expected_state_refs(state_events.iter());

                            let mismatches = state::ref_mismatches(&expected, &fetched_refs);

                            checks.push(ProbeCheck {
                                name: ProbeCheckName::GitRefsMatchState.as_str(),
                                passed: mismatches.is_empty(),
                                skipped: false,
                                duration_ms: 0,
                                detail: None,
                                error: if mismatches.is_empty() {
                                    None
                                } else {
                                    Some(mismatches.join("; "))
                                },
                            });
                        }
                    }
                }
            }
            None => {
                // Not read-only (already handled above) but no repo found
                checks.push(ProbeCheck {
                    name: ProbeCheckName::GitFetchRefs.as_str(),
                    passed: false,
                    skipped: false,
                    duration_ms: 0,
                    detail: None,
                    error: Some("no repositories found on relay".to_string()),
                });
                checks.push(skipped(
                    ProbeCheckName::GitRefsMatchState,
                    "no announcement found",
                ));
            }
        }
    }

    // ============================================================
    // CLEANUP
    // ============================================================
    let _ = std::fs::remove_dir_all(&local_repo_path);

    let all_passed = checks.iter().all(|c| c.passed || c.skipped);
    ProbeReport {
        relay_url: relay_url.to_string(),
        timestamp,
        all_passed,
        total_duration_ms: total_start.elapsed().as_millis() as u64,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ref_state(keys: &Keys, timestamp: u64, branch: &str) -> Event {
        EventBuilder::new(Kind::RepoState, "")
            .tags([
                Tag::identifier("test-repo"),
                Tag::custom("refs/heads/main", ["a".repeat(40)]),
                Tag::custom(format!("refs/heads/{branch}"), ["b".repeat(40)]),
                Tag::custom(format!("refs/tags/{branch}"), ["c".repeat(40)]),
                Tag::custom("HEAD", ["ref: refs/heads/main"]),
                Tag::custom("refs/nostr/private", ["d".repeat(40)]),
            ])
            .custom_created_at(Timestamp::from_secs(timestamp))
            .finalize(keys)
            .unwrap()
    }

    #[test]
    fn expected_refs_choose_lower_id_snapshot_on_timestamp_tie() {
        // Different maintainers can both have a served state at the same timestamp.
        let mut states = [
            ref_state(&Keys::generate(), 100, "first"),
            ref_state(&Keys::generate(), 100, "second"),
        ];
        states.sort_by_key(|event| event.id);
        let [winner, loser] = states;
        let expected = expected_state_refs([&winner]);
        assert_eq!(expected.len(), 3);
        for order in [[&winner, &loser], [&loser, &winner]] {
            assert_eq!(expected_state_refs(order), expected);
        }
    }

    #[test]
    fn expected_refs_drop_branches_and_tags_absent_from_newest_state() {
        let keys = Keys::generate();
        let older = ref_state(&keys, 100, "removed");
        let newer = ref_state(&keys, 101, "current");
        let expected = expected_state_refs([&newer]);
        assert!(!expected.contains_key("refs/heads/removed"));
        assert!(!expected.contains_key("refs/tags/removed"));
        for order in [[&older, &newer], [&newer, &older]] {
            assert_eq!(expected_state_refs(order), expected);
        }
        assert!(expected_state_refs([]).is_empty());
        let empty = EventBuilder::new(Kind::RepoState, "")
            .tags([Tag::identifier("test-repo")])
            .custom_created_at(Timestamp::from_secs(102))
            .finalize(&keys)
            .unwrap();
        assert!(expected_state_refs([&older, &newer, &empty]).is_empty());
    }

    #[test]
    fn probe_check_catalog_preserves_public_names_and_order() {
        let names: Vec<_> = ProbeCheckName::operational()
            .map(ProbeCheckName::as_str)
            .collect();

        assert_eq!(
            names,
            [
                "connect_websocket",
                "nip11_fetch",
                "publish_events",
                "git_repo_initialised",
                "git_push",
                "serves_latest_announcement",
                "git_fetch_refs",
                "git_refs_match_state",
            ]
        );
        assert_eq!(
            serde_json::to_string(&ProbeCheckName::GitRepoInitialised).unwrap(),
            "\"git_repo_initialised\""
        );
    }

    #[test]
    fn hardening_rejects_private_and_special_addresses() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "2001:db8::1",
            "64:ff9b::8.8.8.8",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2002:0808:0808::1",
            "2620:4f:8000::1",
            "3fff::1",
            "5f00::1",
            "4000::1",
            "::8.8.8.8",
        ] {
            assert!(
                !is_public_ip(address.parse().unwrap()),
                "{address} must be rejected"
            );
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn hardened_urls_reject_queries_and_fragments() {
        for url in ["wss://8.8.8.8/?query=true", "wss://8.8.8.8/#fragment"] {
            assert!(validate_public_url(
                &reqwest::Url::parse(url).unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn hardened_http_requests_allow_generated_git_query() {
        let url = reqwest::Url::parse("https://8.8.8.8/info/refs?service=git-upload-pack").unwrap();
        assert!(
            probe_http_client(&url, true, Instant::now() + Duration::from_secs(5))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn hardened_resolution_honours_an_expired_overall_deadline() {
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let error = resolve_public_url(&url, Instant::now()).await.unwrap_err();

        assert!(error.contains("overall timeout"));
    }

    #[tokio::test]
    async fn hardening_rejects_write_probes_before_connecting() {
        let report = run_probe_with_options(
            "wss://example.com",
            None,
            false,
            30,
            60,
            ProbeOptions {
                harden_network: true,
            },
        )
        .await;

        assert!(!report.all_passed);
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].name, ProbeCheckName::Prepare.as_str());
        assert_eq!(
            report.checks[0].error.as_deref(),
            Some("--harden-network cannot be combined with --create-repo")
        );
    }

    #[test]
    fn origin_comparison_includes_scheme_host_and_port() {
        let base = reqwest::Url::parse("https://example.com/repo").unwrap();
        assert!(same_origin(
            &base,
            &reqwest::Url::parse("https://example.com/other").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &reqwest::Url::parse("https://example.net/repo").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &reqwest::Url::parse("https://example.com:8443/repo").unwrap()
        ));
    }
}
