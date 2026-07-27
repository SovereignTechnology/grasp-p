//! GRASP-P Phase 2 blob mirror (pull-only).
//!
//! On any accepted kind-30641 the referenced manifest/pack blobs must exist
//! locally. On the origin node they already do (the client PUT them before
//! publishing); on the replicating node they are missing and are pulled here
//! over the peer's EXISTING public `GET /<sha256>` route — no new inbound
//! surface.
//!
//! Design invariants:
//! - Streamed to a temp file through the Phase-1 [`UploadSink`], which caps
//!   bytes at `min(declared, max_blob_bytes)` mid-stream (a hostile peer
//!   cannot stream unbounded), verifies the SHA-256 against the requested
//!   hash, fsyncs + renames, and claims + charges the replicated tenant's
//!   ledger atomically (same GC-TOCTOU-safe path as a client upload).
//! - Over quota / global budget → skip; the blob stays missing and is
//!   reflected in the `ngit_private_mirror_lag_blobs` gauge (alert on
//!   sustained > 0 — silent-desync lesson F1).
//! - Idempotent: a job whose blob is already local is a no-op; repair scans
//!   re-derive want sets from blob claims (which 30641 handling maintains),
//!   so a restart or a transiently unreachable peer heals automatically.
//!
//! ## Phase-4b B2: retry taxonomy (exponential backoff with jitter)
//!
//! Every fetch failure is classified from its reason string and either
//! gated by the per-blob backoff schedule or left to the flat repair scan:
//!
//! | Reason                              | Class         | Retry behavior                                    |
//! |-------------------------------------|---------------|---------------------------------------------------|
//! | `network: …` (transport)            | transient     | backoff `base * 2^attempt` (capped, ±20% jitter)  |
//! | `http_status: 5xx`                  | transient     | same backoff schedule                             |
//! | `http_status: <other>`              | transient     | same backoff schedule (proxy/edge oddities)       |
//! | `no_peer`                           | transient     | same backoff schedule (peer set may appear)       |
//! | `http_status: 404` (all peers)      | late upload   | backoff retry but always at the MAX interval      |
//! | `too_large`                         | deterministic | NO hot retry — flat repair-scan cadence only      |
//! | `verify: …` (bad bytes/size)        | deterministic | NO hot retry (peer serves poison — content-fixed) |
//! | `store: …` (incl. finish() 403)     | deterministic | NO hot retry (registration/quota state must move) |
//! | `blocked` (SSRF guard)              | deterministic | NO hot retry (config must change)                 |
//! | `quota`                             | deterministic | NO hot retry (GC/ledger must free space)          |
//! | `reserve: …` / `sink: …` / `write: …` | deterministic | NO hot retry (local state must change)            |
//!
//! "NO hot retry" keeps the pre-B2 behavior exactly: the blob is not gated,
//! so the flat repair scan re-enqueues it every tick and it succeeds as
//! soon as the underlying condition changes (persist-skips like the
//! denylist never reach this table at all — they are filtered earlier).
//! Backoff-gated blobs stay counted in `ngit_private_mirror_lag_blobs`;
//! the gate only suppresses re-ENQUEUE, never the gauge. There is no
//! give-up: a referenced blob may legitimately appear late.
//!
//! Retry state is per-blob `(attempt count, next-eligible Instant)` held
//! in memory next to the worker's `inflight` set; a restart resets every
//! blob to the base interval (documented behavior — the boot repair scan
//! immediately re-derives all wants anyway).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr::Event;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::blob_store::UploadSink;
use super::{BlobError, PrivateService};

/// One blob a mirror job wants locally.
#[derive(Debug, Clone)]
pub struct WantBlob {
    pub sha256: String,
    /// Declared size from the 30641 tag / blob claim (upload-sink cap +
    /// in-flight reservation size).
    pub size: u64,
}

/// A mirror work item: pull `want` for (tenant, alias) from `peer_servers`.
#[derive(Debug, Clone)]
pub struct MirrorJob {
    pub tenant_hex: String,
    pub alias: String,
    pub want: Vec<WantBlob>,
    /// Peer blob-server base URLs (this node's own domain already excluded).
    pub peer_servers: Vec<String>,
}

/// Normalize a `server` tag value / configured peer URL into an HTTP base
/// URL: keeps explicit http:// (tests) and https:// schemes, defaults bare
/// host[:port] values to https://, and trims trailing slashes.
fn server_base_url(value: &str) -> Option<String> {
    let v = value.trim().trim_end_matches('/');
    if v.is_empty() {
        return None;
    }
    if v.starts_with("http://") || v.starts_with("https://") {
        Some(v.to_string())
    } else {
        Some(format!("https://{v}"))
    }
}

/// Extract an embedded IPv4 address from the IPv6 transition/translation forms
/// that carry a v4 payload in their low bits: IPv4-mapped (::ffff:0:0/96),
/// NAT64 (64:ff9b::/96), 6to4 (2002::/16, embedded v4 in bytes 2..6), and
/// IPv4-compatible (::/96). Any of these can smuggle an internal v4 (e.g.
/// 169.254.169.254) past a v6-only guard, so we must decode and re-check them.
fn embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    // IPv4-mapped ::ffff:a.b.c.d
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let o = v6.octets();
    // NAT64 well-known prefix 64:ff9b::/96 → embedded v4 in the low 32 bits.
    if o[0] == 0x00
        && o[1] == 0x64
        && o[2] == 0xff
        && o[3] == 0x9b
        && o[4..12].iter().all(|b| *b == 0)
    {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    // 6to4 2002::/16 → embedded v4 in bytes 2..6.
    if o[0] == 0x20 && o[1] == 0x02 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    // IPv4-compatible ::/96 (deprecated) → embedded v4 in the low 32 bits, but
    // only when it is a genuine embedded address, not :: / ::1 (those are
    // already rejected as unspecified/loopback by the caller).
    if o[0..12].iter().all(|b| *b == 0) && !(o[12] == 0 && o[13] == 0 && o[14] == 0) {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

/// True for IPs the mirror must never fetch from in production: loopback,
/// RFC1918 private, CGNAT shared, link-local, unspecified, broadcast,
/// multicast, documentation, IPv6 ULA/link-local, and any embedded-IPv4
/// transition form (IPv4-mapped, NAT64, 6to4, IPv4-compatible) wrapping one
/// of these.
fn is_disallowed_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // CGNAT shared address space 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique local fc00::/7
                || (v6.octets()[0] & 0xfe) == 0xfc
                // link-local fe80::/10
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80)
                // Embedded-IPv4 transition forms (IPv4-mapped / NAT64 / 6to4 /
                // IPv4-compatible) — decode and re-check the embedded v4 so an
                // internal address cannot be smuggled through a v6 wrapper.
                || embedded_ipv4(v6)
                    .map(|v4| is_disallowed_ip(&IpAddr::V4(v4)))
                    .unwrap_or(false)
        }
    }
}

/// SSRF guard for a peer base URL. With `allow_private` (tests) any peer is
/// allowed. Otherwise: require https, resolve the host, and reject if it does
/// not resolve or if ANY resolved address is a disallowed (internal) IP. This
/// defeats the trivial literal-IP / static-hostname SSRF via a hostile 30640
/// `server` tag; DNS-rebinding at connection time remains a documented residual
/// (production should set NGIT_PRIVATE_MIRROR_PEER_URLS to the known peer).
async fn peer_allowed(peer_base: &str, allow_private: bool) -> bool {
    if allow_private {
        return true;
    }
    let Some(rest) = peer_base.strip_prefix("https://") else {
        // Plaintext http is only permitted under allow_private (loopback tests).
        return false;
    };
    host_resolves_public_only(rest).await
}

/// SSRF guard for a private-sync peer relay URL. Same policy as
/// [`peer_allowed`] but for WebSocket peers: with `allow_private` (tests)
/// any peer is allowed; otherwise require wss:// (plain ws:// rejected),
/// resolve the host, and reject if it does not resolve or if ANY resolved
/// address is a disallowed (internal) IP.
pub(crate) async fn relay_peer_allowed(relay_url: &str, allow_private: bool) -> bool {
    if allow_private {
        return true;
    }
    let Some(rest) = relay_url.strip_prefix("wss://") else {
        // Plaintext ws is only permitted under allow_private (loopback tests).
        return false;
    };
    host_resolves_public_only(rest).await
}

/// Resolve the host of `rest` (a URL with scheme stripped) and require every
/// resolved address to be a public, allowed IP.
async fn host_resolves_public_only(rest: &str) -> bool {
    let hostport = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, p.parse::<u16>().unwrap_or(443))
        }
        _ => (hostport, 443u16),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            let mut resolved_any = false;
            for a in addrs {
                resolved_any = true;
                if is_disallowed_ip(&a.ip()) {
                    return false;
                }
            }
            resolved_any
        }
        Err(_) => false,
    }
}

/// Peer servers for an alias: the configured override when present,
/// otherwise the registration's `server` tags minus this node's own domain.
fn peer_servers_for(svc: &PrivateService, registration_servers: &[String]) -> Vec<String> {
    let candidates: Vec<&String> = match svc.cfg.mirror_peer_urls {
        Some(ref configured) => configured.iter().collect(),
        None => registration_servers
            .iter()
            // Phase-4b A3: exact-host own-domain exclusion (host + port —
            // loopback test pairs are host-equal but port-distinct).
            .filter(|v| !is_own_server(v, &svc.cfg.domain))
            .collect(),
    };
    let mut out = Vec::new();
    for value in candidates {
        if let Some(base) = server_base_url(value) {
            if !out.contains(&base) {
                out.push(base);
            }
        }
    }
    out
}

/// Own-domain exclusion for a `server` tag value: exact-host match on the
/// value as given, plus on its scheme-defaulted base-URL form so a bare
/// `host[:port]` self-reference is still recognized as this node (the pre-A3
/// substring check excluded those too).
fn is_own_server(value: &str, own_domain: &str) -> bool {
    if super::host::url_denotes_domain(value, own_domain) {
        return true;
    }
    match server_base_url(value) {
        Some(base) => super::host::url_denotes_domain(&base, own_domain),
        None => false,
    }
}

// =============================================================================
// Phase-4b B2: per-blob retry state (exponential backoff with jitter)
// =============================================================================

/// Per-blob retry state: consecutive failure count + the Instant the blob
/// next becomes eligible for re-enqueue. In-memory only (restart resets to
/// the base interval — see module docs).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RetryState {
    pub attempts: u32,
    pub next_eligible: Instant,
}

/// Failure classification for the retry taxonomy (module-doc table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryClass {
    /// Transient: retry on the exponential schedule.
    Backoff,
    /// 404 on all peers — possibly a late upload: retry at the MAX interval.
    BackoffAtMax,
    /// Deterministic-given-state: do NOT hot-retry; the flat repair scan
    /// keeps re-enqueueing and success requires the condition to change.
    NoRetry,
}

/// Classify a `fetch_from_peer` reason string (module-doc table).
fn classify_failure(reason: &str) -> RetryClass {
    if reason == "no_peer" || reason.starts_with("network:") {
        return RetryClass::Backoff;
    }
    if let Some(rest) = reason.strip_prefix("http_status:") {
        return match rest.trim().parse::<u16>() {
            Ok(404) => RetryClass::BackoffAtMax,
            _ => RetryClass::Backoff,
        };
    }
    // too_large / verify: / store: / blocked / quota / reserve: / sink: /
    // write: and anything unrecognized — deterministic-given-state.
    RetryClass::NoRetry
}

/// Delay before the next retry after `attempts` consecutive failures
/// (`attempts >= 1`): `base * 2^(attempts-1)` capped at `max`, scaled by
/// `jitter` (the caller passes a uniform sample from [0.8, 1.2]).
fn retry_delay(attempts: u32, base: Duration, max: Duration, jitter: f64) -> Duration {
    // Shift capped so base * 2^shift cannot overflow before the max cap.
    let shift = attempts.saturating_sub(1).min(20);
    let capped = base.saturating_mul(1u32 << shift).min(max);
    Duration::from_secs_f64((capped.as_secs_f64() * jitter).max(0.0))
}

/// Is `sha` currently gated (its next-eligible Instant lies in the future)?
/// Gated blobs stay counted in the lag gauge; only re-enqueue is suppressed.
fn retry_gated(retry: &HashMap<String, RetryState>, sha: &str) -> bool {
    retry
        .get(sha)
        .map(|state| state.next_eligible > Instant::now())
        .unwrap_or(false)
}

/// Record one all-peers fetch failure for `sha`, updating the backoff gate
/// per the taxonomy. `NoRetry` classes clear any stale gate so the flat
/// repair-scan cadence applies (pre-B2 behavior).
fn record_mirror_failure(
    retry: &mut HashMap<String, RetryState>,
    sha: &str,
    reason: &str,
    base: Duration,
    max: Duration,
) {
    use ::rand::RngExt;

    let class = classify_failure(reason);
    match class {
        RetryClass::NoRetry => {
            retry.remove(sha);
        }
        RetryClass::Backoff | RetryClass::BackoffAtMax => {
            // ±20% jitter, sampled once per failure.
            let jitter = 0.8 + ::rand::rng().random::<f64>() * 0.4;
            let entry = retry.entry(sha.to_string()).or_insert(RetryState {
                attempts: 0,
                next_eligible: Instant::now(),
            });
            entry.attempts = entry.attempts.saturating_add(1);
            let delay = match class {
                RetryClass::BackoffAtMax => retry_delay(u32::MAX, base, max, jitter),
                _ => retry_delay(entry.attempts, base, max, jitter),
            };
            entry.next_eligible = Instant::now() + delay;
        }
    }
}

/// Clear the retry gate for `sha` (successful fetch, or the blob turned up
/// by other means).
fn record_mirror_success(retry: &mut HashMap<String, RetryState>, sha: &str) {
    retry.remove(sha);
}

/// FS-5 (review L2-F7): warn-log dedup for all-peers fetch failures. At
/// attacker-sized lag sets the flat repair scan re-failed every missing
/// blob every tick and logged one warn per blob per attempt (~73 warns/s);
/// the `ngit_private_mirror_failed_total{reason}` metric already carries
/// the per-attempt signal for alerting, so the warn needs only the FIRST
/// failure and a periodic re-log per (sha256, reason) pair.
///
/// R2-2 (verify-round-2): the per-key dedup alone collapses when MORE THAN
/// [`FailureLogDedup::MAX_ENTRIES`] distinct (sha256, reason) pairs fail
/// inside one TTL — oldest-evict keeps every entry younger than the TTL, so
/// each re-attempt passes the dedup and re-logs (~37-73 warns/s at
/// K=4400). A GLOBAL token bucket downstream of the per-key dedup bounds
/// the total warn rate: burst [`FailureLogDedup::BUCKET_CAPACITY`], refill
/// 1 warn/s. Warns the bucket drops are counted per reason label (the
/// metric's bounded-cardinality prefix — the full reason can carry
/// unbounded peer error text) and summarized by one warn per
/// [`FailureLogDedup::SUMMARY_INTERVAL`], so the signal survives without
/// the flood. Worst-case sustained warn rate is therefore
/// 1 warn/s + 1 summary/min, independent of the number of failing pairs.
/// Per-attempt metrics fire before this gate and are unaffected.
pub(crate) struct FailureLogDedup {
    seen: HashMap<(String, String), Instant>,
    ttl: Duration,
    bucket_tokens: f64,
    bucket_last: Instant,
    suppressed: HashMap<String, u64>,
    window_start: Instant,
}

/// Metric/summary label for a failure reason: the stable prefix before the
/// first ':' (same label the `ngit_private_mirror_failed_total` metric
/// uses, so the summary breakdown joins cleanly against it).
fn reason_label(reason: &str) -> &str {
    reason.split(':').next().unwrap_or("unknown")
}

impl FailureLogDedup {
    /// Re-log cadence for a still-failing (sha256, reason) pair.
    const TTL: Duration = Duration::from_secs(600);
    /// Flood backstop (same bound as the conflict-alert dedup): expired
    /// entries are reclaimed on insert, and at the cap the OLDEST entry is
    /// evicted — a fresh failure must always be able to log once.
    const MAX_ENTRIES: usize = 4096;
    /// R2-2: global warn token bucket — burst capacity, then a sustained
    /// refill of one warn per second.
    const BUCKET_CAPACITY: f64 = 16.0;
    const BUCKET_REFILL_PER_SEC: f64 = 1.0;
    /// R2-2: cadence of the suppressed-count summary warn.
    const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

    pub(crate) fn new() -> Self {
        Self {
            seen: HashMap::new(),
            ttl: Self::TTL,
            bucket_tokens: Self::BUCKET_CAPACITY,
            bucket_last: Instant::now(),
            suppressed: HashMap::new(),
            window_start: Instant::now(),
        }
    }

    /// True when this (sha256, reason) failure should log now: the first
    /// sighting, or once per TTL while it keeps failing — further bounded
    /// by the global bucket (R2-2). Emits the suppressed-count summary warn
    /// when a window closes.
    pub(crate) fn should_log(&mut self, sha256: &str, reason: &str) -> bool {
        let now = Instant::now();
        if let Some(summary) = self.summary_if_due_at(now) {
            tracing::warn!("private mirror: {summary}");
        }
        self.should_log_at(sha256, reason, now)
    }

    fn should_log_at(&mut self, sha256: &str, reason: &str, now: Instant) -> bool {
        if !self.dedup_pass_at(sha256, reason, now) {
            return false;
        }
        // R2-2: global bucket, refilled lazily on each dedup-passing
        // failure (accrual is wall-clock, capped at the burst capacity).
        let elapsed = now.duration_since(self.bucket_last).as_secs_f64();
        self.bucket_tokens =
            (self.bucket_tokens + elapsed * Self::BUCKET_REFILL_PER_SEC).min(Self::BUCKET_CAPACITY);
        self.bucket_last = now;
        if self.bucket_tokens >= 1.0 {
            self.bucket_tokens -= 1.0;
            return true;
        }
        *self
            .suppressed
            .entry(reason_label(reason).to_string())
            .or_insert(0) += 1;
        false
    }

    /// Per-key dedup gate: true on the first sighting of a (sha256, reason)
    /// pair, or once per TTL while it keeps failing.
    fn dedup_pass_at(&mut self, sha256: &str, reason: &str, now: Instant) -> bool {
        let key = (sha256.to_string(), reason.to_string());
        if let Some(at) = self.seen.get(&key) {
            if now.duration_since(*at) < self.ttl {
                return false;
            }
        }
        let ttl = self.ttl;
        self.seen.retain(|_, at| now.duration_since(*at) < ttl);
        if self.seen.len() >= Self::MAX_ENTRIES {
            if let Some(oldest) = self
                .seen
                .iter()
                .max_by_key(|(_, at)| now.duration_since(**at))
                .map(|(k, _)| k.clone())
            {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(key, now);
        true
    }

    /// R2-2: when a summary window has closed, return the summary line for
    /// the warns the global bucket dropped in that window (None when the
    /// window is still open or nothing was dropped) and open a fresh one.
    fn summary_if_due_at(&mut self, now: Instant) -> Option<String> {
        if now.duration_since(self.window_start) < Self::SUMMARY_INTERVAL {
            return None;
        }
        self.window_start = now;
        if self.suppressed.is_empty() {
            return None;
        }
        let total: u64 = self.suppressed.values().sum();
        let mut by_reason: Vec<(String, u64)> =
            std::mem::take(&mut self.suppressed).into_iter().collect();
        by_reason.sort();
        let breakdown = by_reason
            .iter()
            .map(|(label, n)| format!("{label}={n}"))
            .collect::<Vec<_>>()
            .join(", ");
        Some(format!(
            "{total} failure warn(s) dropped by the global rate limit in the last {}s \
             ({breakdown}); per-attempt counts remain in ngit_private_mirror_failed_total",
            Self::SUMMARY_INTERVAL.as_secs()
        ))
    }

    #[cfg(test)]
    fn suppressed_total(&self) -> u64 {
        self.suppressed.values().sum()
    }
}

/// Enqueue a mirror job for an accepted 30641. No-op when the mirror worker
/// is not running (mirroring disabled) or when the event/registration cannot
/// be resolved (the periodic repair scan is the safety net).
pub(crate) fn enqueue_for_state_root(svc: &PrivateService, event: &Event) {
    let Some(tx) = svc.mirror_tx.get() else {
        return;
    };

    let mut alias: Option<String> = None;
    let mut want: Vec<WantBlob> = Vec::new();
    for tag in event.tags.iter() {
        let v = tag.clone().to_vec();
        if v.len() < 2 {
            continue;
        }
        match v[0].as_str() {
            "d" => {
                if alias.is_none() {
                    alias = Some(v[1].clone());
                }
            }
            "m" | "pack" => {
                if v.len() >= 3 && super::blossom_auth::is_lower_hex_64(&v[1]) {
                    if let Ok(size) = v[2].parse::<u64>() {
                        want.push(WantBlob {
                            sha256: v[1].clone(),
                            size,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    let Some(alias) = alias else { return };
    if want.is_empty() {
        return;
    }

    // Skip blobs already local (client-push path on the origin node),
    // denylisted, or currently backoff-gated (B2): a gated blob stays
    // missing until its next-eligible Instant and must not be hot-enqueued
    // by every arriving 30641 edition.
    {
        let retry = svc.mirror_retry.lock();
        want.retain(|w| {
            !svc.blobs.exists(&w.sha256)
                && !svc.is_denylisted(&w.sha256)
                && !retry_gated(&retry, &w.sha256)
        });
    }
    if want.is_empty() {
        return;
    }

    let record = {
        let Ok(txn) = svc.meta.read_txn() else { return };
        match svc.meta.get_registration(&txn, &alias) {
            Ok(Some(record)) if record.tombstoned_at.is_none() => record,
            _ => return,
        }
    };

    let job = MirrorJob {
        tenant_hex: record.tenant_hex.clone(),
        alias,
        want,
        peer_servers: peer_servers_for(svc, &record.servers),
    };
    let _ = tx.send(job);
}

/// Repair scan: derive mirror jobs for every referenced-but-missing blob
/// from the blob-claim table, and update the mirror lag gauge. Covers boot
/// (want sets re-derived from retained 30641 state), missed enqueues, and
/// retries after peer failures.
fn scan_missing(svc: &PrivateService) -> Vec<MirrorJob> {
    let mut jobs: Vec<MirrorJob> = Vec::new();
    let mut lag = 0_u64;

    let Ok(txn) = svc.meta.read_txn() else {
        return jobs;
    };
    let Ok(claims) = svc.meta.all_blob_claims(&txn) else {
        return jobs;
    };

    // B2: prune retry gates for blobs that are no longer lagging (locally
    // stored, denylisted, or fully unclaimed — e.g. after a registration
    // death) so the map stays bounded by the live backlog.
    {
        let lagging: HashSet<&String> = claims
            .iter()
            .filter(|(sha, claim)| {
                !claim.aliases.is_empty() && !svc.blobs.exists(sha) && !svc.is_denylisted(sha)
            })
            .map(|(sha, _)| sha)
            .collect();
        svc.mirror_retry
            .lock()
            .retain(|sha, _| lagging.contains(sha));
    }

    for (sha, claim) in claims {
        if claim.aliases.is_empty() || svc.blobs.exists(&sha) || svc.is_denylisted(&sha) {
            continue;
        }
        lag += 1;

        // B2: backoff-gated blobs remain lag (the gauge is NOT hidden) but
        // are not re-enqueued until their next-eligible Instant.
        if retry_gated(&svc.mirror_retry.lock(), &sha) {
            continue;
        }

        // First claiming alias with a live (non-tombstoned) registration.
        let mut resolved = None;
        for alias in &claim.aliases {
            if let Ok(Some(record)) = svc.meta.get_registration(&txn, alias) {
                if record.tombstoned_at.is_none() {
                    resolved = Some((alias.clone(), record));
                    break;
                }
            }
        }
        let Some((alias, record)) = resolved else {
            continue;
        };

        let want = WantBlob {
            sha256: sha,
            size: claim.size,
        };
        if let Some(job) = jobs
            .iter_mut()
            .find(|j| j.alias == alias && j.tenant_hex == record.tenant_hex)
        {
            job.want.push(want);
        } else {
            jobs.push(MirrorJob {
                tenant_hex: record.tenant_hex.clone(),
                alias,
                want: vec![want],
                peer_servers: peer_servers_for(svc, &record.servers),
            });
        }
    }

    crate::metrics::set_private_mirror_lag_blobs(lag);
    jobs
}

/// Recompute + publish the lag gauge (referenced-but-missing blob count).
fn update_lag(svc: &PrivateService) {
    let Ok(txn) = svc.meta.read_txn() else { return };
    let Ok(claims) = svc.meta.all_blob_claims(&txn) else {
        return;
    };
    let lag = claims
        .iter()
        .filter(|(sha, claim)| {
            !claim.aliases.is_empty() && !svc.blobs.exists(sha) && !svc.is_denylisted(sha)
        })
        .count() as u64;
    crate::metrics::set_private_mirror_lag_blobs(lag);
}

/// Fetch one blob from one peer through the Phase-1 upload sink.
async fn fetch_from_peer(
    svc: &Arc<PrivateService>,
    client: &reqwest::Client,
    job: &MirrorJob,
    blob: &WantBlob,
    peer_base: &str,
) -> Result<(), String> {
    // SSRF guard: never let a tenant-controlled `server` tag point our fetch at
    // an internal host. Checked before any reservation/connection.
    if !peer_allowed(peer_base, svc.cfg.mirror_allow_private_ips).await {
        return Err("blocked".to_string());
    }

    // Reserve in-flight capacity + open the temp-file sink (mirrors a client
    // PUT: reservation → sink → stream → finish). finish() releases any
    // pending speculative charge before its quota check, so the reserve nets
    // it too (FF).
    let pending = svc
        .pending_spec_release(&blob.sha256)
        .map_err(|e| format!("reserve: {}", e.reason()))?;
    let reservation = svc.reserve_upload(blob.size, pending).map_err(|e| match e {
        BlobError::QuotaExceeded => "quota".to_string(),
        other => format!("reserve: {}", other.reason()),
    })?;
    let mut sink = UploadSink::create(
        svc.meta.clone(),
        svc.blobs.clone(),
        svc.cfg.clone(),
        job.tenant_hex.clone(),
        job.alias.clone(),
        blob.sha256.clone(),
        blob.size,
        reservation,
        svc.denylist.clone(),
    )
    .await
    .map_err(|e| format!("sink: {}", e.reason()))?;

    let url = format!("{}/{}", peer_base, blob.sha256);
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("network: {e}"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("http_status: {}", response.status().as_u16()));
    }

    let mut response = response;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                // write_chunk enforces min(declared, max_blob_bytes) and
                // aborts mid-stream on overrun (hostile peer protection).
                sink.write_chunk(&chunk).await.map_err(|e| match e {
                    BlobError::TooLarge => "too_large".to_string(),
                    other => format!("write: {}", other.reason()),
                })?;
            }
            Ok(None) => break,
            Err(e) => return Err(format!("network: {e}")),
        }
    }

    // finish() verifies streamed-bytes == declared size and the SHA-256
    // against the requested hash; on mismatch the temp file is deleted and
    // nothing is stored (no poisoned blob).
    sink.finish().await.map_err(|e| match e {
        BlobError::QuotaExceeded => "quota".to_string(),
        BlobError::BadRequest(reason) => format!("verify: {reason}"),
        other => format!("store: {}", other.reason()),
    })?;
    Ok(())
}

/// Fetch one blob, trying each peer in order. Success is sticky (idempotent
/// no-op when the blob landed via a concurrent job).
///
/// Returns `None` on success (or when no fetch was needed: already local /
/// denylisted) and `Some(reason)` when every peer failed or no peer was
/// available — the worker feeds the reason into the B2 backoff classifier.
async fn fetch_blob(
    svc: &Arc<PrivateService>,
    client: &reqwest::Client,
    job: &MirrorJob,
    blob: &WantBlob,
) -> Option<String> {
    if svc.blobs.exists(&blob.sha256) || svc.is_denylisted(&blob.sha256) {
        return None;
    }
    if job.peer_servers.is_empty() {
        crate::metrics::record_private_mirror_failed("no_peer");
        // FS-5 + R2-2: deduped and globally rate-limited — the metric
        // carries the per-attempt count.
        if svc
            .mirror_failure_log
            .lock()
            .should_log(&blob.sha256, "no_peer")
        {
            tracing::warn!(
                alias = %job.alias,
                sha256 = %blob.sha256,
                "private mirror: no peer server available for blob"
            );
        }
        return Some("no_peer".to_string());
    }

    let mut last_error = String::new();
    for peer in &job.peer_servers {
        match fetch_from_peer(svc, client, job, blob, peer).await {
            Ok(()) => {
                crate::metrics::record_private_mirror_fetched();
                svc.refresh_gauges();
                tracing::info!(
                    alias = %job.alias,
                    sha256 = %blob.sha256,
                    peer = %peer,
                    size = blob.size,
                    "private mirror: blob fetched from peer"
                );
                return None;
            }
            Err(reason) => {
                tracing::debug!(
                    alias = %job.alias,
                    sha256 = %blob.sha256,
                    peer = %peer,
                    reason = %reason,
                    "private mirror: fetch attempt failed"
                );
                last_error = reason;
            }
        }
    }

    let reason_label = last_error
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string();
    crate::metrics::record_private_mirror_failed(&reason_label);
    // FS-5 (review L2-F7) + R2-2: one warn per (sha256, reason) per 10
    // minutes, bounded globally to a 16-warn burst then 1 warn/s — not one
    // per failed attempt. At attacker-sized lag sets the per-attempt warn
    // was ~73 warns/s, drowning every other log line. The metric above
    // keeps the full per-attempt count for alerting.
    if svc
        .mirror_failure_log
        .lock()
        .should_log(&blob.sha256, &last_error)
    {
        tracing::warn!(
            alias = %job.alias,
            sha256 = %blob.sha256,
            reason = %last_error,
            "private mirror: blob fetch failed on all peers (will retry on repair scan)"
        );
    }
    Some(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn retry_class_taxonomy() {
        // Transient classes → exponential backoff.
        assert_eq!(classify_failure("no_peer"), RetryClass::Backoff);
        assert_eq!(
            classify_failure("network: connection refused"),
            RetryClass::Backoff
        );
        assert_eq!(classify_failure("http_status: 500"), RetryClass::Backoff);
        assert_eq!(classify_failure("http_status: 502"), RetryClass::Backoff);
        // Unusual non-404 statuses are treated as transient edge oddities.
        assert_eq!(classify_failure("http_status: 403"), RetryClass::Backoff);
        // 404 on all peers → retry, but at the max interval (late upload).
        assert_eq!(
            classify_failure("http_status: 404"),
            RetryClass::BackoffAtMax
        );
        // Deterministic classes → no hot retry.
        for reason in [
            "too_large",
            "verify: size mismatch",
            "verify: sha256 mismatch",
            "store: forbidden",
            "blocked",
            "quota",
            "reserve: cap reached",
            "sink: io error",
            "write: io error",
            "anything-else",
        ] {
            assert_eq!(
                classify_failure(reason),
                RetryClass::NoRetry,
                "{reason} must be NoRetry"
            );
        }
    }

    #[test]
    fn retry_delay_schedule_cap_and_jitter_bounds() {
        let base = Duration::from_secs(60);
        let max = Duration::from_secs(3600);

        // Exponential growth with jitter=1.0 (exact schedule, no jitter).
        assert_eq!(retry_delay(1, base, max, 1.0), Duration::from_secs(60));
        assert_eq!(retry_delay(2, base, max, 1.0), Duration::from_secs(120));
        assert_eq!(retry_delay(3, base, max, 1.0), Duration::from_secs(240));
        assert_eq!(retry_delay(4, base, max, 1.0), Duration::from_secs(480));

        // Cap: attempt 7 would be 60 * 64 = 3840 > 3600 → capped at max.
        assert_eq!(retry_delay(7, base, max, 1.0), max);
        assert_eq!(retry_delay(100, base, max, 1.0), max);
        // u32::MAX attempts (the BackoffAtMax path) is always the cap.
        assert_eq!(retry_delay(u32::MAX, base, max, 1.0), max);

        // Jitter bounds: 1000 samples per attempt stay within ±20% of the
        // un-jittered value.
        for attempt in 1..=8u32 {
            let exact = retry_delay(attempt, base, max, 1.0).as_secs_f64();
            for _ in 0..1000 {
                let jitter = 0.8 + rand::random::<f64>() * 0.4;
                let sampled = retry_delay(attempt, base, max, jitter).as_secs_f64();
                assert!(
                    (exact * 0.8..=exact * 1.2).contains(&sampled),
                    "attempt {attempt}: {sampled} outside ±20% of {exact}"
                );
            }
        }
    }

    #[test]
    fn retry_gate_skip_and_release() {
        let base = Duration::from_secs(60);
        let max = Duration::from_secs(3600);
        let sha = "ab".repeat(32);
        let mut retry: HashMap<String, RetryState> = HashMap::new();

        // Ungated initially.
        assert!(!retry_gated(&retry, &sha));

        // First transient failure: gated, next-eligible in the future.
        record_mirror_failure(&mut retry, &sha, "network: refused", base, max);
        assert!(retry_gated(&retry, &sha));
        assert_eq!(retry.get(&sha).unwrap().attempts, 1);

        // Success clears the gate.
        record_mirror_success(&mut retry, &sha);
        assert!(!retry_gated(&retry, &sha));
        assert!(retry.get(&sha).is_none());

        // Deterministic failure: no gate is installed (flat repair-scan
        // cadence preserved).
        record_mirror_failure(&mut retry, &sha, "quota", base, max);
        assert!(!retry_gated(&retry, &sha));
        assert!(retry.get(&sha).is_none());

        // A deterministic failure also CLEARS a stale transient gate: the
        // blob drops back to the flat repair-scan cadence (the gate would
        // otherwise delay a retry whose condition already changed).
        record_mirror_failure(&mut retry, &sha, "network: refused", base, max);
        assert!(retry_gated(&retry, &sha));
        record_mirror_failure(&mut retry, &sha, "too_large", base, max);
        assert!(!retry_gated(&retry, &sha));

        // Backoff attempts accumulate while failures stay transient.
        record_mirror_failure(&mut retry, &sha, "http_status: 500", base, max);
        record_mirror_failure(&mut retry, &sha, "http_status: 500", base, max);
        assert_eq!(retry.get(&sha).unwrap().attempts, 2);
    }

    /// FS-5: the failure warn dedups per (sha256, reason) — the first
    /// failure logs, repeats inside the TTL are suppressed, a DIFFERENT
    /// reason for the same sha logs, and the pair re-logs after the TTL.
    #[test]
    fn failure_log_dedup_per_sha_and_reason() {
        let ttl = FailureLogDedup::TTL;
        let mut dedup = FailureLogDedup::new();
        let t0 = Instant::now();

        assert!(dedup.should_log_at("sha1", "network: refused", t0));
        assert!(
            !dedup.should_log_at("sha1", "network: refused", t0 + Duration::from_secs(1)),
            "repeat inside the TTL must be suppressed"
        );
        assert!(
            dedup.should_log_at("sha1", "http_status: 500", t0 + Duration::from_secs(2)),
            "a different reason for the same sha is a different pair"
        );
        assert!(
            dedup.should_log_at("sha2", "network: refused", t0 + Duration::from_secs(3)),
            "a different sha is a different pair"
        );
        assert!(
            dedup.should_log_at("sha1", "network: refused", t0 + ttl + Duration::from_secs(1)),
            "a still-failing pair re-logs after the TTL"
        );
    }

    /// FS-5: at the cap the OLDEST entry is evicted to make room — a fresh
    /// failure must always be able to log once. (Exercises the per-key
    /// dedup gate directly: with K at/above the cap the global bucket is
    /// exactly the R2-2 flood scenario and would bound the full gate.)
    #[test]
    fn failure_log_dedup_cap_evicts_oldest() {
        let mut dedup = FailureLogDedup::new();
        let t0 = Instant::now();
        for i in 0..FailureLogDedup::MAX_ENTRIES {
            assert!(dedup.dedup_pass_at(
                &format!("flood-{i}"),
                "network: refused",
                t0 + Duration::from_millis(i as u64)
            ));
        }
        assert!(
            dedup.dedup_pass_at("fresh", "network: refused", t0 + Duration::from_secs(1)),
            "a fresh failure must log even at the cap"
        );
        assert!(
            !dedup.dedup_pass_at("flood-1", "network: refused", t0 + Duration::from_secs(2)),
            "survivors stay suppressed"
        );
        assert!(
            dedup.dedup_pass_at("flood-0", "network: refused", t0 + Duration::from_secs(3)),
            "the oldest entry was evicted to make room"
        );
    }

    /// R2-2: with K > MAX_ENTRIES distinct failing pairs, oldest-evict
    /// keeps every per-key entry younger than the TTL, so the per-key
    /// dedup alone passes every attempt; the GLOBAL bucket must bound the
    /// warn rate to the burst, then the 1/s refill.
    #[test]
    fn failure_log_global_bucket_bounds_flood() {
        let mut dedup = FailureLogDedup::new();
        let t0 = Instant::now();
        let k = FailureLogDedup::MAX_ENTRIES + 400;
        let mut allowed = 0u32;
        for i in 0..k {
            if dedup.should_log_at(&format!("flood-{i}"), "network: refused", t0) {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed,
            FailureLogDedup::BUCKET_CAPACITY as u32,
            "the burst is bounded by the bucket capacity"
        );
        assert_eq!(
            dedup.suppressed_total(),
            (k - allowed as usize) as u64,
            "every dropped warn is counted for the window summary"
        );
        // No token has refilled yet: a fresh failure in the same instant
        // still drops.
        assert!(!dedup.should_log_at("late", "network: refused", t0));
        // Refill is 1 token/s: ten seconds later exactly ten more pass.
        let mut allowed = 0u32;
        for i in 0..100 {
            if dedup.should_log_at(
                &format!("later-{i}"),
                "network: refused",
                t0 + Duration::from_secs(10),
            ) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 10, "the sustained rate is the 1/s refill");
    }

    /// R2-2: dropped warns are summarized once per window with per-reason
    /// counts; the window then resets and stays quiet while nothing drops.
    #[test]
    fn failure_log_summary_counts_drops_per_reason() {
        let mut dedup = FailureLogDedup::new();
        let t0 = Instant::now();
        // Drain the burst: these pass, nothing is counted yet.
        for i in 0..16 {
            assert!(dedup.should_log_at(&format!("burst-{i}"), "network: refused", t0));
        }
        assert_eq!(dedup.suppressed_total(), 0);
        // The bucket is empty: further first-sightings drop and are counted
        // per reason LABEL (the metric's bounded-cardinality prefix).
        for i in 0..3 {
            assert!(!dedup.should_log_at(&format!("net-{i}"), "network: refused", t0));
        }
        for i in 0..2 {
            assert!(!dedup.should_log_at(&format!("http-{i}"), "http_status: 500", t0));
        }
        assert_eq!(dedup.suppressed_total(), 5);
        // No summary before the interval elapses.
        assert!(dedup
            .summary_if_due_at(t0 + Duration::from_secs(30))
            .is_none());
        // At the window close: one summary with the total and per-reason
        // counts.
        let summary = dedup
            .summary_if_due_at(t0 + FailureLogDedup::SUMMARY_INTERVAL)
            .expect("a summary is due with drops pending");
        assert!(summary.starts_with("5 failure warn(s)"), "{summary}");
        assert!(summary.contains("http_status=2"), "{summary}");
        assert!(summary.contains("network=3"), "{summary}");
        // The window reset: with nothing new dropped there is nothing to
        // say at the next close.
        assert!(dedup
            .summary_if_due_at(t0 + FailureLogDedup::SUMMARY_INTERVAL * 2)
            .is_none());
        assert_eq!(dedup.suppressed_total(), 0);
    }

    #[test]
    fn disallowed_ip_covers_internal_ranges() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "172.16.5.5",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "224.0.0.1",
        ] {
            let ip: IpAddr = IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap());
            assert!(is_disallowed_ip(&ip), "{ip} should be disallowed");
        }
        assert!(is_disallowed_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_disallowed_ip(&IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(is_disallowed_ip(&IpAddr::V6("fc00::1".parse().unwrap())));
        assert!(is_disallowed_ip(&IpAddr::V6("::ffff:127.0.0.1".parse().unwrap())));
    }

    #[test]
    fn embedded_ipv4_transition_forms_are_disallowed() {
        // NAT64 64:ff9b::/96 wrapping cloud-metadata 169.254.169.254.
        let nat64: Ipv6Addr = "64:ff9b::a9fe:a9fe".parse().unwrap();
        assert_eq!(
            embedded_ipv4(&nat64),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert!(is_disallowed_ip(&IpAddr::V6(nat64)));

        // 6to4 2002::/16 wrapping internal 10.0.0.5 (v4 in bytes 2..6).
        let sixtofour: Ipv6Addr = "2002:a00:5::".parse().unwrap();
        assert_eq!(embedded_ipv4(&sixtofour), Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(is_disallowed_ip(&IpAddr::V6(sixtofour)));

        // IPv4-compatible ::/96 wrapping 169.254.169.254.
        let compat: Ipv6Addr = "::a9fe:a9fe".parse().unwrap();
        assert_eq!(embedded_ipv4(&compat), Some(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(is_disallowed_ip(&IpAddr::V6(compat)));

        // A transition form wrapping a *public* v4 stays allowed.
        let public_6to4: Ipv6Addr = "2002:808:808::".parse().unwrap();
        assert_eq!(embedded_ipv4(&public_6to4), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_disallowed_ip(&IpAddr::V6(public_6to4)));
    }

    #[test]
    fn public_ip_allowed() {
        assert!(!is_disallowed_ip(&IpAddr::V4("8.8.8.8".parse().unwrap())));
        assert!(!is_disallowed_ip(&IpAddr::V4("93.184.216.34".parse().unwrap())));
        assert!(!is_disallowed_ip(&IpAddr::V6("2606:4700:4700::1111".parse().unwrap())));
    }

    #[tokio::test]
    async fn peer_allowed_blocks_internal_and_http() {
        // allow_private short-circuits (tests / loopback pairs).
        assert!(peer_allowed("http://127.0.0.1:9999", true).await);
        // Plaintext http rejected in production mode.
        assert!(!peer_allowed("http://example.com", false).await);
        // Literal internal IP rejected.
        assert!(!peer_allowed("https://169.254.169.254", false).await);
        assert!(!peer_allowed("https://127.0.0.1:8080", false).await);
        assert!(!peer_allowed("https://10.0.0.5", false).await);
        // Unresolvable host rejected (fails closed).
        assert!(!peer_allowed("https://nonexistent.invalid", false).await);
    }

    #[tokio::test]
    async fn relay_peer_allowed_blocks_internal_and_ws() {
        // allow_private short-circuits (tests / loopback pairs).
        assert!(relay_peer_allowed("ws://127.0.0.1:9999", true).await);
        // Plaintext ws rejected in production mode.
        assert!(!relay_peer_allowed("ws://example.com", false).await);
        // Literal internal IP rejected.
        assert!(!relay_peer_allowed("wss://169.254.169.254", false).await);
        assert!(!relay_peer_allowed("wss://127.0.0.1:8080", false).await);
        assert!(!relay_peer_allowed("wss://10.0.0.5", false).await);
        // Unresolvable host rejected (fails closed).
        assert!(!relay_peer_allowed("wss://nonexistent.invalid", false).await);
    }
}

/// Spawn the mirror worker. Called once from `RelayServer::start` when
/// private repos AND mirroring are enabled.
pub(crate) fn spawn(svc: Arc<PrivateService>) -> JoinHandle<()> {
    let (tx, mut rx) = unbounded_channel::<MirrorJob>();
    let _ = svc.mirror_tx.set(tx);

    let fetch_timeout = Duration::from_secs(svc.cfg.mirror_fetch_timeout_secs.max(1));
    let max_concurrency = svc.cfg.mirror_max_concurrency.max(1) as usize;
    // B2 backoff knobs: base is clamped to 1s under NGIT_TEST (the existing
    // repair-interval idiom below); max stays as configured.
    let retry_base = Duration::from_secs(svc.cfg.mirror_retry_base_secs.max(1));
    let retry_base = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        retry_base.min(Duration::from_secs(1))
    } else {
        retry_base
    };
    let retry_max = Duration::from_secs(
        svc.cfg
            .mirror_retry_max_secs
            .max(svc.cfg.mirror_retry_base_secs.max(1)),
    );
    let repair_interval = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(60)
    };

    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(fetch_timeout)
            // No redirect-chasing — a peer must not bounce us to an internal host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(e) => {
                tracing::error!("private mirror: failed to build HTTP client: {e}");
                return;
            }
        };
        let semaphore = Arc::new(Semaphore::new(max_concurrency));
        // Blobs currently being fetched — dedups queue jobs vs repair scans.
        let inflight: Arc<parking_lot::Mutex<HashSet<String>>> =
            Arc::new(parking_lot::Mutex::new(HashSet::new()));
        // B2: per-blob retry state (attempt count + next-eligible Instant),
        // shared with scan_missing / enqueue_for_state_root via the service.
        let retry = svc.mirror_retry.clone();

        tracing::info!(
            max_concurrency = max_concurrency,
            fetch_timeout_secs = fetch_timeout.as_secs(),
            repair_interval_secs = repair_interval.as_secs(),
            retry_base_secs = retry_base.as_secs(),
            retry_max_secs = retry_max.as_secs(),
            "private blob mirror worker started"
        );

        let mut repair = tokio::time::interval(repair_interval);
        // First tick fires immediately → boot repair pass re-enqueues
        // missing blobs for all live 30641-referenced claims.
        loop {
            let jobs: Vec<MirrorJob> = tokio::select! {
                job = rx.recv() => match job {
                    Some(job) => vec![job],
                    None => break,
                },
                _ = repair.tick() => scan_missing(&svc),
            };

            for job in jobs {
                let job = Arc::new(job);
                let mut handles = Vec::new();
                for blob in job.want.clone() {
                    if svc.blobs.exists(&blob.sha256) || svc.is_denylisted(&blob.sha256) {
                        continue;
                    }
                    // B2: skip blobs whose backoff gate is still closed —
                    // they were enqueued before the gate was set (or by a
                    // racing job) and must wait for their next-eligible
                    // Instant.
                    if retry_gated(&retry.lock(), &blob.sha256) {
                        continue;
                    }
                    if !inflight.lock().insert(blob.sha256.clone()) {
                        continue; // already being fetched
                    }
                    let permit = match semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return, // semaphore closed — shutting down
                    };
                    let svc = svc.clone();
                    let client = client.clone();
                    let job = job.clone();
                    let inflight = inflight.clone();
                    let retry = retry.clone();
                    handles.push(tokio::spawn(async move {
                        let _permit = permit;
                        let outcome = fetch_blob(&svc, &client, &job, &blob).await;
                        // B2: update the backoff gate from the outcome —
                        // success clears it, failure classifies and schedules
                        // the next-eligible Instant (or clears the gate for
                        // deterministic failure classes).
                        let mut guard = retry.lock();
                        match outcome {
                            None => record_mirror_success(&mut guard, &blob.sha256),
                            Some(reason) => record_mirror_failure(
                                &mut guard,
                                &blob.sha256,
                                &reason,
                                retry_base,
                                retry_max,
                            ),
                        }
                        drop(guard);
                        inflight.lock().remove(&blob.sha256);
                    }));
                }
                // B5: recompute the lag gauge ONCE per job after all its blob
                // fetches finish, instead of once per blob. `update_lag` scans
                // the whole blob_claims table, so the per-blob call turned a
                // full-table scan into a hot loop under load. A join task keeps
                // the main loop free to accept the next job/repair tick.
                if !handles.is_empty() {
                    let svc = svc.clone();
                    tokio::spawn(async move {
                        for handle in handles {
                            let _ = handle.await;
                        }
                        update_lag(&svc);
                    });
                }
            }
        }
    })
}
