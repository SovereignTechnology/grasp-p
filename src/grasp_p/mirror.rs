//! GRASP-P blob mirror (pull-only).
//!
//! On any accepted kind-30641 the referenced manifest/pack blobs must exist
//! locally. On the origin node they already do (the client PUT them before
//! publishing); on the replicating node they are missing and are pulled here
//! over the peer's EXISTING public `GET /<sha256>` route — no new inbound
//! surface.
//!
//! What must hold: on a healthy pair every blob one node stores reaches the
//! other, and a blob that failed is tried again until it arrives. Nothing
//! here gives up on a blob; a referenced blob may legitimately appear late.
//!
//! ## Where work comes from
//!
//! - An accepted 30641 enqueues its missing blobs at once.
//! - A repair scan (every 60 s; at boot) re-derives every missing blob from
//!   the blob-claim table. It is the safety net: anything dropped, refused
//!   for lack of room or lost in a restart comes back through it. The scan
//!   also sets `ngit_private_mirror_lag_blobs`; nothing else does.
//!
//! ## Where blobs come from
//!
//! From the operator's peers and from no other host: the entries of
//! `NGIT_GRASP_P_MIRROR_PEER_URLS`, less the ones that name this node. A
//! registration's `server` tags tell clients where to go and never choose
//! a host the mirror fetches from, so no account can point this node's
//! fetches anywhere. With no list the node has no peer, and every missing
//! blob fails as `no_peer`.
//!
//! The client connects to the address it vetted. Its resolver
//! (`vetted_dns`) looks the peer's name up, refuses the whole answer when
//! an address in it may not be reached, and hands the connector exactly the
//! addresses it vetted; the connection makes no lookup of its own that
//! could lead it elsewhere. A host that is an IP literal never reaches a
//! resolver; the early check before each request covers it.
//!
//! ## How work is ordered
//!
//! Storage is sold per account (the tenant key), so the account is the unit
//! of fairness. `FairQueue` keeps one backlog per account, serves the
//! accounts in turn, and lets one account hold at most half of the
//! concurrent fetches. One account whose blobs come slowly, or never, then
//! cannot take every fetch. (Two such accounts can fill the default four
//! between them; a third then waits for fetches of theirs to end.) An
//! account's backlog is bounded; what does not fit is dropped and
//! re-derived by the next scan.
//!
//! A blob that several accounts claim is fetched for the one with the
//! fewest missing blobs. The other claimants are kept as fallbacks: when
//! the first one's own state refuses the blob (its quota is full, its
//! registration is gone, it no longer references the blob), the fetch goes
//! on for the next, so one account cannot stop a blob that another account
//! can take. A fetch adds no reference: it only stores bytes a repository
//! here already references and pays for, and they set every such charge to
//! their stored size (`claims::settle_stored`).
//!
//! The worker loop never waits for a free fetch slot. It takes new jobs,
//! starts and collects repair scans and collects finished fetches as they
//! come, and after each of those starts every fetch that may start now.
//!
//! ## What a fetch may cost
//!
//! - `AttemptBudget` bounds how many fetches start per minute over all
//!   accounts (`NGIT_GRASP_P_MIRROR_MAX_ATTEMPTS_PER_MIN`).
//! - Every failure closes a per-blob gate (table below). No class is left
//!   to the flat scan cadence, so no blob is fetched again every minute for
//!   ever.
//! - Within one fetch the cheap checks come first: the early address check,
//!   then a quota check against local state, then the request; the peer's
//!   announced length is judged before the first byte of the body is read.
//!
//! ## Failure classes
//!
//! | Reason                         | Retry                     | Ends the peer loop |
//! |--------------------------------|---------------------------|--------------------|
//! | `network: …` (also: no DNS)    | `base * 2^n`, capped      | no                 |
//! | `http_status: <not 404>`       | `base * 2^n`, capped      | no                 |
//! | `no_peer`                      | `base * 2^n`, capped      | (no peer to try)   |
//! | `quota`                        | `base * 2^n`, capped      | yes                |
//! | `reserve: …`                   | `base * 2^n`, capped      | yes                |
//! | `sink: …`                      | `base * 2^n`, capped      | yes                |
//! | `write: …`                     | `base * 2^n`, capped      | yes                |
//! | `store: …`                     | `base * 2^n`, capped      | yes                |
//! | `http_status: 404`             | the maximum interval      | no                 |
//! | `blocked` (address check)      | the maximum interval      | no                 |
//! | `verify: …` (bad bytes/size)   | the maximum interval      | no                 |
//! | `too_large`                    | the maximum interval      | no                 |
//!
//! The first group may heal by itself or by a change on this node (a peer
//! comes back, space is freed), so it is retried soon and then less often.
//! The second group needs someone else to act (an upload, a configuration
//! change, a peer that serves other bytes), so it waits the maximum
//! interval every time. All delays carry ±20% jitter.
//!
//! `blocked` comes from the early check or from the client's resolver, which
//! refuses an answer that holds an address the mirror may not reach. A peer
//! whose name does not resolve, or resolves to no address, is `network`,
//! not `blocked`: a resolver that fails for a moment must not park every
//! blob tried meanwhile for the maximum interval.
//!
//! A failure caused by this node's own state would repeat on every peer,
//! so it ends the peer loop and is the reason recorded. Otherwise each peer
//! is tried and the class with the soonest retry is recorded, whatever the
//! order of the peers: one peer answering 404 must not park for an hour a
//! blob that another peer failed to serve for a passing reason.
//!
//! A gated blob stays counted in `ngit_private_mirror_lag_blobs`; the gate
//! stops it being queued, not being counted. Gates live in memory only: a
//! restart forgets them and the boot scan queues every missing blob again.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr::prelude::Event;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use super::blob_store::UploadSink;
use super::vetted_dns::{self, VettedResolver};
use super::{BlobError, PrivateService, UploadOrigin};

/// Blobs one account may have waiting in the queue. What does not fit is
/// dropped; the next repair scan derives it again from the claim table.
const ACCOUNT_BACKLOG_CAP: usize = 1024;

/// The slowest link a fetch is given time for, in bytes per second. The
/// deadline of a fetch grows by the blob's length divided by this.
const MIN_FETCH_BYTES_PER_SEC: u64 = 256 * 1024;

/// No fetch is given longer than this, whatever the settings say. It keeps
/// the deadline arithmetic far from overflow.
const MAX_FETCH_DEADLINE: Duration = Duration::from_secs(7 * 24 * 3600);

/// The reason recorded when a peer's name did not resolve.
const UNRESOLVED_REASON: &str = "network: peer name did not resolve";

/// The clock the worker, the retry gates and the attempt budget read: the
/// runtime's, so a test can pause it. Outside tests it is the monotonic
/// system clock.
pub(crate) fn clock_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// One blob a mirror job wants locally.
#[derive(Debug, Clone)]
pub struct WantBlob {
    pub sha256: String,
    /// Declared size: from the 30641 tag, or the charge of the repository
    /// the repair scan chose first. A fallback repository is judged, and
    /// read for, at its own charge instead (`fetch_from_peer`), so no
    /// account's declaration sets the size fetched for another.
    pub size: u64,
}

/// A mirror work item: pull `want` for (tenant, alias) from `peer_servers`.
#[derive(Debug, Clone)]
pub struct MirrorJob {
    pub tenant_hex: String,
    pub alias: String,
    pub want: Vec<WantBlob>,
    /// The operator's blob peers as base URLs, this node left out
    /// ([`peer_servers_for`]).
    pub peer_servers: Vec<String>,
}

/// What every blob of one job has in common.
#[derive(Debug)]
struct Route {
    tenant_hex: String,
    alias: String,
    peer_servers: Vec<String>,
}

/// One blob to fetch: the unit the queue holds and a fetch slot runs.
#[derive(Debug, Clone)]
struct FetchTask {
    route: Arc<Route>,
    /// Other accounts' claims on the same blob, tried in order when this
    /// node's own state refuses the blob for `route`. Empty for a job that
    /// came from an event: the repair scan knows every claimant, an event
    /// only its own.
    fallbacks: Vec<Arc<Route>>,
    blob: WantBlob,
}

/// Normalize an entry of the peer list into an HTTP base URL: keeps
/// explicit http:// (tests, a private link) and https:// schemes, defaults
/// bare host[:port] values to https://, and trims trailing slashes.
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
/// of these. The early check and the client's resolver apply it through
/// [`wraps_non_global`].
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

/// The early address check of a peer base URL, made before each request.
/// Production requires https; plaintext http is only permitted under
/// `allow_private` (a private link, the loopback tests). The URL then goes
/// through upstream's outbound target policy (`crate::outbound`), which
/// rejects credentials, local hostnames and non-global IP literals, resolves
/// the host and fails closed unless every answer is globally reachable.
///
/// For a host that is an IP literal this is the only check: reqwest
/// connects to a literal without asking a resolver. For a name, the answer
/// checked here is not the one connected to; the client's resolver
/// (`vetted_dns`) checks the answer the connection uses, so a name that
/// resolves elsewhere by the time of the request is still refused.
async fn peer_allowed(peer_base: &str, allow_private: bool) -> PeerVerdict {
    outbound_target_allowed(
        peer_base,
        crate::outbound::OutboundTargetKind::EventGit,
        "https://",
        allow_private,
    )
    .await
}

/// SSRF guard for a private-sync peer relay URL. Same policy as
/// [`peer_allowed`] for WebSocket peers: production requires wss://.
pub(crate) async fn relay_peer_allowed(relay_url: &str, allow_private: bool) -> bool {
    outbound_target_allowed(
        relay_url,
        crate::outbound::OutboundTargetKind::EventRelay,
        "wss://",
        allow_private,
    )
    .await
        == PeerVerdict::Allowed
}

/// The address check of a relay dial on a GRASP-P node, applied to what
/// upstream's outbound target policy has already vetted.
///
/// Upstream's check counts the NAT64 prefix `64:ff9b::/96` and the 6to4
/// prefix `2002::/16` as public, so a name that resolves to an address there
/// which wraps an internal IPv4 address passes it. [`wraps_non_global`]
/// decodes both, and also refuses IPv6 space public hosts are not numbered
/// from. A node that hosts private repositories dials relays that
/// customers' events name, and must not be pointed at its own network that
/// way.
///
/// `grasp_p_node` is false on any other node, which keeps upstream's verdict
/// as it is. A permissive policy vets no address and hands over an empty
/// list, so nothing is refused for it: that is the operator's statement
/// that the target may be internal.
pub(crate) fn vet_relay_dial(
    grasp_p_node: bool,
    vetted: crate::outbound::ResolvedTarget,
) -> Result<crate::outbound::ResolvedTarget, String> {
    if !grasp_p_node {
        return Ok(vetted);
    }
    match vetted
        .addresses
        .iter()
        .find(|address| wraps_non_global(address))
    {
        Some(address) => Err(format!(
            "address {address} is not globally reachable, or wraps an address that is not"
        )),
        None => Ok(vetted),
    }
}

/// Whether a relay dial, or a blob fetch, must not go to `address`, which
/// upstream's policy has passed: the relay dial of a GRASP-P node, the
/// mirror's early check and the mirror client's resolver all apply it. The
/// mirror's own check comes first.
///
/// An IPv6 address must then lie in the global unicast block `2000::/3`,
/// outside the IETF protocol assignments `2001::/23`: the space public hosts
/// are numbered from. Anything else is refused without being decoded,
/// Teredo (`2001::/32`), SIIT (`::ffff:0:0:0/96`) and SRv6 (`5f00::/16`)
/// among it, since a translator or tunnel on the node's path can carry such
/// an address to an internal host. Two forms outside the block keep being
/// judged by the IPv4 address they carry, as before: IPv4-mapped addresses,
/// and the NAT64 prefix `64:ff9b::/96`, which a DNS64 resolver answers for
/// every IPv4-only host. The local-use NAT64 prefix `64:ff9b:1::/48` is
/// outside the block and refused whatever it carries.
///
/// An IPv6 form that carries an IPv4 address (those two, and 6to4 inside
/// the block) is held to upstream's verdict on that address, which knows
/// ranges the mirror's list lacks (benchmarking, reserved, protocol
/// assignments).
pub(super) fn wraps_non_global(address: &IpAddr) -> bool {
    if is_disallowed_ip(address) {
        return true;
    }
    let IpAddr::V6(v6) = address else {
        return false;
    };
    if !carries_ipv4_by_translation(v6) && outside_global_unicast(v6) {
        return true;
    }
    embedded_ipv4(v6).is_some_and(|v4| !crate::outbound::is_globally_reachable(IpAddr::V4(v4)))
}

/// Whether `v6` is an IPv4-mapped address (`::ffff:0:0/96`) or one in the
/// NAT64 well-known prefix (`64:ff9b::/96`).
fn carries_ipv4_by_translation(v6: &Ipv6Addr) -> bool {
    let o = v6.octets();
    v6.to_ipv4_mapped().is_some()
        || (o[..4] == [0x00, 0x64, 0xff, 0x9b] && o[4..12].iter().all(|b| *b == 0))
}

/// Whether `v6` lies outside the global unicast block `2000::/3`, or inside
/// its IETF protocol assignments `2001::/23`.
fn outside_global_unicast(v6: &Ipv6Addr) -> bool {
    let segments = v6.segments();
    (segments[0] & 0xe000) != 0x2000 || (segments[0] == 0x2001 && segments[1] < 0x0200)
}

/// What the address guard says about a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerVerdict {
    Allowed,
    /// The policy refuses the target: its scheme, its credentials, a local
    /// name, or an address that is not global. Only a change of
    /// configuration or of the peer's DNS records heals it.
    Refused,
    /// The name did not resolve. Nothing is connected to, as for a refusal,
    /// but a resolver that fails heals by itself.
    Unresolved,
}

/// How the outbound policy's errors begin when the lookup itself failed
/// (`OutboundTargetPolicy::authorize_resolved`). If upstream rewords them,
/// a failed lookup reads as a refusal again: still nothing is connected
/// to, and the test `guard_tells_a_failed_lookup_from_a_refusal` fails.
const POLICY_DNS_ERROR_PREFIX: &str = "DNS resolution";

/// Shared body of the two guards. With `allow_private` the policy skips DNS
/// vetting (upstream's `allow_non_global`) but still checks scheme and
/// credentials. Every vetted address is also put to [`wraps_non_global`],
/// the relay dial's check, which decodes the NAT64 / 6to4 /
/// IPv4-compatible transition forms that can wrap an internal IPv4.
async fn outbound_target_allowed(
    url: &str,
    kind: crate::outbound::OutboundTargetKind,
    secure_scheme: &str,
    allow_private: bool,
) -> PeerVerdict {
    if !allow_private && !url.starts_with(secure_scheme) {
        return PeerVerdict::Refused;
    }
    let policy = crate::outbound::OutboundTargetPolicy {
        allow_non_global: allow_private,
    };
    match policy.authorize_resolved(kind, url).await {
        Ok(resolved) => {
            if resolved
                .addresses
                .iter()
                .all(|address| !wraps_non_global(address))
            {
                PeerVerdict::Allowed
            } else {
                PeerVerdict::Refused
            }
        }
        Err(e) if e.starts_with(POLICY_DNS_ERROR_PREFIX) => PeerVerdict::Unresolved,
        Err(_) => PeerVerdict::Refused,
    }
}

/// The blob peers of this node: [`configured_peer_servers`] of the
/// operator's list. The same for every alias: a registration's `server`
/// tags are advisory, and no account chooses a host this node fetches from.
pub(super) fn peer_servers_for(svc: &PrivateService) -> Vec<String> {
    configured_peer_servers(
        svc.cfg.mirror_peer_urls.as_deref().unwrap_or_default(),
        &svc.cfg.service_address,
    )
}

/// The entries of `NGIT_GRASP_P_MIRROR_PEER_URLS` as base URLs, each once,
/// less the ones that name this node, so that both nodes of a pair can be
/// given the same list.
fn configured_peer_servers(entries: &[String], own_service: &str) -> Vec<String> {
    let mut out = Vec::new();
    // Host and port, so that loopback test pairs (same host, different
    // ports) stay distinct, and the mount path when this node has one, so
    // that another service on the same host is a peer and not this node.
    for entry in entries
        .iter()
        .filter(|entry| !is_own_server(entry, own_service))
    {
        if let Some(base) = server_base_url(entry) {
            if !out.contains(&base) {
                out.push(base);
            }
        }
    }
    out
}

/// Does an entry of the peer list name this node? `own_service` is the
/// node's service address: its domain, and its mount path when it has one.
///
/// The value is compared as given, and in its scheme-defaulted base-URL
/// form as well, so that a self-reference written without a scheme
/// (`host[:port]`, with the mount path if any) is still recognised as this
/// node.
fn is_own_server(value: &str, own_service: &str) -> bool {
    if super::host::url_denotes_service(value, own_service) {
        return true;
    }
    match server_base_url(value) {
        Some(base) => super::host::url_denotes_service(&base, own_service),
        None => false,
    }
}

// =============================================================================
// Per-blob retry gates
// =============================================================================

/// Per-blob retry state: consecutive failure count + the Instant the blob
/// next becomes eligible for re-enqueue. In-memory only (restart resets to
/// the base interval — see module docs).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RetryState {
    pub attempts: u32,
    pub next_eligible: Instant,
}

/// The two retry schedules, ordered by which retries sooner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RetryClass {
    /// May heal by itself or by a change on this node: `base * 2^n`, capped.
    Backoff,
    /// Needs someone else to act: the maximum interval, every time.
    AtMax,
}

/// The base and the cap of the backoff.
#[derive(Debug, Clone, Copy)]
struct RetryPolicy {
    base: Duration,
    max: Duration,
}

/// Classify a failure reason (module-doc table). A reason this function
/// does not know backs off like a transient one: nothing may go ungated.
fn classify_failure(reason: &str) -> RetryClass {
    if let Some(rest) = reason.strip_prefix("http_status:") {
        return match rest.trim().parse::<u16>() {
            Ok(404) => RetryClass::AtMax,
            _ => RetryClass::Backoff,
        };
    }
    match reason_label(reason) {
        "blocked" | "verify" | "too_large" => RetryClass::AtMax,
        _ => RetryClass::Backoff,
    }
}

/// Does this failure come from this node's own state (ledgers, disk, the
/// registration)? Another peer would meet the same state, so the peer loop
/// ends on it.
fn stops_peer_loop(reason: &str) -> bool {
    matches!(
        reason_label(reason),
        "quota" | "reserve" | "sink" | "write" | "store"
    )
}

/// The one reason recorded for a blob whose peers all failed.
///
/// A failure from this node's own state wins: it is why the loop ended.
/// Otherwise the class that retries soonest wins, and between two reasons
/// of one class the one that sorts first, so the answer does not depend on
/// the order in which the peers were tried.
fn merge_peer_failures(reasons: &[String]) -> Option<&str> {
    if let Some(local) = reasons.iter().find(|r| stops_peer_loop(r)) {
        return Some(local.as_str());
    }
    reasons
        .iter()
        .map(String::as_str)
        .min_by_key(|r| (classify_failure(r), *r))
}

/// Delay before the next retry after `attempts` consecutive failures
/// (`attempts >= 1`): `base * 2^(attempts-1)` capped at `max`, scaled by
/// `jitter` (the caller passes a uniform sample from [0.8, 1.2]).
fn retry_delay(attempts: u32, base: Duration, max: Duration, jitter: f64) -> Duration {
    // Shift capped so base * 2^shift cannot overflow before the max cap.
    let shift = attempts.saturating_sub(1).min(20);
    let capped = base.saturating_mul(1u32 << shift).min(max);
    // A cap too large to scale is used as it is, never a panic.
    Duration::try_from_secs_f64((capped.as_secs_f64() * jitter).max(0.0)).unwrap_or(capped)
}

/// One sample of the ±20% jitter.
fn sample_jitter() -> f64 {
    use ::rand::RngExt;

    0.8 + ::rand::rng().random::<f64>() * 0.4
}

/// Is `sha` gated at `now` (its next-eligible Instant lies in the future)?
/// Gated blobs stay counted in the lag gauge; only re-enqueue is suppressed.
fn retry_gated(retry: &HashMap<String, RetryState>, sha: &str, now: Instant) -> bool {
    retry
        .get(sha)
        .map(|state| state.next_eligible > now)
        .unwrap_or(false)
}

/// Record one failed attempt for `sha` and close its gate. Every reason
/// closes it: a class left ungated would be fetched again by every scan.
fn record_mirror_failure(
    retry: &mut HashMap<String, RetryState>,
    sha: &str,
    reason: &str,
    policy: RetryPolicy,
    now: Instant,
    jitter: f64,
) {
    let entry = retry.entry(sha.to_string()).or_insert(RetryState {
        attempts: 0,
        next_eligible: now,
    });
    entry.attempts = entry.attempts.saturating_add(1);
    let delay = match classify_failure(reason) {
        RetryClass::AtMax => retry_delay(u32::MAX, policy.base, policy.max, jitter),
        RetryClass::Backoff => retry_delay(entry.attempts, policy.base, policy.max, jitter),
    };
    // A cap too large for the clock means "as late as the clock allows",
    // never a panic in the worker loop.
    entry.next_eligible = now
        .checked_add(delay)
        .unwrap_or(now + Duration::from_secs(365 * 24 * 3600));
}

/// Clear the retry gate for `sha` (successful fetch, or the blob turned up
/// by other means).
fn record_mirror_success(retry: &mut HashMap<String, RetryState>, sha: &str) {
    retry.remove(sha);
}

// =============================================================================
// The fair queue
// =============================================================================

/// What [`FairQueue::push`] did with a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pushed {
    Queued,
    /// The blob is already queued or being fetched.
    Duplicate,
    /// The account's backlog is full. The blob is dropped here and derived
    /// again by the next repair scan.
    BacklogFull,
}

/// A blob handed out by [`FairQueue::pop`]. It counts as running for its
/// account until [`FairQueue::finish`] is called with the same two names.
#[derive(Debug)]
struct Popped<T> {
    account: String,
    sha: String,
    item: T,
}

/// Blobs waiting to be fetched, one backlog per account.
///
/// Accounts are served in turn, and an account that already has
/// `account_running_cap` blobs running is passed over, so one account's
/// backlog, however long or slow, delays another account's blob by at most
/// the fetches already running. A blob is in the queue or running at most
/// once, whoever asked for it; while it waits, the repair scan may move it
/// to the account it should be fetched for ([`Self::push_or_move`]).
///
/// No clock and no I/O: the worker loop owns one and is its only caller.
#[derive(Debug)]
struct FairQueue<T> {
    /// Waiting blobs per account. An account has an entry only while it has
    /// something waiting.
    backlogs: HashMap<String, VecDeque<(String, T)>>,
    /// The accounts of `backlogs`, each once, next to be served first.
    ring: VecDeque<String>,
    /// Blobs running per account. An entry exists only while above zero.
    running: HashMap<String, usize>,
    running_total: usize,
    /// Hashes that are waiting or running: the account a hash waits for,
    /// or `None` once it runs.
    known: HashMap<String, Option<String>>,
    account_running_cap: usize,
    account_backlog_cap: usize,
}

impl<T> FairQueue<T> {
    fn new(account_running_cap: usize, account_backlog_cap: usize) -> Self {
        Self {
            backlogs: HashMap::new(),
            ring: VecDeque::new(),
            running: HashMap::new(),
            running_total: 0,
            known: HashMap::new(),
            account_running_cap: account_running_cap.max(1),
            account_backlog_cap: account_backlog_cap.max(1),
        }
    }

    fn push(&mut self, account: &str, sha: &str, item: T) -> Pushed {
        if self.known.contains_key(sha) {
            return Pushed::Duplicate;
        }
        let waiting = self.backlogs.get(account).map_or(0, VecDeque::len);
        if waiting >= self.account_backlog_cap {
            return Pushed::BacklogFull;
        }
        if waiting == 0 {
            self.ring.push_back(account.to_string());
        }
        self.known
            .insert(sha.to_string(), Some(account.to_string()));
        self.backlogs
            .entry(account.to_string())
            .or_default()
            .push_back((sha.to_string(), item));
        Pushed::Queued
    }

    /// As [`Self::push`], but a blob that waits for another account is
    /// moved to `account`, with `item` in place of what was queued.
    ///
    /// For the repair scan, which knows every claimant of a blob. A job
    /// from an event queues a blob for the account that published the
    /// event; if that account has a long backlog, the blob would wait
    /// behind it although another claimant's queue is short. A blob that is
    /// already running is left alone.
    fn push_or_move(&mut self, account: &str, sha: &str, item: T) -> Pushed {
        let holder = match self.known.get(sha) {
            None => return self.push(account, sha, item),
            Some(None) => return Pushed::Duplicate,
            Some(Some(holder)) if holder == account => return Pushed::Duplicate,
            Some(Some(holder)) => holder.clone(),
        };
        // No room where it should go: it keeps its place where it is.
        if self.backlogs.get(account).map_or(0, VecDeque::len) >= self.account_backlog_cap {
            return Pushed::Duplicate;
        }
        let emptied = match self.backlogs.get_mut(&holder) {
            Some(backlog) => {
                backlog.retain(|(waiting, _)| waiting != sha);
                backlog.is_empty()
            }
            None => false,
        };
        if emptied {
            self.backlogs.remove(&holder);
            self.ring.retain(|waiting| waiting != &holder);
        }
        self.known.remove(sha);
        self.push(account, sha, item)
    }

    /// The next blob to run, or `None` when nothing is waiting or every
    /// account with something waiting is at its cap.
    fn pop(&mut self) -> Option<Popped<T>> {
        for _ in 0..self.ring.len() {
            let account = self.ring.pop_front()?;
            if self.running_for(&account) >= self.account_running_cap {
                self.ring.push_back(account);
                continue;
            }
            let (next, emptied) = match self.backlogs.get_mut(&account) {
                Some(backlog) => (backlog.pop_front(), backlog.is_empty()),
                None => (None, true),
            };
            if emptied {
                self.backlogs.remove(&account);
            } else {
                self.ring.push_back(account.clone());
            }
            let Some((sha, item)) = next else {
                continue;
            };
            *self.running.entry(account.clone()).or_insert(0) += 1;
            self.running_total += 1;
            self.known.insert(sha.clone(), None);
            return Some(Popped { account, sha, item });
        }
        None
    }

    /// Give back what [`Self::pop`] handed out, fetched or not.
    fn finish(&mut self, account: &str, sha: &str) {
        self.known.remove(sha);
        let emptied = match self.running.get_mut(account) {
            Some(count) => {
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => return,
        };
        if emptied {
            self.running.remove(account);
        }
        self.running_total = self.running_total.saturating_sub(1);
    }

    /// Blobs handed out and not yet given back.
    fn running(&self) -> usize {
        self.running_total
    }

    fn running_for(&self, account: &str) -> usize {
        self.running.get(account).copied().unwrap_or(0)
    }

    /// Is there a waiting blob that [`Self::pop`] would hand out?
    fn has_runnable(&self) -> bool {
        self.ring
            .iter()
            .any(|account| self.running_for(account) < self.account_running_cap)
    }

    #[cfg(test)]
    fn waiting(&self) -> usize {
        self.backlogs.values().map(VecDeque::len).sum()
    }
}

/// How many fetches one account may have running: half of them, and at
/// least one. One slow account then never holds every slot. Two slow
/// accounts can, between them: with the default of four they hold two
/// each. A third account then waits for their fetches to end and is served
/// in its turn: each account ahead of it starts at most one more fetch
/// first.
fn account_share(max_concurrency: usize) -> usize {
    (max_concurrency / 2).max(1)
}

// =============================================================================
// The attempt budget
// =============================================================================

/// A token bucket over fetch attempts, all accounts together: holds up to
/// one minute's worth, refills at the configured rate. One token is taken
/// each time a fetch starts. `per_min == 0` means no limit.
///
/// No clock of its own: the caller says what time it is.
#[derive(Debug)]
struct AttemptBudget {
    per_min: u32,
    tokens: f64,
    last: Instant,
}

impl AttemptBudget {
    fn new(per_min: u32, now: Instant) -> Self {
        Self {
            per_min,
            tokens: f64::from(per_min),
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last);
        if elapsed.is_zero() {
            // Also covers a reading earlier than the last one: the time
            // already credited is never credited twice.
            return;
        }
        let rate = f64::from(self.per_min) / 60.0;
        self.tokens = (self.tokens + elapsed.as_secs_f64() * rate).min(f64::from(self.per_min));
        self.last = now;
    }

    /// How long until a token is there: `None` when one can be taken now.
    fn wait(&mut self, now: Instant) -> Option<Duration> {
        if self.per_min == 0 {
            return None;
        }
        self.refill(now);
        if self.tokens >= 1.0 {
            return None;
        }
        let rate = f64::from(self.per_min) / 60.0;
        let wait = Duration::from_secs_f64((1.0 - self.tokens) / rate);
        // Never a zero wait: rounding could otherwise wake the loop a
        // moment early, find no token and spin.
        Some(wait.max(Duration::from_millis(1)))
    }

    /// Take one token if there is one.
    fn try_take(&mut self, now: Instant) -> bool {
        if self.per_min == 0 {
            return true;
        }
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// =============================================================================
// What a fetch is given
// =============================================================================

/// How many bytes to read from a peer that answered 200, or why not to
/// read any.
///
/// `announced` is the length the response states, if it states one.
///
/// Every peer is one the operator listed, the pair's other node. Its length
/// is the length of the blob it stores, so it is believed even where the
/// state root declared another: the replica then stores what the origin
/// stores. With no announced length, the declared size bounds the read. In
/// every case nothing longer than the maximum blob size is read.
fn expected_len(announced: Option<u64>, declared: u64, max_blob_bytes: u64) -> Result<u64, String> {
    let expected = announced.unwrap_or(declared);
    if expected > max_blob_bytes {
        return Err("too_large".to_string());
    }
    Ok(expected)
}

/// How long one request for `len` bytes may take from its first byte sent
/// to its last byte read: the configured timeout, plus the time the body
/// needs on the slowest link the mirror allows for. A fixed limit would
/// either cut every large blob on a slow link or let a small one hang.
fn fetch_deadline(fetch_timeout: Duration, len: u64) -> Duration {
    fetch_timeout.saturating_add(Duration::from_secs(len / MIN_FETCH_BYTES_PER_SEC))
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
            "m" | "pack" if v.len() >= 3 && super::blossom_auth::is_lower_hex_64(&v[1]) => {
                if let Ok(size) = v[2].parse::<u64>() {
                    want.push(WantBlob {
                        sha256: v[1].clone(),
                        size,
                    });
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
    // denylisted, or currently gated: a gated blob stays missing until its
    // next-eligible Instant and must not be queued again by every arriving
    // 30641 edition.
    {
        let now = clock_now();
        let retry = svc.mirror_retry.lock();
        want.retain(|w| {
            !svc.blobs.exists(&w.sha256)
                && !svc.is_denylisted(&w.sha256)
                && !retry_gated(&retry, &w.sha256, now)
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
        tenant_hex: record.tenant_hex,
        alias,
        want,
        peer_servers: peer_servers_for(svc),
    };
    let _ = tx.send(job);
}

// =============================================================================
// The repair scan
// =============================================================================

/// What one repair scan found.
#[derive(Debug, Default)]
struct ScanOutcome {
    /// Missing blobs that may be fetched now, each attributed to one alias.
    tasks: Vec<FetchTask>,
    /// Every referenced blob that is missing, gated ones included.
    lag: u64,
}

/// An alias with a live registration that claims a missing blob.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Claimant {
    account: String,
    alias: String,
}

/// A missing blob as the scan sees it between its two passes.
struct Wanted {
    sha256: String,
    /// The claim's size, for a claimant with no charge of its own (which
    /// the claim's invariants rule out).
    claim_size: u64,
    /// What each referencing repository is charged: its own declared size.
    charges: Vec<super::meta::ClaimCharge>,
    /// The live registrations that claim it.
    live: Vec<Arc<Route>>,
}

/// How many accounts one fetch tries a blob for: the chosen claimant and
/// this many less one as fallbacks.
const MAX_ROUTES_PER_BLOB: usize = 4;

/// Which claimants a missing blob is fetched for, best first: one alias
/// per account, the account with the fewest missing blobs first, at most
/// [`MAX_ROUTES_PER_BLOB`] of them. The values are indexes into
/// `claimants`; `account_lag` counts the missing blobs per account.
///
/// A blob can be claimed by aliases of several accounts, and it waits in
/// the queue of the account it is attributed to. Taking the first claimant
/// would let an account with a huge backlog pull a blob it shares with
/// another account into its own long queue; the shortest queue gets the
/// blob to everyone who claims it soonest. Ties go to the account that
/// sorts first, so the choice does not depend on claim order.
///
/// The rest are fallbacks. Without them the rule above could be turned
/// round: an account with a short queue and no room left would be chosen
/// for a blob every time, be refused every time, and keep the blob from
/// the account that can take it.
///
/// Within one account the alias that sorts first is chosen: every
/// referencing alias pays its own charge, and the quota forecast nets each
/// one's own, so none of them is a better choice than another.
fn rank_claimants(claimants: &[Claimant], account_lag: &HashMap<String, u64>) -> Vec<usize> {
    let mut order: Vec<usize> = (0..claimants.len()).collect();
    order.sort_by_key(|&index| {
        let claimant = &claimants[index];
        (
            account_lag.get(&claimant.account).copied().unwrap_or(0),
            claimant.account.as_str(),
            claimant.alias.as_str(),
        )
    });
    let mut accounts: HashSet<&str> = HashSet::new();
    order.retain(|&index| accounts.insert(claimants[index].account.as_str()));
    order.truncate(MAX_ROUTES_PER_BLOB);
    order
}

/// Drop the gates of blobs that are no longer missing (stored, denylisted,
/// or unclaimed after a registration died), so the map stays bounded by the
/// live backlog. Returns the hashes whose gate is still shut at `now`.
fn prune_gates(
    retry: &mut HashMap<String, RetryState>,
    missing: &HashSet<&str>,
    now: Instant,
) -> HashSet<String> {
    retry.retain(|sha, _| missing.contains(sha.as_str()));
    retry
        .iter()
        .filter(|(_, state)| state.next_eligible > now)
        .map(|(sha, _)| sha.clone())
        .collect()
}

/// Repair scan: derive a fetch for every referenced-but-missing blob from
/// the blob-claim table, and count the missing ones. Covers boot, missed
/// or dropped enqueues, and retries once a gate has opened.
///
/// Reads the whole claim table and asks the file system about every claim,
/// so it must run on a blocking thread, never on the async runtime.
///
/// `None` when the claim table could not be read: that is not "nothing is
/// missing", and the caller must not report it as such.
fn scan_missing(svc: &PrivateService, now: Instant) -> Option<ScanOutcome> {
    let mut outcome = ScanOutcome::default();

    let txn = svc.meta.read_txn().ok()?;
    let claims = svc.meta.all_blob_claims(&txn).ok()?;

    // The one question put to the file system per claim. Everything below
    // works from this list.
    let missing: Vec<(String, super::meta::BlobClaim)> = claims
        .into_iter()
        .filter(|(sha, claim)| {
            !claim.aliases.is_empty() && !svc.is_denylisted(sha) && !svc.blobs.exists(sha)
        })
        .collect();
    outcome.lag = missing.len() as u64;

    let missing_now: HashSet<&str> = missing.iter().map(|(sha, _)| sha.as_str()).collect();
    let gated = prune_gates(&mut svc.mirror_retry.lock(), &missing_now, now);
    // Ends the borrow of `missing`, which is taken apart below.
    drop(missing_now);

    // Each alias is looked up once, however many blobs it claims. Every
    // alias has the same peers: the operator's.
    let peer_servers = peer_servers_for(svc);
    let mut routes: HashMap<String, Option<Arc<Route>>> = HashMap::new();
    let mut route_for = |alias: &str| -> Option<Arc<Route>> {
        if let Some(known) = routes.get(alias) {
            return known.clone();
        }
        let route = match svc.meta.get_registration(&txn, alias) {
            Ok(Some(record)) if record.tombstoned_at.is_none() => Some(Arc::new(Route {
                tenant_hex: record.tenant_hex,
                alias: alias.to_string(),
                peer_servers: peer_servers.clone(),
            })),
            _ => None,
        };
        routes.insert(alias.to_string(), route.clone());
        route
    };

    // First pass: who claims each missing blob, and how many missing blobs
    // each account has. Gated blobs count: they are part of the backlog.
    let mut account_lag: HashMap<String, u64> = HashMap::new();
    let mut wanted: Vec<Wanted> = Vec::with_capacity(missing.len());
    for (sha, claim) in missing {
        let live: Vec<Arc<Route>> = claim
            .aliases
            .iter()
            .filter_map(|alias| route_for(alias))
            .collect();
        // A blob counts once for an account, however many of the account's
        // aliases claim it.
        let accounts: HashSet<&str> = live.iter().map(|r| r.tenant_hex.as_str()).collect();
        for account in accounts {
            *account_lag.entry(account.to_string()).or_insert(0) += 1;
        }
        wanted.push(Wanted {
            sha256: sha,
            claim_size: claim.size,
            charges: claim.charges,
            live,
        });
    }

    // Second pass: one fetch per blob whose gate is open and which a live
    // registration still claims. No more per account than its backlog
    // holds: the queue would drop the rest, and the next scan derives them
    // again.
    let mut derived: HashMap<String, usize> = HashMap::new();
    for Wanted {
        sha256,
        claim_size,
        charges,
        live,
    } in wanted
    {
        if gated.contains(&sha256) {
            continue;
        }
        let claimants: Vec<Claimant> = live
            .iter()
            .map(|route| Claimant {
                account: route.tenant_hex.clone(),
                alias: route.alias.clone(),
            })
            .collect();
        let ranked = rank_claimants(&claimants, &account_lag);
        let Some((&chosen, others)) = ranked.split_first() else {
            continue;
        };
        let route = live[chosen].clone();
        // The size the chosen repository declared, which is what it pays
        // until the bytes arrive: a first declarer's size no longer decides
        // the fetch for everyone.
        let size = charges
            .iter()
            .find(|charge| charge.alias == route.alias)
            .map(|charge| charge.bytes)
            .unwrap_or(claim_size);
        let blob = WantBlob { sha256, size };
        let count = derived.entry(route.tenant_hex.clone()).or_insert(0);
        if *count >= ACCOUNT_BACKLOG_CAP {
            continue;
        }
        *count += 1;
        outcome.tasks.push(FetchTask {
            route,
            fallbacks: others.iter().map(|&index| live[index].clone()).collect(),
            blob,
        });
    }

    Some(outcome)
}

// =============================================================================
// One fetch
// =============================================================================

/// Would storing `len` bytes of this blob for the route's alias fit the
/// ledgers as they stand? Local state only. Asked before any request is
/// sent, so a blob the account has no room for costs no download.
fn local_preflight(
    svc: &PrivateService,
    route: &Route,
    blob: &WantBlob,
    len: u64,
) -> Result<(), String> {
    svc.blob_quota_preflight(&route.tenant_hex, &route.alias, &blob.sha256, len)
        .map_err(|e| match e {
            BlobError::QuotaExceeded => "quota".to_string(),
            other => format!("reserve: {}", other.reason()),
        })
}

/// The reason recorded for a request that got no response. The resolver's
/// refusal of an answer is `blocked`, like the early check's, and names the
/// host and the address; anything else, a name that did not resolve
/// included, is `network`.
fn send_failure_reason(error: &reqwest::Error) -> String {
    match vetted_dns::blocked_target(error) {
        Some(blocked) => format!("blocked: {blocked}"),
        None => format!("network: {error}"),
    }
}

/// Fetch one blob from one peer through the upload sink, for one of the
/// accounts that claim it.
///
/// The order is the point: each step is cheaper than the next, and a blob
/// that a cheap step refuses never reaches a dearer one. Address check,
/// quota preflight, request (whose connection the resolver vets), status,
/// length, byte reservation, temp file, body.
async fn fetch_from_peer(
    svc: &Arc<PrivateService>,
    client: &reqwest::Client,
    fetch_timeout: Duration,
    route: &Route,
    blob: &WantBlob,
    peer_base: &str,
) -> Result<(), String> {
    // The early address check, the only one an IP literal gets. A name
    // that does not resolve is not connected to either, but it is a
    // passing failure, not a refusal.
    match peer_allowed(peer_base, svc.cfg.mirror_allow_private_ips).await {
        PeerVerdict::Allowed => {}
        PeerVerdict::Refused => return Err("blocked".to_string()),
        PeerVerdict::Unresolved => return Err(UNRESOLVED_REASON.to_string()),
    }

    // What this route's own repository declared, which is what it pays
    // until the bytes arrive: for a fallback, `blob.size` is the first
    // route's declaration.
    let own = svc
        .prior_charge(&blob.sha256, &route.alias)
        .map_err(|e| format!("reserve: {}", e.reason()))?;
    let declared = if own > 0 { own } else { blob.size };

    local_preflight(svc, route, blob, declared)?;

    let started = tokio::time::Instant::now();
    let url = format!("{}/{}", peer_base, blob.sha256);
    let response = match tokio::time::timeout(fetch_timeout, client.get(&url).send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(send_failure_reason(&e)),
        Err(_) => {
            return Err(format!(
                "network: no response within {}s",
                fetch_timeout.as_secs()
            ));
        }
    };
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("http_status: {}", response.status().as_u16()));
    }

    let expected = expected_len(response.content_length(), declared, svc.cfg.max_blob_bytes)?;
    // The preflight above used the declared size. The peer may have
    // announced a larger one; ask again before reading it.
    if expected > declared {
        local_preflight(svc, route, blob, expected)?;
    }

    // Reserve in-flight bytes, then open the temp file (as a client PUT
    // does: reservation, sink, stream, finish). Storing sets the route's
    // own charge to the stored size instead of adding one, so the
    // reservation nets that charge.
    //
    // The reservation is for bytes only. A fetch takes none of the upload
    // slots clients share, so clients that fill or stall those slots cannot
    // stop replication; the worker's own concurrency limit bounds how many
    // fetches run at once.
    let pending = svc
        .prior_charge(&blob.sha256, &route.alias)
        .map_err(|e| format!("reserve: {}", e.reason()))?;
    let reservation = svc
        .reserve_upload(UploadOrigin::Mirror, &route.tenant_hex, expected, pending)
        .map_err(|e| match e {
            BlobError::QuotaExceeded => "quota".to_string(),
            other => format!("reserve: {}", other.reason()),
        })?;
    let mut sink = UploadSink::create(
        svc.meta.clone(),
        svc.blobs.clone(),
        svc.cfg.clone(),
        route.tenant_hex.clone(),
        route.alias.clone(),
        blob.sha256.clone(),
        expected,
        reservation,
        svc.denylist.clone(),
        UploadOrigin::Mirror,
    )
    .await
    .map_err(|e| format!("sink: {}", e.reason()))?;

    // Two limits on the body: the whole request must end by a deadline
    // that grows with the length, and the peer may not go silent for
    // longer than the configured timeout in between.
    let body_limit = fetch_deadline(fetch_timeout, expected).min(MAX_FETCH_DEADLINE);
    let deadline = started + body_limit;
    let mut response = response;
    loop {
        let next = tokio::time::timeout_at(
            deadline,
            tokio::time::timeout(fetch_timeout, response.chunk()),
        )
        .await;
        let chunk = match next {
            Err(_) => {
                return Err(format!(
                    "network: body not complete after {}s",
                    body_limit.as_secs()
                ));
            }
            Ok(Err(_)) => {
                return Err(format!(
                    "network: peer sent nothing for {}s",
                    fetch_timeout.as_secs()
                ));
            }
            Ok(Ok(Err(e))) => return Err(format!("network: {e}")),
            Ok(Ok(Ok(chunk))) => chunk,
        };
        let Some(chunk) = chunk else {
            break;
        };
        // write_chunk stops at the expected length (a peer cannot stream
        // without bound).
        sink.write_chunk(&chunk).await.map_err(|e| match e {
            BlobError::TooLarge => "too_large".to_string(),
            other => format!("write: {}", other.reason()),
        })?;
    }

    // finish() verifies that the bytes read are as many as expected and
    // hash to the requested name; on a mismatch the temp file is deleted
    // and nothing is stored.
    sink.finish().await.map_err(|e| match e {
        BlobError::QuotaExceeded => "quota".to_string(),
        BlobError::BadRequest(reason) => format!("verify: {reason}"),
        other => format!("store: {}", other.reason()),
    })?;
    Ok(())
}

/// Fetch one blob, trying each peer in turn, for each account that claims
/// it in turn. Success is sticky (a no-op when the blob landed by other
/// means).
///
/// Returns `None` on success (or when no fetch was needed: already local /
/// denylisted) and `Some(reason)` when no peer delivered it. The reason is
/// the one [`merge_peer_failures`] picks; the worker closes the blob's
/// retry gate from it.
async fn fetch_blob(
    svc: &Arc<PrivateService>,
    client: &reqwest::Client,
    fetch_timeout: Duration,
    task: &FetchTask,
) -> Option<String> {
    let blob = &task.blob;
    if svc.blobs.exists(&blob.sha256) || svc.is_denylisted(&blob.sha256) {
        return None;
    }
    let mut routes: Vec<&Route> = Vec::with_capacity(1 + task.fallbacks.len());
    routes.push(&task.route);
    for fallback in &task.fallbacks {
        routes.push(fallback);
    }
    if routes.iter().all(|route| route.peer_servers.is_empty()) {
        crate::metrics::record_private_mirror_failed("no_peer");
        // FS-5 + R2-2: deduped and globally rate-limited — the metric
        // carries the per-attempt count.
        if svc
            .mirror_failure_log
            .lock()
            .should_log(&blob.sha256, "no_peer")
        {
            tracing::warn!(
                alias = %task.route.alias,
                sha256 = %blob.sha256,
                "private mirror: no peer server available for blob"
            );
        }
        return Some("no_peer".to_string());
    }

    let mut failures: Vec<String> = Vec::new();
    // Peers that gave an answer of their own. It does not depend on which
    // account asks, so they are not asked again for the next one.
    let mut answered: HashSet<&str> = HashSet::new();
    for &route in &routes {
        for peer in &route.peer_servers {
            if answered.contains(peer.as_str()) {
                continue;
            }
            match fetch_from_peer(svc, client, fetch_timeout, route, blob, peer).await {
                Ok(()) => {
                    crate::metrics::record_private_mirror_fetched();
                    svc.refresh_gauges();
                    tracing::info!(
                        alias = %route.alias,
                        sha256 = %blob.sha256,
                        peer = %peer,
                        size = blob.size,
                        "private mirror: blob fetched from peer"
                    );
                    return None;
                }
                Err(reason) => {
                    tracing::debug!(
                        alias = %route.alias,
                        sha256 = %blob.sha256,
                        peer = %peer,
                        reason = %reason,
                        "private mirror: fetch attempt failed"
                    );
                    // This node's own state refused the blob for this
                    // account: the next peer would be refused the same
                    // way, the next account perhaps not.
                    let local = stops_peer_loop(&reason);
                    failures.push(reason);
                    if local {
                        break;
                    }
                    answered.insert(peer.as_str());
                }
            }
        }
    }

    let reason = merge_peer_failures(&failures)
        .unwrap_or("no_peer")
        .to_string();
    crate::metrics::record_private_mirror_failed(reason_label(&reason));
    // FS-5 (review L2-F7) + R2-2: one warn per (sha256, reason) per 10
    // minutes, bounded globally to a 16-warn burst then 1 warn/s — not one
    // per failed attempt. The metric above keeps the full per-attempt count
    // for alerting.
    if svc
        .mirror_failure_log
        .lock()
        .should_log(&blob.sha256, &reason)
    {
        tracing::warn!(
            alias = %task.route.alias,
            sha256 = %blob.sha256,
            reason = %reason,
            "private mirror: blob fetch failed on all peers (will retry after its backoff)"
        );
    }
    Some(reason)
}

// =============================================================================
// The worker
// =============================================================================

/// A fetch in progress: `None` when the blob is local now (or need not
/// be), `Some(reason)` when it could not be fetched.
type FetchFuture = Pin<Box<dyn Future<Output = Option<String>> + Send>>;

/// What the worker loop needs from the node. The loop is written against
/// this so that its scheduling can be tested with time paused and no
/// network or disk.
trait MirrorBackend: Send + Sync + 'static {
    /// Derive the missing blobs. Called on a blocking thread.
    fn scan(&self) -> ScanOutcome;
    /// Is there nothing to fetch for this hash (already local, denylisted)?
    fn settled(&self, sha256: &str) -> bool;
    /// Fetch one blob.
    fn fetch(self: Arc<Self>, task: FetchTask) -> FetchFuture;
}

/// The node itself as the worker's backend.
struct LiveBackend {
    svc: Arc<PrivateService>,
    client: reqwest::Client,
    fetch_timeout: Duration,
}

impl MirrorBackend for LiveBackend {
    fn scan(&self) -> ScanOutcome {
        let Some(outcome) = scan_missing(&self.svc, clock_now()) else {
            // Queue nothing and leave the gauge as the last good scan set
            // it: a zero here would read as "nothing is missing".
            tracing::warn!("private mirror: repair scan could not read the claim table");
            return ScanOutcome::default();
        };
        // The only place the gauge is set: one count per scan, taken from
        // the same pass over the claims as the work it queues.
        crate::metrics::set_private_mirror_lag_blobs(outcome.lag);
        outcome
    }

    fn settled(&self, sha256: &str) -> bool {
        self.svc.blobs.exists(sha256) || self.svc.is_denylisted(sha256)
    }

    fn fetch(self: Arc<Self>, task: FetchTask) -> FetchFuture {
        Box::pin(
            async move { fetch_blob(&self.svc, &self.client, self.fetch_timeout, &task).await },
        )
    }
}

/// The worker's numbers, fixed at start.
#[derive(Debug, Clone, Copy)]
struct WorkerSettings {
    max_concurrency: usize,
    attempts_per_min: u32,
    retry: RetryPolicy,
    repair_interval: Duration,
}

/// How a fetch ended.
#[derive(Debug)]
enum FetchEnd {
    Fetched,
    Failed(String),
    /// The task ended without an answer (it panicked or was cancelled).
    Lost,
}

/// A finished fetch, as reported to the worker loop.
#[derive(Debug)]
struct Finished {
    account: String,
    sha: String,
    end: FetchEnd,
}

/// Reports a fetch to the worker loop when dropped, whatever ended the
/// task. The loop frees the blob's slot only on this report, so a fetch
/// that ended without one would hold its slot, and keep its blob marked as
/// running, for as long as the node runs.
struct FinishReport {
    tx: UnboundedSender<Finished>,
    finished: Option<Finished>,
}

impl Drop for FinishReport {
    fn drop(&mut self) {
        if let Some(finished) = self.finished.take() {
            let _ = self.tx.send(finished);
        }
    }
}

/// Put the blobs of one job into the queue.
fn queue_job(queue: &mut FairQueue<FetchTask>, job: MirrorJob) {
    let route = Arc::new(Route {
        tenant_hex: job.tenant_hex,
        alias: job.alias,
        peer_servers: job.peer_servers,
    });
    queue_tasks(
        queue,
        job.want.into_iter().map(|blob| FetchTask {
            route: route.clone(),
            fallbacks: Vec::new(),
            blob,
        }),
        Asked::ByEvent,
    );
}

/// Who asked for a fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// An accepted event: it knows its own account only.
    ByEvent,
    /// The repair scan: it chose among every claimant, so its choice
    /// replaces an event's while the blob still waits.
    ByScan,
}

/// Put fetches into the queue. One that does not fit its account's backlog
/// is dropped: the claim it came from is still there, and the next repair
/// scan derives it again.
fn queue_tasks(
    queue: &mut FairQueue<FetchTask>,
    tasks: impl IntoIterator<Item = FetchTask>,
    asked: Asked,
) {
    let mut dropped = 0_u64;
    for task in tasks {
        let account = task.route.tenant_hex.clone();
        let sha = task.blob.sha256.clone();
        let pushed = match asked {
            Asked::ByEvent => queue.push(&account, &sha, task),
            Asked::ByScan => queue.push_or_move(&account, &sha, task),
        };
        if pushed == Pushed::BacklogFull {
            dropped += 1;
        }
    }
    if dropped > 0 {
        tracing::debug!(
            dropped,
            "private mirror: account backlog full; the next repair scan queues these again"
        );
    }
}

/// Start every fetch that may start now.
///
/// Returns how long to wait for the attempt budget when the budget is the
/// only thing holding a fetch back, and `None` otherwise. In every other
/// case where something waits, a running fetch has to end first, and its
/// report wakes the loop.
fn dispatch_ready<B: MirrorBackend>(
    backend: &Arc<B>,
    retry: &parking_lot::Mutex<HashMap<String, RetryState>>,
    queue: &mut FairQueue<FetchTask>,
    budget: &mut AttemptBudget,
    max_concurrency: usize,
    done_tx: &UnboundedSender<Finished>,
) -> Option<Duration> {
    loop {
        if queue.running() >= max_concurrency {
            return None;
        }
        let now = clock_now();
        if let Some(wait) = budget.wait(now) {
            return queue.has_runnable().then_some(wait);
        }
        let next = queue.pop()?;
        // Queued a while ago: it may have arrived by another path, or its
        // gate may have been shut by a fetch that finished since. Neither
        // costs an attempt.
        if backend.settled(&next.sha) || retry_gated(&retry.lock(), &next.sha, now) {
            queue.finish(&next.account, &next.sha);
            continue;
        }
        // `wait` said a token is there, and nothing else takes one.
        let _ = budget.try_take(now);

        let report = FinishReport {
            tx: done_tx.clone(),
            finished: Some(Finished {
                account: next.account,
                sha: next.sha,
                end: FetchEnd::Lost,
            }),
        };
        let backend = backend.clone();
        let task = next.item;
        tokio::spawn(async move {
            let mut report = report;
            let outcome = backend.fetch(task).await;
            if let Some(finished) = report.finished.as_mut() {
                finished.end = match outcome {
                    None => FetchEnd::Fetched,
                    Some(reason) => FetchEnd::Failed(reason),
                };
            }
        });
    }
}

/// Take a finished fetch off the books: set or clear the blob's retry gate
/// and free its slot.
fn settle(
    retry: &parking_lot::Mutex<HashMap<String, RetryState>>,
    queue: &mut FairQueue<FetchTask>,
    policy: RetryPolicy,
    finished: Finished,
) {
    let now = clock_now();
    {
        let mut gates = retry.lock();
        match &finished.end {
            FetchEnd::Fetched => record_mirror_success(&mut gates, &finished.sha),
            FetchEnd::Failed(reason) => record_mirror_failure(
                &mut gates,
                &finished.sha,
                reason,
                policy,
                now,
                sample_jitter(),
            ),
            FetchEnd::Lost => {
                tracing::warn!(
                    sha256 = %finished.sha,
                    "private mirror: a fetch ended without an answer; it will be retried"
                );
                record_mirror_failure(
                    &mut gates,
                    &finished.sha,
                    "lost",
                    policy,
                    now,
                    sample_jitter(),
                );
            }
        }
    }
    queue.finish(&finished.account, &finished.sha);
}

/// The worker loop.
///
/// It waits for four things and nothing else: a new job, the repair tick,
/// a finished scan and a finished fetch (plus a timer, armed only while
/// the attempt budget is what holds a fetch back). It never waits for a
/// free fetch slot, so a full set of slow fetches delays neither the jobs
/// nor the scans. After each event it starts every fetch that may start.
///
/// Why nothing runnable is left asleep: a queued blob does not start only
/// if (a) every slot is taken, (b) its account is at its share, or (c) the
/// budget is empty. In (a) and (b) at least one fetch is running, and its
/// report wakes the loop; a report is sent however the fetch ends
/// ([`FinishReport`]). In (c) the timer is armed for the next token. A
/// gated blob is not queued at all: the scan after its gate opens queues
/// it, and the tick that starts scans is always waited for.
async fn run_worker<B: MirrorBackend>(
    backend: Arc<B>,
    mut jobs: UnboundedReceiver<MirrorJob>,
    retry: Arc<parking_lot::Mutex<HashMap<String, RetryState>>>,
    settings: WorkerSettings,
) {
    // The loop keeps a sender of each channel, so neither ever closes.
    let (done_tx, mut done_rx) = unbounded_channel::<Finished>();
    let (scan_tx, mut scan_rx) = unbounded_channel::<Option<ScanOutcome>>();

    let mut queue: FairQueue<FetchTask> =
        FairQueue::new(account_share(settings.max_concurrency), ACCOUNT_BACKLOG_CAP);
    let mut budget = AttemptBudget::new(settings.attempts_per_min, clock_now());
    // One scan at a time: a scan that outlasts the interval must not pile
    // up behind itself.
    let mut scanning = false;

    // The first tick fires at once: the boot scan queues every missing
    // blob of every live claim.
    let mut repair = tokio::time::interval(settings.repair_interval);
    repair.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        let budget_wait = dispatch_ready(
            &backend,
            &retry,
            &mut queue,
            &mut budget,
            settings.max_concurrency,
            &done_tx,
        );

        tokio::select! {
            job = jobs.recv() => match job {
                Some(job) => queue_job(&mut queue, job),
                // Every sender is gone: the node is shutting down.
                None => break,
            },
            _ = repair.tick() => {
                if !scanning {
                    scanning = true;
                    let backend = backend.clone();
                    let scan_tx = scan_tx.clone();
                    tokio::spawn(async move {
                        // `None` when the scan panicked. Sent either way,
                        // or `scanning` would stay set and no scan would
                        // ever run again.
                        let outcome = tokio::task::spawn_blocking(move || backend.scan())
                            .await
                            .ok();
                        let _ = scan_tx.send(outcome);
                    });
                }
            }
            outcome = scan_rx.recv() => {
                scanning = false;
                match outcome.flatten() {
                    Some(outcome) => queue_tasks(&mut queue, outcome.tasks, Asked::ByScan),
                    None => tracing::warn!(
                        "private mirror: a repair scan did not finish; the next tick scans again"
                    ),
                }
            }
            finished = done_rx.recv() => {
                if let Some(finished) = finished {
                    settle(&retry, &mut queue, settings.retry, finished);
                }
            }
            _ = tokio::time::sleep(budget_wait.unwrap_or_default()), if budget_wait.is_some() => {}
        }
    }
}

/// The mirror's one HTTP client. It lives as long as the worker, so a
/// connection to the peer is kept and used again.
///
/// - Its resolver vets every answer and the connection goes to the
///   addresses it vetted ([`VettedResolver`]).
/// - It uses no proxy from the environment: the connection would go to the
///   proxy, which looks the peer's name up again by itself.
/// - It follows no redirect: a peer must not send a fetch on to another
///   host.
/// - It has no total timeout: a fetch sets its own limits, which depend on
///   the blob's length (`fetch_from_peer`). `connect_timeout` bounds the
///   lookup and the connection together.
fn http_client(
    connect_timeout: Duration,
    resolver: VettedResolver,
) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(resolver)
        .build()
}

/// Spawn the mirror worker. Called once from `RelayServer::start` when
/// private repos AND mirroring are enabled.
pub(crate) fn spawn(svc: Arc<PrivateService>) -> JoinHandle<()> {
    let (tx, rx) = unbounded_channel::<MirrorJob>();
    let _ = svc.mirror_tx.set(tx);

    let in_test = std::env::var("NGIT_TEST").as_deref() == Ok("1");
    let fetch_timeout = Duration::from_secs(svc.cfg.mirror_fetch_timeout_secs.max(1));
    let max_concurrency = svc.cfg.mirror_max_concurrency.max(1) as usize;
    // The backoff base and the repair interval are clamped to 1 s under
    // NGIT_TEST; the backoff cap stays as configured.
    let retry_base = Duration::from_secs(svc.cfg.mirror_retry_base_secs.max(1));
    let retry_base = if in_test {
        retry_base.min(Duration::from_secs(1))
    } else {
        retry_base
    };
    let retry_max = Duration::from_secs(
        svc.cfg
            .mirror_retry_max_secs
            .max(svc.cfg.mirror_retry_base_secs.max(1)),
    );
    let repair_interval = if in_test {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(60)
    };
    let settings = WorkerSettings {
        max_concurrency,
        attempts_per_min: svc.cfg.mirror_max_attempts_per_min,
        retry: RetryPolicy {
            base: retry_base,
            max: retry_max,
        },
        repair_interval,
    };

    let resolver = VettedResolver::system(svc.cfg.mirror_allow_private_ips);
    tokio::spawn(async move {
        let client = match http_client(fetch_timeout, resolver) {
            Ok(client) => client,
            Err(e) => {
                tracing::error!("private mirror: failed to build HTTP client: {e}");
                return;
            }
        };
        // Per-blob retry gates, shared with `enqueue_for_state_root` and
        // the scan through the service.
        let retry = svc.mirror_retry.clone();

        tracing::info!(
            blob_peers = peer_servers_for(&svc).len(),
            max_concurrency = max_concurrency,
            max_concurrency_per_account = account_share(max_concurrency),
            max_attempts_per_min = settings.attempts_per_min,
            fetch_timeout_secs = fetch_timeout.as_secs(),
            repair_interval_secs = repair_interval.as_secs(),
            retry_base_secs = retry_base.as_secs(),
            retry_max_secs = retry_max.as_secs(),
            "private blob mirror worker started"
        );

        let backend = Arc::new(LiveBackend {
            svc,
            client,
            fetch_timeout,
        });
        run_worker(backend, rx, retry, settings).await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The reasons a fetch can fail with, one of each label.
    const BACKOFF_REASONS: [&str; 13] = [
        "no_peer",
        "network: connection refused",
        UNRESOLVED_REASON,
        "http_status: 500",
        "http_status: 502",
        // Unusual statuses are taken for a proxy's or an edge's oddity.
        "http_status: 403",
        "quota",
        "reserve: cap reached",
        "sink: io error",
        "write: io error",
        "store: forbidden",
        "lost",
        "anything-else",
    ];
    const AT_MAX_REASONS: [&str; 5] = [
        "http_status: 404",
        "blocked",
        "verify: size mismatch",
        "verify: sha256 mismatch",
        "too_large",
    ];

    fn policy() -> RetryPolicy {
        RetryPolicy {
            base: Duration::from_secs(60),
            max: Duration::from_secs(3600),
        }
    }

    /// Every reason has one of two schedules, and the schedule is what the
    /// table in the module documentation says.
    #[test]
    fn retry_class_taxonomy() {
        let now = Instant::now();
        let sha = "ab".repeat(32);

        for reason in BACKOFF_REASONS {
            assert_eq!(classify_failure(reason), RetryClass::Backoff, "{reason}");
            // Without jitter: the base after the first failure, twice the
            // base after the second.
            let mut retry: HashMap<String, RetryState> = HashMap::new();
            record_mirror_failure(&mut retry, &sha, reason, policy(), now, 1.0);
            assert_eq!(
                retry[&sha].next_eligible,
                now + Duration::from_secs(60),
                "{reason}"
            );
            record_mirror_failure(&mut retry, &sha, reason, policy(), now, 1.0);
            assert_eq!(
                retry[&sha].next_eligible,
                now + Duration::from_secs(120),
                "{reason}"
            );
        }

        for reason in AT_MAX_REASONS {
            assert_eq!(classify_failure(reason), RetryClass::AtMax, "{reason}");
            // The maximum interval from the first failure on.
            let mut retry: HashMap<String, RetryState> = HashMap::new();
            record_mirror_failure(&mut retry, &sha, reason, policy(), now, 1.0);
            assert_eq!(
                retry[&sha].next_eligible,
                now + Duration::from_secs(3600),
                "{reason}"
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
        // u32::MAX attempts (what the AtMax class passes) is always the cap.
        assert_eq!(retry_delay(u32::MAX, base, max, 1.0), max);
        // A base and a cap no clock can hold are used as they are; nothing
        // panics.
        let never = Duration::from_secs(u64::MAX);
        assert_eq!(retry_delay(u32::MAX, never, never, 1.2), never);
        let mut retry: HashMap<String, RetryState> = HashMap::new();
        let now = Instant::now();
        let endless = RetryPolicy {
            base: never,
            max: never,
        };
        record_mirror_failure(&mut retry, "sha", "too_large", endless, now, 1.2);
        assert!(retry_gated(
            &retry,
            "sha",
            now + Duration::from_secs(30 * 24 * 3600)
        ));

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

    /// No reason leaves a blob ungated. A class without a gate is fetched
    /// again by every repair scan, for ever.
    #[test]
    fn retry_gate_never_leaves_a_failure_ungated() {
        let now = Instant::now();
        let sha = "ab".repeat(32);

        for reason in BACKOFF_REASONS.iter().chain(AT_MAX_REASONS.iter()) {
            let mut retry: HashMap<String, RetryState> = HashMap::new();
            assert!(!retry_gated(&retry, &sha, now));

            // The shortest delay any class can get: the base less 20%.
            record_mirror_failure(&mut retry, &sha, reason, policy(), now, 0.8);
            assert!(retry_gated(&retry, &sha, now), "{reason} must gate");
            assert!(
                retry_gated(&retry, &sha, now + Duration::from_secs(47)),
                "{reason} must stay gated for the base interval less its jitter"
            );
            // The gate opens: no class waits longer than the maximum plus
            // its jitter, so no blob is given up on.
            assert!(
                !retry_gated(&retry, &sha, now + Duration::from_secs(3600)),
                "{reason} must be retried"
            );

            // Success clears the gate.
            record_mirror_success(&mut retry, &sha);
            assert!(!retry_gated(&retry, &sha, now));
            assert!(!retry.contains_key(&sha));
        }

        // A later failure of another class never opens a gate: the blob
        // stays gated whatever follows what.
        let mut retry: HashMap<String, RetryState> = HashMap::new();
        record_mirror_failure(&mut retry, &sha, "network: refused", policy(), now, 1.0);
        record_mirror_failure(&mut retry, &sha, "too_large", policy(), now, 1.0);
        assert!(retry_gated(&retry, &sha, now));
        record_mirror_failure(&mut retry, &sha, "quota", policy(), now, 1.0);
        assert!(retry_gated(&retry, &sha, now));
        // Attempts count across classes, so the backoff keeps growing.
        assert_eq!(retry[&sha].attempts, 3);
        assert_eq!(
            retry[&sha].next_eligible,
            now + Duration::from_secs(240),
            "third failure: four times the base"
        );
    }

    /// The scan forgets the gates of blobs that are no longer missing and
    /// reports which of the others are still shut.
    #[test]
    fn scan_prunes_gates_and_reports_the_shut_ones() {
        let now = Instant::now();
        let mut retry: HashMap<String, RetryState> = HashMap::new();
        record_mirror_failure(&mut retry, "arrived", "network: x", policy(), now, 1.0);
        record_mirror_failure(&mut retry, "shut", "http_status: 404", policy(), now, 1.0);
        record_mirror_failure(&mut retry, "open", "network: x", policy(), now, 1.0);

        // "arrived" is no longer missing; 61 s on, the 60 s gate of "open"
        // has opened and the hour-long gate of "shut" has not.
        let later = now + Duration::from_secs(61);
        let missing = HashSet::from(["shut", "open", "new"]);
        let gated = prune_gates(&mut retry, &missing, later);
        assert_eq!(gated, HashSet::from(["shut".to_string()]));
        assert!(!retry.contains_key("arrived"), "its gate is forgotten");
        // An opened gate keeps its failure count: the next failure backs
        // off further.
        assert_eq!(retry["open"].attempts, 1);
    }

    fn reasons(list: &[&str]) -> Vec<String> {
        list.iter().map(|reason| reason.to_string()).collect()
    }

    /// The reason recorded for a blob does not depend on the order in
    /// which its peers were tried, and one peer's 404 does not park a blob
    /// that another peer failed to serve for a passing reason.
    #[test]
    fn merged_failure_prefers_the_soonest_retry() {
        assert_eq!(
            merge_peer_failures(&reasons(&["network: refused", "http_status: 404"])),
            Some("network: refused")
        );
        assert_eq!(
            merge_peer_failures(&reasons(&["http_status: 404", "network: refused"])),
            Some("network: refused")
        );
        // Two reasons of one class: the same one either way round.
        let one_way = reasons(&["http_status: 404", "blocked"]);
        let other_way = reasons(&["blocked", "http_status: 404"]);
        assert_eq!(merge_peer_failures(&one_way), Some("blocked"));
        assert_eq!(merge_peer_failures(&other_way), Some("blocked"));
        let one_way = reasons(&["http_status: 500", "network: refused"]);
        let other_way = reasons(&["network: refused", "http_status: 500"]);
        assert_eq!(
            merge_peer_failures(&one_way),
            merge_peer_failures(&other_way)
        );

        // A failure from this node's own state is the answer, whatever the
        // peers before it said.
        assert_eq!(
            merge_peer_failures(&reasons(&["network: refused", "quota"])),
            Some("quota")
        );
        assert_eq!(
            merge_peer_failures(&reasons(&["http_status: 404", "store: registration gone"])),
            Some("store: registration gone")
        );
        for local in ["quota", "reserve: x", "sink: x", "write: x", "store: x"] {
            assert!(stops_peer_loop(local), "{local} must end the peer loop");
        }
        for remote in [
            "network: x",
            "http_status: 404",
            "http_status: 500",
            "blocked",
            "verify: x",
            "too_large",
        ] {
            assert!(!stops_peer_loop(remote), "{remote} must try the next peer");
        }

        assert_eq!(merge_peer_failures(&[]), None);
    }

    /// The length a fetch reads: every peer is the operator's, and its
    /// announced length is believed up to the maximum blob size, whatever
    /// the state root declared; no announcement leaves the declared size.
    #[test]
    fn expected_len_believes_the_peer_up_to_the_maximum() {
        const MAX: u64 = 1000;

        // The announced length wins, equal, smaller or larger. No length is
        // refused for differing from the declared one any more: the replica
        // stores what the origin stores.
        for announced in [500, 700, 300, 0, 499, 501, MAX] {
            assert_eq!(
                expected_len(Some(announced), 500, MAX),
                Ok(announced),
                "{announced}"
            );
        }
        assert_eq!(
            expected_len(Some(MAX + 1), 500, MAX),
            Err("too_large".to_string())
        );

        // No announced length: the declared size bounds the read.
        assert_eq!(expected_len(None, 500, MAX), Ok(500));
        assert_eq!(
            expected_len(None, MAX + 1, MAX),
            Err("too_large".to_string())
        );
        assert_eq!(classify_failure("too_large"), RetryClass::AtMax);
    }

    /// The peers are the operator's list as base URLs, each once, never
    /// this node, in the order written. Nothing else adds one.
    #[test]
    fn peer_servers_are_the_list_less_this_node() {
        let entries =
            |list: &[&str]| -> Vec<String> { list.iter().map(|entry| entry.to_string()).collect() };
        let own = "127.0.0.1:1111";
        assert_eq!(
            configured_peer_servers(
                &entries(&[
                    "http://127.0.0.1:1111",
                    "http://127.0.0.1:2222/",
                    "peer.example",
                    "http://127.0.0.1:2222",
                    "127.0.0.1:1111",
                ]),
                own
            ),
            vec![
                "http://127.0.0.1:2222".to_string(),
                "https://peer.example".to_string()
            ]
        );
        // A list that names only this node, and no list, give no peer.
        assert!(configured_peer_servers(&entries(&["http://127.0.0.1:1111/"]), own).is_empty());
        assert!(configured_peer_servers(&[], own).is_empty());

        // Under a mount path the node is its host and its path: the bare
        // host is another service, and a peer.
        assert_eq!(
            configured_peer_servers(
                &entries(&["https://h.example/grasp", "https://h.example"]),
                "h.example/grasp"
            ),
            vec!["https://h.example".to_string()]
        );
    }

    /// A registration's `server` tags never choose a host to fetch from, on
    /// either path a job comes by. The repair scan of a node with no list
    /// finds the missing blob and gives it no peer, although the
    /// registration names one, and so does the job a state root enqueues;
    /// with a list the peers are the list's alone.
    #[tokio::test]
    async fn server_tags_never_name_a_blob_peer() {
        async fn scanned_peers(list: Option<&str>) -> Vec<String> {
            use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

            let dir = tempfile::tempdir().expect("tempdir");
            let mut config = crate::config::Config::for_testing();
            config.private_repos_enable = true;
            config.domain = "own.example".to_string();
            config.private_mirror_peer_urls = list.map(str::to_string);
            config.private_meta_data_path =
                Some(dir.path().join("meta").to_string_lossy().into_owned());
            config.private_blob_data_path =
                Some(dir.path().join("blobs").to_string_lossy().into_owned());
            let database: crate::nostr::SharedDatabase =
                Arc::new(nostr_memory::MemoryDatabase::unbounded());
            let svc = PrivateService::new(&config, database)
                .await
                .expect("private service");

            let alias = "ab".repeat(16);
            let sha = "cd".repeat(32);
            let record = crate::grasp_p::meta::RegistrationRecord {
                tenant_hex: "ef".repeat(32),
                event_id: "01".repeat(32),
                created_at: 1,
                w_keys: Vec::new(),
                aux_keys: Vec::new(),
                relays: vec!["wss://own.example".to_string()],
                servers: vec![
                    "https://own.example".to_string(),
                    "https://tagged.example".to_string(),
                ],
                quota_class: None,
                registered_at: 1,
                tombstoned_at: None,
                first_created_at: None,
                first_event_id: None,
            };
            let claim = crate::grasp_p::meta::BlobClaim {
                size: 100,
                aliases: vec![alias.clone()],
                unreferenced_since: None,
                stored: false,
                charges: vec![crate::grasp_p::meta::ClaimCharge {
                    tenant: record.tenant_hex.clone(),
                    alias: alias.clone(),
                    bytes: 100,
                }],
                stored_at: None,
            };
            svc.meta
                .with_write(|meta, txn| {
                    meta.put_registration(txn, &alias, &record)?;
                    meta.put_blob_claim(txn, &sha, &claim)
                })
                .expect("seed the registration and the claim");

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            assert!(svc.mirror_tx.set(tx).is_ok(), "the job channel is set once");

            let outcome = scan_missing(&svc, clock_now()).expect("the claim table reads");
            assert_eq!(outcome.lag, 1);
            assert_eq!(outcome.tasks.len(), 1, "the missing blob is derived");
            let peers = outcome.tasks[0].route.peer_servers.clone();
            assert_eq!(
                peers,
                peer_servers_for(&svc),
                "the scan's peers are the node's peers"
            );

            // A state root for the same alias, as an accepted 30641 enqueues
            // it.
            let state_root = EventBuilder::new(Kind::Custom(crate::grasp_p::KIND_STATE_ROOT), "")
                .tags([
                    Tag::custom("d", vec![alias.clone()]),
                    Tag::custom("m", vec![sha.clone(), "100".to_string()]),
                ])
                .finalize(&Keys::generate())
                .expect("sign");
            enqueue_for_state_root(&svc, &state_root);
            let job = rx.try_recv().expect("one job for the missing blob");
            assert_eq!(
                job.peer_servers, peers,
                "the enqueue path has the scan's peers"
            );
            peers
        }

        assert!(
            scanned_peers(None).await.is_empty(),
            "with no list there is no peer, whatever the registration names"
        );
        assert_eq!(
            scanned_peers(Some("https://own.example, https://peer.example/")).await,
            vec!["https://peer.example".to_string()]
        );
    }

    /// The repair scan fetches a blob at the size the repository it fetches
    /// for declared, not at the size the claim was first declared with: a
    /// first declarer must not set what another account's fetch reads.
    #[tokio::test]
    async fn the_scan_fetches_at_the_chosen_repositorys_own_size() {
        use crate::grasp_p::meta::{BlobClaim, ClaimCharge, RegistrationRecord};

        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::config::Config::for_testing();
        config.private_repos_enable = true;
        config.private_meta_data_path =
            Some(dir.path().join("meta").to_string_lossy().into_owned());
        config.private_blob_data_path =
            Some(dir.path().join("blobs").to_string_lossy().into_owned());
        let database: crate::nostr::SharedDatabase =
            Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let svc = PrivateService::new(&config, database)
            .await
            .expect("private service");

        let record = |tenant: &str| RegistrationRecord {
            tenant_hex: tenant.to_string(),
            event_id: "01".repeat(32),
            created_at: 1,
            w_keys: Vec::new(),
            aux_keys: Vec::new(),
            relays: Vec::new(),
            servers: Vec::new(),
            quota_class: None,
            registered_at: 1,
            tombstoned_at: None,
            first_created_at: None,
            first_event_id: None,
        };
        let charge = |tenant: &str, alias: &str, bytes: u64| ClaimCharge {
            tenant: tenant.to_string(),
            alias: alias.to_string(),
            bytes,
        };
        let (tenant_a, tenant_b) = ("0a".repeat(32), "0b".repeat(32));
        let (alias_a, alias_b) = ("aa".repeat(16), "bb".repeat(16));
        let sha = "cd".repeat(32);
        // B declared first, at 900; A declared 100.
        let claim = BlobClaim {
            size: 900,
            aliases: vec![alias_b.clone(), alias_a.clone()],
            unreferenced_since: None,
            stored: false,
            charges: vec![
                charge(&tenant_b, &alias_b, 900),
                charge(&tenant_a, &alias_a, 100),
            ],
            stored_at: None,
        };
        svc.meta
            .with_write(|meta, txn| {
                meta.put_registration(txn, &alias_a, &record(&tenant_a))?;
                meta.put_registration(txn, &alias_b, &record(&tenant_b))?;
                meta.put_blob_claim(txn, &sha, &claim)
            })
            .expect("seed the registrations and the claim");

        let outcome = scan_missing(&svc, clock_now()).expect("the claim table reads");
        assert_eq!(outcome.tasks.len(), 1);
        let task = &outcome.tasks[0];
        assert_eq!(
            task.route.alias, alias_a,
            "equal backlogs: the account that sorts first"
        );
        assert_eq!(task.blob.size, 100, "A's own declared size");
        assert_eq!(task.fallbacks.len(), 1);
    }

    #[test]
    fn fetch_deadline_grows_with_size() {
        let base = Duration::from_secs(120);
        assert_eq!(fetch_deadline(base, 0), base);
        assert_eq!(fetch_deadline(base, MIN_FETCH_BYTES_PER_SEC - 1), base);
        assert_eq!(
            fetch_deadline(base, MIN_FETCH_BYTES_PER_SEC),
            Duration::from_secs(121)
        );
        // A blob of the default maximum size (256 MiB) at 256 KiB/s.
        assert_eq!(
            fetch_deadline(base, 256 * 1024 * 1024),
            Duration::from_secs(120 + 1024)
        );
        // No length and no timeout can overflow it.
        assert!(fetch_deadline(Duration::MAX, u64::MAX) >= base);
    }

    fn claimant(account: &str, alias: &str) -> Claimant {
        Claimant {
            account: account.to_string(),
            alias: alias.to_string(),
        }
    }

    /// A blob that two accounts claim waits in the shorter queue, and the
    /// other account is kept as a fallback.
    #[test]
    fn claimant_choice_prefers_the_least_lagging_tenant() {
        let lag: HashMap<String, u64> = [("flood".to_string(), 5000), ("small".to_string(), 1)]
            .into_iter()
            .collect();

        let flood_first = [claimant("flood", "f-repo"), claimant("small", "s-repo")];
        assert_eq!(rank_claimants(&flood_first, &lag), vec![1, 0]);
        let small_first = [claimant("small", "s-repo"), claimant("flood", "f-repo")];
        assert_eq!(rank_claimants(&small_first, &lag), vec![0, 1]);

        // Equal lag: the account, then the alias, that sorts first, so the
        // order of the claims does not matter.
        let even: HashMap<String, u64> = HashMap::new();
        let pair = [claimant("bb", "x"), claimant("aa", "y")];
        assert_eq!(rank_claimants(&pair, &even), vec![1, 0]);
        // One alias per account: a second alias of the same account would
        // meet the same ledgers.
        let same_account = [claimant("aa", "repo-2"), claimant("aa", "repo-1")];
        assert_eq!(rank_claimants(&same_account, &even), vec![1]);

        // Within an account, the alias that sorts first, whatever the
        // order of the claims: every alias pays its own charge.
        let shared = [
            claimant("aa", "repo-2"),
            claimant("aa", "repo-1"),
            claimant("bb", "repo-3"),
        ];
        assert_eq!(rank_claimants(&shared, &even), vec![1, 2]);
        // A longer queue still loses.
        let lagging: HashMap<String, u64> = [("aa".to_string(), 9)].into_iter().collect();
        assert_eq!(rank_claimants(&shared, &lagging), vec![2, 1]);

        // No more accounts than a fetch may try.
        let many: Vec<Claimant> = (0..10)
            .map(|i| claimant(&format!("account{i}"), "repo"))
            .collect();
        assert_eq!(rank_claimants(&many, &even), vec![0, 1, 2, 3]);
        assert_eq!(MAX_ROUTES_PER_BLOB, 4);

        assert!(rank_claimants(&[], &lag).is_empty());
    }

    // ---- the fair queue ----------------------------------------------------

    fn pop_account(queue: &mut FairQueue<u32>) -> Option<String> {
        queue.pop().map(|popped| popped.account)
    }

    /// A hundred blobs of one account do not stand in front of another
    /// account's one.
    #[test]
    fn fair_queue_round_robins_between_tenants() {
        let mut queue: FairQueue<u32> = FairQueue::new(100, 1024);
        for i in 0..100 {
            assert_eq!(queue.push("a", &format!("a{i}"), i), Pushed::Queued);
        }
        assert_eq!(queue.push("b", "b0", 0), Pushed::Queued);

        assert_eq!(pop_account(&mut queue).as_deref(), Some("a"));
        assert_eq!(pop_account(&mut queue).as_deref(), Some("b"));
        assert_eq!(pop_account(&mut queue).as_deref(), Some("a"));
        // Within one account, first in is first out.
        let mut queue: FairQueue<u32> = FairQueue::new(100, 1024);
        for i in 0..3 {
            queue.push("a", &format!("a{i}"), i);
        }
        let order: Vec<u32> =
            std::iter::from_fn(|| queue.pop().map(|popped| popped.item)).collect();
        assert_eq!(order, vec![0, 1, 2]);
    }

    /// An account at its share gets nothing more until one of its blobs is
    /// given back; other accounts are served meanwhile.
    #[test]
    fn fair_queue_caps_a_tenant_at_its_share() {
        let mut queue: FairQueue<u32> = FairQueue::new(2, 1024);
        for i in 0..5 {
            queue.push("a", &format!("a{i}"), i);
        }
        let first = queue.pop().expect("a's first");
        let second = queue.pop().expect("a's second");
        assert_eq!(
            (first.account.as_str(), second.account.as_str()),
            ("a", "a")
        );
        assert_eq!(queue.running(), 2);
        assert!(queue.pop().is_none(), "a is at its share");
        assert!(!queue.has_runnable());

        // Another account is not held back by a's cap.
        queue.push("b", "b0", 0);
        assert!(queue.has_runnable());
        assert_eq!(pop_account(&mut queue).as_deref(), Some("b"));
        assert_eq!(queue.running(), 3);
        assert!(queue.pop().is_none());

        // Giving one back frees one place, no more.
        queue.finish(&first.account, &first.sha);
        assert_eq!(queue.running(), 2);
        assert!(queue.has_runnable());
        assert_eq!(pop_account(&mut queue).as_deref(), Some("a"));
        assert!(queue.pop().is_none());

        // The share is never below one.
        assert_eq!(account_share(1), 1);
        assert_eq!(account_share(2), 1);
        assert_eq!(account_share(4), 2);
        assert_eq!(account_share(9), 4);
    }

    /// A blob is queued or running once, whoever asks for it, and can be
    /// queued again once it has been given back.
    #[test]
    fn fair_queue_dedups_a_blob_queued_or_running() {
        let mut queue: FairQueue<u32> = FairQueue::new(2, 1024);
        assert_eq!(queue.push("a", "sha", 1), Pushed::Queued);
        // The same blob from the repair scan, and from another account.
        assert_eq!(queue.push("a", "sha", 2), Pushed::Duplicate);
        assert_eq!(queue.push("b", "sha", 3), Pushed::Duplicate);
        assert_eq!(queue.waiting(), 1);

        // Still known while it runs.
        let running = queue.pop().expect("the blob");
        assert_eq!(running.item, 1);
        assert_eq!(queue.push("b", "sha", 4), Pushed::Duplicate);
        assert!(queue.pop().is_none());

        queue.finish(&running.account, &running.sha);
        assert_eq!(queue.running(), 0);
        assert_eq!(queue.push("b", "sha", 5), Pushed::Queued);
        assert_eq!(pop_account(&mut queue).as_deref(), Some("b"));
    }

    /// The repair scan's choice of account replaces an event's while the
    /// blob waits: a blob queued behind one account's long backlog moves to
    /// the account it should be fetched for.
    #[test]
    fn fair_queue_moves_a_waiting_blob_to_the_scans_account() {
        let mut queue: FairQueue<u32> = FairQueue::new(2, 1024);
        for i in 0..100 {
            queue.push("a", &format!("a{i}"), i);
        }
        assert_eq!(queue.push("a", "shared", 1), Pushed::Queued);
        assert_eq!(queue.push("b", "shared", 2), Pushed::Duplicate);

        assert_eq!(queue.push_or_move("b", "shared", 3), Pushed::Queued);
        assert_eq!(queue.waiting(), 101, "moved, not queued twice");
        // Asked again for the account it waits for: nothing to do.
        assert_eq!(queue.push_or_move("b", "shared", 4), Pushed::Duplicate);

        let first = queue.pop().expect("a's first");
        assert_eq!(first.account, "a");
        let second = queue.pop().expect("the moved blob");
        assert_eq!(
            (second.account.as_str(), second.sha.as_str(), second.item),
            ("b", "shared", 3)
        );
        // A running blob stays where it runs.
        assert_eq!(queue.push_or_move("a", "shared", 5), Pushed::Duplicate);
        queue.finish(&second.account, &second.sha);
        assert_eq!(queue.running_for("b"), 0);

        // Moving the only waiting blob of an account takes the account out
        // of the turn order: nothing is handed out for it afterwards.
        let mut queue: FairQueue<u32> = FairQueue::new(2, 1024);
        queue.push("a", "only", 1);
        assert_eq!(queue.push_or_move("b", "only", 2), Pushed::Queued);
        assert_eq!(pop_account(&mut queue).as_deref(), Some("b"));
        assert!(queue.pop().is_none());
        assert_eq!(queue.waiting(), 0);
        assert_eq!(queue.push("a", "next", 3), Pushed::Queued);
        assert_eq!(pop_account(&mut queue).as_deref(), Some("a"));

        // No room in the account it should move to: it keeps its place.
        let mut queue: FairQueue<u32> = FairQueue::new(2, 1);
        queue.push("a", "stays", 1);
        queue.push("b", "other", 2);
        assert_eq!(queue.push_or_move("b", "stays", 3), Pushed::Duplicate);
        assert_eq!(pop_account(&mut queue).as_deref(), Some("a"));

        // A blob nobody has queued is queued as by `push`.
        let mut queue: FairQueue<u32> = FairQueue::new(2, 1);
        assert_eq!(queue.push_or_move("a", "new", 1), Pushed::Queued);
        assert_eq!(queue.push_or_move("a", "more", 2), Pushed::BacklogFull);
    }

    /// One account cannot fill memory: its backlog stops at the cap, and
    /// the rest is left to the next repair scan.
    #[test]
    fn fair_queue_bounds_a_tenants_backlog() {
        let mut queue: FairQueue<u32> = FairQueue::new(2, ACCOUNT_BACKLOG_CAP);
        let mut refused = 0;
        for i in 0..5000 {
            if queue.push("a", &format!("a{i}"), i) == Pushed::BacklogFull {
                refused += 1;
            }
        }
        assert_eq!(queue.waiting(), ACCOUNT_BACKLOG_CAP);
        assert_eq!(refused, 5000 - ACCOUNT_BACKLOG_CAP);

        // Another account's backlog is its own.
        assert_eq!(queue.push("b", "b0", 0), Pushed::Queued);

        // A refused blob was not remembered: it fits once there is room.
        assert_eq!(pop_account(&mut queue).as_deref(), Some("a"));
        assert_eq!(queue.push("a", "a4999", 4999), Pushed::Queued);
        assert_eq!(queue.push("a", "a4998", 4998), Pushed::BacklogFull);
    }

    // ---- the attempt budget ------------------------------------------------

    /// A burst of one minute's worth, then the configured rate; 0 is no
    /// limit.
    #[test]
    fn attempt_budget_limits_and_refills() {
        let t0 = Instant::now();
        let mut budget = AttemptBudget::new(60, t0);

        let burst = (0..200).filter(|_| budget.try_take(t0)).count();
        assert_eq!(burst, 60, "the burst is one minute's worth");
        assert!(!budget.try_take(t0));
        // The wait is to the next token, and a token is there after it.
        let wait = budget.wait(t0).expect("an empty budget has a wait");
        assert_eq!(wait, Duration::from_secs(1));
        assert!(budget.wait(t0 + wait).is_none());

        // 60 a minute is one a second: ten seconds on, ten more.
        let later = t0 + Duration::from_secs(10);
        let refilled = (0..200).filter(|_| budget.try_take(later)).count();
        assert_eq!(refilled, 10, "the sustained rate is the configured one");

        // A long quiet spell refills to the burst and no further.
        let much_later = later + Duration::from_secs(3600);
        let after_idle = (0..200).filter(|_| budget.try_take(much_later)).count();
        assert_eq!(after_idle, 60);

        // A clock that reads earlier than before takes nothing away and
        // does not panic.
        assert!(!budget.try_take(t0));

        let mut unlimited = AttemptBudget::new(0, t0);
        assert!((0..10_000).all(|_| unlimited.try_take(t0)));
        assert!(unlimited.wait(t0).is_none());
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
            dedup.should_log_at(
                "sha1",
                "network: refused",
                t0 + ttl + Duration::from_secs(1)
            ),
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
        assert!(is_disallowed_ip(&IpAddr::V6(
            "::ffff:127.0.0.1".parse().unwrap()
        )));
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
        assert_eq!(
            embedded_ipv4(&compat),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert!(is_disallowed_ip(&IpAddr::V6(compat)));

        // A transition form wrapping a *public* v4 stays allowed.
        let public_6to4: Ipv6Addr = "2002:808:808::".parse().unwrap();
        assert_eq!(embedded_ipv4(&public_6to4), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_disallowed_ip(&IpAddr::V6(public_6to4)));
    }

    /// Upstream's policy passes a NAT64 or 6to4 address whatever it wraps;
    /// the check of a GRASP-P node's relay dial refuses the ones that wrap an
    /// address upstream would refuse bare, the local-use NAT64 prefix, and
    /// IPv6 space public hosts are not numbered from, and passes the public
    /// addresses.
    #[tokio::test]
    async fn relay_dial_check_refuses_wrapped_internal_addresses() {
        use crate::outbound::{OutboundTargetKind, OutboundTargetPolicy};

        // IP literals are vetted without a lookup, so nothing leaves the host.
        async fn vetted(
            policy: OutboundTargetPolicy,
            url: &str,
        ) -> crate::outbound::ResolvedTarget {
            policy
                .authorize_resolved(OutboundTargetKind::EventRelay, url)
                .await
                .unwrap_or_else(|reason| panic!("upstream's policy passes {url}: {reason}"))
        }
        let strict = OutboundTargetPolicy::default();

        for wrapped in [
            // NAT64 around the cloud metadata address, and around 10.0.0.5.
            "wss://[64:ff9b::a9fe:a9fe]:7777",
            "wss://[64:ff9b::a00:5]",
            // 6to4 around 10.0.0.5, and around loopback.
            "wss://[2002:a00:5::1]:7777",
            "wss://[2002:7f00:1::]",
            // Ranges only upstream's list knows: NAT64 around 198.18.0.1
            // (benchmarking) and 6to4 around 240.0.0.1 (reserved).
            "wss://[64:ff9b::c612:1]",
            "wss://[2002:f000:1::1]",
            // The local-use NAT64 prefix, whatever it carries.
            "wss://[64:ff9b:1::a00:5]",
            // IPv6 space public hosts are not numbered from: Teredo and the
            // rest of 2001::/23, SIIT, SRv6, and the space past 2000::/3.
            "wss://[2001:0:4136:e378:8000:63bf:3fff:fdd2]",
            "wss://[2001::1]",
            "wss://[2001:1ff:ffff::1]",
            "wss://[::ffff:0:a00:5]",
            "wss://[::ffff:0:808:808]",
            "wss://[5f00::1]",
            "wss://[4000::1]",
        ] {
            let target = vetted(strict, wrapped).await;
            assert_eq!(target.addresses.len(), 1, "{wrapped}");
            let refusal = vet_relay_dial(true, target.clone())
                .expect_err("a GRASP-P node must not dial a wrapped internal address");
            assert!(refusal.contains("not globally reachable"), "{refusal}");
            // Any other node keeps upstream's verdict.
            assert!(vet_relay_dial(false, target).is_ok(), "{wrapped}");
        }

        for public in [
            "wss://8.8.8.8",
            "wss://[2606:4700:4700::1111]",
            // The same two forms around a public address, and an IPv4-mapped
            // one: judged by what they carry, as before.
            "wss://[64:ff9b::808:808]",
            "wss://[2002:808:808::1]",
            "wss://[::ffff:8.8.8.8]",
            // 2001::/16 past the protocol assignments.
            "wss://[2001:200::1]",
            "wss://[2001:4860:4860::8888]",
        ] {
            let target = vetted(strict, public).await;
            let passed = vet_relay_dial(true, target.clone()).expect("a public address passes");
            assert_eq!(passed.addresses, target.addresses, "{public}");
        }

        // A permissive policy vets no address, so there is nothing to refuse:
        // the operator has said this target may be internal.
        let permissive = OutboundTargetPolicy {
            allow_non_global: true,
        };
        let target = vetted(permissive, "ws://[64:ff9b::a9fe:a9fe]:7777").await;
        assert!(target.addresses.is_empty());
        assert!(vet_relay_dial(true, target).is_ok());
    }

    /// The IPv6 rule of [`wraps_non_global`] alone: outside 2000::/3, or
    /// inside 2001::/23, is refused; IPv4-mapped and NAT64 addresses are
    /// judged by what they carry, as before; and so is 6to4, inside the
    /// block.
    #[test]
    fn ipv6_outside_the_global_unicast_block_is_refused() {
        let ip = |text: &str| -> IpAddr { text.parse().expect("an address") };

        for refused in [
            // Teredo, at the start of 2001::/23, and the block's last /32.
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001::1",
            "2001:1ff:ffff:ffff::1",
            // SIIT, around an internal and around a public IPv4 address.
            "::ffff:0:a00:5",
            "::ffff:0:808:808",
            // SRv6, and the rest of the space past 2000::/3.
            "5f00::1",
            "4000::1",
            "e000::1",
            // Just below 2000::/3.
            "1fff:ffff:ffff::1",
            // The local-use NAT64 prefix, around a public address too.
            "64:ff9b:1::a00:5",
            "64:ff9b:1::808:808",
            // NAT64 and IPv4-mapped forms around what upstream refuses.
            "64:ff9b::a00:5",
            "64:ff9b::c612:1",
            "::ffff:10.0.0.5",
            "::ffff:198.18.0.1",
        ] {
            assert!(wraps_non_global(&ip(refused)), "{refused} must be refused");
        }

        for passed in [
            "2606:4700:4700::1111",
            // The upper half of 2000::/3, which a narrower mask would refuse.
            "3000::1",
            // 2001::/16 past the protocol assignments.
            "2001:200::1",
            "2001:4860:4860::8888",
            // The translation forms around a public address.
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            // IPv4 is not touched by the IPv6 rule.
            "8.8.8.8",
        ] {
            assert!(!wraps_non_global(&ip(passed)), "{passed} must pass");
        }
    }

    #[test]
    fn public_ip_allowed() {
        assert!(!is_disallowed_ip(&IpAddr::V4("8.8.8.8".parse().unwrap())));
        assert!(!is_disallowed_ip(&IpAddr::V4(
            "93.184.216.34".parse().unwrap()
        )));
        assert!(!is_disallowed_ip(&IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
    }

    #[tokio::test]
    async fn peer_allowed_blocks_internal_and_http() {
        use PeerVerdict::{Allowed, Refused};

        // allow_private short-circuits (tests / loopback pairs).
        assert_eq!(peer_allowed("http://127.0.0.1:9999", true).await, Allowed);
        // Plaintext http rejected in production mode.
        assert_eq!(peer_allowed("http://example.com", false).await, Refused);
        // Literal internal IP rejected.
        assert_eq!(
            peer_allowed("https://169.254.169.254", false).await,
            Refused
        );
        assert_eq!(peer_allowed("https://127.0.0.1:8080", false).await, Refused);
        assert_eq!(peer_allowed("https://10.0.0.5", false).await, Refused);
        // A name under a local-use suffix is refused without a lookup.
        assert_eq!(
            peer_allowed("https://nonexistent.invalid", false).await,
            Refused
        );
    }

    /// A host that is an IP literal never reaches the client's resolver, so
    /// the early check is all that stands between it and a connection. It
    /// refuses the literals each list knows: a NAT64 and a 6to4 form that
    /// upstream's list passes, addresses that upstream's list refuses, the
    /// same forms around addresses only upstream's list knows, the
    /// local-use NAT64 prefix, and IPv6 space outside 2000::/3 or inside
    /// 2001::/23, as the resolver does. On a private link they pass, as the
    /// operator said.
    #[tokio::test]
    async fn peer_allowed_refuses_internal_literals_the_resolver_never_sees() {
        for literal in [
            "https://[64:ff9b::a9fe:a9fe]",
            "https://[2002:a00:5::]",
            "https://[::1]",
            "https://[fe80::1]",
            "https://198.18.0.1",
            // NAT64 around 198.18.0.1, 6to4 around 240.0.0.1.
            "https://[64:ff9b::c612:1]",
            "https://[2002:f000:1::1]",
            // The local-use NAT64 prefix, around 10.0.0.5 and around the
            // cloud metadata address.
            "https://[64:ff9b:1::a00:5]",
            "https://[64:ff9b:1::a9fe:a9fe]",
            // Teredo, SIIT and SRv6.
            "https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]",
            "https://[::ffff:0:a00:5]",
            "https://[5f00::1]",
        ] {
            assert_eq!(
                peer_allowed(literal, false).await,
                PeerVerdict::Refused,
                "{literal}"
            );
            assert_eq!(
                peer_allowed(literal, true).await,
                PeerVerdict::Allowed,
                "{literal}"
            );
        }
    }

    /// A name that does not resolve is not a refusal: it is retried on the
    /// backoff of a network failure, not parked for the maximum interval.
    /// This also pins the wording of the outbound policy's lookup error,
    /// which is what tells the two apart.
    #[tokio::test]
    async fn guard_tells_a_failed_lookup_from_a_refusal() {
        // A label of 64 characters is one more than DNS allows, so the
        // lookup fails on any resolver, and without a network.
        let unresolvable = format!("https://{}.example.com", "a".repeat(64));
        assert_eq!(
            peer_allowed(&unresolvable, false).await,
            PeerVerdict::Unresolved
        );
        assert_eq!(classify_failure(UNRESOLVED_REASON), RetryClass::Backoff);
        assert_eq!(reason_label(UNRESOLVED_REASON), "network");
        assert_eq!(classify_failure("blocked"), RetryClass::AtMax);
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
        // IPv6 space public hosts are not numbered from: Teredo and SRv6.
        assert!(!relay_peer_allowed("wss://[2001::1]", false).await);
        assert!(!relay_peer_allowed("wss://[5f00::1]", false).await);
        // Unresolvable host rejected (fails closed).
        assert!(!relay_peer_allowed("wss://nonexistent.invalid", false).await);
    }

    // ---- the worker loop, with time paused ---------------------------------

    /// What the fake peer does with one blob.
    #[derive(Debug, Clone)]
    struct FakeBlob {
        account: String,
        /// How long a fetch of it takes.
        delay: Duration,
        /// Fetches that fail before one succeeds.
        failures_left: u32,
        /// Fetches that panic before any other outcome.
        panics_left: u32,
        /// Whether the repair scan reports it while it is missing.
        listed: bool,
    }

    impl FakeBlob {
        fn of(account: &str) -> Self {
            Self {
                account: account.to_string(),
                delay: Duration::ZERO,
                failures_left: 0,
                panics_left: 0,
                listed: true,
            }
        }
    }

    /// A node without disk or network: blobs arrive after a set delay.
    #[derive(Default)]
    struct FakeBackend {
        blobs: parking_lot::Mutex<HashMap<String, FakeBlob>>,
        stored: parking_lot::Mutex<HashSet<String>>,
        /// Every fetch started: which blob, and when.
        attempts: parking_lot::Mutex<Vec<(String, Instant)>>,
        /// Fetches running per account, and the most seen at once.
        running: parking_lot::Mutex<HashMap<String, usize>>,
        peak: parking_lot::Mutex<HashMap<String, usize>>,
        scans: std::sync::atomic::AtomicUsize,
    }

    fn fake_task(account: &str, sha: &str) -> FetchTask {
        FetchTask {
            route: Arc::new(Route {
                tenant_hex: account.to_string(),
                alias: format!("{account}-repo"),
                peer_servers: vec!["https://peer.example".to_string()],
            }),
            fallbacks: Vec::new(),
            blob: WantBlob {
                sha256: sha.to_string(),
                size: 1,
            },
        }
    }

    impl FakeBackend {
        fn add(&self, sha: &str, blob: FakeBlob) {
            self.blobs.lock().insert(sha.to_string(), blob);
        }

        fn has(&self, sha: &str) -> bool {
            self.stored.lock().contains(sha)
        }

        fn stored_count(&self) -> usize {
            self.stored.lock().len()
        }

        fn attempt_count(&self) -> usize {
            self.attempts.lock().len()
        }

        fn attempts_of(&self, sha: &str) -> Vec<Instant> {
            self.attempts
                .lock()
                .iter()
                .filter(|(attempted, _)| attempted == sha)
                .map(|(_, at)| *at)
                .collect()
        }

        fn peak_of(&self, account: &str) -> usize {
            self.peak.lock().get(account).copied().unwrap_or(0)
        }

        fn scan_count(&self) -> usize {
            self.scans.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl MirrorBackend for FakeBackend {
        fn scan(&self) -> ScanOutcome {
            self.scans.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let stored = self.stored.lock().clone();
            let blobs = self.blobs.lock();
            let mut missing: Vec<(&String, &FakeBlob)> = blobs
                .iter()
                .filter(|(sha, blob)| blob.listed && !stored.contains(*sha))
                .collect();
            missing.sort_by_key(|(sha, _)| *sha);
            ScanOutcome {
                lag: missing.len() as u64,
                tasks: missing
                    .into_iter()
                    .map(|(sha, blob)| fake_task(&blob.account, sha))
                    .collect(),
            }
        }

        fn settled(&self, sha256: &str) -> bool {
            self.has(sha256)
        }

        fn fetch(self: Arc<Self>, task: FetchTask) -> FetchFuture {
            Box::pin(async move {
                let sha = task.blob.sha256.clone();
                let account = task.route.tenant_hex.clone();
                self.attempts.lock().push((sha.clone(), clock_now()));
                let (delay, fails, panics) = {
                    let mut blobs = self.blobs.lock();
                    let blob = blobs.get_mut(&sha).expect("a blob the test added");
                    let panics = blob.panics_left > 0;
                    let fails = !panics && blob.failures_left > 0;
                    if panics {
                        blob.panics_left -= 1;
                    } else if fails {
                        blob.failures_left -= 1;
                    }
                    (blob.delay, fails, panics)
                };
                assert!(!panics, "a fetch that dies (wanted by the test)");
                {
                    let mut running = self.running.lock();
                    let now_running = running.entry(account.clone()).or_insert(0);
                    *now_running += 1;
                    let mut peak = self.peak.lock();
                    let seen = peak.entry(account.clone()).or_insert(0);
                    *seen = (*seen).max(*now_running);
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if let Some(count) = self.running.lock().get_mut(&account) {
                    *count -= 1;
                }
                if fails {
                    Some("http_status: 500".to_string())
                } else {
                    self.stored.lock().insert(sha);
                    None
                }
            })
        }
    }

    /// A worker loop running against a fake backend.
    struct TestWorker {
        jobs: UnboundedSender<MirrorJob>,
        retry: Arc<parking_lot::Mutex<HashMap<String, RetryState>>>,
        handle: JoinHandle<()>,
    }

    /// Start the loop with a 1 s repair interval and a backoff of 1 s to
    /// 60 s, the values a test node runs with.
    fn start_worker(
        backend: &Arc<FakeBackend>,
        max_concurrency: usize,
        attempts_per_min: u32,
    ) -> TestWorker {
        let (jobs, rx) = unbounded_channel::<MirrorJob>();
        let retry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let settings = WorkerSettings {
            max_concurrency,
            attempts_per_min,
            retry: RetryPolicy {
                base: Duration::from_secs(1),
                max: Duration::from_secs(60),
            },
            repair_interval: Duration::from_secs(1),
        };
        let handle = tokio::spawn(run_worker(backend.clone(), rx, retry.clone(), settings));
        TestWorker {
            jobs,
            retry,
            handle,
        }
    }

    /// Issue 26, the starvation: one account's slow blobs hold at most
    /// half of the fetch slots, so another account's blob is fetched at
    /// once. Before, the worker waited for a slot with the first account's
    /// whole backlog in hand.
    #[tokio::test(start_paused = true)]
    async fn worker_serves_a_second_account_while_the_first_is_slow() {
        let backend = Arc::new(FakeBackend::default());
        for i in 0..10 {
            backend.add(
                &format!("a{i:02}"),
                FakeBlob {
                    delay: Duration::from_secs(100),
                    ..FakeBlob::of("slow")
                },
            );
        }
        backend.add(
            "b00",
            FakeBlob {
                delay: Duration::from_secs(1),
                ..FakeBlob::of("quick")
            },
        );
        let worker = start_worker(&backend, 4, 0);

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            backend.has("b00"),
            "the quick account's blob must not wait for the slow account's backlog"
        );
        assert_eq!(backend.stored_count(), 1, "the slow blobs are still coming");
        assert_eq!(backend.peak_of("slow"), 2, "half of four slots, no more");

        // The slow account is served too: ten blobs, two at a time, 100 s
        // each.
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert_eq!(backend.stored_count(), 11);
        assert_eq!(backend.peak_of("slow"), 2);
        assert_eq!(backend.attempt_count(), 11, "no blob was fetched twice");

        worker.handle.abort();
    }

    /// The replication guarantee: a blob that fails is fetched again until
    /// it arrives, each time after a longer wait, and its gate is gone once
    /// it has arrived.
    #[tokio::test(start_paused = true)]
    async fn worker_retries_a_failed_blob_until_it_arrives() {
        let backend = Arc::new(FakeBackend::default());
        backend.add(
            "flaky",
            FakeBlob {
                failures_left: 3,
                ..FakeBlob::of("account")
            },
        );
        let worker = start_worker(&backend, 4, 0);

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!backend.has("flaky"));
        assert!(
            worker.retry.lock().contains_key("flaky"),
            "a failed blob is gated"
        );

        tokio::time::sleep(Duration::from_secs(58)).await;
        assert!(backend.has("flaky"), "the blob must arrive in the end");
        let attempts = backend.attempts_of("flaky");
        assert_eq!(
            attempts.len(),
            4,
            "three failures, then the fetch that worked"
        );
        // The backoff doubles from 1 s; jitter takes off 20% at most.
        let gaps: Vec<Duration> = attempts
            .windows(2)
            .map(|pair| pair[1].duration_since(pair[0]))
            .collect();
        assert!(gaps[0] >= Duration::from_millis(800), "{gaps:?}");
        assert!(gaps[1] >= Duration::from_millis(1600), "{gaps:?}");
        assert!(gaps[2] >= Duration::from_millis(3200), "{gaps:?}");
        assert!(worker.retry.lock().is_empty(), "success clears the gate");

        worker.handle.abort();
    }

    /// The attempt budget holds fetches back and then lets every one of
    /// them through: the loop wakes for each new token by itself.
    #[tokio::test(start_paused = true)]
    async fn worker_spends_no_more_than_the_attempt_budget() {
        let backend = Arc::new(FakeBackend::default());
        // 300 accounts with one blob each, so that no account's share is
        // what limits them.
        for i in 0..300 {
            backend.add(
                &format!("blob{i:03}"),
                FakeBlob::of(&format!("account{i:03}")),
            );
        }
        let worker = start_worker(&backend, 8, 120);

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            backend.attempt_count(),
            120,
            "the burst is one minute's worth"
        );

        // The next token comes at 0.5 s, between two repair ticks: only the
        // budget timer can wake the loop for it.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            backend.attempt_count(),
            121,
            "the loop must wake for a token without waiting for a tick"
        );

        tokio::time::sleep(Duration::from_secs(10)).await;
        let after_ten = backend.attempt_count();
        assert!(
            (140..=142).contains(&after_ten),
            "two a second after the burst; saw {after_ten}"
        );

        // 180 blobs were left after the burst: 90 s at two a second.
        tokio::time::sleep(Duration::from_secs(100)).await;
        assert_eq!(backend.stored_count(), 300, "every blob arrives in the end");
        assert_eq!(backend.attempt_count(), 300);

        worker.handle.abort();
    }

    /// With every fetch slot held by slow fetches the loop still scans and
    /// still takes jobs; the job's blob is fetched when a slot frees.
    #[tokio::test(start_paused = true)]
    async fn worker_scans_and_takes_jobs_while_every_slot_is_held() {
        let backend = Arc::new(FakeBackend::default());
        for (sha, account) in [("a", "one"), ("b", "two")] {
            backend.add(
                sha,
                FakeBlob {
                    delay: Duration::from_secs(1000),
                    ..FakeBlob::of(account)
                },
            );
        }
        // Known to the fake peer, but not reported by the scan: only a job
        // can bring it in.
        backend.add(
            "c",
            FakeBlob {
                listed: false,
                ..FakeBlob::of("three")
            },
        );
        let worker = start_worker(&backend, 2, 0);

        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(backend.attempt_count(), 2, "both slots are held");
        assert!(
            backend.scan_count() >= 5,
            "the repair scan must keep running; ran {} times",
            backend.scan_count()
        );

        worker
            .jobs
            .send(MirrorJob {
                tenant_hex: "three".to_string(),
                alias: "three-repo".to_string(),
                want: vec![WantBlob {
                    sha256: "c".to_string(),
                    size: 1,
                }],
                peer_servers: vec!["https://peer.example".to_string()],
            })
            .expect("the worker is running");
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!backend.has("c"), "no slot is free yet");

        tokio::time::sleep(Duration::from_secs(1000)).await;
        assert!(
            backend.has("c"),
            "the job taken while the slots were held is fetched when one frees"
        );

        worker.handle.abort();
    }

    /// What does not fit an account's backlog is dropped, and the next
    /// repair scan brings it back: nothing is lost.
    #[tokio::test(start_paused = true)]
    async fn worker_refetches_what_a_full_backlog_dropped() {
        let backend = Arc::new(FakeBackend::default());
        let total = ACCOUNT_BACKLOG_CAP + 50;
        for i in 0..total {
            backend.add(&format!("blob{i:05}"), FakeBlob::of("big"));
        }
        let worker = start_worker(&backend, 4, 0);

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            backend.stored_count(),
            ACCOUNT_BACKLOG_CAP,
            "the first scan queued a full backlog and dropped the rest"
        );

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(backend.stored_count(), total);

        worker.handle.abort();
    }

    /// A fetch that dies still reports, so its slot is freed and its blob
    /// is fetched again. With a share of one, a slot that stayed taken
    /// would stop the account for ever.
    #[tokio::test(start_paused = true)]
    async fn worker_frees_the_slot_of_a_fetch_that_died() {
        let backend = Arc::new(FakeBackend::default());
        backend.add(
            "dies-once",
            FakeBlob {
                panics_left: 1,
                ..FakeBlob::of("account")
            },
        );
        // Sorts after the one that dies, so it queues behind it: it can only
        // be fetched if the dead fetch gave its slot back.
        backend.add("zz-after", FakeBlob::of("account"));
        let worker = start_worker(&backend, 1, 0);

        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(
            backend.has("zz-after"),
            "the account's slot must be free again"
        );
        assert!(backend.has("dies-once"), "the blob must be fetched again");
        assert_eq!(backend.attempts_of("dies-once").len(), 2);

        worker.handle.abort();
    }

    /// An entry of the peer list names this node when it names its host and
    /// port and, for a node under a mount path, that path. At the root of a domain
    /// every path on the host is this node, as it always was.
    #[test]
    fn own_server_is_matched_with_the_mount_path() {
        let mounted = "h.example/grasp";
        assert!(is_own_server("https://h.example/grasp", mounted));
        assert!(is_own_server("https://h.example/grasp/", mounted));
        assert!(is_own_server("h.example/grasp", mounted));
        assert!(!is_own_server("https://h.example", mounted));
        assert!(!is_own_server("h.example", mounted));
        assert!(!is_own_server("https://h.example/other", mounted));
        assert!(!is_own_server("https://peer.example/grasp", mounted));

        let root = "h.example";
        assert!(is_own_server("https://h.example", root));
        assert!(is_own_server("https://h.example/any/path", root));
        assert!(is_own_server("h.example", root));
        assert!(!is_own_server("https://peer.example", root));
        assert!(!is_own_server("http://127.0.0.1:2222", "127.0.0.1:1111"));
    }

    // ---- the client and its resolver ---------------------------------------

    /// A name under `.test`, which no resolver answers: only an injected
    /// lookup can give it an address.
    const PEER_NAME: &str = "peer.mirror.test";

    fn answer_loopback(_host: String) -> vetted_dns::LookupFuture {
        let answer: std::io::Result<Vec<std::net::SocketAddr>> =
            Ok(vec![std::net::SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                0,
            )]);
        Box::pin(std::future::ready(answer))
    }

    fn answer_nothing_found(_host: String) -> vetted_dns::LookupFuture {
        let answer: std::io::Result<Vec<std::net::SocketAddr>> =
            Err(std::io::Error::other("no such name"));
        Box::pin(std::future::ready(answer))
    }

    /// A peer on loopback that counts the connections it accepts, keeps the
    /// head of each request and answers it with an empty 200.
    struct CountingPeer {
        port: u16,
        accepted: Arc<std::sync::atomic::AtomicUsize>,
        heads: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl CountingPeer {
        async fn start() -> Self {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind the peer");
            let port = listener.local_addr().expect("the peer's address").port();
            let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let heads = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let (count, record) = (Arc::clone(&accepted), Arc::clone(&heads));
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let record = Arc::clone(&record);
                    tokio::spawn(async move {
                        let mut head: Vec<u8> = Vec::new();
                        let mut buffer = [0_u8; 1024];
                        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                            match stream.read(&mut buffer).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => head.extend_from_slice(&buffer[..read]),
                            }
                        }
                        record
                            .lock()
                            .push(String::from_utf8_lossy(&head).into_owned());
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self {
                port,
                accepted,
                heads,
            }
        }

        fn accepted(&self) -> usize {
            self.accepted.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn blob_url(&self) -> String {
            format!("http://{PEER_NAME}:{}/{}", self.port, "ab".repeat(32))
        }
    }

    /// The mirror's client connects to the address its resolver vetted and
    /// to nothing else: the name has no address anywhere, so only the
    /// resolver's answer can lead to the listener. The name still travels in
    /// the request.
    #[tokio::test]
    async fn mirror_client_connects_to_the_address_its_resolver_vetted() {
        let peer = CountingPeer::start().await;
        let resolver = VettedResolver::with_lookup(true, Arc::new(answer_loopback));
        let client = http_client(Duration::from_secs(5), resolver).expect("the mirror's client");

        let response = client
            .get(peer.blob_url())
            .send()
            .await
            .expect("the vetted address answers");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(peer.accepted(), 1);
        let heads = peer.heads.lock().clone();
        assert!(
            heads[0]
                .to_ascii_lowercase()
                .contains(&format!("host: {PEER_NAME}:{}\r\n", peer.port)),
            "{heads:?}"
        );
    }

    /// DNS rebinding, on the real client: a name whose lookup answers an
    /// internal address is refused before any connection is made, and the
    /// failure is `blocked`, which waits the maximum interval and names the
    /// host and the address. The test above sends the same request with the
    /// same answer allowed and reaches the listener, so it is the resolver
    /// that kept this one away.
    #[tokio::test]
    async fn mirror_client_refuses_a_name_that_resolves_to_an_internal_address() {
        let peer = CountingPeer::start().await;
        let resolver = VettedResolver::with_lookup(false, Arc::new(answer_loopback));
        let client = http_client(Duration::from_secs(5), resolver).expect("the mirror's client");

        let error = client
            .get(peer.blob_url())
            .send()
            .await
            .expect_err("an internal answer must be refused");

        let blocked =
            vetted_dns::blocked_target(&error).expect("the resolver's refusal is a source");
        assert_eq!(blocked.host, PEER_NAME);
        assert_eq!(blocked.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let reason = send_failure_reason(&error);
        assert_eq!(reason_label(&reason), "blocked", "{reason}");
        assert_eq!(classify_failure(&reason), RetryClass::AtMax);
        assert!(!stops_peer_loop(&reason), "another peer may still serve it");
        assert!(
            reason.contains(PEER_NAME) && reason.contains("127.0.0.1"),
            "{reason}"
        );
        assert_eq!(
            peer.accepted(),
            0,
            "nothing may connect to an address the resolver refused"
        );
    }

    /// `fetch_from_peer` records the resolver's refusal as `blocked`. The
    /// node's early check passes the `.test` name without a lookup (a
    /// private link), and the client's resolver, which allows no internal
    /// answer, refuses loopback before any connection.
    #[tokio::test]
    async fn fetch_from_peer_records_the_resolvers_refusal_as_blocked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::config::Config::for_testing();
        config.private_repos_enable = true;
        config.private_mirror_allow_private_ips = true;
        config.private_meta_data_path =
            Some(dir.path().join("meta").to_string_lossy().into_owned());
        config.private_blob_data_path =
            Some(dir.path().join("blobs").to_string_lossy().into_owned());
        let database: crate::nostr::SharedDatabase =
            Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let svc = PrivateService::new(&config, database)
            .await
            .expect("private service");
        let peer = CountingPeer::start().await;
        let resolver = VettedResolver::with_lookup(false, Arc::new(answer_loopback));
        let client = http_client(Duration::from_secs(5), resolver).expect("the mirror's client");
        let route = Route {
            tenant_hex: "ef".repeat(32),
            alias: "ab".repeat(16),
            peer_servers: Vec::new(),
        };
        let blob = WantBlob {
            sha256: "cd".repeat(32),
            size: 1,
        };
        let peer_base = format!("http://{PEER_NAME}:{}", peer.port);

        let reason = fetch_from_peer(
            &svc,
            &client,
            Duration::from_secs(5),
            &route,
            &blob,
            &peer_base,
        )
        .await
        .expect_err("an internal answer must be refused");

        assert_eq!(reason_label(&reason), "blocked", "{reason}");
        assert!(
            reason.contains(PEER_NAME) && reason.contains("127.0.0.1"),
            "{reason}"
        );
        assert_eq!(peer.accepted(), 0);
    }

    /// A fallback route is judged at its own repository's declared size,
    /// not at the size of the route the scan chose first: at the first
    /// route's 5000 bytes this repository's 1000-byte cap would refuse the
    /// blob as `quota` before any request; at its own 100 the request goes
    /// out, and here the resolver refuses it.
    #[tokio::test]
    async fn a_fallback_route_is_judged_at_its_own_declared_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::config::Config::for_testing();
        config.private_repos_enable = true;
        config.private_mirror_allow_private_ips = true;
        config.private_quota_repo_bytes = 1000;
        config.private_meta_data_path =
            Some(dir.path().join("meta").to_string_lossy().into_owned());
        config.private_blob_data_path =
            Some(dir.path().join("blobs").to_string_lossy().into_owned());
        let database: crate::nostr::SharedDatabase =
            Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let svc = PrivateService::new(&config, database)
            .await
            .expect("private service");
        let route = Route {
            tenant_hex: "ef".repeat(32),
            alias: "ab".repeat(16),
            peer_servers: Vec::new(),
        };
        let sha = "cd".repeat(32);
        svc.meta
            .with_write(|meta, txn| {
                crate::grasp_p::claims::attach_to(
                    meta,
                    txn,
                    &sha,
                    &"0b".repeat(32),
                    &"bb".repeat(16),
                    5000,
                )?;
                crate::grasp_p::claims::attach_to(
                    meta,
                    txn,
                    &sha,
                    &route.tenant_hex,
                    &route.alias,
                    100,
                )
            })
            .expect("both repositories declare the blob");
        let blob = WantBlob {
            sha256: sha.clone(),
            size: 5000,
        };
        let peer = CountingPeer::start().await;
        let resolver = VettedResolver::with_lookup(false, Arc::new(answer_loopback));
        let client = http_client(Duration::from_secs(5), resolver).expect("the mirror's client");
        let peer_base = format!("http://{PEER_NAME}:{}", peer.port);

        let reason = fetch_from_peer(
            &svc,
            &client,
            Duration::from_secs(5),
            &route,
            &blob,
            &peer_base,
        )
        .await
        .expect_err("the resolver refuses loopback");

        assert_eq!(reason_label(&reason), "blocked", "{reason}");
        assert_eq!(peer.accepted(), 0);
    }

    /// A name that does not resolve fails as `network`, as it does in the
    /// early check: a resolver that fails for a moment must not park the
    /// blob for the maximum interval.
    #[tokio::test]
    async fn mirror_client_reports_a_failed_lookup_as_network() {
        let resolver = VettedResolver::with_lookup(false, Arc::new(answer_nothing_found));
        let client = http_client(Duration::from_secs(5), resolver).expect("the mirror's client");

        let error = client
            .get(format!("http://{PEER_NAME}/{}", "ab".repeat(32)))
            .send()
            .await
            .expect_err("a name without an address cannot be fetched from");

        assert!(vetted_dns::blocked_target(&error).is_none(), "{error}");
        let reason = send_failure_reason(&error);
        assert_eq!(reason_label(&reason), "network", "{reason}");
        assert_eq!(classify_failure(&reason), RetryClass::Backoff);
    }
}
