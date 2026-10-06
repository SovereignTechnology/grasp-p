//! External split-view watchdog for GRASP-P two-node deployments.
//!
//! Anonymously probes TWO ngit-grasp nodes and alerts when their views of
//! GRASP-P private-repo state diverge (e.g. one node withholding a kind-30641
//! state-root manifest = split-view attack). Holds NO keys, signs NOTHING,
//! publishes NOTHING — every input it compares is anonymously readable by
//! design (NIP-11, kind-30640/30641 REQs, HEAD/GET blob routes). It does not
//! compare `GET /list/<pubkey>`: that route answers only the listed key.
//!
//! Exit codes: 0 = all checks pass, 1 = divergence alert, 2 = operational
//! error (unreachable node, timeout, unexpected response, underivable blob
//! base, incomplete probe coverage). An unreachable node is NEVER reported
//! as divergence. Completed
//! check results are always emitted: an operational failure inside check
//! 4 (blob-dependent) produces per-check ERROR lines and never suppresses
//! other checks; exit is 1 whenever any check FAILs (divergence dominates),
//! 2 when operational errors occurred without divergence.

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin_hashes::{sha256, Hash, HashEngine};
use clap::{Parser, ValueEnum};
use futures_util::stream::{self, StreamExt};
use ngit_grasp::grasp_p::{KIND_REGISTRATION, KIND_STATE_ROOT};
use nostr::prelude::{Event, Filter, Kind, PublicKey, RelayUrl};
use nostr_sdk::relay::{Relay, RelayStatus};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BlobProbeMode {
    /// HEAD /<sha256> on each blob base; 200 vs 404 vs 451.
    Head,
    /// GET the body and verify sha256 + declared size as well.
    Get,
    /// Skip blob probing entirely.
    None,
}

/// Alias shape: exactly 32 lowercase hex chars (mirrors
/// `private::registration::is_valid_alias`, which is crate-private).
fn is_valid_alias(alias: &str) -> bool {
    alias.len() == 32
        && alias
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn parse_alias(s: &str) -> Result<String, String> {
    if is_valid_alias(s) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "alias must be exactly 32 lowercase hex chars, got {s:?}"
        ))
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "ngit-private-watchdog",
    version = ngit_grasp::grasp_p::build_info::version(),
    about = "External split-view watchdog for GRASP-P two-node deployments",
    long_about = "Anonymously compares two ngit-grasp nodes' views of GRASP-P private-repo \
                  state (NIP-11 policy fingerprint, kind-30640 registrations, kind-30641 \
                  state roots, blob existence) and alerts on divergence. \
                  Exit 0 = parity, 1 = divergence alert, 2 = operational error."
)]
struct Cli {
    /// Relay websocket URL of node A (ws:// or wss://).
    #[arg(long)]
    relay_a: String,
    /// Relay websocket URL of node B (ws:// or wss://).
    #[arg(long)]
    relay_b: String,
    /// Alias to watch (32 lowercase hex chars). Repeatable. When omitted, all
    /// aliases are discovered from the union of both nodes' kind-30640 events.
    #[arg(long, value_parser = parse_alias)]
    alias: Vec<String>,
    /// Blob base URL for node A (default: derived from registrations' `server`
    /// tag matching node A's relay host).
    #[arg(long)]
    blob_base_a: Option<String>,
    /// Blob base URL for node B (default: derived from registrations' `server`
    /// tag matching node B's relay host).
    #[arg(long)]
    blob_base_b: Option<String>,
    /// Blob probe depth.
    #[arg(long, value_enum, default_value_t = BlobProbeMode::Head)]
    blob_probe: BlobProbeMode,
    /// Per-request timeout (relay connect, REQ, HTTP) in seconds.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
    /// Grace window in seconds. A kind-30641 present on one node and absent or
    /// stale on the other only counts as withheld/diverged once its created_at
    /// is strictly older than now - max-skew-secs.
    #[arg(long, default_value_t = 300)]
    max_skew_secs: u64,
    /// Emit a machine-readable JSON report on stdout (FAIL lines still go to
    /// stderr for journal/cron alerting).
    #[arg(long)]
    json: bool,
}

// ---------------------------------------------------------------------------
// Resource bounds (adversarial-review round 1): every unbounded input the
// watchdog consumes is capped below so a hostile or broken node cannot turn
// the watchdog into a memory/connection amplifier against the pair.
// ---------------------------------------------------------------------------

/// Blob probes fan out over every sha referenced by the compared manifests;
/// cap the number of probe tasks polled at once (each task issues one HTTP
/// request per node, so in-flight HTTP is 2x this).
const MAX_IN_FLIGHT_PROBES: usize = 32;

/// Hard cap on the number of distinct blob shas probed per run. Excess
/// targets are skipped loudly (R2-3): the blob-existence check reports
/// ERROR and the run exits 2 — partial coverage must never read as a
/// clean PASS (exit 0) to automation gating on the exit code.
const MAX_PROBE_TARGETS: usize = 10_000;

/// Hard cap on a NIP-11 response body. It is a small JSON document in any
/// real deployment; a body past the cap means a broken or hostile HTTP peer,
/// which is an operational error, not something to buffer.
const MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// Hard cap on events retained from a single REQ batch. The relay SDK
/// collects until EOSE or the timeout, so ingress within the window is
/// already time-bounded; this cap bounds what the watchdog RETAINS and
/// processes. Past it the view is unusable for parity anyway (a healthy
/// GRASP-P node has orders of magnitude fewer 30640/30641 events), so the
/// run fails operationally rather than comparing a firehose.
const MAX_EVENTS_PER_REQ: usize = 100_000;

/// FW-1(b): bound the blob-probe fan-out. Keeps the first `max` targets in
/// deterministic (BTreeMap sha) order; returns the kept map and the number
/// skipped. Skipped targets are surfaced as an ERROR check line plus an
/// operational error (R2-3), never silently dropped.
fn cap_probe_targets(
    targets: BTreeMap<String, BTreeSet<u64>>,
    max: usize,
) -> (BTreeMap<String, BTreeSet<u64>>, usize) {
    let skipped = targets.len().saturating_sub(max);
    if skipped == 0 {
        (targets, 0)
    } else {
        (targets.into_iter().take(max).collect(), skipped)
    }
}

/// FW-1(d): refuse an unreasonably large REQ result as operational.
fn check_event_volume(count: usize, what: &str) -> Result<(), String> {
    if count > MAX_EVENTS_PER_REQ {
        Err(format!(
            "{what} REQ returned {count} events, exceeding the {MAX_EVENTS_PER_REQ}-event volume cap"
        ))
    } else {
        Ok(())
    }
}

/// FW-1(c): read a response body to a string with a hard byte cap, in
/// chunks, so a peer cannot make the watchdog buffer an unbounded body.
async fn read_body_capped(
    mut response: reqwest::Response,
    cap: u64,
    side: &str,
    what: &str,
) -> Result<String, OpError> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() as u64 + chunk.len() as u64 > cap {
                    return Err(op(
                        side,
                        format!("{what} body exceeds the {cap}-byte read cap"),
                    ));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => return Err(op(side, format!("{what} body read failed: {e}"))),
        }
    }
    String::from_utf8(buf).map_err(|e| op(side, format!("{what} body is not valid UTF-8: {e}")))
}

// ---------------------------------------------------------------------------
// Pure model + comparison logic (unit-tested; no IO)
// ---------------------------------------------------------------------------

/// One manifest/pack reference from a kind-30641: (sha256, declared size).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BlobRef {
    sha256: String,
    size: u64,
}

/// Node-local view of one kind-30640 edition, reduced to the fields parity
/// compares. Tag lists are sets: order and duplicates are not meaningful.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistrationView {
    alias: String,
    author: String,
    event_id: String,
    created_at: u64,
    w_keys: BTreeSet<String>,
    aux_keys: BTreeSet<String>,
    relays: BTreeSet<String>,
    servers: BTreeSet<String>,
}

/// Node-local view of one kind-30641 edition.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StateRootView {
    alias: String,
    author: String,
    event_id: String,
    created_at: u64,
    manifest: BlobRef,
    packs: BTreeSet<BlobRef>,
}

/// Addressable-replaceable edition identity. Latest = highest created_at;
/// equal created_at -> LOWEST event id wins. Mirrors
/// `private::registration::is_newer_than_stored` (registration.rs) and the
/// NIP-01 tie-break, so the watchdog resolves the same winner as the nodes.
trait Edition {
    fn created_at(&self) -> u64;
    fn edition_id(&self) -> &str;
}

impl Edition for RegistrationView {
    fn created_at(&self) -> u64 {
        self.created_at
    }
    fn edition_id(&self) -> &str {
        &self.event_id
    }
}

impl Edition for StateRootView {
    fn created_at(&self) -> u64 {
        self.created_at
    }
    fn edition_id(&self) -> &str {
        &self.event_id
    }
}

fn latest_edition<'a, T: Edition>(items: impl IntoIterator<Item = &'a T>) -> Option<&'a T> {
    items.into_iter().reduce(|best, e| {
        if e.created_at() > best.created_at()
            || (e.created_at() == best.created_at() && e.edition_id() < best.edition_id())
        {
            e
        } else {
            best
        }
    })
}

/// Grace rule: an edition is stale enough to accuse a node of withholding
/// only when its age is STRICTLY greater than the grace window. Age exactly
/// equal to the window is still within grace. saturating_sub makes
/// future-dated editions (author clock ahead) always within grace.
fn beyond_grace(now: u64, created_at: u64, max_skew_secs: u64) -> bool {
    now.saturating_sub(created_at) > max_skew_secs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    A,
    B,
}

impl Side {
    fn label(self) -> &'static str {
        match self {
            Side::A => "A",
            Side::B => "B",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ManifestParity {
    /// Both nodes' latest editions carry the same manifest + pack set.
    Match,
    /// Views differ (or one side is missing) but the newest involved
    /// created_at is within the grace window: replication may be in flight.
    WithinGrace { newest_created_at: u64 },
    /// One node has NO kind-30641 for this (alias, author) at all and the
    /// other side's edition is older than the grace window.
    Withheld { missing_on: Side, created_at: u64 },
    /// Both nodes have a latest edition but manifest/pack content differs and
    /// the newest involved created_at is beyond the grace window.
    Diverged { detail: String },
}

fn short(hex: &str) -> String {
    hex.chars().take(8).collect()
}

/// Human-readable description of how two differing state roots differ.
fn describe_manifest_diff(x: &StateRootView, y: &StateRootView) -> String {
    let mut parts = Vec::new();
    if x.manifest != y.manifest {
        parts.push(format!(
            "manifest {}:{} vs {}:{}",
            short(&x.manifest.sha256),
            x.manifest.size,
            short(&y.manifest.sha256),
            y.manifest.size
        ));
    }
    let only_x: Vec<&BlobRef> = x.packs.difference(&y.packs).collect();
    let only_y: Vec<&BlobRef> = y.packs.difference(&x.packs).collect();
    if !only_x.is_empty() {
        parts.push(format!(
            "packs only on first: {}",
            count_and_sample(&only_x)
        ));
    }
    if !only_y.is_empty() {
        parts.push(format!(
            "packs only on second: {}",
            count_and_sample(&only_y)
        ));
    }
    if parts.is_empty() {
        // Same manifest and packs but we were called on unequal views:
        // editions differ only by id/created_at (benign re-publication).
        "same content, different edition id".to_string()
    } else {
        parts.join("; ")
    }
}

fn count_and_sample(refs: &[&BlobRef]) -> String {
    let sample: Vec<String> = refs.iter().take(3).map(|r| short(&r.sha256)).collect();
    if refs.len() > 3 {
        format!(
            "{} [{} +{} more]",
            refs.len(),
            sample.join(","),
            refs.len() - 3
        )
    } else {
        format!("{} [{}]", refs.len(), sample.join(","))
    }
}

/// THE split-view check. `a`/`b` are each node's LATEST kind-30641 for one
/// (alias, author). Caller guarantees at least one is Some.
fn manifest_parity(
    a: Option<&StateRootView>,
    b: Option<&StateRootView>,
    now: u64,
    max_skew_secs: u64,
) -> ManifestParity {
    match (a, b) {
        (Some(x), Some(y)) => {
            if x.manifest == y.manifest && x.packs == y.packs {
                ManifestParity::Match
            } else {
                let newest = x.created_at.max(y.created_at);
                if beyond_grace(now, newest, max_skew_secs) {
                    ManifestParity::Diverged {
                        detail: describe_manifest_diff(x, y),
                    }
                } else {
                    ManifestParity::WithinGrace {
                        newest_created_at: newest,
                    }
                }
            }
        }
        (Some(x), None) => {
            if beyond_grace(now, x.created_at, max_skew_secs) {
                ManifestParity::Withheld {
                    missing_on: Side::B,
                    created_at: x.created_at,
                }
            } else {
                ManifestParity::WithinGrace {
                    newest_created_at: x.created_at,
                }
            }
        }
        (None, Some(y)) => {
            if beyond_grace(now, y.created_at, max_skew_secs) {
                ManifestParity::Withheld {
                    missing_on: Side::A,
                    created_at: y.created_at,
                }
            } else {
                ManifestParity::WithinGrace {
                    newest_created_at: y.created_at,
                }
            }
        }
        (None, None) => ManifestParity::Match,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RegistrationParity {
    Match,
    MissingBoth,
    MissingOn(Side),
    Different(Vec<String>),
}

fn registration_parity(
    a: Option<&RegistrationView>,
    b: Option<&RegistrationView>,
) -> RegistrationParity {
    match (a, b) {
        (None, None) => RegistrationParity::MissingBoth,
        (None, Some(_)) => RegistrationParity::MissingOn(Side::A),
        (Some(_), None) => RegistrationParity::MissingOn(Side::B),
        (Some(x), Some(y)) => {
            let mut diffs = Vec::new();
            if x.event_id != y.event_id {
                diffs.push(format!(
                    "event-id {}@{} vs {}@{}",
                    short(&x.event_id),
                    x.created_at,
                    short(&y.event_id),
                    y.created_at
                ));
            }
            if x.w_keys != y.w_keys {
                diffs.push("w-keys differ".to_string());
            }
            if x.aux_keys != y.aux_keys {
                diffs.push("aux-keys differ".to_string());
            }
            if x.relays != y.relays {
                diffs.push("relays differ".to_string());
            }
            if x.servers != y.servers {
                diffs.push("server tags differ".to_string());
            }
            if diffs.is_empty() {
                RegistrationParity::Match
            } else {
                RegistrationParity::Different(diffs)
            }
        }
    }
}

/// NIP-11 policy fingerprint parity. Both sides must advertise
/// private_repos.policy_fingerprint and agree.
fn fingerprint_parity(a: Option<&str>, b: Option<&str>) -> Result<(), String> {
    match (a, b) {
        (Some(x), Some(y)) if x == y => Ok(()),
        (Some(x), Some(y)) => Err(format!("fingerprint mismatch A={x} B={y}")),
        (None, Some(_)) => Err(
            "node A NIP-11 lacks private_repos.policy_fingerprint (private repos disabled?)"
                .to_string(),
        ),
        (Some(_), None) => Err(
            "node B NIP-11 lacks private_repos.policy_fingerprint (private repos disabled?)"
                .to_string(),
        ),
        (None, None) => Err("neither node advertises private_repos.policy_fingerprint".to_string()),
    }
}

/// Fingerprint-mismatch detail with the version-skew vs knob-split
/// distinction spelled out, so the operator is told which case they are
/// looking at instead of inferring it from an opaque digest pair. A peer
/// that advertises no `policy_version` at all is called out as its own
/// (skew) case: it predates the field, which is exactly the rolling-upgrade
/// window onto the first labelled build.
fn fingerprint_detail(reason: String, a: &Option<String>, b: &Option<String>) -> String {
    match (a, b) {
        (Some(x), Some(y)) if x != y => format!(
            "{reason}; policy_version differs ({x} vs {y}): this is a rolling-upgrade \
             VERSION SKEW — every node's digest moves on a label bump. Finish the roll \
             on both nodes in one maintenance window"
        ),
        (Some(x), Some(_)) => format!(
            "{reason}; both nodes report policy_version={x}: this is a SAME-VERSION knob \
             split — a real acceptance divergence. Compare the preimage knobs (runbook §2)"
        ),
        // Exactly one side advertises a label. That node is NOT on some
        // other version — the peer PREDATES the policy_version field, which
        // is precisely the shape of the first rolling upgrade onto a
        // labelled build. Without this arm the operator sees neither verdict
        // and a bare `policy-a=unadvertised` scope, i.e. no case at all for
        // the most likely real-world mismatch.
        (None, Some(y)) => format!(
            "{reason}; node B reports policy_version={y} and node A advertises none: node A \
             predates the policy_version field — treat this as a VERSION SKEW until both \
             nodes are upgraded, then re-read this line"
        ),
        (Some(x), None) => format!(
            "{reason}; node A reports policy_version={x} and node B advertises none: node B \
             predates the policy_version field — treat this as a VERSION SKEW until both \
             nodes are upgraded, then re-read this line"
        ),
        // Neither node labels its policy: both predate the field, so there
        // is nothing to distinguish a skew from a knob split with. The bare
        // reason (both digests) is all the evidence there is.
        (None, None) => reason,
    }
}

/// Verdict for the advertised accepted-kind set.
#[derive(Debug, PartialEq, Eq)]
enum KindsParity {
    /// Identical sets (and non-empty).
    Match,
    /// Neither node advertises `private_repos.kinds` — nothing to compare
    /// (private repos disabled, or a pre-advert build). The
    /// fingerprint-parity check already reports that condition; repeating
    /// it as a FAIL here would be noise.
    Unavailable,
    Mismatch {
        only_a: Vec<u64>,
        only_b: Vec<u64>,
    },
}

/// Set parity of `private_repos.kinds` across the pair.
///
/// This exists as its OWN check because the `policy_fingerprint` digest
/// folds a dozen knobs into 16 opaque hex chars: a wrap-kind split (one
/// node still admits 1059, the other has retired it) is indistinguishable
/// there from a quota or whitelist difference. A wrap-kind split means
/// wraps accepted on one node are refused on the other and never
/// replicate — a permanent, per-data-class divergence — so it is named
/// explicitly.
///
/// NOTE (scope): this compares what the nodes SAY they accept. Stream
/// wraps themselves are not compared by any watchdog data-parity check;
/// see the runbook.
fn kinds_parity(a: &BTreeSet<u64>, b: &BTreeSet<u64>) -> KindsParity {
    if a.is_empty() && b.is_empty() {
        return KindsParity::Unavailable;
    }
    if a == b {
        return KindsParity::Match;
    }
    KindsParity::Mismatch {
        only_a: a.difference(b).copied().collect(),
        only_b: b.difference(a).copied().collect(),
    }
}

/// Render a kind set for a check line: `1059,3359,23359,30640,30641`.
fn kinds_display(kinds: &BTreeSet<u64>) -> String {
    if kinds.is_empty() {
        return "none".to_string();
    }
    kinds
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Per-node outcome of one blob probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlobProbeOutcome {
    /// 200 (and, in get mode, body hash + size verified).
    Present,
    /// 404.
    Missing,
    /// 451 denylisted — reported distinctly, never silently a "missing".
    Denylisted,
    /// get mode: body sha256 does not equal the requested hash.
    HashMismatch,
    /// get mode: body length disagrees with a declared size.
    SizeMismatch,
}

impl BlobProbeOutcome {
    fn code(self) -> &'static str {
        match self {
            BlobProbeOutcome::Present => "200",
            BlobProbeOutcome::Missing => "404",
            BlobProbeOutcome::Denylisted => "451-denylisted",
            BlobProbeOutcome::HashMismatch => "hash-mismatch",
            BlobProbeOutcome::SizeMismatch => "size-mismatch",
        }
    }
}

/// Map an HTTP status to a data verdict. None = unexpected status, which the
/// IO layer turns into an OPERATIONAL error (exit 2), never a divergence.
fn classify_http_status(code: u16) -> Option<BlobProbeOutcome> {
    match code {
        200 => Some(BlobProbeOutcome::Present),
        404 => Some(BlobProbeOutcome::Missing),
        451 => Some(BlobProbeOutcome::Denylisted),
        _ => None,
    }
}

/// Pick the blob base URL for one node from the `server` tag values seen in
/// registrations: the value whose scheme, host, AND effective port match the
/// node's relay endpoint (https for wss relays, http for ws; default ports
/// normalized — 443/https, 80/http). Host equality is the SSRF guard — a
/// tenant-controlled server tag can never point the watchdog anywhere but
/// the node's own host; the scheme/port equality keeps derivation from
/// latching onto the wrong scheme or an arbitrary port on that host (a blind
/// oracle). Ok(None) = no match; multiple matches go through
/// [`resolve_base_candidates`]: a path-only tie resolves to the path-empty
/// candidate (R2-4), genuine ambiguity is Err (operator must pass
/// --blob-base-{a,b} explicitly).
fn derive_blob_base(
    relay_url: &RelayUrl,
    servers: impl IntoIterator<Item = String>,
) -> Result<Option<String>, String> {
    // Re-parse with the generic URL parser for scheme/port access (RelayUrl
    // exposes only the host); RelayUrl already guarantees a valid ws/wss URL.
    let relay = reqwest::Url::parse(relay_url.as_str_without_trailing_slash())
        .map_err(|e| format!("relay url {relay_url} re-parse failed: {e}"))?;
    let expected_scheme = match relay.scheme() {
        "wss" => "https",
        "ws" => "http",
        other => {
            return Err(format!(
                "relay url {relay_url} has unexpected scheme {other}"
            ))
        }
    };
    let host = relay
        .host_str()
        .ok_or_else(|| format!("relay url {relay_url} has no host"))?
        .to_string();
    // ws/wss (and http/https) are WHATWG special schemes:
    // port_or_known_default normalizes absent ports to 80/443.
    let expected_port = relay
        .port_or_known_default()
        .ok_or_else(|| format!("relay url {relay_url} has no usable port"))?;
    let matches: BTreeSet<String> = servers
        .into_iter()
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| {
            reqwest::Url::parse(s).ok().is_some_and(|u| {
                u.scheme() == expected_scheme
                    && u.host_str()
                        .map(|h| h.eq_ignore_ascii_case(&host))
                        .unwrap_or(false)
                    && u.port_or_known_default() == Some(expected_port)
            })
        })
        .collect();
    resolve_base_candidates(
        &format!("{expected_scheme}://{host}:{expected_port}"),
        matches,
    )
}

/// R2-4: resolve the relay-matched `server`-tag candidates to one blob
/// base. A tie between candidates that differ ONLY by path (same scheme,
/// host, AND effective port — e.g. `https://host` vs `https://host/x`, the
/// common nginx path-vhost shape) is resolved deterministically in favor
/// of the path-empty candidate; two tenant server tags differing only by
/// path must not wedge derivation into a chronic exit 2. Genuine ambiguity
/// still errors: candidates differing in scheme/host/port spelling (the
/// relay filter already guarantees endpoint equality, re-checked here so
/// the preference can never paper over a real mismatch), or a path-only
/// tie with no UNIQUE path-empty candidate (zero, or several spellings of
/// it). Zero/one candidates pass through untouched.
fn resolve_base_candidates(
    expected: &str,
    matches: BTreeSet<String>,
) -> Result<Option<String>, String> {
    if matches.len() <= 1 {
        return Ok(matches.into_iter().next());
    }
    let parsed: Vec<(String, reqwest::Url)> = matches
        .iter()
        .filter_map(|s| reqwest::Url::parse(s).ok().map(|u| (s.clone(), u)))
        .collect();
    if parsed.len() == matches.len() {
        if let Some((_, first)) = parsed.first() {
            let same_endpoint = parsed.iter().all(|(_, u)| {
                u.scheme() == first.scheme()
                    && u.host_str() == first.host_str()
                    && u.port_or_known_default() == first.port_or_known_default()
            });
            if same_endpoint {
                let path_empty: Vec<&String> = parsed
                    .iter()
                    .filter(|(_, u)| {
                        u.path() == "/" && u.query().is_none() && u.fragment().is_none()
                    })
                    .map(|(s, _)| s)
                    .collect();
                if path_empty.len() == 1 {
                    return Ok(Some(path_empty[0].clone()));
                }
            }
        }
    }
    Err(format!(
        "ambiguous blob base for {expected}: {} candidates ({})",
        matches.len(),
        matches.iter().cloned().collect::<Vec<_>>().join(", ")
    ))
}

// ---------------------------------------------------------------------------
// Check lines + report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Fail,
    Skip,
    /// Operational failure inside one check (transport, unexpected response,
    /// underivable blob base). Never a divergence verdict: exit 2 unless a
    /// FAIL elsewhere dominates (exit 1).
    Error,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
            Status::Error => "ERROR",
        }
    }
}

/// R2-3: blob-existence verdict. Divergence (any non-present probe)
/// dominates as FAIL; otherwise incomplete coverage — per-target probe
/// errors OR referenced targets skipped by the cap — is ERROR (exit 2):
/// a partially probed run is operational, not divergence, and must never
/// exit 0 for automation gating on the exit code.
fn blob_existence_status(failures: usize, probe_errors: usize, skipped_targets: usize) -> Status {
    if failures > 0 {
        Status::Fail
    } else if probe_errors > 0 || skipped_targets > 0 {
        Status::Error
    } else {
        Status::Pass
    }
}

#[derive(Debug)]
struct CheckLine {
    check: &'static str,
    status: Status,
    scope: Vec<(String, String)>,
    detail: String,
}

impl CheckLine {
    fn new(check: &'static str, status: Status) -> Self {
        Self {
            check,
            status,
            scope: Vec::new(),
            detail: String::new(),
        }
    }

    fn scope(mut self, key: &str, value: impl Into<String>) -> Self {
        self.scope.push((key.to_string(), value.into()));
        self
    }

    fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    fn human(&self) -> String {
        let mut line = format!("{} {}", self.status.as_str(), self.check);
        for (k, v) in &self.scope {
            line.push_str(&format!(" {k}={v}"));
        }
        if !self.detail.is_empty() {
            line.push_str(&format!(" -- {}", self.detail));
        }
        line
    }

    fn json(&self) -> serde_json::Value {
        let scope: serde_json::Map<String, serde_json::Value> = self
            .scope
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        serde_json::json!({
            "check": self.check,
            "status": self.status.as_str(),
            "scope": scope,
            "detail": self.detail,
        })
    }
}

// ---------------------------------------------------------------------------
// IO layer
// ---------------------------------------------------------------------------

/// Operational failure: exit code 2, never a divergence alert.
struct OpError(String);

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn op(side: &str, what: impl Into<String>) -> OpError {
    OpError(format!("node {side}: {}", what.into()))
}

struct NodeConn {
    side: &'static str,
    relay: Relay,
    relay_url: RelayUrl,
    http: reqwest::Client,
    nip11_url: String,
}

/// Everything fetched from one node, pre-comparison.
struct NodeSnapshot {
    fingerprint: Option<String>,
    registration_mode: Option<String>,
    policy_version: Option<String>,
    kinds: BTreeSet<u64>,
    registrations: Vec<RegistrationView>,
    state_roots: Vec<StateRootView>,
    malformed_registrations: usize,
    malformed_state_roots: usize,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// First value of the first tag named `name` (addressable-identifier order:
/// first d tag wins, matching the relay's own parsing).
fn first_tag_value(event: &Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.as_slice();
        if v.len() >= 2 && v[0] == name {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

/// First value of EVERY tag named `name` (extra values, e.g. key PoP
/// signatures, are not part of the compared surface).
fn tag_value_set(event: &Event, name: &str) -> BTreeSet<String> {
    event
        .tags
        .iter()
        .filter_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == name {
                Some(v[1].clone())
            } else {
                None
            }
        })
        .collect()
}

fn registration_view(event: &Event) -> Option<RegistrationView> {
    let alias = first_tag_value(event, "d")?;
    Some(RegistrationView {
        alias,
        author: event.pubkey.to_hex(),
        event_id: event.id.to_hex(),
        created_at: event.created_at.as_secs(),
        w_keys: tag_value_set(event, "w"),
        aux_keys: tag_value_set(event, "aux"),
        relays: tag_value_set(event, "relays"),
        servers: tag_value_set(event, "server"),
    })
}

fn parse_blob_ref(tag: &[String]) -> Option<BlobRef> {
    if tag.len() < 3 {
        return None;
    }
    let sha256 = tag[1].clone();
    if sha256.len() != 64
        || !sha256
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return None;
    }
    let size = tag[2].parse::<u64>().ok()?;
    Some(BlobRef { sha256, size })
}

fn state_root_view(event: &Event) -> Option<StateRootView> {
    let alias = first_tag_value(event, "d")?;
    let mut manifest: Option<BlobRef> = None;
    let mut packs = BTreeSet::new();
    for tag in event.tags.iter() {
        let v = tag.as_slice();
        if v.len() < 2 {
            continue;
        }
        match v[0].as_str() {
            "m" => {
                if manifest.is_some() {
                    return None; // exactly one m tag; malformed edition
                }
                manifest = Some(parse_blob_ref(v)?);
            }
            "pack" => {
                packs.insert(parse_blob_ref(v)?);
            }
            _ => {}
        }
    }
    Some(StateRootView {
        alias,
        author: event.pubkey.to_hex(),
        event_id: event.id.to_hex(),
        created_at: event.created_at.as_secs(),
        manifest: manifest?,
        packs,
    })
}

async fn connect(side: &'static str, url: &str, timeout: Duration) -> Result<NodeConn, OpError> {
    let relay_url =
        RelayUrl::parse(url).map_err(|e| op(side, format!("invalid relay url {url:?}: {e}")))?;
    let relay = Relay::new(relay_url.clone());
    relay
        .try_connect()
        .timeout(timeout)
        .await
        .map_err(|e| op(side, format!("connect to {url} failed or timed out: {e}")))?;
    if relay.status() != RelayStatus::Connected {
        return Err(op(side, format!("connect to {url} did not complete")));
    }
    let nip11_url = url
        .replacen("wss://", "https://", 1)
        .replacen("ws://", "http://", 1);
    let http = reqwest::Client::builder()
        .timeout(timeout)
        // No redirect chasing (mirror.rs convention): a node must not bounce
        // the watchdog to a different host.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| op(side, format!("build http client: {e}")))?;
    Ok(NodeConn {
        side,
        relay,
        relay_url,
        http,
        nip11_url,
    })
}

/// The `private_repos` advert fields the watchdog compares.
#[derive(Debug, Default, Clone)]
struct Nip11View {
    fingerprint: Option<String>,
    registration_mode: Option<String>,
    /// Preimage-format label behind the digest (`grasp-p-policy-vN`).
    /// Absent on nodes older than the field.
    policy_version: Option<String>,
    /// The advertised accepted-kind set. Compared as its own check: a
    /// wrap-kind split must be reported as a kind split, not inferred from
    /// an opaque digest that also moves for a dozen unrelated knobs.
    kinds: BTreeSet<u64>,
}

async fn fetch_nip11(node: &NodeConn) -> Result<Nip11View, OpError> {
    let response = node
        .http
        .get(&node.nip11_url)
        .header(reqwest::header::ACCEPT, "application/nostr+json")
        .send()
        .await
        .map_err(|e| {
            op(
                node.side,
                format!("NIP-11 fetch from {} failed: {e}", node.nip11_url),
            )
        })?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(op(
            node.side,
            format!(
                "NIP-11 fetch from {} returned HTTP {}",
                node.nip11_url,
                response.status().as_u16()
            ),
        ));
    }
    let body = read_body_capped(response, MAX_BODY_BYTES, node.side, "NIP-11").await?;
    let doc: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| op(node.side, format!("NIP-11 document is not valid JSON: {e}")))?;
    let private = doc.get("private_repos");
    let fingerprint = private
        .and_then(|p| p.get("policy_fingerprint"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let mode = private
        .and_then(|p| p.get("registration_mode"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let policy_version = private
        .and_then(|p| p.get("policy_version"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let kinds = private
        .and_then(|p| p.get("kinds"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|k| k.as_u64()).collect())
        .unwrap_or_default();
    Ok(Nip11View {
        fingerprint,
        registration_mode: mode,
        policy_version,
        kinds,
    })
}

async fn fetch_events(
    node: &NodeConn,
    filters: Vec<Filter>,
    timeout: Duration,
    what: &str,
) -> Result<Vec<Event>, OpError> {
    if filters.is_empty() {
        return Ok(Vec::new());
    }
    let events = node
        .relay
        .fetch_events(filters)
        .timeout(timeout)
        .await
        .map_err(|e| {
            op(
                node.side,
                format!(
                    "{what} REQ failed: {e} (GRASP-P anonymous reads must not require NIP-42 auth)"
                ),
            )
        })?;
    check_event_volume(events.len(), what).map_err(|e| op(node.side, e))?;
    // nostr-sdk admits a frame on the id it CLAIMS once that id is cached, so
    // a node can follow a genuine event with other content under the same id.
    // A node that does is not answering honestly: stop, do not compare.
    if let Some(bad) = events.iter().find(|event| event.verify().is_err()) {
        return Err(op(
            node.side,
            format!(
                "{what} REQ returned event {} whose id or signature does not verify",
                bad.id
            ),
        ));
    }
    Ok(events.iter().cloned().collect())
}

/// Per-alias union of w-keys from BOTH nodes' latest registrations — the
/// author set for kind-30641 REQs (aux keys cannot author state roots).
fn w_key_union(
    latest_a: &BTreeMap<String, RegistrationView>,
    latest_b: &BTreeMap<String, RegistrationView>,
) -> BTreeMap<String, BTreeSet<PublicKey>> {
    let mut out: BTreeMap<String, BTreeSet<PublicKey>> = BTreeMap::new();
    for (alias, reg) in latest_a.iter().chain(latest_b.iter()) {
        let entry = out.entry(alias.clone()).or_default();
        for key in &reg.w_keys {
            if let Ok(pk) = PublicKey::parse(key) {
                entry.insert(pk);
            }
        }
    }
    out
}

async fn snapshot_node(
    node: &NodeConn,
    aliases: Option<&BTreeSet<String>>,
    w_keys: &BTreeMap<String, BTreeSet<PublicKey>>,
    timeout: Duration,
) -> Result<NodeSnapshot, OpError> {
    let nip11 = fetch_nip11(node).await?;

    // kind-30640: unfiltered (discovery) or one filter per explicit alias.
    let reg_filters = match aliases {
        None => vec![Filter::new().kind(Kind::Custom(KIND_REGISTRATION))],
        Some(set) => set
            .iter()
            .map(|a| {
                Filter::new()
                    .kind(Kind::Custom(KIND_REGISTRATION))
                    .identifier(a.clone())
            })
            .collect(),
    };
    let reg_events = fetch_events(node, reg_filters, timeout, "kind-30640").await?;
    let mut registrations = Vec::new();
    let mut malformed_registrations = 0;
    for event in &reg_events {
        match registration_view(event) {
            Some(view) => registrations.push(view),
            None => malformed_registrations += 1,
        }
    }

    // kind-30641: one filter per alias, authors = w-key union.
    let sr_filters: Vec<Filter> = w_keys
        .iter()
        .filter(|(_, keys)| !keys.is_empty())
        .map(|(alias, keys)| {
            Filter::new()
                .kind(Kind::Custom(KIND_STATE_ROOT))
                .identifier(alias.clone())
                .authors(keys.iter().copied())
        })
        .collect();
    let sr_events = fetch_events(node, sr_filters, timeout, "kind-30641").await?;
    let mut state_roots = Vec::new();
    let mut malformed_state_roots = 0;
    for event in &sr_events {
        match state_root_view(event) {
            Some(view) => state_roots.push(view),
            None => malformed_state_roots += 1,
        }
    }

    Ok(NodeSnapshot {
        fingerprint: nip11.fingerprint,
        registration_mode: nip11.registration_mode,
        policy_version: nip11.policy_version,
        kinds: nip11.kinds,
        registrations,
        state_roots,
        malformed_registrations,
        malformed_state_roots,
    })
}

fn latest_registrations_by_alias(snapshot: &NodeSnapshot) -> BTreeMap<String, RegistrationView> {
    let aliases: BTreeSet<&str> = snapshot
        .registrations
        .iter()
        .map(|r| r.alias.as_str())
        .collect();
    aliases
        .into_iter()
        .filter_map(|alias| {
            latest_edition(snapshot.registrations.iter().filter(|r| r.alias == alias))
                .map(|r| (alias.to_string(), r.clone()))
        })
        .collect()
}

fn latest_state_root<'a>(
    snapshot: &'a NodeSnapshot,
    alias: &str,
    author: &str,
) -> Option<&'a StateRootView> {
    latest_edition(
        snapshot
            .state_roots
            .iter()
            .filter(|s| s.alias == alias && s.author == author),
    )
}

async fn probe_blob(
    node: &NodeConn,
    base: &str,
    sha: &str,
    declared_sizes: &BTreeSet<u64>,
    mode: BlobProbeMode,
) -> Result<BlobProbeOutcome, OpError> {
    let url = format!("{base}/{sha}");
    match mode {
        BlobProbeMode::None => unreachable!("probe_blob not called when probe=none"),
        BlobProbeMode::Head => {
            let response = node
                .http
                .head(&url)
                .send()
                .await
                .map_err(|e| op(node.side, format!("HEAD {url} failed: {e}")))?;
            classify_http_status(response.status().as_u16()).ok_or_else(|| {
                op(
                    node.side,
                    format!(
                        "HEAD {url} returned unexpected HTTP {}",
                        response.status().as_u16()
                    ),
                )
            })
        }
        BlobProbeMode::Get => {
            let mut response = node
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| op(node.side, format!("GET {url} failed: {e}")))?;
            match classify_http_status(response.status().as_u16()) {
                Some(BlobProbeOutcome::Present) => {}
                Some(other) => return Ok(other),
                None => {
                    return Err(op(
                        node.side,
                        format!(
                            "GET {url} returned unexpected HTTP {}",
                            response.status().as_u16()
                        ),
                    ))
                }
            }
            // Stream with an early-abort cap just past the largest declared
            // size so a lying server cannot make the watchdog buffer unbounded.
            let cap = declared_sizes.iter().max().copied().unwrap_or(0) + 1;
            let mut engine = sha256::Hash::engine();
            let mut total: u64 = 0;
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        total = total.saturating_add(chunk.len() as u64);
                        if total >= cap {
                            return Ok(BlobProbeOutcome::SizeMismatch);
                        }
                        engine.input(&chunk);
                    }
                    Ok(None) => break,
                    Err(e) => return Err(op(node.side, format!("GET {url} body failed: {e}"))),
                }
            }
            if sha256::Hash::from_engine(engine).to_string() != sha {
                return Ok(BlobProbeOutcome::HashMismatch);
            }
            if !declared_sizes.contains(&total) {
                return Ok(BlobProbeOutcome::SizeMismatch);
            }
            Ok(BlobProbeOutcome::Present)
        }
    }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

struct Report {
    lines: Vec<CheckLine>,
    json: serde_json::Value,
    failed: usize,
    /// Operational errors accumulated by check 4 (blob base resolution,
    /// per-target probe failures, probe-target cap skips).
    /// Non-empty with zero FAILs
    /// -> exit 2; any FAIL -> exit 1 (divergence dominates).
    op_errors: Vec<String>,
    /// Shape-invalid events excluded from comparison, per node:
    /// (malformed 30640, malformed 30641) for (A, B). Surfaced as a human-
    /// mode NOTE line; in --json they are the malformed_*_ignored fields.
    malformed: [(usize, usize); 2],
}

async fn run(cli: Cli) -> Result<(Report, ExitCode), OpError> {
    let timeout = Duration::from_secs(cli.timeout_secs.max(1));
    let now = now_secs();

    let node_a = connect("A", &cli.relay_a, timeout).await?;
    let node_b = connect("B", &cli.relay_b, timeout).await?;

    // Phase 1: NIP-11 + kind-30640 (discovery uses unfiltered REQs).
    let explicit_aliases: Option<BTreeSet<String>> = if cli.alias.is_empty() {
        None
    } else {
        Some(cli.alias.iter().cloned().collect())
    };
    let empty_w: BTreeMap<String, BTreeSet<PublicKey>> = BTreeMap::new();
    let (mut snap_a, mut snap_b) = tokio::try_join!(
        snapshot_node(&node_a, explicit_aliases.as_ref(), &empty_w, timeout),
        snapshot_node(&node_b, explicit_aliases.as_ref(), &empty_w, timeout),
    )?;

    // Alias universe: explicit list, or the union of discovered aliases.
    let aliases: BTreeSet<String> = match &explicit_aliases {
        Some(set) => set.clone(),
        None => snap_a
            .registrations
            .iter()
            .chain(snap_b.registrations.iter())
            .map(|r| r.alias.clone())
            .collect(),
    };

    // Phase 2: kind-30641 for the derived author sets.
    let latest_a = latest_registrations_by_alias(&snap_a);
    let latest_b = latest_registrations_by_alias(&snap_b);
    let w_keys = w_key_union(&latest_a, &latest_b);
    let w_keys: BTreeMap<String, BTreeSet<PublicKey>> = w_keys
        .into_iter()
        .filter(|(alias, _)| aliases.contains(alias))
        .collect();
    let (sra, srb) = tokio::try_join!(
        fetch_events(
            &node_a,
            w_keys
                .iter()
                .filter(|(_, keys)| !keys.is_empty())
                .map(|(alias, keys)| {
                    Filter::new()
                        .kind(Kind::Custom(KIND_STATE_ROOT))
                        .identifier(alias.clone())
                        .authors(keys.iter().copied())
                })
                .collect(),
            timeout,
            "kind-30641"
        ),
        fetch_events(
            &node_b,
            w_keys
                .iter()
                .filter(|(_, keys)| !keys.is_empty())
                .map(|(alias, keys)| {
                    Filter::new()
                        .kind(Kind::Custom(KIND_STATE_ROOT))
                        .identifier(alias.clone())
                        .authors(keys.iter().copied())
                })
                .collect(),
            timeout,
            "kind-30641"
        ),
    )?;
    for (snap, events) in [(&mut snap_a, sra), (&mut snap_b, srb)] {
        for event in &events {
            match state_root_view(event) {
                Some(view) => snap.state_roots.push(view),
                None => snap.malformed_state_roots += 1,
            }
        }
    }

    let mut lines: Vec<CheckLine> = Vec::new();

    // -- Check 1: fingerprint-parity ---------------------------------------
    //
    // The policy VERSION label is reported next to the digest: on a label
    // bump (e.g. v2 -> v3) every node's digest moves, so a rolling upgrade
    // fails this check for the whole window. Without the labels an operator
    // cannot tell that expected, self-healing skew from a same-version knob
    // split, and learns to ignore the check that would reveal a real one.
    let policy_version_of = |snap: &NodeSnapshot| -> String {
        snap.policy_version
            .clone()
            .unwrap_or_else(|| "unadvertised".into())
    };
    match fingerprint_parity(snap_a.fingerprint.as_deref(), snap_b.fingerprint.as_deref()) {
        Ok(()) => lines.push(
            CheckLine::new("fingerprint-parity", Status::Pass)
                .scope(
                    "fingerprint",
                    snap_a.fingerprint.clone().unwrap_or_default(),
                )
                .scope("policy-a", policy_version_of(&snap_a))
                .scope("policy-b", policy_version_of(&snap_b))
                .scope(
                    "mode-a",
                    snap_a
                        .registration_mode
                        .clone()
                        .unwrap_or_else(|| "?".into()),
                )
                .scope(
                    "mode-b",
                    snap_b
                        .registration_mode
                        .clone()
                        .unwrap_or_else(|| "?".into()),
                ),
        ),
        Err(reason) => lines.push(
            CheckLine::new("fingerprint-parity", Status::Fail)
                .scope(
                    "fingerprint-a",
                    snap_a.fingerprint.clone().unwrap_or_else(|| "none".into()),
                )
                .scope(
                    "fingerprint-b",
                    snap_b.fingerprint.clone().unwrap_or_else(|| "none".into()),
                )
                .scope("policy-a", policy_version_of(&snap_a))
                .scope("policy-b", policy_version_of(&snap_b))
                .scope(
                    "mode-a",
                    snap_a
                        .registration_mode
                        .clone()
                        .unwrap_or_else(|| "?".into()),
                )
                .scope(
                    "mode-b",
                    snap_b
                        .registration_mode
                        .clone()
                        .unwrap_or_else(|| "?".into()),
                )
                .detail(fingerprint_detail(
                    reason,
                    &snap_a.policy_version,
                    &snap_b.policy_version,
                )),
        ),
    }

    // -- Check 1b: kinds-parity --------------------------------------------
    match kinds_parity(&snap_a.kinds, &snap_b.kinds) {
        KindsParity::Match => lines.push(
            CheckLine::new("kinds-parity", Status::Pass)
                .scope("kinds", kinds_display(&snap_a.kinds)),
        ),
        KindsParity::Unavailable => {
            lines.push(CheckLine::new("kinds-parity", Status::Skip).detail(
                "neither node advertises private_repos.kinds (private repos disabled?); \
                 see the fingerprint-parity line",
            ))
        }
        KindsParity::Mismatch { only_a, only_b } => {
            let fmt = |v: &[u64]| {
                if v.is_empty() {
                    "-".to_string()
                } else {
                    v.iter().map(u64::to_string).collect::<Vec<_>>().join(",")
                }
            };
            lines.push(
                CheckLine::new("kinds-parity", Status::Fail)
                    .scope("kinds-a", kinds_display(&snap_a.kinds))
                    .scope("kinds-b", kinds_display(&snap_b.kinds))
                    .scope("only-a", fmt(&only_a))
                    .scope("only-b", fmt(&only_b))
                    .detail(
                        "the nodes accept different private-repo kinds: events of a kind \
                         only one side admits are rejected on the other and never \
                         replicate. For stream-wrap kinds (1059/21059 vs 3359/23359) flip \
                         NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND on both nodes in ONE \
                         maintenance window (runbook §2)",
                    ),
            );
        }
    }

    if aliases.is_empty() {
        lines.push(CheckLine::new("discovery", Status::Skip).detail(
            "no kind-30640 registrations on either node; registration/manifest/blob checks skipped",
        ));
    } else {
        lines.push(
            CheckLine::new("discovery", Status::Pass)
                .scope("aliases", aliases.len().to_string())
                .detail(if explicit_aliases.is_some() {
                    "explicit --alias list"
                } else {
                    "aliases discovered from union of both nodes"
                }),
        );
    }

    // -- Check 2: registration-parity ---------------------------------------
    for alias in &aliases {
        let a = latest_a.get(alias);
        let b = latest_b.get(alias);
        let line = match registration_parity(a, b) {
            RegistrationParity::Match => CheckLine::new("registration-parity", Status::Pass)
                .scope("alias", alias)
                .scope("event", short(&a.expect("match implies both").event_id)),
            RegistrationParity::MissingBoth => CheckLine::new("registration-parity", Status::Fail)
                .scope("alias", alias)
                .detail("alias not found on either node"),
            RegistrationParity::MissingOn(side) => {
                CheckLine::new("registration-parity", Status::Fail)
                    .scope("alias", alias)
                    .detail(format!("alias missing on node {}", side.label()))
            }
            RegistrationParity::Different(diffs) => {
                CheckLine::new("registration-parity", Status::Fail)
                    .scope("alias", alias)
                    .detail(diffs.join("; "))
            }
        };
        lines.push(line);
    }

    // -- Check 3: manifest-parity (THE split-view check) ---------------------
    let pairs: BTreeSet<(String, String)> = snap_a
        .state_roots
        .iter()
        .chain(snap_b.state_roots.iter())
        .map(|s| (s.alias.clone(), s.author.clone()))
        .filter(|(alias, _)| aliases.contains(alias))
        .collect();
    // Blob targets: every sha referenced by the compared latest manifests.
    let mut blob_targets: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    for (alias, author) in &pairs {
        let a = latest_state_root(&snap_a, alias, author);
        let b = latest_state_root(&snap_b, alias, author);
        for view in [a, b].into_iter().flatten() {
            blob_targets
                .entry(view.manifest.sha256.clone())
                .or_default()
                .insert(view.manifest.size);
            for pack in &view.packs {
                blob_targets
                    .entry(pack.sha256.clone())
                    .or_default()
                    .insert(pack.size);
            }
        }
        let base = CheckLine::new("manifest-parity", Status::Pass)
            .scope("alias", alias)
            .scope("author", short(author));
        let line = match manifest_parity(a, b, now, cli.max_skew_secs) {
            ManifestParity::Match => base.detail("manifest + pack set identical"),
            ManifestParity::WithinGrace { newest_created_at } => base.detail(format!(
                "views differ or one side missing, but newest edition created_at={newest_created_at} is within --max-skew-secs={} (replication in flight?)",
                cli.max_skew_secs
            )),
            ManifestParity::Withheld { missing_on, created_at } => CheckLine::new("manifest-parity", Status::Fail)
                .scope("alias", alias)
                .scope("author", short(author))
                .scope("reason", "withheld-30641")
                .detail(format!(
                    "kind-30641 present on {} but absent on {}; created_at={created_at} age={}s exceeds --max-skew-secs={}",
                    missing_on.label(),
                    match missing_on { Side::A => "B", Side::B => "A" },
                    now.saturating_sub(created_at),
                    cli.max_skew_secs
                )),
            ManifestParity::Diverged { detail } => CheckLine::new("manifest-parity", Status::Fail)
                .scope("alias", alias)
                .scope("author", short(author))
                .scope("reason", "diverged")
                .detail(detail),
        };
        lines.push(line);
    }

    // -- Blob bases (resolved on demand by check 4) --------------------------
    let all_servers = || {
        snap_a
            .registrations
            .iter()
            .chain(snap_b.registrations.iter())
            .flat_map(|r| r.servers.iter().cloned())
    };
    let resolve_bases = || -> Result<(String, String), OpError> {
        let one = |node: &NodeConn, flag: &Option<String>| -> Result<String, OpError> {
            if let Some(base) = flag {
                return Ok(base.trim_end_matches('/').to_string());
            }
            match derive_blob_base(&node.relay_url, all_servers()) {
                Ok(Some(base)) => Ok(base),
                Ok(None) => Err(op(
                    node.side,
                    "could not derive blob base: no registration `server` tag matches this \
                     node's relay endpoint (scheme/host/port); pass \
                     --blob-base-a/--blob-base-b explicitly",
                )),
                Err(e) => Err(op(
                    node.side,
                    format!("{e}; pass --blob-base-a/--blob-base-b explicitly"),
                )),
            }
        };
        Ok((
            one(&node_a, &cli.blob_base_a)?,
            one(&node_b, &cli.blob_base_b)?,
        ))
    };
    // FW-2: a blob-base failure must wedge ONLY the blob-dependent check
    // (4), never the run. Resolve once (memoized) when the check needs
    // bases; it emits its own ERROR line on failure.
    let need_bases = cli.blob_probe != BlobProbeMode::None && !blob_targets.is_empty();
    let bases: Option<Result<(String, String), OpError>> = if need_bases {
        Some(resolve_bases())
    } else {
        None
    };
    // Set when (and only when) a check actually resolved blob bases.
    let used_bases: Option<(String, String)> =
        bases.as_ref().and_then(|r| r.as_ref().ok().cloned());
    // Operational errors accumulated by check 4: echoed on stderr and in
    // the JSON report; drive exit 2 only when no divergence was emitted
    // (divergence dominates).
    let mut op_errors: Vec<String> = Vec::new();

    // -- Check 4: blob-existence ----------------------------------------------
    match cli.blob_probe {
        BlobProbeMode::None => {
            lines.push(CheckLine::new("blob-existence", Status::Skip).detail("--blob-probe=none"))
        }
        mode if blob_targets.is_empty() => lines.push(
            CheckLine::new("blob-existence", Status::Pass)
                .scope("probe", format!("{mode:?}").to_lowercase())
                .scope("probed", "0")
                .detail("no blobs referenced by any compared manifest"),
        ),
        mode => match bases.as_ref().expect("needed above") {
            Err(e) => {
                lines.push(
                    CheckLine::new("blob-existence", Status::Error)
                        .scope("probe", format!("{mode:?}").to_lowercase())
                        .detail(format!("blob base unresolved: {e}")),
                );
                op_errors.push(format!("blob-existence: blob base unresolved: {e}"));
            }
            Ok((base_a, base_b)) => {
                let (blob_targets, skipped_targets) =
                    cap_probe_targets(blob_targets, MAX_PROBE_TARGETS);
                let probes = blob_targets.iter().map(|(sha, sizes)| {
                    let node_a = &node_a;
                    let node_b = &node_b;
                    async move {
                        let (pa, pb) = tokio::try_join!(
                            probe_blob(node_a, base_a, sha, sizes, mode),
                            probe_blob(node_b, base_b, sha, sizes, mode),
                        )?;
                        Ok::<_, OpError>((sha.clone(), pa, pb))
                    }
                });
                // Bounded fan-out: at most MAX_IN_FLIGHT_PROBES probe tasks
                // (each one HEAD/GET per node) are polled concurrently.
                let results: Vec<Result<(String, BlobProbeOutcome, BlobProbeOutcome), OpError>> =
                    stream::iter(probes)
                        .buffer_unordered(MAX_IN_FLIGHT_PROBES)
                        .collect()
                        .await;
                // Per-target operational errors no longer abort the run: the
                // check keeps the data verdicts it got and reports the rest
                // as ERROR, so one broken route cannot mask divergence.
                let mut failures: Vec<String> = Vec::new();
                let mut probe_errors: Vec<String> = Vec::new();
                let mut probed = 0usize;
                for result in results {
                    match result {
                        Ok((sha, pa, pb)) => {
                            probed += 1;
                            if pa != BlobProbeOutcome::Present || pb != BlobProbeOutcome::Present {
                                failures.push(format!(
                                    "{} A={} B={}",
                                    short(&sha),
                                    pa.code(),
                                    pb.code()
                                ));
                            }
                        }
                        Err(e) => probe_errors.push(e.to_string()),
                    }
                }
                op_errors.extend(probe_errors.iter().cloned());
                // R2-3: targets skipped by the cap mean the run probed only
                // part of the referenced set — incomplete coverage is an
                // operational error (exit 2), never a clean PASS.
                if skipped_targets > 0 {
                    op_errors.push(format!(
                        "blob-existence: target cap {MAX_PROBE_TARGETS} reached; {skipped_targets} referenced blob(s) NOT probed this run (partial coverage)"
                    ));
                }
                let status =
                    blob_existence_status(failures.len(), probe_errors.len(), skipped_targets);
                let mut line = CheckLine::new("blob-existence", status)
                    .scope("probe", format!("{mode:?}").to_lowercase())
                    .scope("probed", probed.to_string());
                if skipped_targets > 0 {
                    line = line.scope("skipped", skipped_targets.to_string());
                }
                if !probe_errors.is_empty() {
                    line = line.scope("errors", probe_errors.len().to_string());
                }
                let mut detail_parts: Vec<String> = Vec::new();
                if skipped_targets > 0 {
                    detail_parts.push(format!(
                        "target cap {MAX_PROBE_TARGETS} reached; {skipped_targets} referenced blob(s) NOT probed this run"
                    ));
                }
                if !failures.is_empty() {
                    let shown = failures.len().min(5);
                    line = line.scope("failed", failures.len().to_string());
                    detail_parts.push(format!(
                        "{}{}",
                        failures[..shown].join("; "),
                        if failures.len() > shown {
                            format!("; +{} more", failures.len() - shown)
                        } else {
                            String::new()
                        }
                    ));
                }
                if !probe_errors.is_empty() {
                    let shown = probe_errors.len().min(3);
                    detail_parts.push(format!(
                        "probe error(s): {}{}",
                        probe_errors[..shown].join("; "),
                        if probe_errors.len() > shown {
                            format!("; +{} more", probe_errors.len() - shown)
                        } else {
                            String::new()
                        }
                    ));
                }
                if !detail_parts.is_empty() {
                    line = line.detail(detail_parts.join("; "));
                }
                lines.push(line);
            }
        },
    }

    node_a.relay.disconnect();
    node_b.relay.disconnect();

    // -- Report ------------------------------------------------------------------
    // Exit code (FW-2): divergence dominates — any FAIL means exit 1 even if
    // operational errors also occurred; operational errors alone mean exit 2;
    // otherwise 0. Completed check results are ALWAYS emitted before the exit
    // code is decided, so an op error can never mask a detected divergence.
    let failed = lines.iter().filter(|l| l.status == Status::Fail).count();
    let passed = lines.iter().filter(|l| l.status == Status::Pass).count();
    let skipped = lines.iter().filter(|l| l.status == Status::Skip).count();
    let errored = lines.iter().filter(|l| l.status == Status::Error).count();
    let exit_code: u8 = if failed > 0 {
        1
    } else if !op_errors.is_empty() {
        2
    } else {
        0
    };
    let (base_a_json, base_b_json) = match &used_bases {
        Some((a, b)) => (
            serde_json::Value::String(a.clone()),
            serde_json::Value::String(b.clone()),
        ),
        None => (serde_json::Value::Null, serde_json::Value::Null),
    };
    let json = serde_json::json!({
        "tool": "ngit-private-watchdog",
        "report_version": 1,
        "ok": exit_code == 0,
        "exit_code": exit_code,
        "now": now,
        "nodes": {
            "a": {
                "relay": cli.relay_a,
                "blob_base": base_a_json,
                "nip11_policy_fingerprint": snap_a.fingerprint,
                "nip11_registration_mode": snap_a.registration_mode,
                "malformed_30640_ignored": snap_a.malformed_registrations,
                "malformed_30641_ignored": snap_a.malformed_state_roots,
            },
            "b": {
                "relay": cli.relay_b,
                "blob_base": base_b_json,
                "nip11_policy_fingerprint": snap_b.fingerprint,
                "nip11_registration_mode": snap_b.registration_mode,
                "malformed_30640_ignored": snap_b.malformed_registrations,
                "malformed_30641_ignored": snap_b.malformed_state_roots,
            },
        },
        "params": {
            "timeout_secs": cli.timeout_secs,
            "max_skew_secs": cli.max_skew_secs,
            "blob_probe": format!("{:?}", cli.blob_probe).to_lowercase(),
            "aliases": aliases,
        },
        "checks": lines.iter().map(CheckLine::json).collect::<Vec<_>>(),
        "operational_errors": op_errors,
        "summary": {
            "total": lines.len(),
            "pass": passed,
            "fail": failed,
            "skip": skipped,
            "error": errored,
        },
    });
    Ok((
        Report {
            lines,
            json,
            failed,
            op_errors,
            malformed: [
                (snap_a.malformed_registrations, snap_a.malformed_state_roots),
                (snap_b.malformed_registrations, snap_b.malformed_state_roots),
            ],
        },
        ExitCode::from(exit_code),
    ))
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json_mode = cli.json;
    match run(cli).await {
        Ok((report, code)) => {
            if json_mode {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report.json).expect("json")
                );
            } else {
                for line in &report.lines {
                    println!("{}", line.human());
                }
                // Malformed 30640/30641 events are excluded from comparison;
                // in human mode the counts would otherwise be invisible
                // (--json carries them as malformed_*_ignored per node).
                for (side, (reg, sr)) in [("A", report.malformed[0]), ("B", report.malformed[1])] {
                    if reg > 0 || sr > 0 {
                        println!(
                            "NOTE malformed-events node={side} ignored-30640={reg} ignored-30641={sr} -- shape-invalid events excluded from comparison"
                        );
                    }
                }
            }
            if report.failed > 0 {
                // Alert channel: stderr is what systemd journals and cron mail
                // surface. Every FAIL line is echoed here even in --json mode.
                for line in report.lines.iter().filter(|l| l.status == Status::Fail) {
                    eprintln!("{}", line.human());
                }
                eprintln!("WATCHDOG ALERT: {} check(s) failed", report.failed);
            }
            // Operational errors (check 4) also land on stderr so
            // journal/cron consumers see them in all output modes.
            for e in &report.op_errors {
                eprintln!("WATCHDOG OPERATIONAL ERROR: {e}");
            }
            code
        }
        Err(e) => {
            eprintln!("WATCHDOG OPERATIONAL ERROR: {e}");
            if json_mode {
                println!(
                    "{}",
                    serde_json::json!({
                        "tool": "ngit-private-watchdog",
                        "report_version": 1,
                        "ok": false,
                        "exit_code": 2,
                        "operational_error": e.to_string(),
                    })
                );
            }
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (pure comparison logic)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(alias: &str, id: &str, created_at: u64) -> RegistrationView {
        RegistrationView {
            alias: alias.to_string(),
            author: "aa".repeat(32),
            event_id: id.to_string(),
            created_at,
            w_keys: BTreeSet::from(["aa".repeat(32)]),
            aux_keys: BTreeSet::new(),
            relays: BTreeSet::from(["wss://node-a".to_string()]),
            servers: BTreeSet::from(["https://node-a".to_string()]),
        }
    }

    fn blob(sha: &str, size: u64) -> BlobRef {
        BlobRef {
            sha256: sha.to_string(),
            size,
        }
    }

    fn state(alias: &str, author: &str, id: &str, created_at: u64, m_sha: &str) -> StateRootView {
        StateRootView {
            alias: alias.to_string(),
            author: author.to_string(),
            event_id: id.to_string(),
            created_at,
            manifest: blob(m_sha, 100),
            packs: BTreeSet::from([blob("p1", 10), blob("p2", 20)]),
        }
    }

    // -- latest_edition ------------------------------------------------------

    #[test]
    fn latest_edition_empty() {
        let v: Vec<RegistrationView> = vec![];
        assert!(latest_edition(v.iter()).is_none());
    }

    #[test]
    fn latest_edition_picks_highest_created_at() {
        let alias = "a".repeat(32);
        let old = reg(&alias, &"f".repeat(64), 100);
        let new = reg(&alias, &"0".repeat(64), 200);
        let v = [old, new];
        assert_eq!(latest_edition(v.iter()).unwrap().event_id, "0".repeat(64));
    }

    #[test]
    fn latest_edition_tie_breaks_to_lowest_id() {
        // Equal created_at: the LOWEST id wins (NIP-01 tie-break, mirroring
        // registration.rs::is_newer_than_stored).
        let alias = "a".repeat(32);
        let high = reg(&alias, &"f".repeat(64), 100);
        let low = reg(&alias, &"0".repeat(64), 100);
        let v = [high, low];
        assert_eq!(latest_edition(v.iter()).unwrap().event_id, "0".repeat(64));
        // Order of iteration must not matter.
        let high = reg(&alias, &"f".repeat(64), 100);
        let low = reg(&alias, &"0".repeat(64), 100);
        let v = [low, high];
        assert_eq!(latest_edition(v.iter()).unwrap().event_id, "0".repeat(64));
    }

    // -- grace window -----------------------------------------------------------

    #[test]
    fn grace_boundary_is_exclusive() {
        // age == window: still within grace. age == window + 1: beyond.
        assert!(!beyond_grace(1000, 700, 300));
        assert!(beyond_grace(1001, 700, 300));
        // Future-dated edition (author clock ahead) is always within grace.
        assert!(!beyond_grace(1000, 5000, 300));
    }

    // -- manifest_parity ---------------------------------------------------------

    #[test]
    fn manifest_parity_match_ignores_edition_ids() {
        let alias = "a".repeat(32);
        let author = "w".repeat(64);
        // Same content, different edition id/created_at: views agree.
        let x = state(&alias, &author, &"1".repeat(64), 100, "m1");
        let y = state(&alias, &author, &"2".repeat(64), 150, "m1");
        assert_eq!(
            manifest_parity(Some(&x), Some(&y), 10_000, 300),
            ManifestParity::Match
        );
    }

    #[test]
    fn manifest_parity_missing_within_grace() {
        let alias = "a".repeat(32);
        let author = "w".repeat(64);
        let x = state(&alias, &author, &"1".repeat(64), 950, "m1");
        // now - created_at = 50 <= 300: not yet an accusation.
        assert_eq!(
            manifest_parity(Some(&x), None, 1000, 300),
            ManifestParity::WithinGrace {
                newest_created_at: 950
            }
        );
        assert_eq!(
            manifest_parity(None, Some(&x), 1000, 300),
            ManifestParity::WithinGrace {
                newest_created_at: 950
            }
        );
    }

    #[test]
    fn manifest_parity_missing_beyond_grace_is_withheld() {
        let alias = "a".repeat(32);
        let author = "w".repeat(64);
        let x = state(&alias, &author, &"1".repeat(64), 600, "m1");
        assert_eq!(
            manifest_parity(Some(&x), None, 1000, 300),
            ManifestParity::Withheld {
                missing_on: Side::B,
                created_at: 600
            }
        );
        assert_eq!(
            manifest_parity(None, Some(&x), 1000, 300),
            ManifestParity::Withheld {
                missing_on: Side::A,
                created_at: 600
            }
        );
    }

    #[test]
    fn manifest_parity_diverged_beyond_grace() {
        let alias = "a".repeat(32);
        let author = "w".repeat(64);
        let x = state(&alias, &author, &"1".repeat(64), 500, "m1");
        let y = state(&alias, &author, &"2".repeat(64), 600, "m2"); // different manifest
        match manifest_parity(Some(&x), Some(&y), 1000, 300) {
            ManifestParity::Diverged { detail } => {
                assert!(detail.contains("manifest"), "detail: {detail}");
            }
            other => panic!("expected Diverged, got {other:?}"),
        }
    }

    #[test]
    fn manifest_parity_diverged_within_grace() {
        let alias = "a".repeat(32);
        let author = "w".repeat(64);
        let x = state(&alias, &author, &"1".repeat(64), 900, "m1");
        let y = state(&alias, &author, &"2".repeat(64), 950, "m2");
        // Newest involved created_at (950) is 50s old: in-flight, not divergence.
        assert_eq!(
            manifest_parity(Some(&x), Some(&y), 1000, 300),
            ManifestParity::WithinGrace {
                newest_created_at: 950
            }
        );
    }

    #[test]
    fn manifest_parity_pack_difference_detected() {
        let alias = "a".repeat(32);
        let author = "w".repeat(64);
        let x = state(&alias, &author, &"1".repeat(64), 500, "m1");
        let mut y = state(&alias, &author, &"2".repeat(64), 500, "m1");
        y.packs.insert(blob("p3", 30)); // extra pack on one side
        match manifest_parity(Some(&x), Some(&y), 1000, 300) {
            ManifestParity::Diverged { detail } => {
                assert!(detail.contains("packs only on second"), "detail: {detail}");
            }
            other => panic!("expected Diverged, got {other:?}"),
        }
    }

    #[test]
    fn manifest_parity_size_mismatch_detected() {
        // Same sha, different DECLARED size: not the same blob reference.
        let alias = "a".repeat(32);
        let author = "w".repeat(64);
        let x = state(&alias, &author, &"1".repeat(64), 500, "m1");
        let mut y = state(&alias, &author, &"2".repeat(64), 500, "m1");
        y.manifest.size = 999;
        assert!(matches!(
            manifest_parity(Some(&x), Some(&y), 1000, 300),
            ManifestParity::Diverged { .. }
        ));
    }

    // -- registration_parity ------------------------------------------------------

    #[test]
    fn registration_parity_match_and_missing() {
        let alias = "a".repeat(32);
        let x = reg(&alias, &"1".repeat(64), 100);
        let y = reg(&alias, &"1".repeat(64), 100);
        assert_eq!(
            registration_parity(Some(&x), Some(&y)),
            RegistrationParity::Match
        );
        assert_eq!(
            registration_parity(Some(&x), None),
            RegistrationParity::MissingOn(Side::B)
        );
        assert_eq!(
            registration_parity(None, Some(&y)),
            RegistrationParity::MissingOn(Side::A)
        );
        assert_eq!(
            registration_parity(None, None),
            RegistrationParity::MissingBoth
        );
    }

    #[test]
    fn registration_parity_reports_differing_fields() {
        let alias = "a".repeat(32);
        let x = reg(&alias, &"1".repeat(64), 100);
        let mut y = reg(&alias, &"2".repeat(64), 200);
        y.aux_keys.insert("bb".repeat(32));
        match registration_parity(Some(&x), Some(&y)) {
            RegistrationParity::Different(diffs) => {
                assert!(diffs.iter().any(|d| d.contains("event-id")), "{diffs:?}");
                assert!(diffs.iter().any(|d| d.contains("aux")), "{diffs:?}");
            }
            other => panic!("expected Different, got {other:?}"),
        }
    }

    // -- fingerprint_parity ---------------------------------------------------------

    #[test]
    fn fingerprint_parity_compares() {
        assert!(fingerprint_parity(Some("abc"), Some("abc")).is_ok());
        assert!(fingerprint_parity(Some("abc"), Some("def")).is_err());
        assert!(fingerprint_parity(None, Some("abc"))
            .unwrap_err()
            .contains("node A"));
        assert!(fingerprint_parity(Some("abc"), None)
            .unwrap_err()
            .contains("node B"));
        assert!(fingerprint_parity(None, None)
            .unwrap_err()
            .contains("neither"));
    }

    // -- kinds_parity -----------------------------------------------------------------

    /// The accepted-kind set is compared as a SET, on its own check: a
    /// wrap-kind split is a per-data-class divergence (wraps accepted on one
    /// node are refused on the other and never replicate) and must be named,
    /// not folded into the fingerprint digest.
    #[test]
    fn kinds_parity_is_a_set_comparison() {
        let set = |v: &[u64]| -> BTreeSet<u64> { v.iter().copied().collect() };

        // Order and duplicates in the advert cannot matter (BTreeSet).
        assert_eq!(
            kinds_parity(&set(&[30640, 3359, 23359]), &set(&[23359, 30640, 3359])),
            KindsParity::Match
        );

        // The migration-window split: A still dual-accepts, B has retired.
        let dual = set(&[1059, 3359, 21059, 23359, 30640, 30641]);
        let strict = set(&[3359, 23359, 30640, 30641]);
        assert_eq!(
            kinds_parity(&dual, &strict),
            KindsParity::Mismatch {
                only_a: vec![1059, 21059],
                only_b: vec![],
            }
        );
        assert_eq!(
            kinds_parity(&strict, &dual),
            KindsParity::Mismatch {
                only_a: vec![],
                only_b: vec![1059, 21059],
            }
        );

        // Neither side advertises: nothing to compare — fingerprint-parity
        // already reports "private repos disabled?", so this must not
        // duplicate it as a FAIL.
        assert_eq!(
            kinds_parity(&BTreeSet::new(), &BTreeSet::new()),
            KindsParity::Unavailable
        );
        // One side advertising and the other not IS a divergence.
        assert!(matches!(
            kinds_parity(&strict, &BTreeSet::new()),
            KindsParity::Mismatch { .. }
        ));

        assert_eq!(kinds_display(&set(&[3359, 30640])), "3359,30640");
        assert_eq!(kinds_display(&BTreeSet::new()), "none");
    }

    /// A fingerprint mismatch has two very different causes and the operator
    /// must be told which: a label bump moves EVERY node's digest for the
    /// duration of a rolling upgrade (transient, self-healing), while a
    /// same-version mismatch is a real acceptance divergence.
    #[test]
    fn fingerprint_detail_separates_version_skew_from_knob_split() {
        let v2 = Some("grasp-p-policy-v2".to_string());
        let v3 = Some("grasp-p-policy-v3".to_string());

        let skew = fingerprint_detail("mismatch".into(), &v2, &v3);
        assert!(skew.contains("VERSION SKEW"), "{skew}");
        assert!(skew.contains("grasp-p-policy-v2") && skew.contains("grasp-p-policy-v3"));

        let split = fingerprint_detail("mismatch".into(), &v3, &v3);
        assert!(split.contains("SAME-VERSION knob split"), "{split}");
        assert!(!split.contains("VERSION SKEW"), "{split}");

        // Pre-advert node on ONE side is the rolling-upgrade window onto the
        // first labelled build — the likeliest real mismatch there is. It
        // must name the unlabelled node and land on the skew verdict, not
        // fall through to a bare reason with an `unadvertised` scope.
        let a_predates = fingerprint_detail("mismatch".into(), &None, &v3);
        assert!(a_predates.contains("VERSION SKEW"), "{a_predates}");
        assert!(
            a_predates.contains("node A predates the policy_version field"),
            "{a_predates}"
        );
        let b_predates = fingerprint_detail("mismatch".into(), &v3, &None);
        assert!(b_predates.contains("VERSION SKEW"), "{b_predates}");
        assert!(
            b_predates.contains("node B predates the policy_version field"),
            "{b_predates}"
        );

        // Neither side labels its policy: nothing to distinguish, so the
        // reason is passed through untouched rather than guessed at.
        let neither = fingerprint_detail("mismatch".into(), &None, &None);
        assert_eq!(neither, "mismatch");
    }

    // -- blob probing -----------------------------------------------------------------

    #[test]
    fn classify_http_status_known_codes() {
        assert_eq!(classify_http_status(200), Some(BlobProbeOutcome::Present));
        assert_eq!(classify_http_status(404), Some(BlobProbeOutcome::Missing));
        assert_eq!(
            classify_http_status(451),
            Some(BlobProbeOutcome::Denylisted)
        );
        // Anything else is operational, never a data verdict.
        assert_eq!(classify_http_status(500), None);
        assert_eq!(classify_http_status(301), None);
        assert_eq!(classify_http_status(403), None);
    }

    // -- blob-existence status (R2-3) ----------------------------------------

    #[test]
    fn blob_existence_status_partial_coverage_is_error_not_pass() {
        // Clean full-coverage run.
        assert_eq!(blob_existence_status(0, 0, 0), Status::Pass);
        // R2-3: skipped targets alone must never read as a clean pass —
        // incomplete coverage is ERROR (exit 2), not PASS (exit 0).
        assert_eq!(blob_existence_status(0, 0, 7), Status::Error);
        // Probe errors alone are already ERROR.
        assert_eq!(blob_existence_status(0, 3, 0), Status::Error);
        assert_eq!(blob_existence_status(0, 3, 7), Status::Error);
        // Divergence dominates both error kinds.
        assert_eq!(blob_existence_status(2, 0, 0), Status::Fail);
        assert_eq!(blob_existence_status(1, 3, 7), Status::Fail);
    }

    // -- derive_blob_base ---------------------------------------------------------------

    #[test]
    fn derive_blob_base_matches_relay_host() {
        let relay = RelayUrl::parse("wss://grasp-a.example.com").unwrap();
        let servers = vec![
            "https://grasp-b.example.com".to_string(),
            "https://grasp-a.example.com/".to_string(), // trailing slash trimmed
        ];
        assert_eq!(
            derive_blob_base(&relay, servers).unwrap(),
            Some("https://grasp-a.example.com".to_string())
        );
    }

    #[test]
    fn derive_blob_base_no_match() {
        let relay = RelayUrl::parse("wss://grasp-a.example.com").unwrap();
        let servers = vec!["https://unrelated.example.com".to_string()];
        assert_eq!(derive_blob_base(&relay, servers).unwrap(), None);
    }

    #[test]
    fn derive_blob_base_path_tie_prefers_empty_path() {
        // R2-4: two tenant server tags differing ONLY by path (same
        // scheme/host/effective-port) resolve to the path-empty candidate
        // deterministically — no operator flags needed.
        let relay = RelayUrl::parse("wss://grasp-a.example.com").unwrap();
        let servers = vec![
            "https://grasp-a.example.com/x".to_string(),
            "https://grasp-a.example.com".to_string(),
        ];
        assert_eq!(
            derive_blob_base(&relay, servers).unwrap(),
            Some("https://grasp-a.example.com".to_string())
        );
        // Several path-ful candidates still resolve to the one empty path.
        let servers = vec![
            "https://grasp-a.example.com/x".to_string(),
            "https://grasp-a.example.com/y/z".to_string(),
            "https://grasp-a.example.com".to_string(),
        ];
        assert_eq!(
            derive_blob_base(&relay, servers).unwrap(),
            Some("https://grasp-a.example.com".to_string())
        );
    }

    #[test]
    fn derive_blob_base_path_tie_without_empty_candidate_still_errors() {
        // R2-4: a path-only tie with NO path-empty candidate is genuine
        // ambiguity — there is no deterministic preference.
        let relay = RelayUrl::parse("wss://grasp-a.example.com").unwrap();
        let servers = vec![
            "https://grasp-a.example.com/x".to_string(),
            "https://grasp-a.example.com/y".to_string(),
        ];
        assert!(derive_blob_base(&relay, servers).is_err());
    }

    #[test]
    fn derive_blob_base_port_spelling_mismatch_still_errors() {
        // R2-4: differing port spellings (`:443` explicit vs implicit) are
        // NOT a path-only tie — two path-empty candidates with no unique
        // preference stay ambiguous.
        let relay = RelayUrl::parse("wss://grasp-a.example.com").unwrap();
        let servers = vec![
            "https://grasp-a.example.com".to_string(),
            "https://grasp-a.example.com:443".to_string(),
        ];
        assert!(derive_blob_base(&relay, servers).is_err());
    }

    #[test]
    fn resolve_base_candidates_scheme_mismatch_still_errors() {
        // R2-4: the path-only preference must never paper over a scheme
        // difference. The relay-match filter already guarantees scheme
        // equality in production, so this exercises the resolver's own
        // endpoint re-check directly (defense in depth).
        let matches = BTreeSet::from([
            "http://grasp-a.example.com".to_string(),
            "https://grasp-a.example.com".to_string(),
        ]);
        assert!(resolve_base_candidates("https://grasp-a.example.com:443", matches).is_err());
    }

    #[test]
    fn derive_blob_base_requires_matching_scheme() {
        // wss relay expects https blob bases; a plain-http server tag on the
        // same host must NOT win derivation (wrong scheme = blind oracle).
        let relay = RelayUrl::parse("wss://grasp-a.example.com").unwrap();
        let servers = vec!["http://grasp-a.example.com".to_string()];
        assert_eq!(derive_blob_base(&relay, servers).unwrap(), None);
        // ws relay expects http, not https.
        let relay = RelayUrl::parse("ws://127.0.0.1:8080").unwrap();
        let servers = vec!["https://127.0.0.1:8080".to_string()];
        assert_eq!(derive_blob_base(&relay, servers).unwrap(), None);
    }

    #[test]
    fn derive_blob_base_normalizes_default_ports() {
        // Implicit :443 and explicit :443 are the same effective port.
        let relay = RelayUrl::parse("wss://grasp-a.example.com:443").unwrap();
        let servers = vec!["https://grasp-a.example.com".to_string()];
        assert_eq!(
            derive_blob_base(&relay, servers).unwrap(),
            Some("https://grasp-a.example.com".to_string())
        );
        let relay = RelayUrl::parse("wss://grasp-a.example.com").unwrap();
        let servers = vec!["https://grasp-a.example.com:443".to_string()];
        assert_eq!(
            derive_blob_base(&relay, servers).unwrap(),
            Some("https://grasp-a.example.com:443".to_string())
        );
    }

    #[test]
    fn derive_blob_base_requires_matching_effective_port() {
        // A same-host server tag on a NON-relay port must not win derivation
        // (the watchdog must not probe arbitrary ports on the node host).
        let relay = RelayUrl::parse("wss://grasp-a.example.com").unwrap();
        let servers = vec!["https://grasp-a.example.com:8443".to_string()];
        assert_eq!(derive_blob_base(&relay, servers).unwrap(), None);
        // Explicit non-default relay port: only that port matches.
        let relay = RelayUrl::parse("wss://grasp-a.example.com:8443").unwrap();
        assert_eq!(
            derive_blob_base(&relay, vec!["https://grasp-a.example.com".to_string()]).unwrap(),
            None
        );
        assert_eq!(
            derive_blob_base(&relay, vec!["https://grasp-a.example.com:8443".to_string()]).unwrap(),
            Some("https://grasp-a.example.com:8443".to_string())
        );
        // ws relay on a test port: http on the same port matches, http on
        // the default port does not.
        let relay = RelayUrl::parse("ws://127.0.0.1:8080").unwrap();
        assert_eq!(
            derive_blob_base(&relay, vec!["http://127.0.0.1:8080".to_string()]).unwrap(),
            Some("http://127.0.0.1:8080".to_string())
        );
        assert_eq!(
            derive_blob_base(&relay, vec!["http://127.0.0.1".to_string()]).unwrap(),
            None
        );
    }

    // -- resource caps (FW-1) ---------------------------------------------------

    #[test]
    fn cap_probe_targets_keeps_all_under_cap() {
        let mut targets: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        for i in 0..3 {
            targets.insert(format!("{i:064}"), BTreeSet::from([i as u64]));
        }
        let (kept, skipped) = cap_probe_targets(targets, MAX_PROBE_TARGETS);
        assert_eq!(kept.len(), 3);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn cap_probe_targets_bounds_and_reports_skips() {
        let mut targets: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        for i in 0..(MAX_PROBE_TARGETS + 7) {
            targets.insert(format!("{i:064}"), BTreeSet::from([i as u64]));
        }
        let (kept, skipped) = cap_probe_targets(targets, MAX_PROBE_TARGETS);
        assert_eq!(kept.len(), MAX_PROBE_TARGETS);
        assert_eq!(skipped, 7);
        // Deterministic: the kept set is the lowest shas (BTreeMap order).
        assert!(kept.contains_key(&format!("{:064}", MAX_PROBE_TARGETS - 1)));
        assert!(!kept.contains_key(&format!("{:064}", MAX_PROBE_TARGETS)));
    }

    #[test]
    fn check_event_volume_bounds_retention() {
        assert!(check_event_volume(MAX_EVENTS_PER_REQ, "kind-30640").is_ok());
        let err = check_event_volume(MAX_EVENTS_PER_REQ + 1, "kind-30641").unwrap_err();
        assert!(err.contains("kind-30641"), "{err}");
        assert!(err.contains("volume cap"), "{err}");
    }

    // -- parsing helpers -------------------------------------------------------------------

    #[test]
    fn parse_blob_ref_validates_shape() {
        let sha = "ab".repeat(32);
        assert_eq!(
            parse_blob_ref(&["m".into(), sha.clone(), "42".into()]),
            Some(blob(&sha, 42))
        );
        // Too few values.
        assert_eq!(parse_blob_ref(&["m".into(), sha.clone()]), None);
        // Bad hash shape.
        assert_eq!(
            parse_blob_ref(&["m".into(), "XYZ".into(), "1".into()]),
            None
        );
        // Bad size.
        assert_eq!(parse_blob_ref(&["m".into(), sha, "nan".into()]), None);
    }

    #[test]
    fn cli_rejects_bad_alias() {
        assert!(parse_alias(&"ab".repeat(16)).is_ok());
        assert!(parse_alias(&"AB".repeat(16)).is_err());
        assert!(parse_alias("short").is_err());
    }
}
