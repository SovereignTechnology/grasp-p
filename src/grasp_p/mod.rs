//! GRASP-P: multi-tenant private git repositories on a public grasp relay.
//!
//! The server is content-blind: it verifies outer signatures against
//! registered opaque pubkeys and moves ciphertext (events + blobs). It never
//! inspects wrap contents and never creates bare git repos for private repos.
//!
//! Everything here is inert unless `NGIT_GRASP_P_REPOS_ENABLE=true`: when the
//! flag is off no [`PrivateService`] is constructed and every private kind
//! (30640/30641 + the stream-wrap kinds 3359/23359 and, while legacy accept
//! is on, 1059/21059) falls through to the existing admission handling. The
//! one exception is [`build_info`]: both binaries name the build in
//! `--version` whatever the flag says.

pub mod admission;
pub mod blob_store;
pub mod blossom_auth;
pub mod build_info;
#[cfg(test)]
mod config_sources;
pub mod denylist;
pub mod gc;
pub mod host;
pub mod meta;
pub mod metrics_endpoint;
pub mod mirror;
pub mod quota;
pub mod rate;
pub mod registration;
pub mod relay_labels;
pub mod state_root;
pub mod write_keys;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use nostr::prelude::{Event, Filter, Kind, PublicKey};
use nostr_sdk::local_relay::WritePolicyResult;
use tokio::task::JoinHandle;

use crate::config::{Config, RegistrationMode};
use crate::nostr::policy::{reject_error, reject_restricted};
use crate::nostr::SharedDatabase;

pub use blob_store::{BlobDescriptor, BlobStore, UploadSink};
pub use blossom_auth::{BlossomAuth, BlossomOp};
pub use meta::{MetaEnv, RegistrationRecord};

/// Private-repo event kinds.
pub const KIND_REGISTRATION: u16 = 30640;
pub const KIND_STATE_ROOT: u16 = 30641;
/// LEGACY stream-wrap envelope: NIP-59's gift-wrap kind. GRASP-P stream
/// wraps were never NIP-59 (no `p` tag, no kind-13 seal, symmetric AEAD, a
/// derived deterministic signer), so riding 1059 bought nothing while
/// forcing the spec to require relays to violate NIP-59's relay behaviours.
/// Accepted only while `accept_legacy_wrap_kind` is on (default true) so
/// wraps published by pre-migration clients keep flowing.
pub const KIND_WRAP: u16 = 1059;
/// LEGACY ephemeral stream-wrap envelope (see [`KIND_WRAP`]).
pub const KIND_EPHEMERAL_WRAP: u16 = 21059;
/// CORD stream wrap: the dedicated regular/stored envelope kind that
/// replaces the stream-wrap use of 1059. Genuine NIP-59 gift-wrapped
/// invites stay on 1059 and are not a git-node concern (they go to inbox
/// relays).
pub const KIND_STREAM_WRAP: u16 = 3359;
/// Ephemeral analog of [`KIND_STREAM_WRAP`], replacing 21059. Never stored,
/// never quota-charged; a server admission capability only (no client
/// currently emits it).
pub const KIND_EPHEMERAL_STREAM_WRAP: u16 = 23359;
/// NIP-56 report (Phase-4b D3 intake: log + metric only).
pub const KIND_REPORT: u16 = 1984;

/// Is `kind` an admissible STORED stream-wrap envelope?
///
/// Single source of truth for stream-wrap kind membership: the admission
/// arms, the sync filters/holds and the NIP-11 advert all route through
/// this (or [`stream_wrap_kinds`]) so the accepted set can never drift
/// between what we admit, what we ask peers for, and what we advertise.
pub fn is_stream_wrap_kind(kind: u16, accept_legacy: bool) -> bool {
    kind == KIND_STREAM_WRAP || (accept_legacy && kind == KIND_WRAP)
}

/// Is `kind` an admissible EPHEMERAL stream-wrap envelope?
pub fn is_ephemeral_stream_wrap_kind(kind: u16, accept_legacy: bool) -> bool {
    kind == KIND_EPHEMERAL_STREAM_WRAP || (accept_legacy && kind == KIND_EPHEMERAL_WRAP)
}

/// Is `kind` one of the LEGACY stream-wrap envelopes (stored or ephemeral)?
///
/// Kind membership only — [`is_stream_wrap_kind`] decides admission. This
/// exists so a node with `accept_legacy_wrap_kind = false` can REFUSE these
/// kinds outright instead of letting them fall through to the public
/// related-event policy (see `PrivateService::rejects_retired_wrap_kind`).
pub fn is_legacy_wrap_kind(kind: u16) -> bool {
    kind == KIND_WRAP || kind == KIND_EPHEMERAL_WRAP
}

/// The admitted STORED stream-wrap kinds, newest first. Feeds the derived
/// sync filter (one filter carrying every accepted kind, so held/in-flight
/// legacy wraps still drain) and the NIP-11 `kinds` advert.
pub fn stream_wrap_kinds(accept_legacy: bool) -> Vec<u16> {
    let mut kinds = vec![KIND_STREAM_WRAP];
    if accept_legacy {
        kinds.push(KIND_WRAP);
    }
    kinds
}

/// The admitted EPHEMERAL stream-wrap kinds (NIP-11 advert only —
/// ephemeral wraps are deliberately never synced).
pub fn ephemeral_stream_wrap_kinds(accept_legacy: bool) -> Vec<u16> {
    let mut kinds = vec![KIND_EPHEMERAL_STREAM_WRAP];
    if accept_legacy {
        kinds.push(KIND_EPHEMERAL_WRAP);
    }
    kinds
}

/// Hard cap on concurrent in-flight blob uploads. Together with the in-flight
/// byte reservation this bounds transient `<blob_root>/tmp` disk usage, file
/// descriptors, and inodes BEFORE any request body bytes land on disk.
const MAX_CONCURRENT_UPLOADS: u32 = 64;

/// Book-keeping for uploads whose bytes are still streaming to tmp files.
#[derive(Debug, Default)]
struct InflightUploads {
    bytes: u64,
    count: u32,
}

/// RAII reservation of in-flight upload capacity: declared bytes are counted
/// against the global budget from BEFORE the temp file is opened until the
/// sink is finished or dropped.
#[derive(Debug)]
pub struct UploadReservation {
    inflight: Arc<parking_lot::Mutex<InflightUploads>>,
    bytes: u64,
}

impl Drop for UploadReservation {
    fn drop(&mut self) {
        let mut guard = self.inflight.lock();
        guard.bytes = guard.bytes.saturating_sub(self.bytes);
        guard.count = guard.count.saturating_sub(1);
    }
}

/// Errors surfaced by the blob routes, carrying their HTTP status.
#[derive(Debug)]
pub enum BlobError {
    /// 400 — malformed request / hash mismatch.
    BadRequest(String),
    /// 401 — missing/malformed/expired authorization; also every refused
    /// `GET /list/<pubkey>`, whatever the cause.
    Unauthorized(String),
    /// 403 — valid auth event signed by a key not authorized for the alias.
    Forbidden(String),
    /// 411 — PUT without Content-Length.
    LengthRequired,
    /// 413 — blob exceeds the per-blob cap (pre- or mid-stream).
    TooLarge,
    /// 451 — denylisted content.
    Denylisted,
    /// 507 — tenant/repo/global quota exceeded.
    QuotaExceeded,
    /// 429 — per-write-key rate limit exhausted (client write spam).
    RateLimited {
        /// `Retry-After` hint in seconds.
        retry_after_secs: u64,
    },
    /// 500 — internal failure.
    Internal(String),
}

impl BlobError {
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized(_) => 401,
            Self::Forbidden(_) => 403,
            Self::LengthRequired => 411,
            Self::TooLarge => 413,
            Self::Denylisted => 451,
            Self::QuotaExceeded => 507,
            Self::RateLimited { .. } => 429,
            Self::Internal(_) => 500,
        }
    }

    pub fn reason(&self) -> String {
        match self {
            Self::BadRequest(reason) | Self::Unauthorized(reason) | Self::Forbidden(reason) => {
                reason.clone()
            }
            Self::LengthRequired => "Content-Length header is required".to_string(),
            Self::TooLarge => "blob exceeds the maximum blob size".to_string(),
            Self::Denylisted => "content unavailable for legal reasons".to_string(),
            Self::QuotaExceeded => "quota exceeded".to_string(),
            Self::RateLimited { .. } => "rate-limited; retry later".to_string(),
            Self::Internal(reason) => reason.clone(),
        }
    }

    /// The reason a client is told, in `X-Reason`.
    ///
    /// The same as [`Self::reason`] except for an internal failure, whose
    /// text carries database and filesystem errors: paths, table names and
    /// library messages that are nobody's business outside the node. The
    /// client learns only that the failure was internal; the HTTP layer
    /// logs the detail. Code inside the node (the mirror's retry classes
    /// and log lines) keeps reading `reason()`.
    pub fn public_reason(&self) -> String {
        match self {
            Self::Internal(_) => INTERNAL_ERROR_PUBLIC_REASON.to_string(),
            other => other.reason(),
        }
    }
}

/// What a client is told about any internal failure of the blob routes.
pub const INTERNAL_ERROR_PUBLIC_REASON: &str = "internal error";

/// Extracted private-repo config subset (cheap to clone into sinks/tasks).
#[derive(Debug, Clone)]
pub struct PrivateConfig {
    pub domain: String,
    /// This node's public address without a scheme: the domain, plus the
    /// mount path when the server runs under `NGIT_BASE_PATH`
    /// (`Config::service_address`). The blob routes live under the mount
    /// path, so every URL handed to a client is built from this.
    pub service_address: String,
    pub registration_mode: RegistrationMode,
    pub pow_bits: u8,
    pub tenant_whitelist: Vec<String>,
    pub max_blob_bytes: u64,
    pub max_event_bytes: u64,
    pub quota_tenant_bytes: u64,
    pub quota_repo_bytes: u64,
    pub global_budget_bytes: u64,
    pub max_aliases_per_tenant: u32,
    pub max_write_keys_per_alias: u32,
    pub state_history_editions: u32,
    pub gc_grace_secs: u64,
    pub gc_interval_secs: u64,
    /// Stored and not enforced yet (issue 1).
    pub offboard_retention_secs: u64,
    /// Dual-accept the LEGACY stream-wrap kinds (1059/21059) alongside the
    /// dedicated 3359/23359. Default true: the server must accept 3359
    /// BEFORE any client emits it, and legacy wraps already in flight (or
    /// held for out-of-order reprocess) must keep draining.
    pub accept_legacy_wrap_kind: bool,
    // Phase 2 blob mirror knobs.
    pub mirror_enable: bool,
    pub mirror_peer_urls: Option<Vec<String>>,
    pub mirror_max_concurrency: u32,
    pub mirror_fetch_timeout_secs: u64,
    /// Phase-4b B2: base delay for the per-blob mirror retry backoff
    /// (transient failure classes only — see mirror.rs taxonomy).
    pub mirror_retry_base_secs: u64,
    /// Phase-4b B2: backoff cap; also the fixed retry interval for
    /// 404-on-all-peers (possible late upload).
    pub mirror_retry_max_secs: u64,
    /// SSRF guard: when false (default), mirror fetch peers resolving to
    /// loopback/private/link-local/unspecified/multicast IPs are dropped and
    /// only https peers are contacted. Tests set this true to mirror over
    /// http://127.0.0.1.
    pub mirror_allow_private_ips: bool,
    /// R6 parity fingerprint over the admission-affecting config.
    pub policy_fingerprint: String,
    /// Phase-4b A1: per-write-key token bucket capacity for CLIENT-submitted
    /// private writes (30641/1059/21059 events + blob PUTs). 0 = unlimited
    /// (limiter disabled). Node-local DoS protection only — synced/loopback
    /// traffic bypasses it, so it has no cross-node convergence impact and is
    /// deliberately NOT part of `policy_fingerprint`.
    pub write_rate_capacity: u32,
    /// Phase-4b A1: bucket refill in tokens per minute.
    pub write_rate_refill_per_min: u32,
    /// Phase-4b A2: per-(tenant, alias) token bucket capacity for same-tenant
    /// kind-30640 REPLACEMENTS (0 = unlimited). Cross-node acceptance knob —
    /// part of the `policy_fingerprint` preimage (v3): a same-tenant newer
    /// 30640 accepted on one node may be cadence-rejected on another running
    /// different knobs, and the divergence heals only via refill + sync
    /// redelivery, so paired nodes must run identical values.
    pub registration_replace_capacity: u32,
    /// Phase-4b A2: bucket refill in replacements per hour.
    pub registration_replace_refill_per_hour: u32,
    /// Phase-4b D1: denylist file paths (CSV-expanded). Node-local legal
    /// config — deliberately NOT part of `policy_fingerprint`.
    pub denylist_paths: Vec<String>,
    /// Phase-4b D1: denylist reload interval in seconds (0 = reload
    /// disabled; the boot-time set is kept).
    pub denylist_reload_secs: u64,
}

impl PrivateConfig {
    fn from_config(config: &Config) -> Self {
        Self {
            domain: config.domain.clone(),
            service_address: config.service_address(),
            registration_mode: config.private_registration_mode,
            pow_bits: config.private_pow_bits,
            tenant_whitelist: config.private_tenant_whitelist_entries(),
            max_blob_bytes: config.private_max_blob_bytes,
            max_event_bytes: config.private_max_event_bytes,
            quota_tenant_bytes: config.private_quota_tenant_bytes,
            quota_repo_bytes: config.private_quota_repo_bytes,
            global_budget_bytes: config.private_global_budget_bytes,
            max_aliases_per_tenant: config.private_max_aliases_per_tenant,
            max_write_keys_per_alias: config.private_max_write_keys_per_alias,
            state_history_editions: config.private_state_history_editions,
            gc_grace_secs: config.private_gc_grace_secs,
            gc_interval_secs: config.private_gc_interval_secs,
            offboard_retention_secs: config.private_offboard_retention_secs,
            accept_legacy_wrap_kind: config.private_accept_legacy_wrap_kind,
            mirror_enable: config.private_mirror_enable,
            mirror_peer_urls: config.private_mirror_peer_url_entries(),
            mirror_max_concurrency: config.private_mirror_max_concurrency,
            mirror_fetch_timeout_secs: config.private_mirror_fetch_timeout_secs,
            mirror_retry_base_secs: config.private_mirror_retry_base_secs,
            mirror_retry_max_secs: config.private_mirror_retry_max_secs,
            mirror_allow_private_ips: config.private_mirror_allow_private_ips,
            policy_fingerprint: policy_fingerprint(config),
            write_rate_capacity: config.private_write_rate_capacity,
            write_rate_refill_per_min: config.private_write_rate_refill_per_min,
            registration_replace_capacity: config.private_registration_replace_capacity,
            registration_replace_refill_per_hour: config
                .private_registration_replace_refill_per_hour,
            denylist_paths: config.private_denylist_paths(),
            denylist_reload_secs: config.private_denylist_reload_secs,
        }
    }
}

/// R6 config-parity fingerprint: a short hash of the admission-affecting
/// private-repo config. Both nodes of a pair must advertise the SAME value
/// (compare via NIP-11 `private_repos.policy_fingerprint` or the startup
/// log); a mismatch means registrations can be accepted on one node and
/// silently rejected on the other (per-repo desync).
///
/// The raw tenant whitelist feeds the hash but is never exposed. The domain
/// set is `sorted({own service address} ∪ {bootstrap peer})` so a correctly-paired
/// two-node setup (each bootstrapped to the other) hashes the same set on
/// both sides.
/// Label of the `policy_fingerprint` PREIMAGE FORMAT, bumped whenever a
/// knob joins or leaves the preimage.
///
/// Advertised verbatim alongside the digest (NIP-11
/// `private_repos.policy_version`) because the digest alone cannot
/// distinguish the two very different reasons a pair's fingerprints
/// differ: a version skew mid-rolling-upgrade (both nodes correctly
/// configured, one not yet restarted — every node's digest moves on a label
/// bump) versus a same-version knob split (a real, lasting divergence in
/// what the two nodes accept). Operators who cannot tell those apart learn
/// to ignore the one signal that reveals a genuine split view.
pub const POLICY_VERSION: &str = "grasp-p-policy-v3";

pub fn policy_fingerprint(config: &Config) -> String {
    use bitcoin_hashes::{sha256, Hash};

    fn strip_url(value: &str) -> String {
        let v = value.trim().trim_end_matches('/');
        for prefix in ["wss://", "ws://", "https://", "http://"] {
            if let Some(rest) = v.strip_prefix(prefix) {
                return rest.to_string();
            }
        }
        v.to_string()
    }

    // The service address, not the bare domain: under NGIT_BASE_PATH the
    // peer names this node by a URL that carries the mount path, and the two
    // nodes of a pair must hash the same set. Identical to the domain for a
    // root deployment.
    let mut domains = vec![strip_url(&config.service_address())];
    if let Some(ref bootstrap) = config.sync_bootstrap_relay_url {
        domains.push(strip_url(bootstrap));
    }
    domains.sort();
    domains.dedup();

    let mut whitelist = config.private_tenant_whitelist_entries();
    whitelist.sort();

    let preimage = format!(
        // v1 -> v2 (Phase-4b A2): the 30640 replacement-cadence knobs now
        // affect cross-node acceptance (a same-tenant newer edition can be
        // accepted on one node and cadence-rejected on another), so they
        // join the preimage AND the label bumps — a v1/v2 fingerprint
        // mismatch is itself the divergence signal an operator must see.
        // The A1 client-write-rate knobs are deliberately ABSENT: they are
        // node-local DoS protection (sync/loopback traffic bypasses them)
        // with no convergence impact. The D1 denylist knobs are likewise
        // ABSENT: the denylist is node-local LEGAL config (per-jurisdiction
        // takedown lists legitimately differ across paired nodes) and its
        // enforcement (451s, purges) never changes event acceptance.
        //
        // v2 -> v3 (wire-kind migration): `accept_legacy_wrap_kind` decides
        // which stream-wrap KINDS this node admits, which is DIRECT
        // acceptance behaviour — a paired node with legacy accept OFF would
        // reject a 1059 stream wrap its peer accepted and stored, i.e.
        // exactly the split-view divergence this fingerprint exists to
        // detect. The label bumps with it so a v2/v3 mismatch is itself the
        // signal an operator must see on a rolling upgrade.
        "{}|mode={}|pow_bits={}|whitelist={}|max_event_bytes={}|max_blob_bytes={}|quota_tenant={}|quota_repo={}|global_budget={}|max_aliases={}|max_keys={}|replace_capacity={}|replace_refill_per_hour={}|accept_legacy_wrap_kind={}|domains={}",
        POLICY_VERSION,
        config.private_registration_mode,
        config.private_pow_bits,
        whitelist.join(","),
        config.private_max_event_bytes,
        config.private_max_blob_bytes,
        config.private_quota_tenant_bytes,
        config.private_quota_repo_bytes,
        config.private_global_budget_bytes,
        config.private_max_aliases_per_tenant,
        config.private_max_write_keys_per_alias,
        config.private_registration_replace_capacity,
        config.private_registration_replace_refill_per_hour,
        config.private_accept_legacy_wrap_kind,
        domains.join(","),
    );
    let digest = sha256::Hash::hash(preimage.as_bytes()).to_string();
    digest[..16].to_string()
}

/// Upper bound on how far into the future a private event's `created_at` may
/// be (15 minutes of clock skew). NIP-59 gift wraps are backdated, never
/// future-dated, and a future-dated 30640/30641 is an attack twice over: it
/// wins latest-edition selection on naive readers, AND — worse — it EVICTS
/// the real latest edition from the relay DB (addressable replacement keeps
/// only the newest per coordinate), a data-availability attack. Anything
/// beyond clock skew is refused at admission.
pub(crate) const MAX_FUTURE_SKEW_SECS: u64 = 900;

/// Reject events dated implausibly far in the future. Returns Some(rejection)
/// when the event must be refused, None when it may proceed.
pub(crate) fn check_not_future_dated(event: &Event) -> Option<WritePolicyResult> {
    let now = nostr::prelude::Timestamp::now().as_secs();
    if event.created_at.as_secs() > now + MAX_FUTURE_SKEW_SECS {
        Some(crate::nostr::policy::reject_invalid(
            "event created_at is too far in the future",
        ))
    } else {
        None
    }
}

/// The GRASP-P private-repo subsystem: registration/key/quota/blob state plus
/// admission handlers and blob-route logic. Constructed once per relay when
/// `NGIT_GRASP_P_REPOS_ENABLE=true`.
pub struct PrivateService {
    pub(crate) cfg: PrivateConfig,
    pub(crate) meta: MetaEnv,
    pub(crate) blobs: BlobStore,
    pub(crate) database: SharedDatabase,
    /// Node-local legal takedown list (Phase-4b D1), behind an RwLock for
    /// the periodic reload's atomic swap. Deliberately NOT part of the
    /// policy_fingerprint: paired nodes in different jurisdictions may
    /// legitimately enforce different lists.
    pub(crate) denylist: denylist::SharedDenylist,
    /// What the boot load read from each denylist file, held until the
    /// reload task takes it as its starting state (`denylist::spawn`).
    denylist_boot_files: parking_lot::Mutex<Option<Vec<denylist::FileState>>>,
    /// In-flight upload reservations (see [`UploadReservation`]).
    inflight: Arc<parking_lot::Mutex<InflightUploads>>,
    /// Phase 2: hot cache of 30641/1059 events rejected before their 30640
    /// arrived (out-of-order sync). Drained by the sync layer on 30640 Accept.
    sync_rejected: crate::sync::private_index::PrivateRejectedIndex,
    /// FG: dedup for the `incoming_rejected` registration-conflict alert,
    /// keyed on loser event id (replays from boot reconcile / sync
    /// redelivery must not re-alert forever).
    conflict_alert_dedup: parking_lot::Mutex<registration::ConflictAlertDedup>,
    /// Phase 2: blob mirror job queue sender (set by [`Self::spawn_mirror`],
    /// absent when mirroring is disabled).
    mirror_tx: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<mirror::MirrorJob>>,
    /// Phase-4b B2: per-blob mirror retry state (attempt count + next-eligible
    /// Instant) for the exponential backoff. In-memory only — a restart
    /// resets every blob to the base interval (documented behavior).
    pub(crate) mirror_retry: Arc<parking_lot::Mutex<HashMap<String, mirror::RetryState>>>,
    /// FS-5 (review L2-F7): per-(sha256, reason) dedup for the mirror's
    /// all-peers-failed warn — the metric carries the per-attempt signal;
    /// the warn logs the first failure and re-logs once per 10 minutes.
    pub(crate) mirror_failure_log: parking_lot::Mutex<mirror::FailureLogDedup>,
    /// Phase-4b A1: per-write-key token bucket bounding CLIENT-submitted
    /// private writes (30641/1059/21059 + blob PUT). Synced/loopback traffic
    /// never touches this — the WS arms gate on the loopback:0 marker, and
    /// the mirror never PUTs.
    write_rate: parking_lot::Mutex<rate::KeyedTokenBucket>,
    /// Phase-4b A2: per-(tenant, alias) token bucket bounding same-tenant
    /// kind-30640 REPLACEMENT cadence (client AND synced live admission —
    /// this knob is consensus-relevant, hence the fingerprint preimage;
    /// only boot_reconcile replays bypass it).
    registration_replace_rate: parking_lot::Mutex<rate::KeyedTokenBucket>,
}

impl std::fmt::Debug for PrivateService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateService")
            .field("domain", &self.cfg.domain)
            .field("mode", &self.cfg.registration_mode)
            .finish()
    }
}

impl PrivateService {
    /// Construct the service: open meta env + blob store, load the denylist,
    /// and reconcile the meta index against the relay DB's kind-30640 events.
    pub async fn new(config: &Config, database: SharedDatabase) -> Result<Arc<Self>> {
        let meta_path = PathBuf::from(config.effective_private_meta_path());
        let blob_path = PathBuf::from(config.effective_private_blob_path());

        let meta = MetaEnv::open(&meta_path)?;
        let blobs = BlobStore::open(&blob_path)?;

        let denylist_paths = config.private_denylist_paths();
        let denylist_files = denylist::load_boot(&denylist_paths)?;
        let denylist = denylist::union(&denylist_files);
        crate::metrics::set_private_denylist_entries(denylist.len());

        let svc = Arc::new(Self {
            cfg: PrivateConfig::from_config(config),
            meta,
            blobs,
            database,
            denylist: std::sync::Arc::new(std::sync::RwLock::new(denylist)),
            denylist_boot_files: parking_lot::Mutex::new(Some(denylist_files)),
            inflight: Arc::new(parking_lot::Mutex::new(InflightUploads::default())),
            sync_rejected: crate::sync::private_index::PrivateRejectedIndex::new(
                std::time::Duration::from_secs(config.rejected_hot_cache_duration_secs),
                // R2-1(b): refill-aware per-registration retry eligibility,
                // derived from the cadence refill knob (clamped; NGIT_TEST
                // caps at 1s).
                crate::sync::private_index::registration_retry_period(
                    config.private_registration_replace_refill_per_hour,
                ),
                // Sized from the event limit so the budget always has room
                // for a useful number of the largest events admission lets
                // through.
                crate::sync::private_index::hold_budget_bytes(config.private_max_event_bytes),
            ),
            conflict_alert_dedup: parking_lot::Mutex::new(registration::ConflictAlertDedup::new(
                registration::CONFLICT_ALERT_DEDUP_TTL,
            )),
            mirror_tx: std::sync::OnceLock::new(),
            mirror_retry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            mirror_failure_log: parking_lot::Mutex::new(mirror::FailureLogDedup::new()),
            write_rate: parking_lot::Mutex::new(rate::KeyedTokenBucket::new(
                config.private_write_rate_capacity,
                config.private_write_rate_refill_per_min as f64 / 60.0,
            )),
            registration_replace_rate: parking_lot::Mutex::new(rate::KeyedTokenBucket::new(
                config.private_registration_replace_capacity,
                config.private_registration_replace_refill_per_hour as f64 / 3600.0,
            )),
        });

        svc.boot_reconcile().await?;
        svc.refresh_gauges();
        tracing::info!(
            mode = %svc.cfg.registration_mode,
            policy_fingerprint = %svc.cfg.policy_fingerprint,
            mirror_enabled = svc.cfg.mirror_enable,
            configured_peer = ?config.sync_bootstrap_relay_url,
            build = build_info::version(),
            "GRASP-P private repositories enabled"
        );
        Ok(svc)
    }

    /// Phase 2: the out-of-order rejected-event hold (30641 by alias, 1059
    /// by outer author). Used by the sync layer's pre-filter and
    /// 30640-Accept reprocess hook. Rejections enter it through
    /// [`Self::note_rejected`] only.
    pub fn sync_rejected(&self) -> &crate::sync::private_index::PrivateRejectedIndex {
        &self.sync_rejected
    }

    /// The one place that decides what the node keeps of a rejected 30640,
    /// 30641 or stored stream wrap. Other kinds are ignored.
    ///
    /// - A DEPENDENCY rejection (`admission::is_dependency_rejection`: one a
    ///   later registration can turn into an acceptance) holds the full
    ///   event, so the registration's arrival can retry it. This is what
    ///   keeps out-of-order replication whole, on both paths.
    /// - Any other rejection of a SYNCED event keeps the id only: the event
    ///   will not become acceptable by waiting for a registration, but
    ///   without the id the node would fetch and validate it again on every
    ///   delivery until the peer stops offering it.
    /// - Any other rejection of a CLIENT's event keeps nothing: the client
    ///   has its answer and decides whether to send again.
    ///
    /// The client path reaches this from `admission::admit`, the sync path
    /// from the sync manager's rejection hook, which also sees the events
    /// rejected before admission (blacklist, deletion gate). Each rejection
    /// is noted once.
    pub fn note_rejected(&self, event: &Event, message: &str, synced: bool) {
        use crate::sync::private_index::{HoldDropReason, HoldOutcome};

        let Some(held_kind) =
            admission::held_kind(event.kind.as_u16(), self.cfg.accept_legacy_wrap_kind)
        else {
            return;
        };
        let full_hold = if admission::is_dependency_rejection(held_kind, message) {
            match held_kind {
                admission::HeldKind::Registration => {
                    Some(self.sync_rejected.add_registration(event.clone()))
                }
                // A dependency rejection implies a d tag (the shape check
                // comes first), so the `None` here is only a guard.
                admission::HeldKind::StateRoot => admission::d_tag(event)
                    .map(|alias| self.sync_rejected.add_state_root(alias, event.clone())),
                admission::HeldKind::StreamWrap => Some(
                    self.sync_rejected
                        .add_wrap(event.pubkey.to_hex(), event.clone()),
                ),
            }
        } else {
            None
        };
        let outcome = match full_hold {
            Some(outcome) => outcome,
            None if synced => match self.sync_rejected.add_id_only(event.id) {
                // The id is kept; what was not kept is the event.
                HoldOutcome::IdOnly => HoldOutcome::Dropped(HoldDropReason::NotHoldable),
                other => other,
            },
            None => HoldOutcome::Dropped(HoldDropReason::NotHoldable),
        };
        if let HoldOutcome::Dropped(reason) = outcome {
            crate::metrics::record_private_hold_dropped(reason.as_label());
        }
    }

    /// Phase-4b A1: spend one token from the CLIENT write bucket of
    /// `pubkey_hex` (a secp256k1 write key). Callers MUST gate on the
    /// submission path — this is for client WS events and blob PUTs only,
    /// never for synced/loopback/reprocess traffic (the whole point is that
    /// quota-uncharged spam like 21059 floods gets capped without touching
    /// convergence traffic).
    pub fn client_write_allowed(&self, pubkey_hex: &str) -> bool {
        self.write_rate.lock().try_take(pubkey_hex, 1)
    }

    /// Phase-4b A1: `Retry-After` hint (seconds) for a rate-limited blob PUT.
    pub fn write_rate_retry_after_secs(&self) -> u64 {
        self.write_rate.lock().retry_after_secs(1)
    }

    /// Phase-4b A2: spend one same-tenant 30640 REPLACEMENT token for
    /// `(tenant_hex, alias)`. Live admission only (client AND synced) —
    /// boot_reconcile replays must not consume budget (they re-run events
    /// this node already admitted).
    pub(crate) fn registration_replace_allowed(&self, tenant_hex: &str, alias: &str) -> bool {
        self.registration_replace_rate
            .lock()
            .try_take(&format!("{tenant_hex}:{alias}"), 1)
    }

    /// Rebuild registrations/key_claims/tenant_aliases from the relay DB's
    /// kind-30640 events when the meta index is missing or stale. Ledger and
    /// blob claims are authoritative in meta and never recomputed here.
    async fn boot_reconcile(&self) -> Result<()> {
        let filter = Filter::new().kind(Kind::Custom(KIND_REGISTRATION));
        let events = self
            .database
            .query(filter)
            .await
            .map_err(|e| anyhow::anyhow!("boot reconcile query failed: {e}"))?;

        let mut applied = 0_usize;
        for event in events.into_iter() {
            let alias = event.tags.iter().find_map(|t| {
                let v = t.clone().to_vec();
                if v.len() >= 2 && v[0] == "d" {
                    Some(v[1].clone())
                } else {
                    None
                }
            });
            let Some(alias) = alias else { continue };
            if !registration::is_valid_alias(&alias) {
                continue;
            }

            let needs_apply = {
                let txn = self.meta.read_txn()?;
                match self.meta.get_registration(&txn, &alias)? {
                    None => true,
                    Some(record) => record.event_id != event.id.to_hex(),
                }
            };
            if needs_apply {
                // Re-run the registration handler. Admission-mode gates only
                // apply to aliases that are NEW to the meta index, so a
                // same-tenant replay of an event this node already admitted
                // skips them: an operator flipping mode (e.g. open ->
                // whitelist via the WP-E shipped-default change) keeps every
                // existing tenant across reboots.
                //
                // Whitelist/pow changes ARE re-enforced when the replay
                // rebuilds a missing meta index (stored == None) or the
                // incoming event wins a cross-tenant conflict — those are
                // intentionally treated as fresh admissions for consistency.
                // A rejected replay is NON-DESTRUCTIVE: the reject path
                // performs no meta mutation, prunes no relay-DB coordinate,
                // and only warn-logs below — mode enforcement belongs at
                // admission time, never as retroactive eviction. (Operator
                // remedy for a meta-wipe rebuild under a stricter mode:
                // temporarily reopen / whitelist the affected npubs,
                // restart, then flip back.)
                //
                // The §3.2 conflict merge makes PAIRWISE conflicts converge
                // order-independently: if the DB somehow holds two
                // conflicting registrations (e.g. a missed eviction prune),
                // reprocessing them in any order converges on the
                // deterministic winner — the loser is either rejected
                // (arrived after the winner) or evicted (arrived first), and
                // its coordinate is pruned below. Chains of ≥3 parties (A
                // and B share one key, B and C share another, A and C are
                // disjoint) are NOT fully order-independent: depending on
                // arrival order, a later registrant's disjoint-key seat can
                // be transiently dropped when its evictor is itself evicted,
                // and recovery relies on sync redelivery of the dropped
                // event (the earliest registrant always keeps its seat in
                // every order).
                //
                // Phase-4b A2: REPLAY admission — the replacement-cadence
                // bucket is skipped (these events were already admitted
                // once; replays must not consume budget).
                let outcome = registration::handle_replay(self, &event);
                self.prune_evicted_registrations(&outcome.prune).await;
                if matches!(outcome.result, WritePolicyResult::Accept) {
                    applied += 1;
                } else {
                    tracing::warn!(
                        alias = %alias,
                        "boot reconcile: stored 30640 no longer passes registration checks"
                    );
                }
            }
        }
        if applied > 0 {
            tracing::info!("private meta boot reconcile applied {applied} registration(s)");
        }
        Ok(())
    }

    /// Update the aggregate gauges (aliases + global ledger bytes).
    pub(crate) fn refresh_gauges(&self) {
        if let Ok(txn) = self.meta.read_txn() {
            if let Ok(count) = self.meta.registrations_len(&txn) {
                crate::metrics::set_private_aliases_total(count);
            }
            if let Ok(total) = quota::global_total(&self.meta, &txn) {
                crate::metrics::set_private_ledger_global_bytes(total);
            }
        }
    }

    /// A registration that exists in meta, is not tombstoned, AND whose 30640
    /// coordinate still exists in the relay DB (self-healing vs missed
    /// deletes — see exit test 8).
    pub(crate) async fn live_registration(
        &self,
        alias: &str,
    ) -> Result<Option<RegistrationRecord>> {
        let record = {
            let txn = self.meta.read_txn()?;
            self.meta.get_registration(&txn, alias)?
        };
        let Some(record) = record else {
            return Ok(None);
        };
        if record.tombstoned_at.is_some() {
            return Ok(None);
        }
        let Ok(tenant_pk) = PublicKey::from_hex(&record.tenant_hex) else {
            return Ok(None);
        };
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_REGISTRATION))
            .author(tenant_pk)
            .identifier(alias)
            .limit(1);
        let events = self
            .database
            .query(filter)
            .await
            .map_err(|e| anyhow::anyhow!("liveness query failed: {e}"))?;
        if events.is_empty() {
            return Ok(None);
        }
        Ok(Some(record))
    }

    // ------------------------------------------------------------------
    // admit_event arms
    // ------------------------------------------------------------------

    /// Kind 30640. Applies identically to user-submitted and synced events.
    pub async fn handle_registration(&self, event: &Event) -> WritePolicyResult {
        let outcome = registration::handle(self, event);
        self.prune_evicted_registrations(&outcome.prune).await;
        record_event_metric(KIND_REGISTRATION, &outcome.result);
        outcome.result
    }

    /// Remove the relay-DB 30640 coordinate of every registration the §3.2
    /// conflict merge evicted, so naive REQ readers cannot resolve a merge
    /// loser as live. Best-effort: the meta store is the admission authority
    /// (the loser's keys are already unclaimed), and a lingering event is
    /// re-rejected — and re-pruned — whenever it is next reprocessed.
    async fn prune_evicted_registrations(&self, evicted: &[(String, String)]) {
        for (tenant_hex, alias) in evicted {
            let Ok(tenant_pk) = PublicKey::from_hex(tenant_hex) else {
                continue;
            };
            let filter = Filter::new()
                .kind(Kind::Custom(KIND_REGISTRATION))
                .author(tenant_pk)
                .identifier(alias);
            if let Err(e) = self.database.delete(filter).await {
                tracing::warn!(
                    alias = %alias,
                    tenant = %tenant_hex,
                    error = %e,
                    "failed to prune evicted registration from the relay DB"
                );
            }
        }
    }

    /// Kind 30641.
    pub async fn handle_state_root(&self, event: &Event) -> WritePolicyResult {
        let result = state_root::handle(self, event).await;
        if matches!(result, WritePolicyResult::Accept) {
            // Phase 2: pull any referenced blobs we don't hold from a peer.
            // No-op when mirroring is disabled (sender never set) or when all
            // blobs are already local (client-push path on the origin node).
            mirror::enqueue_for_state_root(self, event);
        }
        record_event_metric(KIND_STATE_ROOT, &result);
        result
    }

    /// Stream wraps: kinds 3359 / 23359, plus the legacy 1059 / 21059 while
    /// `accept_legacy_wrap_kind` is on. Both kind families are treated
    /// IDENTICALLY here — same gating, same quota charging, same
    /// hold/reprocess, same per-id wrap-charge idempotency; the only thing
    /// the kind changes is the metric label.
    ///
    /// Returns `None` for wraps from unregistered keys. That is NOT a
    /// fall-through to the public related-event path: per §3.2 the caller
    /// REJECTS (see `builder.rs`, the wrap arms) — accepting referenced
    /// wraps from unregistered keys made every deregistered rekey address
    /// permanently floodable. The stored arm additionally holds the event
    /// keyed by its outer author for out-of-order reprocess.
    pub async fn try_handle_wrap(
        &self,
        event: &Event,
        ephemeral: bool,
    ) -> Option<WritePolicyResult> {
        // Metrics keep the wire kind so the 1059 -> 3359 migration is
        // observable per-kind on a live node.
        let kind = event.kind.as_u16();

        let author_hex = event.pubkey.to_hex();
        let claim = match write_keys::find_claim(&self.meta, &author_hex) {
            Ok(claim) => claim,
            Err(e) => {
                tracing::warn!("private wrap key lookup failed: {e}");
                let result = reject_error("private meta store failure");
                record_event_metric(kind, &result);
                return Some(result);
            }
        };
        // Unregistered outer key → fall through to public handling.
        let (alias, record, _role) = claim?;

        // From here on this subsystem owns the event.
        if let Some(rejection) = check_not_future_dated(event) {
            // Metered like every other rejection arm: without this a
            // future-dated wrap flood is invisible in
            // ngit_private_events_rejected_total, which is exactly the
            // series an operator watches for wrap abuse.
            record_event_metric(kind, &rejection);
            return Some(rejection);
        }
        let event_json_len = event.as_json().len() as u64;
        if event_json_len > self.cfg.max_event_bytes {
            let result = reject_restricted(admission::OVERSIZE_REJECT_MESSAGE);
            record_event_metric(kind, &result);
            return Some(result);
        }

        // Alias must still be live (registration deleted → reject).
        match self.live_registration(&alias).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                let result = reject_restricted(admission::WRAP_UNREGISTERED_KEY);
                record_event_metric(kind, &result);
                return Some(result);
            }
            Err(e) => {
                tracing::warn!("private wrap liveness check failed: {e}");
                let result = reject_error("private liveness check failed");
                record_event_metric(kind, &result);
                return Some(result);
            }
        }

        // Quota: charge only stored wraps (3359/1059), never ephemeral
        // (23359/21059).
        // §4b idempotency: admit_event runs BEFORE the library's save_event,
        // and duplicates/replays (client retries, P2 loopback:0 sync) still
        // reach this policy — charge only wraps the DB does not already hold,
        // otherwise every replay would inflate the ledger.
        if !ephemeral {
            match self.database.check_id(&event.id).await {
                Ok(nostr_sdk::prelude::DatabaseEventStatus::NotExistent) => {}
                Ok(_) => {
                    // Already saved (the DB will answer Duplicate) or deleted
                    // (the deletion gate handles it): never re-charge.
                    let result = WritePolicyResult::Accept;
                    record_event_metric(kind, &result);
                    return Some(result);
                }
                Err(e) => {
                    tracing::warn!("private wrap duplicate check failed: {e}");
                    let result = reject_error("private liveness check failed");
                    record_event_metric(kind, &result);
                    return Some(result);
                }
            }
            let event_id_hex = event.id.to_hex();
            // The async `check_id` above races: two concurrent deliveries of the
            // SAME wrap id can both observe NotExistent before either is saved,
            // then both charge event_bytes for one stored copy. Make the charge
            // idempotent per id INSIDE the serialized meta write txn: the first
            // delivery charges + records the id; any concurrent one sees the id
            // already charged and accepts without re-charging.
            let charge_result = self.meta.with_write(|meta, txn| {
                apply_wrap_charge_txn(
                    meta,
                    txn,
                    &self.cfg,
                    &record,
                    &alias,
                    event_json_len,
                    &event_id_hex,
                )
            });
            match charge_result {
                Ok(WrapCharge::Charged) => {}
                Ok(WrapCharge::QuotaExceeded) => {
                    let result = reject_restricted("quota exceeded");
                    record_event_metric(kind, &result);
                    return Some(result);
                }
                Ok(WrapCharge::Unregistered) => {
                    // R2-C: the registration died or was taken over between
                    // the liveness check and the charge txn. Distinct from
                    // the genuine "unregistered key" rejection above: an
                    // honest same-tenant rotation trips this arm too, and
                    // that race is TRANSIENT (retry under the new record
                    // succeeds) — callers must be able to tell them apart
                    // (verify round 3); notably the cord-git client treats
                    // any "unregistered" message as its widenable case.
                    let result = reject_restricted(admission::WRAP_REGISTRATION_CHANGED);
                    record_event_metric(kind, &result);
                    return Some(result);
                }
                Err(e) => {
                    tracing::warn!("private wrap quota update failed: {e}");
                    let result = reject_error("private meta store failure");
                    record_event_metric(kind, &result);
                    return Some(result);
                }
            }
            self.refresh_gauges();
        }

        let result = WritePolicyResult::Accept;
        record_event_metric(kind, &result);
        Some(result)
    }

    /// NIP-09 follow-up (cord-git !13 verify-round): free the key claims of
    /// every private 30640 this author-valid deletion targets — by `a`-tag
    /// coordinate or `e`-tag event id. Key claims are otherwise freed only
    /// by a newer registration edition (the diff in `registration::handle`),
    /// so a deleted registration left its claims dangling forever: a member
    /// could squat an epoch's (derivable) rekey addresses, delete their own
    /// registration, and permanently wedge every future rotation whose widen
    /// lists those keys ("write key already registered"). Claims must die
    /// with the registration. The NIP-09 cutoff is honored: a registration
    /// edition NEWER than the deletion keeps its claims (a replayed stale
    /// deletion cannot wipe a live edition). An honored deletion also runs
    /// the shared death cleanup (blob-claim stripping, spec release,
    /// event-column reset, ring deletion — see `free_registration_claims`);
    /// the `t:`/`g:` event-byte stranding remains the pre-existing !1/!4
    /// backlog.
    pub fn free_claims_for_deleted_registrations(&self, event: &Event) {
        let author_hex = event.pubkey.to_hex();
        let deletion_at = event.created_at.as_secs();
        let mut coords: Vec<String> = Vec::new();
        let mut ids: Vec<String> = Vec::new();
        for tag in event.tags.iter() {
            let v = tag.clone().to_vec();
            if v.len() < 2 {
                continue;
            }
            match v[0].as_str() {
                "a" => {
                    let mut parts = v[1].splitn(3, ':');
                    if let (Some(kind), Some(pubkey), Some(alias)) =
                        (parts.next(), parts.next(), parts.next())
                    {
                        if kind == "30640"
                            && pubkey == author_hex
                            && registration::is_valid_alias(alias)
                        {
                            coords.push(alias.to_string());
                        }
                    }
                }
                "e" => ids.push(v[1].clone()),
                _ => {}
            }
        }
        if coords.is_empty() && ids.is_empty() {
            return;
        }
        let freed = self.meta.with_write(|meta, txn| {
            let mut n = 0usize;
            for alias in &coords {
                n += free_registration_claims(meta, txn, &author_hex, alias, deletion_at)?;
            }
            if !ids.is_empty() {
                // e-tags carry only the event id — resolve it against the
                // author's own registrations' current editions.
                let aliases = meta.get_tenant_aliases(txn, &author_hex)?;
                for alias in aliases {
                    let Some(record) = meta.get_registration(txn, &alias)? else {
                        continue;
                    };
                    if ids.contains(&record.event_id) {
                        n += free_registration_claims(meta, txn, &author_hex, &alias, deletion_at)?;
                    }
                }
            }
            Ok(n)
        });
        match freed {
            Ok(n) if n > 0 => {
                tracing::info!(author = %author_hex, keys = n, "freed private key claims of deleted registration(s)");
                self.refresh_gauges();
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "failed to free private key claims of deleted registration")
            }
        }
    }

    /// NIP-62 follow-up: a vanish deletes ALL of the author's events,
    /// including their 30640s — free every claim they hold (same
    /// dangling-claim wedge as the kind-5 path). The kind-5 cutoff applies
    /// here too: registrations newer than the vanish keep their claims (a
    /// replayed stale vanish cannot wipe a re-registered edition). Death
    /// cleanup (blob-claim stripping, spec release, event-column reset,
    /// ring deletion) is shared with the other death paths via
    /// [`free_registration_claims`].
    pub fn free_claims_for_vanished_author(&self, event: &Event) {
        let author_hex = event.pubkey.to_hex();
        let vanish_at = event.created_at.as_secs();
        let freed = self.meta.with_write(|meta, txn| {
            let mut n = 0usize;
            let aliases = meta.get_tenant_aliases(txn, &author_hex)?;
            for alias in aliases {
                n += free_registration_claims(meta, txn, &author_hex, &alias, vanish_at)?;
            }
            Ok(n)
        });
        match freed {
            Ok(n) if n > 0 => {
                tracing::info!(author = %author_hex, keys = n, "freed private key claims of vanished author");
                self.refresh_gauges();
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "failed to free private key claims of vanished author")
            }
        }
    }

    // ------------------------------------------------------------------
    // Blob routes
    // ------------------------------------------------------------------

    /// Parse + verify a Blossom `Authorization` header for `op` on
    /// `expected_sha`, resolving the attribution to a live registration and
    /// requiring the signing key to be in the alias's **w** set.
    pub async fn verify_blossom_auth(
        &self,
        header: Option<&str>,
        op: BlossomOp,
        expected_sha: &str,
    ) -> Result<BlossomAuth, BlobError> {
        let auth = blossom_auth::verify_auth_shape(header, op, expected_sha, &self.cfg.domain)?;

        let record = self
            .live_registration(&auth.alias)
            .await
            .map_err(|e| BlobError::Internal(format!("liveness check failed: {e}")))?
            .ok_or_else(|| {
                BlobError::Forbidden("attributed alias is not a live registration".into())
            })?;

        if record.tenant_hex != auth.tenant_hex {
            return Err(BlobError::Forbidden(
                "a tag tenant does not match the registration".into(),
            ));
        }
        if !record.w_keys.contains(&auth.pubkey_hex) {
            return Err(BlobError::Forbidden(
                "signing key is not a write key for this alias".into(),
            ));
        }
        Ok(auth)
    }

    /// BUD-06 preflight checks for an upload of `len` bytes.
    pub async fn blob_upload_preflight(
        &self,
        auth: &BlossomAuth,
        sha256: &str,
        len: u64,
    ) -> Result<(), BlobError> {
        if auth.sha256 != sha256 {
            return Err(BlobError::BadRequest(
                "authorization does not cover this sha256".into(),
            ));
        }
        // B4: reject denylisted (taken-down) content on the WRITE path too, not
        // only on read — otherwise the same bytes could be re-uploaded and
        // re-stored. Same status the read path returns (451).
        if self.is_denylisted(sha256) {
            return Err(BlobError::Denylisted);
        }
        if len > self.cfg.max_blob_bytes {
            return Err(BlobError::TooLarge);
        }
        // Existing blobs re-upload for free (no double-charge).
        let claim = {
            let txn = self
                .meta
                .read_txn()
                .map_err(|e| BlobError::Internal(e.to_string()))?;
            self.meta
                .get_blob_claim(&txn, sha256)
                .map_err(|e| BlobError::Internal(e.to_string()))?
        };
        let needs_charge = match &claim {
            Some(claim) if claim.stored => false,
            _ => !self.blobs.exists(sha256),
        };
        if needs_charge {
            let txn = self
                .meta
                .read_txn()
                .map_err(|e| BlobError::Internal(e.to_string()))?;
            // FF (verify round 1): net the claim's pending speculative
            // release, mirroring finish()'s release-before-check ordering —
            // otherwise a declare-then-upload near the cap is 507-rejected
            // here while finish() would pass. finish() releases the spec
            // charge globally regardless of uploader, so the GLOBAL scope
            // nets for anyone; the tenant/alias scopes net only when the
            // pending charge belongs to this same (tenant, alias).
            let (same_scope, spec_bytes) = match &claim {
                Some(meta::BlobClaim {
                    spec_charge: Some(spec),
                    ..
                }) => (
                    spec.tenant == auth.tenant_hex && spec.alias == auth.alias,
                    spec.bytes,
                ),
                _ => (false, 0),
            };
            let scoped_additional = if same_scope {
                len.saturating_sub(spec_bytes)
            } else {
                len
            };
            let global_additional = len.saturating_sub(spec_bytes);
            let ledger = |key: String| {
                self.meta
                    .get_ledger_txn(&txn, &key)
                    .map_err(|e| BlobError::Internal(e.to_string()))
            };
            let tenant_entry = ledger(quota::tenant_key(&auth.tenant_hex))?;
            let alias_entry = ledger(quota::alias_key(&auth.alias))?;
            let global_entry = ledger(meta::LEDGER_GLOBAL_KEY.to_string())?;
            let ok = alias_entry.total().saturating_add(scoped_additional)
                <= self.cfg.quota_repo_bytes
                && tenant_entry.total().saturating_add(scoped_additional)
                    <= self.cfg.quota_tenant_bytes
                && global_entry.total().saturating_add(global_additional)
                    <= self.cfg.global_budget_bytes;
            if !ok {
                return Err(BlobError::QuotaExceeded);
            }
        }
        Ok(())
    }

    /// Reserve in-flight capacity for `declared_len` bytes BEFORE any body
    /// byte lands on disk. Enforces (a) a hard cap on concurrent uploads and
    /// (b) `ledger global total + reserved in-flight bytes + declared_len ≤
    /// global_budget_bytes`, so N concurrent slow streams can never exceed
    /// the global byte budget in transient tmp usage.
    ///
    /// `pending_spec_release` is the upload's own claim's speculative charge
    /// (0 when none): finish() releases it from the global scope before
    /// charging, so the check nets it out (FF — same double-count the
    /// preflight had near the cap).
    fn reserve_upload(
        &self,
        declared_len: u64,
        pending_spec_release: u64,
    ) -> Result<UploadReservation, BlobError> {
        let ledger_total = {
            let txn = self
                .meta
                .read_txn()
                .map_err(|e| BlobError::Internal(e.to_string()))?;
            quota::global_total(&self.meta, &txn).map_err(|e| BlobError::Internal(e.to_string()))?
        };
        let mut guard = self.inflight.lock();
        if guard.count >= MAX_CONCURRENT_UPLOADS {
            return Err(BlobError::QuotaExceeded);
        }
        if ledger_total
            .saturating_sub(pending_spec_release)
            .saturating_add(guard.bytes)
            .saturating_add(declared_len)
            > self.cfg.global_budget_bytes
        {
            return Err(BlobError::QuotaExceeded);
        }
        guard.count += 1;
        guard.bytes = guard.bytes.saturating_add(declared_len);
        Ok(UploadReservation {
            inflight: self.inflight.clone(),
            bytes: declared_len,
        })
    }

    /// The speculative bytes still held against this upload's own claim
    /// (released by finish() before it charges), 0 when there is no claim or
    /// no pending charge. Read-only; used to net the preflight/reserve
    /// quota math (FF).
    fn pending_spec_release(&self, sha256: &str) -> Result<u64, BlobError> {
        let txn = self
            .meta
            .read_txn()
            .map_err(|e| BlobError::Internal(e.to_string()))?;
        Ok(self
            .meta
            .get_blob_claim(&txn, sha256)
            .map_err(|e| BlobError::Internal(e.to_string()))?
            .and_then(|claim| claim.spec_charge)
            .map(|spec| spec.bytes)
            .unwrap_or(0))
    }

    /// Open a streaming upload sink after validating auth + quota like the
    /// preflight. The HTTP layer feeds `hyper::body::Incoming` frames in.
    pub async fn begin_upload(
        &self,
        auth: &BlossomAuth,
        declared_len: u64,
    ) -> Result<UploadSink, BlobError> {
        self.blob_upload_preflight(auth, &auth.sha256, declared_len)
            .await?;
        // Reserve BEFORE opening the temp file: without this, unbounded
        // concurrent PUT streams could exhaust disk/inodes/fds while each
        // one's authoritative charge only happens at finish().
        let reservation =
            self.reserve_upload(declared_len, self.pending_spec_release(&auth.sha256)?)?;
        UploadSink::create(
            self.meta.clone(),
            self.blobs.clone(),
            self.cfg.clone(),
            auth.tenant_hex.clone(),
            auth.alias.clone(),
            auth.sha256.clone(),
            declared_len,
            reservation,
            self.denylist.clone(),
        )
        .await
    }

    /// Path of a stored blob, or `None` if absent. Denylist handling (451) is
    /// the caller's job via [`Self::is_denylisted`].
    pub fn blob_path(&self, sha256: &str) -> Option<PathBuf> {
        let path = self.blobs.path_for(sha256);
        path.is_file().then_some(path)
    }

    pub fn is_denylisted(&self, sha256: &str) -> bool {
        denylist::read_set(&self.denylist).contains(sha256)
    }

    /// Remove this alias's claim on a blob (Blossom DELETE). File removal is
    /// GC's job after the grace period. Idempotent — 200 even if no claim.
    pub async fn blob_delete(&self, auth: &BlossomAuth, sha256: &str) -> Result<(), BlobError> {
        if auth.sha256 != sha256 {
            return Err(BlobError::BadRequest(
                "authorization does not cover this sha256".into(),
            ));
        }
        let alias = auth.alias.clone();
        self.meta
            .with_write(|meta, txn| {
                if let Some(mut claim) = meta.get_blob_claim(txn, sha256)? {
                    if claim.aliases.iter().any(|a| a == &alias) {
                        claim.aliases.retain(|a| a != &alias);
                        // R2-D (verify round 2): same release condition as
                        // the FH ring-trim / R2-A death cleanup — the
                        // DELETING alias was carrying the speculative charge
                        // and other aliases still reference the sha: release
                        // it against the recorded scope/bytes, exactly once
                        // (the survivor re-charges on its next referencing
                        // 30641). Otherwise the DELETE pins the charge on
                        // the deleting scope until claim death or upload.
                        let release_spec = !claim.aliases.is_empty()
                            && claim
                                .spec_charge
                                .as_ref()
                                .map(|spec| spec.alias == alias)
                                .unwrap_or(false);
                        if release_spec {
                            let spec = claim.spec_charge.take().expect("spec charge present");
                            quota::release_spec_charge(meta, txn, &spec)?;
                        }
                        if claim.aliases.is_empty() && claim.unreferenced_since.is_none() {
                            claim.unreferenced_since =
                                Some(nostr::prelude::Timestamp::now().as_secs());
                        }
                        meta.put_blob_claim(txn, sha256, &claim)?;
                        meta.delete_alias_claim(txn, &alias, sha256)?;
                    }
                }
                Ok(())
            })
            .map_err(|e| BlobError::Internal(format!("meta update failed: {e}")))?;
        // The release above is ledger-visible: keep the gauge honest (the
        // pre-R2-D path never touched the ledger and needed no refresh).
        self.refresh_gauges();
        Ok(())
    }

    /// Aggregate blob descriptors across all of a tenant's aliases.
    ///
    /// Iterates the per-alias claim index (prefix scans scoped to the
    /// tenant's own aliases) — never the whole cross-tenant `blob_claims`
    /// table, so a `/list` request costs only the caller's own aliases and
    /// never a full-table LMDB scan. The route authorizes the caller before
    /// this runs (`blossom_auth::authorize_list`).
    pub async fn blob_list(&self, tenant: &PublicKey) -> Vec<BlobDescriptor> {
        let tenant_hex = tenant.to_hex();
        let mut out = Vec::new();
        let Ok(txn) = self.meta.read_txn() else {
            return out;
        };
        let Ok(aliases) = self.meta.get_tenant_aliases(&txn, &tenant_hex) else {
            return out;
        };
        let mut seen: HashSet<String> = HashSet::new();
        for alias in &aliases {
            let Ok(shas) = self.meta.alias_claim_shas(&txn, alias) else {
                continue;
            };
            for sha in shas {
                if seen.contains(&sha) {
                    continue;
                }
                let Ok(Some(claim)) = self.meta.get_blob_claim(&txn, &sha) else {
                    continue;
                };
                if !claim.stored {
                    continue;
                }
                seen.insert(sha.clone());
                out.push(BlobDescriptor {
                    url: format!("https://{}/{}", self.cfg.service_address, sha),
                    sha256: sha,
                    size: claim.size,
                    // 0 only for a claim stored by a build that did not
                    // record the time.
                    uploaded: claim.stored_at.unwrap_or(0),
                });
            }
        }
        out
    }

    /// Does this node admit `kind` as a STORED stream wrap? The one gate
    /// every caller (admission arm, sync skip-set, sync hold) asks.
    pub fn accepts_stream_wrap_kind(&self, kind: u16) -> bool {
        is_stream_wrap_kind(kind, self.cfg.accept_legacy_wrap_kind)
    }

    /// Does this node admit `kind` as an EPHEMERAL stream wrap?
    pub fn accepts_ephemeral_stream_wrap_kind(&self, kind: u16) -> bool {
        is_ephemeral_stream_wrap_kind(kind, self.cfg.accept_legacy_wrap_kind)
    }

    /// Does this node REFUSE `kind` outright as a RETIRED stream-wrap
    /// envelope? True exactly for 1059/21059 once `accept_legacy_wrap_kind`
    /// is off.
    ///
    /// Turning the knob off must NARROW what this node stores, and closing
    /// the private arm alone does not do that: a 1059 that misses every
    /// private arm lands on the PUBLIC related-event policy, which stores
    /// any event carrying an `a`/`e` tag that references accepted content —
    /// from ANY key, with no §3.2 registered-key gate, no
    /// `private_max_event_bytes` cap, no private quota charge, and no
    /// private GC. That is strictly MORE permissive than the default
    /// (legacy on), where an unregistered 1059 is rejected outright
    /// precisely because referenced wraps from unregistered keys made every
    /// deregistered rekey address permanently floodable. A migration knob
    /// that widens the accepted set when switched off is a footgun on an
    /// operator-untrusted server, so the retired kinds are refused
    /// explicitly.
    ///
    /// Scoped to nodes with private repos ENABLED (this method only exists
    /// on a live `PrivateService`): where GRASP-P is off, 1059 keeps its
    /// vanilla public related-event handling untouched.
    pub fn rejects_retired_wrap_kind(&self, kind: u16) -> bool {
        !self.cfg.accept_legacy_wrap_kind && is_legacy_wrap_kind(kind)
    }

    /// Spawn the background GC loop.
    pub fn spawn_gc(self: &Arc<Self>) -> JoinHandle<()> {
        gc::spawn(self.clone())
    }

    /// Spawn the background blob-mirror worker (Phase 2). Installs the job
    /// queue sender so `handle_state_root` Accepts start enqueueing, then
    /// runs a boot repair pass plus periodic repair scans that re-enqueue
    /// referenced-but-missing blobs.
    pub fn spawn_mirror(self: &Arc<Self>) -> JoinHandle<()> {
        mirror::spawn(self.clone())
    }

    /// Spawn the periodic denylist reload task (Phase-4b D1). Returns None
    /// (no task) when reload is disabled or no denylist files are
    /// configured.
    pub fn spawn_denylist_reload(self: &Arc<Self>) -> Option<JoinHandle<()>> {
        denylist::spawn(self.clone())
    }

    /// Hand the boot load's per-file states to the reload task. `None` once
    /// they have been taken.
    pub(crate) fn take_denylist_boot_files(&self) -> Option<Vec<denylist::FileState>> {
        self.denylist_boot_files.lock().take()
    }
}

/// Spawn every GRASP-P background loop for `RelayServer`: the blob GC, the
/// pull-only blob mirror when `NGIT_GRASP_P_MIRROR_ENABLE=true`, and the
/// periodic denylist reload when configured.
pub fn spawn_background_tasks(
    service: &Arc<PrivateService>,
    config: &Config,
) -> Vec<JoinHandle<()>> {
    let mut tasks = vec![service.spawn_gc()];
    tracing::info!("Private blob GC task started");
    if config.private_mirror_enable {
        tasks.push(service.spawn_mirror());
        tracing::info!("Private blob mirror task started");
    }
    if let Some(reload) = service.spawn_denylist_reload() {
        tasks.push(reload);
        tracing::info!("Private denylist reload task started");
    }
    tasks
}

/// Free one registration's key claims and remove its record (and its slot
/// in the tenant's alias list) iff it belongs to `author_hex` and its
/// current edition is not newer than `max_created_at` (the NIP-09 cutoff:
/// editions after the deletion survive with claims intact; conflict-merge
/// eviction passes `u64::MAX` — the loser is dead regardless of edition).
/// Returns the number of claims freed.
///
/// A registration that actually dies here also loses the rest of its
/// footprint IN THE SAME TXN (verify round 1, FC/FD — applies to all three
/// death paths: merge eviction, honored kind-5, NIP-62 vanish):
///
/// 1. The dead alias is stripped from every blob claim it referenced (via
///    the per-alias index — never a cross-tenant scan). A claim that loses
///    its last alias is marked unreferenced (wall clock — cleanup state,
///    not merge state) so GC collects it after the grace period, and GC's
///    existing `release_claim` path refunds any stored charge (no
///    hand-rolled refunds here).
/// 2. A claim that became fully unreferenced dies with its speculative
///    charge: released NOW against the recorded (tenant, alias, bytes) —
///    never `claim.size` — closing the !12 zero-release leak without waiting
///    for grace. GC cannot double-release (`spec_charge` is then `None`).
///    R2-A (verify round 2): the same release runs when the CHARGING alias
///    is the one dying even while other live aliases still reference the
///    sha — otherwise the charge strands on the dead scope with zero
///    release paths (GC needs empty aliases; upload needs a preimage; the
///    dead alias's ring was just deleted, so no FH trim ever fires). The
///    surviving referrer is re-charged on its next referencing 30641 via
///    the `spec_charge.is_none()` upgrade path (the same accepted
///    unbilled-window trade-off as FH; pre-fix zombie data is not covered).
///    Stored charges of still-referenced claims stay — real bytes on disk.
/// 3. The alias scope's EVENT-bytes column (`r:<alias>`) is reset: those
///    wrap/30641 bytes are unattributable per tenant and belonged to dead
///    holders; leaving them would brick the seat for a conflict-merge
///    winner (whose own registration charge lands later in the same txn).
///    The blob/spec columns stay intact — real bytes on disk that GC/grace
///    handles.
/// 4. The alias's state-ring editions are deleted: they belong to the dead
///    tenant, and leaving them would let the next 30641's retained-edition
///    rescan keep stripped claims "referenced". The next holder starts a
///    fresh ring.
///
/// NOT cleaned up here (pre-existing, issues !1/!4): event bytes the loser
/// charged to its `t:<tenant>` scope and the `g:` global scope stay stranded
/// on registration death. The record is deleted, not tombstoned — no
/// Phase-4 worker handle is needed on this path.
pub(crate) fn free_registration_claims(
    meta: &MetaEnv,
    txn: &mut heed::RwTxn,
    author_hex: &str,
    alias: &str,
    max_created_at: u64,
) -> anyhow::Result<usize> {
    let Some(record) = meta.get_registration(txn, alias)? else {
        return Ok(0);
    };
    if record.tenant_hex != author_hex {
        return Ok(0);
    }
    if record.created_at > max_created_at {
        return Ok(0);
    }
    let mut n = 0;
    for key in record.w_keys.iter().chain(record.aux_keys.iter()) {
        meta.delete_key_claim(txn, key)?;
        n += 1;
    }
    meta.delete_registration(txn, alias)?;
    let mut aliases = meta.get_tenant_aliases(txn, author_hex)?;
    aliases.retain(|a| a != alias);
    meta.put_tenant_aliases(txn, author_hex, &aliases)?;

    let now = nostr::prelude::Timestamp::now().as_secs();
    for sha in meta.alias_claim_shas(txn, alias)? {
        let Some(mut claim) = meta.get_blob_claim(txn, &sha)? else {
            meta.delete_alias_claim(txn, alias, &sha)?;
            continue;
        };
        if claim.aliases.iter().any(|a| a == alias) {
            claim.aliases.retain(|a| a != alias);
            if claim.aliases.is_empty() {
                if claim.unreferenced_since.is_none() {
                    claim.unreferenced_since = Some(now);
                }
                if let Some(spec) = claim.spec_charge.take() {
                    quota::release_spec_charge(meta, txn, &spec)?;
                }
            } else {
                // R2-A (verify round 2): the DEAD alias was carrying the
                // speculative charge and other aliases still reference the
                // sha — release it against the recorded (tenant, alias,
                // bytes), exactly once (take() → None; GC/upload/FH all
                // guard on Some). The surviving referrer is re-charged on
                // its next referencing 30641 (accepted unbilled window,
                // same trade-off as FH). A charge belonging to a SURVIVING
                // alias stays — that declaration is still live.
                let release_spec = claim
                    .spec_charge
                    .as_ref()
                    .map(|spec| spec.alias == alias)
                    .unwrap_or(false);
                if release_spec {
                    let spec = claim.spec_charge.take().expect("spec charge present");
                    quota::release_spec_charge(meta, txn, &spec)?;
                }
            }
            meta.put_blob_claim(txn, &sha, &claim)?;
        }
        meta.delete_alias_claim(txn, alias, &sha)?;
    }
    quota::reset_alias_event_bytes(meta, txn, alias)?;
    for (key, _) in meta.state_ring_for_alias(txn, alias)? {
        meta.delete_state_ring(txn, &key)?;
    }
    Ok(n)
}

fn record_event_metric(kind: u16, result: &WritePolicyResult) {
    match result {
        WritePolicyResult::Accept => crate::metrics::record_private_event_accepted(kind),
        _ => crate::metrics::record_private_event_rejected(kind),
    }
}

/// R2-C (verify round 2): identity re-check for mutation txns whose pre-txn
/// admission checks read the registration OUTSIDE the write txn (an eviction
/// or kind-5/vanish death can land in between). Returns true iff the alias
/// still has a live registration with the SAME tenant and the SAME latest
/// event id — existence covers kind-5/vanish death, identity covers a
/// conflict-merge takeover. On false the caller must reject WITHOUT any
/// mutation: cleanup runs once at death, and footprints born afterwards
/// (zombie claims/spec charges billed to the dead scope) have no cleanup
/// trigger left.
pub(crate) fn registration_identity_intact(
    meta: &MetaEnv,
    txn: &heed::RoTxn,
    alias: &str,
    expected_tenant: &str,
    expected_event_id: &str,
) -> anyhow::Result<bool> {
    Ok(meta
        .get_registration(txn, alias)?
        .map(|r| {
            r.tombstoned_at.is_none()
                && r.tenant_hex == expected_tenant
                && r.event_id == expected_event_id
        })
        .unwrap_or(false))
}

/// Outcome of the wrap event-byte charge txn.
pub(crate) enum WrapCharge {
    /// Charged (or already charged — idempotent replay), proceed.
    Charged,
    /// Over quota.
    QuotaExceeded,
    /// R2-C: the registration died or was taken over between the liveness
    /// check and the charge txn (maps to the distinct transient
    /// "registration changed; retry" rejection, NOT quota and NOT the
    /// genuine "unregistered key" string — an honest same-tenant rotation
    /// trips this arm too and a retry succeeds).
    Unregistered,
}

/// The wrap event-byte charge txn, extracted from
/// [`PrivateService::try_handle_wrap`] so the R2-C in-txn identity re-check
/// is testable against a stale pre-txn `record` without racing a live
/// handler. The per-id charge idempotency (async duplicate-check race) is
/// preserved: the first delivery charges + records the id, concurrent ones
/// see it charged and accept without re-charging.
pub(crate) fn apply_wrap_charge_txn(
    meta: &MetaEnv,
    txn: &mut heed::RwTxn,
    cfg: &PrivateConfig,
    record: &RegistrationRecord,
    alias: &str,
    event_json_len: u64,
    event_id_hex: &str,
) -> anyhow::Result<WrapCharge> {
    // R2-C: re-verify the registration's identity BEFORE anything else in
    // the txn — liveness was checked outside it, and an eviction/death can
    // land in between.
    if !registration_identity_intact(meta, txn, alias, &record.tenant_hex, &record.event_id)? {
        return Ok(WrapCharge::Unregistered);
    }
    if meta.is_wrap_charged(txn, event_id_hex)? {
        return Ok(WrapCharge::Charged);
    }
    if !quota::check(meta, txn, cfg, &record.tenant_hex, alias, event_json_len)? {
        return Ok(WrapCharge::QuotaExceeded);
    }
    quota::charge(meta, txn, &record.tenant_hex, alias, event_json_len, false)?;
    meta.mark_wrap_charged(txn, event_id_hex)?;
    Ok(WrapCharge::Charged)
}

/// Build the NIP-11 `private_repos` object. Shared by [`PrivateService`] and
/// `http::nip11` (which only has a `Config`).
#[allow(clippy::too_many_arguments)]
pub fn nip11_private_repos_value(
    mode: RegistrationMode,
    pow_bits: u8,
    max_blob_bytes: u64,
    max_event_bytes: u64,
    quota_tenant_bytes: u64,
    quota_repo_bytes: u64,
    service_address: &str,
    policy_fingerprint: &str,
    accept_legacy_wrap_kind: bool,
) -> serde_json::Value {
    // Kept in lockstep with the admission arms by construction: both read
    // the accepted set from the same helpers.
    let mut kinds = vec![KIND_REGISTRATION, KIND_STATE_ROOT];
    kinds.extend(stream_wrap_kinds(accept_legacy_wrap_kind));
    kinds.extend(ephemeral_stream_wrap_kinds(accept_legacy_wrap_kind));
    let mut object = serde_json::json!({
        "kinds": kinds,
        "registration_mode": mode.to_string(),
        "max_blob_bytes": max_blob_bytes,
        "max_event_bytes": max_event_bytes,
        "quota_tenant_bytes": quota_tenant_bytes,
        "quota_repo_bytes": quota_repo_bytes,
        "blob_endpoints": [format!("https://{service_address}")],
        // R6 parity: short hash of the admission-affecting config. Ops (and
        // `doctor --two-node`) compare this across a node pair; a mismatch
        // means silent per-repo replication desync. Never the raw whitelist.
        "policy_fingerprint": policy_fingerprint,
        // The preimage FORMAT label behind that digest. Published so a pair
        // whose digests differ can be told apart at a glance: same version
        // = a real knob split, different version = a rolling upgrade that
        // has not finished. See POLICY_VERSION.
        "policy_version": POLICY_VERSION,
    });
    if mode == RegistrationMode::Pow {
        object["pow_bits"] = serde_json::json!(pow_bits);
    }
    object
}

/// The ONE advert constructor, called from
/// `http::nip11::RelayInformationDocument::from_config`. There is
/// deliberately no `PrivateService`-bound twin: two constructors reading
/// the same knob from two places (`self.cfg` vs `config`) is how "the
/// advert tracks the accepted set exactly" breaks silently the next time
/// the advert grows an argument.
pub fn nip11_private_repos_from_config(config: &Config) -> Option<serde_json::Value> {
    if !config.private_repos_enable {
        return None;
    }
    Some(nip11_private_repos_value(
        config.private_registration_mode,
        config.private_pow_bits,
        config.private_max_blob_bytes,
        config.private_max_event_bytes,
        config.private_quota_tenant_bytes,
        config.private_quota_repo_bytes,
        &config.service_address(),
        &policy_fingerprint(config),
        config.private_accept_legacy_wrap_kind,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase-4b A2: the replacement-cadence knobs are admission-affecting
    /// (cross-node acceptance), so they feed the policy_fingerprint
    /// preimage; the A1 client-write-rate knobs are node-local DoS
    /// protection and must NOT.
    #[test]
    fn fingerprint_covers_cadence_knobs_not_write_rate_knobs() {
        let base = Config::for_testing();
        let same = Config::for_testing();
        assert_eq!(
            policy_fingerprint(&base),
            policy_fingerprint(&same),
            "identical config must fingerprint identically"
        );

        let mut cadence = Config::for_testing();
        cadence.private_registration_replace_capacity = 16;
        assert_ne!(
            policy_fingerprint(&base),
            policy_fingerprint(&cadence),
            "cadence capacity must change the fingerprint"
        );

        let mut cadence_refill = Config::for_testing();
        cadence_refill.private_registration_replace_refill_per_hour = 8;
        assert_ne!(
            policy_fingerprint(&base),
            policy_fingerprint(&cadence_refill),
            "cadence refill must change the fingerprint"
        );

        let mut write_rate = Config::for_testing();
        write_rate.private_write_rate_capacity = 0;
        write_rate.private_write_rate_refill_per_min = 0;
        assert_eq!(
            policy_fingerprint(&base),
            policy_fingerprint(&write_rate),
            "node-local write-rate knobs must NOT change the fingerprint"
        );

        // v3: stream-wrap kind acceptance is DIRECT acceptance behaviour —
        // a peer with legacy accept OFF rejects a 1059 stream wrap this
        // node accepted and stored (split view), so it must be visible in
        // the fingerprint.
        let mut legacy_off = Config::for_testing();
        legacy_off.private_accept_legacy_wrap_kind = false;
        assert_ne!(
            policy_fingerprint(&base),
            policy_fingerprint(&legacy_off),
            "wrap-kind acceptance must change the fingerprint"
        );
    }

    /// The accepted-kind helpers are the single source of truth: dual
    /// accept covers both families, legacy-off covers only 3359/23359, and
    /// the stored/ephemeral sets never overlap.
    #[test]
    fn stream_wrap_kind_membership() {
        for (kind, dual, strict) in [
            (KIND_STREAM_WRAP, true, true),
            (KIND_WRAP, true, false),
            (KIND_EPHEMERAL_STREAM_WRAP, false, false),
            (KIND_EPHEMERAL_WRAP, false, false),
            (KIND_REGISTRATION, false, false),
            (KIND_STATE_ROOT, false, false),
        ] {
            assert_eq!(is_stream_wrap_kind(kind, true), dual, "stored/dual {kind}");
            assert_eq!(
                is_stream_wrap_kind(kind, false),
                strict,
                "stored/legacy-off {kind}"
            );
        }
        for (kind, dual, strict) in [
            (KIND_EPHEMERAL_STREAM_WRAP, true, true),
            (KIND_EPHEMERAL_WRAP, true, false),
            (KIND_STREAM_WRAP, false, false),
            (KIND_WRAP, false, false),
        ] {
            assert_eq!(
                is_ephemeral_stream_wrap_kind(kind, true),
                dual,
                "ephemeral/dual {kind}"
            );
            assert_eq!(
                is_ephemeral_stream_wrap_kind(kind, false),
                strict,
                "ephemeral/legacy-off {kind}"
            );
        }

        // The retired-kind complement: exactly the legacy kinds, exactly
        // when the window is closed. Closing the window must NARROW the
        // accepted set — a legacy kind that merely stops matching the
        // private arms would be picked up by the public related-event
        // policy instead (wider than the default; see
        // `PrivateService::rejects_retired_wrap_kind`).
        for kind in [KIND_WRAP, KIND_EPHEMERAL_WRAP] {
            assert!(is_legacy_wrap_kind(kind), "legacy membership {kind}");
        }
        for kind in [
            KIND_STREAM_WRAP,
            KIND_EPHEMERAL_STREAM_WRAP,
            KIND_REGISTRATION,
            KIND_STATE_ROOT,
            KIND_REPORT,
        ] {
            assert!(
                !is_legacy_wrap_kind(kind),
                "only 1059/21059 may be retired: {kind}"
            );
        }
        // No kind is ever both admitted and retired.
        for kind in [
            KIND_STREAM_WRAP,
            KIND_WRAP,
            KIND_EPHEMERAL_STREAM_WRAP,
            KIND_EPHEMERAL_WRAP,
        ] {
            let admitted =
                is_stream_wrap_kind(kind, false) || is_ephemeral_stream_wrap_kind(kind, false);
            assert!(
                !(admitted && is_legacy_wrap_kind(kind)),
                "legacy-off: {kind} cannot be both admitted and retired"
            );
        }

        assert_eq!(stream_wrap_kinds(true), vec![KIND_STREAM_WRAP, KIND_WRAP]);
        assert_eq!(stream_wrap_kinds(false), vec![KIND_STREAM_WRAP]);
        assert_eq!(
            ephemeral_stream_wrap_kinds(true),
            vec![KIND_EPHEMERAL_STREAM_WRAP, KIND_EPHEMERAL_WRAP]
        );
        assert_eq!(
            ephemeral_stream_wrap_kinds(false),
            vec![KIND_EPHEMERAL_STREAM_WRAP]
        );
    }

    /// A pair mounted under a base path names each other with the path, so
    /// each node's own entry in the preimage has to carry it too, or the two
    /// fingerprints can never match.
    #[test]
    fn fingerprint_is_symmetric_for_a_pair_under_a_base_path() {
        let mut a = Config::for_testing();
        a.domain = "a.example".to_string();
        a.base_path = "/grasp".to_string();
        a.sync_bootstrap_relay_url = Some("wss://b.example/grasp".to_string());
        let mut b = Config::for_testing();
        b.domain = "b.example".to_string();
        b.base_path = "/grasp".to_string();
        b.sync_bootstrap_relay_url = Some("wss://a.example/grasp".to_string());
        assert_eq!(policy_fingerprint(&a), policy_fingerprint(&b));
    }

    /// The blob routes are matched below the mount path, so the advert has
    /// to name it: a client that follows a bare-domain advert gets a 404.
    #[test]
    fn nip11_blob_endpoint_follows_the_base_path() {
        let mut config = Config::for_testing();
        config.private_repos_enable = true;
        config.domain = "example.com".to_string();
        let at_root = nip11_private_repos_from_config(&config).expect("GRASP-P is enabled");
        assert_eq!(
            at_root["blob_endpoints"],
            serde_json::json!(["https://example.com"])
        );

        config.base_path = "/grasp".to_string();
        let mounted = nip11_private_repos_from_config(&config).expect("GRASP-P is enabled");
        assert_eq!(
            mounted["blob_endpoints"],
            serde_json::json!(["https://example.com/grasp"])
        );
    }

    /// The NIP-11 advert must mirror exactly what the admission arms
    /// accept — a drifting advert is how a client learns to publish a kind
    /// the node then rejects.
    #[test]
    fn nip11_kinds_track_the_accepted_set() {
        let kinds_for = |accept_legacy: bool| -> Vec<u64> {
            let value = nip11_private_repos_value(
                RegistrationMode::Open,
                20,
                1,
                1,
                1,
                1,
                "example.com",
                "deadbeefdeadbeef",
                accept_legacy,
            );
            value["kinds"]
                .as_array()
                .expect("kinds array")
                .iter()
                .map(|k| k.as_u64().expect("kind number"))
                .collect()
        };
        assert_eq!(
            kinds_for(true),
            vec![30640, 30641, 3359, 1059, 23359, 21059],
            "dual accept must advertise both wrap families"
        );
        assert_eq!(
            kinds_for(false),
            vec![30640, 30641, 3359, 23359],
            "legacy accept off must drop 1059/21059 from the advert"
        );
    }

    async fn hold_harness(accept_legacy: bool) -> (tempfile::TempDir, Arc<PrivateService>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = Config::for_testing();
        config.private_repos_enable = true;
        config.private_accept_legacy_wrap_kind = accept_legacy;
        config.private_meta_data_path =
            Some(dir.path().join("meta").to_string_lossy().into_owned());
        config.private_blob_data_path =
            Some(dir.path().join("blobs").to_string_lossy().into_owned());
        let database: SharedDatabase =
            std::sync::Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let svc = PrivateService::new(&config, database)
            .await
            .expect("private service");
        (dir, svc)
    }

    /// An event of `kind` with a `d` tag, enough for the hold to key it. A
    /// counter in the content keeps the ids distinct.
    fn hold_event(signer: &nostr_sdk::prelude::Keys, kind: u16, alias: &str) -> Event {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Tag};
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        EventBuilder::new(Kind::Custom(kind), format!("{n:016x}"))
            .tags(vec![Tag::custom("d", vec![alias.to_string()])])
            .finalize(signer)
            .expect("sign")
    }

    /// A rejection no registration can cure: the sync path keeps the id so
    /// the event is not fetched in a loop, and holds nothing; the client
    /// path keeps nothing at all.
    #[tokio::test]
    async fn non_dependency_rejection_is_id_only_when_synced() {
        let (_dir, svc) = hold_harness(true).await;
        let hold = svc.sync_rejected();
        let keys = nostr_sdk::prelude::Keys::generate();
        let author = keys.public_key().to_hex();
        let alias = "cd".repeat(16);
        let counted_before = crate::metrics::private_hold_dropped("not_holdable");

        for kind in [
            KIND_STATE_ROOT,
            KIND_STREAM_WRAP,
            KIND_WRAP,
            KIND_REGISTRATION,
        ] {
            let synced = hold_event(&keys, kind, &alias);
            svc.note_rejected(&synced, "quota exceeded", true);
            assert!(hold.contains(&synced.id), "kind {kind}: the id is skipped");

            let from_client = hold_event(&keys, kind, &alias);
            svc.note_rejected(&from_client, "quota exceeded", false);
            assert!(
                !hold.contains(&from_client.id),
                "kind {kind}: a client's rejection leaves nothing behind"
            );
        }
        // Four kinds on two paths. The registry is shared with tests running
        // at the same time, so this is a lower bound.
        assert!(
            crate::metrics::private_hold_dropped("not_holdable") >= counted_before + 8.0,
            "each non-dependency rejection is counted once"
        );
        assert!(hold.take_for_alias(&alias).is_empty());
        assert!(hold
            .take_for_authors(std::slice::from_ref(&author))
            .is_empty());
        assert!(hold
            .drain_registrations(
                std::time::Instant::now() + std::time::Duration::from_secs(7200),
                64
            )
            .events
            .is_empty());
        assert_eq!(hold.held_len(), 0);
        assert_eq!(hold.held_bytes(), 0);
        hold.assert_accounting();
    }

    /// Every dependency rejection holds the whole event, whichever path it
    /// came by, and the hold gives back exactly that event. This is the
    /// replication guarantee: what arrives before its registration is
    /// retried when the registration arrives.
    #[tokio::test]
    async fn dependency_rejections_are_held_on_both_paths() {
        let (_dir, svc) = hold_harness(true).await;
        let hold = svc.sync_rejected();
        let keys = nostr_sdk::prelude::Keys::generate();
        let author = keys.public_key().to_hex();
        let alias = "ef".repeat(16);

        for synced in [true, false] {
            for message in [
                admission::STATE_ROOT_UNREGISTERED_ALIAS,
                admission::STATE_ROOT_COORDINATE_MISMATCH,
                admission::STATE_ROOT_AUTHOR_NOT_WRITE_KEY,
                admission::STATE_ROOT_REGISTRATION_CHANGED,
            ] {
                let event = hold_event(&keys, KIND_STATE_ROOT, &alias);
                svc.note_rejected(&event, message, synced);
                assert!(hold.contains(&event.id), "{message:?} synced={synced}");
                hold.assert_accounting();
                let taken = hold.take_for_alias(&alias);
                assert_eq!(taken.len(), 1, "{message:?} synced={synced}");
                assert_eq!(taken[0].id, event.id);
            }
            for message in [
                admission::WRAP_UNREGISTERED_KEY,
                admission::WRAP_REGISTRATION_CHANGED,
            ] {
                for kind in [KIND_STREAM_WRAP, KIND_WRAP] {
                    let event = hold_event(&keys, kind, &alias);
                    svc.note_rejected(&event, message, synced);
                    assert!(hold.contains(&event.id), "{message:?} synced={synced}");
                    let taken = hold.take_for_authors(std::slice::from_ref(&author));
                    assert_eq!(taken.len(), 1, "{message:?} kind={kind} synced={synced}");
                    assert_eq!(taken[0].id, event.id);
                }
            }
            let event = hold_event(&keys, KIND_REGISTRATION, &alias);
            svc.note_rejected(&event, registration::REPLACE_CADENCE_REJECT_MESSAGE, synced);
            assert!(hold.contains(&event.id), "cadence synced={synced}");
            hold.assert_accounting();
            let drained = hold.drain_registrations(
                std::time::Instant::now() + std::time::Duration::from_secs(7200),
                64,
            );
            assert_eq!(drained.events.len(), 1, "cadence synced={synced}");
            assert_eq!(drained.events[0].id, event.id);
        }
        assert_eq!(hold.held_bytes(), 0);
        hold.assert_accounting();
    }

    /// Kinds the hold does not know are left alone on both paths: ephemeral
    /// wraps always, and the legacy wrap kind once the node has retired it.
    #[tokio::test]
    async fn rejections_of_other_kinds_are_not_noted() {
        let (_dir, svc) = hold_harness(false).await;
        let hold = svc.sync_rejected();
        let keys = nostr_sdk::prelude::Keys::generate();
        let alias = "0a".repeat(16);
        for kind in [
            KIND_EPHEMERAL_STREAM_WRAP,
            KIND_EPHEMERAL_WRAP,
            KIND_WRAP,
            1,
        ] {
            for synced in [true, false] {
                let event = hold_event(&keys, kind, &alias);
                svc.note_rejected(&event, admission::WRAP_UNREGISTERED_KEY, synced);
                assert!(!hold.contains(&event.id), "kind {kind} synced={synced}");
            }
        }
        assert_eq!(hold.held_len(), 0);
    }
}
