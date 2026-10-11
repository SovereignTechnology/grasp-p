//! Prometheus metrics for ngit-grasp relay.
//!
//! This module provides comprehensive monitoring metrics including:
//! - WebSocket connection tracking (with privacy-preserving IP aggregation)
//! - Git operation metrics (clone, fetch, push)
//! - Repository bandwidth tracking (top-N only for cardinality control)
//! - Nostr event metrics
//! - Sync metrics (GRASP-02 proactive sync)
//!
//! # Privacy
//! IP addresses are NEVER exposed in metrics. The `ConnectionTracker` maintains
//! per-IP counts internally only for abuse detection. Only aggregate counts
//! are exposed to Prometheus.

pub mod bandwidth;
pub mod connection;

pub use crate::sync::SyncMetrics;

use std::sync::Arc;
use std::time::Instant;

#[cfg(target_os = "linux")]
use std::path::PathBuf;

use lazy_static::lazy_static;
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, Opts,
    Registry, TextEncoder,
};

use bandwidth::BandwidthTracker;
use connection::ConnectionTracker;

#[cfg(target_os = "linux")]
fn cgroup_v2_directory() -> Option<PathBuf> {
    let membership = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = membership.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        match (fields.next(), fields.next(), fields.next()) {
            (Some("0"), Some(""), Some(path)) => Some(path.trim_start_matches('/')),
            _ => None,
        }
    })?;
    Some(PathBuf::from("/sys/fs/cgroup").join(relative))
}

#[cfg(target_os = "linux")]
fn cgroup_cpu_seconds(directory: &std::path::Path) -> Option<f64> {
    let stat = std::fs::read_to_string(directory.join("cpu.stat")).ok()?;
    let usage_usec = stat.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some("usage_usec"), Some(value)) => value.parse::<u64>().ok(),
            _ => None,
        }
    })?;
    Some(usage_usec as f64 / 1_000_000.0)
}

#[cfg(target_os = "linux")]
fn cgroup_memory_bytes(directory: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(directory.join("memory.current"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

lazy_static! {
    /// Global Prometheus registry for ngit-grasp metrics
    pub static ref REGISTRY: Registry = {
        let registry = Registry::new();
        #[cfg(target_os = "linux")]
        registry
            .register(Box::new(
                prometheus::process_collector::ProcessCollector::for_self(),
            ))
            .expect("register process metrics");
        registry
    };
    static ref BLACKLIST_DELETIONS_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_blacklist_deletions_total",
                "Blacklist-triggered deletion attempts by phase and result",
            ),
            &["phase", "result"],
        )
        .expect("build blacklist deletion metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register blacklist deletion metric");
        metric
    };
    static ref BLACKLIST_STARTUP_RESTORE_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_blacklist_startup_restore_total",
                "Blacklist startup restore operations by result and reason",
            ),
            &["result", "reason"],
        )
        .expect("build blacklist startup restore metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register blacklist startup restore metric");
        metric
    };
    static ref WHITELIST_STARTUP_RESTORE_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_whitelist_startup_restore_total",
                "Whitelist startup restore operations by result and reason",
            ),
            &["result", "reason"],
        )
        .expect("build whitelist startup restore metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register whitelist startup restore metric");
        metric
    };
    static ref HOLDING_CLEANUP_RUNS_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_holding_cleanup_runs_total",
            "Number of holding cleanup passes run",
        ))
        .expect("build holding cleanup runs metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register holding cleanup runs metric");
        metric
    };
    static ref HOLDING_CLEANUP_DELETED_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_holding_cleanup_deleted_total",
                "Holding cleanup deleted objects by type",
            ),
            &["type"],
        )
        .expect("build holding cleanup deleted metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register holding cleanup deleted metric");
        metric
    };
    static ref HOLDING_CLEANUP_LAST_RUN_DELETED: GaugeVec = {
        let metric = GaugeVec::new(
            Opts::new(
                "ngit_holding_cleanup_last_run_deleted",
                "Objects deleted in the most recent holding cleanup pass by type",
            ),
            &["type"],
        )
        .expect("build holding cleanup last-run metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register holding cleanup last-run metric");
        metric
    };
    static ref DELETION_REQUEST_CLEANUP_RUNS_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_deletion_request_cleanup_runs_total",
            "Number of deletion-request cleanup passes run",
        )).expect("build deletion request cleanup runs metric");
        REGISTRY.register(Box::new(metric.clone())).expect("register deletion request cleanup runs metric");
        metric
    };
    static ref DELETION_REQUEST_CLEANUP_REMOVED_TOTAL: CounterVec = {
        let metric = CounterVec::new(Opts::new(
            "ngit_deletion_request_cleanup_removed_total",
            "Deletion-request cleanup removals by storage type",
        ), &["type"]).expect("build deletion request cleanup removed metric");
        REGISTRY.register(Box::new(metric.clone())).expect("register deletion request cleanup removed metric");
        metric
    };
    static ref DELETION_REQUEST_CLEANUP_OUTCOMES_TOTAL: CounterVec = {
        let metric = CounterVec::new(Opts::new(
            "ngit_deletion_request_cleanup_outcomes_total",
            "Deletion-request cleanup failures and concurrent skips",
        ), &["outcome"]).expect("build deletion request cleanup outcomes metric");
        REGISTRY.register(Box::new(metric.clone())).expect("register deletion request cleanup outcomes metric");
        metric
    };
    static ref RECOVERY_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_recovery_total",
                "Recovery attempts by outcome",
            ),
            &["result"],
        )
        .expect("build recovery metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register recovery metric");
        metric
    };
    static ref MANUAL_EJECTIONS_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_manual_ejections_total",
            "Number of manual holding ejections",
        ))
        .expect("build manual ejections metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register manual ejections metric");
        metric
    };
    static ref MANUAL_EJECTION_DELETED_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_manual_ejection_deleted_total",
                "Objects deleted by manual ejection operations",
            ),
            &["type"],
        )
        .expect("build manual ejection deleted metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register manual ejection deleted metric");
        metric
    };
    // ------------------------------------------------------------------
    // GRASP-P private repositories (aggregate metrics only by default)
    // ------------------------------------------------------------------
    static ref PRIVATE_REGISTRATIONS_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_private_registrations_total",
                "Accepted private-repo registrations by admission mode",
            ),
            &["mode"],
        )
        .expect("build private registrations metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private registrations metric");
        metric
    };
    static ref PRIVATE_EVENTS_ACCEPTED_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_private_events_accepted_total",
                "Accepted private-repo events by kind",
            ),
            &["kind"],
        )
        .expect("build private events accepted metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private events accepted metric");
        metric
    };
    static ref PRIVATE_EVENTS_REJECTED_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_private_events_rejected_total",
                "Rejected private-repo events by kind",
            ),
            &["kind"],
        )
        .expect("build private events rejected metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private events rejected metric");
        metric
    };
    static ref PRIVATE_BLOB_BYTES_STORED: Gauge = {
        let metric = Gauge::with_opts(Opts::new(
            "ngit_private_blob_bytes_stored",
            "Total bytes currently stored in the private blob store",
        ))
        .expect("build private blob bytes stored metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private blob bytes stored metric");
        metric
    };
    static ref PRIVATE_BLOB_UPLOADS_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_private_blob_uploads_total",
            "Completed private blob uploads",
        ))
        .expect("build private blob uploads metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private blob uploads metric");
        metric
    };
    static ref PRIVATE_BLOB_DOWNLOADS_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_private_blob_downloads_total",
            "Served private blob downloads",
        ))
        .expect("build private blob downloads metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private blob downloads metric");
        metric
    };
    static ref PRIVATE_LEDGER_BYTES: GaugeVec = {
        let metric = GaugeVec::new(
            Opts::new(
                "ngit_private_ledger_bytes",
                "Private-subsystem ledger bytes by scope",
            ),
            &["scope"],
        )
        .expect("build private ledger bytes metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private ledger bytes metric");
        metric
    };
    static ref PRIVATE_ALIASES_TOTAL: Gauge = {
        let metric = Gauge::with_opts(Opts::new(
            "ngit_private_aliases_total",
            "Live private-repo alias registrations",
        ))
        .expect("build private aliases metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private aliases metric");
        metric
    };
    static ref PRIVATE_MIRROR_LAG_BLOBS: Gauge = {
        let metric = Gauge::with_opts(Opts::new(
            "ngit_private_mirror_lag_blobs",
            "Referenced private blobs not yet present in the local blob store (mirror backlog)",
        ))
        .expect("build private mirror lag metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private mirror lag metric");
        metric
    };
    static ref PRIVATE_MIRROR_FETCHED_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_private_mirror_fetched_total",
            "Private blobs successfully mirrored from a peer",
        ))
        .expect("build private mirror fetched metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private mirror fetched metric");
        metric
    };
    static ref PRIVATE_MIRROR_FAILED_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_private_mirror_failed_total",
                "Failed private blob mirror fetch attempts by reason",
            ),
            &["reason"],
        )
        .expect("build private mirror failed metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private mirror failed metric");
        metric
    };
    static ref PRIVATE_REGISTRATION_CONFLICTS_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_private_registration_conflicts_total",
                "Cross-tenant registration conflicts resolved by the deterministic \
                 (created_at, id) merge, by resolution (stored_evicted = a previously \
                 accepted registration lost its seat; incoming_rejected = the arriving \
                 registration lost). Alert on any increase: every conflict is either a \
                 split-brain heal or an attempted alias/key squat.",
            ),
            &["resolution"],
        )
        .expect("build private registration conflicts metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private registration conflicts metric");
        metric
    };
    static ref PRIVATE_RATE_LIMITED_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_private_rate_limited_total",
                "Client-submitted private writes rejected by the per-write-key token \
                 bucket, by path (state_root|wrap|ewrap|upload). Alert on sustained \
                 increases from a single source; brief spikes during legit cord-git \
                 rotation bursts should not occur at default capacity.",
            ),
            &["path"],
        )
        .expect("build private rate limited metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private rate limited metric");
        metric
    };
    static ref PRIVATE_FULL_REISSUE_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_private_full_reissue_total",
            "Periodic since=None full re-issue rounds of the private sync filters \
             (kind-30640 + derived 30641/stream-wrap) that ACTUALLY re-issued at least one \
             live peer (Phase-4b B1). Steady ~1/NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS. \
             Rounds where every peer was skipped (rate-limited or inside the FS-3 \
             re-issue floor) count into ngit_private_full_reissue_skipped_total \
             instead; silence of BOTH while private repos are enabled means the \
             self-heal timer is dead.",
        ))
        .expect("build private full reissue metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private full reissue metric");
        metric
    };
    static ref PRIVATE_FULL_REISSUE_SKIPPED_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_private_full_reissue_skipped_total",
            "Periodic full re-issue timer rounds (Phase-4b B1) that re-issued NO peer \
             because every live relay was skipped (health-tracker rate-limit cooldown \
             or the FS-3 NGIT_GRASP_P_REISSUE_MIN_INTERVAL_SECS floor). Sustained \
             increases mean a chronically-skipped peer: the self-heal timer fires but \
             never delivers.",
        ))
        .expect("build private full reissue skipped metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private full reissue skipped metric");
        metric
    };
    static ref PRIVATE_DENYLIST_ENTRIES: Gauge = {
        let metric = Gauge::with_opts(Opts::new(
            "ngit_private_denylist_entries",
            "Sha256 entries in the live private blob denylist (set at boot and on \
             every reload swap; Phase-4b D1). A drop to 0 on a node that should be \
             enforcing a takedown list means the files went missing.",
        ))
        .expect("build private denylist entries metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private denylist entries metric");
        metric
    };
    static ref PRIVATE_DENYLIST_PURGED_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_private_denylist_purged_total",
            "Private blobs purged because their sha256 is denylisted — reload \
             purge-on-add plus the GC denylist sweep (Phase-4b D1/D2). Every \
             increase is a takedown action; alert-worthy in both directions \
             (unexpected purges, or a known takedown that never purges).",
        ))
        .expect("build private denylist purged metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private denylist purged metric");
        metric
    };
    static ref PRIVATE_REPORT_EVENTS_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_private_report_events_total",
            "Kind-1984 (NIP-56 report) events observed while private repos are \
             enabled (Phase-4b D3). Reports are intake-logged with their \
             sha256-looking tag values (takedown evidence) and then admitted \
             under the unchanged related-event rules; v1 takes NO automatic \
             action, so a rising count is an operator page to work the \
             manual denylist runbook.",
        ))
        .expect("build private report events metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private report events metric");
        metric
    };
    static ref PRIVATE_HOLD_DROPPED_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_private_hold_dropped_total",
                "Rejected private-repo events the out-of-order hold did not keep, by \
                 reason: count_cap (the hold has its maximum number of events), \
                 byte_budget (the hold has its maximum bytes), not_holdable (the \
                 rejection is not one a later registration can change, so only the \
                 id is remembered for a synced event and nothing for a client's), \
                 skip_set_full (the id could not be remembered either). count_cap \
                 and byte_budget mean early events are not retried from memory: \
                 synced ones are fetched again when their registration is accepted \
                 or at the next full re-issue, a client's must be sent again; \
                 not_holdable is routine.",
            ),
            &["reason"],
        )
        .expect("build private hold dropped metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private hold dropped metric");
        metric
    };
    static ref PRIVATE_UPLOAD_REFUSED_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_private_upload_refused_total",
                "Client blob uploads refused or cut for a reason other than \
                 authorization, size or quota, by reason: account_slots (the \
                 account had its maximum number of uploads in flight; 429), \
                 node_slots (every upload slot of the node was taken; 503), \
                 idle_timeout (the body sent nothing for the idle time; 408), \
                 deadline (the body took longer in total than its declared \
                 length allows, including a stall that ends at the deadline; \
                 408). node_slots means clients are being turned \
                 away from a full node and is the one to alert on.",
            ),
            &["reason"],
        )
        .expect("build private upload refused metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register private upload refused metric");
        metric
    };
    static ref PURGATORY_GIT_FETCH_PASSES_TOTAL: Counter = {
        let metric = Counter::with_opts(Opts::new(
            "ngit_purgatory_git_fetch_passes_total",
            "Outbound purgatory git fetch passes (one ls-remote comparison plus fetches per pass)",
        ))
        .expect("build purgatory git fetch passes metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register purgatory git fetch passes metric");
        metric
    };
    static ref PURGATORY_GIT_FETCH_OIDS_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_purgatory_git_fetch_oids_total",
                "Purgatory git fetch OID outcomes by kind \
                 (advertised_tip, residual_attempted, residual_missing, residual_skipped, fetched)",
            ),
            &["kind"],
        )
        .expect("build purgatory git fetch oids metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register purgatory git fetch oids metric");
        metric
    };
    static ref PURGATORY_GIT_SUBPROCESS_ACTIVE: GaugeVec = {
        let metric = GaugeVec::new(
            Opts::new(
                "ngit_purgatory_git_subprocess_active",
                "Active outbound purgatory Git subprocesses by operation and hedge role",
            ),
            &["operation", "role"],
        )
        .expect("register purgatory Git subprocess active gauge");
        REGISTRY.register(Box::new(metric.clone())).expect("register metric");
        metric
    };
    static ref PURGATORY_GIT_DEFERRED_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new("ngit_purgatory_git_deferred_total",
                "Outbound Git admission deferrals by operation and budget reason"),
            &["operation", "reason"],
        ).expect("build Git admission deferrals counter");
        REGISTRY.register(Box::new(metric.clone())).expect("register metric");
        metric
    };
    static ref PURGATORY_GIT_SUBPROCESS_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_purgatory_git_subprocess_total",
                "Completed outbound purgatory Git subprocesses by operation, hedge role, and outcome",
            ),
            &["operation", "role", "outcome"],
        )
        .expect("register purgatory Git subprocess counter");
        REGISTRY.register(Box::new(metric.clone())).expect("register metric");
        metric
    };
    static ref PURGATORY_GIT_SUBPROCESS_DURATION_SECONDS: HistogramVec = {
        let metric = HistogramVec::new(
            HistogramOpts::new(
                "ngit_purgatory_git_subprocess_duration_seconds",
                "Outbound purgatory Git subprocess duration by operation and hedge role",
            ),
            &["operation", "role"],
        )
        .expect("register purgatory Git subprocess duration histogram");
        REGISTRY.register(Box::new(metric.clone())).expect("register metric");
        metric
    };
    static ref PURGATORY_GIT_SUBPROCESS_OUTPUT_BYTES_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_purgatory_git_subprocess_output_bytes_total",
                "Bytes drained from outbound purgatory Git subprocess output by operation, hedge role, and stream",
            ),
            &["operation", "role", "stream"],
        )
        .expect("register purgatory Git subprocess output counter");
        REGISTRY.register(Box::new(metric.clone())).expect("register metric");
        metric
    };
    static ref TRANSIENT_REQ_WATCHDOG_TOTAL: CounterVec = {
        let metric = CounterVec::new(
            Opts::new(
                "ngit_sync_transient_req_watchdog_total",
                "Transient REQ watchdog outcomes by bounded request class",
            ),
            &["class", "outcome"],
        )
        .expect("build transient REQ watchdog metric");
        REGISTRY
            .register(Box::new(metric.clone()))
            .expect("register transient REQ watchdog metric");
        metric
    };
}

pub fn record_transient_req_watchdog(class: &str, outcome: &str) {
    TRANSIENT_REQ_WATCHDOG_TOTAL
        .with_label_values(&[class, outcome])
        .inc();
}

/// Record one completed outbound purgatory git fetch pass.
///
/// Together with the per-pass summary log line this gives production the
/// client-side view of purgatory git fetching: how many needed OIDs were
/// advertised by the remote (batch-fetched), how many residual OIDs were
/// attempted individually, how many the remote did not have, and how many
/// unchanged-advertisement misses were skipped, and how many OIDs actually arrived.
pub fn record_purgatory_git_fetch_pass(
    advertised_tips: usize,
    residual_attempted: usize,
    residual_missing: usize,
    residual_skipped: usize,
    fetched: usize,
) {
    PURGATORY_GIT_FETCH_PASSES_TOTAL.inc();
    PURGATORY_GIT_FETCH_OIDS_TOTAL
        .with_label_values(&["advertised_tip"])
        .inc_by(advertised_tips as f64);
    PURGATORY_GIT_FETCH_OIDS_TOTAL
        .with_label_values(&["residual_attempted"])
        .inc_by(residual_attempted as f64);
    PURGATORY_GIT_FETCH_OIDS_TOTAL
        .with_label_values(&["residual_missing"])
        .inc_by(residual_missing as f64);
    PURGATORY_GIT_FETCH_OIDS_TOTAL
        .with_label_values(&["residual_skipped"])
        .inc_by(residual_skipped as f64);
    PURGATORY_GIT_FETCH_OIDS_TOTAL
        .with_label_values(&["fetched"])
        .inc_by(fetched as f64);
}

pub struct PurgatoryGitSubprocessGuard {
    operation: &'static str,
    role: &'static str,
    started: Instant,
    outcome: &'static str,
}

pub fn record_purgatory_git_deferred(operation: &'static str, reason: &'static str) {
    PURGATORY_GIT_DEFERRED_TOTAL
        .with_label_values(&[operation, reason])
        .inc();
}

impl PurgatoryGitSubprocessGuard {
    pub fn finish(&mut self, success: bool) {
        self.outcome = if success { "success" } else { "failure" };
    }

    pub fn finish_with_outcome(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

impl Drop for PurgatoryGitSubprocessGuard {
    fn drop(&mut self) {
        PURGATORY_GIT_SUBPROCESS_ACTIVE
            .with_label_values(&[self.operation, self.role])
            .dec();
        PURGATORY_GIT_SUBPROCESS_TOTAL
            .with_label_values(&[self.operation, self.role, self.outcome])
            .inc();
        PURGATORY_GIT_SUBPROCESS_DURATION_SECONDS
            .with_label_values(&[self.operation, self.role])
            .observe(self.started.elapsed().as_secs_f64());
    }
}

pub fn start_purgatory_git_subprocess(
    operation: &'static str,
    role: &'static str,
) -> PurgatoryGitSubprocessGuard {
    PURGATORY_GIT_SUBPROCESS_ACTIVE
        .with_label_values(&[operation, role])
        .inc();
    PurgatoryGitSubprocessGuard {
        operation,
        role,
        started: Instant::now(),
        outcome: "cancelled",
    }
}

pub fn record_purgatory_git_subprocess_output(
    operation: &str,
    role: &str,
    stream: &str,
    bytes: u64,
) {
    PURGATORY_GIT_SUBPROCESS_OUTPUT_BYTES_TOTAL
        .with_label_values(&[operation, role, stream])
        .inc_by(bytes as f64);
}

pub fn record_blacklist_deletion_attempt(phase: &str) {
    BLACKLIST_DELETIONS_TOTAL
        .with_label_values(&[phase, "attempted"])
        .inc();
}

pub fn record_blacklist_deletion_success(phase: &str) {
    BLACKLIST_DELETIONS_TOTAL
        .with_label_values(&[phase, "succeeded"])
        .inc();
}

pub fn record_blacklist_deletion_failure(phase: &str) {
    BLACKLIST_DELETIONS_TOTAL
        .with_label_values(&[phase, "failed"])
        .inc();
}

pub fn record_blacklist_startup_restore_attempt() {
    BLACKLIST_STARTUP_RESTORE_TOTAL
        .with_label_values(&["attempted", "none"])
        .inc();
}

pub fn record_blacklist_startup_restore_success() {
    BLACKLIST_STARTUP_RESTORE_TOTAL
        .with_label_values(&["succeeded", "none"])
        .inc();
}

pub fn record_blacklist_startup_restore_failure() {
    BLACKLIST_STARTUP_RESTORE_TOTAL
        .with_label_values(&["failed", "none"])
        .inc();
}

pub fn record_blacklist_startup_restore_skipped(reason: &str) {
    BLACKLIST_STARTUP_RESTORE_TOTAL
        .with_label_values(&["skipped", reason])
        .inc();
}

pub fn record_whitelist_startup_restore_attempt() {
    WHITELIST_STARTUP_RESTORE_TOTAL
        .with_label_values(&["attempted", "none"])
        .inc();
}

pub fn record_whitelist_startup_restore_success() {
    WHITELIST_STARTUP_RESTORE_TOTAL
        .with_label_values(&["succeeded", "none"])
        .inc();
}

pub fn record_whitelist_startup_restore_failure() {
    WHITELIST_STARTUP_RESTORE_TOTAL
        .with_label_values(&["failed", "none"])
        .inc();
}

pub fn record_whitelist_startup_restore_skipped(reason: &str) {
    WHITELIST_STARTUP_RESTORE_TOTAL
        .with_label_values(&["skipped", reason])
        .inc();
}

pub fn record_holding_cleanup_run(
    metadata_deleted: usize,
    archived_events_deleted: usize,
    archive_files_deleted: usize,
) {
    HOLDING_CLEANUP_RUNS_TOTAL.inc();
    HOLDING_CLEANUP_DELETED_TOTAL
        .with_label_values(&["metadata"])
        .inc_by(metadata_deleted as f64);
    HOLDING_CLEANUP_DELETED_TOTAL
        .with_label_values(&["payload"])
        .inc_by(archived_events_deleted as f64);
    HOLDING_CLEANUP_DELETED_TOTAL
        .with_label_values(&["archive_file"])
        .inc_by(archive_files_deleted as f64);

    HOLDING_CLEANUP_LAST_RUN_DELETED
        .with_label_values(&["metadata"])
        .set(metadata_deleted as f64);
    HOLDING_CLEANUP_LAST_RUN_DELETED
        .with_label_values(&["payload"])
        .set(archived_events_deleted as f64);
    HOLDING_CLEANUP_LAST_RUN_DELETED
        .with_label_values(&["archive_file"])
        .set(archive_files_deleted as f64);
}

pub fn record_deletion_request_cleanup_run(
    main_removed: usize,
    tombstone_removed: usize,
    metadata_removed: usize,
    failures: usize,
    skipped: usize,
) {
    DELETION_REQUEST_CLEANUP_RUNS_TOTAL.inc();
    for (kind, value) in [
        ("main", main_removed),
        ("tombstone", tombstone_removed),
        ("metadata", metadata_removed),
    ] {
        DELETION_REQUEST_CLEANUP_REMOVED_TOTAL
            .with_label_values(&[kind])
            .inc_by(value as f64);
    }
    for (outcome, value) in [("failure", failures), ("stale_or_concurrent_skip", skipped)] {
        DELETION_REQUEST_CLEANUP_OUTCOMES_TOTAL
            .with_label_values(&[outcome])
            .inc_by(value as f64);
    }
}

pub fn record_recovery_attempt() {
    RECOVERY_TOTAL.with_label_values(&["attempted"]).inc();
}

pub fn record_recovery_success() {
    RECOVERY_TOTAL.with_label_values(&["succeeded"]).inc();
}

pub fn record_recovery_failed() {
    RECOVERY_TOTAL.with_label_values(&["failed"]).inc();
}

pub fn record_recovery_partial() {
    RECOVERY_TOTAL.with_label_values(&["partial"]).inc();
}

pub fn record_manual_ejection(
    metadata_deleted: usize,
    archived_events_deleted: usize,
    archive_files_deleted: usize,
) {
    MANUAL_EJECTIONS_TOTAL.inc();
    MANUAL_EJECTION_DELETED_TOTAL
        .with_label_values(&["metadata"])
        .inc_by(metadata_deleted as f64);
    MANUAL_EJECTION_DELETED_TOTAL
        .with_label_values(&["payload"])
        .inc_by(archived_events_deleted as f64);
    MANUAL_EJECTION_DELETED_TOTAL
        .with_label_values(&["archive_file"])
        .inc_by(archive_files_deleted as f64);
}

// ------------------------------------------------------------------
// GRASP-P private repositories — free-function recorders
// ------------------------------------------------------------------

/// Record an accepted private-repo registration (kind 30640) by admission mode.
pub fn record_private_registration(mode: &str) {
    PRIVATE_REGISTRATIONS_TOTAL.with_label_values(&[mode]).inc();
}

/// Record an accepted private-repo event by kind.
pub fn record_private_event_accepted(kind: u16) {
    PRIVATE_EVENTS_ACCEPTED_TOTAL
        .with_label_values(&[&kind.to_string()])
        .inc();
}

/// Record a rejected private-repo event by kind.
pub fn record_private_event_rejected(kind: u16) {
    PRIVATE_EVENTS_REJECTED_TOTAL
        .with_label_values(&[&kind.to_string()])
        .inc();
}

/// Record a completed private blob upload of `bytes` bytes.
pub fn record_private_blob_upload(bytes: u64) {
    PRIVATE_BLOB_UPLOADS_TOTAL.inc();
    PRIVATE_BLOB_BYTES_STORED.add(bytes as f64);
}

/// Record bytes removed from the private blob store (GC / delete).
pub fn record_private_blob_removed(bytes: u64) {
    PRIVATE_BLOB_BYTES_STORED.sub(bytes as f64);
}

/// Record a served private blob download.
pub fn record_private_blob_download() {
    PRIVATE_BLOB_DOWNLOADS_TOTAL.inc();
}

/// Update the global private ledger gauge (aggregate scope only by default).
pub fn set_private_ledger_global_bytes(bytes: u64) {
    PRIVATE_LEDGER_BYTES
        .with_label_values(&["global"])
        .set(bytes as f64);
}

/// Update the live private alias count gauge.
pub fn set_private_aliases_total(count: u64) {
    PRIVATE_ALIASES_TOTAL.set(count as f64);
}

/// Update the mirror backlog gauge (referenced-but-missing private blobs).
pub fn set_private_mirror_lag_blobs(count: u64) {
    PRIVATE_MIRROR_LAG_BLOBS.set(count as f64);
}

/// Record one private blob successfully mirrored from a peer.
pub fn record_private_mirror_fetched() {
    PRIVATE_MIRROR_FETCHED_TOTAL.inc();
}

/// Record one failed private blob mirror fetch attempt.
pub fn record_private_mirror_failed(reason: &str) {
    PRIVATE_MIRROR_FAILED_TOTAL
        .with_label_values(&[reason])
        .inc();
}

/// Record one cross-tenant registration conflict resolved by the
/// deterministic merge. `resolution` is `stored_evicted` or
/// `incoming_rejected` (§3.2 first-registrant-wins conflict alert).
pub fn record_private_registration_conflict(resolution: &str) {
    PRIVATE_REGISTRATION_CONFLICTS_TOTAL
        .with_label_values(&[resolution])
        .inc();
}

/// Record one client private write rejected by the per-write-key token
/// bucket. `path` is `state_root`, `wrap`, `ewrap`, or `upload`.
pub fn record_private_rate_limited(path: &str) {
    PRIVATE_RATE_LIMITED_TOTAL.with_label_values(&[path]).inc();
}

/// Record one periodic since=None full re-issue round of the private sync
/// filters (Phase-4b B1) that actually re-issued at least one live peer.
pub fn record_private_full_reissue() {
    PRIVATE_FULL_REISSUE_TOTAL.inc();
}

/// Record one full re-issue timer round that re-issued NO peer (every
/// live relay rate-limit- or floor-skipped, FS-8 review L3-F7).
pub fn record_private_full_reissue_skipped() {
    PRIVATE_FULL_REISSUE_SKIPPED_TOTAL.inc();
}

/// Update the live denylist entry-count gauge (boot load + every reload
/// swap, Phase-4b D1).
pub fn set_private_denylist_entries(count: usize) {
    PRIVATE_DENYLIST_ENTRIES.set(count as f64);
}

/// Record `n` blobs purged because their sha256 is denylisted (reload
/// purge-on-add or GC denylist sweep, Phase-4b D1/D2).
pub fn record_private_denylist_purged(n: u64) {
    PRIVATE_DENYLIST_PURGED_TOTAL.inc_by(n as f64);
}

/// Record one observed kind-1984 (NIP-56 report) event (Phase-4b D3).
pub fn record_private_report_event() {
    PRIVATE_REPORT_EVENTS_TOTAL.inc();
}

/// Record one rejected private-repo event the out-of-order hold did not
/// keep. `reason` is one of a fixed set (`count_cap`, `byte_budget`,
/// `not_holdable`, `skip_set_full`); never pass anything derived from the
/// event, so the series count stays fixed.
pub fn record_private_hold_dropped(reason: &str) {
    PRIVATE_HOLD_DROPPED_TOTAL
        .with_label_values(&[reason])
        .inc();
}

/// Record one client blob upload refused for want of a slot, or cut for a
/// body that stalled or ran out of time. `reason` is one of a fixed set
/// (`account_slots`, `node_slots`, `idle_timeout`, `deadline`); never pass
/// anything derived from the request, so the series count stays fixed.
pub fn record_private_upload_refused(reason: &str) {
    PRIVATE_UPLOAD_REFUSED_TOTAL
        .with_label_values(&[reason])
        .inc();
}

/// Current value of the hold-drop counter for `reason`.
#[cfg(test)]
pub(crate) fn private_hold_dropped(reason: &str) -> f64 {
    PRIVATE_HOLD_DROPPED_TOTAL
        .with_label_values(&[reason])
        .get()
}

/// Central metrics collection for ngit-grasp relay.
///
/// Thread-safe and designed for concurrent access from multiple tokio tasks.
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
    render_permit: Arc<tokio::sync::Semaphore>,
    /// GRASP-P seam: set on a node with GRASP-P enabled, whose scrape must
    /// not name a relay by its URL (`grasp_p::relay_labels`).
    relay_labels: Option<Arc<crate::grasp_p::relay_labels::RelayLabels>>,
}

struct MetricsInner {
    /// Connection tracking with abuse detection
    pub connection_tracker: ConnectionTracker,

    /// Repository bandwidth tracking (top-N only)
    pub bandwidth_tracker: BandwidthTracker,

    /// Sync metrics (GRASP-02 proactive sync)
    pub sync_metrics: Option<crate::sync::SyncMetrics>,

    // === WebSocket Metrics ===
    /// Total WebSocket connections since startup
    pub websocket_connections_total: Counter,
    /// Connection duration histogram
    pub websocket_connection_duration: Histogram,
    /// Messages received by type (REQ, EVENT, CLOSE)
    pub websocket_messages_received: CounterVec,
    /// Messages sent by type (EVENT, EOSE, OK, NOTICE)
    pub websocket_messages_sent: CounterVec,

    // === Git Operation Metrics ===
    /// Git operations by type and status
    pub git_operations_total: CounterVec,
    /// Git operation duration histogram
    pub git_operation_duration: HistogramVec,
    /// Total bytes transferred
    pub git_bytes_total: CounterVec,
    /// Push authorization results
    pub git_push_authorization: CounterVec,

    // === Nostr Event Metrics ===
    /// Events received by kind
    pub events_received_total: CounterVec,
    /// Events successfully stored by kind
    pub events_stored_total: CounterVec,
    /// Events rejected by kind and reason
    pub events_rejected_total: CounterVec,

    // === Repository Metrics ===
    /// Total repositories hosted (counted from disk on each metrics request)
    pub repositories_total: Gauge,
    /// Git data directory path for counting repositories on disk
    pub git_data_path: Option<String>,

    // === System Health Metrics ===
    /// Server start time for uptime calculation
    pub start_time: Instant,
    /// Build information gauge (stored to prevent unregistration from Prometheus)
    #[allow(dead_code)]
    pub build_info: GaugeVec,
}

impl Metrics {
    /// Creates a new Metrics instance and registers all metrics with Prometheus.
    ///
    /// # Arguments
    /// * `abuse_threshold` - Number of connections from a single IP before flagging as abuse
    /// * `git_data_path` - Optional path to git data directory for counting repositories
    pub fn new(abuse_threshold: u32, git_data_path: Option<String>) -> Self {
        let inner = MetricsInner::new(abuse_threshold, git_data_path);
        Self {
            inner: Arc::new(inner),
            render_permit: Arc::new(tokio::sync::Semaphore::new(1)),
            relay_labels: None,
        }
    }

    /// GRASP-P seam: have every render rewrite the relay labels. With `None`
    /// the render stays as it is.
    pub fn with_relay_labels(
        mut self,
        relay_labels: Option<crate::grasp_p::relay_labels::RelayLabels>,
    ) -> Self {
        self.relay_labels = relay_labels.map(Arc::new);
        self
    }

    /// Returns the sync metrics if registered.
    pub fn sync_metrics(&self) -> Option<&crate::sync::SyncMetrics> {
        self.inner.sync_metrics.as_ref()
    }

    /// Returns the connection tracker for WebSocket connection management.
    pub fn connection_tracker(&self) -> &ConnectionTracker {
        &self.inner.connection_tracker
    }

    /// Returns the bandwidth tracker for repository bandwidth tracking.
    pub fn bandwidth_tracker(&self) -> &BandwidthTracker {
        &self.inner.bandwidth_tracker
    }

    // === WebSocket Recording Methods ===

    /// Record a new WebSocket connection
    pub fn record_websocket_connection(&self) {
        self.inner.websocket_connections_total.inc();
    }

    /// Start timing a WebSocket connection, returns timer that records on drop
    pub fn start_connection_timer(&self) -> HistogramTimer {
        HistogramTimer::new(self.inner.websocket_connection_duration.clone())
    }

    /// Record a received WebSocket message
    pub fn record_message_received(&self, msg_type: &str) {
        self.inner
            .websocket_messages_received
            .with_label_values(&[msg_type])
            .inc();
    }

    /// Record a sent WebSocket message
    pub fn record_message_sent(&self, msg_type: &str) {
        self.inner
            .websocket_messages_sent
            .with_label_values(&[msg_type])
            .inc();
    }

    // === Git Operation Recording Methods ===

    /// Record a git operation event.
    ///
    /// Buffered handlers record completion from the synchronous request path.
    /// Streaming handlers record the final `success`/`error` from the background
    /// task that owns the Git subprocess; their synchronous `Ok(Response)` only
    /// means stream setup succeeded.
    pub fn record_git_operation(&self, operation: &str, status: &str) {
        self.inner
            .git_operations_total
            .with_label_values(&[operation, status])
            .inc();
    }

    /// Start timing a git operation, returns a timer
    pub fn start_git_operation_timer(&self, operation: &str) -> GitOperationTimer {
        GitOperationTimer::new(
            self.inner.git_operation_duration.clone(),
            operation.to_string(),
        )
    }

    /// Record bytes transferred for a git operation
    pub fn record_git_bytes(&self, direction: &str, bytes: u64) {
        self.inner
            .git_bytes_total
            .with_label_values(&[direction])
            .inc_by(bytes as f64);
    }

    /// Record a push authorization result
    pub fn record_push_authorization(&self, result: &str) {
        self.inner
            .git_push_authorization
            .with_label_values(&[result])
            .inc();
    }

    // === Nostr Event Recording Methods ===

    /// Record a received Nostr event
    pub fn record_event_received(&self, kind: u64) {
        self.inner
            .events_received_total
            .with_label_values(&[&kind.to_string()])
            .inc();
    }

    /// Record a stored Nostr event
    pub fn record_event_stored(&self, kind: u64) {
        self.inner
            .events_stored_total
            .with_label_values(&[&kind.to_string()])
            .inc();
    }

    /// Record a rejected Nostr event
    pub fn record_event_rejected(&self, kind: u64, reason: &str) {
        let kind = kind.to_string();
        self.inner
            .events_rejected_total
            .with_label_values(&[kind.as_str(), reason])
            .inc();
    }

    // === Repository Metrics ===

    /// Set the total number of repositories
    pub fn set_repositories_total(&self, count: u64) {
        self.inner.repositories_total.set(count as f64);
    }

    /// Count all git repositories on disk.
    ///
    /// This scans the git data directory for all `*.git` directories.
    ///
    /// # Arguments
    /// * `git_data_path` - Path to the git data directory (e.g., "./data/git")
    ///
    /// # Returns
    /// The number of repositories found on disk
    pub fn count_repositories_on_disk(git_data_path: &str) -> u64 {
        use std::fs;
        use std::path::Path;

        let git_dir = Path::new(git_data_path);
        if !git_dir.exists() {
            return 0;
        }

        let mut count = 0u64;
        if let Ok(entries) = fs::read_dir(git_dir) {
            for npub_entry in entries.flatten() {
                if let Ok(npub_meta) = npub_entry.metadata() {
                    if npub_meta.is_dir() {
                        // This is a npub directory, scan for *.git repos inside
                        if let Ok(repo_entries) = fs::read_dir(npub_entry.path()) {
                            for repo_entry in repo_entries.flatten() {
                                if let Some(name) = repo_entry.file_name().to_str() {
                                    if name.ends_with(".git") {
                                        if let Ok(repo_meta) = repo_entry.metadata() {
                                            if repo_meta.is_dir() {
                                                count += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        count
    }

    // === Rendering ===

    /// Render a scrape without blocking the async executor on filesystem
    /// traversal or encoding. Concurrent scrapes wait before spawning work;
    /// cancelling an HTTP request cannot release a running worker's permit.
    pub async fn render_async(&self) -> Result<String, tokio::task::JoinError> {
        let permit = self
            .render_permit
            .clone()
            .acquire_owned()
            .await
            .expect("metrics render semaphore is never closed");
        let metrics = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            metrics.render()
        })
        .await
    }

    /// Render all metrics in Prometheus text format.
    ///
    /// This method:
    /// 1. Refreshes the top-N bandwidth metrics if needed
    /// 2. Counts repositories on disk (if git_data_path configured)
    /// 3. Updates uptime
    /// 4. Gathers all metrics from the registry
    /// 5. Encodes them in Prometheus text format
    pub fn render(&self) -> String {
        // Refresh top-N bandwidth repos if needed
        self.inner.bandwidth_tracker.maybe_refresh_top_n();

        // Count repositories on disk and update metric
        if let Some(git_data_path) = &self.inner.git_data_path {
            let count = Self::count_repositories_on_disk(git_data_path);
            self.inner.repositories_total.set(count as f64);
        }

        // Gather and encode metrics
        let encoder = TextEncoder::new();
        let metric_families = REGISTRY.gather();
        // GRASP-P seam: the scrape of a node with GRASP-P enabled names no
        // relay by its URL.
        let metric_families = match &self.relay_labels {
            Some(relay_labels) => relay_labels.scrub(metric_families),
            None => metric_families,
        };
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        // Add uptime as a comment (it's derived, not a registered metric)
        let uptime = self.inner.start_time.elapsed().as_secs();
        let mut output = String::from_utf8(buffer).unwrap();
        output.push_str(&format!(
            "\n# HELP ngit_uptime_seconds Seconds since server startup\n# TYPE ngit_uptime_seconds counter\nngit_uptime_seconds {}\n",
            uptime
        ));

        // A systemd service's cgroup includes ngit-grasp and the Git processes
        // it launches, making these the headline measures of total service
        // cost. ProcessCollector metrics remain useful for separating the
        // daemon's own usage from its children. Omit these metrics gracefully
        // outside a readable cgroup v2 hierarchy.
        #[cfg(target_os = "linux")]
        if let Some(directory) = cgroup_v2_directory() {
            if let Some(cpu_seconds) = cgroup_cpu_seconds(&directory) {
                output.push_str(&format!(
                    "# HELP ngit_cgroup_cpu_seconds_total Total CPU time used by ngit-grasp and child processes\n# TYPE ngit_cgroup_cpu_seconds_total counter\nngit_cgroup_cpu_seconds_total {cpu_seconds}\n"
                ));
            }
            if let Some(memory_bytes) = cgroup_memory_bytes(&directory) {
                output.push_str(&format!(
                    "# HELP ngit_cgroup_memory_current_bytes Current memory used by ngit-grasp and child processes\n# TYPE ngit_cgroup_memory_current_bytes gauge\nngit_cgroup_memory_current_bytes {memory_bytes}\n"
                ));
            }
        }

        output
    }

    /// Check if the system is under high load (for sync scheduling)
    pub fn is_high_load(&self, threshold: u64) -> bool {
        self.inner.connection_tracker.active_connections() > threshold
    }
}

impl MetricsInner {
    fn new(abuse_threshold: u32, git_data_path: Option<String>) -> Self {
        // Create connection tracker
        let connection_tracker = ConnectionTracker::new(abuse_threshold, &REGISTRY);

        // Create bandwidth tracker
        let bandwidth_tracker = BandwidthTracker::new(&REGISTRY);

        // Create sync metrics (may fail if already registered in tests)
        let sync_metrics = crate::sync::SyncMetrics::register(&REGISTRY).ok();
        if sync_metrics.is_some() {
            tracing::info!("Sync metrics registered with Prometheus");
        }

        // WebSocket metrics
        let websocket_connections_total = Counter::with_opts(Opts::new(
            "ngit_websocket_connections_total",
            "Total WebSocket connections since startup",
        ))
        .unwrap();
        REGISTRY
            .register(Box::new(websocket_connections_total.clone()))
            .unwrap();

        let websocket_connection_duration = Histogram::with_opts(
            HistogramOpts::new(
                "ngit_websocket_connection_duration_seconds",
                "Duration of WebSocket connections",
            )
            .buckets(vec![1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 900.0, 3600.0]),
        )
        .unwrap();
        REGISTRY
            .register(Box::new(websocket_connection_duration.clone()))
            .unwrap();

        let websocket_messages_received = CounterVec::new(
            Opts::new(
                "ngit_websocket_messages_received_total",
                "WebSocket messages received by type",
            ),
            &["type"],
        )
        .unwrap();
        REGISTRY
            .register(Box::new(websocket_messages_received.clone()))
            .unwrap();

        let websocket_messages_sent = CounterVec::new(
            Opts::new(
                "ngit_websocket_messages_sent_total",
                "WebSocket messages sent by type",
            ),
            &["type"],
        )
        .unwrap();
        REGISTRY
            .register(Box::new(websocket_messages_sent.clone()))
            .unwrap();

        // Git operation metrics
        let git_operations_total = CounterVec::new(
            Opts::new(
                "ngit_git_operations_total",
                "Git operations by type and status",
            ),
            &["operation", "status"],
        )
        .unwrap();
        REGISTRY
            .register(Box::new(git_operations_total.clone()))
            .unwrap();

        let git_operation_duration = HistogramVec::new(
            HistogramOpts::new(
                "ngit_git_operation_duration_seconds",
                "Duration of git operations",
            )
            .buckets(vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]),
            &["operation"],
        )
        .unwrap();
        REGISTRY
            .register(Box::new(git_operation_duration.clone()))
            .unwrap();

        let git_bytes_total = CounterVec::new(
            Opts::new(
                "ngit_git_bytes_total",
                "Total bytes transferred for git operations",
            ),
            &["direction"],
        )
        .unwrap();
        REGISTRY
            .register(Box::new(git_bytes_total.clone()))
            .unwrap();

        let git_push_authorization = CounterVec::new(
            Opts::new(
                "ngit_git_push_authorization_total",
                "Push authorization results",
            ),
            &["result"],
        )
        .unwrap();
        REGISTRY
            .register(Box::new(git_push_authorization.clone()))
            .unwrap();

        // Nostr event metrics
        let events_received_total = CounterVec::new(
            Opts::new(
                "ngit_events_received_total",
                "Nostr events received by kind",
            ),
            &["kind"],
        )
        .unwrap();
        REGISTRY
            .register(Box::new(events_received_total.clone()))
            .unwrap();

        let events_stored_total = CounterVec::new(
            Opts::new(
                "ngit_events_stored_total",
                "Nostr events successfully stored by kind",
            ),
            &["kind"],
        )
        .unwrap();
        REGISTRY
            .register(Box::new(events_stored_total.clone()))
            .unwrap();

        let events_rejected_total = CounterVec::new(
            Opts::new(
                "ngit_events_rejected_total",
                "Nostr events rejected by kind and reason",
            ),
            &["kind", "reason"],
        )
        .unwrap();
        REGISTRY
            .register(Box::new(events_rejected_total.clone()))
            .unwrap();

        // Repository metrics
        let repositories_total = Gauge::with_opts(Opts::new(
            "ngit_repositories_total",
            "Total repositories hosted",
        ))
        .unwrap();
        REGISTRY
            .register(Box::new(repositories_total.clone()))
            .unwrap();

        // Build info
        let build_info = GaugeVec::new(
            Opts::new("ngit_build_info", "Build information"),
            &["version", "commit"],
        )
        .unwrap();
        REGISTRY.register(Box::new(build_info.clone())).unwrap();

        // Set build info gauge to 1 (it's just for labels)
        build_info
            .with_label_values(&[
                env!("CARGO_PKG_VERSION"),
                option_env!("GIT_COMMIT").unwrap_or("unknown"),
            ])
            .set(1.0);

        Self {
            connection_tracker,
            bandwidth_tracker,
            sync_metrics,
            websocket_connections_total,
            websocket_connection_duration,
            websocket_messages_received,
            websocket_messages_sent,
            git_operations_total,
            git_operation_duration,
            git_bytes_total,
            git_push_authorization,
            events_received_total,
            events_stored_total,
            events_rejected_total,
            repositories_total,
            git_data_path,
            start_time: Instant::now(),
            build_info,
        }
    }
}

/// Timer for tracking WebSocket connection duration.
/// Records the elapsed time when dropped.
pub struct HistogramTimer {
    histogram: Histogram,
    start: Instant,
}

impl HistogramTimer {
    fn new(histogram: Histogram) -> Self {
        Self {
            histogram,
            start: Instant::now(),
        }
    }
}

impl Drop for HistogramTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        self.histogram.observe(elapsed);
    }
}

/// Timer for tracking Git operation duration.
/// Records the elapsed time when dropped.
pub struct GitOperationTimer {
    histogram_vec: HistogramVec,
    operation: String,
    start: Instant,
}

impl GitOperationTimer {
    fn new(histogram_vec: HistogramVec, operation: String) -> Self {
        Self {
            histogram_vec,
            operation,
            start: Instant::now(),
        }
    }
}

impl Drop for GitOperationTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        self.histogram_vec
            .with_label_values(&[&self.operation])
            .observe(elapsed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn concurrent_scrapes_wait_without_blocking_the_runtime(metrics: &Metrics) {
        use futures_util::FutureExt;
        let permit = metrics.render_permit.clone().acquire_owned().await.unwrap();
        let render = metrics.render_async();
        tokio::pin!(render);
        assert!(render.as_mut().now_or_never().is_none());
        drop(permit);
        let output = tokio::time::timeout(std::time::Duration::from_secs(5), render)
            .await
            .unwrap()
            .unwrap();
        assert!(output.contains("ngit_uptime_seconds"));
        assert_eq!(metrics.render_permit.available_permits(), 1);
    }

    #[test]
    fn test_count_repositories_on_disk() {
        use std::fs;
        use tempfile::TempDir;

        // Create temporary directory structure
        let temp_dir = TempDir::new().unwrap();
        let git_data_path = temp_dir.path();

        // Initially should be 0
        let count = Metrics::count_repositories_on_disk(git_data_path.to_str().unwrap());
        assert_eq!(count, 0);

        // Create some fake repositories
        let npub1 = git_data_path.join("npub1test");
        fs::create_dir_all(&npub1).unwrap();
        fs::create_dir_all(npub1.join("repo1.git")).unwrap();
        fs::create_dir_all(npub1.join("repo2.git")).unwrap();

        let npub2 = git_data_path.join("npub2test");
        fs::create_dir_all(&npub2).unwrap();
        fs::create_dir_all(npub2.join("repo3.git")).unwrap();

        // Should count 3 repositories
        let count = Metrics::count_repositories_on_disk(git_data_path.to_str().unwrap());
        assert_eq!(count, 3);

        // Create a non-.git directory (should be ignored)
        fs::create_dir_all(npub1.join("not-a-repo")).unwrap();
        let count = Metrics::count_repositories_on_disk(git_data_path.to_str().unwrap());
        assert_eq!(count, 3);

        // Create a file with .git suffix (should be ignored, not a directory)
        fs::write(npub1.join("file.git"), "content").unwrap();
        let count = Metrics::count_repositories_on_disk(git_data_path.to_str().unwrap());
        assert_eq!(count, 3);
    }

    /// Comprehensive test for Metrics functionality including repository counting.
    ///
    /// NOTE: This test creates a Metrics instance which registers with the global
    /// Prometheus REGISTRY. Due to this global state, we cannot have multiple tests
    /// that create Metrics instances - they would conflict. Therefore, this single
    /// test covers:
    /// 1. Metrics creation and basic operations
    /// 2. Repository counting on disk via render()
    ///
    /// If additional Metrics tests are needed, they should either be added to this
    /// test or use a separate test-specific Prometheus registry.
    #[tokio::test]
    async fn test_metrics_with_repository_counting() {
        use std::fs;
        use tempfile::TempDir;

        // Create temporary directory structure for repository counting
        let temp_dir = TempDir::new().unwrap();
        let git_data_path = temp_dir.path();

        // Create Metrics with git_data_path for repository counting
        let metrics = Metrics::new(10, Some(git_data_path.to_str().unwrap().to_string()));

        // Test basic metrics operations
        metrics.record_websocket_connection();
        metrics.record_message_received("REQ");
        metrics.record_message_sent("EVENT");
        metrics.record_git_operation("clone", "success");
        metrics.record_git_bytes("in", 1024);
        metrics.record_event_received(1);
        metrics.record_event_stored(1);
        metrics.record_event_rejected(1, "invalid_signature");
        metrics.set_repositories_total(5);

        // Test repository counting via render()
        // Render should count 0 repos initially (even though we set it to 5 above,
        // render() recounts from disk)
        let output = metrics.render();
        assert!(output.contains("ngit_repositories_total 0"));
        #[cfg(target_os = "linux")]
        {
            // ProcessCollector is registered only on Linux, just like the
            // cgroup collectors below. Repository metrics are portable.
            assert!(output.contains("process_cpu_seconds_total"));
            assert!(output.contains("process_resident_memory_bytes"));
            if let Some(directory) = cgroup_v2_directory() {
                if cgroup_cpu_seconds(&directory).is_some() {
                    assert!(output.contains("ngit_cgroup_cpu_seconds_total"));
                }
                if cgroup_memory_bytes(&directory).is_some() {
                    assert!(output.contains("ngit_cgroup_memory_current_bytes"));
                }
            }
        }

        // Create some repositories
        let npub1 = git_data_path.join("npub1test");
        fs::create_dir_all(&npub1).unwrap();
        fs::create_dir_all(npub1.join("repo1.git")).unwrap();
        fs::create_dir_all(npub1.join("repo2.git")).unwrap();

        // Render should count 2 repos now
        let output = metrics.render();
        assert!(output.contains("ngit_repositories_total 2"));

        // Add another repo
        fs::create_dir_all(npub1.join("repo3.git")).unwrap();

        // Render should count 3 repos
        let output = metrics.render();
        assert!(output.contains("ngit_repositories_total 3"));
        concurrent_scrapes_wait_without_blocking_the_runtime(&metrics).await;
        assert!(metrics
            .render_async()
            .await
            .unwrap()
            .contains("ngit_repositories_total 3"));
    }
}
