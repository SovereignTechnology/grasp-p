//! Test relay fixture
//!
//! Provides automatic relay lifecycle management for integration tests.
//!
//! ## Port allocation
//!
//! All public `start*` methods route through [`PortReservation`] (see
//! [`crate::common::port`]) so that parallel `#[tokio::test]`s cannot be
//! handed the same loopback port. Callers that need to embed the relay's
//! address into events *before* the relay is up should reserve the port
//! themselves and pass the reservation into one of the
//! `start_on_reservation_*` constructors — the listener stays bound for
//! the duration of the reservation, eliminating the same-process race.

use nostr_sdk::prelude::{Client, Keys, ToBech32};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;

use crate::common::port::{self, PortReservation};

/// How long to wait for the spawned ngit-grasp subprocess to handle HTTP
/// requests before giving up on a single attempt.
const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// How often to retry the HTTP probe while waiting for readiness.
const READY_POLL: Duration = Duration::from_millis(100);
/// Per-attempt timeout for the HTTP readiness probe once TCP connects.
const READY_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// Test relay fixture that manages relay lifecycle
///
/// Automatically starts and stops the ngit-grasp relay for testing.
/// Transfers a kernel-assigned listener to the child while retaining a
/// parent copy, so startup and same-address restart never release the port.
pub struct TestRelay {
    process: Child,
    /// Parent copy retains the address across a same-endpoint restart.
    listener: std::net::TcpListener,
    url: String,
    port: u16,
    /// Relay-owner identity configured in the subprocess.
    owner_keys: Keys,
    /// Temporary directory for git repositories
    /// Kept alive for the lifetime of the relay
    _git_data_dir: Option<tempfile::TempDir>,
    /// Path to git data directory (for test assertions)
    git_data_path: PathBuf,
    /// Temporary directory for relay data (LMDB side stores)
    _relay_data_dir: Option<tempfile::TempDir>,
    /// Path to relay data directory (for test assertions)
    relay_data_path: PathBuf,
    /// Options used at start, retained so [`Self::restart`] can respawn
    /// an identical relay on the same port.
    options: RelayOptions,
}

/// Options that the various `start*` constructors fan out into a single
/// internal entry point. Field names mirror the original positional
/// parameters so the call-site changes are mechanical.
#[derive(Default, Clone)]
struct RelayOptions {
    /// Owner identity for the subprocess. `try_start_once` fills this in
    /// when unset so [`TestRelay::restart`] keeps the same identity, as a
    /// production restart would.
    owner_keys: Option<Keys>,
    base_path: Option<String>,
    bootstrap_relay_url: Option<String>,
    sync_plus_fallback_relays: Option<String>,
    disable_negentropy: bool,
    archive_all: bool,
    archive_read_only: bool,
    /// Comma-separated GRASP service domains whose repositories this relay
    /// archives (`NGIT_ARCHIVE_GRASP_SERVICES`).
    archive_grasp_services: Option<String>,
    grasp06_enable: bool,
    deletion_request_disrespector: bool,
    lmdb_backend: bool,
    repository_blacklist: Option<String>,
    git_data_path: Option<PathBuf>,
    relay_data_path: Option<PathBuf>,
    deletion_lifecycle: Option<DeletionLifecycleOptions>,
    rejected_hot_cache_duration_secs: Option<u64>,
    /// Application log level for tests that observe a diagnostic as an
    /// ordering barrier. Other fixtures retain the production `info` default.
    log_level: Option<String>,
    relay_max_subscriptions: Option<usize>,
    sync_recursive_descendant_limit: Option<usize>,
    private_members: Option<String>,
    /// Explicit NGIT_USER_INDEX_RELAYS value (comma-separated), overriding
    /// the bootstrap relay's double duty as the sole user-index target.
    user_index_relays: Option<String>,
    /// Run with the production outbound target policy (reject non-global
    /// event-directed sync targets). The fixture default is permissive
    /// because the entire test infrastructure lives on loopback.
    enforce_outbound_target_policy: bool,
    /// Extra environment variables (name, value) passed verbatim to the
    /// subprocess, applied last. The GRASP-P suites drive the
    /// `NGIT_GRASP_P_*` knob matrix through this.
    extra_env: Vec<(String, String)>,
}

/// Focused configuration for short-lived deletion-request lifecycle tests.
///
/// Explicit paths are owned by the caller, so they can be reused after
/// [`TestRelay::stop`] to exercise LMDB restart reconciliation.
#[derive(Clone, Debug)]
pub struct DeletionLifecycleOptions {
    pub unused_served_retention_secs: u64,
    pub unused_gating_additional_secs: u64,
    pub used_served_after_last_use_secs: u64,
    pub used_gating_additional_secs: u64,
    pub cleanup_interval_secs: u64,
    pub git_data_path: Option<PathBuf>,
    pub relay_data_path: Option<PathBuf>,
    pub deletion_request_disrespector: bool,
}

impl TestRelay {
    /// Start a test relay instance on a kernel-assigned loopback port.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use common::TestRelay;
    ///
    /// #[tokio::test]
    /// async fn test_something() {
    ///     let relay = TestRelay::start().await;
    ///     // Use relay.url() for testing
    ///     relay.stop().await;
    /// }
    /// ```
    pub async fn start() -> Self {
        Self::start_internal(port::reserve_port(), RelayOptions::default()).await
    }

    /// Start a relay mounted at an explicit public URL path.
    pub async fn start_at_base_path(base_path: &str) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                base_path: Some(base_path.to_string()),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start one GRASP-08 private service whose static membership contains
    /// `member`.
    pub async fn start_private(member: &nostr_sdk::prelude::PublicKey) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                private_members: Some(
                    member
                        .to_bech32()
                        .expect("Failed to encode private test member"),
                ),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start relay with sync from another relay (bootstrap relay)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use common::TestRelay;
    ///
    /// #[tokio::test]
    /// async fn test_sync() {
    ///     let source = TestRelay::start().await;
    ///     let syncing = TestRelay::start_with_sync(source.url()).await;
    ///     // ... test sync behavior ...
    ///     syncing.stop().await;
    ///     source.stop().await;
    /// }
    /// ```
    pub async fn start_with_sync(bootstrap_relay_url: Option<String>) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                bootstrap_relay_url,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a syncing relay with user-index identity publication disabled.
    ///
    /// `start_with_sync` points identity publication at the bootstrap relay.
    /// Tests making log-based assertions about the bootstrap connection use
    /// this variant so identity-publication traffic cannot confound them.
    pub async fn start_with_sync_without_user_index(bootstrap_relay_url: Option<String>) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                bootstrap_relay_url,
                user_index_relays: Some(String::new()),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a syncing relay on a caller-reserved port with user-index
    /// identity publication disabled. See
    /// [`Self::start_with_sync_without_user_index`] and
    /// [`Self::start_on_reservation_with_options`] for the two concerns
    /// this combines.
    pub async fn start_on_reservation_with_sync_without_user_index(
        reservation: PortReservation,
        bootstrap_relay_url: Option<String>,
    ) -> Self {
        Self::start_internal(
            reservation,
            RelayOptions {
                bootstrap_relay_url,
                user_index_relays: Some(String::new()),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a syncing relay with application debug diagnostics enabled.
    ///
    /// Most integration tests use the production `info` default. This focused
    /// fixture supports tests that wait on a debug record as an observable
    /// ordering condition before changing remote state.
    pub async fn start_with_sync_debug(bootstrap_relay_url: Option<String>) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                bootstrap_relay_url,
                log_level: Some("debug".to_string()),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a syncing relay with a caller-chosen relay-owner identity.
    ///
    /// Lets tests stage owner-signed events on other relays before this
    /// relay boots, e.g. to model an identity that survives on a user-index
    /// relay after the local database was wiped.
    pub async fn start_with_sync_and_owner_keys(
        bootstrap_relay_url: Option<String>,
        owner_keys: Keys,
    ) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                bootstrap_relay_url,
                owner_keys: Some(owner_keys),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a GRASP-08 private service with an explicit member list, an
    /// optional sync bootstrap, and a caller-chosen relay-owner identity.
    ///
    /// Lets private-to-private sync tests model two services whose member
    /// sets deliberately differ (e.g. the source service admits the
    /// mirroring service's owner identity).
    pub async fn start_private_with_sync_owner_keys_and_members(
        bootstrap_relay_url: Option<String>,
        owner_keys: Keys,
        members: &[nostr_sdk::prelude::PublicKey],
    ) -> Self {
        let members = members
            .iter()
            .map(|member| {
                member
                    .to_bech32()
                    .expect("Failed to encode private test member")
            })
            .collect::<Vec<_>>()
            .join(",");
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                bootstrap_relay_url,
                owner_keys: Some(owner_keys),
                private_members: Some(members),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a GRASP-08 private relay whose sole configured member is also
    /// the relay-owner identity, with user-index relays configured.
    ///
    /// Lets tests observe that a private relay seeds its identity locally
    /// (queryable by the authenticated owner) without ever publishing it to
    /// the configured user-index relays.
    pub async fn start_private_with_sync_and_owner_keys(
        bootstrap_relay_url: Option<String>,
        owner_keys: Keys,
    ) -> Self {
        let member = owner_keys
            .public_key()
            .to_bech32()
            .expect("Failed to encode private test member");
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                bootstrap_relay_url,
                owner_keys: Some(owner_keys),
                private_members: Some(member),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a syncing relay with the production outbound target policy.
    ///
    /// Unlike every other constructor, this does NOT set
    /// `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`, so event-directed sync
    /// targets on loopback/private addresses are rejected exactly as they
    /// would be in production. The operator-configured bootstrap relay is
    /// still allowed even when it is local.
    pub async fn start_with_sync_enforced_outbound_policy(
        bootstrap_relay_url: Option<String>,
    ) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                bootstrap_relay_url,
                enforce_outbound_target_policy: true,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a syncing relay with a short rejected-event hot-cache lifetime.
    ///
    /// This is used by ordering regressions that need an event to leave the
    /// immediate retry window without making the test wait for the production
    /// two-minute default.
    pub async fn start_with_sync_and_rejected_hot_cache(
        bootstrap_relay_url: Option<String>,
        rejected_hot_cache_duration_secs: u64,
    ) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                bootstrap_relay_url,
                rejected_hot_cache_duration_secs: Some(rejected_hot_cache_duration_secs),
                log_level: Some("debug".to_string()),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start relay with sync and negentropy disabled
    ///
    /// This is useful for testing that sync works without NIP-77 negentropy.
    /// History sync will use REQ+EOSE instead of the more efficient negentropy protocol.
    pub async fn start_with_sync_no_negentropy(bootstrap_relay_url: Option<String>) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                bootstrap_relay_url,
                disable_negentropy: true,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start relay with archive configuration
    ///
    /// This is useful for testing GRASP-05 archive mode behavior.
    ///
    /// # Arguments
    /// * `archive_all` - Accept all repository announcements (GRASP-05)
    /// * `archive_read_only` - Reject git pushes (read-only archive mode)
    pub async fn start_with_archive_config(archive_all: bool, archive_read_only: bool) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                archive_all,
                archive_read_only,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start an archive-all source relay that applies the production
    /// outbound target policy.
    ///
    /// Scenarios that front a source relay with a proxy must list the proxy
    /// URL in the announcement so the relay under test targets the proxied
    /// connection. Under the permissive test policy the source itself also
    /// treats that URL as an event-directed sync target — it is a distinct
    /// host:port that happens to front the source — and opens its own sync
    /// traffic through the proxy, contaminating measurements the scenario
    /// means to attribute to the relay under test alone. The production
    /// policy rejects non-global event-directed targets, so the source stays
    /// scenery. Its own hosting, admission, and serving behavior is unchanged.
    /// Start a relay that archives repositories hosted on the given
    /// comma-separated GRASP service domains.
    pub async fn start_with_archive_grasp_services(services: &str) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                archive_grasp_services: Some(services.to_string()),
                ..RelayOptions::default()
            },
        )
        .await
    }

    pub async fn start_archive_source_behind_proxy() -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                archive_all: true,
                enforce_outbound_target_policy: true,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start relay with GRASP-06 contributor PR submission enabled.
    ///
    /// Sets `NGIT_GRASP06_ENABLE=true` on the relay process. When the relay
    /// does not yet support this flag (e.g. before the feature is implemented),
    /// the env var is ignored — this is harmless and lets the same test file
    /// drive both the pre- and post-implementation contracts.
    pub async fn start_with_grasp_06_enabled() -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                grasp06_enable: true,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Persistent GRASP-06 storage for crash/restart tests.
    pub async fn start_with_grasp_06_paths(
        git_data_path: PathBuf,
        relay_data_path: PathBuf,
    ) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                grasp06_enable: true,
                lmdb_backend: true,
                git_data_path: Some(git_data_path),
                relay_data_path: Some(relay_data_path),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a relay on a port that the caller has already reserved.
    ///
    /// Use this when the test needs the port number *before* the relay
    /// boots — e.g. to embed `127.0.0.1:{port}` into an announcement event
    /// that will be created and published before the syncing relay
    /// itself comes up. Holding the [`PortReservation`] across the gap
    /// guarantees no other parallel test in this process will be handed
    /// the same port number in the meantime.
    pub async fn start_on_reservation_with_options(
        reservation: PortReservation,
        bootstrap_relay_url: Option<String>,
        disable_negentropy: bool,
    ) -> Self {
        Self::start_internal(
            reservation,
            RelayOptions {
                bootstrap_relay_url,
                disable_negentropy,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a relay with archive configuration on a pre-reserved port.
    ///
    /// See [`Self::start_on_reservation_with_options`] for why one would
    /// reserve a port up front; this variant additionally accepts the
    /// archive flags.
    pub async fn start_on_reservation_with_archive_and_sync(
        reservation: PortReservation,
        bootstrap_relay_url: Option<String>,
        disable_negentropy: bool,
        archive_all: bool,
        archive_read_only: bool,
    ) -> Self {
        Self::start_internal(
            reservation,
            RelayOptions {
                bootstrap_relay_url,
                disable_negentropy,
                archive_all,
                archive_read_only,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a relay in NIP-09 deletion "disrespector" (archival) mode.
    ///
    /// Sets `NGIT_DELETION_REQUEST_DISRESPECTOR=true`: the relay stores incoming
    /// kind-5 deletion requests but does not act on them.
    pub async fn start_with_deletion_disrespector() -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                deletion_request_disrespector: true,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a source relay advertising and enforcing a small per-connection
    /// subscription budget. Sync scenarios use this to exercise graceful
    /// degradation paths selected from NIP-11.
    pub async fn start_with_relay_max_subscriptions(limit: usize) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                relay_max_subscriptions: Some(limit),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a relay with LMDB backend (persistent side DBs on a temp dir).
    pub async fn start_with_lmdb() -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                lmdb_backend: true,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start an LMDB relay with explicit, short deletion-request lifecycle
    /// timings. This intentionally groups the retention knobs used by the
    /// subprocess lifecycle tests rather than expanding the public constructor
    /// matrix with positional duration arguments.
    pub async fn start_with_deletion_lifecycle(options: DeletionLifecycleOptions) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                deletion_request_disrespector: options.deletion_request_disrespector,
                lmdb_backend: true,
                git_data_path: options.git_data_path.clone(),
                relay_data_path: options.relay_data_path.clone(),
                deletion_lifecycle: Some(options),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a relay with LMDB backend + deletion disrespector mode.
    pub async fn start_with_lmdb_deletion_disrespector() -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                deletion_request_disrespector: true,
                lmdb_backend: true,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a relay with LMDB backend and repository blacklist.
    pub async fn start_with_lmdb_blacklist(repository_blacklist: impl Into<String>) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                lmdb_backend: true,
                repository_blacklist: Some(repository_blacklist.into()),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a relay on fresh port using pre-existing LMDB/git directories.
    pub async fn start_with_existing_lmdb_paths(
        git_data_path: PathBuf,
        relay_data_path: PathBuf,
        repository_blacklist: Option<String>,
        deletion_request_disrespector: bool,
    ) -> Self {
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                lmdb_backend: true,
                repository_blacklist,
                git_data_path: Some(git_data_path),
                relay_data_path: Some(relay_data_path),
                deletion_request_disrespector,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a syncing relay on a caller-reserved port with persistent
    /// LMDB storage in explicit directories, so [`Self::restart`] can
    /// resume from the same data on the same port.
    pub async fn start_on_reservation_persistent_sync(
        reservation: PortReservation,
        bootstrap_relay_url: Option<String>,
        disable_negentropy: bool,
        git_data_path: PathBuf,
        relay_data_path: PathBuf,
    ) -> Self {
        Self::start_internal(
            reservation,
            RelayOptions {
                bootstrap_relay_url,
                disable_negentropy,
                lmdb_backend: true,
                git_data_path: Some(git_data_path),
                relay_data_path: Some(relay_data_path),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a persistent relay with an explicit user-index relay list and
    /// no sync bootstrap, so identity-publication targets can differ from
    /// the sync topology and survive [`Self::restart`].
    pub async fn start_on_reservation_persistent_user_index_relays(
        reservation: PortReservation,
        user_index_relays: String,
        git_data_path: PathBuf,
        relay_data_path: PathBuf,
    ) -> Self {
        Self::start_internal(
            reservation,
            RelayOptions {
                user_index_relays: Some(user_index_relays),
                lmdb_backend: true,
                git_data_path: Some(git_data_path),
                relay_data_path: Some(relay_data_path),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a persistent syncing relay with a small recursive-descendant
    /// allowance so saturation and restart reconstruction can be exercised.
    pub async fn start_on_reservation_persistent_sync_with_recursive_limit(
        reservation: PortReservation,
        bootstrap_relay_url: Option<String>,
        disable_negentropy: bool,
        git_data_path: PathBuf,
        relay_data_path: PathBuf,
        recursive_descendant_limit: usize,
    ) -> Self {
        Self::start_internal(
            reservation,
            RelayOptions {
                bootstrap_relay_url,
                disable_negentropy,
                lmdb_backend: true,
                git_data_path: Some(git_data_path),
                relay_data_path: Some(relay_data_path),
                sync_recursive_descendant_limit: Some(recursive_descendant_limit),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a persistent syncing relay with an explicit Sync+ fallback set.
    pub async fn start_on_reservation_persistent_sync_with_fallback(
        reservation: PortReservation,
        bootstrap_relay_url: String,
        fallback_relay_url: String,
        git_data_path: PathBuf,
        relay_data_path: PathBuf,
    ) -> Self {
        Self::start_internal(
            reservation,
            RelayOptions {
                bootstrap_relay_url: Some(bootstrap_relay_url),
                sync_plus_fallback_relays: Some(fallback_relay_url),
                lmdb_backend: true,
                git_data_path: Some(git_data_path),
                relay_data_path: Some(relay_data_path),
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a relay with GRASP-P private repos enabled plus arbitrary
    /// additional `NGIT_GRASP_P_*` settings (memory backend).
    ///
    /// `NGIT_GRASP_P_REPOS_ENABLE=true` is always set; `extra_env` is applied
    /// afterwards, so a caller can override it. The node also gets a metrics
    /// endpoint on a kernel-assigned loopback port (see
    /// [`Self::grasp_p_metrics`]), which `extra_env` can override as well.
    pub async fn start_with_grasp_p(extra_env: &[(&str, &str)]) -> Self {
        let mut env = vec![
            ("NGIT_GRASP_P_REPOS_ENABLE".to_string(), "true".to_string()),
            // A GRASP-P node serves no scrape on its public port. Port 0:
            // the kernel picks, and `grasp_p_metrics` reads the choice from
            // the log, so no port is reserved and released for it.
            (
                "NGIT_GRASP_P_METRICS_BIND".to_string(),
                "127.0.0.1:0".to_string(),
            ),
        ];
        env.extend(
            extra_env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
        );
        Self::start_internal(
            port::reserve_port(),
            RelayOptions {
                extra_env: env,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start one node of a GRASP-P two-node pair on a pre-reserved port:
    /// private repos and the blob mirror enabled, an optional bootstrap peer
    /// (each node of a pair bootstraps to the other), and optional persistent
    /// LMDB paths for kill-and-restart tests.
    ///
    /// `extra_env` is applied last, so callers can override any default.
    pub async fn start_grasp_p_pair_node(
        reservation: PortReservation,
        bootstrap_relay_url: Option<String>,
        lmdb_backend: bool,
        git_data_path: Option<PathBuf>,
        relay_data_path: Option<PathBuf>,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let mut env = vec![
            ("NGIT_GRASP_P_REPOS_ENABLE".to_string(), "true".to_string()),
            ("NGIT_GRASP_P_MIRROR_ENABLE".to_string(), "true".to_string()),
            // Tests mirror over http://127.0.0.1, so allow the SSRF-guarded
            // private-IP path (production defaults it off).
            (
                "NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS".to_string(),
                "true".to_string(),
            ),
            // See `start_with_grasp_p`: the scrape has a listener of its
            // own, on a port the kernel picks.
            (
                "NGIT_GRASP_P_METRICS_BIND".to_string(),
                "127.0.0.1:0".to_string(),
            ),
        ];
        // Private-sync peers come only from the operator allowlist: point
        // each node of the pair at its peer explicitly.
        if let Some(ref url) = bootstrap_relay_url {
            env.push(("NGIT_GRASP_P_SYNC_PEER_URLS".to_string(), url.clone()));
        }
        env.extend(
            extra_env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
        );
        Self::start_internal(
            reservation,
            RelayOptions {
                bootstrap_relay_url,
                lmdb_backend,
                git_data_path,
                relay_data_path,
                extra_env: env,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Start a relay with every configurable option, on a pre-reserved port.
    ///
    /// Prefer the narrower constructors above — this exists so the option
    /// matrix has a single place to grow.
    pub async fn start_on_reservation_with_all_options(
        reservation: PortReservation,
        bootstrap_relay_url: Option<String>,
        disable_negentropy: bool,
        archive_all: bool,
        archive_read_only: bool,
        grasp06_enable: bool,
    ) -> Self {
        Self::start_internal(
            reservation,
            RelayOptions {
                bootstrap_relay_url,
                disable_negentropy,
                archive_all,
                archive_read_only,
                grasp06_enable,
                ..RelayOptions::default()
            },
        )
        .await
    }

    /// Single entry point that drives the spawn+readiness loop.
    ///
    /// Transfer the reserved listener to the child. Startup errors are real
    /// failures; no port is released and no address retry is needed.
    async fn start_internal(reservation: PortReservation, options: RelayOptions) -> Self {
        match Self::try_start_once(reservation, &options).await {
            StartOutcome::Ready(relay) => relay,
            StartOutcome::EarlyExit { status } => panic!(
                "ngit-grasp exited before readiness (status: {status:?}); see /tmp/relay-*.log"
            ),
        }
    }

    /// One attempt at spawning ngit-grasp on the given reservation and
    /// waiting for it to be ready. Returns [`StartOutcome::EarlyExit`]
    /// specifically when the subprocess died before the readiness probe
    /// succeeded.
    async fn try_start_once(reservation: PortReservation, options: &RelayOptions) -> StartOutcome {
        let port = reservation.port();
        let bind_address = format!("127.0.0.1:{}", port);
        let base_path = options.base_path.as_deref().unwrap_or("/");
        let url_path = if base_path == "/" { "" } else { base_path };
        let url = format!("ws://127.0.0.1:{port}{url_path}");

        // Create temporary directories unless caller provided explicit paths.
        let (git_data_dir, git_data_path) = if let Some(path) = options.git_data_path.clone() {
            std::fs::create_dir_all(&path).expect("Failed to create provided git data directory");
            (None, path)
        } else {
            let dir = tempfile::tempdir().expect("Failed to create temporary git data directory");
            let path = dir.path().to_path_buf();
            (Some(dir), path)
        };

        let (relay_data_dir, relay_data_path) = if let Some(path) = options.relay_data_path.clone()
        {
            std::fs::create_dir_all(&path).expect("Failed to create provided relay data directory");
            (None, path)
        } else {
            let dir = tempfile::tempdir().expect("Failed to create temporary relay data directory");
            let path = dir.path().to_path_buf();
            (Some(dir), path)
        };

        // Use the built binary directly (faster than cargo run)
        let binary_path = std::env::current_exe()
            .expect("Failed to get current exe")
            .parent()
            .expect("Failed to get parent dir")
            .parent()
            .expect("Failed to get grandparent dir")
            .join("ngit-grasp");

        // Give the relay a stable signing identity for NIP-11 and NIP-42,
        // reusing the caller-provided identity across restarts.
        let test_keys = options
            .owner_keys
            .clone()
            .unwrap_or_else(nostr_sdk::prelude::Keys::generate);
        let test_nsec = test_keys
            .secret_key()
            .to_bech32()
            .expect("Failed to generate test nsec");

        // Build the Command *before* releasing the reservation so that
        // none of the env-setting allocations happen while the listener
        // is held. We release immediately before `spawn`.
        let mut cmd = Command::new(&binary_path);
        cmd.env("NGIT_BIND_ADDRESS", &bind_address)
            .env("NGIT_DOMAIN", &bind_address) // Set domain to match bind address
            .env("NGIT_GIT_DATA_PATH", &git_data_path)
            .env("NGIT_RELAY_DATA_PATH", &relay_data_path)
            .env("NGIT_RELAY_OWNER_NSEC", &test_nsec)
            .env("NGIT_TEST", "1") // Enable test mode: fast timers (200ms batch window, 200ms purgatory sync)
            // Integration tests must never depend on or send discovery traffic
            // to the production user-index defaults. A configured loopback
            // bootstrap below becomes the scenario's sole index source.
            .env("NGIT_USER_INDEX_RELAYS", "")
            .env("NGIT_SYNC_PLUS_FALLBACK_RELAYS", "")
            .env("NGIT_SYNC_STARTUP_DELAY_SECS", "0") // No startup delay for faster tests
            .env("NGIT_SYNC_STARTUP_JITTER_MS", "0") // No jitter for tests
            .env("NGIT_SYNC_DISCONNECT_CHECK_INTERVAL_SECS", "1") // Fast reconnect attempts for tests
            .env("NGIT_SYNC_BASE_BACKOFF_SECS", "1") // Fast backoff for tests (1s instead of 5s default)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            ) // Use RUST_LOG from environment or default to info
            .stdout(
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(format!("/tmp/relay-{}.log", port))
                    .map(Stdio::from)
                    .unwrap_or(Stdio::null()),
            )
            .stderr(Stdio::inherit()); // Inherit stderr for test output

        if let Some(base_path) = &options.base_path {
            cmd.env("NGIT_BASE_PATH", base_path);
        }

        cmd.env(
            "NGIT_DATABASE_BACKEND",
            if options.lmdb_backend {
                "lmdb"
            } else {
                "memory"
            },
        );

        // Add bootstrap relay URL if provided
        if let Some(ref bootstrap_url) = options.bootstrap_relay_url {
            cmd.env("NGIT_SYNC_BOOTSTRAP_RELAY_URL", bootstrap_url)
                .env("NGIT_USER_INDEX_RELAYS", bootstrap_url);
        }
        if let Some(ref fallback_relays) = options.sync_plus_fallback_relays {
            cmd.env("NGIT_SYNC_PLUS_FALLBACK_RELAYS", fallback_relays);
        }
        if let Some(ref user_index_relays) = options.user_index_relays {
            cmd.env("NGIT_USER_INDEX_RELAYS", user_index_relays);
        }
        if let Some(ref private_members) = options.private_members {
            cmd.env("NGIT_PRIVATE_MODE", "true")
                .env("NGIT_PRIVATE_MEMBERS", private_members)
                .env(
                    "NGIT_PRIVATE_PUBLIC_ORIGIN",
                    format!("http://{bind_address}"),
                );
        }

        // The test infrastructure runs entirely on loopback, which the
        // production outbound target policy rejects for event-directed sync.
        // Default to the permissive test policy; policy regression tests opt
        // back into production behavior via enforce_outbound_target_policy.
        if !options.enforce_outbound_target_policy {
            cmd.env("NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS", "true");
        }

        if let Some(duration_secs) = options.rejected_hot_cache_duration_secs {
            cmd.env(
                "NGIT_REJECTED_HOT_CACHE_DURATION_SECS",
                duration_secs.to_string(),
            );
        }

        if let Some(log_level) = &options.log_level {
            cmd.env("NGIT_LOG_LEVEL", log_level);
        }

        if let Some(limit) = options.relay_max_subscriptions {
            cmd.env("NGIT_RELAY_MAX_SUBSCRIPTIONS", limit.to_string());
        }

        if let Some(limit) = options.sync_recursive_descendant_limit {
            cmd.env("NGIT_SYNC_RECURSIVE_DESCENDANT_LIMIT", limit.to_string());
        }

        // Add negentropy disable flag if requested
        if options.disable_negentropy {
            cmd.env("NGIT_SYNC_DISABLE_NEGENTROPY", "true");
        }

        // Add archive configuration if requested
        if options.archive_all {
            cmd.env("NGIT_ARCHIVE_ALL", "true");
        }
        if options.archive_read_only {
            cmd.env("NGIT_ARCHIVE_READ_ONLY", "true");
        }
        if let Some(services) = &options.archive_grasp_services {
            cmd.env("NGIT_ARCHIVE_GRASP_SERVICES", services);
        }

        // Enable GRASP-06 if requested. If the binary does not yet recognise
        // this env var (pre-implementation), clap simply ignores it.
        if options.grasp06_enable {
            cmd.env("NGIT_GRASP06_ENABLE", "true");
        }

        // Enable NIP-09 deletion disrespector (archival) mode if requested.
        if options.deletion_request_disrespector {
            cmd.env("NGIT_DELETION_REQUEST_DISRESPECTOR", "true");
        }

        if let Some(ref blacklist) = options.repository_blacklist {
            cmd.env("NGIT_REPOSITORY_BLACKLIST", blacklist);
        }

        if let Some(lifecycle) = &options.deletion_lifecycle {
            cmd.env(
                "NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS",
                lifecycle.unused_served_retention_secs.to_string(),
            )
            .env(
                "NGIT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS",
                lifecycle.unused_gating_additional_secs.to_string(),
            )
            .env(
                "NGIT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS",
                lifecycle.used_served_after_last_use_secs.to_string(),
            )
            .env(
                "NGIT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS",
                lifecycle.used_gating_additional_secs.to_string(),
            )
            .env(
                "NGIT_HOLDING_CLEANUP_INTERVAL_SECS",
                lifecycle.cleanup_interval_secs.to_string(),
            );
        }

        // GRASP-P (and any other ad-hoc) settings, applied last so they can
        // override the defaults above.
        for (name, value) in &options.extra_env {
            cmd.env(name, value);
        }

        // Transfer the reservation through exec and retain a parent copy
        // for same-address restarts. The port is never released during startup.
        let listener = reservation.into_std_listener();
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::process::CommandExt};
            let fd = listener.as_raw_fd();
            cmd.env("NGIT_TEST_LISTENER_FD", fd.to_string());
            // SAFETY: fcntl is async-signal-safe; the parent owns the descriptor
            // through spawn. The child adopts it before starting the server.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let process = cmd.spawn().expect("Failed to start relay process");

        let mut relay = Self {
            process,
            listener,
            url,
            port,
            owner_keys: test_keys.clone(),
            _git_data_dir: git_data_dir,
            git_data_path,
            _relay_data_dir: relay_data_dir,
            relay_data_path,
            options: RelayOptions {
                owner_keys: Some(test_keys),
                ..options.clone()
            },
        };

        match relay.wait_for_ready_or_early_exit().await {
            ReadyOutcome::Ready => StartOutcome::Ready(relay),
            ReadyOutcome::EarlyExit { status } => {
                // The subprocess is already gone; release the rest of
                // the fixture (tempdir, etc.) by dropping `relay` here
                // so the retry doesn't pile up unused temp dirs.
                drop(relay);
                StartOutcome::EarlyExit { status }
            }
        }
    }

    /// Get the relay WebSocket URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the relay domain (host:port)
    pub fn domain(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Get the scheme-less public service address, including any mount path.
    pub fn service_address(&self) -> String {
        let base_path = self.options.base_path.as_deref().unwrap_or("/");
        if base_path == "/" {
            self.domain()
        } else {
            format!("{}{base_path}", self.domain())
        }
    }

    /// Keys configured as this test relay's operator identity.
    pub fn owner_keys(&self) -> &Keys {
        &self.owner_keys
    }

    /// Get the subprocess log captured by the test harness.
    pub fn log_path(&self) -> PathBuf {
        PathBuf::from(format!("/tmp/relay-{}.log", self.port))
    }

    /// Address of this node's GRASP-P metrics endpoint, or `None` when its
    /// log announces none.
    ///
    /// The GRASP-P constructors ask for port 0, so the port is known only
    /// from the node's own startup line. The last such line counts: every
    /// spawn truncates the log, a restart included, so it belongs to the
    /// process that is running now.
    pub fn grasp_p_metrics_address(&self) -> Option<std::net::SocketAddr> {
        let log = std::fs::read_to_string(self.log_path()).ok()?;
        log.lines().rev().find_map(|line| {
            let (_, rest) =
                line.split_once(ngit_grasp::grasp_p::metrics_endpoint::LISTENING_LOG)?;
            rest.split_whitespace()
                .next()?
                .parse::<std::net::SocketAddr>()
                .ok()
        })
    }

    /// Scrape the metrics endpoint of a GRASP-P node.
    ///
    /// Such a node answers `/metrics` on its public port with the 404 page
    /// of any unknown path, and upstream's `fetch_metrics` returns the body
    /// of any status. An assertion that reads a missing series as 0 would
    /// pass on that page, so this panics unless the endpoint answers 200.
    pub async fn grasp_p_metrics(&self) -> String {
        // The node logs the address before it answers the readiness probe,
        // so the line is there by the time a test holds this relay. The
        // bounded wait only covers a log write still on its way to the file.
        let deadline = Instant::now() + READY_TIMEOUT;
        let address = loop {
            if let Some(address) = self.grasp_p_metrics_address() {
                break address;
            }
            assert!(
                Instant::now() < deadline,
                "relay {} announced no metrics endpoint in {} (is GRASP-P off, or \
                 NGIT_GRASP_P_METRICS_BIND overridden?)",
                self.port,
                self.log_path().display()
            );
            sleep(READY_POLL).await;
        };
        let url = format!("http://{address}/metrics");
        let response = reqwest::get(&url)
            .await
            .unwrap_or_else(|error| panic!("GET {url} failed: {error}"));
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|error| panic!("GET {url}: unreadable body: {error}"));
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "GET {url} must answer 200; body: {body}"
        );
        body
    }

    /// Stop the relay process and start a fresh one on the same port with
    /// the same options and data directories.
    ///
    /// Only meaningful for relays started with persistent (caller-owned)
    /// data directories: an in-memory or tempdir-backed relay would
    /// restart empty. The same port is re-reserved so addresses embedded
    /// in already-published events stay valid.
    pub async fn restart(mut self) -> Self {
        let port = self.port;
        let options = self.options.clone();
        let reservation = port::PortReservation::from_listener(
            self.listener.try_clone().expect("retain restart listener"),
        );
        let _ = self.process.kill();
        let _ = self.process.wait();
        drop(self);

        match Self::try_start_once(reservation, &options).await {
            StartOutcome::Ready(relay) => relay,
            StartOutcome::EarlyExit { status } => panic!(
                "restarted ngit-grasp subprocess exited early (status: {status:?}); \
                 check /tmp/relay-{port}.log"
            ),
        }
    }

    /// Get the git data directory path
    ///
    /// This is useful for test assertions that need to verify
    /// git repositories were created correctly.
    pub fn git_data_path(&self) -> &PathBuf {
        &self.git_data_path
    }

    /// Get the relay data directory path.
    pub fn relay_data_path(&self) -> &PathBuf {
        &self.relay_data_path
    }

    /// Probe the relay with a real HTTP request until it responds 200,
    /// while concurrently watching for the subprocess to exit early (the
    /// signature of a lost port-bind race). A raw TCP connect can succeed
    /// before Hyper has installed the service that accepts test clients,
    /// so HTTP readiness is the point where WebSocket clients may safely
    /// begin racing the relay.
    async fn wait_for_ready_or_early_exit(&mut self) -> ReadyOutcome {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            // Check whether the subprocess has already exited. If so no
            // readiness probe can succeed — bail immediately so the caller
            // can retry with a fresh port.
            match self.process.try_wait() {
                Ok(Some(status)) => return ReadyOutcome::EarlyExit { status },
                Ok(None) => { /* still running */ }
                Err(e) => {
                    panic!("Failed to poll relay subprocess status during readiness check: {e}");
                }
            }

            match self.probe_http_ready().await {
                Ok(()) => {
                    // HTTP service handled a request successfully, so the
                    // accept loop, Hyper service, and relay wiring are ready.
                    return ReadyOutcome::Ready;
                }
                Err(_) if Instant::now() < deadline => {
                    sleep(READY_POLL).await;
                }
                Err(e) => {
                    panic!(
                        "Relay at 127.0.0.1:{} did not become ready within {:?}: {e}",
                        self.port, READY_TIMEOUT,
                    );
                }
            }
        }
    }

    async fn probe_http_ready(&self) -> std::io::Result<()> {
        let base_path = self.options.base_path.as_deref().unwrap_or("/");
        probe_http_ready(self.port, base_path).await
    }

    /// Stop the relay
    /// Stop with SIGTERM so the relay runs its shutdown path, then reap it.
    pub async fn stop_gracefully(mut self) {
        let status = std::process::Command::new("kill")
            .args(["-TERM", &self.process.id().to_string()])
            .status()
            .expect("send SIGTERM to relay");
        assert!(status.success(), "SIGTERM delivery failed");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while self.process.try_wait().expect("poll relay").is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "relay did not exit after SIGTERM"
            );
            tokio::task::yield_now().await;
        }
    }

    pub async fn stop(mut self) {
        // kill() sends SIGKILL; reap directly instead of guessing a grace period.
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        // Ensure process is killed when TestRelay is dropped
        let _ = self.process.kill();
        let _ = self.process.wait();
        if std::thread::panicking() {
            // Sandboxed builders discard /tmp after failure. Preserve a bounded
            // tail from every participating relay in libtest's failure output.
            // Diagnostic I/O must never cause a second panic during unwinding.
            use std::io::{Read, Seek, SeekFrom, Write};
            let path = self.log_path();
            let tail = (|| -> std::io::Result<Vec<u8>> {
                let mut file = std::fs::File::open(&path)?;
                let start = file.metadata()?.len().saturating_sub(64 * 1024);
                file.seek(SeekFrom::Start(start))?;
                let mut bytes = Vec::new();
                file.take(64 * 1024).read_to_end(&mut bytes)?;
                Ok(bytes)
            })();
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "Relay {} failure log ({})",
                self.port,
                path.display()
            );
            match tail {
                Ok(bytes) => {
                    let _ = stderr.write_all(&bytes);
                    let _ = writeln!(stderr);
                }
                Err(error) => {
                    let _ = writeln!(stderr, "Could not read relay log: {error}");
                }
            }
        }
    }
}

/// Probe a relay's HTTP handler once, returning `Ok(())` only on a 200
/// response. A raw TCP connect can succeed before Hyper has installed the
/// service that accepts test clients, so only a handled request proves the
/// accept loop and relay wiring are live.
pub async fn probe_http_ready(port: u16, base_path: &str) -> std::io::Result<()> {
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        let request = format!(
            "GET {base_path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        let mut reader = tokio::io::BufReader::new(stream);
        let read =
            tokio::io::AsyncBufReadExt::read_until(&mut reader, b'\n', &mut response).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "readiness probe got empty HTTP response",
            ));
        }

        let status = String::from_utf8_lossy(&response[..read]);
        if status.starts_with("HTTP/1.1 200") || status.starts_with("HTTP/1.0 200") {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("readiness probe got non-200 response: {status:?}"),
            ))
        }
    };

    tokio::time::timeout(READY_PROBE_TIMEOUT, probe)
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTP readiness probe timed out",
            ))
        })
}

/// Poll [`probe_http_ready`] until the relay answers, bounded by `timeout`.
///
/// Used by test-local relay fixtures that spawn the binary themselves and so
/// cannot reuse [`TestRelay`]'s own readiness wait.
pub async fn wait_for_http_ready(port: u16, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match probe_http_ready(port, "/").await {
            Ok(()) => return Ok(()),
            Err(e) if Instant::now() >= deadline => {
                return Err(format!(
                    "relay at 127.0.0.1:{port} did not answer HTTP within {timeout:?}: {e}"
                ))
            }
            Err(_) => sleep(READY_POLL).await,
        }
    }
}

/// Connect `client` to its configured relays and return only once every
/// relay reports a completed connection attempt, failing the test if any
/// attempt fails.
///
/// `Client::connect().and_wait(..)` observes connection state through status
/// notifications after a separate status check; a loopback relay can connect
/// in that gap under scheduler pressure, and the missed notification then
/// stalls the caller for the whole timeout. `try_connect` awaits the attempt
/// itself, so healthy runs continue immediately and failures are explicit.
pub async fn connect_client(client: &Client) {
    let output = client.try_connect().timeout(Duration::from_secs(30)).await;
    assert!(
        output.failed.is_empty(),
        "relay connection attempts failed: {:?}",
        output.failed
    );
    assert!(
        !output.success.is_empty(),
        "no relay connection was attempted; add relays before connecting"
    );
}

/// Internal outcome of a single [`TestRelay::try_start_once`] attempt.
///
/// `EarlyExit` is the retry-eligible case (subprocess died before
/// becoming ready — almost always a lost bind race); `Ready` is the
/// happy path.
#[allow(clippy::large_enum_variant)]
enum StartOutcome {
    Ready(TestRelay),
    EarlyExit { status: std::process::ExitStatus },
}

/// Internal outcome of the readiness wait loop. Mirrors `StartOutcome`
/// but without the `TestRelay` payload — the relay is constructed by
/// the caller before calling the readiness probe.
enum ReadyOutcome {
    Ready,
    EarlyExit { status: std::process::ExitStatus },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `start()` reserves and uses a non-zero port end-to-end.
    /// (The reservation correctness invariants — distinct ports across
    /// parallel reservations, bindability after release — live in
    /// `port.rs`'s own unit tests.)
    #[tokio::test]
    async fn start_acquires_a_usable_port() {
        let relay = TestRelay::start().await;
        assert!(relay.port > 0);
        relay.stop().await;
    }
}
