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

use nostr_sdk::prelude::ToBech32;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::common::port::{self, PortReservation};

/// How long to wait for the spawned ngit-grasp subprocess to accept TCP
/// connections before giving up on a single attempt.
const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// How often to retry the TCP probe while waiting for readiness.
const READY_POLL: Duration = Duration::from_millis(100);
/// Extra grace after the listener accepts before declaring the relay
/// ready. Mirrors the existing fixture; without it the first WebSocket
/// upgrade can race the handler wiring.
const READY_GRACE: Duration = Duration::from_millis(100);
/// How many fresh port reservations to attempt before giving up. The
/// subprocess binds itself from `NGIT_BIND_ADDRESS`, so there is a
/// microsecond-scale TOCTOU window between [`PortReservation::release`]
/// and the subprocess's own `bind`. If that window loses the race the
/// subprocess exits before its TCP listener accepts; the readiness
/// check picks that up via `try_wait` so we can retry on a fresh port
/// instead of hanging the full readiness timeout.
///
/// In practice this loop has never been observed to fire in local
/// stress testing — kept as defense-in-depth for CI / loaded hardware.
const MAX_BIND_ATTEMPTS: usize = 5;

/// Test relay fixture that manages relay lifecycle
///
/// Automatically starts and stops the ngit-grasp relay for testing.
/// Uses a kernel-assigned port held open by a [`PortReservation`] until
/// just before subprocess spawn, eliminating the same-process port race
/// that plagued the older "bind, drop, return port" pattern.
pub struct TestRelay {
    process: Child,
    url: String,
    port: u16,
    /// Temporary directory for git repositories
    /// Kept alive for the lifetime of the relay
    _git_data_dir: tempfile::TempDir,
    /// Path to git data directory (for test assertions)
    git_data_path: PathBuf,
    /// Temporary directory for relay data (LMDB side stores)
    _relay_data_dir: tempfile::TempDir,
    /// Path to relay data directory (for test assertions)
    relay_data_path: PathBuf,
}

/// Options that the various `start*` constructors fan out into a single
/// internal entry point. Field names mirror the original positional
/// parameters so the call-site changes are mechanical.
#[derive(Default, Clone)]
struct RelayOptions {
    bootstrap_relay_url: Option<String>,
    disable_negentropy: bool,
    archive_all: bool,
    archive_read_only: bool,
    grasp06_enable: bool,
    deletion_request_disrespector: bool,
    lmdb_backend: bool,
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
    /// Retries up to [`MAX_BIND_ATTEMPTS`] times if the subprocess exits
    /// early — that's the signature of having lost the bind race in the
    /// microseconds between [`PortReservation::release`] and the
    /// subprocess's own `bind`. Each retry draws a brand-new
    /// kernel-assigned port; two consecutive `AddrInUse` failures would
    /// therefore require two independent races back to back.
    async fn start_internal(initial_reservation: PortReservation, options: RelayOptions) -> Self {
        let mut reservation = Some(initial_reservation);
        for attempt in 1..=MAX_BIND_ATTEMPTS {
            // Each attempt consumes the current reservation. On retry we
            // re-acquire from the kernel — guaranteed to give us a port
            // number different from any reservation currently held
            // elsewhere in this process.
            let r = reservation
                .take()
                .expect("reservation always present on attempt entry");
            match Self::try_start_once(r, &options).await {
                StartOutcome::Ready(relay) => return relay,
                StartOutcome::EarlyExit { status } if attempt < MAX_BIND_ATTEMPTS => {
                    eprintln!(
                        "[TestRelay] ngit-grasp exited early on attempt \
                         {attempt}/{MAX_BIND_ATTEMPTS} (status: {status:?}); \
                         likely a port-bind race — retrying with a fresh port",
                    );
                    reservation = Some(port::reserve_port());
                    continue;
                }
                StartOutcome::EarlyExit { status } => {
                    panic!(
                        "ngit-grasp subprocess exited early after {MAX_BIND_ATTEMPTS} attempts \
                         (last exit status: {status:?}). If this is not a port-bind race, \
                         check /tmp/relay-*.log for the relay's stdout."
                    );
                }
            }
        }
        unreachable!("MAX_BIND_ATTEMPTS loop terminated without returning")
    }

    /// One attempt at spawning ngit-grasp on the given reservation and
    /// waiting for it to be ready. Returns [`StartOutcome::EarlyExit`]
    /// specifically when the subprocess died before the readiness probe
    /// succeeded — the caller may retry in that case.
    async fn try_start_once(reservation: PortReservation, options: &RelayOptions) -> StartOutcome {
        let port = reservation.port();
        let bind_address = format!("127.0.0.1:{}", port);
        let url = format!("ws://127.0.0.1:{}", port);

        // Create temporary directory for git repositories
        let git_data_dir =
            tempfile::tempdir().expect("Failed to create temporary git data directory");
        let relay_data_dir =
            tempfile::tempdir().expect("Failed to create temporary relay data directory");

        // Use the built binary directly (faster than cargo run)
        let binary_path = std::env::current_exe()
            .expect("Failed to get current exe")
            .parent()
            .expect("Failed to get parent dir")
            .parent()
            .expect("Failed to get grandparent dir")
            .join("ngit-grasp");

        // Generate a test owner npub (using a random keypair)
        let test_keys = nostr_sdk::prelude::Keys::generate();
        let test_npub = test_keys
            .public_key()
            .to_bech32()
            .expect("Failed to generate test npub");

        // Build the Command *before* releasing the reservation so that
        // none of the env-setting allocations happen while the listener
        // is held. We release immediately before `spawn`.
        let mut cmd = Command::new(&binary_path);
        cmd.env("NGIT_BIND_ADDRESS", &bind_address)
            .env("NGIT_DOMAIN", &bind_address) // Set domain to match bind address
            .env("NGIT_GIT_DATA_PATH", git_data_dir.path())
            .env("NGIT_RELAY_DATA_PATH", relay_data_dir.path())
            .env("NGIT_OWNER_NPUB", &test_npub)
            .env("NGIT_TEST", "1") // Enable test mode: fast timers (200ms batch window, 200ms purgatory sync)
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
                    .append(true)
                    .open(format!("/tmp/relay-{}.log", port))
                    .map(Stdio::from)
                    .unwrap_or(Stdio::null()),
            )
            .stderr(Stdio::inherit()); // Inherit stderr for test output

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
            cmd.env("NGIT_SYNC_BOOTSTRAP_RELAY_URL", bootstrap_url);
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

        // Enable GRASP-06 if requested. If the binary does not yet recognise
        // this env var (pre-implementation), clap simply ignores it.
        if options.grasp06_enable {
            cmd.env("NGIT_GRASP06_ENABLE", "true");
        }

        // Enable NIP-09 deletion disrespector (archival) mode if requested.
        if options.deletion_request_disrespector {
            cmd.env("NGIT_DELETION_REQUEST_DISRESPECTOR", "true");
        }

        // Release the port reservation immediately before spawning the
        // subprocess that will bind it. Holding the reservation through
        // env-var setup above is what keeps any concurrent
        // `reserve_port()` calls from picking this same number.
        let _ = reservation.release();

        let process = cmd.spawn().expect("Failed to start relay process");

        // Store git data path for test assertions
        let git_data_path = git_data_dir.path().to_path_buf();
        let relay_data_path = relay_data_dir.path().to_path_buf();

        let mut relay = Self {
            process,
            url,
            port,
            _git_data_dir: git_data_dir,
            git_data_path,
            _relay_data_dir: relay_data_dir,
            relay_data_path,
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

    /// Probe the listener with async TCP connects until it accepts,
    /// while concurrently watching for the subprocess to exit early
    /// (the signature of a lost port-bind race). Without the early-exit
    /// check we'd burn the full [`READY_TIMEOUT`] on a process that's
    /// already dead.
    async fn wait_for_ready_or_early_exit(&mut self) -> ReadyOutcome {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            // Check whether the subprocess has already exited. If so the
            // TCP probe will never succeed — bail immediately so the
            // caller can retry with a fresh port.
            match self.process.try_wait() {
                Ok(Some(status)) => return ReadyOutcome::EarlyExit { status },
                Ok(None) => { /* still running */ }
                Err(e) => {
                    panic!("Failed to poll relay subprocess status during readiness check: {e}");
                }
            }

            match tokio::net::TcpStream::connect(("127.0.0.1", self.port)).await {
                Ok(_) => {
                    // Connection successful, relay is ready
                    // Give it a tiny bit more time to fully initialize
                    sleep(READY_GRACE).await;
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

    /// Stop the relay
    pub async fn stop(mut self) {
        // Kill the process (gracefully if possible)
        let _ = self.process.kill();

        // Wait a bit for graceful shutdown
        sleep(Duration::from_millis(100)).await;

        // Force kill if still running
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        // Ensure process is killed when TestRelay is dropped
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Internal outcome of a single [`TestRelay::try_start_once`] attempt.
///
/// `EarlyExit` is the retry-eligible case (subprocess died before
/// becoming ready — almost always a lost bind race); `Ready` is the
/// happy path.
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
