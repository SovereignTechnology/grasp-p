//! Git HTTP Protocol Handlers
//!
//! This module implements the HTTP handlers for Git Smart HTTP protocol.

use futures_util::stream;
use http_body_util::{BodyExt, StreamBody};
use hyper::{body::Bytes, body::Frame, Response, StatusCode};
use nostr_relay_builder::LocalRelay;
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use super::protocol::{GitService, PktLine};
use super::subprocess::GitSubprocess;
use super::{full_body, GitResponseBody};

use crate::git::authorization::{authorize_push, parse_pushed_refs};
use crate::git::sync::{process_newly_available_git_data, PurgatoryPromotionHooks};
use crate::metrics::Metrics;
use crate::nostr::lifecycle::LifecycleReadGuard;
use crate::nostr::SharedDatabase;
use crate::purgatory::Purgatory;

pub(crate) const STREAM_CHANNEL_DEPTH: usize = 8;
const STREAM_CHUNK_SIZE: usize = 8 * 1024;
const POST_PUSH_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const POST_PUSH_KEEPALIVE_MESSAGE: &[u8] = b"GRASP is finalizing the push\n";

/// Handle GET /info/refs?service=git-{upload,receive}-pack
///
/// This advertises the repository's refs to the client.
pub async fn handle_info_refs(
    repo_path: PathBuf,
    service: GitService,
    git_protocol: Option<&str>,
) -> Result<Response<GitResponseBody>, GitError> {
    debug!(
        "Handling info/refs for {:?} with service {:?}",
        repo_path, service
    );

    // Check if repository exists
    if !repo_path.exists() {
        warn!("Repository not found: {:?}", repo_path);
        return Err(GitError::RepositoryNotFound);
    }

    // Spawn git with --advertise-refs
    let mut git = GitSubprocess::spawn(service, &repo_path, true, git_protocol).map_err(|e| {
        error!("Failed to spawn git process: {}", e);
        GitError::ProcessSpawnFailed(e)
    })?;

    // Read the output from git
    let mut output = Vec::new();
    let mut stderr_output = Vec::new();

    if let Some(stdout) = git.take_stdout() {
        let mut stdout = stdout;
        stdout.read_to_end(&mut output).await.map_err(|e| {
            error!("Failed to read git output: {}", e);
            GitError::IoError(e)
        })?;
    }

    if let Some(stderr) = git.take_stderr() {
        let mut stderr = stderr;
        stderr.read_to_end(&mut stderr_output).await.map_err(|e| {
            error!("Failed to read git stderr: {}", e);
            GitError::IoError(e)
        })?;
    }

    // Wait for process to complete
    let status = git.wait().await.map_err(|e| {
        error!("Failed to wait for git process: {}", e);
        GitError::IoError(e)
    })?;

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr_output);
        error!(
            "Git process failed with status: {:?}, stderr: {}",
            status, stderr_str
        );
        return Err(GitError::GitFailed(status.code()));
    }

    // Build response with pkt-line header
    let mut response_body = Vec::new();

    // First line: service advertisement
    let service_line = format!("# service={}\n", service.as_str());
    response_body.extend_from_slice(&PktLine::data(service_line.as_bytes()).encode());
    response_body.extend_from_slice(&PktLine::flush().encode());

    // Then the git output
    response_body.extend_from_slice(&output);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", service.advertisement_content_type())
        .header("cache-control", "no-cache")
        .body(full_body(response_body))
        .unwrap())
}

/// Detect whether a git-receive-pack client negotiated `side-band-64k`.
///
/// On a receive-pack POST, the client advertises its capabilities in the
/// first command pkt-line of the request body. Per the smart-HTTP protocol,
/// the format of that pkt-line is:
///
///   <old-oid> SP <new-oid> SP <ref-name> NUL <capabilities>
///
/// Where `<capabilities>` is a space-separated list that may include
/// `side-band-64k` (and/or the legacy `side-band`). We look at the bytes
/// after the first NUL inside the first non-flush pkt-line and check for
/// the capability token.
///
/// Returns `false` for any malformed or truncated body, which is the
/// conservative choice because a `false` answer means we do NOT band-wrap
/// the ERR pkt-line and clients without sideband-64k will still see it.
///
/// `pub(crate)` for testability.
pub(crate) fn client_negotiated_sideband_64k(request_body: &[u8]) -> bool {
    // First 4 bytes are the hex length of the first pkt-line. "0000" is a
    // flush packet (shouldn't appear here) — bail.
    if request_body.len() < 4 {
        return false;
    }
    let len_str = match std::str::from_utf8(&request_body[0..4]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let len = match u16::from_str_radix(len_str, 16) {
        Ok(n) => n as usize,
        Err(_) => return false,
    };
    if len < 4 || request_body.len() < len {
        return false;
    }
    let payload = &request_body[4..len];
    // Look for capability list after first NUL byte
    let caps = match payload.iter().position(|&b| b == 0) {
        Some(pos) => &payload[pos + 1..],
        None => return false,
    };
    // Capabilities are space-separated tokens, possibly terminated by LF.
    for tok in caps.split(|&b| b == b' ' || b == b'\n' || b == b'\0') {
        if tok == b"side-band-64k" {
            return true;
        }
    }
    false
}

/// Build an HTTP 200 OK response with an ERR pkt-line for git protocol errors.
///
/// Per the git smart HTTP protocol spec, protocol-level errors (like "not our ref")
/// should be returned as HTTP 200 OK with the error message in pkt-line format:
/// `PKT-LINE("ERR" SP explanation-text)`
///
/// This allows git clients to properly parse and display the error message.
///
/// **Sideband wrapping (git-receive-pack):** modern `git push` clients
/// always advertise `side-band-64k` when posting to `git-receive-pack`.
/// When sideband is negotiated, the client demultiplexes the response via
/// `recv_sideband`, which reads the first byte of each pkt-line payload as
/// the band id (1=pack data, 2=progress, 3=error). A bare `ERR ...`
/// payload is therefore interpreted as band id `0x45` (`'E'`, decimal 69)
/// and the client aborts with `send-pack: protocol error: bad band #69`.
///
/// To stay compatible with sideband-aware clients, when this is a
/// receive-pack response and `request_body` shows the client advertised
/// `side-band-64k`, the ERR pkt-line payload is prefixed with band id 3
/// ("error") inside the pkt-line frame.
///
/// `pub(crate)` so the `/prs/` receive-pack handler in `crate::grasp06::receive`
/// can return identically-shaped rejections without duplicating the pkt-line
/// framing.
pub(crate) fn build_git_protocol_error_response(
    service: GitService,
    error_message: &str,
    request_body: Option<&[u8]>,
) -> Response<GitResponseBody> {
    let err_pktline = encode_err_pktline(service, error_message, request_body);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", service.result_content_type())
        .header("cache-control", "no-cache")
        .body(full_body(err_pktline))
        .unwrap()
}

fn encode_err_pktline(
    service: GitService,
    error_message: &str,
    request_body: Option<&[u8]>,
) -> Vec<u8> {
    // Format: "ERR <message>\n"
    let err_content = format!("ERR {}\n", error_message.trim());

    // Wrap in sideband band 3 when the receive-pack client negotiated
    // side-band-64k. See doc comment above for the protocol details.
    let use_sideband = matches!(service, GitService::ReceivePack)
        && request_body
            .map(client_negotiated_sideband_64k)
            .unwrap_or(false);

    if use_sideband {
        let mut framed = Vec::with_capacity(1 + err_content.len());
        framed.push(0x03); // band 3 = error
        framed.extend_from_slice(err_content.as_bytes());
        PktLine::data(framed).encode()
    } else {
        PktLine::data(err_content.as_bytes()).encode()
    }
}

pub(crate) fn err_pktline_frame(
    service: GitService,
    error_message: &str,
    request_body: Option<&[u8]>,
) -> Frame<Bytes> {
    Frame::data(Bytes::from(encode_err_pktline(
        service,
        error_message,
        request_body,
    )))
}

/// Check if a git process failure is a protocol error (vs transport error).
///
/// Protocol errors are communicated via stderr when git exits with code 128.
/// These should be returned to the client as HTTP 200 with ERR pkt-line.
///
/// Transport errors (process spawn failures, I/O errors, signals) should
/// remain as HTTP 500 errors.
///
/// `pub(crate)` so the `/prs/` receive-pack handler in `crate::grasp06::receive`
/// can classify subprocess failures the same way without duplicating the rule.
pub(crate) fn is_git_protocol_error(exit_code: Option<i32>, stderr: &[u8]) -> bool {
    // Git uses exit code 128 for protocol/usage errors
    // If there's stderr content, it's a protocol error message
    exit_code == Some(128) && !stderr.is_empty()
}

/// Build the common channel-backed Git response used by streaming handlers.
///
/// The handler returns this response before the Git child has necessarily
/// exited. A background task sends `Frame<Bytes>` values into `rx`; dropping the
/// sender closes the HTTP body. Kept `pub(crate)` so `/prs/` receive-pack can
/// use the same wire shape as the standard endpoints.
pub(crate) fn streaming_response(
    service: GitService,
    rx: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>,
) -> Response<GitResponseBody> {
    let body_stream = stream::unfold(rx, |mut rx| async {
        rx.recv().await.map(|item| (item, rx))
    });
    let body = BodyExt::boxed(StreamBody::new(body_stream));

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", service.result_content_type())
        .header("cache-control", "no-cache")
        .body(body)
        .unwrap()
}

/// Record Git metrics from either the request handler or the detached streaming
/// task without repeating the `Option<Metrics>` plumbing at every callsite.
pub(crate) fn record_git_operation(metrics: &Option<Arc<Metrics>>, operation: &str, status: &str) {
    if let Some(metrics) = metrics {
        metrics.record_git_operation(operation, status);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PumpResult {
    /// Stdout reached EOF. `sent_stdout` tells callers whether it is still safe
    /// to synthesize a Git `ERR` pkt-line for a late process failure.
    Eof { sent_stdout: bool },
    /// The response receiver was dropped, usually because the HTTP client
    /// disconnected. Callers should stop the child process and clean up state.
    ClientDisconnected,
    /// Reading stdout failed. The read error has already been sent through the
    /// body channel so Hyper can terminate the response stream.
    ReadError,
}

/// Forward Git stdout into the streaming response channel.
///
/// This is intentionally only the stdout pump. The caller still owns process
/// termination, stderr collection, protocol-error classification, and any
/// endpoint-specific cleanup after the stream ends.
pub(crate) async fn pump_stdout_to_channel<R>(
    mut stdout: R,
    tx: &mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
) -> PumpResult
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut read_buf = [0_u8; STREAM_CHUNK_SIZE];
    let mut sent_stdout = false;

    loop {
        match stdout.read(&mut read_buf).await {
            Ok(0) => return PumpResult::Eof { sent_stdout },
            Ok(n) => {
                sent_stdout = true;
                if send_body_bytes(tx, read_buf[..n].to_vec()).await.is_err() {
                    return PumpResult::ClientDisconnected;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return PumpResult::ReadError;
            }
        }
    }
}

/// Forward receive-pack progress while retaining its protocol terminator.
///
/// A successful receive-pack response ends with a `0000` flush pkt-line.
/// Git clients use that flush as the semantic end of the push and need not wait
/// for the HTTP body to reach EOF. Retaining the final four bytes lets the
/// caller finish GRASP post-push processing before making success visible,
/// without buffering the progress stream that keeps clients alive during
/// expensive pack processing.
async fn pump_receive_pack_stdout_to_channel<R>(
    mut stdout: R,
    tx: &mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
) -> (PumpResult, Option<Vec<u8>>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    const FLUSH_PKT: &[u8; 4] = b"0000";

    let mut read_buf = [0_u8; STREAM_CHUNK_SIZE];
    let mut pending = Vec::with_capacity(4);
    let mut sent_stdout = false;

    loop {
        match stdout.read(&mut read_buf).await {
            Ok(0) => {
                if pending.as_slice() == FLUSH_PKT {
                    return (
                        PumpResult::Eof { sent_stdout },
                        Some(std::mem::take(&mut pending)),
                    );
                }

                if !pending.is_empty() {
                    sent_stdout = true;
                    if send_body_bytes(tx, std::mem::take(&mut pending))
                        .await
                        .is_err()
                    {
                        return (PumpResult::ClientDisconnected, None);
                    }
                }

                return (PumpResult::Eof { sent_stdout }, None);
            }
            Ok(n) => {
                pending.extend_from_slice(&read_buf[..n]);
                if pending.len() > FLUSH_PKT.len() {
                    let retained = pending.split_off(pending.len() - FLUSH_PKT.len());
                    sent_stdout = true;
                    if send_body_bytes(tx, std::mem::replace(&mut pending, retained))
                        .await
                        .is_err()
                    {
                        return (PumpResult::ClientDisconnected, None);
                    }
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return (PumpResult::ReadError, None);
            }
        }
    }
}

/// Encode progress that keeps a sideband-aware receive-pack client alive.
///
/// Post-push purgatory promotion can copy objects and align several owner
/// repositories. The terminal flush remains withheld until that work finishes,
/// so send a valid band-2 pkt-line during a long finalization window instead of
/// leaving libgit2 with no response bytes until its per-recv timeout expires.
fn receive_pack_keepalive_pktline() -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + POST_PUSH_KEEPALIVE_MESSAGE.len());
    payload.push(0x02); // band 2 = progress
    payload.extend_from_slice(POST_PUSH_KEEPALIVE_MESSAGE);
    PktLine::data(payload).encode()
}

struct ReceivePackKeepalive {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ReceivePackKeepalive {
    fn spawn(tx: mpsc::Sender<Result<Frame<Bytes>, io::Error>>, period: Duration) -> Self {
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            ticker.tick().await;

            loop {
                ticker.tick().await;
                if send_body_bytes(&tx, receive_pack_keepalive_pktline())
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        Self { task: Some(task) }
    }

    async fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for ReceivePackKeepalive {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Drain Git stderr for later logging or Git protocol error synthesis.
///
/// Streaming handlers run this concurrently with stdout pumping so the child
/// cannot block on a full stderr pipe while the HTTP body is still being read.
pub(crate) async fn read_stderr_to_end<R>(mut stderr: R) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut stderr_output = Vec::new();
    if let Err(e) = stderr.read_to_end(&mut stderr_output).await {
        warn!("Failed to read git subprocess stderr: {}", e);
    }
    stderr_output
}

/// Handle POST /git-upload-pack (clone/fetch)
pub async fn handle_upload_pack(
    repo_path: PathBuf,
    request_body: Bytes,
    git_protocol: Option<&str>,
    repo_lifecycle_guard: Option<LifecycleReadGuard>,
    metrics: Option<Arc<Metrics>>,
) -> Result<Response<GitResponseBody>, GitError> {
    debug!("Handling upload-pack for {:?}", repo_path);

    if !repo_path.exists() {
        return Err(GitError::RepositoryNotFound);
    }

    // Spawn git upload-pack
    let mut git = GitSubprocess::spawn(GitService::UploadPack, &repo_path, false, git_protocol)
        .map_err(GitError::ProcessSpawnFailed)?;

    // Write request to git's stdin
    if let Some(mut stdin) = git.take_stdin() {
        stdin.write_all(&request_body).await.map_err(|e| {
            error!("Failed to write to git upload-pack stdin: {}", e);
            GitError::IoError(e)
        })?;
        // Close stdin to signal end of input
        drop(stdin);
    }

    let stdout = git.take_stdout().ok_or_else(|| {
        GitError::IoError(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "git upload-pack stdout unavailable",
        ))
    })?;
    let stderr = git.take_stderr();

    // Stream upload-pack stdout as Git produces it instead of buffering the
    // whole fetch response in memory. The detached task below owns the child
    // until EOF so the request future can return the HTTP body immediately.
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(STREAM_CHANNEL_DEPTH);

    tokio::spawn(async move {
        stream_upload_pack_output(git, stdout, stderr, tx, repo_lifecycle_guard, metrics).await;
    });

    Ok(streaming_response(GitService::UploadPack, rx))
}

async fn stream_upload_pack_output<S, E>(
    mut git: GitSubprocess,
    stdout: S,
    stderr: Option<E>,
    tx: mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
    repo_lifecycle_guard: Option<LifecycleReadGuard>,
    metrics: Option<Arc<Metrics>>,
) where
    S: tokio::io::AsyncRead + Unpin + Send + 'static,
    E: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let stderr_task = stderr.map(|stderr| tokio::spawn(read_stderr_to_end(stderr)));
    let pump_result = pump_stdout_to_channel(stdout, &tx).await;

    if !matches!(pump_result, PumpResult::Eof { .. }) {
        let _ = git.kill().await;
    }

    let status = match git.wait().await {
        Ok(status) => status,
        Err(e) => {
            let _ = tx.send(Err(e)).await;
            drop(repo_lifecycle_guard);
            record_git_operation(&metrics, "clone", "error");
            return;
        }
    };

    // Keep the repository lifecycle read lock until git-upload-pack exits so
    // deletion/archive/restore cannot remove or replace the bare repository
    // while Git is still reading it in the detached streaming task.
    drop(repo_lifecycle_guard);

    let stderr_output = match stderr_task {
        Some(task) => task.await.unwrap_or_default(),
        None => Vec::new(),
    };

    if !status.success() && matches!(pump_result, PumpResult::Eof { sent_stdout: false }) {
        record_git_operation(&metrics, "clone", "error");
        let stderr_str = String::from_utf8_lossy(&stderr_output);
        let msg = if stderr_str.trim().is_empty() {
            format!("git upload-pack failed with code {:?}", status.code())
        } else {
            stderr_str.to_string()
        };

        if is_git_protocol_error(status.code(), &stderr_output) {
            warn!(
                "Git upload-pack protocol error (returning ERR pkt-line): {}",
                stderr_str
            );
        } else {
            error!("Git upload-pack failed: {}", stderr_str);
        }

        // The streaming response headers have already been sent. If Git failed
        // before producing any stdout, surface a protocol-visible ERR pkt-line
        // instead of silently completing an empty HTTP 200 body.
        let _ = tx
            .send(Ok(err_pktline_frame(GitService::UploadPack, &msg, None)))
            .await;
    } else if !status.success() {
        record_git_operation(&metrics, "clone", "error");
        let stderr_str = String::from_utf8_lossy(&stderr_output);
        error!(
            "Git upload-pack failed after streaming stdout: {}",
            stderr_str
        );
    } else if matches!(pump_result, PumpResult::Eof { .. }) {
        debug!("Git upload-pack stream completed successfully");
        record_git_operation(&metrics, "clone", "success");
    } else {
        record_git_operation(&metrics, "clone", "error");
    }
}

/// Handle POST /git-receive-pack (push)
///
/// This includes GRASP authorization validation according to GRASP-01:
/// "MUST accept pushes via this service that match the latest repo state announcement
/// on the relay, respecting the recursive maintainer set."
///
/// Also per GRASP-01: "MUST set repository HEAD per repository state announcement
/// as soon as the git data related to that branch has been received."
///
/// Also purgatory GRASP-01: "Accepted repo state announcements, PRs and PR Updates
/// SHOULD be accepted with message "purgatory: won't be served until git data arrives"
/// and kepted in purgatory (not served) until the related git data arrives and
/// otherwise discarded after 30 minutes."
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
/// * `request_body` - The git pack data from the client
/// * `database` - Database reference for authorization queries
/// * `identifier` - The repository identifier (d tag) for authorization lookup
/// * `owner_pubkey` - The owner's public key (hex) from the URL path, scoping authorization
/// * `git_data_path` - Base path for git repositories (for syncing to other owner repos)
/// * `git_protocol` - Optional Git protocol version (e.g., "version=2")
#[allow(clippy::too_many_arguments)]
pub async fn handle_receive_pack(
    repo_path: PathBuf,
    request_body: Bytes,
    database: SharedDatabase,
    relay: LocalRelay,
    identifier: &str,
    owner_pubkey: &str,
    purgatory: Arc<Purgatory>,
    git_data_path: &str,
    git_protocol: Option<&str>,
    repo_lifecycle_guard: Option<LifecycleReadGuard>,
    promotion_hooks: Option<Arc<dyn PurgatoryPromotionHooks>>,
    metrics: Option<Arc<Metrics>>,
) -> Result<Response<GitResponseBody>, GitError> {
    debug!("Handling receive-pack for {:?}", repo_path);

    if !repo_path.exists() {
        return Err(GitError::RepositoryNotFound);
    }

    // GRASP Authorization Check
    debug!(
        "Authorizing push for {} owned by {} via database query",
        identifier, owner_pubkey
    );

    // check push is authorised
    let _auth_result = match authorize_push(
        &database,
        identifier,
        owner_pubkey,
        &request_body,
        &purgatory,
        &repo_path,
    )
    .await
    {
        Ok(auth_result) => {
            if !auth_result.authorized {
                warn!("Push rejected for {}: {}", identifier, auth_result.reason);
                record_git_operation(&metrics, "push", "error");
                return Ok(build_git_protocol_error_response(
                    GitService::ReceivePack,
                    &format!("authorisation failed: {}", auth_result.reason),
                    Some(&request_body),
                ));
            }
            info!(
                "Push authorized for {} - {} maintainers, {} purgatory events: {}",
                identifier,
                auth_result.maintainers.len(),
                auth_result.purgatory_events.len(),
                auth_result.reason
            );
            auth_result
        }
        Err(e) => {
            warn!("Authorization check failed for {}: {}", identifier, e);
            record_git_operation(&metrics, "push", "error");
            return Ok(build_git_protocol_error_response(
                GitService::ReceivePack,
                &format!("authorisation failed: {}", e),
                Some(&request_body),
            ));
        }
    };

    // Spawn git receive-pack
    let mut git = GitSubprocess::spawn(GitService::ReceivePack, &repo_path, false, git_protocol)
        .map_err(GitError::ProcessSpawnFailed)?;

    // Write request to git's stdin
    if let Some(mut stdin) = git.take_stdin() {
        stdin.write_all(&request_body).await.map_err(|e| {
            error!("Failed to write to git receive-pack stdin: {}", e);
            GitError::IoError(e)
        })?;
        drop(stdin);
    }

    let stdout = git.take_stdout().ok_or_else(|| {
        GitError::IoError(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "git receive-pack stdout unavailable",
        ))
    })?;
    let stderr = git.take_stderr();

    // Do not buffer receive-pack stdout: for large pushes Git may spend tens of
    // seconds resolving deltas/checking connectivity after the client finishes
    // uploading. Streaming sideband progress keeps libgit2 clients from
    // hitting their per-recv timeout during that otherwise-silent window.
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(STREAM_CHANNEL_DEPTH);
    let pushed_refs = parse_pushed_refs(&request_body);
    let new_oids: HashSet<String> = pushed_refs
        .iter()
        .filter(|(_, new_oid, _)| new_oid != "0000000000000000000000000000000000000000")
        .map(|(_, new_oid, _)| new_oid.clone())
        .collect();
    let request_body_for_errors = request_body.clone();
    let identifier = identifier.to_owned();
    let git_data_path = git_data_path.to_owned();

    tokio::spawn(async move {
        stream_receive_pack_output(
            git,
            stdout,
            stderr,
            tx,
            repo_path,
            new_oids,
            database,
            relay,
            identifier,
            purgatory,
            git_data_path,
            request_body_for_errors,
            repo_lifecycle_guard,
            promotion_hooks,
            metrics,
        )
        .await;
    });

    Ok(streaming_response(GitService::ReceivePack, rx))
}

#[allow(clippy::too_many_arguments)]
async fn stream_receive_pack_output<S, E>(
    mut git: GitSubprocess,
    stdout: S,
    stderr: Option<E>,
    tx: mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
    repo_path: PathBuf,
    new_oids: HashSet<String>,
    database: SharedDatabase,
    relay: LocalRelay,
    identifier: String,
    purgatory: Arc<Purgatory>,
    git_data_path: String,
    request_body: Bytes,
    repo_lifecycle_guard: Option<LifecycleReadGuard>,
    promotion_hooks: Option<Arc<dyn PurgatoryPromotionHooks>>,
    metrics: Option<Arc<Metrics>>,
) where
    S: tokio::io::AsyncRead + Unpin + Send + 'static,
    E: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let stderr_task = stderr.map(|stderr| tokio::spawn(read_stderr_to_end(stderr)));
    let (pump_result, terminal_flush) = pump_receive_pack_stdout_to_channel(stdout, &tx).await;

    if !matches!(pump_result, PumpResult::Eof { .. }) {
        let _ = git.kill().await;
    }

    let status = match git.wait().await {
        Ok(status) => status,
        Err(e) => {
            let _ = tx.send(Err(e)).await;
            drop(repo_lifecycle_guard);
            record_git_operation(&metrics, "push", "error");
            return;
        }
    };

    let stderr_output = match stderr_task {
        Some(task) => task.await.unwrap_or_default(),
        None => Vec::new(),
    };

    let mut sent_stdout = match pump_result {
        PumpResult::Eof { sent_stdout } => sent_stdout,
        PumpResult::ClientDisconnected | PumpResult::ReadError => {
            drop(repo_lifecycle_guard);
            record_git_operation(&metrics, "push", "error");
            return;
        }
    };

    if !status.success() {
        if let Some(flush) = terminal_flush {
            sent_stdout = true;
            if send_body_bytes(&tx, flush).await.is_err() {
                drop(repo_lifecycle_guard);
                record_git_operation(&metrics, "push", "error");
                return;
            }
        }

        drop(repo_lifecycle_guard);
        record_git_operation(&metrics, "push", "error");
        let stderr_str = String::from_utf8_lossy(&stderr_output);

        if is_git_protocol_error(status.code(), &stderr_output) {
            warn!(
                "Git receive-pack protocol error (returning ERR pkt-line): {}",
                stderr_str
            );
            if !sent_stdout {
                let _ = tx
                    .send(Ok(err_pktline_frame(
                        GitService::ReceivePack,
                        &stderr_str,
                        Some(&request_body),
                    )))
                    .await;
            }
        } else {
            error!("Git receive-pack failed: {}", stderr_str);
            if !sent_stdout {
                let msg = if stderr_str.trim().is_empty() {
                    format!("git receive-pack failed with code {:?}", status.code())
                } else {
                    stderr_str.to_string()
                };
                let _ = tx
                    .send(Ok(err_pktline_frame(
                        GitService::ReceivePack,
                        &msg,
                        Some(&request_body),
                    )))
                    .await;
            }
        }
        return;
    }

    debug!("Git receive-pack stream completed successfully");

    // Release the repository lifecycle read lock once git-receive-pack itself
    // has finished. The lock's purpose is to keep deletion/archive/restore from
    // removing or replacing the bare repository while Git is actively reading or
    // writing it; Git's own internal locking handles concurrent push/fetch ref
    // and object consistency. Post-push purgatory promotion may re-enter
    // recovery paths that take the lifecycle write lock, so holding this beyond
    // the subprocess boundary would deadlock.
    drop(repo_lifecycle_guard);

    // Git's receive-pack progress has already been streamed verbatim, but its
    // final flush remains withheld. Run GRASP follow-up work before releasing
    // that client-visible success boundary so push completion implies local
    // refs/HEAD and promoted events are ready. Follow-up failures remain
    // internal/log-only rather than client-visible push rejections.
    //
    // A complex promotion may itself run longer than the client's receive
    // timeout. Only clients that negotiated side-band-64k can safely receive
    // invented progress pkt-lines, so keep those clients alive while leaving
    // the response for non-sideband clients byte-for-byte unchanged.
    let keepalive_task =
        if terminal_flush.is_some() && client_negotiated_sideband_64k(&request_body) {
            Some(ReceivePackKeepalive::spawn(
                tx.clone(),
                POST_PUSH_KEEPALIVE_INTERVAL,
            ))
        } else {
            None
        };

    let processing_result = process_newly_available_git_data(
        &repo_path,
        &new_oids,
        &database,
        Some(&relay),
        &purgatory,
        std::path::Path::new(&git_data_path),
        promotion_hooks.as_deref(),
    )
    .await;

    // Stop and join the sender before releasing the flush so no keepalive can
    // race behind the terminal protocol boundary.
    if let Some(task) = keepalive_task {
        task.stop().await;
    }

    match processing_result {
        Ok(result) => {
            if result.released_any() {
                info!(
                    "Processed push for {}: {} states released, {} PRs released, {} repos synced",
                    identifier, result.states_released, result.prs_released, result.repos_synced
                );
            }

            if !result.errors.is_empty() {
                for error in &result.errors {
                    warn!(
                        "Error during post-push processing for {}: {}",
                        identifier, error
                    );
                }
            }
        }
        Err(e) => {
            warn!(
                "Failed to process newly available git data after push to {}: {}",
                identifier, e
            );
        }
    }

    // The final receive-pack flush is the client-visible success boundary.
    // Release it only after promoted events have been saved and subscribers
    // notified, so a completed push implies that local GRASP state is ready.
    if let Some(flush) = terminal_flush {
        if send_body_bytes(&tx, flush).await.is_err() {
            record_git_operation(&metrics, "push", "error");
            return;
        }
    }

    record_git_operation(&metrics, "push", "success");
}

async fn send_body_bytes(
    tx: &mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
    bytes: Vec<u8>,
) -> Result<(), mpsc::error::SendError<Result<Frame<Bytes>, io::Error>>> {
    tx.send(Ok(Frame::data(Bytes::from(bytes)))).await
}

/// Errors that can occur in Git handlers
///
/// These represent transport/infrastructure failures, not application-level
/// rejections. Application-level rejections (e.g. auth failures) are returned
/// as HTTP 200 with an ERR pkt-line so git clients can display the message.
#[derive(Debug)]
pub enum GitError {
    RepositoryNotFound,
    ProcessSpawnFailed(std::io::Error),
    IoError(std::io::Error),
    GitFailed(Option<i32>),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RepositoryNotFound => write!(f, "repository not found"),
            Self::ProcessSpawnFailed(e) => write!(f, "failed to spawn git process: {}", e),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::GitFailed(code) => write!(f, "git process failed with code: {:?}", code),
        }
    }
}

impl std::error::Error for GitError {}

impl GitError {
    /// Convert to HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::RepositoryNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    /// Build a single-update receive-pack request body pkt-line for tests.
    ///
    /// Matches the smart-HTTP format:
    ///   <old-oid> SP <new-oid> SP <ref-name> NUL <capabilities>\n
    fn build_receive_pack_pktline(caps: &str) -> Vec<u8> {
        let old = "0".repeat(40);
        let new = "1".repeat(40);
        let refname = "refs/heads/main";
        // payload format with NUL between ref-name and capabilities
        let mut payload = Vec::new();
        payload.extend_from_slice(format!("{} {} {}", old, new, refname).as_bytes());
        payload.push(0);
        payload.extend_from_slice(caps.as_bytes());
        payload.push(b'\n');
        // pkt-line frame: hex length prefix
        let total_len = payload.len() + 4;
        let mut out = Vec::new();
        out.extend_from_slice(format!("{:04x}", total_len).as_bytes());
        out.extend_from_slice(&payload);
        out
    }

    async fn response_body_bytes(resp: Response<GitResponseBody>) -> Vec<u8> {
        resp.into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn detects_side_band_64k_in_first_pktline() {
        let body = build_receive_pack_pktline("report-status side-band-64k agent=git/2.42");
        assert!(client_negotiated_sideband_64k(&body));
    }

    #[test]
    fn detects_side_band_64k_when_only_capability() {
        let body = build_receive_pack_pktline("side-band-64k");
        assert!(client_negotiated_sideband_64k(&body));
    }

    #[test]
    fn detects_no_sideband_when_only_report_status() {
        let body = build_receive_pack_pktline("report-status agent=git/2.42");
        assert!(!client_negotiated_sideband_64k(&body));
    }

    #[test]
    fn detects_no_sideband_for_legacy_side_band() {
        // The legacy `side-band` (without -64k) is NOT what modern clients
        // use for the demuxer; treat it as no-sideband to be conservative.
        let body = build_receive_pack_pktline("report-status side-band");
        assert!(!client_negotiated_sideband_64k(&body));
    }

    #[test]
    fn handles_short_or_malformed_body() {
        assert!(!client_negotiated_sideband_64k(b""));
        assert!(!client_negotiated_sideband_64k(b"abc"));
        // claimed length 4 = flush
        assert!(!client_negotiated_sideband_64k(b"0000"));
        // invalid hex length
        assert!(!client_negotiated_sideband_64k(b"zzzz1234"));
        // length larger than body
        assert!(!client_negotiated_sideband_64k(b"0099short"));
    }

    #[tokio::test]
    async fn receive_pack_err_is_sideband_wrapped_when_client_negotiates() {
        let body = build_receive_pack_pktline("report-status side-band-64k");
        let resp = build_git_protocol_error_response(
            GitService::ReceivePack,
            "authorisation failed: nope",
            Some(&body),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap_or("").to_string()),
            Some("application/x-git-receive-pack-result".to_string())
        );

        let raw = response_body_bytes(resp).await;
        // pkt-line: <4-hex-length><payload>
        assert!(raw.len() >= 4);
        let len =
            u16::from_str_radix(std::str::from_utf8(&raw[0..4]).unwrap(), 16).unwrap() as usize;
        assert_eq!(raw.len(), len);
        // First payload byte MUST be the band id 0x03 (error band)
        assert_eq!(raw[4], 0x03);
        // Remainder is the ERR pkt-line content
        let rest = std::str::from_utf8(&raw[5..]).unwrap();
        assert!(
            rest.starts_with("ERR authorisation failed: nope"),
            "unexpected error payload: {:?}",
            rest
        );
    }

    #[tokio::test]
    async fn receive_pack_err_is_bare_when_no_sideband() {
        let body = build_receive_pack_pktline("report-status");
        let resp = build_git_protocol_error_response(
            GitService::ReceivePack,
            "authorisation failed: nope",
            Some(&body),
        );
        let raw = response_body_bytes(resp).await;
        // Without sideband, first payload byte is 'E' (ASCII 0x45) from "ERR".
        assert!(raw.len() >= 5);
        assert_eq!(raw[4], b'E');
        let rest = std::str::from_utf8(&raw[4..]).unwrap();
        assert!(rest.starts_with("ERR authorisation failed: nope"));
    }

    #[tokio::test]
    async fn upload_pack_err_is_never_sideband_wrapped() {
        // Even if we somehow had a body that mentioned side-band-64k, upload-pack
        // responses must remain bare ERR pkt-lines.
        let body = build_receive_pack_pktline("side-band-64k");
        let resp =
            build_git_protocol_error_response(GitService::UploadPack, "not our ref", Some(&body));
        let raw = response_body_bytes(resp).await;
        assert_eq!(raw[4], b'E');
    }

    #[tokio::test]
    async fn streaming_body_yields_stdout_before_eof() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::{timeout, Duration};

        let (mut writer, reader) = tokio::io::duplex(64);
        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(STREAM_CHANNEL_DEPTH);

        let pump_task = tokio::spawn(async move { pump_stdout_to_channel(reader, &tx).await });
        writer.write_all(b"progress chunk").await.unwrap();

        let mut body = streaming_response(GitService::ReceivePack, rx).into_body();
        let frame = timeout(Duration::from_secs(1), body.frame())
            .await
            .expect("stream should yield first stdout chunk before EOF")
            .expect("stream should still be open")
            .expect("stdout chunk should not be a body error");

        let data = frame.into_data().expect("frame should contain data");
        assert_eq!(data, Bytes::from_static(b"progress chunk"));

        assert!(
            !pump_task.is_finished(),
            "stdout pump should still be waiting for EOF after yielding first chunk"
        );

        drop(writer);
        assert_eq!(
            pump_task.await.unwrap(),
            PumpResult::Eof { sent_stdout: true }
        );
    }

    #[tokio::test]
    async fn post_push_keepalive_is_sideband_progress() {
        use tokio::time::timeout;

        let (tx, mut rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(STREAM_CHANNEL_DEPTH);
        let keepalive = ReceivePackKeepalive::spawn(tx, Duration::from_millis(10));

        let frame = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("keepalive should arrive before timeout")
            .expect("keepalive channel should remain open")
            .expect("keepalive should not be an HTTP body error");
        let data = frame.into_data().expect("keepalive should contain data");

        assert_eq!(data.as_ref(), receive_pack_keepalive_pktline());
        assert_eq!(
            data[4], 0x02,
            "keepalive pkt-line payload must use sideband band 2"
        );

        keepalive.stop().await;
    }

    #[tokio::test]
    async fn receive_pack_err_without_body_is_not_wrapped() {
        // No request body → conservative path: do not wrap.
        let resp = build_git_protocol_error_response(GitService::ReceivePack, "boom", None);
        let raw = response_body_bytes(resp).await;
        assert_eq!(raw[4], b'E');
    }
}
