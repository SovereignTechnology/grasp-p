//! Git HTTP Protocol Handlers
//!
//! This module implements the HTTP handlers for Git Smart HTTP protocol.

use http_body_util::Full;
use hyper::{body::Bytes, Response, StatusCode};
use nostr_relay_builder::LocalRelay;
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use super::protocol::{GitService, PktLine};
use super::subprocess::GitSubprocess;

use crate::git::authorization::{authorize_push, parse_pushed_refs};
use crate::git::sync::process_newly_available_git_data;
use crate::nostr::builder::{Nip34WritePolicy, SharedDatabase};
use crate::purgatory::Purgatory;
use crate::sync::rejected_index::RejectedEventsIndex;

/// Handle GET /info/refs?service=git-{upload,receive}-pack
///
/// This advertises the repository's refs to the client.
pub async fn handle_info_refs(
    repo_path: PathBuf,
    service: GitService,
    git_protocol: Option<&str>,
) -> Result<Response<Full<Bytes>>, GitError> {
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
        .body(Full::new(Bytes::from(response_body)))
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
) -> Response<Full<Bytes>> {
    // Format: "ERR <message>\n"
    let err_content = format!("ERR {}\n", error_message.trim());

    // Wrap in sideband band 3 when the receive-pack client negotiated
    // side-band-64k. See doc comment above for the protocol details.
    let use_sideband = matches!(service, GitService::ReceivePack)
        && request_body
            .map(client_negotiated_sideband_64k)
            .unwrap_or(false);

    let err_pktline = if use_sideband {
        let mut framed = Vec::with_capacity(1 + err_content.len());
        framed.push(0x03); // band 3 = error
        framed.extend_from_slice(err_content.as_bytes());
        PktLine::data(framed).encode()
    } else {
        PktLine::data(err_content.as_bytes()).encode()
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", service.result_content_type())
        .header("cache-control", "no-cache")
        .body(Full::new(Bytes::from(err_pktline)))
        .unwrap()
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

/// Handle POST /git-upload-pack (clone/fetch)
pub async fn handle_upload_pack(
    repo_path: PathBuf,
    request_body: Bytes,
    git_protocol: Option<&str>,
) -> Result<Response<Full<Bytes>>, GitError> {
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

    // Read response from git's stdout
    let mut output = Vec::new();
    let mut stderr_output = Vec::new();

    if let Some(stdout) = git.take_stdout() {
        let mut stdout = stdout;
        stdout.read_to_end(&mut output).await.map_err(|e| {
            error!("Failed to read git upload-pack stdout: {}", e);
            GitError::IoError(e)
        })?;
    }

    if let Some(stderr) = git.take_stderr() {
        let mut stderr = stderr;
        stderr.read_to_end(&mut stderr_output).await.map_err(|e| {
            error!("Failed to read git upload-pack stderr: {}", e);
            GitError::IoError(e)
        })?;
    }

    // Wait for process
    let status = git.wait().await.map_err(|e| {
        error!("Failed to wait for git upload-pack process: {}", e);
        GitError::IoError(e)
    })?;

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr_output);

        // Check if this is a git protocol error (exit code 128 with stderr)
        // Protocol errors should be returned as HTTP 200 with ERR pkt-line
        if is_git_protocol_error(status.code(), &stderr_output) {
            warn!(
                "Git upload-pack protocol error (returning ERR pkt-line): {}",
                stderr_str
            );
            return Ok(build_git_protocol_error_response(
                GitService::UploadPack,
                &stderr_str,
                None,
            ));
        }

        // Transport errors (spawn failures, signals, etc.) remain as HTTP 500
        error!("Git upload-pack failed: {}", stderr_str);
        return Err(GitError::GitFailed(status.code()));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", GitService::UploadPack.result_content_type())
        .header("cache-control", "no-cache")
        .body(Full::new(Bytes::from(output)))
        .unwrap())
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
    write_policy: Arc<Nip34WritePolicy>,
    rejected_events_index: Arc<RejectedEventsIndex>,
) -> Result<Response<Full<Bytes>>, GitError> {
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

    // Read response from git's stdout
    let mut output = Vec::new();
    let mut stderr_output = Vec::new();

    if let Some(stdout) = git.take_stdout() {
        let mut stdout = stdout;
        stdout.read_to_end(&mut output).await.map_err(|e| {
            error!("Failed to read git receive-pack stdout: {}", e);
            GitError::IoError(e)
        })?;
    }

    if let Some(stderr) = git.take_stderr() {
        let mut stderr = stderr;
        stderr.read_to_end(&mut stderr_output).await.map_err(|e| {
            error!("Failed to read git receive-pack stderr: {}", e);
            GitError::IoError(e)
        })?;
    }

    // Wait for process
    let status = git.wait().await.map_err(|e| {
        error!("Failed to wait for git receive-pack process: {}", e);
        GitError::IoError(e)
    })?;

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr_output);

        // Check if this is a git protocol error (exit code 128 with stderr)
        // Protocol errors should be returned as HTTP 200 with ERR pkt-line
        if is_git_protocol_error(status.code(), &stderr_output) {
            warn!(
                "Git receive-pack protocol error (returning ERR pkt-line): {}",
                stderr_str
            );
            return Ok(build_git_protocol_error_response(
                GitService::ReceivePack,
                &stderr_str,
                Some(&request_body),
            ));
        }

        // Transport errors (spawn failures, signals, etc.) remain as HTTP 500
        error!("Git receive-pack failed: {}", stderr_str);
        return Err(GitError::GitFailed(status.code()));
    }

    // Process newly available git data using the unified function
    // This handles:
    // - Discovering satisfiable events from purgatory (state events and PR events)
    // - Syncing OIDs to authorized owner repos
    // - Aligning refs (+ setting HEAD) in all owner repos
    // - Saving events to database
    // - Notifying WebSocket subscribers
    // - Removing from purgatory
    //
    // Parse pushed refs to collect new OIDs
    let pushed_refs = parse_pushed_refs(&request_body);
    let new_oids: HashSet<String> = pushed_refs
        .iter()
        .filter(|(_, new_oid, _)| new_oid != "0000000000000000000000000000000000000000")
        .map(|(_, new_oid, _)| new_oid.clone())
        .collect();

    let git_data_path_buf = std::path::Path::new(git_data_path);

    match process_newly_available_git_data(
        &repo_path,
        &new_oids,
        &database,
        Some(&relay),
        &purgatory,
        git_data_path_buf,
        Some(&write_policy),
        Some(&rejected_events_index),
    )
    .await
    {
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

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            "content-type",
            GitService::ReceivePack.result_content_type(),
        )
        .header("cache-control", "no-cache")
        .body(Full::new(Bytes::from(output)))
        .unwrap())
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

    async fn response_body_bytes(resp: Response<Full<Bytes>>) -> Vec<u8> {
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
    async fn receive_pack_err_without_body_is_not_wrapped() {
        // No request body → conservative path: do not wrap.
        let resp = build_git_protocol_error_response(GitService::ReceivePack, "boom", None);
        let raw = response_body_bytes(resp).await;
        assert_eq!(raw[4], b'E');
    }
}
