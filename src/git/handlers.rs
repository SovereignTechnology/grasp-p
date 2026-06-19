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
use crate::nostr::builder::Nip34WritePolicy;
use crate::nostr::holding::LifecycleReadGuard;
use crate::nostr::SharedDatabase;
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

/// Build an HTTP 200 OK response with an ERR pkt-line for git protocol errors.
///
/// Per the git smart HTTP protocol spec, protocol-level errors (like "not our ref")
/// should be returned as HTTP 200 OK with the error message in pkt-line format:
/// `PKT-LINE("ERR" SP explanation-text)`
///
/// This allows git clients to properly parse and display the error message.
///
/// `pub(crate)` so the `/prs/` receive-pack handler in `crate::grasp06::receive`
/// can return identically-shaped rejections without duplicating the pkt-line
/// framing.
pub(crate) fn build_git_protocol_error_response(
    service: GitService,
    error_message: &str,
) -> Response<Full<Bytes>> {
    // Format: "ERR <message>\n"
    let err_content = format!("ERR {}\n", error_message.trim());
    let err_pktline = PktLine::data(err_content.as_bytes()).encode();

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
    repo_lifecycle_guard: Option<LifecycleReadGuard>,
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
        drop(repo_lifecycle_guard);
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
            ));
        }

        // Transport errors (spawn failures, signals, etc.) remain as HTTP 500
        error!("Git receive-pack failed: {}", stderr_str);
        return Err(GitError::GitFailed(status.code()));
    }

    // Release the repository lifecycle read lock once git-receive-pack itself
    // has finished. The lock's purpose is to keep deletion/archive/restore from
    // removing or replacing the bare repository while Git is actively reading or
    // writing it; Git's own internal locking handles concurrent push/fetch ref
    // and object consistency. Post-push purgatory promotion may re-enter
    // recovery paths that take the lifecycle write lock, so holding this beyond
    // the subprocess boundary would deadlock.
    drop(repo_lifecycle_guard);

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
        Some(write_policy.deletion()),
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
