//! GRASP-06 `/prs/` fetch handlers.
//!
//! Spec 06.md line 11:
//!
//! > MUST respond to upload-pack requests for any well-formed path as if
//! > serving an empty bare repository.
//!
//! When a real `/prs/<submitter>/<identifier>.git` repo exists on disk we
//! delegate to the standard handlers in [`crate::git::handlers`]. Otherwise we
//! synthesize an empty thin view in a per-request temporary directory. If the
//! identifier family exists, receive-pack discovery can advertise its bases as
//! anonymous `.have` entries without exposing any named refs.
//!
//! Receive-pack lives in [`crate::grasp06::receive`].

use hyper::body::Bytes;
use hyper::Response;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tempfile::TempDir;
use tracing::{debug, warn};

use crate::git::handlers::{handle_info_refs, handle_upload_pack, GitError};
use crate::git::protocol::GitService;
use crate::git::storage::{FamilyKey, LocalGitStorage};
use crate::git::GitResponseBody;
use crate::grasp06::endpoint::PrsUrl;
use crate::grasp06::paths::prs_repo_path;
use crate::metrics::Metrics;

/// Handle `GET /prs/<npub>/<id>.git/info/refs?service=...`.
///
/// Used for both `git-upload-pack` (clone/fetch) discovery and
/// `git-receive-pack` discovery: in both cases we advertise the refs of
/// an empty bare repo when no real repo exists at the requested path,
/// so that `git push` can proceed to its POST step (where
/// [`crate::grasp06::receive::handle_prs_receive_pack`] validates the
/// ref-update list and initialises the repo on demand if appropriate).
pub async fn handle_prs_info_refs(
    prs: &PrsUrl,
    git_data_path: &str,
    service: GitService,
    git_protocol: Option<&str>,
) -> Result<Response<GitResponseBody>, GitError> {
    let real_repo = prs_repo_path(
        Path::new(git_data_path),
        &prs.submitter.to_hex(),
        &prs.identifier,
    );

    if real_repo.exists() {
        debug!(
            "/prs/ info/refs: real repo found at {} — delegating",
            real_repo.display()
        );
        return handle_info_refs(real_repo, service, git_protocol).await;
    }

    debug!(
        "/prs/ info/refs: synthesising empty bare repo for prs={}/{}",
        prs.submitter.to_hex(),
        prs.identifier
    );
    let storage = LocalGitStorage::new(git_data_path);
    let key = FamilyKey::sha1(&prs.identifier).map_err(|e| GitError::Storage(e.to_string()))?;
    let temp = init_empty_bare_repo(&storage, &key)?;
    let repo_path = temp.path().to_path_buf();
    let response = handle_info_refs(repo_path, service, git_protocol).await;
    // `temp` is dropped here, deleting the directory. Git has already
    // read everything it needs by the time `handle_info_refs` returns.
    drop(temp);
    response
}

/// Handle `POST /prs/<npub>/<id>.git/git-upload-pack`.
///
/// Same synthesise-or-delegate behaviour as [`handle_prs_info_refs`].
pub async fn handle_prs_upload_pack(
    prs: &PrsUrl,
    git_data_path: &str,
    body: Bytes,
    git_protocol: Option<&str>,
    metrics: Option<Arc<Metrics>>,
) -> Result<Response<GitResponseBody>, GitError> {
    let real_repo = prs_repo_path(
        Path::new(git_data_path),
        &prs.submitter.to_hex(),
        &prs.identifier,
    );

    if real_repo.exists() {
        debug!(
            "/prs/ upload-pack: real repo found at {} — delegating",
            real_repo.display()
        );
        return handle_upload_pack(real_repo, body, git_protocol, None, metrics).await;
    }

    debug!(
        "/prs/ upload-pack: synthesising empty bare repo for prs={}/{}",
        prs.submitter.to_hex(),
        prs.identifier
    );
    let storage = LocalGitStorage::new(git_data_path);
    let key = FamilyKey::sha1(&prs.identifier).map_err(|e| GitError::Storage(e.to_string()))?;
    let temp = init_empty_bare_repo(&storage, &key)?;
    handle_prs_upload_pack_buffered(temp, body, git_protocol).await
}

async fn handle_prs_upload_pack_buffered(
    temp: TempDir,
    request_body: Bytes,
    git_protocol: Option<&str>,
) -> Result<Response<GitResponseBody>, GitError> {
    use crate::git::full_body;
    use crate::git::handlers::{build_git_protocol_error_response, is_git_protocol_error};
    use crate::git::subprocess::GitSubprocess;
    use hyper::StatusCode;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let repo_path = temp.path().to_path_buf();
    let mut git = GitSubprocess::spawn(GitService::UploadPack, &repo_path, false, git_protocol)
        .map_err(GitError::ProcessSpawnFailed)?;

    if let Some(mut stdin) = git.take_stdin() {
        stdin
            .write_all(&request_body)
            .await
            .map_err(GitError::IoError)?;
        drop(stdin);
    }

    let mut output = Vec::new();
    let mut stderr_output = Vec::new();

    if let Some(mut stdout) = git.take_stdout() {
        stdout
            .read_to_end(&mut output)
            .await
            .map_err(GitError::IoError)?;
    }

    if let Some(mut stderr) = git.take_stderr() {
        stderr
            .read_to_end(&mut stderr_output)
            .await
            .map_err(GitError::IoError)?;
    }

    let status = git.wait().await.map_err(GitError::IoError)?;

    // Keep the TempDir alive until git has fully exited. The standard
    // upload-pack handler streams in a detached task; using that for this
    // synthesized repo would race with dropping `temp` and deleting the repo.
    drop(temp);

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr_output);
        if is_git_protocol_error(status.code(), &stderr_output) {
            return Ok(build_git_protocol_error_response(
                GitService::UploadPack,
                &stderr_str,
                None,
            ));
        }
        return Err(GitError::GitFailed(status.code()));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", GitService::UploadPack.result_content_type())
        .header("cache-control", "no-cache")
        .body(full_body(output))
        .unwrap())
}

/// Create a fresh empty thin view in a temp directory.
///
/// Per-request temp dirs are deliberate. They are cheap on
/// any reasonable filesystem (one `mkdir`, one `git init --bare`) and
/// avoid any concurrency hazards a shared template would introduce. If
/// profiling shows this is a bottleneck we can switch to a shared
/// `<git_data_path>/prs/.empty-template.git`; do not optimise until
/// measurable.
fn init_empty_bare_repo(
    storage: &LocalGitStorage,
    family_key: &FamilyKey,
) -> Result<TempDir, GitError> {
    let temp = TempDir::new().map_err(GitError::IoError)?;
    let path = temp.path();
    let output = Command::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(path)
        .output()
        .map_err(GitError::ProcessSpawnFailed)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            "/prs/ empty-repo synthesis: git init --bare failed in {}: {}",
            path.display(),
            stderr.trim()
        );
        return Err(GitError::GitFailed(output.status.code()));
    }
    if storage.family_exists(family_key) {
        storage
            .configure_thin_view(family_key, path)
            .map_err(|error| GitError::Storage(error.to_string()))?;
    }
    Ok(temp)
}
