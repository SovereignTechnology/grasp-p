//! Git Smart HTTP Backend
//!
//! This module implements Git Smart HTTP protocol support for ngit-grasp.
//! It provides handlers for clone, fetch, and push operations over HTTP.
//!
//! # Architecture
//!
//! - `protocol` - Git pkt-line format parsing and utilities
//! - `subprocess` - Git process spawning and management
//! - `handlers` - HTTP request handlers for Git operations
//!
//! # URL Patterns
//!
//! The following URL patterns are supported:
//! - `GET /<npub>/<identifier>.git/info/refs?service=git-upload-pack` - Clone/fetch advertisement
//! - `GET /<npub>/<identifier>.git/info/refs?service=git-receive-pack` - Push advertisement
//! - `POST /<npub>/<identifier>.git/git-upload-pack` - Clone/fetch operation
//! - `POST /<npub>/<identifier>.git/git-receive-pack` - Push operation

pub mod authorization;
pub mod authorization_integrity;
pub mod handlers;
pub mod integrity;
pub mod migration;
pub mod process;
pub mod protocol;
mod receive_pack_plan;
pub mod staging;
pub mod storage;
pub mod subprocess;
pub mod sync;
// SovTech: the startup check that git is new enough to promote pushes.
pub mod version;

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::process::Command;

use ::nostr::nips::nip19::FromBech32;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use nostr_sdk::prelude::{PublicKey, ToBech32};
use tracing::{debug, info};

/// Unified HTTP response body for every route served by ngit-grasp.
///
/// This boxed body can hold either a buffered [`Full<Bytes>`] payload (for
/// small responses such as advertisements, protocol-error pkt-lines, JSON
/// pages, and static assets) or a streaming body backed by a channel (for live
/// `git-receive-pack` / `git-upload-pack` stdout). Using one body type keeps
/// the Hyper service response type unified.
pub type GitResponseBody = BoxBody<Bytes, std::io::Error>;

/// Wrap an in-memory payload as a one-shot [`GitResponseBody`].
pub fn full_body(bytes: impl Into<Bytes>) -> GitResponseBody {
    Full::new(bytes.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

/// Explicit empty response body.
pub fn empty_body() -> GitResponseBody {
    full_body(Bytes::new())
}

/// Parse a Git repository path from URL components
///
/// Converts /<npub>/<identifier>.git/* to a filesystem path
///
/// # Arguments
/// * `git_data_path` - Base directory for Git repositories
/// * `npub` - The npub (Nostr public key in bech32 format)
/// * `identifier` - The repository identifier
///
/// # Returns
/// Path to the bare Git repository, or `None` when either URL component is
/// non-canonical or could escape the configured Git data root.
pub fn resolve_repo_path(git_data_path: &str, npub: &str, identifier: &str) -> Option<PathBuf> {
    validate_repository_coordinate(npub, identifier)?;
    let root = PathBuf::from(git_data_path);
    let candidate = root.join(npub).join(format!("{identifier}.git"));
    candidate.starts_with(&root).then_some(candidate)
}

/// Check if a commit exists in the repository
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
/// * `commit_hash` - The commit hash to check
///
/// # Returns
/// True if the commit exists in the repository, false otherwise
pub fn commit_exists(repo_path: &Path, commit_hash: &str) -> bool {
    let output = Command::new("git")
        .args(["cat-file", "-t", commit_hash])
        .current_dir(repo_path)
        .output();

    match output {
        Ok(result) => {
            if result.status.success() {
                let obj_type = String::from_utf8_lossy(&result.stdout);
                // Object exists and is a commit
                obj_type.trim() == "commit"
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Check if a oid exists in the repository
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
/// * `oid` - The commit hash to check
///
/// # Returns
/// True if the commit exists in the repository, false otherwise
pub fn oid_exists(repo_path: &Path, oid: &str) -> bool {
    let output = Command::new("git")
        .args(["cat-file", "-e", oid])
        .current_dir(repo_path)
        .output();

    match output {
        Ok(result) => result.status.success(),
        Err(_) => false,
    }
}

/// Set the repository HEAD to point to a branch
///
/// This updates the HEAD symbolic ref to point to the specified branch.
/// Per GRASP-01: "MUST set repository HEAD per repository state announcement
/// as soon as the git data related to that branch has been received."
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
/// * `head_ref` - The ref to set HEAD to (e.g., "refs/heads/main")
///
/// # Returns
/// Ok(()) if successful, Err with error message otherwise
pub fn set_repository_head(repo_path: &Path, head_ref: &str) -> Result<(), String> {
    // Validate the ref format
    if !head_ref.starts_with("refs/heads/") {
        return Err(format!(
            "Invalid HEAD ref: {} (must start with refs/heads/)",
            head_ref
        ));
    }

    debug!("Setting HEAD to {} in {}", head_ref, repo_path.display());

    let output = Command::new("git")
        .args(["symbolic-ref", "HEAD", head_ref])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to execute git symbolic-ref: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git symbolic-ref failed: {}", stderr));
    }

    info!("Updated HEAD to {} in {}", head_ref, repo_path.display());
    Ok(())
}

/// Try to set repository HEAD from a repository state event
///
/// This function checks if the HEAD branch's commit is available in the repository
/// and sets HEAD if it is. This should be called:
/// 1. When a repository state event is received (in case git data already exists)
/// 2. After git data is received (in case a state event was already received)
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
/// * `head_ref` - The ref to set HEAD to (e.g., "refs/heads/main")
/// * `head_commit` - The commit hash that the HEAD branch should point to
///
/// # Returns
/// Ok(true) if HEAD was set, Ok(false) if commit not yet available, Err on failure
pub fn try_set_head_if_available(
    repo_path: &Path,
    head_ref: &str,
    head_commit: &str,
) -> Result<bool, String> {
    // Check if repository exists
    if !repo_path.exists() {
        debug!(
            "Repository not found at {}, cannot set HEAD",
            repo_path.display()
        );
        return Ok(false);
    }

    // Check if the commit exists in the repository
    if !commit_exists(repo_path, head_commit) {
        debug!(
            "Commit {} not found in {}, HEAD not set yet",
            head_commit,
            repo_path.display()
        );
        return Ok(false);
    }

    // Commit exists, set HEAD
    set_repository_head(repo_path, head_ref)?;
    Ok(true)
}

/// Get the commit hash that a ref points to
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
/// * `ref_name` - The ref name (e.g., "refs/nostr/<event-id>")
///
/// # Returns
/// Some(commit_hash) if the ref exists, None otherwise
pub fn get_ref_commit(repo_path: &Path, ref_name: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", ref_name])
        .current_dir(repo_path)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Delete a git ref from the repository
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
/// * `ref_name` - The ref name to delete (e.g., "refs/nostr/<event-id>")
///
/// # Returns
/// Ok(()) if successful, Err with error message otherwise
pub fn delete_ref(repo_path: &Path, ref_name: &str) -> Result<(), String> {
    debug!("Deleting ref {} from {}", ref_name, repo_path.display());

    let output = Command::new("git")
        .args(["update-ref", "-d", ref_name])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to execute git update-ref: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git update-ref -d failed: {}", stderr));
    }

    info!("Deleted ref {} from {}", ref_name, repo_path.display());
    staging::request_maintenance(repo_path);
    Ok(())
}

/// Update a git ref to point to a specific commit
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
/// * `ref_name` - The ref name to update (e.g., "refs/heads/main")
/// * `commit_hash` - The commit hash to set the ref to
///
/// # Returns
/// Ok(()) if successful, Err with error message otherwise
pub fn update_ref(repo_path: &Path, ref_name: &str, commit_hash: &str) -> Result<(), String> {
    debug!(
        "Updating ref {} to {} in {}",
        ref_name,
        commit_hash,
        repo_path.display()
    );

    let output = Command::new("git")
        .args(["update-ref", ref_name, commit_hash])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to execute git update-ref: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git update-ref failed: {}", stderr));
    }

    debug!(
        "Updated ref {} to {} in {}",
        ref_name,
        commit_hash,
        repo_path.display()
    );
    Ok(())
}

/// List all refs in a repository with their commit hashes
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
///
/// # Returns
/// Vec of (ref_name, commit_hash) tuples
pub fn list_refs(repo_path: &Path) -> Result<Vec<(String, String)>, String> {
    if !repo_path.exists() {
        return Ok(Vec::new());
    }

    let output = Command::new("git")
        .args(["for-each-ref", "--format=%(refname) %(objectname)"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to execute git for-each-ref: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git for-each-ref failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let refs = stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect();

    Ok(refs)
}

/// Validate refs/nostr/<event-id> ref against expected commit
///
/// If the ref exists but points to a different commit than expected,
/// the ref is deleted. This is called when a PR event is received to
/// ensure refs/nostr refs are consistent with their corresponding events.
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
/// * `event_id` - The event ID (hex string)
/// * `expected_commit` - The commit hash from the event's `c` tag
///
/// # Returns
/// Ok(true) if ref was deleted (mismatch), Ok(false) if no action taken, Err on failure
pub fn validate_nostr_ref(
    repo_path: &Path,
    event_id: &str,
    expected_commit: &str,
) -> Result<bool, String> {
    let ref_name = format!("refs/nostr/{}", event_id);

    // Check if repository exists
    if !repo_path.exists() {
        debug!(
            "Repository not found at {}, skipping ref validation",
            repo_path.display()
        );
        return Ok(false);
    }

    // Check if the ref exists
    let current_commit = match get_ref_commit(repo_path, &ref_name) {
        Some(commit) => commit,
        None => {
            debug!("Ref {} does not exist in {}", ref_name, repo_path.display());
            return Ok(false);
        }
    };

    // Compare commits
    if current_commit == expected_commit {
        debug!(
            "Ref {} points to correct commit {} in {}",
            ref_name,
            expected_commit,
            repo_path.display()
        );
        return Ok(false);
    }

    // Commit mismatch - delete the ref
    info!(
        "Deleting mismatched ref {} in {}: expected {}, found {}",
        ref_name,
        repo_path.display(),
        expected_commit,
        current_commit
    );
    delete_ref(repo_path, &ref_name)?;
    Ok(true)
}

/// Clean up placeholder refs from all repositories on shutdown.
///
/// Walks through all git repositories in the git_data_path and deletes
/// `refs/nostr/<event-id>` refs for the given event IDs. This is called
/// on shutdown to clean up placeholders created when git data arrived
/// before the corresponding PR event.
///
/// # Arguments
/// * `git_data_path` - Base directory containing git repositories
/// * `event_ids` - Event IDs whose refs/nostr/ refs should be deleted
///
/// # Returns
/// Number of refs successfully deleted
pub fn cleanup_placeholder_refs(git_data_path: &str, event_ids: &[String]) -> usize {
    if event_ids.is_empty() {
        return 0;
    }

    let git_path = PathBuf::from(git_data_path);
    if !git_path.exists() {
        debug!("Git data path does not exist: {}", git_data_path);
        return 0;
    }

    let mut deleted_count = 0;

    // Walk through all repositories (npub/repo.git structure)
    if let Ok(npub_entries) = std::fs::read_dir(&git_path) {
        for npub_entry in npub_entries.flatten() {
            if !npub_entry.path().is_dir() {
                continue;
            }

            // For each npub directory, check repos
            if let Ok(repo_entries) = std::fs::read_dir(npub_entry.path()) {
                for repo_entry in repo_entries.flatten() {
                    let repo_path = repo_entry.path();
                    if !repo_path.is_dir() || !repo_path.to_string_lossy().ends_with(".git") {
                        continue;
                    }

                    // Try to delete refs/nostr/<event-id> for each placeholder event
                    for event_id in event_ids {
                        let ref_name = format!("refs/nostr/{}", event_id);
                        if delete_ref(&repo_path, &ref_name).is_ok() {
                            deleted_count += 1;
                            info!(
                                "Cleaned up placeholder ref {} from {}",
                                ref_name,
                                repo_path.display()
                            );
                        }
                    }
                }
            }
        }
    }

    if deleted_count > 0 {
        info!(
            "Shutdown cleanup: removed {} placeholder refs from git repositories",
            deleted_count
        );
    }

    deleted_count
}

/// Get the current HEAD ref from a repository
///
/// # Arguments
/// * `repo_path` - Path to the bare git repository
///
/// # Returns
/// The current HEAD ref (e.g., "refs/heads/main") or None if not set
pub fn get_repository_head(repo_path: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["symbolic-ref", "HEAD"])
        .current_dir(repo_path)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Percent-encode a string for use as a URL path segment (RFC 3986 §2.1).
///
/// Encodes all bytes that are not unreserved characters (`A-Z a-z 0-9 - _ . ~`).
/// This is suitable for encoding a repository identifier in a `nostr://` URL or
/// an HTTP path component such as `/<npub>/<encoded-identifier>.git`.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            // RFC 3986 unreserved characters — never encoded
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((byte >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((byte & 0xf) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Decode percent-encoded characters in a URL path component.
///
/// Handles `%XX` sequences (e.g. `%20` → space). Invalid sequences are left as-is.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Extract npub and identifier from a Git URL path
///
/// Parses paths like `/<npub>/<identifier>.git/info/refs`
///
/// The identifier component is percent-decoded so that URLs like
/// `/npub1.../my%20repo.git/info/refs` resolve to the filesystem path
/// `my repo.git`. Per NIP-34 and GRASP-01, identifiers MUST be percent-encoded
/// in URLs; they are stored verbatim on disk.
///
/// Returns (npub, identifier, subpath) where subpath is the part after .git/
/// and identifier has been percent-decoded.
pub fn parse_git_url(path: &str) -> Option<(String, String, String)> {
    // Remove leading slash
    let path = path.strip_prefix('/').unwrap_or(path);

    // Split into components
    let parts: Vec<&str> = path.splitn(3, '/').collect();

    if parts.len() < 3 {
        return None;
    }

    let npub = parts[0];
    let repo_part = percent_decode(parts[1]);
    let subpath = parts[2].to_string();

    // `.git` is part of the HTTP route, not part of the NIP-34 identifier.
    let identifier = repo_part.strip_suffix(".git")?;
    validate_repository_coordinate(npub, identifier)?;

    Some((npub.to_owned(), identifier.to_owned(), subpath))
}

/// Extract a validated repository coordinate from its canonical HTTP root.
pub fn parse_repository_root_url(path: &str) -> Option<(String, String)> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let mut parts = path.split('/');
    let npub = parts.next()?;
    let repo_part = percent_decode(parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let identifier = repo_part.strip_suffix(".git")?;
    validate_repository_coordinate(npub, identifier)?;
    Some((npub.to_owned(), identifier.to_owned()))
}

fn validate_repository_coordinate(npub: &str, identifier: &str) -> Option<()> {
    let public_key = PublicKey::from_bech32(npub).ok()?;
    if public_key.to_bech32().ok()?.as_str() != npub {
        return None;
    }
    validate_repository_identifier(identifier).then_some(())
}

/// Return whether a NIP-34 identifier is safe as one filesystem component.
///
/// Family storage and public repository paths must share this predicate so an
/// event identifier can never select a different internal path than its HTTP
/// route.
pub fn validate_repository_identifier(identifier: &str) -> bool {
    if identifier.is_empty()
        || identifier == "."
        || identifier == ".."
        || identifier.contains('/')
        || identifier.contains('\\')
        || identifier.contains('\0')
    {
        return false;
    }

    let mut components = Path::new(identifier).components();
    matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(component)), None)
            if component == std::ffi::OsStr::new(identifier)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::Keys;
    use std::fs;
    use tempfile::TempDir;

    fn test_npub() -> String {
        Keys::generate().public_key().to_bech32().unwrap()
    }

    /// Run one fixture git step hermetically (immune to ambient git
    /// configuration such as hooks, signing, and templates) and fail loudly
    /// on error instead of letting a later assertion fail obscurely.
    fn run_git(dir: Option<&Path>, args: &[&str]) -> String {
        let mut command = grasp_audit::git_command();
        if let Some(dir) = dir {
            command.current_dir(dir);
        }
        let output = command.args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    /// Create a test bare repository with optional commits
    fn create_test_repo() -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path().join("test.git");

        // Initialize bare repository
        run_git(None, &["init", "--bare", repo_path.to_str().unwrap()]);

        (temp_dir, repo_path)
    }

    /// Create a test repository with a commit on a branch
    fn create_test_repo_with_commit() -> (TempDir, PathBuf, String) {
        let temp_dir = TempDir::new().unwrap();
        let work_dir = temp_dir.path().join("work");
        let bare_repo = temp_dir.path().join("test.git");

        // Initialize bare repository
        run_git(
            None,
            &[
                "init",
                "--bare",
                "--initial-branch=main",
                bare_repo.to_str().unwrap(),
            ],
        );

        // Clone to working directory
        run_git(
            None,
            &[
                "clone",
                bare_repo.to_str().unwrap(),
                work_dir.to_str().unwrap(),
            ],
        );

        // Configure git for commits
        run_git(Some(&work_dir), &["config", "user.email", "test@test.com"]);
        run_git(Some(&work_dir), &["config", "user.name", "Test"]);

        // Create a file and commit
        fs::write(work_dir.join("README.md"), "# Test").unwrap();
        run_git(Some(&work_dir), &["add", "README.md"]);
        run_git(Some(&work_dir), &["commit", "-m", "Initial commit"]);

        // Get commit hash
        let commit_hash = run_git(Some(&work_dir), &["rev-parse", "HEAD"]);

        // Push to bare repo
        run_git(Some(&work_dir), &["push", "origin", "main"]);

        (temp_dir, bare_repo, commit_hash)
    }

    #[test]
    fn test_resolve_repo_path() {
        let npub = test_npub();
        let path = resolve_repo_path("/data/git", &npub, "my-repo").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/data/git").join(npub).join("my-repo.git")
        );
    }

    #[test]
    fn test_resolve_repo_path_preserves_identifier_git_suffix() {
        let npub = test_npub();
        let path = resolve_repo_path("/data/git", &npub, "my-repo.git").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/data/git")
                .join(npub)
                .join("my-repo.git.git")
        );
    }

    #[test]
    fn test_parse_git_url_info_refs() {
        let npub = test_npub();
        let path = format!("/{npub}/repo.git/info/refs");
        let (parsed_npub, id, subpath) = parse_git_url(&path).unwrap();
        assert_eq!(parsed_npub, npub);
        assert_eq!(id, "repo");
        assert_eq!(subpath, "info/refs");
    }

    #[test]
    fn test_parse_git_url_upload_pack() {
        let npub = test_npub();
        let path = format!("/{npub}/repo.git/git-upload-pack");
        let (parsed_npub, id, subpath) = parse_git_url(&path).unwrap();
        assert_eq!(parsed_npub, npub);
        assert_eq!(id, "repo");
        assert_eq!(subpath, "git-upload-pack");
    }

    #[test]
    fn test_parse_git_url_invalid() {
        assert!(parse_git_url("/npub1abc").is_none());
        assert!(parse_git_url("/npub1abc/repo").is_none());
        assert!(parse_git_url("/npub1abc/repo.git/info/refs").is_none());
    }

    #[test]
    fn test_parse_git_url_percent_encoded_identifier() {
        // Identifiers with spaces encoded as %20 must be decoded so the
        // filesystem path lookup finds the correct directory.
        let npub = test_npub();
        let path = format!("/{npub}/kuboslopp%20by%20Shakespeare.git/info/refs");
        let (parsed_npub, id, subpath) = parse_git_url(&path).unwrap();
        assert_eq!(parsed_npub, npub);
        assert_eq!(id, "kuboslopp by Shakespeare");
        assert_eq!(subpath, "info/refs");
    }

    #[test]
    fn repository_urls_reject_encoded_traversal_and_noncanonical_npubs() {
        let npub = test_npub();
        for identifier in [
            "..",
            "%2E%2E",
            "%2E%2E%2Fother",
            "nested%2Frepo",
            r"nested%5Crepo",
        ] {
            let smart = format!("/{npub}/{identifier}.git/info/refs");
            let root = format!("/{npub}/{identifier}.git");
            assert!(parse_git_url(&smart).is_none(), "{smart}");
            assert!(parse_repository_root_url(&root).is_none(), "{root}");
        }
        assert!(parse_git_url("/../repo.git/info/refs").is_none());
        assert!(resolve_repo_path("/data/git", "..", "repo").is_none());
        assert!(resolve_repo_path("/data/git", &npub, "../repo").is_none());
    }

    #[test]
    fn test_percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("no-encoding"), "no-encoding");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("%41%42%43"), "ABC");
    }

    #[test]
    fn test_percent_decode_invalid_sequence_passthrough() {
        // Incomplete or invalid sequences are left as-is
        assert_eq!(percent_decode("foo%2"), "foo%2");
        assert_eq!(percent_decode("foo%zz"), "foo%zz");
    }

    #[test]
    fn test_percent_encode_basic() {
        assert_eq!(percent_encode("my-repo"), "my-repo");
        assert_eq!(percent_encode("my_repo"), "my_repo");
        assert_eq!(percent_encode("repo123"), "repo123");
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(
            percent_encode("kuboslopp by Shakespeare"),
            "kuboslopp%20by%20Shakespeare"
        );
    }

    #[test]
    fn test_percent_encode_special_chars() {
        assert_eq!(percent_encode("a/b"), "a%2Fb");
        assert_eq!(percent_encode("a\\b"), "a%5Cb");
        assert_eq!(percent_encode("a b\tc"), "a%20b%09c");
    }

    #[test]
    fn test_percent_encode_decode_roundtrip() {
        let identifiers = [
            "my-repo",
            "my repo",
            "kuboslopp by Shakespeare",
            "a/b",
            "foo\0bar",
        ];
        for id in &identifiers {
            assert_eq!(percent_decode(&percent_encode(id)), *id);
        }
    }

    #[test]
    fn test_commit_exists_nonexistent() {
        let (_temp_dir, repo_path) = create_test_repo();
        assert!(!commit_exists(
            &repo_path,
            "deadbeef1234567890abcdef1234567890abcdef"
        ));
    }

    #[test]
    fn test_commit_exists_with_commit() {
        let (_temp_dir, repo_path, commit_hash) = create_test_repo_with_commit();
        assert!(commit_exists(&repo_path, &commit_hash));
    }

    #[test]
    fn test_set_repository_head() {
        let (_temp_dir, repo_path, _commit_hash) = create_test_repo_with_commit();

        // Default HEAD might be refs/heads/master
        let result = set_repository_head(&repo_path, "refs/heads/main");
        assert!(result.is_ok());

        let head = get_repository_head(&repo_path);
        assert_eq!(head, Some("refs/heads/main".to_string()));
    }

    #[test]
    fn test_set_repository_head_invalid_ref() {
        let (_temp_dir, repo_path) = create_test_repo();

        // Invalid ref format should fail
        let result = set_repository_head(&repo_path, "main");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must start with refs/heads/"));
    }

    #[test]
    fn test_try_set_head_if_available_commit_missing() {
        let (_temp_dir, repo_path) = create_test_repo();

        let result = try_set_head_if_available(
            &repo_path,
            "refs/heads/main",
            "deadbeef1234567890abcdef1234567890abcdef",
        );

        // Should return Ok(false) - commit not found
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_try_set_head_if_available_success() {
        let (_temp_dir, repo_path, commit_hash) = create_test_repo_with_commit();

        let result = try_set_head_if_available(&repo_path, "refs/heads/main", &commit_hash);

        // Should return Ok(true) - HEAD was set
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify HEAD was set
        let head = get_repository_head(&repo_path);
        assert_eq!(head, Some("refs/heads/main".to_string()));
    }
}
