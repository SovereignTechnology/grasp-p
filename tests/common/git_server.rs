//! HTTP Git Servers for Testing
//!
//! This module provides two git server implementations for integration tests:
//!
//! ## `SimpleGitServer` (Dumb HTTP Protocol)
//!
//! Serves static files from a bare git repository using Git's "dumb HTTP" protocol.
//! This is lightweight but does NOT support shallow fetches (`git fetch --depth=1`).
//!
//! ## `SmartGitServer` (Smart HTTP Protocol)
//!
//! Implements the Git Smart HTTP protocol by spawning `git upload-pack` subprocesses.
//! This supports all git fetch operations including shallow fetches.
//!
//! # Usage
//!
//! ```ignore
//! use common::{SimpleGitServer, SmartGitServer};
//!
//! #[tokio::test]
//! async fn test_git_fetch() {
//!     // Create a test repo
//!     let temp_dir = tempfile::tempdir().unwrap();
//!     create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest).unwrap();
//!     
//!     // Use SmartGitServer for full protocol support (including shallow fetches)
//!     let server = SmartGitServer::start(temp_dir.path()).await;
//!     
//!     // Git operations work against server.url()
//!     let output = git_command()
//!         .args(["clone", "--depth=1", server.url(), "/tmp/clone"])
//!         .output()
//!         .unwrap();
//!     assert!(output.status.success());
//!     
//!     // Server cleans up on drop
//!     server.stop().await;
//! }
//! ```
//!
//! # When to Use Which
//!
//! - **SimpleGitServer**: Fast, lightweight, good for basic `git fetch` without depth limits
//! - **SmartGitServer**: Full protocol support, required for `--depth=1` shallow fetches
//!
//! Tests which explicitly exercise shallow client fetches should use
//! `SmartGitServer`; ordinary purgatory sync performs full fetches.

use grasp_audit::git_command;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Simple HTTP server for serving git repositories.
///
/// Creates a bare clone of a source repository and serves it over HTTP
/// using git's "dumb HTTP" protocol. Useful for testing git fetch operations
/// without needing a full git HTTP backend.
pub struct SimpleGitServer {
    /// Shutdown signal sender
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Server task handle
    handle: Option<tokio::task::JoinHandle<()>>,
    /// Server URL (http://127.0.0.1:<port>)
    url: String,
    /// Server port
    #[allow(dead_code)]
    port: u16,
    /// Temporary directory containing the bare repository
    /// Kept alive for the lifetime of the server
    _temp_dir: tempfile::TempDir,
}

impl SimpleGitServer {
    /// Start a simple HTTP git server serving the given repository.
    ///
    /// Creates a bare clone of the source repository, runs `git update-server-info`,
    /// and starts an HTTP server to serve the repository files.
    ///
    /// # Arguments
    /// * `source_repo` - Path to the source git repository (can be non-bare)
    ///
    /// # Returns
    /// A `SimpleGitServer` instance with the server running
    ///
    /// # Panics
    /// Panics if the git operations fail or the server cannot start
    pub async fn start(source_repo: &Path) -> Self {
        // 1. Create temp directory for bare repo
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir for git server");
        let bare_repo_path = temp_dir.path().join("repo.git");

        // 2. Create bare clone
        let output = git_command()
            .args(["clone", "--bare"])
            .arg(source_repo)
            .arg(&bare_repo_path)
            .output()
            .expect("Failed to run git clone --bare");

        if !output.status.success() {
            panic!(
                "git clone --bare failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // 3. Run git update-server-info to generate info/refs and objects/info/packs
        let output = git_command()
            .args(["update-server-info"])
            .current_dir(&bare_repo_path)
            .output()
            .expect("Failed to run git update-server-info");

        if !output.status.success() {
            panic!(
                "git update-server-info failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // 4. Create and bind listener (eliminates port race condition)
        let std_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port");
        let port = std_listener
            .local_addr()
            .expect("Failed to get local addr")
            .port();

        // Convert to tokio listener (keeps port bound)
        std_listener
            .set_nonblocking(true)
            .expect("Failed to set non-blocking");
        let listener =
            TcpListener::from_std(std_listener).expect("Failed to convert to tokio listener");

        // 5. Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        // 6. Start the HTTP server
        let repo_path = Arc::new(bare_repo_path);

        let handle = tokio::spawn(async move {
            println!("[SmartGitServer] Server loop started on port {}", port);
            eprintln!("[SmartGitServer] Server loop started on port {}", port);
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, addr)) => {
                                eprintln!("[SmartGitServer] Accepted connection from {}", addr);
                                let repo_path = Arc::clone(&repo_path);
                                let io = TokioIo::new(stream);

                                tokio::spawn(async move {
                                    let service = service_fn(move |req| {
                                        let repo_path = Arc::clone(&repo_path);
                                        async move { handle_request(req, &repo_path).await }
                                    });

                                    if let Err(e) = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .await
                                    {
                                        // Connection errors are expected when client disconnects
                                        if !e.to_string().contains("connection") {
                                            eprintln!("SimpleGitServer connection error: {}", e);
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("SimpleGitServer accept error: {}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        // Shutdown signal received
                        break;
                    }
                }
            }
        });

        let url = format!("http://127.0.0.1:{}", port);

        // 7. Wait for server to be ready
        wait_for_server_ready(port).await;

        Self {
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
            url,
            port,
            _temp_dir: temp_dir,
        }
    }

    /// Get the server URL.
    ///
    /// Returns the HTTP URL where the git repository is served.
    /// Can be used directly with `git clone`, `git fetch`, or `git ls-remote`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Stop the server.
    ///
    /// Sends a shutdown signal and waits for the server to stop.
    /// The temporary directory is cleaned up when the server is dropped.
    pub async fn stop(mut self) {
        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for server task to complete
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for SimpleGitServer {
    fn drop(&mut self) {
        // Send shutdown signal if not already sent
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // Note: We can't await the handle in drop, but the temp_dir cleanup
        // will happen automatically when _temp_dir is dropped
    }
}

/// Handle an HTTP request by serving files from the git repository.
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    repo_path: &Path,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();

    // Remove leading slash and construct file path
    let relative_path = path.trim_start_matches('/');
    let file_path = repo_path.join(relative_path);

    // Security: ensure the path doesn't escape the repo directory
    if !is_safe_path(&file_path, repo_path) {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from("Forbidden")))
            .unwrap());
    }

    // Try to read the file
    match tokio::fs::read(&file_path).await {
        Ok(contents) => {
            let content_type = guess_content_type(&file_path);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", content_type)
                .body(Full::new(Bytes::from(contents)))
                .unwrap())
        }
        Err(_) => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap()),
    }
}

/// Check if a path is safe (doesn't escape the repository directory).
fn is_safe_path(path: &Path, repo_path: &Path) -> bool {
    match path.canonicalize() {
        Ok(canonical) => canonical.starts_with(repo_path),
        Err(_) => {
            // If canonicalize fails, check if the path would escape
            // by looking for .. components
            !path.to_string_lossy().contains("..")
        }
    }
}

/// Guess the content type for a git-related file.
fn guess_content_type(path: &Path) -> &'static str {
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if filename == "info/refs" || filename == "refs" {
        "text/plain; charset=utf-8"
    } else if filename.ends_with(".pack") {
        "application/x-git-packed-objects"
    } else if filename.ends_with(".idx") {
        "application/x-git-packed-objects-toc"
    } else {
        "application/octet-stream"
    }
}

/// Wait for the server to be ready to accept connections.
async fn wait_for_server_ready(port: u16) {
    let max_attempts = 50; // 5 seconds total
    let delay = std::time::Duration::from_millis(100);

    for attempt in 0..max_attempts {
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(_) => {
                // Connection successful, server is ready
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                return;
            }
            Err(_) => {
                if attempt == max_attempts - 1 {
                    panic!(
                        "SimpleGitServer failed to start after {} attempts",
                        max_attempts
                    );
                }
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::purgatory_helpers::{create_test_repo_with_commit, CommitVariant};

    #[tokio::test]
    async fn test_simple_git_server_starts_and_stops() {
        // Create a test repo
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Start server
        let server = SimpleGitServer::start(temp_dir.path()).await;

        // Verify URL is set
        assert!(server.url().starts_with("http://127.0.0.1:"));

        // Stop server
        server.stop().await;
    }

    #[tokio::test]
    async fn test_simple_git_server_serves_git_info_refs() {
        // Create a test repo
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Start server
        let server = SimpleGitServer::start(temp_dir.path()).await;

        // Fetch info/refs
        let info_refs_url = format!("{}/info/refs", server.url());
        let response = reqwest::get(&info_refs_url)
            .await
            .expect("Failed to fetch info/refs");

        assert!(
            response.status().is_success(),
            "info/refs should be accessible"
        );

        let body = response.text().await.expect("Failed to read response body");

        // Should contain at least one ref (HEAD or refs/heads/main)
        assert!(
            body.contains("refs/heads/main") || body.contains("HEAD"),
            "info/refs should contain refs, got: {}",
            body
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn test_git_ls_remote_from_simple_server() {
        // Create a test repo
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Start server
        let server = SimpleGitServer::start(temp_dir.path()).await;

        // Run git ls-remote against the server (using tokio::process::Command)
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["ls-remote", server.url()])
            .output()
            .await
            .expect("Failed to run git ls-remote");

        assert!(
            output.status.success(),
            "git ls-remote should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Should list the main branch with the correct commit
        assert!(
            stdout.contains(&commit_hash),
            "ls-remote output should contain commit {}, got: {}",
            commit_hash,
            stdout
        );
        assert!(
            stdout.contains("refs/heads/main"),
            "ls-remote output should contain refs/heads/main, got: {}",
            stdout
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn test_git_fetch_from_simple_server() {
        // Create a source repo with a commit
        let source_dir = tempfile::tempdir().expect("Failed to create source dir");
        let commit_hash = create_test_repo_with_commit(source_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Start server serving the source repo
        let server = SimpleGitServer::start(source_dir.path()).await;

        // Create a destination repo to fetch into
        let dest_dir = tempfile::tempdir().expect("Failed to create dest dir");

        // Initialize empty repo (using tokio::process::Command)
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["init"])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to init dest repo");
        assert!(output.status.success());

        // Add the server as a remote
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["remote", "add", "origin", server.url()])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to add remote");
        assert!(output.status.success());

        // Fetch from the server
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["fetch", "origin"])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to fetch");

        assert!(
            output.status.success(),
            "git fetch should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Verify the commit was fetched
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["rev-parse", "origin/main"])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to rev-parse");

        assert!(output.status.success());
        let fetched_commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(
            fetched_commit, commit_hash,
            "Fetched commit should match source commit"
        );

        server.stop().await;
    }

    #[test]
    fn test_is_safe_path_blocks_traversal() {
        let repo_path = Path::new("/tmp/repo");

        // Safe paths
        assert!(is_safe_path(Path::new("/tmp/repo/info/refs"), repo_path));
        assert!(is_safe_path(
            Path::new("/tmp/repo/objects/pack/file.pack"),
            repo_path
        ));

        // Unsafe paths (path traversal)
        assert!(!is_safe_path(
            Path::new("/tmp/repo/../etc/passwd"),
            repo_path
        ));
        assert!(!is_safe_path(
            Path::new("/tmp/repo/../../etc/passwd"),
            repo_path
        ));
    }
}

// =============================================================================
// SmartGitServer - Git Smart HTTP Protocol Server
// =============================================================================

/// Smart HTTP server for serving git repositories with full protocol support.
///
/// Unlike `SimpleGitServer` which uses the "dumb HTTP" protocol (static files),
/// this server implements the Git Smart HTTP protocol by spawning `git upload-pack`
/// subprocesses. This enables:
///
/// - Shallow clones (`git clone --depth=1`)
/// - Shallow fetches (`git fetch --depth=1`)
/// - Full protocol negotiation
///
/// This is required for tests which explicitly exercise shallow client fetches.
pub struct SmartGitServer {
    /// Shutdown signal sender
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Server task handle
    handle: Option<tokio::task::JoinHandle<()>>,
    /// Server URL (http://127.0.0.1:<port>)
    url: String,
    /// Server port
    #[allow(dead_code)]
    port: u16,
    /// Temporary directory containing the bare repository
    /// Kept alive for the lifetime of the server
    _temp_dir: tempfile::TempDir,
}

impl SmartGitServer {
    /// Start a smart HTTP git server serving the given repository.
    ///
    /// Creates a bare clone of the source repository and starts an HTTP server
    /// that implements the Git Smart HTTP protocol.
    ///
    /// # Arguments
    /// * `source_repo` - Path to the source git repository (can be non-bare)
    ///
    /// # Returns
    /// A `SmartGitServer` instance with the server running
    ///
    /// # Panics
    /// Panics if the git operations fail or the server cannot start
    pub async fn start(source_repo: &Path) -> Self {
        // 1. Create temp directory for bare repo
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir for git server");
        let bare_repo_path = temp_dir.path().join("repo.git");

        // 2. Create bare clone
        let output = git_command()
            .args(["clone", "--bare"])
            .arg(source_repo)
            .arg(&bare_repo_path)
            .output()
            .expect("Failed to run git clone --bare");

        if !output.status.success() {
            panic!(
                "git clone --bare failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // 3. Create and bind listener (eliminates port race condition)
        let std_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port");
        let port = std_listener
            .local_addr()
            .expect("Failed to get local addr")
            .port();

        // Convert to tokio listener (keeps port bound)
        std_listener
            .set_nonblocking(true)
            .expect("Failed to set non-blocking");
        let listener =
            TcpListener::from_std(std_listener).expect("Failed to convert to tokio listener");

        // 4. Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        // 5. Start the HTTP server
        let repo_path = Arc::new(bare_repo_path);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, _addr)) => {
                                let repo_path = Arc::clone(&repo_path);
                                let io = TokioIo::new(stream);

                                tokio::spawn(async move {
                                    let service = service_fn(move |req| {
                                        let repo_path = Arc::clone(&repo_path);
                                        async move { handle_smart_request(req, &repo_path).await }
                                    });

                                    if let Err(e) = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .await
                                    {
                                        // Connection errors are expected when client disconnects
                                        if !e.to_string().contains("connection") {
                                            eprintln!("SmartGitServer connection error: {}", e);
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("SmartGitServer accept error: {}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        // Shutdown signal received
                        break;
                    }
                }
            }
        });

        let url = format!("http://127.0.0.1:{}", port);

        // 6. Wait for server to be ready
        wait_for_server_ready(port).await;

        Self {
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
            url,
            port,
            _temp_dir: temp_dir,
        }
    }

    /// Get the server URL.
    ///
    /// Returns the HTTP URL where the git repository is served.
    /// Can be used directly with `git clone`, `git fetch`, or `git ls-remote`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Stop the server.
    ///
    /// Sends a shutdown signal and waits for the server to stop.
    /// The temporary directory is cleaned up when the server is dropped.
    pub async fn stop(mut self) {
        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for server task to complete
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for SmartGitServer {
    fn drop(&mut self) {
        // Send shutdown signal if not already sent
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // Note: We can't await the handle in drop, but the temp_dir cleanup
        // will happen automatically when _temp_dir is dropped
    }
}

/// Handle an HTTP request using the Git Smart HTTP protocol.
async fn handle_smart_request(
    req: Request<hyper::body::Incoming>,
    repo_path: &Path,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or("");
    let method = req.method();

    // Extract Git-Protocol header (for protocol version 2)
    // We need to clone it to avoid borrowing issues when moving req
    let git_protocol = req
        .headers()
        .get("Git-Protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Route: GET /info/refs?service=git-upload-pack
    if method == hyper::Method::GET && path.ends_with("/info/refs") {
        // Parse service from query string
        let service = query.split('&').find_map(|param| {
            let mut parts = param.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some("service"), Some(svc)) => Some(svc),
                _ => None,
            }
        });

        match service {
            Some("git-upload-pack") => {
                return handle_info_refs_upload_pack(repo_path, git_protocol.as_deref()).await;
            }
            Some("git-receive-pack") => {
                // We only support upload-pack for testing (fetch/clone)
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from("receive-pack not supported")))
                    .unwrap());
            }
            _ => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from(
                        "Missing or invalid service parameter",
                    )))
                    .unwrap());
            }
        }
    }

    // Route: POST /git-upload-pack
    if method == hyper::Method::POST && path.ends_with("/git-upload-pack") {
        return handle_upload_pack(req, repo_path, git_protocol.as_deref()).await;
    }

    // Not found
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("Not Found")))
        .unwrap())
}

/// Handle GET /info/refs?service=git-upload-pack
///
/// This advertises the repository's refs to the client using the smart protocol.
async fn handle_info_refs_upload_pack(
    repo_path: &Path,
    git_protocol_version: Option<&str>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    use tokio::process::Command as TokioCommand;

    // Spawn git upload-pack --advertise-refs
    let mut cmd = TokioCommand::from(grasp_audit::git_command());
    cmd.arg("-c")
        .arg("uploadpack.allowReachableSHA1InWant=true")
        .arg("-c")
        .arg("uploadpack.allowTipSHA1InWant=true")
        .arg("-c")
        .arg("uploadpack.allowFilter=true")
        .arg("upload-pack")
        .arg("--advertise-refs")
        .arg("--stateless-rpc");

    // Set GIT_PROTOCOL environment variable if version 2 is requested
    if let Some(version) = git_protocol_version {
        cmd.env("GIT_PROTOCOL", version);
    }

    cmd.arg(repo_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("Failed to spawn git upload-pack: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Failed to spawn git process")))
                .unwrap());
        }
    };

    // Read stdout
    let mut output = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        if let Err(e) = stdout.read_to_end(&mut output).await {
            eprintln!("Failed to read git output: {}", e);
        }
    }

    // Wait for process
    let status = child.wait().await;
    if let Ok(s) = &status {
        if !s.success() {
            eprintln!("git upload-pack --advertise-refs failed");
        }
    }

    // Build response with pkt-line header
    // Format: pkt-line("# service=git-upload-pack\n") + flush + git output
    let mut response_body = Vec::new();

    // First line: service advertisement
    let service_line = "# service=git-upload-pack\n";
    let len = service_line.len() + 4;
    response_body.extend_from_slice(format!("{:04x}", len).as_bytes());
    response_body.extend_from_slice(service_line.as_bytes());

    // Flush packet
    response_body.extend_from_slice(b"0000");

    // Then the git output
    response_body.extend_from_slice(&output);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            "Content-Type",
            "application/x-git-upload-pack-advertisement",
        )
        .header("Cache-Control", "no-cache")
        .body(Full::new(Bytes::from(response_body)))
        .unwrap())
}

/// Handle POST /git-upload-pack
///
/// This handles the actual fetch negotiation and pack data transfer.
async fn handle_upload_pack(
    req: Request<hyper::body::Incoming>,
    repo_path: &Path,
    git_protocol_version: Option<&str>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    use http_body_util::BodyExt;
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command as TokioCommand;

    // Read request body
    let body_bytes = req.collect().await?.to_bytes();

    // Spawn git upload-pack
    let mut cmd = TokioCommand::from(grasp_audit::git_command());
    cmd.arg("-c")
        .arg("uploadpack.allowReachableSHA1InWant=true")
        .arg("-c")
        .arg("uploadpack.allowTipSHA1InWant=true")
        .arg("-c")
        .arg("uploadpack.allowFilter=true")
        .arg("upload-pack")
        .arg("--stateless-rpc");

    // Set GIT_PROTOCOL environment variable if version 2 is requested
    if let Some(version) = git_protocol_version {
        cmd.env("GIT_PROTOCOL", version);
    }

    cmd.arg(repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("Failed to spawn git upload-pack: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Failed to spawn git process")))
                .unwrap());
        }
    };

    // Write request body to stdin
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(&body_bytes).await {
            eprintln!("Failed to write to git stdin: {}", e);
        }
        // Close stdin to signal end of input
        drop(stdin);
    }

    // Read stdout
    let mut output = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        if let Err(e) = stdout.read_to_end(&mut output).await {
            eprintln!("Failed to read git output: {}", e);
        }
    }

    // Read stderr for debugging
    let mut stderr_output = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_end(&mut stderr_output).await;
    }

    // Wait for process
    let status = child.wait().await;
    if let Ok(s) = &status {
        if !s.success() {
            let stderr_str = String::from_utf8_lossy(&stderr_output);
            eprintln!("git upload-pack failed: {}", stderr_str);
        }
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-upload-pack-result")
        .header("Cache-Control", "no-cache")
        .body(Full::new(Bytes::from(output)))
        .unwrap())
}

#[cfg(test)]
mod smart_git_server_tests {
    use super::*;
    use crate::common::purgatory_helpers::{create_test_repo_with_commit, CommitVariant};

    #[tokio::test]
    async fn test_smart_git_server_starts_and_stops() {
        // Create a test repo
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Start server
        let server = SmartGitServer::start(temp_dir.path()).await;

        // Verify URL is set
        assert!(server.url().starts_with("http://127.0.0.1:"));

        // Stop server
        server.stop().await;
    }

    #[tokio::test]
    async fn test_smart_git_server_info_refs() {
        // Create a test repo
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Start server
        let server = SmartGitServer::start(temp_dir.path()).await;

        // Fetch info/refs with service parameter
        let info_refs_url = format!("{}/info/refs?service=git-upload-pack", server.url());
        let response = reqwest::get(&info_refs_url)
            .await
            .expect("Failed to fetch info/refs");

        assert!(
            response.status().is_success(),
            "info/refs should be accessible"
        );

        // Check content type
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("application/x-git-upload-pack-advertisement"),
            "Content-Type should be git-upload-pack-advertisement, got: {}",
            content_type
        );

        let body = response
            .bytes()
            .await
            .expect("Failed to read response body");

        // Should start with service advertisement pkt-line
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("# service=git-upload-pack"),
            "Response should contain service advertisement, got: {}",
            body_str
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn test_smart_git_server_ls_remote() {
        // Create a test repo
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Start server
        let server = SmartGitServer::start(temp_dir.path()).await;

        // Run git ls-remote against the server (using tokio::process::Command)
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["ls-remote", server.url()])
            .output()
            .await
            .expect("Failed to run git ls-remote");

        assert!(
            output.status.success(),
            "git ls-remote should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Should list the main branch with the correct commit
        assert!(
            stdout.contains(&commit_hash),
            "ls-remote output should contain commit {}, got: {}",
            commit_hash,
            stdout
        );
        assert!(
            stdout.contains("refs/heads/main"),
            "ls-remote output should contain refs/heads/main, got: {}",
            stdout
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn test_smart_git_server_fetch() {
        // Create a source repo with a commit
        let source_dir = tempfile::tempdir().expect("Failed to create source dir");
        let commit_hash = create_test_repo_with_commit(source_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Start server serving the source repo
        let server = SmartGitServer::start(source_dir.path()).await;

        // Create a destination repo to fetch into
        let dest_dir = tempfile::tempdir().expect("Failed to create dest dir");

        // Initialize empty repo
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["init"])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to init dest repo");
        assert!(output.status.success());

        // Add the server as a remote
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["remote", "add", "origin", server.url()])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to add remote");
        assert!(output.status.success());

        // Fetch from the server
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["fetch", "origin"])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to fetch");

        assert!(
            output.status.success(),
            "git fetch should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Verify the commit was fetched
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["rev-parse", "origin/main"])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to rev-parse");

        assert!(output.status.success());
        let fetched_commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(
            fetched_commit, commit_hash,
            "Fetched commit should match source commit"
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn test_smart_git_server_shallow_fetch() {
        // This is the KEY test - shallow fetch requires smart HTTP protocol

        // Create a source repo with a commit
        let source_dir = tempfile::tempdir().expect("Failed to create source dir");
        let commit_hash = create_test_repo_with_commit(source_dir.path(), CommitVariant::StateTest)
            .expect("Failed to create test repo");

        // Start server serving the source repo
        let server = SmartGitServer::start(source_dir.path()).await;

        // Create a destination repo to fetch into
        let dest_dir = tempfile::tempdir().expect("Failed to create dest dir");

        // Initialize empty repo
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["init"])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to init dest repo");
        assert!(output.status.success());

        // Add the server as a remote
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["remote", "add", "origin", server.url()])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to add remote");
        assert!(output.status.success());

        // Shallow fetch from the server - THIS IS WHAT PURGATORY SYNC USES
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["fetch", "--depth=1", "origin", &commit_hash])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to fetch");

        assert!(
            output.status.success(),
            "git fetch --depth=1 should succeed with smart HTTP: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Verify the commit was fetched
        let output = tokio::process::Command::from(grasp_audit::git_command())
            .args(["cat-file", "-t", &commit_hash])
            .current_dir(dest_dir.path())
            .output()
            .await
            .expect("Failed to cat-file");

        assert!(
            output.status.success(),
            "Commit should exist after shallow fetch"
        );
        let object_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(object_type, "commit", "Object should be a commit");

        server.stop().await;
    }
}
