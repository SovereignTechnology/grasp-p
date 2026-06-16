/// HTTP Server Module
///
/// Provides hyper HTTP server with WebSocket upgrade support for the Nostr relay.
pub mod landing;
pub mod nip11;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use nostr_relay_builder::LocalRelay;
use nostr::hashes::sha1::Hash as Sha1Hash;
use nostr::hashes::{Hash, HashEngine};
use nostr_sdk::prelude::PublicKey;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::git;
use crate::grasp06::receive::RepoInitLocks;
use crate::metrics::Metrics;
use crate::nostr::builder::{Nip34WritePolicy, SharedDatabase};
use crate::purgatory::Purgatory;
use crate::sync::rejected_index::RejectedEventsIndex;

/// CORS headers required by GRASP-01 specification (lines 40-47)
const CORS_ALLOW_ORIGIN: &str = "*";
const CORS_ALLOW_METHODS: &str = "GET, POST";
const CORS_ALLOW_HEADERS: &str = "Content-Type";

/// Embedded icon image (Grasp logo)
const ICON_PNG: &[u8] = include_bytes!("../../static/icon.png");

/// Extract npub and identifier from a repository URL path (no git subpath required)
///
/// Parses paths like `/<npub>/<identifier>.git` (for repository webpage/404)
///
/// The identifier is percent-decoded so that URLs like `/npub1.../my%20repo.git`
/// resolve to the correct filesystem path.
///
/// Returns (npub, identifier) if the path matches a repository URL pattern
fn parse_repo_url(path: &str) -> Option<(String, String)> {
    // Defensive guard: never match the GRASP-06 `/prs/` namespace as a
    // standard repo URL. `HttpService::call` already intercepts `/prs/*`
    // before reaching the landing branch when grasp06_enable is on, but
    // this early-return ensures a future routing change cannot regress us
    // into serving repo landing HTML at `/prs/<npub>/<id>.git` regardless
    // of the feature flag.
    if path.starts_with("/prs/") || path.starts_with("prs/") {
        return None;
    }

    // Remove leading slash
    let path = path.strip_prefix('/').unwrap_or(path);

    // Split into components
    let parts: Vec<&str> = path.split('/').collect();

    // Must be exactly 2 parts: npub and repo.git (no subpath)
    if parts.len() != 2 {
        return None;
    }

    let npub = parts[0];
    let repo_part = git::percent_decode(parts[1]);

    // The repo part must end with .git
    if !repo_part.ends_with(".git") {
        return None;
    }

    // Must have an npub that looks valid (starts with npub1)
    if !npub.starts_with("npub1") {
        return None;
    }

    // Extract identifier (remove .git suffix)
    let identifier = repo_part
        .strip_suffix(".git")
        .unwrap_or(&repo_part)
        .to_string();

    // Identifier must not be empty
    if identifier.is_empty() {
        return None;
    }

    Some((npub.to_string(), identifier))
}

/// Add CORS headers to a response builder
fn add_cors_headers(builder: hyper::http::response::Builder) -> hyper::http::response::Builder {
    builder
        .header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
        .header("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)
        .header("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
}

/// HTTP Service that serves both WebSocket (relay) and HTML landing page
struct HttpService {
    relay: LocalRelay,
    config: Config,
    remote: SocketAddr,
    /// Database reference for direct queries (e.g., push authorization)
    database: SharedDatabase,
    /// Optional metrics for Prometheus endpoint
    metrics: Option<Arc<Metrics>>,
    /// Purgatory for event/git coordination
    purgatory: Arc<Purgatory>,
    /// Write policy for re-processing hot-cache events after git push promotion
    write_policy: Arc<Nip34WritePolicy>,
    /// Rejected events index for hot-cache re-processing after git push promotion
    rejected_events_index: Arc<RejectedEventsIndex>,
    /// Per-path init mutexes for GRASP-06 `/prs/` on-demand bare-repo
    /// creation. See [`crate::grasp06::receive::RepoInitLocks`].
    repo_init_locks: RepoInitLocks,
}

impl HttpService {
    #[allow(clippy::too_many_arguments)]
    fn new(
        relay: LocalRelay,
        config: Config,
        remote: SocketAddr,
        database: SharedDatabase,
        metrics: Option<Arc<Metrics>>,
        purgatory: Arc<Purgatory>,
        write_policy: Arc<Nip34WritePolicy>,
        rejected_events_index: Arc<RejectedEventsIndex>,
        repo_init_locks: RepoInitLocks,
    ) -> Self {
        Self {
            relay,
            config,
            remote,
            database,
            metrics,
            purgatory,
            write_policy,
            rejected_events_index,
            repo_init_locks,
        }
    }
}

impl Service<Request<Incoming>> for HttpService {
    type Response = Response<Full<Bytes>>;
    type Error = String;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let base = add_cors_headers(Response::builder().header("server", "ngit-grasp"));
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(|s| s.to_string());
        let method = req.method().clone();
        let git_data_path = self.config.effective_git_data_path();
        let database = self.database.clone();
        let purgatory = self.purgatory.clone();
        let write_policy = self.write_policy.clone();
        let rejected_events_index = self.rejected_events_index.clone();
        let repo_init_locks = self.repo_init_locks.clone();

        // Handle OPTIONS preflight requests (CORS)
        // GRASP-01 spec line 47: Respond to OPTIONS with 204 No Content
        if method == Method::OPTIONS {
            return Box::pin(async move {
                Ok(
                    add_cors_headers(Response::builder().header("server", "ngit-grasp"))
                        .status(204)
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
            });
        }

        // GRASP-06: route /prs/<npub>/<id>.git/* before the standard git URL
        // parser. When disabled, the path falls through to existing 404
        // handling (preserving the discovery-gate contract).
        if self.config.grasp06_enable {
            if let Some(prs) = crate::grasp06::endpoint::parse_prs_url(&path) {
                let git_protocol = req
                    .headers()
                    .get("git-protocol")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let content_encoding = req
                    .headers()
                    .get("content-encoding")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_lowercase());

                tracing::debug!(
                    "/prs/ request: {} {} (submitter={}, id={}, subpath={}, protocol={:?})",
                    method,
                    path,
                    prs.submitter.to_hex(),
                    prs.identifier,
                    prs.subpath,
                    git_protocol
                );

                let subpath = prs.subpath.clone();
                let method_clone = method.clone();
                let metrics_clone = self.metrics.clone();
                let relay_clone = self.relay.clone();
                let config_clone = self.config.clone();

                return Box::pin(async move {
                    // Collect (and gunzip if needed) the request body just like
                    // the standard git branch does.
                    let raw_body = req
                        .collect()
                        .await
                        .map(|collected| collected.to_bytes())
                        .unwrap_or_else(|_| Bytes::new());
                    let body_bytes = if content_encoding.as_deref() == Some("gzip") {
                        use flate2::read::GzDecoder;
                        use std::io::Read;
                        let mut decoder = GzDecoder::new(&raw_body[..]);
                        let mut decompressed = Vec::new();
                        match decoder.read_to_end(&mut decompressed) {
                            Ok(_) => Bytes::from(decompressed),
                            Err(e) => {
                                tracing::warn!("/prs/ gzip decompress failed: {}", e);
                                raw_body
                            }
                        }
                    } else {
                        raw_body
                    };

                    let result: Result<Response<Full<Bytes>>, git::handlers::GitError> =
                        match (method_clone.as_ref(), subpath.as_str()) {
                            // GET|HEAD /info/refs?service=git-{upload,receive}-pack
                            // HEAD must mirror GET headers with no body (RFC 9110 §9.3.2)
                            (m, sp)
                                if (m == Method::GET || m == Method::HEAD)
                                    && sp.starts_with("info/refs") =>
                            {
                                let service = query
                                    .as_deref()
                                    .unwrap_or("")
                                    .strip_prefix("service=")
                                    .and_then(git::protocol::GitService::from_query_param);
                                match service {
                                    Some(svc) => {
                                        let r = crate::grasp06::fetch::handle_prs_info_refs(
                                            &prs,
                                            &git_data_path,
                                            svc,
                                            git_protocol.as_deref(),
                                        )
                                        .await;
                                        if let Some(ref m) = metrics_clone {
                                            let status =
                                                if r.is_ok() { "success" } else { "error" };
                                            let op = match svc {
                                                git::protocol::GitService::UploadPack => "fetch",
                                                git::protocol::GitService::ReceivePack => "push",
                                            };
                                            m.record_git_operation(op, status);
                                        }
                                        r
                                    }
                                    None => Err(git::handlers::GitError::RepositoryNotFound),
                                }
                            }

                            // POST /git-upload-pack — clone/fetch.
                            (m, "git-upload-pack") if m == Method::POST => {
                                let r = crate::grasp06::fetch::handle_prs_upload_pack(
                                    &prs,
                                    &git_data_path,
                                    body_bytes,
                                    git_protocol.as_deref(),
                                )
                                .await;
                                if let Some(ref m) = metrics_clone {
                                    let status = if r.is_ok() { "success" } else { "error" };
                                    m.record_git_operation("clone", status);
                                }
                                r
                            }

                            // POST /git-receive-pack — accept pushes to
                            // refs/nostr/<event-id>, reject anything else,
                            // per GRASP-06 06.md line 15.
                            (m, "git-receive-pack") if m == Method::POST => {
                                let r = crate::grasp06::receive::handle_prs_receive_pack(
                                    &prs,
                                    body_bytes,
                                    database.clone(),
                                    relay_clone.clone(),
                                    purgatory.clone(),
                                    write_policy.clone(),
                                    rejected_events_index.clone(),
                                    &git_data_path,
                                    git_protocol.as_deref(),
                                    repo_init_locks.clone(),
                                    &config_clone.domain,
                                )
                                .await;
                                if let Some(ref m) = metrics_clone {
                                    let status = if r.is_ok() { "success" } else { "error" };
                                    m.record_git_operation("push", status);
                                }
                                r
                            }

                            _ => Err(git::handlers::GitError::RepositoryNotFound),
                        };

                    match result {
                        Ok(response) => {
                            let (parts, body) = response.into_parts();
                            // RFC 9110 §9.3.2: HEAD response must have same headers as GET
                            // but no body.
                            let body = if method_clone == Method::HEAD {
                                Full::new(Bytes::new())
                            } else {
                                body
                            };
                            Ok(add_cors_headers(Response::builder().status(parts.status))
                                .header(
                                    "content-type",
                                    parts
                                        .headers
                                        .get("content-type")
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or("application/octet-stream"),
                                )
                                .header(
                                    "cache-control",
                                    parts
                                        .headers
                                        .get("cache-control")
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or("no-cache"),
                                )
                                .body(body)
                                .unwrap())
                        }
                        Err(e) => {
                            let error_msg = format!("Git error: {}", e);
                            Ok(add_cors_headers(Response::builder())
                                .status(e.status_code())
                                .body(Full::new(Bytes::from(error_msg)))
                                .unwrap())
                        }
                    }
                });
            }
        }

        // Check for Git HTTP requests first
        if let Some((npub, identifier, subpath)) = git::parse_git_url(&path) {
            // Extract Git-Protocol header for protocol v2 support
            let git_protocol = req
                .headers()
                .get("git-protocol")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Extract Content-Encoding header to handle gzip-compressed request bodies
            // Modern git clients send gzip-compressed POST bodies for efficiency
            let content_encoding = req
                .headers()
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_lowercase());

            tracing::debug!(
                "Git request: {} {} (npub={}, id={}, subpath={}, protocol={:?}, encoding={:?})",
                method,
                path,
                npub,
                identifier,
                subpath,
                git_protocol,
                content_encoding
            );

            let repo_path = git::resolve_repo_path(&git_data_path, &npub, &identifier);
            let metrics_clone = self.metrics.clone();
            let relay = self.relay.clone();

            return Box::pin(async move {
                // Collect request body once before the match statement
                let raw_body = req
                    .collect()
                    .await
                    .map(|collected| collected.to_bytes())
                    .unwrap_or_else(|_| Bytes::new());

                // Decompress gzip-encoded request bodies
                // Git clients send Content-Encoding: gzip for POST requests
                let body_bytes = if content_encoding.as_deref() == Some("gzip") {
                    use flate2::read::GzDecoder;
                    use std::io::Read;

                    let mut decoder = GzDecoder::new(&raw_body[..]);
                    let mut decompressed = Vec::new();
                    match decoder.read_to_end(&mut decompressed) {
                        Ok(_) => {
                            tracing::debug!(
                                "Decompressed gzip body: {} -> {} bytes",
                                raw_body.len(),
                                decompressed.len()
                            );
                            Bytes::from(decompressed)
                        }
                        Err(e) => {
                            tracing::warn!("Failed to decompress gzip body: {}", e);
                            // Fall back to raw body (might work if not actually gzip)
                            raw_body
                        }
                    }
                } else {
                    raw_body
                };

                let result = match (method.as_ref(), subpath.as_str()) {
                    // GET|HEAD /info/refs?service=git-upload-pack or git-receive-pack
                    // HEAD must mirror GET headers with no body (RFC 9110 §9.3.2)
                    (m, sp)
                        if (m == Method::GET || m == Method::HEAD)
                            && sp.starts_with("info/refs") =>
                    {
                        // Parse query string for service parameter
                        let service = query
                            .as_deref()
                            .unwrap_or("")
                            .strip_prefix("service=")
                            .and_then(git::protocol::GitService::from_query_param);

                        match service {
                            Some(svc) => {
                                let result = git::handlers::handle_info_refs(
                                    repo_path,
                                    svc,
                                    git_protocol.as_deref(),
                                )
                                .await;
                                // Track operation
                                if let Some(ref m) = metrics_clone {
                                    let status = if result.is_ok() { "success" } else { "error" };
                                    let operation = match svc {
                                        git::protocol::GitService::UploadPack => "fetch",
                                        git::protocol::GitService::ReceivePack => "push",
                                    };
                                    m.record_git_operation(operation, status);
                                }
                                result
                            }
                            None => Err(git::handlers::GitError::RepositoryNotFound),
                        }
                    }

                    // POST /git-upload-pack (clone/fetch)
                    (m, "git-upload-pack") if m == Method::POST => {
                        let result = git::handlers::handle_upload_pack(
                            repo_path,
                            body_bytes,
                            git_protocol.as_deref(),
                        )
                        .await;
                        if let Some(ref m) = metrics_clone {
                            let status = if result.is_ok() { "success" } else { "error" };
                            m.record_git_operation("clone", status);
                        }
                        result
                    }

                    // POST /git-receive-pack (push) - with GRASP authorization via database
                    (m, "git-receive-pack") if m == Method::POST => {
                        // Convert npub (bech32) to hex pubkey for authorization
                        let owner_pubkey_hex = match PublicKey::parse(&npub) {
                            Ok(pk) => pk.to_hex(),
                            Err(e) => {
                                tracing::warn!("Invalid npub in URL {}: {}", npub, e);
                                // Track failed push due to invalid npub
                                if let Some(ref m) = metrics_clone {
                                    m.record_git_operation("push", "error");
                                }
                                return Ok(add_cors_headers(Response::builder())
                                    .status(hyper::StatusCode::BAD_REQUEST)
                                    .body(Full::new(Bytes::from(format!("Invalid npub: {}", e))))
                                    .unwrap());
                            }
                        };

                        let result = git::handlers::handle_receive_pack(
                            repo_path,
                            body_bytes.clone(),
                            database.clone(),
                            relay.clone(),
                            &identifier,
                            &owner_pubkey_hex,
                            purgatory.clone(),
                            &git_data_path,
                            git_protocol.as_deref(),
                            write_policy.clone(),
                            rejected_events_index.clone(),
                        )
                        .await;

                        if let Some(ref m) = metrics_clone {
                            let status = if result.is_ok() { "success" } else { "error" };
                            m.record_git_operation("push", status);
                        }

                        result
                    }

                    _ => Err(git::handlers::GitError::RepositoryNotFound),
                };

                match result {
                    Ok(response) => {
                        // Add CORS headers to successful Git responses
                        let (parts, body) = response.into_parts();
                        // RFC 9110 §9.3.2: HEAD response must have same headers as GET
                        // but no body.
                        let body = if method == Method::HEAD {
                            Full::new(Bytes::new())
                        } else {
                            body
                        };
                        Ok(add_cors_headers(Response::builder().status(parts.status))
                            .header(
                                "content-type",
                                parts
                                    .headers
                                    .get("content-type")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("application/octet-stream"),
                            )
                            .header(
                                "cache-control",
                                parts
                                    .headers
                                    .get("cache-control")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("no-cache"),
                            )
                            .body(body)
                            .unwrap())
                    }
                    Err(e) => {
                        // Errors are already logged at their source with full context
                        let error_msg = format!("Git error: {}", e);
                        Ok(add_cors_headers(Response::builder())
                            .status(e.status_code())
                            .body(Full::new(Bytes::from(error_msg)))
                            .unwrap())
                    }
                }
            });
        }

        // Check for NIP-11 relay information request (Accept: application/nostr+json)
        if let Some(accept) = req.headers().get("accept") {
            if accept
                .to_str()
                .map(|s| s.contains("application/nostr+json"))
                .unwrap_or(false)
            {
                let doc = nip11::RelayInformationDocument::from_config(&self.config);
                let json = doc.to_json().unwrap_or_else(|e| {
                    tracing::error!("Failed to serialize NIP-11 document: {}", e);
                    "{}".to_string()
                });

                tracing::debug!(
                    "Serving NIP-11 relay information document to {}",
                    self.remote
                );

                return Box::pin(async move {
                    Ok(
                        add_cors_headers(Response::builder().header("server", "ngit-grasp"))
                            .status(200)
                            .header("content-type", "application/nostr+json")
                            .body(Full::new(Bytes::from(json)))
                            .unwrap(),
                    )
                });
            }
        }

        // Check for repository URL pattern (e.g., /npub/repo.git without subpath)
        // GRASP-01: "SHOULD serve a webpage at the same endpoint linking to git nostr client(s)
        // to browse the repository and a 404 page for repositories it doesn't host"
        if let Some((npub, identifier)) = parse_repo_url(&path) {
            let config = self.config.clone();
            let repo_path = git::resolve_repo_path(&git_data_path, &npub, &identifier);

            tracing::debug!(
                "Repository URL request: {} (npub={}, id={}, path={:?})",
                path,
                npub,
                identifier,
                repo_path
            );

            return Box::pin(async move {
                // Check if repository exists
                if repo_path.exists() {
                    // Serve repository webpage
                    let html = landing::get_repo_html(&config, &npub, &identifier);
                    Ok(
                        add_cors_headers(Response::builder().header("server", "ngit-grasp"))
                            .status(200)
                            .header("content-type", "text/html; charset=utf-8")
                            .body(Full::new(Bytes::from(html)))
                            .unwrap(),
                    )
                } else {
                    // Serve 404 page for non-existent repository
                    let html = landing::get_404_html(&config, &npub, &identifier);
                    Ok(
                        add_cors_headers(Response::builder().header("server", "ngit-grasp"))
                            .status(404)
                            .header("content-type", "text/html; charset=utf-8")
                            .body(Full::new(Bytes::from(html)))
                            .unwrap(),
                    )
                }
            });
        }

        // Check if this is a WebSocket upgrade request
        if let (Some(c), Some(w)) = (
            req.headers().get("connection"),
            req.headers().get("upgrade"),
        ) {
            if c.to_str()
                .map(|s| s.to_lowercase() == "upgrade")
                .unwrap_or(false)
                && w.to_str()
                    .map(|s| s.to_lowercase() == "websocket")
                    .unwrap_or(false)
            {
                let key = req.headers().get("sec-websocket-key");
                let derived = key.map(|k| derive_accept_key(k.as_bytes()));

                let addr = self.remote;
                let relay = self.relay.clone();
                let metrics_clone = self.metrics.clone();

                tokio::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            tracing::info!("WebSocket connection established from {}", addr);
                            // Track connection
                            if let Some(ref m) = metrics_clone {
                                m.connection_tracker().on_connect(addr.ip());
                                m.record_websocket_connection();
                            }
                            if let Err(e) =
                                relay.take_connection(TokioIo::new(upgraded), addr).await
                            {
                                tracing::error!("Relay error for {}: {}", addr, e);
                            }
                            tracing::info!("WebSocket connection closed for {}", addr);
                            // Untrack connection
                            if let Some(ref m) = metrics_clone {
                                m.connection_tracker().on_disconnect(addr.ip());
                            }
                        }
                        Err(e) => tracing::error!("Upgrade error: {}", e),
                    }
                });

                return Box::pin(async move {
                    Ok(base
                        .status(101)
                        .header(CONNECTION, "upgrade")
                        .header(UPGRADE, "websocket")
                        .header(SEC_WEBSOCKET_ACCEPT, derived.unwrap())
                        .body(Full::new(Bytes::new()))
                        .unwrap())
                });
            }
        }

        // Serve Prometheus metrics if enabled
        if path == "/metrics" {
            if let Some(ref metrics) = self.metrics {
                let metrics = metrics.clone();
                return Box::pin(async move {
                    let output = metrics.render();
                    Ok(
                        add_cors_headers(Response::builder().header("server", "ngit-grasp"))
                            .status(200)
                            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
                            .body(Full::new(Bytes::from(output)))
                            .unwrap(),
                    )
                });
            } else {
                // Metrics disabled
                return Box::pin(async move {
                    Ok(
                        add_cors_headers(Response::builder().header("server", "ngit-grasp"))
                            .status(404)
                            .body(Full::new(Bytes::from("Metrics disabled")))
                            .unwrap(),
                    )
                });
            }
        }

        // Serve static icon at /icon.png
        if path == "/icon.png" {
            return Box::pin(async move {
                Ok(
                    add_cors_headers(Response::builder().header("server", "ngit-grasp"))
                        .status(200)
                        .header("content-type", "image/png")
                        .header("cache-control", "public, max-age=86400")
                        .body(Full::new(Bytes::from_static(ICON_PNG)))
                        .unwrap(),
                )
            });
        }

        // Only serve landing page for root path "/", 404 for everything else
        let config = self.config.clone();
        Box::pin(async move {
            if path == "/" {
                // Serve landing page for root
                let html = landing::get_html(&config);
                Ok(
                    add_cors_headers(Response::builder().header("server", "ngit-grasp"))
                        .status(200)
                        .header("content-type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(html)))
                        .unwrap(),
                )
            } else {
                // Serve generic 404 for unknown paths
                let html = landing::get_generic_404_html(&config, &path);
                Ok(
                    add_cors_headers(Response::builder().header("server", "ngit-grasp"))
                        .status(404)
                        .header("content-type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(html)))
                        .unwrap(),
                )
            }
        })
    }
}

/// Derive the `Sec-WebSocket-Accept` response header from a `Sec-WebSocket-Key` request header
fn derive_accept_key(request_key: &[u8]) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut engine = Sha1Hash::engine();
    engine.input(request_key);
    engine.input(WS_GUID);
    let hash: Sha1Hash = Sha1Hash::from_engine(engine);
    base64::prelude::BASE64_STANDARD.encode(hash)
}

/// Start the HTTP server with integrated Nostr relay
///
/// # Arguments
/// * `config` - Server configuration
/// * `relay` - The LocalRelay for WebSocket connections
/// * `database` - The database for direct queries (e.g., push authorization)
/// * `metrics` - Optional metrics for Prometheus endpoint
/// * `purgatory` - Purgatory for event/git coordination
/// * `write_policy` - Write policy for re-processing hot-cache events after git push promotion
/// * `rejected_events_index` - Rejected events index for hot-cache re-processing
#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    config: Config,
    relay: LocalRelay,
    database: SharedDatabase,
    metrics: Option<Arc<Metrics>>,
    purgatory: Arc<Purgatory>,
    write_policy: Arc<Nip34WritePolicy>,
    rejected_events_index: Arc<RejectedEventsIndex>,
    repo_init_locks: RepoInitLocks,
) -> anyhow::Result<()> {
    let bind_addr: SocketAddr = config.bind_address.parse()?;

    tracing::info!("Starting HTTP server on {}", bind_addr);
    tracing::info!("Relay name: {}", config.relay_name());
    tracing::info!("Domain: {}", config.domain);

    let listener = TcpListener::bind(&bind_addr).await?;

    loop {
        let (socket, addr) = listener.accept().await?;
        let io = TokioIo::new(socket);
        let service = HttpService::new(
            relay.clone(),
            config.clone(),
            addr,
            database.clone(),
            metrics.clone(),
            purgatory.clone(),
            write_policy.clone(),
            rejected_events_index.clone(),
            repo_init_locks.clone(),
        );

        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                tracing::error!("Failed to handle request from {}: {}", addr, e);
            }
        });
    }
}
