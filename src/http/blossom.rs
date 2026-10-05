//! GRASP-P Blossom-subset blob routes (BUD-01/BUD-02/BUD-06 subset).
//!
//! Routed from `HttpService::call` between the git-URL block and the NIP-11
//! Accept check, and only when a `PrivateService` exists
//! (`NGIT_GRASP_P_REPOS_ENABLE=true`). Unlike the git endpoints, these routes
//! use real HTTP status codes (400/401/403/404/411/413/451/507) with the
//! reason mirrored in an `X-Reason` header.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::{Bytes, Frame, Incoming};
use hyper::{Method, Request, Response};
use nostr_sdk::prelude::PublicKey;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::git::{empty_body, full_body, GitResponseBody};
use crate::grasp_p::{BlobError, BlossomOp, PrivateService};

use futures_util::stream;
use http_body_util::StreamBody;

const STREAM_CHUNK_SIZE: usize = 8 * 1024;
const STREAM_CHANNEL_DEPTH: usize = 8;

type HttpBody = GitResponseBody;

/// CORS advertised only when the GRASP-P blob routes are live
/// (`NGIT_GRASP_P_REPOS_ENABLE=true`): upstream's set plus PUT/DELETE/HEAD and
/// the Blossom request headers. Used by the OPTIONS preflight and by the blob
/// responses, so a disabled node's responses stay upstream's.
const CORS_ALLOW_METHODS: &str = "GET, POST, PUT, DELETE, HEAD";
const CORS_ALLOW_HEADERS: &str =
    "Content-Type, Authorization, Git-Protocol, X-SHA-256, X-Content-Length";

/// Add the GRASP-P CORS headers to a response builder.
pub(super) fn add_cors_headers(
    builder: hyper::http::response::Builder,
) -> hyper::http::response::Builder {
    builder
        .header("Access-Control-Allow-Origin", super::CORS_ALLOW_ORIGIN)
        .header("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)
        .header("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
        .header("Access-Control-Expose-Headers", super::CORS_EXPOSE_HEADERS)
}

fn base_builder() -> hyper::http::response::Builder {
    // These responses are only reachable when private repos are enabled, so
    // they carry the extended blob-method CORS set.
    add_cors_headers(Response::builder().header("server", "ngit-grasp"))
}

/// A GRASP-P Blossom-subset route. Paths are 1-2 segments after the base
/// path is stripped, so they never collide with Git URLs (3+ segments) or
/// the npub landing route.
pub(super) enum BlobRoute {
    /// `HEAD|PUT /upload`
    Upload,
    /// `GET|HEAD|DELETE /<64-lowercase-hex>`
    Blob(String),
    /// `GET /list/<pubkey-hex-or-npub>`
    List(String),
}

/// Match a base-path-stripped request path against the blob routes.
pub(super) fn match_route(path: &str, method: &Method) -> Option<BlobRoute> {
    if matches_upload_route(path, method) {
        return Some(BlobRoute::Upload);
    }
    let segment = path.strip_prefix('/').unwrap_or(path);
    if is_sha256_path_segment(segment)
        && (method == Method::GET || method == Method::HEAD || method == Method::DELETE)
    {
        return Some(BlobRoute::Blob(segment.to_string()));
    }
    if method == Method::GET {
        if let Some(target) = path.strip_prefix("/list/") {
            if !target.is_empty() && !target.contains('/') {
                return Some(BlobRoute::List(target.to_string()));
            }
        }
    }
    None
}

/// Serve a matched blob route.
pub(super) async fn serve(
    route: BlobRoute,
    service: Arc<PrivateService>,
    req: Request<Incoming>,
) -> Response<HttpBody> {
    let method = req.method().clone();
    match route {
        BlobRoute::Upload if method == Method::HEAD => {
            handle_upload_preflight(&service, &req).await
        }
        BlobRoute::Upload => handle_upload_put(&service, req).await,
        BlobRoute::Blob(sha) if method == Method::DELETE => {
            handle_blob_delete(&service, &req, sha).await
        }
        BlobRoute::Blob(sha) => handle_blob_get(&service, sha, method == Method::HEAD).await,
        BlobRoute::List(target) => handle_blob_list(&service, &target).await,
    }
}

fn error_response(err: &BlobError) -> Response<HttpBody> {
    let builder = base_builder()
        .status(err.status())
        .header("X-Reason", err.reason().replace(['\r', '\n'], " "));
    let builder = match err {
        BlobError::RateLimited { retry_after_secs } => {
            builder.header("Retry-After", retry_after_secs.to_string())
        }
        _ => builder,
    };
    builder.body(empty_body()).unwrap()
}

fn json_response(status: u16, json: String) -> Response<HttpBody> {
    base_builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full_body(json))
        .unwrap()
}

/// Is `s` a 64-lowercase-hex sha256?
pub(crate) fn is_sha256_path_segment(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn header_str<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// `HEAD /upload` — BUD-06 preflight.
pub(crate) async fn handle_upload_preflight(
    private: &Arc<PrivateService>,
    req: &Request<Incoming>,
) -> Response<HttpBody> {
    let sha = match header_str(req, "x-sha-256") {
        Some(s) if is_sha256_path_segment(s) => s.to_string(),
        Some(_) => {
            return error_response(&BlobError::BadRequest(
                "X-SHA-256 must be 64 lowercase hex chars".into(),
            ))
        }
        None => {
            return error_response(&BlobError::BadRequest(
                "X-SHA-256 header is required".into(),
            ))
        }
    };
    let len = match header_str(req, "x-content-length").and_then(|v| v.parse::<u64>().ok()) {
        Some(len) => len,
        None => {
            return error_response(&BlobError::BadRequest(
                "X-Content-Length header is required and must be a u64".into(),
            ))
        }
    };

    let auth = match private
        .verify_blossom_auth(header_str(req, "authorization"), BlossomOp::Upload, &sha)
        .await
    {
        Ok(auth) => auth,
        Err(e) => return error_response(&e),
    };

    match private.blob_upload_preflight(&auth, &sha, len).await {
        Ok(()) => base_builder().status(200).body(empty_body()).unwrap(),
        Err(e) => error_response(&e),
    }
}

/// `PUT /upload` — streaming upload: frames are hashed + counted while being
/// written to a temp file; mid-stream overrun aborts with 413; the final hash
/// must equal the auth `x` tag.
pub(crate) async fn handle_upload_put(
    private: &Arc<PrivateService>,
    req: Request<Incoming>,
) -> Response<HttpBody> {
    // Content-Length is REQUIRED (411) and preflight-checked before reading.
    let declared_len = match header_str(&req, "content-length").and_then(|v| v.parse::<u64>().ok())
    {
        Some(len) => len,
        None => return error_response(&BlobError::LengthRequired),
    };

    let auth_header = header_str(&req, "authorization").map(|s| s.to_string());
    // The sha256 being uploaded is the auth event's x-tag commitment. Parse the
    // shape first with a placeholder? No — extract x from the header itself by
    // verifying against the X-SHA-256 header when present, else trust the auth
    // x tag as the target.
    let expected_sha = match header_str(&req, "x-sha-256") {
        Some(s) if is_sha256_path_segment(s) => Some(s.to_string()),
        Some(_) => {
            return error_response(&BlobError::BadRequest(
                "X-SHA-256 must be 64 lowercase hex chars".into(),
            ))
        }
        None => None,
    };

    // Verify the auth event shape/signature/authorization. When no X-SHA-256
    // header is present the auth x tag itself names the target blob.
    let auth = match &expected_sha {
        Some(sha) => {
            match private
                .verify_blossom_auth(auth_header.as_deref(), BlossomOp::Upload, sha)
                .await
            {
                Ok(auth) => auth,
                Err(e) => return error_response(&e),
            }
        }
        None => {
            // Shape-parse to discover the x tag, then verify against it.
            match crate::grasp_p::blossom_auth::sha_from_header(auth_header.as_deref()) {
                Ok(sha) => match private
                    .verify_blossom_auth(auth_header.as_deref(), BlossomOp::Upload, &sha)
                    .await
                {
                    Ok(auth) => auth,
                    Err(e) => return error_response(&e),
                },
                Err(e) => return error_response(&e),
            }
        }
    };

    // Phase-4b A1: per-write-key token bucket — one token per PUT request,
    // keyed by the verified auth (write) pubkey. Blob PUTs are client-only
    // (the mirror pulls over GET; sync never PUTs), so no bypass is needed.
    if !private.client_write_allowed(&auth.pubkey_hex) {
        crate::metrics::record_private_rate_limited("upload");
        return error_response(&BlobError::RateLimited {
            retry_after_secs: private.write_rate_retry_after_secs(),
        });
    }

    // Preflight against quota / max size before reading the body, then open
    // the streaming sink.
    let mut sink = match private.begin_upload(&auth, declared_len).await {
        Ok(sink) => sink,
        Err(e) => return error_response(&e),
    };

    // Stream hyper's Incoming frame-by-frame — never buffer the body.
    let mut body = req.into_body();
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if let Err(e) = sink.write_chunk(&data).await {
                        // Mid-stream 413 (or IO failure): drop the sink (temp
                        // file removed by Drop) and answer immediately.
                        return error_response(&e);
                    }
                }
            }
            Some(Err(e)) => {
                return error_response(&BlobError::BadRequest(format!("request body error: {e}")));
            }
            None => break,
        }
    }

    match sink.finish().await {
        Ok(descriptor) => match serde_json::to_string(&descriptor) {
            Ok(json) => json_response(200, json),
            Err(e) => error_response(&BlobError::Internal(format!("serialize failed: {e}"))),
        },
        Err(e) => error_response(&e),
    }
}

/// `GET|HEAD /<sha256>` — public unauthenticated blob fetch (v1 by design).
pub(crate) async fn handle_blob_get(
    private: &Arc<PrivateService>,
    sha: String,
    is_head: bool,
) -> Response<HttpBody> {
    if private.is_denylisted(&sha) {
        return error_response(&BlobError::Denylisted);
    }
    let Some(path) = private.blob_path(&sha) else {
        return base_builder().status(404).body(empty_body()).unwrap();
    };
    let size = match tokio::fs::metadata(&path).await {
        Ok(meta) => meta.len(),
        Err(_) => return base_builder().status(404).body(empty_body()).unwrap(),
    };

    let builder = base_builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .header("cache-control", "public, max-age=31536000, immutable")
        .header("content-length", size);

    if is_head {
        return builder.body(empty_body()).unwrap();
    }

    let file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(e) => return error_response(&BlobError::Internal(format!("failed to open blob: {e}"))),
    };

    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(STREAM_CHANNEL_DEPTH);
    tokio::spawn(async move {
        let mut file = file;
        let mut buf = [0_u8; STREAM_CHUNK_SIZE];
        loop {
            match file.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .send(Ok(Frame::data(Bytes::from(buf[..n].to_vec()))))
                        .await
                        .is_err()
                    {
                        break; // client disconnected
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    let body_stream = stream::unfold(rx, |mut rx| async { rx.recv().await.map(|i| (i, rx)) });
    let body = BodyExt::boxed(StreamBody::new(body_stream));

    crate::metrics::record_private_blob_download();
    builder.body(body).unwrap()
}

/// `DELETE /<sha256>` — remove the attributed alias's claim (idempotent).
pub(crate) async fn handle_blob_delete(
    private: &Arc<PrivateService>,
    req: &Request<Incoming>,
    sha: String,
) -> Response<HttpBody> {
    let auth = match private
        .verify_blossom_auth(header_str(req, "authorization"), BlossomOp::Delete, &sha)
        .await
    {
        Ok(auth) => auth,
        Err(e) => return error_response(&e),
    };
    match private.blob_delete(&auth, &sha).await {
        Ok(()) => base_builder().status(200).body(empty_body()).unwrap(),
        Err(e) => error_response(&e),
    }
}

/// `GET /list/<pubkey-hex-or-npub>` — aggregate blob descriptors for a tenant.
pub(crate) async fn handle_blob_list(
    private: &Arc<PrivateService>,
    tenant: &str,
) -> Response<HttpBody> {
    let Ok(pubkey) = PublicKey::parse(tenant) else {
        return error_response(&BlobError::BadRequest(
            "list target must be a pubkey (hex or npub)".into(),
        ));
    };
    let descriptors = private.blob_list(&pubkey).await;
    match serde_json::to_string(&descriptors) {
        Ok(json) => json_response(200, json),
        Err(e) => error_response(&BlobError::Internal(format!("serialize failed: {e}"))),
    }
}

/// `PUT|HEAD /upload` requests with any other method fall through to the
/// generic 404, so `matches_upload_route` only claims what we serve.
pub(crate) fn matches_upload_route(path: &str, method: &Method) -> bool {
    path == "/upload" && (*method == Method::PUT || *method == Method::HEAD)
}
