//! GRASP-P Blossom-subset blob routes (BUD-01/BUD-02/BUD-06 subset).
//!
//! Routed from `HttpService::call` between the git-URL block and the NIP-11
//! Accept check, and only when a `PrivateService` exists
//! (`NGIT_PRIVATE_REPOS_ENABLE=true`). Unlike the git endpoints, these routes
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
use crate::private::{BlobError, BlossomOp, PrivateService};

use futures_util::stream;
use http_body_util::StreamBody;

const STREAM_CHUNK_SIZE: usize = 8 * 1024;
const STREAM_CHANNEL_DEPTH: usize = 8;

type HttpBody = GitResponseBody;

fn base_builder() -> hyper::http::response::Builder {
    // These responses are only reachable when private repos are enabled, so
    // they carry the extended blob-method CORS set.
    super::add_cors_headers_private(Response::builder().header("server", "ngit-grasp"))
}

fn error_response(err: &BlobError) -> Response<HttpBody> {
    base_builder()
        .status(err.status())
        .header("X-Reason", err.reason().replace(['\r', '\n'], " "))
        .body(empty_body())
        .unwrap()
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
            match crate::private::blossom_auth::sha_from_header(auth_header.as_deref()) {
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
                return error_response(&BlobError::BadRequest(format!(
                    "request body error: {e}"
                )));
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
        Err(e) => {
            return error_response(&BlobError::Internal(format!("failed to open blob: {e}")))
        }
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
