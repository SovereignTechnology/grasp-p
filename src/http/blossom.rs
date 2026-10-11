//! GRASP-P Blossom-subset blob routes (BUD-01/BUD-02/BUD-06 subset).
//!
//! Routed from `HttpService::call` between the git-URL block and the NIP-11
//! Accept check, and only when a `PrivateService` exists
//! (`NGIT_GRASP_P_REPOS_ENABLE=true`). Unlike the git endpoints, these routes
//! use real HTTP status codes (400/401/403/404/411/413/451/507) with the
//! reason mirrored in an `X-Reason` header. Upload, delete and list need a
//! kind-24242 authorization; `GET`/`HEAD /<sha256>` are anonymous by design.
//!
//! What every response of these routes says to a browser or a cache:
//!
//! - `X-Content-Type-Options: nosniff` on all of them, the `OPTIONS`
//!   preflight that `mod.rs` answers included. The bytes are
//!   whatever a client uploaded, and a browser must not guess a type.
//! - A served blob adds a `Content-Security-Policy` that makes the bytes
//!   inert if a browser is pointed at them, and `Cache-Control: no-cache`
//!   with a strong `ETag` of the sha256. A cache may keep the bytes but has
//!   to ask this node before each reuse, so a blob that was taken down
//!   stops being served from caches too. The question is answered `304`
//!   only after the denylist and the existence checks ([`decide_blob_read`]).
//! - Errors and `404`s say `Cache-Control: no-store`: `404` and `451` are
//!   cacheable by default, and a cached one would outlive its cause.
//! - `WWW-Authenticate: Nostr` on a `401` and on no other status.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::{Bytes, Frame, Incoming};
use hyper::{Method, Request, Response};
use nostr_sdk::prelude::PublicKey;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::git::{empty_body, full_body, GitResponseBody};
use crate::grasp_p::blossom_auth::authorize_list;
use crate::grasp_p::{BlobError, BlossomOp, PrivateService};

use futures_util::stream;
use http_body_util::StreamBody;

/// What a client is told when its upload body could not be read.
const BODY_ERROR_REASON: &str = "request body error";

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
/// Upstream's exposed header, plus the two a browser client needs to read to
/// tell why a blob request failed and when to try again.
const CORS_EXPOSE_HEADERS: &str = "WWW-Authenticate, X-Reason, Retry-After";

/// Makes a browser treat a blob it is pointed at as inert: nothing in it
/// may load or run, and it gets an origin of its own.
const BLOB_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; sandbox";
/// A cache may keep a blob, but must ask this node before each reuse.
const BLOB_CACHE_CONTROL: &str = "no-cache";
/// For responses no cache may keep: errors, `404`s and per-key listings.
const NO_STORE: &str = "no-store";

/// Add the GRASP-P CORS headers to a response builder, and the `nosniff`
/// every response of these routes carries, the preflight included (the
/// `OPTIONS` answer in `mod.rs` is built from this function alone).
pub(super) fn add_cors_headers(
    builder: hyper::http::response::Builder,
) -> hyper::http::response::Builder {
    builder
        .header("Access-Control-Allow-Origin", super::CORS_ALLOW_ORIGIN)
        .header("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)
        .header("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
        .header("Access-Control-Expose-Headers", CORS_EXPOSE_HEADERS)
        .header("X-Content-Type-Options", "nosniff")
}

/// The start of every response of the blob routes.
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
        BlobRoute::Blob(sha) => {
            let conditional = if_none_match(&req);
            handle_blob_get(
                &service,
                sha,
                method == Method::HEAD,
                conditional.as_deref(),
            )
            .await
        }
        BlobRoute::List(target) => handle_blob_list(&service, &req, &target).await,
    }
}

fn error_response(err: &BlobError) -> Response<HttpBody> {
    if let BlobError::Internal(detail) = err {
        // The one place the detail of an internal failure is recorded: the
        // client is told only that there was one.
        tracing::error!("blob route internal error: {detail}");
    }
    let builder = base_builder()
        .status(err.status())
        .header("cache-control", NO_STORE)
        .header(
            "X-Reason",
            // A control character is not allowed in a header value.
            err.public_reason().replace(char::is_control, " "),
        );
    let builder = match err {
        BlobError::Unauthorized(_) => builder.header("WWW-Authenticate", "Nostr"),
        BlobError::RateLimited { retry_after_secs } => {
            builder.header("Retry-After", retry_after_secs.to_string())
        }
        _ => builder,
    };
    builder.body(empty_body()).unwrap()
}

/// The `404` of a blob this node does not hold.
fn not_found() -> Response<HttpBody> {
    base_builder()
        .status(404)
        .header("cache-control", NO_STORE)
        .body(empty_body())
        .unwrap()
}

/// The validators a served blob and the `304` that confirms it share: a
/// `304` has to repeat the `ETag` and `Cache-Control` of the `200`.
fn blob_validators(
    builder: hyper::http::response::Builder,
    sha: &str,
) -> hyper::http::response::Builder {
    builder
        .header("cache-control", BLOB_CACHE_CONTROL)
        .header("etag", format!("\"{sha}\""))
}

/// The head of a `200` for a stored blob, shared by `GET` and `HEAD`.
fn blob_ok_builder(sha: &str, size: u64) -> hyper::http::response::Builder {
    blob_validators(base_builder().status(200), sha)
        .header("content-type", "application/octet-stream")
        .header("content-security-policy", BLOB_CONTENT_SECURITY_POLICY)
        .header("content-length", size)
}

/// The `304` for a conditional request whose blob is still served.
fn blob_not_modified(sha: &str) -> Response<HttpBody> {
    blob_validators(base_builder().status(304), sha)
        .body(empty_body())
        .unwrap()
}

/// Does an `If-None-Match` header value match the blob named `sha`?
///
/// The value is `*` or a comma-separated list of entity tags. The
/// comparison is the weak one RFC 9110 prescribes for this header, so a
/// tag marked weak (`W/"..."`) matches as well. The only tag this node
/// ever gives a blob is its sha256 in quotes.
fn etag_matches(header: &str, sha: &str) -> bool {
    header.split(',').map(str::trim).any(|candidate| {
        if candidate == "*" {
            return true;
        }
        let tag = candidate.strip_prefix("W/").unwrap_or(candidate);
        tag.strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .is_some_and(|opaque| opaque == sha)
    })
}

/// The request's `If-None-Match` value. A list may be split over several
/// header lines, which mean the same as one line joined by commas.
fn if_none_match(req: &Request<Incoming>) -> Option<String> {
    let values: Vec<&str> = req
        .headers()
        .get_all("if-none-match")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// How a `GET` or `HEAD` of a blob is answered.
#[derive(Debug, PartialEq, Eq)]
enum BlobRead {
    /// `451`: the hash is on the denylist.
    Denylisted,
    /// `404`: this node does not hold the bytes.
    Missing,
    /// `304`: the caller's copy is the blob this node would serve.
    NotModified,
    /// `200`, with the size of the stored file.
    Serve { size: u64 },
}

/// Decide the answer from the three facts, in the one order that is safe:
/// denylist, then existence, then the conditional request.
///
/// The order is the point. A `304` tells a cache to go on serving its
/// copy, so it must never be given for a blob that has been taken down or
/// removed: a cache that revalidates such a blob has to get the `451` or
/// the `404`. Keeping the decision in one function, apart from the code
/// that gathers the facts and builds the responses, is what stops a later
/// edit from moving the conditional answer ahead of the other two.
fn decide_blob_read(
    denylisted: bool,
    stored_size: Option<u64>,
    if_none_match: Option<&str>,
    sha: &str,
) -> BlobRead {
    if denylisted {
        return BlobRead::Denylisted;
    }
    let Some(size) = stored_size else {
        return BlobRead::Missing;
    };
    if if_none_match.is_some_and(|header| etag_matches(header, sha)) {
        return BlobRead::NotModified;
    }
    BlobRead::Serve { size }
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
                // The transport's own error text stays in the log.
                tracing::debug!("blob upload body could not be read: {e}");
                return error_response(&BlobError::BadRequest(BODY_ERROR_REASON.into()));
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
///
/// `if_none_match` is the request's `If-None-Match` value, if it sent one.
pub(crate) async fn handle_blob_get(
    private: &Arc<PrivateService>,
    sha: String,
    is_head: bool,
    if_none_match: Option<&str>,
) -> Response<HttpBody> {
    // Gather the facts, then let `decide_blob_read` order them.
    // A denylisted hash is not looked up on disk at all.
    let denylisted = private.is_denylisted(&sha);
    let path = if denylisted {
        None
    } else {
        private.blob_path(&sha)
    };
    let stored_size = match &path {
        Some(path) => tokio::fs::metadata(path).await.ok().map(|meta| meta.len()),
        None => None,
    };
    let (path, size) = match decide_blob_read(denylisted, stored_size, if_none_match, &sha) {
        BlobRead::Denylisted => return error_response(&BlobError::Denylisted),
        BlobRead::Missing => return not_found(),
        BlobRead::NotModified => return blob_not_modified(&sha),
        BlobRead::Serve { size } => match path {
            Some(path) => (path, size),
            // A size is only ever read from a path that was found.
            None => return not_found(),
        },
    };

    let builder = blob_ok_builder(&sha, size);

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

/// `GET /list/<pubkey-hex-or-npub>` — the blob descriptors of that pubkey's
/// own aliases, served to that pubkey only: the request must carry a
/// kind-24242 `list` authorization it signed.
///
/// The inventory (hashes, sizes, count) is metadata the encryption does not
/// cover, and an open route was also a way to ask whether a pubkey is a
/// tenant here. Authorization is checked before anything is looked up, and
/// every refusal is the same 401, whether the pubkey has blobs, has none, or
/// has never been seen.
pub(crate) async fn handle_blob_list(
    private: &Arc<PrivateService>,
    req: &Request<Incoming>,
    tenant: &str,
) -> Response<HttpBody> {
    let Ok(pubkey) = PublicKey::parse(tenant) else {
        return error_response(&BlobError::BadRequest(
            "list target must be a pubkey (hex or npub)".into(),
        ));
    };
    if let Err(e) = authorize_list(
        header_str(req, "authorization"),
        &pubkey.to_hex(),
        &private.cfg.domain,
    ) {
        return error_response(&e);
    }
    let descriptors = private.blob_list(&pubkey).await;
    match serde_json::to_string(&descriptors) {
        // Per-key content: keep it out of shared caches.
        Ok(json) => base_builder()
            .status(200)
            .header("content-type", "application/json")
            .header("cache-control", NO_STORE)
            .body(full_body(json))
            .unwrap(),
        Err(e) => error_response(&BlobError::Internal(format!("serialize failed: {e}"))),
    }
}

/// `PUT|HEAD /upload` requests with any other method fall through to the
/// generic 404, so `matches_upload_route` only claims what we serve.
pub(crate) fn matches_upload_route(path: &str, method: &Method) -> bool {
    path == "/upload" && (*method == Method::PUT || *method == Method::HEAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DETAIL: &str = "mdb_put: MDB_MAP_FULL at /var/lib/node/meta";

    fn header<'a>(response: &'a Response<HttpBody>, name: &str) -> Option<&'a str> {
        response.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// One error of every kind the routes can answer with.
    fn every_error() -> Vec<BlobError> {
        vec![
            BlobError::BadRequest("bad".into()),
            BlobError::Unauthorized("who".into()),
            BlobError::Forbidden("no".into()),
            BlobError::LengthRequired,
            BlobError::TooLarge,
            BlobError::Denylisted,
            BlobError::QuotaExceeded,
            BlobError::RateLimited {
                retry_after_secs: 7,
            },
            BlobError::Internal(DETAIL.into()),
        ]
    }

    #[test]
    fn error_response_challenges_only_on_401() {
        let mut statuses = Vec::new();
        for err in every_error() {
            let response = error_response(&err);
            let status = response.status().as_u16();
            statuses.push(status);
            if status == 401 {
                assert_eq!(header(&response, "www-authenticate"), Some("Nostr"));
            } else {
                assert_eq!(
                    header(&response, "www-authenticate"),
                    None,
                    "a {status} must not carry a challenge"
                );
            }
        }
        assert_eq!(statuses, [400, 401, 403, 411, 413, 451, 507, 429, 500]);
        assert_eq!(header(&not_found(), "www-authenticate"), None);
        assert_eq!(header(&blob_not_modified(SHA), "www-authenticate"), None);
    }

    #[test]
    fn internal_error_reason_is_generic() {
        let response = error_response(&BlobError::Internal(DETAIL.into()));
        assert_eq!(response.status().as_u16(), 500);
        assert_eq!(header(&response, "x-reason"), Some("internal error"));
        for (name, value) in response.headers() {
            let value = value.to_str().unwrap_or_default();
            assert!(
                !value.contains("MDB") && !value.contains("/var/lib"),
                "{name} leaks the detail: {value}"
            );
        }
        // The detail is still there for code inside the node.
        assert_eq!(BlobError::Internal(DETAIL.into()).reason(), DETAIL);
        // Every other error tells the client what it tells the node.
        for err in every_error() {
            if !matches!(err, BlobError::Internal(_)) {
                assert_eq!(err.public_reason(), err.reason());
            }
        }
    }

    #[test]
    fn every_error_response_is_no_store_and_nosniff() {
        let mut responses: Vec<Response<HttpBody>> =
            every_error().iter().map(error_response).collect();
        responses.push(not_found());
        for response in &responses {
            let status = response.status();
            assert_eq!(
                header(response, "cache-control"),
                Some("no-store"),
                "{status}"
            );
            assert_eq!(
                header(response, "x-content-type-options"),
                Some("nosniff"),
                "{status}"
            );
        }
        assert_eq!(not_found().status().as_u16(), 404);
    }

    #[test]
    fn rate_limited_response_says_when_to_retry() {
        let response = error_response(&BlobError::RateLimited {
            retry_after_secs: 7,
        });
        assert_eq!(header(&response, "retry-after"), Some("7"));
        assert_eq!(
            header(&error_response(&BlobError::QuotaExceeded), "retry-after"),
            None
        );
    }

    #[test]
    fn reason_with_control_characters_still_makes_a_header() {
        let response = error_response(&BlobError::BadRequest("one\r\ntwo\u{7}three".into()));
        assert_eq!(header(&response, "x-reason"), Some("one  two three"));
    }

    #[test]
    fn browser_clients_can_read_the_reason_and_the_retry_hint() {
        let response = not_found();
        let exposed = header(&response, "access-control-expose-headers").unwrap_or_default();
        for name in ["WWW-Authenticate", "X-Reason", "Retry-After"] {
            assert!(
                exposed.split(", ").any(|listed| listed == name),
                "{name} missing from {exposed}"
            );
        }
    }

    #[test]
    fn etag_matches_handles_quotes_weak_lists_and_star() {
        let quoted = format!("\"{SHA}\"");
        assert!(etag_matches(&quoted, SHA));
        assert!(etag_matches(&format!("W/{quoted}"), SHA));
        assert!(etag_matches("*", SHA));
        assert!(etag_matches(&format!("\"other\", {quoted}"), SHA));
        assert!(etag_matches(
            &format!("\"other\" ,W/{quoted} , \"more\""),
            SHA
        ));
        assert!(etag_matches(&format!("  {quoted}  "), SHA));

        assert!(!etag_matches("", SHA));
        assert!(!etag_matches("\"other\"", SHA));
        assert!(!etag_matches("\"other\", W/\"more\"", SHA));
        // Not an entity tag without its quotes, and not ours in another case.
        assert!(!etag_matches(SHA, SHA));
        assert!(!etag_matches(&format!("\"{}\"", SHA.to_uppercase()), SHA));
        assert!(!etag_matches(&format!("\"{SHA}"), SHA));
        assert!(!etag_matches(&format!("w/{quoted}"), SHA));
    }

    /// The security property of the conditional request: a blob that was
    /// taken down or is gone is never confirmed to a cache, whatever the
    /// request says it already has.
    #[test]
    fn conditional_answer_comes_after_denylist_and_existence() {
        let matching = format!("\"{SHA}\"");
        let conditionals = [None, Some(matching.as_str()), Some("*"), Some("\"other\"")];

        for conditional in conditionals {
            for stored in [None, Some(5)] {
                assert_eq!(
                    decide_blob_read(true, stored, conditional, SHA),
                    BlobRead::Denylisted,
                    "denylisted, stored {stored:?}, If-None-Match {conditional:?}"
                );
            }
            assert_eq!(
                decide_blob_read(false, None, conditional, SHA),
                BlobRead::Missing,
                "absent, If-None-Match {conditional:?}"
            );
        }

        assert_eq!(
            decide_blob_read(false, Some(5), Some(matching.as_str()), SHA),
            BlobRead::NotModified
        );
        assert_eq!(
            decide_blob_read(false, Some(5), Some("*"), SHA),
            BlobRead::NotModified
        );
        assert_eq!(
            decide_blob_read(false, Some(5), Some("\"other\""), SHA),
            BlobRead::Serve { size: 5 }
        );
        assert_eq!(
            decide_blob_read(false, Some(5), None, SHA),
            BlobRead::Serve { size: 5 }
        );
    }

    #[test]
    fn served_blob_is_inert_and_must_be_revalidated() {
        let response = blob_ok_builder(SHA, 5).body(empty_body()).unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let etag = format!("\"{SHA}\"");
        assert_eq!(header(&response, "cache-control"), Some("no-cache"));
        assert_eq!(header(&response, "etag"), Some(etag.as_str()));
        assert_eq!(header(&response, "x-content-type-options"), Some("nosniff"));
        assert_eq!(
            header(&response, "content-security-policy"),
            Some("default-src 'none'; sandbox")
        );
        assert_eq!(
            header(&response, "content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(header(&response, "content-length"), Some("5"));
    }

    #[test]
    fn not_modified_repeats_the_validators_of_the_200() {
        let ok = blob_ok_builder(SHA, 5).body(empty_body()).unwrap();
        let not_modified = blob_not_modified(SHA);
        assert_eq!(not_modified.status().as_u16(), 304);
        for name in ["etag", "cache-control", "x-content-type-options"] {
            assert!(header(&ok, name).is_some(), "{name} missing from the 200");
            assert_eq!(header(&not_modified, name), header(&ok, name), "{name}");
        }
        // A length here would have to be the blob's, and nothing reads it.
        assert_eq!(header(&not_modified, "content-length"), None);
    }
}
