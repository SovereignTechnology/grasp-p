//! Counting Git Smart-HTTP Proxy for Purgatory Sync Tests
//!
//! A transparent HTTP proxy that sits between a syncing relay's outbound
//! purgatory git fetches and the relay serving the repository. It records
//! every `POST /git-upload-pack` exchange so tests can assert *how* the
//! syncing relay asks for missing git data, not just whether the data
//! eventually arrives:
//!
//! - the `want <oid>` lines contained in each request body;
//! - whether the response carried an upload-pack `not our ref` error
//!   (the signature a git server produces when a want names an object it
//!   does not have);
//! - the order of exchanges, so tests can assert that available data is
//!   fetched before (and independently of) requests destined to fail.
//!
//! `GET .../info/refs?service=git-upload-pack` requests (ref
//! advertisements, used by both `git fetch` and `git ls-remote`) are
//! counted but not recorded in detail.
//!
//! Bodies are buffered, not streamed: test repositories are tiny and the
//! proxy needs complete request/response bytes to classify the exchange.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

/// One observed `POST /git-upload-pack` exchange.
#[derive(Debug, Clone)]
pub struct UploadPackExchange {
    /// Object ids named in `want` lines of the request body, in order.
    pub wants: Vec<String>,
    /// The response contained an upload-pack "not our ref" error.
    pub not_our_ref: bool,
    /// The exchange succeeded: HTTP 200 and no "not our ref" in the body.
    pub ok: bool,
    /// The request body carried a `Content-Encoding` the proxy cannot
    /// inspect (git only compresses very large bodies; tests assert this
    /// never happens so `wants` is trustworthy).
    pub opaque_body: bool,
}

/// Transparent counting proxy for a git smart-HTTP endpoint.
pub struct UploadPackCountingProxy {
    url: String,
    exchanges: Arc<Mutex<Vec<UploadPackExchange>>>,
    info_refs: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl UploadPackCountingProxy {
    /// Start the proxy on a random loopback port, forwarding every request
    /// to `backend_url` (e.g. `http://127.0.0.1:<relay-port>`).
    pub async fn start(backend_url: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("UploadPackCountingProxy failed to bind");
        let port = listener
            .local_addr()
            .expect("UploadPackCountingProxy local_addr")
            .port();

        let exchanges = Arc::new(Mutex::new(Vec::new()));
        let info_refs = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let backend_url = backend_url.trim_end_matches('/').to_string();
        let accept_exchanges = exchanges.clone();
        let accept_info_refs = info_refs.clone();

        let handle = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            // One shared upstream client; keep it plain so request and
            // response bodies pass through byte-for-byte.
            let client = reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("build reqwest client");

            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let backend_url = backend_url.clone();
                        let client = client.clone();
                        let exchanges = accept_exchanges.clone();
                        let info_refs = accept_info_refs.clone();
                        connections.spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let backend_url = backend_url.clone();
                                let client = client.clone();
                                let exchanges = exchanges.clone();
                                let info_refs = info_refs.clone();
                                async move {
                                    forward(req, &backend_url, &client, &exchanges, &info_refs)
                                        .await
                                }
                            });
                            if let Err(error) = http1::Builder::new()
                                .serve_connection(io, service)
                                .await
                            {
                                // Client disconnects mid-test are expected.
                                if !error.to_string().contains("connection") {
                                    eprintln!(
                                        "UploadPackCountingProxy connection error: {error}"
                                    );
                                }
                            }
                        });
                    }
                    _ = &mut shutdown_rx => break,
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.shutdown().await;
        });

        Self {
            url: format!("http://127.0.0.1:{port}"),
            exchanges,
            info_refs,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    /// Base URL of the proxy (`http://127.0.0.1:<port>`); append the
    /// `/{npub}/{identifier}.git` path when building clone URLs.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Snapshot of all recorded `POST /git-upload-pack` exchanges, oldest
    /// first.
    pub fn exchanges(&self) -> Vec<UploadPackExchange> {
        self.exchanges.lock().unwrap().clone()
    }

    /// Number of ref-advertisement requests
    /// (`GET .../info/refs?service=git-upload-pack`) observed.
    pub fn info_refs_count(&self) -> usize {
        self.info_refs.load(Ordering::Relaxed)
    }

    /// Stop the proxy.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            tokio::time::timeout(std::time::Duration::from_secs(5), handle)
                .await
                .expect("upload-pack proxy tasks should stop")
                .expect("upload-pack proxy server task should not panic");
        }
    }
}

impl Drop for UploadPackCountingProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Forward one request to the backend, recording upload-pack exchanges.
async fn forward(
    req: Request<hyper::body::Incoming>,
    backend_url: &str,
    client: &reqwest::Client,
    exchanges: &Mutex<Vec<UploadPackExchange>>,
    info_refs: &AtomicUsize,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let headers = req.headers().clone();
    let body_bytes = req.collect().await?.to_bytes();

    let is_upload_pack_post =
        method == hyper::Method::POST && path_and_query.ends_with("/git-upload-pack");
    if method == hyper::Method::GET
        && path_and_query.contains("/info/refs")
        && path_and_query.contains("service=git-upload-pack")
    {
        info_refs.fetch_add(1, Ordering::Relaxed);
    }

    let opaque_body = headers.contains_key(hyper::header::CONTENT_ENCODING);
    let wants = if is_upload_pack_post && !opaque_body {
        parse_wants(&body_bytes)
    } else {
        Vec::new()
    };

    // Forward with original headers; the upstream client recomputes
    // Host and Content-Length itself.
    let mut upstream = client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).expect("valid method"),
            format!("{backend_url}{path_and_query}"),
        )
        .body(body_bytes.to_vec());
    for (name, value) in headers.iter() {
        let name = name.as_str();
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        upstream = upstream.header(name, value.as_bytes());
    }

    let upstream_response = match upstream.send().await {
        Ok(response) => response,
        Err(error) => {
            eprintln!("UploadPackCountingProxy upstream error: {error}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("upstream error")))
                .unwrap());
        }
    };

    let status = upstream_response.status();
    let response_headers = upstream_response.headers().clone();
    let response_bytes = upstream_response.bytes().await.unwrap_or_default();

    if is_upload_pack_post {
        let not_our_ref = contains(&response_bytes, b"not our ref");
        exchanges.lock().unwrap().push(UploadPackExchange {
            wants,
            not_our_ref,
            ok: status.is_success() && !not_our_ref,
            opaque_body,
        });
    }

    let mut builder = Response::builder()
        .status(hyper::StatusCode::from_u16(status.as_u16()).expect("valid status"));
    for (name, value) in response_headers.iter() {
        let name = name.as_str();
        // hyper recomputes framing headers for the buffered body.
        if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        builder = builder.header(name, value.as_bytes());
    }
    Ok(builder.body(Full::new(response_bytes)).unwrap())
}

/// Extract the object ids named in `want` pkt-lines of a smart-HTTP
/// request body (works for protocol v0 and v2: both carry plain-text
/// `want <40-hex-oid>` sequences inside pkt-line framing).
fn parse_wants(body: &[u8]) -> Vec<String> {
    const NEEDLE: &[u8] = b"want ";
    const OID_LEN: usize = 40;
    let mut wants = Vec::new();
    let mut index = 0;
    while index + NEEDLE.len() + OID_LEN <= body.len() {
        if &body[index..index + NEEDLE.len()] == NEEDLE {
            let oid = &body[index + NEEDLE.len()..index + NEEDLE.len() + OID_LEN];
            if oid.iter().all(u8::is_ascii_hexdigit) {
                wants.push(String::from_utf8_lossy(oid).to_string());
                index += NEEDLE.len() + OID_LEN;
                continue;
            }
        }
        index += 1;
    }
    wants
}

/// Byte-level substring search (`response_bytes` is protocol data, not
/// guaranteed to be valid UTF-8).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_closes_active_forwarded_requests() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = UploadPackCountingProxy::start(&format!(
                "http://{}",
                backend.local_addr().unwrap()
            ))
            .await;
            let address = proxy.url().strip_prefix("http://").unwrap();
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client
                .write_all(
                    b"GET /info/refs?service=git-upload-pack HTTP/1.1\r\nHost: localhost\r\n\r\n",
                )
                .await
                .unwrap();
            let (mut upstream, _) = backend.accept().await.unwrap();
            let mut request = [0; 256];
            assert!(upstream.read(&mut request).await.unwrap() > 0);
            // The request has reached the backend, which deliberately retains
            // the connection without replying while the proxy is stopped.
            proxy.stop().await;
            let mut byte = [0];
            match client.read(&mut byte).await {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => panic!("proxy retained an active request after stop: {result:?}"),
            }
        })
        .await
        .expect("proxy stop must close active requests");
    }

    #[test]
    fn parse_wants_extracts_oids_from_pkt_lines() {
        let body = b"0032want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
            0054want bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb multi_ack side-band-64k\n\
            0032have cccccccccccccccccccccccccccccccccccccccc\n0000";
        let wants = parse_wants(body);
        assert_eq!(
            wants,
            vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            ]
        );
    }

    #[test]
    fn parse_wants_ignores_short_or_non_hex_suffixes() {
        assert!(parse_wants(b"0009want zz\n").is_empty());
        assert!(parse_wants(b"want deadbeef").is_empty());
    }

    #[test]
    fn contains_finds_error_text_in_binary_bodies() {
        let mut body = vec![0u8, 1, 2];
        body.extend_from_slice(b"ERR upload-pack: not our ref beef");
        assert!(contains(&body, b"not our ref"));
        assert!(!contains(&body, b"unrelated"));
    }
}
