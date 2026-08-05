//! Concurrency-Limiting NEG Proxy for Sync Tests
//!
//! A transparent WebSocket proxy that sits between a syncing relay and its
//! bootstrap relay and enforces a strfry-style bound on concurrent NIP-77
//! negentropy rounds per connection. strfry counts negentropy views against
//! `maxSubsPerConnection` and answers excess `NEG-OPEN` frames with
//! `NOTICE ERROR: too many concurrent NEG requests` — the production
//! behaviour observed from nos.lol (which advertises `max_subscriptions: 20`)
//! during gitnostr.com startup bursts.
//!
//! The proxy additionally:
//! - records the peak number of concurrently open NEG rounds, so tests can
//!   assert the syncing relay's concurrency bound end to end;
//! - delays backend responses to in-flight NEG rounds by a fixed interval,
//!   so rounds opened together provably overlap instead of racing the
//!   loopback round-trip.
//!
//! # Usage
//!
//! ```ignore
//! let source = TestRelay::start().await;
//! let proxy = NegLimitingProxy::start(source.url(), 4).await;
//! let syncing = TestRelay::start_with_sync(Some(proxy.url().into())).await;
//! // ... assert proxy.rejected_count() == 0 && proxy.peak_concurrent() <= 4 ...
//! ```

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

/// Fixed delay applied to backend responses for in-flight NEG rounds.
///
/// Long enough that a burst of NEG-OPEN frames sent together is observed
/// before any round can complete; short enough to keep tests fast.
const NEG_RESPONSE_DELAY: Duration = Duration::from_millis(100);

/// WebSocket proxy bounding concurrent NEG rounds like a strfry relay.
pub struct NegLimitingProxy {
    url: String,
    peak: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
    opened: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl NegLimitingProxy {
    /// Start a proxy on a random loopback port, forwarding to `backend_url`
    /// and rejecting NEG-OPEN frames that would exceed `limit` concurrent
    /// rounds on a connection.
    pub async fn start(backend_url: &str, limit: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("NegLimitingProxy failed to bind");
        let port = listener
            .local_addr()
            .expect("NegLimitingProxy local_addr")
            .port();

        let peak = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));
        let opened = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let backend_url = backend_url.to_string();
        let accept_peak = peak.clone();
        let accept_rejected = rejected.clone();
        let accept_opened = opened.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let backend_url = backend_url.clone();
                        let peak = accept_peak.clone();
                        let rejected = accept_rejected.clone();
                        let opened = accept_opened.clone();
                        tokio::spawn(async move {
                            if let Err(error) = proxy_connection(
                                stream,
                                &backend_url,
                                limit,
                                peak,
                                rejected,
                                opened,
                            )
                            .await
                            {
                                // Disconnects mid-test are expected; log only.
                                eprintln!("NegLimitingProxy connection ended: {error}");
                            }
                        });
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });

        Self {
            url: format!("ws://127.0.0.1:{port}"),
            peak,
            rejected,
            opened,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    /// The ws:// URL the syncing relay should use as its bootstrap relay.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Highest number of NEG rounds observed open at once on any connection.
    pub fn peak_concurrent(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Number of NEG-OPEN frames rejected for exceeding the limit.
    pub fn rejected_count(&self) -> usize {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Total NEG-OPEN frames accepted and forwarded to the backend.
    pub fn opened_count(&self) -> usize {
        self.opened.load(Ordering::Relaxed)
    }

    /// Stop the proxy.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for NegLimitingProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Forward one client connection to the backend, bounding concurrent NEG
/// rounds and recording the observed peak.
///
/// A single loop owns both writers so rejections can be answered directly
/// to the client without forwarding to the backend.
async fn proxy_connection(
    client_stream: tokio::net::TcpStream,
    backend_url: &str,
    limit: usize,
    peak: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
    opened: Arc<AtomicUsize>,
) -> Result<(), String> {
    let client_ws = tokio_tungstenite::accept_async(client_stream)
        .await
        .map_err(|e| format!("client handshake failed: {e}"))?;
    let (backend_ws, _) = tokio_tungstenite::connect_async(backend_url)
        .await
        .map_err(|e| format!("backend connect failed: {e}"))?;

    let (mut client_tx, mut client_rx) = client_ws.split();
    let (mut backend_tx, mut backend_rx) = backend_ws.split();

    // NEG subscription ids currently open on this connection.
    let mut active: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            message = client_rx.next() => {
                let Some(message) = message else { break };
                let message = message.map_err(|e| format!("client read: {e}"))?;
                if let Message::Text(text) = &message {
                    match parse_neg_frame(text.as_str()) {
                        Some(NegFrame::Open(subid)) => {
                            if active.len() >= limit {
                                rejected.fetch_add(1, Ordering::Relaxed);
                                client_tx
                                    .send(Message::text(
                                        r#"["NOTICE","ERROR: too many concurrent NEG requests"]"#
                                            .to_string(),
                                    ))
                                    .await
                                    .map_err(|e| format!("client write: {e}"))?;
                                client_tx
                                    .send(Message::text(format!(
                                        r#"["NEG-ERR","{subid}","blocked: too many concurrent NEG requests"]"#
                                    )))
                                    .await
                                    .map_err(|e| format!("client write: {e}"))?;
                                continue;
                            }
                            active.insert(subid);
                            opened.fetch_add(1, Ordering::Relaxed);
                            peak.fetch_max(active.len(), Ordering::Relaxed);
                        }
                        Some(NegFrame::Close(subid)) => {
                            active.remove(&subid);
                        }
                        Some(NegFrame::Other) | None => {}
                    }
                }
                backend_tx
                    .send(message)
                    .await
                    .map_err(|e| format!("backend write: {e}"))?;
            }
            message = backend_rx.next() => {
                let Some(message) = message else { break };
                let message = message.map_err(|e| format!("backend read: {e}"))?;
                if let Message::Text(text) = &message {
                    match parse_neg_frame(text.as_str()) {
                        Some(NegFrame::Other) => {
                            // Hold NEG responses briefly so simultaneously
                            // opened rounds provably overlap at the proxy.
                            tokio::time::sleep(NEG_RESPONSE_DELAY).await;
                        }
                        Some(NegFrame::Open(subid)) | Some(NegFrame::Close(subid)) => {
                            // Backend-initiated NEG-ERR ends the round.
                            active.remove(&subid);
                        }
                        None => {}
                    }
                }
                client_tx
                    .send(message)
                    .await
                    .map_err(|e| format!("client write: {e}"))?;
            }
        }
    }

    Ok(())
}

/// Parsed shape of a NEG-* frame.
enum NegFrame {
    /// `["NEG-OPEN", <subid>, ...]` from the client.
    Open(String),
    /// `["NEG-CLOSE", <subid>]` from the client, or `["NEG-ERR", <subid>, ..]`
    /// from the backend (both end the round).
    Close(String),
    /// `["NEG-MSG", ...]` — an in-flight reconciliation frame.
    Other,
}

/// Classify a text frame if it is negentropy-related, else `None`.
fn parse_neg_frame(text: &str) -> Option<NegFrame> {
    if !text.starts_with("[\"NEG-") {
        return None;
    }
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let array = value.as_array()?;
    let kind = array.first()?.as_str()?;
    let subid = || {
        array
            .get(1)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    match kind {
        "NEG-OPEN" => Some(NegFrame::Open(subid()?)),
        "NEG-CLOSE" | "NEG-ERR" => Some(NegFrame::Close(subid()?)),
        "NEG-MSG" => Some(NegFrame::Other),
        _ => None,
    }
}
