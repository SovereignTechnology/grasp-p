//! Concurrency-Limiting REQ Proxy for Sync Tests
//!
//! A transparent WebSocket proxy that sits between a syncing relay and its
//! bootstrap relay and enforces a strfry-style bound on concurrent transient
//! REQ subscriptions per connection. strfry counts REQ subscriptions against
//! `maxSubsPerConnection` and answers excess REQ frames with
//! `NOTICE ERROR: too many concurrent REQs` — the production behaviour
//! observed from nos.lol (which advertises `max_subscriptions: 20`) during
//! gitnostr.com startup bursts.
//!
//! The proxy models *awaiting-EOSE* occupancy — the quantity the client-side
//! transient-REQ bound controls: a REQ joins the active set when it is
//! opened and leaves it when the client sends CLOSE or the backend answers
//! EOSE/CLOSED, whichever comes first. Live subscriptions (every filter
//! carrying `limit: 0`) are exempt; they are persistent by design and
//! budgeted separately.
//!
//! The proxy additionally:
//! - records the peak number of concurrently open transient REQs, so tests
//!   can assert the syncing relay's concurrency bound end to end;
//! - delays backend EOSE frames for counted REQs by a fixed interval, so
//!   REQs opened together provably overlap instead of racing the loopback
//!   round-trip;
//! - rejects NEG-OPEN frames as unsupported, so a syncing relay with
//!   negentropy enabled still exercises the REQ+EOSE path.
//!
//! # Usage
//!
//! ```ignore
//! let source = TestRelay::start().await;
//! let proxy = ReqLimitingProxy::start(source.url(), 5).await;
//! let syncing = TestRelay::start_with_sync_no_negentropy(Some(proxy.url().into())).await;
//! // ... assert proxy.rejected_count() == 0 && proxy.peak_concurrent() <= 5 ...
//! ```

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

/// Fixed delay applied to backend EOSE frames for counted REQs.
///
/// Long enough that a burst of REQ frames sent together is observed before
/// any subscription can complete; short enough to keep tests fast.
const REQ_RESPONSE_DELAY: Duration = Duration::from_millis(150);

/// WebSocket proxy bounding concurrent transient REQs like a strfry relay.
pub struct ReqLimitingProxy {
    url: String,
    peak: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
    opened: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl ReqLimitingProxy {
    /// Start a proxy on a random loopback port, forwarding to `backend_url`
    /// and rejecting transient REQ frames that would exceed `limit`
    /// concurrent subscriptions on a connection.
    pub async fn start(backend_url: &str, limit: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ReqLimitingProxy failed to bind");
        let port = listener
            .local_addr()
            .expect("ReqLimitingProxy local_addr")
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
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let backend_url = backend_url.clone();
                        let peak = accept_peak.clone();
                        let rejected = accept_rejected.clone();
                        let opened = accept_opened.clone();
                        connections.spawn(async move {
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
                                eprintln!("ReqLimitingProxy connection ended: {error}");
                            }
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.expect("connection task").expect("fixture connection panicked");
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
            connections.shutdown().await;
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

    /// Highest number of transient REQs observed open at once on any
    /// connection.
    pub fn peak_concurrent(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Number of REQ frames rejected for exceeding the limit.
    pub fn rejected_count(&self) -> usize {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Total transient REQ frames accepted and forwarded to the backend.
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

impl Drop for ReqLimitingProxy {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Forward one client connection to the backend, bounding concurrent
/// transient REQs and recording the observed peak.
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

    // Transient REQ subscription ids currently open on this connection.
    let mut active: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            message = client_rx.next() => {
                let Some(message) = message else { break };
                let message = message.map_err(|e| format!("client read: {e}"))?;
                if let Message::Text(text) = &message {
                    match parse_client_frame(text.as_str()) {
                        Some(ClientFrame::Req(subid)) => {
                            match admit_req(&mut active, subid.clone(), limit) {
                                ReqAdmission::Replacement => {
                                    // NIP-01 replaces an existing subscription with
                                    // the same id; relay-side occupancy is unchanged.
                                }
                                ReqAdmission::Rejected => {
                                    eprintln!(
                                        "ReqLimitingProxy rejecting REQ {subid}; active={active:?}; frame={text}"
                                    );
                                    rejected.fetch_add(1, Ordering::Relaxed);
                                    client_tx
                                        .send(Message::text(
                                            r#"["NOTICE","ERROR: too many concurrent REQs"]"#
                                                .to_string(),
                                        ))
                                        .await
                                        .map_err(|e| format!("client write: {e}"))?;
                                    client_tx
                                        .send(Message::text(format!(
                                            r#"["CLOSED","{subid}","blocked: too many concurrent REQs"]"#
                                        )))
                                        .await
                                        .map_err(|e| format!("client write: {e}"))?;
                                    continue;
                                }
                                ReqAdmission::Opened => {
                                    opened.fetch_add(1, Ordering::Relaxed);
                                    peak.fetch_max(active.len(), Ordering::Relaxed);
                                }
                            }
                        }
                        Some(ClientFrame::LiveReq) => {
                            // Persistent live subscription (all filters
                            // limit:0) - budgeted separately, not counted.
                        }
                        Some(ClientFrame::Close(subid)) => {
                            active.remove(&subid);
                        }
                        Some(ClientFrame::NegOpen(subid)) => {
                            // This proxy models a relay without NIP-77 so
                            // historic sync exercises the REQ+EOSE path.
                            client_tx
                                .send(Message::text(format!(
                                    r#"["NEG-ERR","{subid}","blocked: negentropy not supported"]"#
                                )))
                                .await
                                .map_err(|e| format!("client write: {e}"))?;
                            continue;
                        }
                        None => {}
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
                    if let Some((subid, is_eose)) = parse_backend_subscription_end(text.as_str()) {
                        if is_eose && active.contains(&subid) {
                            // Hold EOSE frames briefly so simultaneously opened
                            // REQs provably overlap at the proxy. EOSE ends the
                            // stored-event phase but does not close the relay-side
                            // subscription; wait for client CLOSE or backend CLOSED.
                            tokio::time::sleep(REQ_RESPONSE_DELAY).await;
                        } else if !is_eose {
                            apply_backend_end(&mut active, &subid, is_eose);
                        }
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

#[derive(Debug, PartialEq, Eq)]
enum ReqAdmission {
    Replacement,
    Opened,
    Rejected,
}

fn admit_req(active: &mut HashSet<String>, subid: String, limit: usize) -> ReqAdmission {
    if active.contains(&subid) {
        ReqAdmission::Replacement
    } else if active.len() >= limit {
        ReqAdmission::Rejected
    } else {
        active.insert(subid);
        ReqAdmission::Opened
    }
}

fn apply_backend_end(active: &mut HashSet<String>, subid: &str, is_eose: bool) -> bool {
    !is_eose && active.remove(subid)
}

/// Parsed shape of a client-to-relay frame the proxy cares about.
enum ClientFrame {
    /// `["REQ", <subid>, <filters...>]` - transient, counted.
    Req(String),
    /// `["REQ", ...]` where every filter carries `limit: 0` - a persistent
    /// live subscription, exempt from the transient bound.
    LiveReq,
    /// `["CLOSE", <subid>]` - ends the subscription.
    Close(String),
    /// `["NEG-OPEN", <subid>, ...]` - rejected as unsupported.
    NegOpen(String),
}

/// Classify a client text frame if the proxy tracks it, else `None`.
fn parse_client_frame(text: &str) -> Option<ClientFrame> {
    if !(text.starts_with("[\"REQ")
        || text.starts_with("[\"CLOSE")
        || text.starts_with("[\"NEG-OPEN"))
    {
        return None;
    }
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let array = value.as_array()?;
    let kind = array.first()?.as_str()?;
    let subid = array.get(1)?.as_str()?.to_string();
    match kind {
        "REQ" => {
            let filters = &array[2..];
            let live = !filters.is_empty()
                && filters
                    .iter()
                    .all(|f| f.get("limit").and_then(|l| l.as_u64()) == Some(0));
            if live {
                Some(ClientFrame::LiveReq)
            } else {
                Some(ClientFrame::Req(subid))
            }
        }
        "CLOSE" => Some(ClientFrame::Close(subid)),
        "NEG-OPEN" => Some(ClientFrame::NegOpen(subid)),
        _ => None,
    }
}

/// Extract the subscription id from a definitive backend EOSE/CLOSED frame.
fn parse_backend_subscription_end(text: &str) -> Option<(String, bool)> {
    if !(text.starts_with("[\"EOSE") || text.starts_with("[\"CLOSED")) {
        return None;
    }
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let array = value.as_array()?;
    let kind = array.first()?.as_str()?;
    Some((array.get(1)?.as_str()?.to_string(), kind == "EOSE"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{admit_req, apply_backend_end, parse_backend_subscription_end, ReqAdmission};

    #[test]
    fn same_id_req_replaces_without_consuming_another_slot() {
        let mut active = (0..5).map(|id| id.to_string()).collect::<HashSet<_>>();

        assert_eq!(
            admit_req(&mut active, "4".to_string(), 5),
            ReqAdmission::Replacement
        );
        assert_eq!(active.len(), 5);
    }

    #[test]
    fn distinct_req_is_rejected_at_the_limit() {
        let mut active = (0..5).map(|id| id.to_string()).collect::<HashSet<_>>();

        assert_eq!(
            admit_req(&mut active, "5".to_string(), 5),
            ReqAdmission::Rejected
        );
        assert_eq!(active.len(), 5);
    }

    #[test]
    fn eose_retains_occupancy_but_closed_releases_it() {
        let mut active = HashSet::from(["historic-id".to_string()]);

        assert!(!apply_backend_end(&mut active, "historic-id", true));
        assert!(active.contains("historic-id"));
        assert!(apply_backend_end(&mut active, "historic-id", false));
        assert!(active.is_empty());
    }

    #[test]
    fn backend_closed_definitively_releases_proxy_occupancy() {
        assert_eq!(
            parse_backend_subscription_end(
                r#"["CLOSED","historic-id","rate-limited: too many queries"]"#
            ),
            Some(("historic-id".to_string(), false))
        );
        assert_eq!(
            parse_backend_subscription_end(r#"["EOSE","historic-id"]"#),
            Some(("historic-id".to_string(), true))
        );
    }
}
