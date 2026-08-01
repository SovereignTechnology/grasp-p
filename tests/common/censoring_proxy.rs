//! Censoring WebSocket Proxy for Sync Tests
//!
//! A transparent WebSocket proxy that sits between a syncing relay and its
//! bootstrap relay, forwarding every frame except `["EVENT", ...]` messages
//! whose event ID is currently withheld.
//!
//! This simulates a relay that reports events during NIP-77 negentropy
//! reconciliation (NEG-* frames pass through untouched, so the backend's
//! full event set is visible to reconciliation) but fails to deliver some
//! of those events on exact-ID REQ fetches — the production behaviour
//! behind incomplete historic-sync batches.
//!
//! # Usage
//!
//! ```ignore
//! let source = TestRelay::start().await;
//! let proxy = CensoringProxy::start(source.url()).await;
//! proxy.withhold(event.id);
//! let syncing = TestRelay::start_with_sync(Some(proxy.url().into())).await;
//! // ... syncing relay never receives `event` ...
//! proxy.release(event.id);
//! // ... the next fetch through the proxy can deliver it ...
//! ```

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use futures_util::{SinkExt, StreamExt};
use nostr_sdk::prelude::EventId;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

/// WebSocket proxy that withholds selected EVENT frames from its backend.
pub struct CensoringProxy {
    url: String,
    withheld: Arc<RwLock<HashSet<String>>>,
    dropped: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl CensoringProxy {
    /// Start a proxy on a random loopback port, forwarding to `backend_url`.
    pub async fn start(backend_url: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("CensoringProxy failed to bind");
        let port = listener
            .local_addr()
            .expect("CensoringProxy local_addr")
            .port();

        let withheld: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let backend_url = backend_url.to_string();
        let accept_withheld = withheld.clone();
        let accept_dropped = dropped.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let backend_url = backend_url.clone();
                        let withheld = accept_withheld.clone();
                        let dropped = accept_dropped.clone();
                        tokio::spawn(async move {
                            if let Err(error) =
                                proxy_connection(stream, &backend_url, withheld, dropped).await
                            {
                                // Disconnects mid-test are expected; log for debugging only.
                                eprintln!("CensoringProxy connection ended: {error}");
                            }
                        });
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });

        Self {
            url: format!("ws://127.0.0.1:{port}"),
            withheld,
            dropped,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    /// The ws:// URL the syncing relay should use as its bootstrap relay.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Start withholding EVENT frames carrying this event ID.
    pub fn withhold(&self, event_id: EventId) {
        self.withheld
            .write()
            .expect("withheld lock poisoned")
            .insert(event_id.to_hex());
    }

    /// Stop withholding this event ID. Frames sent by the backend after this
    /// call pass through; already-dropped frames are not replayed.
    pub fn release(&self, event_id: EventId) {
        self.withheld
            .write()
            .expect("withheld lock poisoned")
            .remove(&event_id.to_hex());
    }

    /// Number of EVENT frames dropped so far.
    pub fn dropped_count(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
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

impl Drop for CensoringProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Forward one client connection to the backend, censoring backend->client
/// EVENT frames for withheld IDs.
async fn proxy_connection(
    client_stream: tokio::net::TcpStream,
    backend_url: &str,
    withheld: Arc<RwLock<HashSet<String>>>,
    dropped: Arc<AtomicUsize>,
) -> Result<(), String> {
    let client_ws = tokio_tungstenite::accept_async(client_stream)
        .await
        .map_err(|e| format!("client handshake failed: {e}"))?;
    let (backend_ws, _) = tokio_tungstenite::connect_async(backend_url)
        .await
        .map_err(|e| format!("backend connect failed: {e}"))?;

    let (mut client_tx, mut client_rx) = client_ws.split();
    let (mut backend_tx, mut backend_rx) = backend_ws.split();

    // Client -> backend: forward untouched.
    let upstream = async {
        while let Some(message) = client_rx.next().await {
            let message = message.map_err(|e| format!("client read: {e}"))?;
            backend_tx
                .send(message)
                .await
                .map_err(|e| format!("backend write: {e}"))?;
        }
        Ok::<(), String>(())
    };

    // Backend -> client: drop withheld EVENT frames, forward everything else
    // (including NEG-MSG, EOSE, NOTICE, and control frames).
    let downstream = async {
        while let Some(message) = backend_rx.next().await {
            let message = message.map_err(|e| format!("backend read: {e}"))?;
            if let Message::Text(text) = &message {
                let ids = withheld.read().expect("withheld lock poisoned");
                if is_withheld_event_frame(text.as_str(), &ids) {
                    drop(ids);
                    dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            client_tx
                .send(message)
                .await
                .map_err(|e| format!("client write: {e}"))?;
        }
        Ok::<(), String>(())
    };

    // Either side ending tears the whole proxied connection down.
    tokio::select! {
        result = upstream => result,
        result = downstream => result,
    }
}

/// True if `text` is a NIP-01 `["EVENT", <sub>, {..}]` frame whose event ID
/// is in the withheld set.
fn is_withheld_event_frame(text: &str, withheld: &HashSet<String>) -> bool {
    if withheld.is_empty() {
        return false;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    let Some(array) = value.as_array() else {
        return false;
    };
    if array.first().and_then(|v| v.as_str()) != Some("EVENT") {
        return false;
    }
    array
        .get(2)
        .and_then(|event| event.get("id"))
        .and_then(|id| id.as_str())
        .is_some_and(|id| withheld.contains(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withheld_event_frames_are_detected() {
        let mut withheld = HashSet::new();
        withheld.insert("ab".repeat(32));
        let id = "ab".repeat(32);

        let event_frame = format!(r#"["EVENT","sub",{{"id":"{id}","kind":1}}]"#);
        assert!(is_withheld_event_frame(&event_frame, &withheld));

        let other_frame = r#"["EVENT","sub",{"id":"cd","kind":1}]"#;
        assert!(!is_withheld_event_frame(other_frame, &withheld));

        let eose_frame = r#"["EOSE","sub"]"#;
        assert!(!is_withheld_event_frame(eose_frame, &withheld));

        let neg_frame = format!(r#"["NEG-MSG","sub","{id}"]"#);
        assert!(
            !is_withheld_event_frame(&neg_frame, &withheld),
            "negentropy frames must pass through so reconciliation still reports the event"
        );
    }
}
