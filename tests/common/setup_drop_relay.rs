//! Relay fixture that disconnects the WebSocket during its NIP-11 setup fetch.
//!
//! Public syncing instances also probe NIP-11 *before* dialing (to detect
//! GRASP-08 private services); that pre-dial probe is answered immediately.
//! Only a NIP-11 request arriving while a WebSocket session is live triggers
//! the drop-during-setup choreography under test.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};

/// Endpoint for reproducing a stale successful connection result.
pub struct SetupDropRelay {
    url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl SetupDropRelay {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("SetupDropRelay failed to bind");
        let port = listener.local_addr().expect("setup-drop local_addr").port();
        let (nip11_tx, nip11_rx) = watch::channel(false);
        let (dropped_tx, dropped_rx) = watch::channel(false);
        let nip11_tx = Arc::new(nip11_tx);
        let dropped_tx = Arc::new(dropped_tx);
        let active_websockets = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let nip11_tx = nip11_tx.clone();
                        let nip11_rx = nip11_rx.clone();
                        let dropped_tx = dropped_tx.clone();
                        let dropped_rx = dropped_rx.clone();
                        let active_websockets = active_websockets.clone();
                        connections.spawn(async move {
                            handle_connection(
                                stream,
                                nip11_tx,
                                nip11_rx,
                                dropped_tx,
                                dropped_rx,
                                active_websockets,
                            )
                            .await;
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
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    nip11_tx: Arc<watch::Sender<bool>>,
    mut nip11_rx: watch::Receiver<bool>,
    dropped_tx: Arc<watch::Sender<bool>>,
    mut dropped_rx: watch::Receiver<bool>,
    active_websockets: Arc<AtomicUsize>,
) {
    let mut header = [0_u8; 4096];
    let header_len = loop {
        let Ok(length) = stream.peek(&mut header).await else {
            return;
        };
        if length == 0 {
            return;
        }
        if header[..length]
            .windows(4)
            .any(|bytes| bytes == b"\r\n\r\n")
        {
            break length;
        }
        tokio::task::yield_now().await;
    };
    let request = String::from_utf8_lossy(&header[..header_len]).to_ascii_lowercase();

    if request.contains("upgrade: websocket") {
        let Ok(_websocket) = tokio_tungstenite::accept_async(stream).await else {
            return;
        };
        active_websockets.fetch_add(1, Ordering::SeqCst);
        while !*nip11_rx.borrow() && nip11_rx.changed().await.is_ok() {}
        // Dropping the live socket is the behavior under test. Give the SDK a
        // bounded propagation window before allowing the HTTP setup to finish.
        drop(_websocket);
        active_websockets.fetch_sub(1, Ordering::SeqCst);
        let _ = dropped_tx.send(true);
    } else {
        let mut request_bytes = vec![0_u8; header_len];
        if stream.read_exact(&mut request_bytes).await.is_err() {
            return;
        }
        // Pre-dial NIP-11 probes (no live WebSocket) are answered without
        // choreography; only a fetch during a live session drops it.
        if active_websockets.load(Ordering::SeqCst) > 0 {
            let _ = nip11_tx.send(true);
            while !*dropped_rx.borrow() && dropped_rx.changed().await.is_ok() {}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let body = r#"{"limitation":{"max_subscriptions":20}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

impl Drop for SetupDropRelay {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}
