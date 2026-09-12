//! WebSocket relay fixture that accepts normal setup and then drops the session.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Notify};
use tokio_tungstenite::tungstenite::Message;

/// Relay-shaped endpoint for exercising reconnect health accounting.
pub struct FlappingRelay {
    url: String,
    connected_at: Arc<Mutex<Vec<Instant>>>,
    connection_observed: Arc<Notify>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl FlappingRelay {
    /// Start an endpoint that drops each WebSocket after the first REQ frame.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("FlappingRelay failed to bind");
        let port = listener.local_addr().expect("flapping local_addr").port();
        let connected_at = Arc::new(Mutex::new(Vec::new()));
        let connection_observed = Arc::new(Notify::new());
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let observed = connected_at.clone();
        let notify = connection_observed.clone();

        let handle = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let observed = observed.clone();
                        let notify = notify.clone();
                        connections.spawn(async move {
                            let Ok(mut websocket) = tokio_tungstenite::accept_async(stream).await
                            else {
                                // NIP-11 HTTP probes are expected to fail this
                                // deliberately WebSocket-only fixture.
                                return;
                            };
                            observed.lock().expect("flapping timestamps poisoned").push(Instant::now());
                            notify.notify_waiters();

                            while let Some(message) = websocket.next().await {
                                let Ok(message) = message else { break };
                                if matches!(message, Message::Text(ref text) if text.contains("\"REQ\"")) {
                                    // Dropping the socket after observable normal
                                    // setup and a short established dwell models
                                    // the production peer reset. The dwell also
                                    // distinguishes this fixture from a peer that
                                    // vanishes during connection setup.
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    return;
                                }
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
            connected_at,
            connection_observed,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Wait for `count` successful WebSocket sessions using notifications,
    /// bounded by `timeout`.
    pub async fn wait_for_connections(&self, count: usize, timeout: Duration) -> Vec<Instant> {
        tokio::time::timeout(timeout, async {
            loop {
                let notified = self.connection_observed.notified();
                let timestamps = self
                    .connected_at
                    .lock()
                    .expect("flapping timestamps poisoned")
                    .clone();
                if timestamps.len() >= count {
                    return timestamps;
                }
                notified.await;
            }
        })
        .await
        .expect("recovered relay did not make the expected connection attempts")
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

impl Drop for FlappingRelay {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}
