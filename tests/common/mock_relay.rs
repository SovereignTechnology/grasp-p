//! Mock Nostr Relay for Testing
//!
//! Provides a simple Nostr relay that accepts all events without validation.
//! Uses rust-nostr's `LocalRelayBuilder` to create an in-memory relay.
//!
//! # Usage
//!
//! ```ignore
//! use common::MockRelay;
//!
//! #[tokio::test]
//! async fn test_mock_relay() {
//!     // Start the mock relay
//!     let mock = MockRelay::start().await;
//!     
//!     // Use mock.url() for WebSocket connections
//!     let client = Client::builder().authenticator(SignerAuthenticator::new(keys)).build();
//!     client.add_relay(mock.url()).await.unwrap();
//!     
//!     // All events are accepted without validation
//!     client.send_event(&event).await.unwrap();
//!     
//!     // Cleanup
//!     mock.stop().await;
//! }
//! ```
//!
//! # How It Works
//!
//! The mock relay:
//! - Uses `LocalRelayBuilder::default().build()` which accepts all events
//! - Runs an HTTP server with WebSocket upgrade support
//! - Stores events in an in-memory database
//! - Does NOT perform any GRASP validation (no purgatory, no git data checks)

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use nostr_sdk::prelude::*;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Mock Nostr relay that accepts all events without validation.
///
/// This relay is useful for testing scenarios where you need a relay
/// that serves events without GRASP validation (no purgatory, no git checks).
pub struct MockRelay {
    /// Shutdown signal sender
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Server task handle
    handle: Option<tokio::task::JoinHandle<()>>,
    /// Server URL (ws://127.0.0.1:<port>)
    url: String,
    /// Server port
    #[allow(dead_code)]
    port: u16,
    /// The underlying LocalRelay (kept alive for the server lifetime)
    #[allow(dead_code)]
    relay: LocalRelay,
}

impl MockRelay {
    /// Start a mock relay on a random free port.
    ///
    /// The relay accepts all events without validation and stores them
    /// in an in-memory database.
    pub async fn start() -> Self {
        Self::start_with_rate_limit(RateLimit::default()).await
    }

    /// Start a mock relay with a custom per-connection active REQ limit.
    pub async fn start_with_max_reqs(max_reqs: usize) -> Self {
        Self::start_with_rate_limit(RateLimit {
            max_reqs,
            ..RateLimit::default()
        })
        .await
    }

    async fn start_with_rate_limit(rate_limit: RateLimit) -> Self {
        // Create and bind listener (eliminates port race condition)
        let std_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port");
        let port = std_listener
            .local_addr()
            .expect("Failed to get local addr")
            .port();

        // Convert to tokio listener (keeps port bound)
        std_listener
            .set_nonblocking(true)
            .expect("Failed to set non-blocking");
        let listener =
            TcpListener::from_std(std_listener).expect("Failed to convert to tokio listener");

        Self::start_with_listener(listener, port, rate_limit).await
    }

    /// Start a mock relay on a specific port.
    pub async fn start_on_port(port: u16) -> Self {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let listener = TcpListener::bind(addr)
            .await
            .expect("Failed to bind to address");
        Self::start_with_listener(listener, port, RateLimit::default()).await
    }

    /// Internal method to start the relay with an existing listener.
    async fn start_with_listener(listener: TcpListener, port: u16, rate_limit: RateLimit) -> Self {
        // Create a simple relay with no write policy (accepts all events)
        let relay = LocalRelayBuilder::default().rate_limit(rate_limit).build();

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        // Clone relay for the server task
        let server_relay = relay.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, remote_addr)) => {
                                let relay = server_relay.clone();
                                let io = TokioIo::new(stream);

                                tokio::spawn(async move {
                                    let service = service_fn(move |req| {
                                        let relay = relay.clone();
                                        async move { handle_request(req, relay, remote_addr).await }
                                    });

                                    if let Err(e) = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .with_upgrades()
                                        .await
                                    {
                                        // Connection errors are expected when client disconnects
                                        if !e.to_string().contains("connection") {
                                            eprintln!("MockRelay connection error: {}", e);
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("MockRelay accept error: {}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        // Shutdown signal received
                        break;
                    }
                }
            }
        });

        let url = format!("ws://127.0.0.1:{}", port);

        // Wait for server to be ready
        wait_for_server_ready(port).await;

        Self {
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
            url,
            port,
            relay,
        }
    }

    /// Get the relay WebSocket URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the relay domain as a host and port.
    pub fn domain(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Stop the mock relay.
    pub async fn stop(mut self) {
        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for server task to complete
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        // Send shutdown signal if not already sent
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Handle an HTTP request, upgrading to WebSocket if requested.
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    relay: LocalRelay,
    addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check for WebSocket upgrade request
    let is_websocket = req
        .headers()
        .get(UPGRADE)
        .map(|v| v.to_str().unwrap_or("").to_lowercase() == "websocket")
        .unwrap_or(false);

    if is_websocket {
        // Get the Sec-WebSocket-Key header
        let key = req
            .headers()
            .get(SEC_WEBSOCKET_KEY)
            .and_then(|k| k.to_str().ok())
            .map(|k| k.to_string());

        if let Some(key) = key {
            let accept_key = derive_accept_key(key.as_bytes());

            // Spawn task to handle the upgraded connection
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = relay.take_connection(TokioIo::new(upgraded), addr).await {
                            eprintln!("MockRelay WebSocket error: {}", e);
                        }
                    }
                    Err(e) => eprintln!("MockRelay upgrade error: {}", e),
                }
            });

            // Return 101 Switching Protocols
            return Ok(Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(CONNECTION, "upgrade")
                .header(UPGRADE, "websocket")
                .header(SEC_WEBSOCKET_ACCEPT, accept_key)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
    }

    // Non-WebSocket request - return simple response
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from("MockRelay - Nostr test relay")))
        .unwrap())
}

/// Derive the Sec-WebSocket-Accept key from the request key.
fn derive_accept_key(request_key: &[u8]) -> String {
    use bitcoin_hashes::sha1::Hash as Sha1Hash;
    use bitcoin_hashes::{Hash, HashEngine};

    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    let mut engine = Sha1Hash::engine();
    engine.input(request_key);
    engine.input(WS_GUID);
    let hash = Sha1Hash::from_engine(engine);
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        hash.as_byte_array(),
    )
}

/// Wait for the server to be ready to accept connections.
async fn wait_for_server_ready(port: u16) {
    let max_attempts = 50; // 5 seconds total
    let delay = std::time::Duration::from_millis(100);

    for attempt in 0..max_attempts {
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(_) => {
                // Connection successful, server is ready
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                return;
            }
            Err(_) => {
                if attempt == max_attempts - 1 {
                    panic!("MockRelay failed to start after {} attempts", max_attempts);
                }
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Disambiguate from `nostr_sdk::local_relay::MockRelay`, which the SDK
    // prelude also exports since the relay builder was merged into nostr-sdk.
    use super::MockRelay;
    use nostr_sdk::prelude::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_mock_relay_starts_and_stops() {
        let mock = MockRelay::start().await;

        // Verify URL is set
        assert!(mock.url().starts_with("ws://127.0.0.1:"));

        mock.stop().await;
    }

    #[tokio::test]
    async fn test_mock_relay_accepts_events() {
        let mock = MockRelay::start().await;

        // Create a client and connect
        let keys = Keys::generate();
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(keys.clone()))
            .build();
        client
            .add_relay(mock.url())
            .await
            .expect("Failed to add relay");
        client.connect().await;

        // Wait for connection
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Create and send a simple event
        let event = EventBuilder::new(Kind::TextNote, "Test note from MockRelay test")
            .finalize(&keys)
            .expect("Failed to sign event");

        let result = client.send_event(&event).await;
        assert!(result.is_ok(), "MockRelay should accept events");

        // Verify event was stored by fetching it back
        let filter = Filter::new().id(event.id);
        let events = client
            .fetch_events(filter)
            .timeout(Duration::from_secs(2))
            .await
            .expect("Failed to fetch events");

        assert!(!events.is_empty(), "Event should be stored and retrievable");
        assert_eq!(events.first().unwrap().id, event.id);

        client.disconnect().await;
        mock.stop().await;
    }
}
