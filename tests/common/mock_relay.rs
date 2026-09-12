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
use std::sync::{Arc, Mutex};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use nostr_sdk::prelude::*;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

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

#[derive(Clone, Copy)]
struct PaginationConfig {
    page_size: usize,
    advertised_default_limit: Option<usize>,
    advertised_max_limit: Option<usize>,
}

impl MockRelay {
    /// Start a mock relay on a random free port.
    ///
    /// The relay accepts all events without validation and stores them
    /// in an in-memory database.
    pub async fn start() -> Self {
        Self::start_with_options(RateLimit::default(), None, None).await
    }

    /// Start a mock relay with a custom per-connection active REQ limit.
    pub async fn start_with_max_reqs(max_reqs: usize) -> Self {
        Self::start_with_options(
            RateLimit {
                max_reqs,
                ..RateLimit::default()
            },
            None,
            None,
        )
        .await
    }

    /// Start a relay with a strict maximum number of filters in each REQ.
    pub async fn start_with_max_filters(max_filters: usize) -> Self {
        Self::start_with_options(RateLimit::default(), None, Some(max_filters)).await
    }

    /// Start a relay whose omitted-limit pages and NIP-11 hints can be varied independently.
    pub async fn start_with_pagination(
        page_size: usize,
        advertised_default_limit: Option<usize>,
        advertised_max_limit: Option<usize>,
    ) -> Self {
        Self::start_with_options(
            RateLimit::default(),
            Some(PaginationConfig {
                page_size,
                advertised_default_limit,
                advertised_max_limit,
            }),
            None,
        )
        .await
    }

    async fn start_with_options(
        rate_limit: RateLimit,
        pagination: Option<PaginationConfig>,
        max_filters: Option<usize>,
    ) -> Self {
        Self::start_with_options_and_nip11(rate_limit, pagination, max_filters, None).await
    }

    /// Start a mock relay that serves a caller-provided NIP-11 document for
    /// `Accept: application/nostr+json` requests.
    ///
    /// This lets tests control fields the default document never emits, such
    /// as the GRASP `supported_grasps` extension array or the `pubkey` owner.
    pub async fn start_with_nip11_document(document: serde_json::Value) -> Self {
        Self::start_with_options_and_nip11(RateLimit::default(), None, None, Some(document)).await
    }

    async fn start_with_options_and_nip11(
        rate_limit: RateLimit,
        pagination: Option<PaginationConfig>,
        max_filters: Option<usize>,
        custom_nip11: Option<serde_json::Value>,
    ) -> Self {
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

        Self::start_with_listener(
            listener,
            port,
            rate_limit,
            pagination,
            max_filters,
            Vec::new(),
            custom_nip11,
        )
        .await
    }

    /// Start a mock relay on a specific port.
    pub async fn start_on_port(port: u16) -> Self {
        Self::start_on_port_with_events(port, Vec::new()).await
    }

    /// Start a mock relay on a specific port with events already stored.
    ///
    /// The events are stored before the accept loop starts, so a client
    /// reaching the freshly (re)bound port deterministically sees them —
    /// modelling an index relay recovering with prior state.
    pub async fn start_on_port_with_events(port: u16, events: Vec<Event>) -> Self {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let listener = TcpListener::bind(addr)
            .await
            .expect("Failed to bind to address");
        Self::start_with_listener(
            listener,
            port,
            RateLimit::default(),
            None,
            None,
            events,
            None,
        )
        .await
    }

    /// Recover on an owned listener, with initial events visible before accepts.
    pub async fn start_on_listener(listener: std::net::TcpListener, events: Vec<Event>) -> Self {
        let port = listener.local_addr().expect("mock listener address").port();
        listener
            .set_nonblocking(true)
            .expect("nonblocking mock listener");
        let listener = TcpListener::from_std(listener).expect("register mock listener");
        Self::start_with_listener(
            listener,
            port,
            RateLimit::default(),
            None,
            None,
            events,
            None,
        )
        .await
    }

    /// Internal method to start the relay with an existing listener.
    #[allow(clippy::too_many_arguments)]
    async fn start_with_listener(
        listener: TcpListener,
        port: u16,
        rate_limit: RateLimit,
        pagination: Option<PaginationConfig>,
        max_filters: Option<usize>,
        initial_events: Vec<Event>,
        custom_nip11: Option<serde_json::Value>,
    ) -> Self {
        // Create a simple relay with no write policy (accepts all events)
        let mut builder = LocalRelayBuilder::default().rate_limit(rate_limit);
        if let Some(config) = pagination {
            builder = builder
                .default_filter_limit(config.page_size)
                .max_filter_limit(config.page_size.max(1000))
                .max_query_results(config.page_size.max(1000));
        }
        if let Some(max_filters) = max_filters {
            builder = builder.max_filters_per_req(max_filters);
        }
        let relay = builder.build();
        for event in initial_events {
            relay
                .add_event(event)
                .await
                .expect("Failed to seed initial mock relay event");
        }

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        // Clone relay for the server task
        let server_relay = relay.clone();

        let handle = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let upgrades = Arc::new(Mutex::new(JoinSet::new()));
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, remote_addr)) => {
                                let relay = server_relay.clone();
                                let pagination = pagination;
                                let custom_nip11 = custom_nip11.clone();
                                let io = TokioIo::new(stream);

                                let upgrades = upgrades.clone();
                                connections.spawn(async move {
                                    let service = service_fn(move |req| {
                                        let upgrades = upgrades.clone();
                                        let relay = relay.clone();
                                        let custom_nip11 = custom_nip11.clone();
                                        async move {
                                            handle_request(
                                                req,
                                                relay,
                                                remote_addr,
                                                pagination,
                                                custom_nip11,
                                                upgrades,
                                            )
                                            .await
                                        }
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
                    _ = &mut shutdown_rx => break,
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            // Stop HTTP services before draining upgrades so no service can
            // create another WebSocket task after the snapshot is taken.
            connections.shutdown().await;
            let mut upgrades = std::mem::take(&mut *upgrades.lock().unwrap());
            upgrades.shutdown().await;
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
        // End active WebSocket sessions as well as refusing new accepts. Tests
        // that exercise natural remote disconnects need the same lifecycle a
        // real relay shutdown produces.
        self.relay.shutdown();

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for server task to complete
        if let Some(handle) = self.handle.take() {
            tokio::time::timeout(std::time::Duration::from_secs(5), handle)
                .await
                .expect("mock relay tasks should stop")
                .expect("mock relay server task should not panic");
        }
    }
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        self.relay.shutdown();
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
    pagination: Option<PaginationConfig>,
    custom_nip11: Option<serde_json::Value>,
    upgrades: Arc<Mutex<JoinSet<()>>>,
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

            // Retain upgrade tasks until the fixture shuts down.
            let mut upgrades = upgrades.lock().unwrap();
            while upgrades.try_join_next().is_some() {}
            upgrades.spawn(async move {
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

    if req
        .headers()
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("application/nostr+json"))
    {
        if let Some(document) = custom_nip11 {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/nostr+json")
                .body(Full::new(Bytes::from(document.to_string())))
                .unwrap());
        }
        let limitation = pagination.map(|config| {
            serde_json::json!({
                "default_limit": config.advertised_default_limit,
                "max_limit": config.advertised_max_limit,
            })
        });
        let document = serde_json::json!({
            "name": "pagination test relay",
            "supported_nips": [1, 11],
            "limitation": limitation,
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/nostr+json")
            .body(Full::new(Bytes::from(document.to_string())))
            .unwrap());
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
    async fn stop_closes_active_websocket_sessions() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        tokio::time::timeout(Duration::from_secs(5), async {
            let mock = MockRelay::start().await;
            let (mut client, _) = tokio_tungstenite::connect_async(mock.url()).await.unwrap();
            client
                .send(Message::Text(r#"["REQ","stop-probe",{"limit":1}]"#.into()))
                .await
                .unwrap();
            loop {
                let message = client.next().await.unwrap().unwrap();
                if message.to_text().is_ok_and(|text| text.contains("EOSE")) {
                    break;
                }
            }
            mock.stop().await;
            assert!(matches!(
                client.next().await,
                None | Some(Err(_)) | Some(Ok(Message::Close(_)))
            ));
        })
        .await
        .expect("mock stop must close active sessions");
    }

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
        client
            .try_connect_relay(mock.url(), Duration::from_secs(5))
            .await
            .expect("connect to mock relay");

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
