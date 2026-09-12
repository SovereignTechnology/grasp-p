//! NIP-42 Gating Relay for Outbound Authentication Tests
//!
//! A WebSocket front-end that demands NIP-42 authentication before doing
//! anything, standing in for an authenticated (but NOT GRASP-08) relay:
//!
//! - HTTP requests with `Accept: application/nostr+json` receive a minimal
//!   NIP-11 document without a `supported_grasps` field, so a syncing
//!   instance treats the gate as an ordinary relay.
//! - Every WebSocket session is greeted with `["AUTH", <challenge>]`. Until
//!   a valid AUTH event (kind 22242, verified signature, matching challenge
//!   tag) arrives, `REQ`/`COUNT` receive an `auth-required:` CLOSED, `EVENT`
//!   an `auth-required:` OK-false, and `NEG-OPEN` a `NEG-ERR` marking
//!   negentropy unsupported (so sync falls back to plain REQs).
//! - After a valid AUTH the session either bridges transparently to the
//!   backend relay ([`GateMode::Admit`]) or keeps answering every `REQ` with
//!   a `restricted:` CLOSED ([`GateMode::Restricted`]).
//!
//! Authenticated pubkeys and the number of `REQ` frames received are shared
//! observable state for test assertions.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use nostr_sdk::prelude::{Event, Keys, Kind, PublicKey};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// What an authenticated session is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// Bridge authenticated sessions transparently to the backend relay.
    Admit,
    /// Accept valid authentication but refuse every query with `restricted:`.
    Restricted,
}

#[derive(Clone)]
struct GateState {
    authenticated: Arc<Mutex<HashSet<PublicKey>>>,
    req_count: Arc<AtomicUsize>,
}

/// NIP-42 gate in front of a backend relay. See the module docs.
pub struct AuthGatingRelay {
    url: String,
    state: GateState,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl AuthGatingRelay {
    /// Start the gate on a random loopback port in front of `backend_url`.
    pub async fn start(backend_url: &str, mode: GateMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("AuthGatingRelay failed to bind");
        let port = listener
            .local_addr()
            .expect("AuthGatingRelay local_addr")
            .port();

        let state = GateState {
            authenticated: Arc::new(Mutex::new(HashSet::new())),
            req_count: Arc::new(AtomicUsize::new(0)),
        };
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let backend_url = backend_url.to_string();
        let accept_state = state.clone();
        let handle = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let upgrades = Arc::new(Mutex::new(JoinSet::new()));
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let backend_url = backend_url.clone();
                        let state = accept_state.clone();
                        let io = TokioIo::new(stream);
                        let upgrades = upgrades.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |req| {
                                let upgrades = upgrades.clone();
                                let backend_url = backend_url.clone();
                                let state = state.clone();
                                async move { handle_request(req, backend_url, mode, state, upgrades).await }
                            });
                            // Errors are expected when clients disconnect.
                            let _ = http1::Builder::new()
                                .serve_connection(io, service)
                                .with_upgrades()
                                .await;
                        });
                    }
                    _ = &mut shutdown_rx => break,
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.shutdown().await;
            let mut upgrades = std::mem::take(&mut *upgrades.lock().unwrap());
            upgrades.shutdown().await;
        });

        Self {
            url: format!("ws://127.0.0.1:{port}"),
            state,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    /// The ws:// URL a syncing relay should use to reach the gate.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Pubkeys that completed a valid NIP-42 authentication.
    pub fn authenticated_pubkeys(&self) -> HashSet<PublicKey> {
        self.state
            .authenticated
            .lock()
            .expect("authenticated set poisoned")
            .clone()
    }

    /// Total `REQ` frames received across all sessions.
    pub fn req_count(&self) -> usize {
        self.state.req_count.load(Ordering::SeqCst)
    }

    /// Stop the gate.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            tokio::time::timeout(std::time::Duration::from_secs(5), handle)
                .await
                .expect("auth gating relay tasks should stop")
                .expect("auth gating relay server task should not panic");
        }
    }
}

impl Drop for AuthGatingRelay {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    backend_url: String,
    mode: GateMode,
    state: GateState,
    upgrades: Arc<Mutex<JoinSet<()>>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let is_websocket = req
        .headers()
        .get(UPGRADE)
        .map(|v| v.to_str().unwrap_or("").eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_websocket {
        if let Some(key) = req
            .headers()
            .get(SEC_WEBSOCKET_KEY)
            .and_then(|k| k.to_str().ok())
            .map(str::to_string)
        {
            let accept_key = derive_accept_key(key.as_bytes());
            let mut upgrades = upgrades.lock().unwrap();
            while upgrades.try_join_next().is_some() {}
            upgrades.spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let ws = WebSocketStream::from_raw_socket(
                            TokioIo::new(upgraded),
                            Role::Server,
                            None,
                        )
                        .await;
                        if let Err(error) = run_session(ws, &backend_url, mode, state).await {
                            eprintln!("AuthGatingRelay session ended: {error}");
                        }
                    }
                    Err(error) => eprintln!("AuthGatingRelay upgrade error: {error}"),
                }
            });
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
        // Deliberately no supported_grasps: the gate models an authenticated
        // ordinary relay, not a GRASP-08 private service.
        let document = serde_json::json!({
            "name": "auth gating relay",
            "supported_nips": [1, 11, 42],
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/nostr+json")
            .body(Full::new(Bytes::from(document.to_string())))
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from("AuthGatingRelay")))
        .unwrap())
}

type ClientWs = WebSocketStream<TokioIo<Upgraded>>;
type SharedClientSink = Arc<tokio::sync::Mutex<SplitSink<ClientWs, Message>>>;

async fn send_json(sink: &SharedClientSink, value: serde_json::Value) -> Result<(), String> {
    sink.lock()
        .await
        .send(Message::Text(value.to_string().into()))
        .await
        .map_err(|e| format!("client write: {e}"))
}

async fn run_session(
    ws: ClientWs,
    backend_url: &str,
    mode: GateMode,
    state: GateState,
) -> Result<(), String> {
    let (client_tx, mut client_rx) = ws.split();
    let client_tx: SharedClientSink = Arc::new(tokio::sync::Mutex::new(client_tx));

    // Challenge only needs to be unpredictable within the test process.
    let challenge = Keys::generate().public_key().to_hex();
    send_json(&client_tx, serde_json::json!(["AUTH", challenge])).await?;

    let mut authenticated = false;
    let mut backend: Option<SplitSink<_, Message>> = None;
    let mut backend_tasks = JoinSet::new();

    while let Some(message) = client_rx.next().await {
        let message = message.map_err(|e| format!("client read: {e}"))?;
        match message {
            Message::Text(text) => {
                let Ok(frame) = serde_json::from_str::<serde_json::Value>(text.as_str()) else {
                    continue;
                };
                let Some(kind) = frame.get(0).and_then(|v| v.as_str()) else {
                    continue;
                };

                if kind == "AUTH" {
                    handle_auth(&frame, &challenge, &state, &mut authenticated, &client_tx).await?;
                    if authenticated && mode == GateMode::Admit && backend.is_none() {
                        let (backend_ws, _) =
                            tokio_tungstenite::connect_async(backend_url)
                                .await
                                .map_err(|e| format!("backend connect failed: {e}"))?;
                        let (backend_tx, backend_rx) = backend_ws.split();
                        backend = Some(backend_tx);
                        backend_tasks.spawn(forward_backend(backend_rx, client_tx.clone()));
                    }
                    continue;
                }

                if kind == "REQ" {
                    state.req_count.fetch_add(1, Ordering::SeqCst);
                }

                if authenticated && mode == GateMode::Admit {
                    if let Some(backend_tx) = backend.as_mut() {
                        backend_tx
                            .send(Message::Text(text))
                            .await
                            .map_err(|e| format!("backend write: {e}"))?;
                    }
                    continue;
                }

                // Pre-authentication, or authenticated in Restricted mode.
                let refusal = if authenticated {
                    "restricted: not a member"
                } else {
                    "auth-required: authentication required"
                };
                let sub_id = frame.get(1).and_then(|v| v.as_str()).unwrap_or_default();
                match kind {
                    "REQ" | "COUNT" => {
                        send_json(&client_tx, serde_json::json!(["CLOSED", sub_id, refusal]))
                            .await?;
                    }
                    // The "not supported" wording makes sync classify
                    // negentropy as unsupported and fall back to REQs.
                    "NEG-OPEN" => {
                        send_json(
                            &client_tx,
                            serde_json::json!([
                                "NEG-ERR",
                                sub_id,
                                "blocked: negentropy not supported"
                            ]),
                        )
                        .await?;
                    }
                    "EVENT" => {
                        let id = frame
                            .get(1)
                            .and_then(|event| event.get("id"))
                            .and_then(|id| id.as_str())
                            .unwrap_or_default();
                        send_json(&client_tx, serde_json::json!(["OK", id, false, refusal]))
                            .await?;
                    }
                    _ => {}
                }
            }
            Message::Ping(payload) => {
                client_tx
                    .lock()
                    .await
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|e| format!("client write: {e}"))?;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    backend_tasks.shutdown().await;
    Ok(())
}

async fn handle_auth(
    frame: &serde_json::Value,
    challenge: &str,
    state: &GateState,
    authenticated: &mut bool,
    client_tx: &SharedClientSink,
) -> Result<(), String> {
    let event = frame
        .get(1)
        .and_then(|value| Event::from_json(value.to_string()).ok());
    let Some(event) = event else {
        return send_json(
            client_tx,
            serde_json::json!(["OK", "", false, "auth-required: malformed AUTH"]),
        )
        .await;
    };
    let challenge_matches = event.tags.iter().any(|tag| {
        let values = tag.as_slice();
        values.first().is_some_and(|name| name == "challenge")
            && values.get(1).is_some_and(|value| value == challenge)
    });
    let valid = event.kind == Kind::Authentication && event.verify().is_ok() && challenge_matches;
    if valid {
        *authenticated = true;
        state
            .authenticated
            .lock()
            .expect("authenticated set poisoned")
            .insert(event.pubkey);
    }
    send_json(
        client_tx,
        serde_json::json!([
            "OK",
            event.id.to_hex(),
            valid,
            if valid {
                ""
            } else {
                "auth-required: invalid AUTH"
            }
        ]),
    )
    .await
}

async fn forward_backend(
    mut backend_rx: SplitStream<
        WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    >,
    client_tx: SharedClientSink,
) {
    while let Some(message) = backend_rx.next().await {
        let Ok(message) = message else { break };
        if client_tx.lock().await.send(message).await.is_err() {
            break;
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_closes_active_websocket_sessions() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let gate = AuthGatingRelay::start("ws://127.0.0.1:1", GateMode::Restricted).await;
            let (mut client, _) = tokio_tungstenite::connect_async(gate.url()).await.unwrap();
            let challenge = client.next().await.unwrap().unwrap();
            assert!(challenge.to_text().unwrap().contains("AUTH"));
            gate.stop().await;
            assert!(matches!(
                client.next().await,
                None | Some(Err(_)) | Some(Ok(Message::Close(_)))
            ));
        })
        .await
        .expect("gate stop must close active sessions");
    }
}
