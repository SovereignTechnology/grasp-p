//! Local relay fixture that owns its listener from allocation through shutdown.

use std::convert::Infallible;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use nostr_sdk::prelude::{LocalRelay, LocalRelayBuilder};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

pub(super) struct TestRelay {
    relay: LocalRelay,
    url: String,
    task: JoinHandle<()>,
}

impl TestRelay {
    pub(super) async fn start(builder: LocalRelayBuilder) -> Self {
        // The SDK's run() probes and releases a port before binding it again.
        // Keep this listener bound and give upgraded streams to the SDK instead.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let url = format!("ws://{}", listener.local_addr().expect("relay address"));
        let relay = builder.build();
        let server = relay.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, addr) = accepted.expect("accept test relay connection");
                        let relay = server.clone();
                        connections.spawn(async move {
                            let upgrade = Arc::new(Mutex::new(None));
                            let requested_upgrade = upgrade.clone();
                            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                                let key = req.headers().get("sec-websocket-key").cloned();
                                let response = if let Some(key) = key {
                                    let accept = derive_accept_key(key.as_bytes());
                                    *requested_upgrade.lock().expect("upgrade lock") =
                                        Some(hyper::upgrade::on(req));
                                    Response::builder()
                                        .status(101)
                                        .header("connection", "upgrade")
                                        .header("upgrade", "websocket")
                                        .header("sec-websocket-accept", accept)
                                } else {
                                    Response::builder().status(400)
                                };
                                async move {
                                    Ok::<_, Infallible>(response.body(Full::new(Bytes::new())).unwrap())
                                }
                            });
                            let http = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .with_upgrades();
                            if !matches!(tokio::time::timeout(Duration::from_secs(5), http).await, Ok(Ok(()))) {
                                return;
                            }
                            let upgrade = upgrade.lock().expect("upgrade lock").take();
                            if let Some(upgrade) = upgrade {
                                if let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(5), upgrade).await {
                                    let _ = relay.take_connection(TokioIo::new(stream), addr).await;
                                }
                            }
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.expect("connection task").expect("connection task panicked");
                    }
                }
            }
        });
        Self { relay, url, task }
    }

    pub(super) async fn url(&self) -> String {
        self.url.clone()
    }

    pub(super) fn shutdown(&self) {
        self.task.abort();
        self.relay.shutdown();
    }
}

impl Deref for TestRelay {
    type Target = LocalRelay;

    fn deref(&self) -> &Self::Target {
        &self.relay
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        // Aborting the listener also drops its JoinSet and aborts connections.
        self.shutdown();
    }
}

#[tokio::test]
async fn concurrent_relays_keep_distinct_reachable_listeners() {
    let mut starts = JoinSet::new();
    for _ in 0..32 {
        starts.spawn(TestRelay::start(LocalRelayBuilder::default()));
    }
    let mut relays = Vec::new();
    let mut urls = std::collections::HashSet::new();
    while let Some(result) = starts.join_next().await {
        let relay = result.expect("start task");
        assert!(urls.insert(relay.url().await.to_owned()));
        relays.push(relay);
    }
    for relay in &relays {
        let (mut socket, _) = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_tungstenite::connect_async(relay.url().await),
        )
        .await
        .expect("handshake deadline")
        .expect("connect test relay");
        tokio::time::timeout(Duration::from_secs(5), socket.close(None))
            .await
            .expect("close deadline")
            .expect("close test connection");
    }
}
