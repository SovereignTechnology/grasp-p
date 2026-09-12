//! Accepted connections must not outlive the fixture that owns them.
mod common;

use std::time::Duration;

use common::{
    censoring_proxy::CensoringProxy, flapping_relay::FlappingRelay,
    neg_limiting_proxy::NegLimitingProxy, req_limiting_proxy::ReqLimitingProxy,
    setup_drop_relay::SetupDropRelay, MockRelay,
};
use futures_util::StreamExt;

macro_rules! check_shutdown {
    ($fixture:expr) => {{
        tokio::time::timeout(Duration::from_secs(10), async {
            let fixture = $fixture;
            let (mut connection, _) = tokio_tungstenite::connect_async(fixture.url())
                .await
                .expect("fixture must finish the WebSocket handshake");
            fixture.stop().await;
            while let Some(message) = connection.next().await {
                if message.is_err() || message.unwrap().is_close() {
                    break;
                }
            }
        })
        .await
        .expect("fixture stop must close accepted connections");
    }};
}

#[tokio::test]
async fn censoring_proxy_closes_connections_on_stop() {
    let backend = MockRelay::start().await;
    check_shutdown!(CensoringProxy::start(backend.url()).await);
}

#[tokio::test]
async fn req_limiting_proxy_closes_connections_on_stop() {
    let backend = MockRelay::start().await;
    check_shutdown!(ReqLimitingProxy::start(backend.url(), 2).await);
}

#[tokio::test]
async fn neg_limiting_proxy_closes_connections_on_stop() {
    let backend = MockRelay::start().await;
    check_shutdown!(NegLimitingProxy::start(backend.url(), 2).await);
}

#[tokio::test]
async fn flapping_relay_closes_connections_on_stop() {
    check_shutdown!(FlappingRelay::start().await);
}

#[tokio::test]
async fn setup_drop_relay_closes_connections_on_stop() {
    check_shutdown!(SetupDropRelay::start().await);
}
