//! Connection-wide relay message-rate regression scenarios.
//!
//! rust-nostr 0.45 added a catch-all 300-frame-per-minute bucket on top of
//! its operation-specific quotas. Production browser clients crossed that
//! threshold during legitimate subscription churn and were disconnected.

mod common;

use std::time::Duration;

use common::TestRelay;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

const CLIENT_MESSAGES_PER_MINUTE: usize = 6_000;

async fn send_close_frames(
    stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    count: usize,
) {
    for index in 0..count {
        stream
            .send(Message::Text(
                format!(r#"["CLOSE","burst-{index}"]"#).into(),
            ))
            .await
            .expect("connection should accept frame");
    }
}

#[tokio::test]
async fn legitimate_1201_frame_burst_keeps_connection_usable() {
    let relay = TestRelay::start().await;
    let (mut stream, _) = tokio_tungstenite::connect_async(relay.url())
        .await
        .expect("connect to relay");

    send_close_frames(&mut stream, 1_201).await;
    stream
        .send(Message::Text(r#"["REQ","proof",{"kinds":[1]}]"#.into()))
        .await
        .expect("send proof query");

    let response = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(message) = stream.next().await {
            let text = message.expect("valid relay response").into_text().unwrap();
            if text.contains(r#"["EOSE","proof"]"#) {
                return;
            }
        }
        panic!("relay closed before answering proof query");
    })
    .await;

    assert!(response.is_ok(), "relay did not answer proof query in time");
    relay.stop().await;
}

#[tokio::test]
async fn catch_all_limit_still_closes_excessive_frame_burst() {
    let relay = TestRelay::start().await;
    let (mut stream, _) = tokio_tungstenite::connect_async(relay.url())
        .await
        .expect("connect to relay");

    send_close_frames(&mut stream, CLIENT_MESSAGES_PER_MINUTE + 1).await;

    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(message) = stream.next().await {
            if message.is_err() {
                return;
            }
        }
    })
    .await;

    assert!(
        closed.is_ok(),
        "relay did not close excessive sender in time"
    );
    relay.stop().await;
}
