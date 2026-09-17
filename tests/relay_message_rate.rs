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

#[tokio::test]
async fn sdk_query_allowance_accepts_more_than_120_starts() {
    let relay = TestRelay::start().await;
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut stream, _) = tokio_tungstenite::connect_async(relay.url()).await.unwrap();
        for _ in 0..121 {
            stream
                .send(Message::Text(
                    r#"["REQ","probe",{"kinds":[1],"limit":0}]"#.into(),
                ))
                .await
                .unwrap();
            let response = stream.next().await.unwrap().unwrap().into_text().unwrap();
            assert_eq!(response, r#"["EOSE","probe"]"#);
        }
        stream.close(None).await.unwrap();
    })
    .await
    .expect("query burst exceeded deadline");
    relay.stop().await;
}

#[tokio::test]
async fn sdk_default_allows_more_than_128_established_connections() {
    let relay = TestRelay::start().await;
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut connections = Vec::new();
        for _ in 0..129 {
            let (mut stream, _) = tokio_tungstenite::connect_async(relay.url()).await.unwrap();
            stream
                .send(Message::Text(
                    r#"["REQ","probe",{"kinds":[1],"limit":0}]"#.into(),
                ))
                .await
                .unwrap();
            let response = stream.next().await.unwrap().unwrap().into_text().unwrap();
            assert_eq!(response, r#"["EOSE","probe"]"#);
            connections.push(stream);
        }
        for mut stream in connections {
            stream.close(None).await.unwrap();
        }
    })
    .await
    .expect("connection admission exceeded deadline");
    relay.stop().await;
}
