//! WebSocket lifecycle metrics scenarios.

mod common;

use std::time::{Duration, Instant};

use common::{sync_helpers::fetch_metrics, TestRelay};

fn connection_duration_count(metrics: &str) -> Option<u64> {
    metrics.lines().find_map(|line| {
        line.strip_prefix("ngit_websocket_connection_duration_seconds_count ")?
            .parse()
            .ok()
    })
}

#[tokio::test]
async fn closed_websocket_records_its_connection_duration() {
    let relay = TestRelay::start().await;
    let (mut stream, _) = tokio_tungstenite::connect_async(relay.url())
        .await
        .expect("connect to relay");

    stream.close(None).await.expect("close websocket");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let metrics = fetch_metrics(relay.url()).await.expect("fetch metrics");
        if connection_duration_count(&metrics) == Some(1) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "closed connection was not observed in duration histogram: {metrics}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    relay.stop().await;
}
