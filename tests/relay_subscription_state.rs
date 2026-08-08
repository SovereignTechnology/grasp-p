//! Connection-wide active-subscription state regression scenarios.
//!
//! Repository sync can legitimately keep many byte-budgeted filters live on
//! one relay connection. The cumulative allowance must accommodate that
//! coverage even though each individual REQ remains conservatively bounded.

mod common;

use std::time::Duration;

use common::TestRelay;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn repository_scale_live_filter_set_remains_admitted() {
    let relay = TestRelay::start().await;
    let (mut stream, _) = tokio_tungstenite::connect_async(relay.url())
        .await
        .expect("connect to relay");

    // Two 550-value filters are about 74 KiB. Seventeen persistent REQs model
    // the 34-filter live set that production rejected after crossing the old
    // 1 MiB cumulative default, while every individual message stays below
    // the sync client's 96 KiB REQ budget.
    let ids = (0..550)
        .map(|index| format!("{index:064x}"))
        .collect::<Vec<_>>();
    let filter = serde_json::json!({"#e": ids, "limit": 0});

    for index in 0..17 {
        let request = serde_json::json!(["REQ", format!("live-{index}"), filter, filter]);
        assert!(request.to_string().len() < 96 * 1024);
        stream
            .send(Message::Text(request.to_string().into()))
            .await
            .expect("send persistent live REQ");
    }

    let admitted = tokio::time::timeout(Duration::from_secs(10), async {
        let mut eose = 0;
        while let Some(message) = stream.next().await {
            let text = message.expect("valid relay response").into_text().unwrap();
            assert!(
                !text.contains("active subscriptions exceed max size"),
                "repository-scale live coverage was rejected: {text}"
            );
            if text.starts_with("[\"EOSE\",\"live-") {
                eose += 1;
                if eose == 17 {
                    return;
                }
            }
        }
        panic!("relay closed before acknowledging every live REQ");
    })
    .await;

    assert!(
        admitted.is_ok(),
        "relay did not acknowledge live coverage in time"
    );
    relay.stop().await;
}
