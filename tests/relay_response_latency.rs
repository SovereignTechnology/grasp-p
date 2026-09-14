//! Opt-in Linux delayed-ACK benchmark for the accepted HTTP/WebSocket socket.

mod common;

#[tokio::test]
#[ignore = "local load benchmark; run explicitly with --nocapture"]
async fn concurrent_lmdb_read_batches_reach_eose() {
    use common::{TestClient, TestRelay};
    use futures_util::{SinkExt, StreamExt};
    use nostr_sdk::prelude::*;
    use std::time::{Duration, Instant};
    use tokio_tungstenite::tungstenite::Message;

    let relay = TestRelay::start_with_lmdb().await;
    let keys = relay.owner_keys().clone();
    let client = TestClient::new(relay.url(), keys.clone()).await.unwrap();
    for index in 0..32 {
        let event = EventBuilder::new(Kind::TextNote, format!("{index}:{}", "x".repeat(8192)))
            .finalize(&keys)
            .unwrap();
        client.send_event(&event).await.unwrap();
    }
    for concurrency in [1, 4, 16, 32] {
        let url = relay.url().to_string();
        let reads = (0..concurrency).map(|_| {
            let url = url.clone();
            async move {
                let (mut stream, _) = tokio_tungstenite::connect_async(url).await.unwrap();
                let started = Instant::now();
                for _ in 0..3 {
                    stream
                        .send(Message::Text(r#"["REQ","load",{"kinds":[1]}]"#.into()))
                        .await
                        .unwrap();
                    let mut events = 0;
                    loop {
                        let frame = stream.next().await.unwrap().unwrap();
                        if !frame.is_text() {
                            continue;
                        }
                        let message: serde_json::Value =
                            serde_json::from_str(frame.to_text().unwrap()).unwrap();
                        match message[0].as_str() {
                            Some("EVENT") => events += 1,
                            Some("EOSE") => break,
                            other => panic!("unexpected reply: {other:?}"),
                        }
                    }
                    assert_eq!(events, 32);
                }
                let elapsed = started.elapsed();
                stream.close(None).await.unwrap();
                elapsed
            }
        });
        let times = tokio::time::timeout(
            Duration::from_secs(30),
            futures_util::future::join_all(reads),
        )
        .await
        .expect("all readers must reach EOSE under local load");
        eprintln!(
            "{concurrency} concurrent LMDB readers, three 32-event batches each: max {:?}",
            times.iter().max().unwrap()
        );
    }
    client.disconnect().await;
    relay.stop().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "socket latency benchmark; run explicitly on an otherwise idle worker"]
async fn small_event_batches_do_not_wait_for_delayed_ack() {
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    use common::{TestClient, TestRelay};
    use futures_util::{SinkExt, StreamExt};
    use nostr_sdk::prelude::*;
    use tokio_tungstenite::tungstenite::Message;

    let relay = TestRelay::start().await;
    let keys = relay.owner_keys().clone();
    let client = TestClient::new(relay.url(), keys.clone()).await.unwrap();
    for index in 0..2 {
        let event = EventBuilder::new(Kind::TextNote, format!("event {index}"))
            .finalize(&keys)
            .unwrap();
        client.send_event(&event).await.unwrap();
    }
    let socket = tokio::net::TcpStream::connect(relay.domain())
        .await
        .unwrap();
    socket.set_nodelay(true).unwrap();
    let (mut stream, _) = tokio_tungstenite::client_async(relay.url(), socket)
        .await
        .unwrap();
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..25 {
            let disabled: libc::c_int = 0;
            // Explicitly model a peer that uses delayed acknowledgements.
            // The descriptor and option value remain alive for setsockopt.
            let result = unsafe {
                libc::setsockopt(
                    stream.get_ref().as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_QUICKACK,
                    &disabled as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&disabled) as libc::socklen_t,
                )
            };
            assert_eq!(result, 0);
            stream
                .send(Message::Text(r#"["REQ","latency",{"kinds":[1]}]"#.into()))
                .await
                .unwrap();
            let mut events = 0;
            loop {
                let frame = stream.next().await.unwrap().unwrap();
                if !frame.is_text() {
                    continue;
                }
                let message: serde_json::Value =
                    serde_json::from_str(frame.to_text().unwrap()).unwrap();
                match message[0].as_str() {
                    Some("EVENT") => events += 1,
                    Some("EOSE") => break,
                    other => panic!("unexpected reply: {other:?}"),
                }
            }
            assert_eq!(events, 2);
        }
    })
    .await
    .expect("batch reads must complete");
    let elapsed = started.elapsed();
    eprintln!("25 two-event reads with delayed ACK: {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(500),
        "small batches were delayed: {elapsed:?}"
    );
    client.disconnect().await;
    relay.stop().await;
}
