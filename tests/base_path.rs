//! Integration coverage for path-mounted GRASP services.

mod common;

use std::time::Duration;

use common::TestRelay;
use nostr_sdk::prelude::{Keys, ToBech32};

#[tokio::test]
async fn path_mount_scopes_http_websocket_and_nip05_behavior() {
    let relay = TestRelay::start_at_base_path("/grasp").await;
    let client = reqwest::Client::new();
    let root = format!("http://{}", relay.domain());

    assert_eq!(relay.service_address(), format!("{}/grasp", relay.domain()));
    assert_eq!(relay.url(), format!("ws://{}/grasp", relay.domain()));

    let outside = client.get(&root).send().await.expect("request domain root");
    assert_eq!(outside.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(outside
        .text()
        .await
        .expect("read outside-prefix response")
        .contains("href=\"/grasp\""));

    let landing = client
        .get(format!("{root}/grasp"))
        .send()
        .await
        .expect("request mounted landing page");
    assert_eq!(landing.status(), reqwest::StatusCode::OK);

    let nip11: serde_json::Value = client
        .get(format!("{root}/grasp"))
        .header("Accept", "application/nostr+json")
        .send()
        .await
        .expect("request mounted NIP-11 document")
        .json()
        .await
        .expect("parse mounted NIP-11 document");
    assert!(!nip11["supported_nips"]
        .as_array()
        .expect("supported_nips should be an array")
        .contains(&serde_json::json!(5)));
    assert_eq!(
        nip11["icon"],
        format!("https://{}/grasp/icon.png", relay.domain())
    );

    for path in ["/.well-known/nostr.json", "/grasp/.well-known/nostr.json"] {
        let response = client
            .get(format!("{root}{path}"))
            .send()
            .await
            .expect("request unavailable path-mounted NIP-05 document");
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND, "{path}");
    }

    let metrics = client
        .get(format!("{root}/grasp/metrics"))
        .send()
        .await
        .expect("request mounted metrics");
    assert_eq!(metrics.status(), reqwest::StatusCode::OK);

    let npub = Keys::generate()
        .public_key()
        .to_bech32()
        .expect("encode npub");
    let repo = client
        .get(format!("{root}/grasp/{npub}/missing.git"))
        .send()
        .await
        .expect("request mounted repository landing page");
    assert_eq!(repo.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(repo
        .text()
        .await
        .expect("read repository response")
        .contains("Repository Not Found"));

    let mounted_repo = relay.git_data_path().join(&npub).join("mounted.git");
    std::fs::create_dir_all(mounted_repo.parent().expect("repository parent"))
        .expect("create repository owner directory");
    let init = tokio::process::Command::new("git")
        .args(["init", "--bare"])
        .arg(&mounted_repo)
        .output()
        .await
        .expect("initialize mounted bare repository");
    assert!(
        init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let ls_remote = tokio::process::Command::new("git")
        .arg("ls-remote")
        .arg(format!("{root}/grasp/{npub}/mounted.git"))
        .output()
        .await
        .expect("run git ls-remote through mounted Smart HTTP route");
    assert!(
        ls_remote.status.success(),
        "git ls-remote failed: {}",
        String::from_utf8_lossy(&ls_remote.stderr)
    );

    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async(relay.url()),
    )
    .await
    .expect("mounted WebSocket connection timed out")
    .expect("connect to mounted WebSocket relay");
    socket.close(None).await.expect("close mounted WebSocket");

    let root_websocket = format!("ws://{}", relay.domain());
    let root_result = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async(&root_websocket),
    )
    .await
    .expect("root WebSocket rejection timed out");
    assert!(
        root_result.is_err(),
        "domain-root WebSocket must not upgrade"
    );

    relay.stop().await;
}
