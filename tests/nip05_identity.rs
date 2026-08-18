//! NIP-05 root-identifier integration tests.

mod common;

use common::TestRelay;

#[tokio::test]
async fn well_known_root_identity_matches_relay_pubkey() {
    let relay = TestRelay::start().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!(
            "http://{}/.well-known/nostr.json?name=_",
            relay.domain()
        ))
        .header("Accept", "application/nostr+json, application/json")
        .send()
        .await
        .expect("request NIP-05 root identity");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok()),
        Some("*")
    );
    assert!(response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json")));

    let nip05: serde_json::Value = response.json().await.expect("parse NIP-05 document");
    let root_pubkey = nip05["names"]["_"]
        .as_str()
        .expect("NIP-05 document should map the root identifier");
    assert_eq!(root_pubkey.len(), 64);
    assert!(root_pubkey
        .chars()
        .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)));

    let nip11: serde_json::Value = client
        .get(format!("http://{}", relay.domain()))
        .header("Accept", "application/nostr+json")
        .send()
        .await
        .expect("request NIP-11 document")
        .json()
        .await
        .expect("parse NIP-11 document");

    assert_eq!(nip11["pubkey"], root_pubkey);
    assert!(nip11["supported_nips"]
        .as_array()
        .expect("supported_nips should be an array")
        .contains(&serde_json::json!(5)));

    let nested_nip11 = client
        .get(format!("http://{}/relay", relay.domain()))
        .header("Accept", "application/nostr+json")
        .send()
        .await
        .expect("request NIP-11 document at an unconfigured relay path");
    assert_eq!(nested_nip11.status(), reqwest::StatusCode::NOT_FOUND);

    let nested_response = client
        .get(format!(
            "http://{}/repository/.well-known/nostr.json?name=_",
            relay.domain()
        ))
        .send()
        .await
        .expect("request a non-root well-known path");
    assert_eq!(nested_response.status(), reqwest::StatusCode::NOT_FOUND);

    relay.stop().await;
}
