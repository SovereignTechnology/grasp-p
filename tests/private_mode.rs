mod common;

use base64::Engine;
use common::TestRelay;
use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, ToBech32};
use reqwest::header::{AUTHORIZATION, WWW_AUTHENTICATE};

fn credential(keys: &Keys, repository_url: &str) -> String {
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(vec![
            Tag::parse(["u", repository_url]).expect("URL tag"),
            Tag::parse(["method", "GET"]).expect("method tag"),
        ])
        .finalize(keys)
        .expect("signed NIP-98 credential");
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(event.as_json())
    )
}

#[tokio::test]
async fn private_git_endpoint_requires_a_service_member() {
    let member = Keys::generate();
    let outsider = Keys::generate();
    let repository_owner = Keys::generate()
        .public_key()
        .to_bech32()
        .expect("repository owner npub");
    let relay = TestRelay::start_private(&member.public_key()).await;
    let repository_url = format!(
        "http://{}/{repository_owner}/private-repository.git",
        relay.domain()
    );
    let client = reqwest::Client::new();

    for authorization in [None, Some(credential(&outsider, &repository_url))] {
        let mut request = client.get(&repository_url);
        if let Some(authorization) = authorization {
            request = request.header(AUTHORIZATION, authorization);
        }
        let response = request.send().await.expect("private Git response");
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(WWW_AUTHENTICATE)
                .expect("Nostr challenge")
                .to_str()
                .expect("ASCII challenge"),
            format!("Nostr realm=\"{}\", method=\"GET\"", relay.domain())
        );
        assert!(response.bytes().await.expect("response body").is_empty());
    }

    let response = client
        .get(&repository_url)
        .header(AUTHORIZATION, credential(&member, &repository_url))
        .send()
        .await
        .expect("authenticated Git response");
    assert_ne!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    relay.stop().await;
}
