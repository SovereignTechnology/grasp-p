mod common;

use std::time::Duration;

use base64::Engine;
use common::TestRelay;
use futures_util::{SinkExt, StreamExt};
use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp, ToBech32};
use reqwest::header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use tokio_tungstenite::tungstenite::Message;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const WS_DEADLINE: Duration = Duration::from_secs(10);

fn credential(keys: &Keys, repository_url: &str) -> String {
    credential_at(keys, repository_url, Timestamp::now())
}

fn credential_at(keys: &Keys, repository_url: &str, created_at: Timestamp) -> String {
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(vec![
            Tag::parse(["u", repository_url]).expect("URL tag"),
            Tag::parse(["method", "GET"]).expect("method tag"),
        ])
        .custom_created_at(created_at)
        .finalize(keys)
        .expect("signed NIP-98 credential");
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(event.as_json())
    )
}

fn auth_message(keys: &Keys, relay_domain: &str, challenge: &str) -> String {
    let relay_url = format!("ws://{relay_domain}");
    let event = EventBuilder::new(Kind::Authentication, "")
        .tags(vec![
            Tag::parse(["relay", relay_url.as_str()]).expect("relay tag"),
            Tag::parse(["challenge", challenge]).expect("challenge tag"),
        ])
        .finalize(keys)
        .expect("signed NIP-42 event");
    format!("[\"AUTH\",{}]", event.as_json())
}

/// Await the next text frame within the bounded deadline, skipping
/// non-text control frames.
async fn next_text(stream: &mut WsStream) -> String {
    tokio::time::timeout(WS_DEADLINE, async {
        while let Some(message) = stream.next().await {
            if let Message::Text(text) = message.expect("valid websocket frame") {
                return text.to_string();
            }
        }
        panic!("websocket closed while awaiting a relay message");
    })
    .await
    .expect("relay message within deadline")
}

/// Connect to a private relay and consume the initial NIP-42 challenge.
async fn connect_and_challenge(relay: &TestRelay) -> (WsStream, String) {
    let (mut stream, _) = tokio_tungstenite::connect_async(relay.url())
        .await
        .expect("connect to private relay");
    let frame: serde_json::Value =
        serde_json::from_str(&next_text(&mut stream).await).expect("relay JSON message");
    assert_eq!(
        frame[0], "AUTH",
        "first relay message must be the challenge"
    );
    let challenge = frame[1].as_str().expect("challenge string").to_owned();
    (stream, challenge)
}

async fn send_text(stream: &mut WsStream, text: String) {
    tokio::time::timeout(WS_DEADLINE, stream.send(Message::Text(text.into())))
        .await
        .expect("send within deadline")
        .expect("send websocket frame");
}

/// Assert the peer terminates the connection without further relay messages.
async fn expect_closed(stream: &mut WsStream) {
    tokio::time::timeout(WS_DEADLINE, async {
        loop {
            match stream.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return,
                Some(Ok(Message::Text(text))) => {
                    panic!("expected connection close, received: {text}")
                }
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .expect("connection close within deadline");
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

#[tokio::test]
async fn private_git_credential_expiry_and_smart_http_scope() {
    let member = Keys::generate();
    let repository_owner = Keys::generate()
        .public_key()
        .to_bech32()
        .expect("repository owner npub");
    let relay = TestRelay::start_private(&member.public_key()).await;
    let repository_url = format!(
        "http://{}/{repository_owner}/private-repository.git",
        relay.domain()
    );
    let info_refs_url = format!("{repository_url}/info/refs?service=git-upload-pack");
    let client = reqwest::Client::new();

    // A credential outside the 60-second validity window is indistinguishable
    // from any other failure: same empty 401 challenge.
    let expired = credential_at(
        &member,
        &repository_url,
        Timestamp::from_secs(Timestamp::now().as_secs().saturating_sub(300)),
    );
    let response = client
        .get(&info_refs_url)
        .header(AUTHORIZATION, expired)
        .send()
        .await
        .expect("expired credential response");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(response.bytes().await.expect("response body").is_empty());

    // A credential signing the Smart HTTP subpath instead of the repository
    // root does not match the GRASP-08 canonical URL.
    let response = client
        .get(&info_refs_url)
        .header(AUTHORIZATION, credential(&member, &info_refs_url))
        .send()
        .await
        .expect("subpath-scoped credential response");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    // The repository-root credential is reusable across Smart HTTP endpoints
    // within its validity window.
    let reusable = credential(&member, &repository_url);
    for url in [&info_refs_url, &repository_url] {
        let response = client
            .get(url)
            .header(AUTHORIZATION, reusable.clone())
            .send()
            .await
            .expect("member Smart HTTP response");
        assert_ne!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    relay.stop().await;
}

#[tokio::test]
async fn private_nip11_document_stays_public_and_advertises_auth() {
    let member = Keys::generate();
    let relay = TestRelay::start_private(&member.public_key()).await;

    // Clients must be able to discover the authentication requirement without
    // credentials, so the NIP-11 document is deliberately unauthenticated.
    let response = reqwest::Client::new()
        .get(format!("http://{}/", relay.domain()))
        .header(ACCEPT, "application/nostr+json")
        .send()
        .await
        .expect("NIP-11 response");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let document: serde_json::Value = response.json().await.expect("NIP-11 JSON");
    let nips = document["supported_nips"]
        .as_array()
        .expect("supported_nips array");
    for nip in [42, 98] {
        assert!(
            nips.contains(&serde_json::Value::from(nip)),
            "NIP-11 must advertise NIP-{nip}: {nips:?}"
        );
    }

    relay.stop().await;
}

#[tokio::test]
async fn private_websocket_rejects_messages_before_authentication() {
    let member = Keys::generate();
    let relay = TestRelay::start_private(&member.public_key()).await;
    let (mut stream, _challenge) = connect_and_challenge(&relay).await;

    send_text(&mut stream, r#"["REQ","pre-auth",{}]"#.to_string()).await;
    let closed: serde_json::Value =
        serde_json::from_str(&next_text(&mut stream).await).expect("CLOSED JSON");
    assert_eq!(closed[0], "CLOSED");
    assert_eq!(closed[1], "pre-auth");
    assert!(
        closed[2]
            .as_str()
            .expect("CLOSED message")
            .starts_with("auth-required:"),
        "{closed}"
    );

    let note = EventBuilder::new(Kind::TextNote, "pre-auth publish")
        .finalize(&member)
        .expect("signed note");
    send_text(&mut stream, format!("[\"EVENT\",{}]", note.as_json())).await;
    let ok: serde_json::Value =
        serde_json::from_str(&next_text(&mut stream).await).expect("OK JSON");
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[1].as_str(), Some(note.id.to_hex().as_str()));
    assert_eq!(ok[2], false);
    assert!(
        ok[3]
            .as_str()
            .expect("OK message")
            .starts_with("auth-required:"),
        "{ok}"
    );

    send_text(&mut stream, "not a nostr message".to_string()).await;
    let notice: serde_json::Value =
        serde_json::from_str(&next_text(&mut stream).await).expect("NOTICE JSON");
    assert_eq!(notice[0], "NOTICE");

    relay.stop().await;
}

#[tokio::test]
async fn private_websocket_admits_member_and_bridges_to_relay() {
    let member = Keys::generate();
    let relay = TestRelay::start_private(&member.public_key()).await;
    let (mut stream, challenge) = connect_and_challenge(&relay).await;

    send_text(
        &mut stream,
        auth_message(&member, &relay.domain(), &challenge),
    )
    .await;
    let ok: serde_json::Value =
        serde_json::from_str(&next_text(&mut stream).await).expect("OK JSON");
    assert_eq!(ok[0], "OK");
    assert_eq!(
        ok[2], true,
        "member NIP-42 authentication must succeed: {ok}"
    );

    // The authenticated session reaches the inner relay: a subscription is
    // answered with EOSE instead of an auth-required rejection.
    send_text(
        &mut stream,
        r#"["REQ","after-auth",{"kinds":[1],"limit":1}]"#.to_string(),
    )
    .await;
    let deadline = tokio::time::timeout(WS_DEADLINE, async {
        loop {
            let frame: serde_json::Value =
                serde_json::from_str(&next_text(&mut stream).await).expect("relay JSON");
            if frame[0] == "EOSE" && frame[1] == "after-auth" {
                return;
            }
            assert_ne!(
                frame[0], "CLOSED",
                "authenticated REQ was rejected: {frame}"
            );
        }
    })
    .await;
    assert!(deadline.is_ok(), "no EOSE for authenticated subscription");

    relay.stop().await;
}

#[tokio::test]
async fn private_websocket_rejects_valid_nonmember_auth_and_closes() {
    let member = Keys::generate();
    let outsider = Keys::generate();
    let relay = TestRelay::start_private(&member.public_key()).await;
    let (mut stream, challenge) = connect_and_challenge(&relay).await;

    send_text(
        &mut stream,
        auth_message(&outsider, &relay.domain(), &challenge),
    )
    .await;
    let ok: serde_json::Value =
        serde_json::from_str(&next_text(&mut stream).await).expect("OK JSON");
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], false);
    assert!(
        ok[3]
            .as_str()
            .expect("OK message")
            .starts_with("restricted:"),
        "valid non-member auth must be restricted: {ok}"
    );
    expect_closed(&mut stream).await;

    relay.stop().await;
}

/// Build a GRASP-01-valid repository announcement listing this relay in
/// both the `clone` and `relays` tags.
fn announcement(keys: &Keys, relay_domain: &str) -> nostr_sdk::prelude::Event {
    let npub = keys
        .public_key()
        .to_bech32()
        .expect("announcement author npub");
    let clone_url = format!("https://{relay_domain}/{npub}/private-membership-repo.git");
    let relay_url = format!("ws://{relay_domain}");
    EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![
            Tag::parse(["d", "private-membership-repo"]).expect("d tag"),
            Tag::parse(["clone", clone_url.as_str()]).expect("clone tag"),
            Tag::parse(["relays", relay_url.as_str()]).expect("relays tag"),
        ])
        .finalize(keys)
        .expect("signed announcement")
}

/// Bare-repository path an admitted announcement by `keys` would create.
fn bare_repo_path(relay: &TestRelay, keys: &Keys) -> std::path::PathBuf {
    relay
        .git_data_path()
        .join(keys.public_key().to_bech32().expect("owner npub"))
        .join("private-membership-repo.git")
}

#[tokio::test]
async fn private_announcement_admission_requires_member_author() {
    let member = Keys::generate();
    let outsider = Keys::generate();
    let relay = TestRelay::start_private(&member.public_key()).await;
    let (mut stream, challenge) = connect_and_challenge(&relay).await;

    send_text(
        &mut stream,
        auth_message(&member, &relay.domain(), &challenge),
    )
    .await;
    let ok: serde_json::Value =
        serde_json::from_str(&next_text(&mut stream).await).expect("OK JSON");
    assert_eq!(
        ok[2], true,
        "member NIP-42 authentication must succeed: {ok}"
    );

    // A member-authored announcement is admitted (OK true, parked in
    // purgatory awaiting git data) and its bare repository is created.
    let admitted = announcement(&member, &relay.domain());
    send_text(&mut stream, format!("[\"EVENT\",{}]", admitted.as_json())).await;
    let ok: serde_json::Value =
        serde_json::from_str(&next_text(&mut stream).await).expect("OK JSON");
    assert_eq!(ok[1].as_str(), Some(admitted.id.to_hex().as_str()));
    assert_eq!(
        ok[2], true,
        "member-authored announcement must be admitted: {ok}"
    );
    assert!(
        bare_repo_path(&relay, &member).exists(),
        "admitted announcement must create its bare repository"
    );

    // The same authenticated member session cannot introduce a valid
    // announcement signed by a non-member author: membership gates the
    // announcement's author, not the publishing session.
    let rejected = announcement(&outsider, &relay.domain());
    send_text(&mut stream, format!("[\"EVENT\",{}]", rejected.as_json())).await;
    let ok: serde_json::Value =
        serde_json::from_str(&next_text(&mut stream).await).expect("OK JSON");
    assert_eq!(ok[1].as_str(), Some(rejected.id.to_hex().as_str()));
    assert_eq!(
        ok[2], false,
        "non-member-authored announcement must be rejected: {ok}"
    );
    assert!(
        !bare_repo_path(&relay, &outsider).exists(),
        "rejected announcement must not admit a repository"
    );

    relay.stop().await;
}

#[tokio::test]
async fn private_websocket_bounds_invalid_authentication_attempts() {
    let member = Keys::generate();
    let outsider = Keys::generate();
    let relay = TestRelay::start_private(&member.public_key()).await;
    let (mut stream, _challenge) = connect_and_challenge(&relay).await;

    // Three syntactically valid AUTH events signed over the wrong challenge
    // exhaust the attempt budget and terminate the connection.
    for _ in 0..3 {
        send_text(
            &mut stream,
            auth_message(&outsider, &relay.domain(), "wrong-challenge"),
        )
        .await;
        let ok: serde_json::Value =
            serde_json::from_str(&next_text(&mut stream).await).expect("OK JSON");
        assert_eq!(ok[0], "OK");
        assert_eq!(ok[2], false);
        assert!(
            ok[3]
                .as_str()
                .expect("OK message")
                .starts_with("auth-required:"),
            "{ok}"
        );
    }
    expect_closed(&mut stream).await;

    relay.stop().await;
}
