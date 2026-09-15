//! Reusing a repository fixture must not mint replaceable event revisions.
use std::{collections::BTreeSet, time::Duration};

use nostr_sdk::prelude::*;

use crate::common::{reserve_port, setup_announcement_on_relay, TestRelay};

async fn repository_event_ids(
    relay: &TestRelay,
    keys: &Keys,
    identifier: &str,
) -> BTreeSet<EventId> {
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys.clone()))
        .build();
    client.add_relay(relay.url()).await.unwrap();
    client
        .try_connect_relay(relay.url(), Duration::from_secs(5))
        .await
        .expect("connect to installed repository");
    let events = client
        .fetch_events(
            Filter::new()
                .author(keys.public_key())
                .identifier(identifier)
                .kinds([Kind::GitRepoAnnouncement, Kind::RepoState]),
        )
        .timeout(Duration::from_secs(5))
        .await
        .expect("fetch installed repository events");
    client.disconnect().await;
    events.iter().map(|event| event.id).collect()
}

async fn remote_head(relay: &TestRelay, keys: &Keys, identifier: &str) -> String {
    let url = format!(
        "http://{}/{}/{}.git",
        relay.domain(),
        keys.public_key().to_bech32().unwrap(),
        identifier
    );
    let output = tokio::process::Command::from(grasp_audit::git_command())
        .args(["ls-remote", &url, "refs/heads/main"])
        .kill_on_drop(true)
        .output()
        .await
        .expect("query repository ref");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .expect("main ref exists")
        .to_string()
}

#[tokio::test]
async fn reinstalling_shared_repository_preserves_event_ids_and_git_refs() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let source = TestRelay::start().await;
        let target_reservation = reserve_port();
        let target_domain = format!("127.0.0.1:{}", target_reservation.port());
        let domains = [source.domain(), target_domain];
        let refs = domains.iter().map(String::as_str).collect::<Vec<_>>();
        let keys = Keys::generate();
        let identifier = "shared-fixture-identity";
        let (announcement, repository) =
            setup_announcement_on_relay(&source, &keys, &refs, identifier).await;
        let original_ids = repository_event_ids(&source, &keys, identifier).await;
        assert_eq!(
            original_ids.len(),
            2,
            "announcement and state must both exist"
        );
        assert!(original_ids.contains(&announcement.id));
        let original_head = remote_head(&source, &keys, identifier).await;

        // Start the peer only after seeding the source, matching historic sync.
        let target =
            TestRelay::start_on_reservation_with_options(target_reservation, None, false).await;
        repository.install(&target).await;
        assert_eq!(
            repository_event_ids(&target, &keys, identifier).await,
            original_ids
        );
        assert_eq!(remote_head(&target, &keys, identifier).await, original_head);

        // Reinstall after sync has seen the same address. There must be no new
        // event IDs, timestamps or competing Git state in either direction.
        repository.install(&source).await;
        repository.install(&target).await;
        for relay in [&source, &target] {
            assert_eq!(
                repository_event_ids(relay, &keys, identifier).await,
                original_ids
            );
            assert_eq!(remote_head(relay, &keys, identifier).await, original_head);
        }
        target.stop().await;
        source.stop().await;
    })
    .await
    .expect("shared repository setup and reinstalls must complete");
}
