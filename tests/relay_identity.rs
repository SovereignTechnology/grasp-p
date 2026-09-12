//! Relay-owner identity publication and admission integration tests.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use common::port::UnavailableEndpoint;
use common::{reserve_port, wait_for_event_on_relay, MockRelay, TestClient, TestRelay};
use nostr::nips::nip65;
use nostr_sdk::prelude::*;

const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn relay_owner_identity_is_local_indexed_and_trusted_for_undedicated_kinds() {
    let index = MockRelay::start().await;
    let relay = TestRelay::start_with_sync(Some(index.url().to_string())).await;
    let owner = relay.owner_keys().public_key();
    let identity_filter = Filter::new()
        .author(owner)
        .kinds([Kind::Metadata, Kind::RelayList]);

    for url in [relay.url(), index.url()] {
        for kind in [Kind::Metadata, Kind::RelayList] {
            assert!(
                wait_for_event_on_relay(
                    url,
                    Filter::new().author(owner).kind(kind),
                    OBSERVATION_TIMEOUT,
                )
                .await,
                "relay-owner kind {} was not published to {url}",
                kind.as_u16()
            );
        }
    }

    let local_identity = fetch_events(relay.url(), identity_filter.clone()).await;
    let indexed_identity = fetch_events(index.url(), identity_filter).await;
    assert_eq!(event_ids(&local_identity), event_ids(&indexed_identity));
    assert_identity_shape(&relay, &local_identity);

    // Kind 19843 has no repository-root reference and no dedicated admission
    // policy, so ordinary related-event policy rejects it. The scoped
    // relay-owner trust path must still accept it for ngit-ci's coordinator
    // advertisement, while NIP-34 repository kinds keep their normal
    // policies (covered by owner_signed_repository_events below).
    let coordinator_advertisement = EventBuilder::new(Kind::from(19_843), "")
        .finalize(relay.owner_keys())
        .expect("sign owner-authored coordinator advertisement");
    let owner_client = TestClient::new(relay.url(), relay.owner_keys().clone())
        .await
        .expect("connect owner client");
    owner_client
        .send_event(&coordinator_advertisement)
        .await
        .expect("relay owner event should be accepted");
    assert!(
        wait_for_event_on_relay(
            relay.url(),
            Filter::new().id(coordinator_advertisement.id),
            OBSERVATION_TIMEOUT,
        )
        .await,
        "accepted relay-owner event was not queryable"
    );

    let deletion = EventBuilder::new(Kind::EventDeletion, "")
        .tags([Tag::event(coordinator_advertisement.id)])
        .finalize(relay.owner_keys())
        .expect("sign coordinator-advertisement deletion");
    owner_client
        .send_event(&deletion)
        .await
        .expect("relay-owner deletion should be accepted");
    assert!(
        fetch_events(relay.url(), Filter::new().id(coordinator_advertisement.id))
            .await
            .is_empty(),
        "relay-owner trust path must retain NIP-09 lifecycle effects"
    );

    // Owner-signed events are public, so anyone can replay them. The trust
    // path must still enforce the tombstone left by the deletion above.
    assert!(
        owner_client
            .send_event(&coordinator_advertisement)
            .await
            .is_err(),
        "replayed deleted relay-owner event must be rejected"
    );
    assert!(
        fetch_events(relay.url(), Filter::new().id(coordinator_advertisement.id))
            .await
            .is_empty(),
        "replayed deleted relay-owner event must not be stored"
    );

    relay.stop().await;
    index.stop().await;
}

#[tokio::test]
async fn restart_preserves_customized_profile_and_never_overwrites_index_copy() {
    let index = MockRelay::start().await;
    let git_data = tempfile::tempdir().expect("git data dir");
    let relay_data = tempfile::tempdir().expect("relay data dir");
    let relay = TestRelay::start_on_reservation_persistent_sync(
        reserve_port(),
        Some(index.url().to_string()),
        false,
        git_data.path().to_path_buf(),
        relay_data.path().to_path_buf(),
    )
    .await;
    let owner = relay.owner_keys().public_key();
    let profile_filter = Filter::new().author(owner).kind(Kind::Metadata);

    assert!(
        wait_for_event_on_relay(index.url(), profile_filter.clone(), OBSERVATION_TIMEOUT).await,
        "generated relay-owner profile was not published to the user index"
    );
    let generated_ids = event_ids(&fetch_events(index.url(), profile_filter.clone()).await);

    // The operator customizes the bot profile through an ordinary client.
    // Future-dated by a few seconds so it stays newer than anything the
    // restarted relay could sign, making the overwrite deterministic if
    // seeding ever regressed to unconditional publication.
    let customized = EventBuilder::new(Kind::Metadata, r#"{"name":"customized-bot"}"#)
        .custom_created_at(nostr_sdk::prelude::Timestamp::now() + 5)
        .finalize(relay.owner_keys())
        .expect("sign customized profile");
    let owner_client = TestClient::new(relay.url(), relay.owner_keys().clone())
        .await
        .expect("connect owner client");
    owner_client
        .send_event(&customized)
        .await
        .expect("customized owner profile should be accepted");
    assert!(
        wait_for_event_on_relay(
            relay.url(),
            Filter::new().id(customized.id),
            OBSERVATION_TIMEOUT,
        )
        .await,
        "customized profile was not stored"
    );

    let relay = relay.restart().await;

    // Restart seeding must not overwrite the operator-customized profile
    // locally, and the copy already on the user index is left untouched:
    // identities found on an index are adopted, never replaced, so pushing
    // a profile update out to the indexes is the operator's own client's
    // job. Non-replacement is stable absence over time, so poll across
    // several identity retry cycles (test mode retries every 200ms-2s).
    let stored = fetch_events(relay.url(), profile_filter.clone()).await;
    assert_eq!(
        event_ids(&stored),
        BTreeSet::from([customized.id]),
        "restart seeding must not overwrite the operator-customized profile"
    );
    let observation_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < observation_deadline {
        assert_eq!(
            event_ids(&fetch_events(index.url(), profile_filter.clone()).await),
            generated_ids,
            "restart must not overwrite the identity already on the user index"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    relay.stop().await;
    index.stop().await;
}

#[tokio::test]
async fn wiped_relay_adopts_identity_from_user_index_instead_of_publishing() {
    let owner_keys = Keys::generate();
    let index = MockRelay::start().await;
    let owner = owner_keys.public_key();

    // The only surviving copy of the operator-customized profile lives on
    // the user index, as after a local database wipe or redeployment onto
    // fresh storage with the same nsec.
    let customized = EventBuilder::new(Kind::Metadata, r#"{"name":"customized-bot"}"#)
        .finalize(&owner_keys)
        .expect("sign customized profile");
    let staging = TestClient::new(index.url(), owner_keys.clone())
        .await
        .expect("connect staging client to index");
    staging
        .send_event(&customized)
        .await
        .expect("stage customized profile on the user index");

    let relay =
        TestRelay::start_with_sync_and_owner_keys(Some(index.url().to_string()), owner_keys).await;

    // The relay adopts the indexed profile locally instead of seeding a
    // fresh minimal one...
    assert!(
        wait_for_event_on_relay(
            relay.url(),
            Filter::new().id(customized.id),
            OBSERVATION_TIMEOUT,
        )
        .await,
        "customized profile from the user index was not adopted locally"
    );
    // ...while the relay list, which no index holds, is still generated,
    // seeded, and published.
    for url in [relay.url(), index.url()] {
        assert!(
            wait_for_event_on_relay(
                url,
                Filter::new().author(owner).kind(Kind::RelayList),
                OBSERVATION_TIMEOUT,
            )
            .await,
            "generated relay list was not published to {url}"
        );
    }

    // The generated kind-0 must never have been published: the index still
    // holds exactly the customized profile. The relay list arriving on the
    // index above is the ordering anchor - a wrongly queued generated
    // profile would have been attempted in the same publication round.
    let indexed_profiles = fetch_events(
        index.url(),
        Filter::new().author(owner).kind(Kind::Metadata),
    )
    .await;
    assert_eq!(
        event_ids(&indexed_profiles),
        BTreeSet::from([customized.id]),
        "generated profile displaced the customized identity on the user index"
    );

    relay.stop().await;
    index.stop().await;
}

#[tokio::test]
async fn identity_publication_defers_until_a_user_index_relay_is_reachable() {
    // Reject protocol connections while retaining the recovery address.
    let unavailable = UnavailableEndpoint::new();
    let port = unavailable.port();
    let index_url = format!("ws://127.0.0.1:{port}");

    let relay = TestRelay::start_with_sync(Some(index_url)).await;
    let owner = relay.owner_keys().public_key();
    let identity_filter = Filter::new()
        .author(owner)
        .kinds([Kind::Metadata, Kind::RelayList]);

    // With no reachable user index, nothing may be seeded locally. Deferral
    // is stable absence over time, so observe it across several identity
    // retry cycles (test mode retries every 200ms-2s) by polling rather
    // than asserting once.
    let observation_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < observation_deadline {
        assert!(
            fetch_events(relay.url(), identity_filter.clone())
                .await
                .is_empty(),
            "identity must not be seeded while no user-index relay is reachable"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Once an empty index becomes reachable, the generated identity is
    // released: seeded locally and published to the index.
    let index = MockRelay::start_on_listener(unavailable.into_listener().await, Vec::new()).await;
    for url in [relay.url(), index.url()] {
        for kind in [Kind::Metadata, Kind::RelayList] {
            assert!(
                wait_for_event_on_relay(
                    url,
                    Filter::new().author(owner).kind(kind),
                    OBSERVATION_TIMEOUT,
                )
                .await,
                "kind {} was not published to {url} after the index became reachable",
                kind.as_u16()
            );
        }
    }

    relay.stop().await;
    index.stop().await;
}

#[tokio::test]
async fn stored_identity_is_not_pushed_to_recovering_index_holding_an_identity() {
    // Index A stays unreachable until it "recovers" already holding the
    // operator's customized profile; index B is reachable so the phase-1
    // index check can succeed without A.
    let unavailable_a = UnavailableEndpoint::new();
    let port_a = unavailable_a.port();
    let listener_b = reserve_port().into_std_listener();
    let port_b = listener_b.local_addr().expect("index B address").port();
    let index_b = MockRelay::start_on_listener(
        listener_b.try_clone().expect("retain index B listener"),
        Vec::new(),
    )
    .await;
    let git_data = tempfile::tempdir().expect("git data dir");
    let relay_data = tempfile::tempdir().expect("relay data dir");
    let relay = TestRelay::start_on_reservation_persistent_user_index_relays(
        reserve_port(),
        format!("ws://127.0.0.1:{port_a},ws://127.0.0.1:{port_b}"),
        git_data.path().to_path_buf(),
        relay_data.path().to_path_buf(),
    )
    .await;
    let owner = relay.owner_keys().public_key();

    // First boot: B confirms it holds no identity, so the generated events
    // are seeded and published to B. They are now locally *stored*.
    for kind in [Kind::Metadata, Kind::RelayList] {
        assert!(
            wait_for_event_on_relay(
                index_b.url(),
                Filter::new().author(owner).kind(kind),
                OBSERVATION_TIMEOUT,
            )
            .await,
            "generated kind {} was not published to the reachable empty index",
            kind.as_u16()
        );
    }

    // The only surviving copy of the operator-customized profile will live
    // on index A. Future-dated so it is deterministically newer than the
    // stored generated profile.
    let customized = EventBuilder::new(Kind::Metadata, r#"{"name":"customized-bot"}"#)
        .custom_created_at(Timestamp::now() + 50)
        .finalize(relay.owner_keys())
        .expect("sign customized profile");

    // Restart against a wiped, empty B (and A still down): even stored
    // identity events must wait for a successful index check before any
    // publication, then reach only relays confirmed to hold nothing.
    index_b.stop().await;
    let unavailable_b = UnavailableEndpoint::from_listener(listener_b);
    let relay = relay.restart().await;
    let index_b =
        MockRelay::start_on_listener(unavailable_b.into_listener().await, Vec::new()).await;
    for kind in [Kind::Metadata, Kind::RelayList] {
        assert!(
            wait_for_event_on_relay(
                index_b.url(),
                Filter::new().author(owner).kind(kind),
                OBSERVATION_TIMEOUT,
            )
            .await,
            "stored kind {} was not republished to the empty index after its check succeeded",
            kind.as_u16()
        );
    }

    // A recovers already holding the customized profile. The per-relay
    // re-check before every send must adopt it locally instead of pushing
    // the stored (formerly generated) profile over it.
    let index_a = MockRelay::start_on_listener(
        unavailable_a.into_listener().await,
        vec![customized.clone()],
    )
    .await;
    assert!(
        wait_for_event_on_relay(
            relay.url(),
            Filter::new().id(customized.id),
            OBSERVATION_TIMEOUT,
        )
        .await,
        "customized profile on the recovering index was not adopted locally"
    );
    // The relay list is still delivered to A, which holds none — proving
    // the publication round reached A while the profile was withheld.
    assert!(
        wait_for_event_on_relay(
            index_a.url(),
            Filter::new().author(owner).kind(Kind::RelayList),
            OBSERVATION_TIMEOUT,
        )
        .await,
        "relay list was not delivered to the recovered index"
    );
    // Non-displacement is stable absence over time, so poll across several
    // identity retry cycles (test mode retries every 200ms-2s).
    let observation_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < observation_deadline {
        let profiles = fetch_events(
            index_a.url(),
            Filter::new().author(owner).kind(Kind::Metadata),
        )
        .await;
        assert_eq!(
            event_ids(&profiles),
            BTreeSet::from([customized.id]),
            "stored profile displaced the customized identity on the recovering index"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    relay.stop().await;
    index_a.stop().await;
    index_b.stop().await;
}

#[tokio::test]
async fn owner_signed_repository_events_use_normal_admission_policies() {
    let relay = TestRelay::start().await;
    let owner_client = TestClient::new(relay.url(), relay.owner_keys().clone())
        .await
        .expect("connect owner client");

    // A state event for a repository with no accepted announcement is
    // rejected by the normal state policy. Relay-owner trust is scoped to
    // kinds without a dedicated policy, so it must not detach owner-signed
    // NIP-34 events from announcement validation and ref alignment.
    let state = EventBuilder::new(Kind::RepoState, "")
        .tags([Tag::identifier("nonexistent-repo")])
        .finalize(relay.owner_keys())
        .expect("sign owner-authored state event");
    assert!(
        owner_client.send_event(&state).await.is_err(),
        "owner-signed state event for a nonexistent repository must be rejected"
    );
    assert!(
        fetch_events(relay.url(), Filter::new().id(state.id))
            .await
            .is_empty(),
        "rejected owner-signed state event must not be stored"
    );

    relay.stop().await;
}

#[tokio::test]
async fn private_mode_seeds_identity_locally_but_never_publishes_it() {
    let index = MockRelay::start().await;
    let owner_keys = Keys::generate();
    let relay = TestRelay::start_private_with_sync_and_owner_keys(
        Some(index.url().to_string()),
        owner_keys.clone(),
    )
    .await;
    let identity_filter = Filter::new()
        .author(owner_keys.public_key())
        .kinds([Kind::Metadata, Kind::RelayList]);

    // A private relay must not leak its existence through identity events
    // on the user-index relays. Suppression is stable absence over time, so
    // poll across several identity retry cycles (test mode retries every
    // 200ms-2s) rather than asserting once.
    let observation_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < observation_deadline {
        assert!(
            fetch_events(index.url(), identity_filter.clone())
                .await
                .is_empty(),
            "identity must not be published to user-index relays in private mode"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Local seeding and serving still work: the owner — the sole GRASP-08
    // member — authenticates with NIP-42 and queries both identity events.
    let local_identity =
        fetch_events_authenticated(relay.url(), identity_filter, owner_keys.clone()).await;
    assert_identity_shape(&relay, &local_identity);

    relay.stop().await;
    index.stop().await;
}

async fn fetch_events(relay_url: &str, filter: Filter) -> Vec<Event> {
    let client = Client::new();
    client
        .add_relay(relay_url)
        .await
        .expect("add relay for identity query");
    let connected = client.try_connect().timeout(Duration::from_secs(3)).await;
    assert!(
        !connected.success.is_empty(),
        "connect to {relay_url}: {:?}",
        connected.failed
    );
    let events = client
        .fetch_events(filter)
        .timeout(Duration::from_secs(3))
        .await
        .expect("fetch relay identity")
        .into_iter()
        .collect();
    client.shutdown().await;
    events
}

/// Fetch with NIP-42 authentication, for querying a GRASP-08 private relay.
async fn fetch_events_authenticated(relay_url: &str, filter: Filter, keys: Keys) -> Vec<Event> {
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys))
        .build();
    client
        .add_relay(relay_url)
        .await
        .expect("add relay for identity query");
    let connected = client.try_connect().timeout(Duration::from_secs(3)).await;
    assert!(
        !connected.success.is_empty(),
        "connect to {relay_url}: {:?}",
        connected.failed
    );
    let events = client
        .fetch_events(filter)
        .timeout(Duration::from_secs(5))
        .await
        .expect("fetch relay identity")
        .into_iter()
        .collect();
    client.shutdown().await;
    events
}

fn event_ids(events: &[Event]) -> BTreeSet<EventId> {
    events.iter().map(|event| event.id).collect()
}

fn assert_identity_shape(relay: &TestRelay, events: &[Event]) {
    assert_eq!(events.len(), 2);
    let profile = events
        .iter()
        .find(|event| event.kind == Kind::Metadata)
        .expect("kind-0 profile");
    let metadata: serde_json::Value =
        serde_json::from_str(&profile.content).expect("parse profile content");
    let fields = metadata.as_object().expect("profile content object");
    assert_eq!(fields.len(), 3);
    assert_eq!(
        fields.get("name"),
        Some(&serde_json::json!(relay.domain())),
        "name is the scheme-less public URL"
    );
    assert_eq!(
        fields.get("nip05"),
        Some(&serde_json::json!(format!("_@{}", relay.domain())))
    );
    assert_eq!(fields.get("bot"), Some(&serde_json::json!(true)));

    let relay_list = events
        .iter()
        .find(|event| event.kind == Kind::RelayList)
        .expect("kind-10002 relay list");
    let advertised: Vec<_> = nip65::extract_relay_list(relay_list).collect();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].0.to_string(), relay.url());
    assert_eq!(advertised[0].1, None, "unmarked means read and write");
}

#[tokio::test]
async fn subprocess_restart_retains_the_reserved_endpoint() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let relay = TestRelay::start().await;
        let url = relay.url().to_string();
        let relay = relay.restart().await;
        assert_eq!(relay.url(), url);
        let (_connection, _) = tokio_tungstenite::connect_async(relay.url())
            .await
            .expect("restarted subprocess must serve the inherited listener");
        relay.stop().await;
    })
    .await
    .expect("subprocess startup and restart must complete");
}
