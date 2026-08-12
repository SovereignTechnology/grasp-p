//! Minimal GRASP-03 mailbox discovery scenario.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{
    build_layer2_issue_event, repo_coord, send_to_relay_url, setup_announcement_on_relay,
    wait_for_event_on_relay, MockRelay, TestClient, TestRelay, reserve_port,
};

#[tokio::test]
async fn root_author_inbox_reuses_existing_root_sync_pipeline() {
    let index = MockRelay::start().await;
    let outbox = MockRelay::start().await;
    let inbox = MockRelay::start().await;
    let replacement_inbox = MockRelay::start().await;
    let owner = Keys::generate();
    let root_author = Keys::generate();
    let unrelated = Keys::generate();
    let identifier = "minimal-proactive-sync-plus";

    let relay_list = EventBuilder::new(Kind::RelayList, "")
        .tags([
            Tag::custom("r", vec![inbox.url(), "read"]),
            Tag::custom("r", vec![outbox.url(), "write"]),
        ])
        .custom_created_at(Timestamp::from(Timestamp::now().as_secs() - 10))
        .finalize(&root_author)
        .expect("build NIP-65 relay list");
    let old_profile = EventBuilder::new(Kind::Metadata, r#"{"name":"old"}"#)
        .custom_created_at(Timestamp::from(Timestamp::now().as_secs() - 20))
        .finalize(&root_author)
        .expect("build old root-author profile");
    let profile = EventBuilder::new(Kind::Metadata, r#"{"name":"current"}"#)
        .custom_created_at(Timestamp::from(Timestamp::now().as_secs() - 5))
        .finalize(&root_author)
        .expect("build current root-author profile");
    let unrelated_profile = EventBuilder::new(Kind::Metadata, r#"{"name":"unrelated"}"#)
        .finalize(&unrelated)
        .expect("build unrelated profile");
    send_to_relay_url(index.url(), &old_profile)
        .await
        .expect("seed old profile");
    send_to_relay_url(index.url(), &profile)
        .await
        .expect("seed current profile");
    send_to_relay_url(index.url(), &unrelated_profile)
        .await
        .expect("seed unrelated profile");
    send_to_relay_url(index.url(), &relay_list)
        .await
        .expect("seed discovery index");
    let replacement = EventBuilder::new(Kind::RelayList, "")
        .tags([
            Tag::custom("r", vec![replacement_inbox.url(), "read"]),
            Tag::custom("r", vec![outbox.url(), "write"]),
        ])
        .custom_created_at(Timestamp::now())
        .finalize(&root_author)
        .expect("build outbox replacement relay list");
    send_to_relay_url(outbox.url(), &replacement)
        .await
        .expect("seed newer relay list on advertised outbox");

    let syncing_git_dir = tempfile::tempdir().expect("create persistent git directory");
    let syncing_relay_dir = tempfile::tempdir().expect("create persistent relay directory");
    let syncing = TestRelay::start_on_reservation_persistent_sync(
        reserve_port(),
        Some(index.url().to_string()),
        false,
        syncing_git_dir.path().to_path_buf(),
        syncing_relay_dir.path().to_path_buf(),
    )
    .await;
    let syncing_domain = syncing.domain();
    let (_announcement, _git_dir) =
        setup_announcement_on_relay(&syncing, &owner, &[&syncing_domain], identifier).await;
    let issue = build_layer2_issue_event(
        &root_author,
        &repo_coord(&owner, identifier),
        "root whose replies live in its inbox",
    )
    .expect("build accepted root");
    let client = TestClient::new(syncing.url(), root_author.clone())
        .await
        .expect("connect to target");
    client.send_event(&issue).await.expect("publish root");

    let reply = EventBuilder::new(Kind::TextNote, "inbox-only reply")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .finalize(&root_author)
        .expect("build reply");
    send_to_relay_url(inbox.url(), &reply)
        .await
        .expect("seed root-author inbox");

    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(reply.id),
            Duration::from_secs(20),
        )
        .await,
        "NIP-65 inbox roots should flow through ordinary descendant coverage"
    );
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(profile.id),
            Duration::from_secs(15),
        )
        .await,
        "latest accepted root-author metadata should be retained locally"
    );
    assert!(
        !wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(old_profile.id),
            Duration::from_secs(2),
        )
        .await,
        "older root-author metadata should not be selected"
    );
    assert!(
        !wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(unrelated_profile.id),
            Duration::from_secs(2),
        )
        .await,
        "unrelated metadata on the discovery relay must remain absent"
    );

    let replacement_reply = EventBuilder::new(Kind::TextNote, "replacement inbox reply")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .finalize(&root_author)
        .expect("build replacement reply");
    send_to_relay_url(replacement_inbox.url(), &replacement_reply)
        .await
        .expect("seed replacement inbox");
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(replacement_reply.id),
            Duration::from_secs(15),
        )
        .await,
        "replacement NIP-65 inbox should become the desired root source"
    );
    let draining_reply = EventBuilder::new(Kind::TextNote, "reply on naturally draining inbox")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .finalize(&root_author)
        .expect("build draining reply");
    send_to_relay_url(inbox.url(), &draining_reply)
        .await
        .expect("seed old inbox while its live subscription drains");
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(draining_reply.id),
            Duration::from_secs(5),
        )
        .await,
        "replacement must not eagerly close existing descendant live coverage"
    );

    // A restart must reconstruct the accepted kind-10002 overlay locally.
    // Stop the only discovery source first so a remote refresh cannot make the
    // assertion pass accidentally.
    index.stop().await;
    let syncing = syncing.restart().await;
    let restart_reply = EventBuilder::new(Kind::TextNote, "reply after offline-index restart")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .finalize(&root_author)
        .expect("build restart reply");
    send_to_relay_url(replacement_inbox.url(), &restart_reply)
        .await
        .expect("seed replacement inbox after restart");
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(restart_reply.id),
            Duration::from_secs(20),
        )
        .await,
        "retained kind-10002 must rebuild inbox coverage while its index source is offline"
    );

    syncing.stop().await;
    replacement_inbox.stop().await;
    outbox.stop().await;
    inbox.stop().await;
}
