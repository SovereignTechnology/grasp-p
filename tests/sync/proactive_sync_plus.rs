//! Minimal GRASP-03 mailbox discovery scenario.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{
    build_layer2_issue_event, repo_coord, send_to_relay_url, setup_announcement_on_relay,
    wait_for_event_on_relay, MockRelay, TestClient, TestRelay,
};

#[tokio::test]
async fn root_author_inbox_reuses_existing_root_sync_pipeline() {
    let index = MockRelay::start().await;
    let inbox = MockRelay::start().await;
    let replacement_inbox = MockRelay::start().await;
    let owner = Keys::generate();
    let root_author = Keys::generate();
    let identifier = "minimal-proactive-sync-plus";

    let relay_list = EventBuilder::new(Kind::RelayList, "")
        .tag(Tag::custom("r", vec![inbox.url(), "read"]))
        .custom_created_at(Timestamp::from(Timestamp::now().as_secs() - 10))
        .finalize(&root_author)
        .expect("build NIP-65 relay list");
    send_to_relay_url(index.url(), &relay_list)
        .await
        .expect("seed discovery index");

    let syncing = TestRelay::start_with_sync(Some(index.url().to_string())).await;
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

    let replacement = EventBuilder::new(Kind::RelayList, "")
        .tag(Tag::custom("r", vec![replacement_inbox.url(), "read"]))
        .custom_created_at(Timestamp::now())
        .finalize(&root_author)
        .expect("build replacement relay list");
    send_to_relay_url(index.url(), &replacement)
        .await
        .expect("replace root-author inbox");
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

    let obsolete_reply = EventBuilder::new(Kind::TextNote, "obsolete inbox reply")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .finalize(&root_author)
        .expect("build obsolete-inbox reply");
    send_to_relay_url(inbox.url(), &obsolete_reply)
        .await
        .expect("seed obsolete inbox after replacement");
    assert!(
        !wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(obsolete_reply.id),
            Duration::from_secs(3),
        )
        .await,
        "obsolete inbox coverage should be retired after replacement"
    );

    syncing.stop().await;
    replacement_inbox.stop().await;
    inbox.stop().await;
    index.stop().await;
}
