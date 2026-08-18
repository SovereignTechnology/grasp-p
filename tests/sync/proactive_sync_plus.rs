//! Minimal GRASP-03 mailbox discovery scenario.

use std::path::Path;
use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{
    build_layer2_issue_event, repo_coord, reserve_port, send_to_relay_url,
    setup_announcement_on_relay, wait_for_event_on_relay, MockRelay, TestClient, TestRelay,
};

async fn wait_for_log_line<F>(path: &Path, timeout: Duration, predicate: F) -> bool
where
    F: Fn(&str) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let log = std::fs::read_to_string(path).unwrap_or_default();
        if log.lines().any(&predicate) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

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
    let sync_log = std::fs::read_to_string(syncing.log_path()).expect("read syncing relay log");
    assert!(
        sync_log.lines().any(|line| {
            line.contains("NIP-65 discovery connection ready without repository sync")
                && line.contains(outbox.url())
        }),
        "the advertised outbox connection should be identified as discovery-only"
    );
    assert!(
        !sync_log
            .lines()
            .any(|line| { line.contains("Starting fresh_start") && line.contains(outbox.url()) }),
        "querying an advertised outbox must not start ordinary repository sync against it"
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

#[tokio::test]
async fn participant_write_mailbox_fetches_child_of_direct_reaction() {
    let index = MockRelay::start().await;
    let mailbox = MockRelay::start().await;
    let owner = Keys::generate();
    let root_author = Keys::generate();
    let participant = Keys::generate();
    let child_author = Keys::generate();
    let identifier = "participant-write-mailbox";

    let relay_list = EventBuilder::new(Kind::RelayList, "")
        .tag(Tag::custom("r", vec![mailbox.url(), "write"]))
        .finalize(&participant)
        .expect("build participant relay list");
    send_to_relay_url(index.url(), &relay_list)
        .await
        .expect("seed participant relay list");

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
        "root with a reaction whose child is mailbox-only",
    )
    .expect("build accepted root");
    let root_client = TestClient::new(syncing.url(), root_author)
        .await
        .expect("connect root author");
    root_client.send_event(&issue).await.expect("publish root");

    let reaction = EventBuilder::new(Kind::Reaction, "+")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .finalize(&participant)
        .expect("build direct participant reaction");
    let participant_client = TestClient::new(syncing.url(), participant)
        .await
        .expect("connect participant");
    participant_client
        .send_event(&reaction)
        .await
        .expect("publish direct reaction");

    let child = EventBuilder::new(Kind::TextNote, "reply to a reaction")
        .tag(Tag::custom("e", vec![reaction.id.to_hex()]))
        .finalize(&child_author)
        .expect("build mailbox-only child");
    send_to_relay_url(mailbox.url(), &child)
        .await
        .expect("seed participant write mailbox");

    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(child.id),
            Duration::from_secs(30),
        )
        .await,
        "history probing should fetch a child that only names the participant's direct reaction"
    );
    let sync_log = std::fs::read_to_string(syncing.log_path()).expect("read syncing relay log");
    assert!(
        sync_log.lines().any(|line| {
            line.contains("Started bounded participant mailbox fetch")
                && line.contains(mailbox.url())
        }),
        "participant mailbox transport should remain observable"
    );

    syncing.stop().await;
    mailbox.stop().await;
    index.stop().await;
}

#[tokio::test]
async fn owner_mailbox_discovers_unknown_root_and_root_only_status() {
    let index = MockRelay::start().await;
    let mailbox = MockRelay::start().await;
    let owner = Keys::generate();
    let root_author = Keys::generate();
    let identifier = "owner-repository-mailbox";

    let relay_list = EventBuilder::new(Kind::RelayList, "")
        .tag(Tag::custom("r", vec![mailbox.url(), "write"]))
        .finalize(&owner)
        .expect("build owner relay list");
    send_to_relay_url(index.url(), &relay_list)
        .await
        .expect("seed owner relay list");

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
        "root stored only on the repository owner's mailbox",
    )
    .expect("build mailbox-only root");
    let closed = EventBuilder::new(Kind::from(1632), "closed")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .finalize(&owner)
        .expect("build root-only closed status");
    send_to_relay_url(mailbox.url(), &issue)
        .await
        .expect("seed unknown root on owner mailbox");
    send_to_relay_url(mailbox.url(), &closed)
        .await
        .expect("seed root-only status on owner mailbox");

    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(issue.id),
            Duration::from_secs(30),
        )
        .await,
        "the owner's repository-coordinate scope should discover an unknown root"
    );
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(closed.id),
            Duration::from_secs(30),
        )
        .await,
        "the owner's mailbox should be queried for known root IDs after inventory growth"
    );
    let sync_log = std::fs::read_to_string(syncing.log_path()).expect("read syncing relay log");
    assert!(
        sync_log.lines().any(|line| {
            line.contains("Reconciled proactive participant mailbox inventory")
                && line.contains("repository_mailbox_author_count=1")
        }),
        "repository mailbox ownership should remain observable without public-key labels"
    );
    assert!(
        !sync_log
            .lines()
            .any(|line| { line.contains("Starting fresh_start") && line.contains(mailbox.url()) }),
        "an owner mailbox must remain history-only rather than becoming a repository source"
    );

    syncing.stop().await;
    mailbox.stop().await;
    index.stop().await;
}

#[tokio::test]
async fn missing_relay_list_uses_bounded_fallback_coverage() {
    let index = MockRelay::start().await;
    let fallback = MockRelay::start().await;
    let discovered_inbox = MockRelay::start().await;
    let owner = Keys::generate();
    let root_author = Keys::generate();
    let identifier = "missing-list-fallback";
    let syncing_git_dir = tempfile::tempdir().expect("create persistent git directory");
    let syncing_relay_dir = tempfile::tempdir().expect("create persistent relay directory");
    let syncing = TestRelay::start_on_reservation_persistent_sync_with_fallback(
        reserve_port(),
        index.url().to_string(),
        fallback.url().to_string(),
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
        "root with no published relay list",
    )
    .expect("build accepted root");
    let client = TestClient::new(syncing.url(), root_author.clone())
        .await
        .expect("connect to target");
    client.send_event(&issue).await.expect("publish root");

    let reply = EventBuilder::new(Kind::TextNote, "fallback-only reply")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .finalize(&root_author)
        .expect("build reply");
    send_to_relay_url(fallback.url(), &reply)
        .await
        .expect("seed fallback relay");

    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(reply.id),
            Duration::from_secs(20),
        )
        .await,
        "a successful empty index lookup should activate bounded fallback coverage"
    );
    let sync_log = std::fs::read_to_string(syncing.log_path()).expect("read syncing relay log");
    assert!(
        sync_log.lines().any(|line| {
            line.contains("Updated proactive participant mailbox coverage from NIP-65")
                && line.contains("fallback_authors=1")
        }),
        "fallback activation should remain observable"
    );

    let relay_list = EventBuilder::new(Kind::RelayList, "")
        .tag(Tag::custom("r", vec![discovered_inbox.url(), "read"]))
        .finalize(&root_author)
        .expect("build later relay list");
    send_to_relay_url(index.url(), &relay_list)
        .await
        .expect("publish later relay list to index");
    let declared_reply = EventBuilder::new(Kind::TextNote, "declared-inbox reply")
        .tag(Tag::custom("e", vec![issue.id.to_hex()]))
        .finalize(&root_author)
        .expect("build declared-inbox reply");
    send_to_relay_url(discovered_inbox.url(), &declared_reply)
        .await
        .expect("seed declared inbox");
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(declared_reply.id),
            Duration::from_secs(20),
        )
        .await,
        "a later accepted relay list should replace desired fallback coverage"
    );
    assert!(
        wait_for_log_line(&syncing.log_path(), Duration::from_secs(20), |line| {
            line.contains("proactive participant mailbox") && line.contains("fallback_authors=0")
        })
        .await,
        "accepted NIP-65 ownership should retire the author from desired fallback coverage"
    );

    syncing.stop().await;
    discovered_inbox.stop().await;
    fallback.stop().await;
    index.stop().await;
}
