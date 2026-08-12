//! Adaptive historic-pagination integration scenarios.
//!
//! These drive the real REQ+EOSE sync path against a configurable rust-nostr
//! LocalRelay. Its omitted-limit page size models Ditto independently from
//! the NIP-11 values it advertises, which covers missing, honest, and wrong-high
//! `default_limit` documents without adding an explicit `limit` to our filters.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::purgatory_helpers::{
    create_state_event, create_test_repo_with_commit, push_to_relay, CommitVariant,
};
use crate::common::sync_helpers::{repo_coord, wait_for_event_on_relay, TestClient};
use crate::common::{port, MockRelay, TestRelay};

const SEED_BATCH: usize = 50;

async fn seed_issues(
    source: &MockRelay,
    repo_keys: &Keys,
    coordinate: &str,
    count: usize,
) -> Vec<Event> {
    let base_created_at = Timestamp::now().as_secs() - count as u64 - 10;
    let mut issues = Vec::with_capacity(count);

    for batch_start in (0..count).step_by(SEED_BATCH) {
        let client = TestClient::new(source.url(), Keys::generate())
            .await
            .expect("connect seeding client");
        for index in batch_start..(batch_start + SEED_BATCH).min(count) {
            let issue = EventBuilder::new(Kind::GitIssue, format!("Historic issue {index}"))
                .tags(vec![Tag::custom("a", vec![coordinate.to_string()])])
                .custom_created_at(Timestamp::from_secs(base_created_at + index as u64))
                .finalize(repo_keys)
                .expect("build historic issue");
            client
                .send_event(&issue)
                .await
                .expect("seed historic issue");
            issues.push(issue);
        }
        client.disconnect().await;
    }

    issues
}

async fn run_pagination_scenario(
    page_size: usize,
    advertised_default_limit: Option<usize>,
    advertised_max_limit: Option<usize>,
    event_count: usize,
) -> (TestRelay, MockRelay) {
    let reservation = port::reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", reservation.port());
    let source =
        MockRelay::start_with_pagination(page_size, advertised_default_limit, advertised_max_limit)
            .await;
    let repo_keys = Keys::generate();
    let identifier = "adaptive-pagination";
    let coordinate = repo_coord(&repo_keys, identifier);
    let issues = seed_issues(&source, &repo_keys, &coordinate, event_count).await;
    let oldest = issues.first().expect("at least one event").id;

    let syncing = TestRelay::start_on_reservation_with_options(
        reservation,
        Some(source.url().to_string()),
        true,
    )
    .await;

    // Admit one real repository locally so its self-subscriber installs the
    // Layer-2 historic filter that matches the already-seeded issues.
    let git_temp_dir = tempfile::tempdir().expect("create pagination git repo");
    let commit_hash = create_test_repo_with_commit(git_temp_dir.path(), CommitVariant::StateTest)
        .expect("create pagination git history");
    let npub = repo_keys.public_key().to_bech32().expect("npub");
    let clone_urls = vec![format!("http://{syncing_domain}/{npub}/{identifier}.git")];
    let relay_urls = vec![source.url().to_string(), syncing.url().to_string()];
    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "pagination repository")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom("clone", clone_urls.clone()),
            Tag::custom("relays", relay_urls.clone()),
        ])
        .finalize(&repo_keys)
        .expect("build repository announcement");
    let state = create_state_event(
        &repo_keys,
        identifier,
        &[("main", &commit_hash)],
        &[],
        &clone_urls.iter().map(String::as_str).collect::<Vec<_>>(),
        &relay_urls.iter().map(String::as_str).collect::<Vec<_>>(),
    )
    .expect("build repository state");
    let client = TestClient::new(syncing.url(), repo_keys.clone())
        .await
        .expect("connect announcement client");
    client
        .send_event(&announcement)
        .await
        .expect("submit repository announcement");
    client
        .send_event(&state)
        .await
        .expect("submit repository state");
    client.disconnect().await;
    push_to_relay(git_temp_dir.path(), &syncing.domain(), &npub, identifier)
        .expect("push repository data to syncing relay");

    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(oldest),
            Duration::from_secs(30),
        )
        .await,
        "the oldest of {event_count} issues must survive pagination"
    );

    (syncing, source)
}

#[tokio::test]
async fn ditto_shaped_omitted_limit_pages_reach_the_oldest_event() {
    // Ditto advertises only the explicit-request maximum (1000), while an
    // omitted-limit filter receives 100-event pages.
    let (syncing, source) = run_pagination_scenario(100, None, Some(1000), 320).await;
    syncing.stop().await;
    source.stop().await;
}

#[tokio::test]
async fn honest_default_limit_stops_after_its_verification_page() {
    // The relay honestly advertises a 500-event default but has only 100
    // matches. The short first page gets exactly one verification request;
    // its inclusive cursor repeats only the boundary event, then stops.
    let (syncing, source) = run_pagination_scenario(500, Some(500), Some(1000), 100).await;
    let log_path = format!(
        "/tmp/relay-{}.log",
        syncing.domain().split(':').next_back().unwrap()
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let log = loop {
        let log = std::fs::read_to_string(&log_path).expect("read syncing relay log");
        if log
            .matches("Grouped subscription hit pagination threshold")
            .count()
            >= 1
        {
            break log;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "verification page was not scheduled before the deadline"
        );
        tokio::task::yield_now().await;
    };
    assert_eq!(
        log.matches("Grouped subscription hit pagination threshold")
            .count(),
        1,
        "an honest hint should require only its single verification page"
    );
    syncing.stop().await;
    source.stop().await;
}

#[tokio::test]
async fn wrong_high_default_limit_is_discarded_after_productive_verification() {
    // The document claims 1000, but omitted-limit pages contain only 100.
    // The first verification page is productive, so learned-only threshold
    // selection must rescue the remaining history.
    let (syncing, source) = run_pagination_scenario(100, Some(1000), Some(1000), 320).await;
    syncing.stop().await;
    source.stop().await;
}
