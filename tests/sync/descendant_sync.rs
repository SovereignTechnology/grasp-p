//! Scheduled repository-descendant synchronization scenarios.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{sync_helpers::*, TestRelay};

async fn wait_for_log(path: &std::path::Path, needle: &str, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if std::fs::read_to_string(path)
            .unwrap_or_default()
            .contains(needle)
        {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Events which reference a direct repository-thread member, but not the
/// repository or its root event, are recovered by the scheduled historic
/// pass. The recovered events do not recursively extend the frontier.
#[tokio::test]
async fn historic_sync_recovers_one_generation_of_parent_only_descendants() {
    let source = TestRelay::start_with_relay_max_subscriptions(5).await;
    let keys = Keys::generate();
    let repo_id = "scheduled-descendant-history";

    // Seed the source before the syncing relay exists so this exercises the
    // complete historic rotation, not ordinary live coverage.
    let source_domains = [source.domain()];
    let source_refs = source_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (_announcement, _source_git) =
        setup_announcement_on_relay(&source, &keys, &source_refs, repo_id).await;
    let source_client = TestClient::new(source.url(), keys.clone())
        .await
        .expect("connect to source relay");
    let issue =
        build_layer2_issue_event(&keys, &repo_coord(&keys, repo_id), "Repository thread root")
            .expect("build issue");
    let direct_reply = build_layer3_reply_with_e_tag(&keys, &issue.id, "Direct reply")
        .expect("build direct reply");
    let parent_only = build_layer3_reply_with_e_tag(
        &keys,
        &direct_reply.id,
        "Reply visible only through the scheduled descendant query",
    )
    .expect("build parent-only descendant");
    let recursive = build_layer3_reply_with_e_tag(
        &keys,
        &parent_only.id,
        "Deliberately out-of-scope recursive descendant",
    )
    .expect("build recursive descendant");
    for event in [&issue, &direct_reply, &parent_only, &recursive] {
        source_client
            .send_event(event)
            .await
            .expect("seed source event");
    }

    let syncing = TestRelay::start_with_sync(None).await;
    let domains = [source.domain(), syncing.domain()];
    let domain_refs = domains.iter().map(String::as_str).collect::<Vec<_>>();
    let (_target_announcement, _target_git) =
        setup_announcement_on_relay(&syncing, &keys, &domain_refs, repo_id).await;

    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(parent_only.id),
            Duration::from_secs(20),
        )
        .await,
        "scheduled historic rotation should recover a parent-only descendant"
    );
    assert!(
        wait_for_log(
            &syncing.log_path(),
            "Started queued descendant fallback query",
            Duration::from_secs(5),
        )
        .await,
        "the constrained source should exercise EOSE-closing fallback"
    );
    assert!(
        !wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(recursive.id),
            Duration::from_secs(7),
        )
        .await,
        "recovered descendants must not recursively extend the frontier"
    );

    source_client.disconnect().await;
    syncing.stop().await;
    source.stop().await;
}

/// A relay with spare NIP-11 subscription capacity receives permanent
/// descendant coverage, so a later parent-only event arrives without waiting
/// for the fallback rotation.
#[tokio::test]
async fn descendant_live_coverage_is_preferred_when_capacity_remains() {
    let source = TestRelay::start().await;
    let keys = Keys::generate();
    let repo_id = "live-descendant-coverage";
    let source_domains = [source.domain()];
    let source_refs = source_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (_announcement, _source_git) =
        setup_announcement_on_relay(&source, &keys, &source_refs, repo_id).await;
    let source_client = TestClient::new(source.url(), keys.clone())
        .await
        .expect("connect to source relay");
    let issue = build_layer2_issue_event(&keys, &repo_coord(&keys, repo_id), "Live root")
        .expect("build issue");
    let direct_reply = build_layer3_reply_with_e_tag(&keys, &issue.id, "Direct reply")
        .expect("build direct reply");
    source_client.send_event(&issue).await.unwrap();
    source_client.send_event(&direct_reply).await.unwrap();

    let syncing = TestRelay::start_with_sync(None).await;
    let domains = [source.domain(), syncing.domain()];
    let domain_refs = domains.iter().map(String::as_str).collect::<Vec<_>>();
    let (_target_announcement, _target_git) =
        setup_announcement_on_relay(&syncing, &keys, &domain_refs, repo_id).await;
    assert!(
        wait_for_log(
            &syncing.log_path(),
            "Installed auxiliary descendant live coverage",
            Duration::from_secs(20),
        )
        .await,
        "spare source capacity should retain descendant coverage"
    );

    let parent_only =
        build_layer3_reply_with_e_tag(&keys, &direct_reply.id, "Arrives through live coverage")
            .expect("build parent-only descendant");
    source_client.send_event(&parent_only).await.unwrap();
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(parent_only.id),
            Duration::from_secs(10),
        )
        .await,
        "parent-only descendant should arrive through retained live coverage"
    );

    source_client.disconnect().await;
    syncing.stop().await;
    source.stop().await;
}
