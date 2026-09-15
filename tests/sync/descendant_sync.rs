//! Scheduled repository-descendant synchronization scenarios.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{reserve_port, sync_helpers::*, TestRelay};

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

/// A tiny configured frontier exercises saturation and LMDB reconstruction
/// without needing a naturally popular production thread.
#[tokio::test]
async fn historic_recursive_cap_is_enforced_and_reconstructed_after_restart() {
    const LIMIT: usize = 2;

    let source = TestRelay::start_with_relay_max_subscriptions(4).await;
    let keys = Keys::generate();
    let repo_id = "restart-safe-recursive-cap";
    let syncing_reservation = reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_reservation.port());
    let source_domains = [source.domain(), syncing_domain];
    let source_refs = source_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (_announcement, repository) =
        setup_announcement_on_relay(&source, &keys, &source_refs, repo_id).await;
    let source_client = TestClient::new(source.url(), keys.clone())
        .await
        .expect("connect to source relay");
    let issue = build_layer2_issue_event(&keys, &repo_coord(&keys, repo_id), "Recursive cap root")
        .expect("build issue");
    let direct = build_layer3_reply_with_e_tag(&keys, &issue.id, "Direct branch owner")
        .expect("build direct branch owner");
    let first = build_layer3_reply_with_e_tag(&keys, &direct.id, "First recursive descendant")
        .expect("build first recursive descendant");
    let second = build_layer3_reply_with_e_tag(&keys, &first.id, "Second recursive descendant")
        .expect("build second recursive descendant");
    let overflow = build_layer3_reply_with_e_tag(&keys, &second.id, "Beyond bounded frontier")
        .expect("build descendant beyond bounded frontier");
    for event in std::iter::once(&issue)
        .chain(std::iter::once(&direct))
        .chain([&first, &second, &overflow])
    {
        source_client
            .send_event(event)
            .await
            .expect("seed source event");
    }

    let syncing_git_dir = tempfile::tempdir().expect("create syncing git dir");
    let syncing_data_dir = tempfile::tempdir().expect("create syncing relay data dir");
    let syncing = TestRelay::start_on_reservation_persistent_sync_with_recursive_limit(
        syncing_reservation,
        None,
        true,
        syncing_git_dir.path().to_path_buf(),
        syncing_data_dir.path().to_path_buf(),
        LIMIT,
    )
    .await;
    repository.install(&syncing).await;

    for descendant in [&first, &second] {
        assert!(
            wait_for_event_on_relay(
                syncing.url(),
                Filter::new().id(descendant.id),
                Duration::from_secs(30),
            )
            .await,
            "the bounded frontier should recover {}",
            descendant.content
        );
    }
    assert!(
        wait_for_log(
            &syncing.log_path(),
            "Started queued descendant fallback query",
            Duration::from_secs(5),
        )
        .await,
        "the constrained source should reach saturation through historic fallback"
    );
    assert!(
        !wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(overflow.id),
            Duration::from_secs(10),
        )
        .await,
        "a full branch must not query through its last retained descendant"
    );

    let syncing = syncing.restart().await;
    let late_child = build_layer3_reply_with_e_tag(&keys, &second.id, "Late recursive child")
        .expect("build late recursive child");
    let progress_marker =
        build_layer3_reply_with_e_tag(&keys, &issue.id, "Unmetered direct progress marker")
            .expect("build direct progress marker");
    source_client.send_event(&late_child).await.unwrap();
    source_client.send_event(&progress_marker).await.unwrap();
    assert!(
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(progress_marker.id),
            Duration::from_secs(20),
        )
        .await,
        "the restarted relay should continue direct/core live sync"
    );
    for excluded in [&overflow, &late_child] {
        assert!(
            !wait_for_event_on_relay(
                syncing.url(),
                Filter::new().id(excluded.id),
                Duration::from_secs(10),
            )
            .await,
            "restart must reconstruct the full branch and leave {} outside its query frontier",
            excluded.content
        );
    }

    source_client.disconnect().await;
    syncing.stop().await;
    source.stop().await;
}

/// Events which reference a direct repository-thread member, but not the
/// repository or its root event, are recovered recursively by the scheduled
/// historic pass while the direct member's branch remains below its allowance.
#[tokio::test]
async fn historic_sync_recovers_recursive_parent_only_descendants() {
    let source = TestRelay::start_with_relay_max_subscriptions(4).await;
    let keys = Keys::generate();
    let repo_id = "scheduled-descendant-history";

    // Seed the source before the syncing relay exists so this exercises the
    // complete historic rotation, not ordinary live coverage.
    let syncing_reservation = reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_reservation.port());
    let source_domains = [source.domain(), syncing_domain];
    let source_refs = source_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (_announcement, repository) =
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

    let syncing =
        TestRelay::start_on_reservation_with_options(syncing_reservation, None, false).await;
    repository.install(&syncing).await;

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
        wait_for_event_on_relay(
            syncing.url(),
            Filter::new().id(recursive.id),
            Duration::from_secs(20),
        )
        .await,
        "a retained recursive descendant must extend its branch frontier"
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
    let syncing_reservation = reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_reservation.port());
    let source_domains = [source.domain(), syncing_domain];
    let source_refs = source_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (_announcement, repository) =
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

    let syncing =
        TestRelay::start_on_reservation_with_options(syncing_reservation, None, false).await;
    repository.install(&syncing).await;
    assert!(
        wait_for_log(
            &syncing.log_path(),
            "Installed priority-bounded auxiliary live coverage",
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

/// A direct addressable thread member extends the non-recursive frontier by
/// its coordinate as well as its event ID. Descendants which carry only an
/// address tag must therefore be recovered by a constrained relay's historic
/// fallback rotation.
#[tokio::test]
async fn historic_sync_recovers_address_tag_descendants() {
    let source = TestRelay::start_with_relay_max_subscriptions(4).await;
    let keys = Keys::generate();
    let repo_id = "addressable-descendant-history";
    let syncing_reservation = reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_reservation.port());
    let source_domains = [source.domain(), syncing_domain];
    let source_refs = source_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (_announcement, repository) =
        setup_announcement_on_relay(&source, &keys, &source_refs, repo_id).await;
    let source_client = TestClient::new(source.url(), keys.clone())
        .await
        .expect("connect to source relay");
    let issue = build_layer2_issue_event(
        &keys,
        &repo_coord(&keys, repo_id),
        "Addressable descendant root",
    )
    .expect("build issue");
    let direct_addressable = EventBuilder::new(Kind::Custom(30_023), "Direct article")
        .tags([
            Tag::custom("d", ["direct-article"]),
            Tag::custom("e", [issue.id.to_hex()]),
        ])
        .finalize(&keys)
        .expect("build direct addressable member");
    let coordinate = format!(
        "30023:{}:direct-article",
        direct_addressable.pubkey.to_hex()
    );
    let address_only_children = ["a", "A", "q"].map(|tag| {
        EventBuilder::new(Kind::Custom(1_111), format!("{tag}-tag child"))
            .tag(Tag::custom(tag, [coordinate.clone()]))
            .finalize(&keys)
            .expect("build address-only child")
    });
    source_client.send_event(&issue).await.unwrap();
    source_client.send_event(&direct_addressable).await.unwrap();
    for event in &address_only_children {
        source_client.send_event(event).await.unwrap();
    }

    let syncing =
        TestRelay::start_on_reservation_with_options(syncing_reservation, None, false).await;
    repository.install(&syncing).await;

    for event in &address_only_children {
        assert!(
            wait_for_event_on_relay(
                syncing.url(),
                Filter::new().id(event.id),
                Duration::from_secs(25),
            )
            .await,
            "historic fallback should recover the {} child",
            event.content
        );
    }
    assert!(
        wait_for_log(
            &syncing.log_path(),
            "Started queued descendant fallback query",
            Duration::from_secs(5),
        )
        .await,
        "the constrained source should exercise coordinate fallback filters"
    );

    source_client.disconnect().await;
    syncing.stop().await;
    source.stop().await;
}
