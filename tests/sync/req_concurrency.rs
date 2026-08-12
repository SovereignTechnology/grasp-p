//! Transient REQ Concurrency Bound Tests
//!
//! Regression coverage for a production failure observed on gitnostr.com:
//! historic REQ+EOSE sync subscribed every byte-budgeted filter group of a
//! batch in one fast loop and left them all open concurrently until EOSE.
//! On strfry-family relays REQ subscriptions share `maxSubsPerConnection`
//! with negentropy views and live subscriptions; nos.lol (budget 20)
//! answered each gitnostr.com startup with a burst of
//! "ERROR: too many concurrent REQs" NOTICEs (6 in one second at the
//! 2026-08-05 startup; 7,739 over the prior three days).
//!
//! The scenario drives the real sync path end to end: a genuine ngit-grasp
//! source relay sits behind a proxy that mimics the strfry limit, rejecting
//! REQ frames beyond 5 concurrent transient subscriptions. The syncing
//! relay runs with negentropy disabled so historic sync takes the REQ+EOSE
//! path, and the watched set is sized so that one startup batch needs more
//! REQ groups than the limit (2500 root events → six byte-budgeted chunks →
//! 18 e/E/q filters; two full 32 KB filters fill a 96 KB REQ group, giving
//! ~8 groups).
//!
//! The burst only occurs when startup recomputes filters from an
//! already-populated index — during initial discovery, root events trickle
//! in through short batching windows and batches stay small. The scenario
//! therefore syncs everything into persistent storage first, then restarts
//! the relay, exactly the production startup shape. Unbounded subscription
//! creation draws rejections at that startup; the bounded client must draw
//! none while still overlapping REQs and completing the sync.
//!
//! See docs/explanation/sync-scaling-constraints.md for the budget model.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::purgatory_helpers::{
    create_state_event, create_test_repo_with_commit, push_to_relay, CommitVariant,
};
use crate::common::req_limiting_proxy::ReqLimitingProxy;
use crate::common::sync_helpers::{repo_coord, send_to_relay, wait_for_event_on_relay, TestClient};
use crate::common::{port, TestRelay};

/// Concurrency limit enforced by the proxy.
///
/// Matches `MAX_CONCURRENT_TRANSIENT_REQS` in `sync::relay_connection`: the
/// test relay must stay within its own advertised bound, so a relay
/// enforcing exactly that bound must never reject a REQ.
const PROXY_REQ_LIMIT: usize = 5;

/// Root events to seed. Byte-budgeted chunking fits ~489 hex event IDs per
/// filter (32 KB of serialized tag values), so 2500 IDs split into six
/// chunks; six chunks × three tag variants (e/E/q) give 18 filters, and two
/// full 32 KB filters fill a 96 KB REQ group — roughly eight groups in a
/// single historic batch, more concurrent REQ subscriptions than the bound,
/// so bounded scheduling is required to avoid rejections.
const ISSUE_COUNT: usize = 2500;

/// Wait until the proxy has seen at least `min_total` transient REQs
/// (opened + rejected) and the count has been stable for `stable_for`.
///
/// Returns the final (opened, rejected) pair, or `None` on deadline.
async fn wait_for_req_quiescence(
    proxy: &ReqLimitingProxy,
    min_total: usize,
    stable_for: Duration,
    deadline: Duration,
) -> Option<(usize, usize)> {
    let end = tokio::time::Instant::now() + deadline;
    let mut last_total = 0usize;
    let mut stable_since = tokio::time::Instant::now();
    loop {
        let opened = proxy.opened_count();
        let rejected = proxy.rejected_count();
        let total = opened + rejected;
        if total != last_total {
            last_total = total;
            stable_since = tokio::time::Instant::now();
        } else if total >= min_total && stable_since.elapsed() >= stable_for {
            return Some((opened, rejected));
        }
        if tokio::time::Instant::now() >= end {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Scenario:
/// 1. Source relay hosts one repository (announcement + state + git data)
///    and 2500 historic issues, each a root event of that repository.
/// 2. A proxy in front of the source enforces the strfry-style limit of 5
///    concurrent transient REQs and records peak concurrency and
///    rejections.
/// 3. The syncing relay (negentropy disabled, persistent storage)
///    bootstraps through the proxy and syncs all issues.
/// 4. The syncing relay restarts. Startup recomputes sync filters from the
///    persisted index of 2500 root events, producing one historic batch
///    with ~8 REQ groups — more than the limit.
/// 5. The relay must complete that startup sync without a single rejection
///    while still keeping REQ subscriptions overlapping.
#[tokio::test]
async fn startup_historic_sync_stays_within_relay_req_concurrency_limit() {
    // 1. Pre-allocate the syncing relay port for announcement tags.
    let syncing_reservation = port::reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_reservation.port());

    // 2. Source relay with the strfry-style limiting proxy in front. The
    //    announcement's relays tag lists the proxy (so the syncing relay
    //    targets the proxied connection), not the source itself, so the
    //    source runs in archive-all mode to accept it.
    let source = TestRelay::start_with_archive_config(true, false).await;
    let proxy = ReqLimitingProxy::start(source.url(), PROXY_REQ_LIMIT).await;

    // 3. One hosted repository: announcement + state event + git data. The
    //    relays tag lists the proxy so the syncing relay targets the proxied
    //    connection for this repository's sync work.
    let git_temp_dir = tempfile::tempdir().expect("create temp dir for git repo");
    let commit_hash = create_test_repo_with_commit(git_temp_dir.path(), CommitVariant::StateTest)
        .expect("create test git repo");

    let keys = Keys::generate();
    let npub = keys.public_key().to_bech32().expect("npub");
    let clone_urls = vec![
        format!("http://{}/{}/req-repo.git", source.domain(), npub),
        format!("http://{}/{}/req-repo.git", syncing_domain, npub),
    ];
    let relay_urls = vec![proxy.url().to_string(), format!("ws://{}", syncing_domain)];

    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Repository state")
        .tags(vec![
            Tag::identifier("req-repo"),
            Tag::custom("clone", clone_urls.clone()),
            Tag::custom("relays", relay_urls.clone()),
        ])
        .finalize(&keys)
        .expect("sign repo announcement");
    let state_event = create_state_event(
        &keys,
        "req-repo",
        &[("main", &commit_hash)],
        &[],
        &clone_urls.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        &relay_urls.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    )
    .expect("create state event");

    send_to_relay(&source, &announcement)
        .await
        .expect("send announcement to source");
    send_to_relay(&source, &state_event)
        .await
        .expect("send state event to source");
    push_to_relay(git_temp_dir.path(), &source.domain(), &npub, "req-repo")
        .expect("push git data to source relay");

    // The push releases the announcement from purgatory; wait until the
    // source actually serves it before seeding dependent events.
    assert!(
        wait_for_event_on_relay(
            source.url(),
            Filter::new().id(announcement.id),
            Duration::from_secs(15),
        )
        .await,
        "announcement should be released from purgatory on the source"
    );

    // 4. Seed historic issues; each becomes a tracked root event once
    //    synced. One persistent client keeps seeding fast, and distinct
    //    descending created_at timestamps let REQ+EOSE pagination cursors
    //    (until = oldest seen) terminate instead of re-fetching the same
    //    page forever.
    let coordinate = repo_coord(&keys, "req-repo");
    let base_created_at = Timestamp::now().as_secs() - ISSUE_COUNT as u64 - 10;

    // The embedded relay rate-limits notes per minute PER CONNECTION with a
    // full initial token bucket, so seed through a fresh connection per
    // batch, each batch staying under the initial burst allowance.
    const SEED_BATCH: usize = 50;
    let mut issue_ids = Vec::with_capacity(ISSUE_COUNT);
    for batch_start in (0..ISSUE_COUNT).step_by(SEED_BATCH) {
        let seed_client = TestClient::new(source.url(), Keys::generate())
            .await
            .expect("connect seed client to source");
        for index in batch_start..(batch_start + SEED_BATCH).min(ISSUE_COUNT) {
            let issue = EventBuilder::new(Kind::GitIssue, format!("Historic issue {index}"))
                .tags(vec![Tag::custom("a", vec![coordinate.clone()])])
                .custom_created_at(Timestamp::from(base_created_at + index as u64))
                .finalize(&keys)
                .expect("sign issue event");
            issue_ids.push(issue.id);
            seed_client
                .send_event(&issue)
                .await
                .expect("send issue to source");
        }
        seed_client.disconnect().await;
    }

    // Seeding sanity: the last issue must be queryable on the source before
    // the syncing relay is pointed at it.
    assert!(
        wait_for_event_on_relay(
            source.url(),
            Filter::new().id(issue_ids[ISSUE_COUNT - 1]),
            Duration::from_secs(15),
        )
        .await,
        "seeded issues should be accepted by the source relay"
    );

    // 5. Phase 1: the syncing relay (negentropy disabled) bootstraps
    //    through the proxy and syncs everything into persistent storage.
    //    Root events trickle in through short batching windows here, so
    //    historic batches stay small; the burst this test guards against
    //    comes at the next startup.
    let syncing_git_dir = tempfile::tempdir().expect("create syncing git dir");
    let syncing_data_dir = tempfile::tempdir().expect("create syncing relay data dir");
    let syncing = TestRelay::start_on_reservation_persistent_sync(
        syncing_reservation,
        Some(proxy.url().to_string()),
        true,
        syncing_git_dir.path().to_path_buf(),
        syncing_data_dir.path().to_path_buf(),
    )
    .await;

    // 6. The issues must arrive via historic sync (sampled ends of the
    //    range cover the byte-budgeted chunks).
    for issue_id in [
        issue_ids[0],
        issue_ids[ISSUE_COUNT / 2],
        issue_ids[ISSUE_COUNT - 1],
    ] {
        assert!(
            wait_for_event_on_relay(
                syncing.url(),
                Filter::new().id(issue_id),
                Duration::from_secs(120),
            )
            .await,
            "issue should reach the syncing relay through historic sync"
        );
    }

    // 7. Let phase-1 REQ activity settle, then restart. Startup recomputes
    //    sync filters from the full persisted index (2500 root events),
    //    producing one historic batch with ~8 byte-budgeted REQ groups —
    //    the production startup burst.
    wait_for_req_quiescence(&proxy, 1, Duration::from_secs(3), Duration::from_secs(120))
        .await
        .expect("phase-1 REQ activity should settle before restart");
    let before_restart = proxy.opened_count() + proxy.rejected_count();

    let syncing = syncing.restart().await;

    // 8. Wait for the startup burst to complete and settle: the restarted
    //    relay re-syncs the repository batch and the ~8 root-event groups.
    let (opened, rejected) = wait_for_req_quiescence(
        &proxy,
        before_restart + 7,
        Duration::from_secs(3),
        Duration::from_secs(120),
    )
    .await
    .expect("restart REQ burst should complete and settle");

    // 9. The regression assertions (cumulative across both phases; the
    //    trickle-shaped phase 1 must stay within the bound too).
    assert_eq!(
        rejected,
        0,
        "relay exceeded the per-connection REQ concurrency limit \
         (opened: {opened}, peak: {})",
        proxy.peak_concurrent()
    );
    assert!(
        proxy.peak_concurrent() <= PROXY_REQ_LIMIT,
        "peak concurrent transient REQs {} exceeded the bound {PROXY_REQ_LIMIT}",
        proxy.peak_concurrent()
    );
    assert!(
        proxy.peak_concurrent() >= 2,
        "transient REQs should still overlap under the bound, peak: {}",
        proxy.peak_concurrent()
    );
    assert!(
        opened > PROXY_REQ_LIMIT,
        "scenario must open more REQs than the bound to exercise queueing, opened: {opened}"
    );

    syncing.stop().await;
    proxy.stop().await;
    source.stop().await;
}
