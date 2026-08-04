//! Negentropy Concurrency Bound Tests
//!
//! Regression coverage for a production failure observed on gitnostr.com
//! (2026-08-04): startup historic sync opened one NIP-77 negentropy round per
//! filter with no bound (146 filters in one batch on the bootstrap relay),
//! exceeding relay per-connection subscription budgets. nos.lol — a strfry
//! relay advertising `max_subscriptions: 20`, a budget shared between
//! ordinary subscriptions and negentropy views — answered with 34
//! "ERROR: too many concurrent NEG requests" NOTICEs, and the burst produced
//! 61 per-filter timeouts and 21 failed fallback-subscription creations in
//! the first two minutes after startup.
//!
//! The scenario drives the real sync path end to end: a genuine ngit-grasp
//! source relay (real NIP-77) sits behind a proxy that mimics the strfry
//! limit, rejecting NEG-OPEN frames beyond 4 concurrent rounds. The watched
//! set is sized so that one historic batch needs more negentropy rounds than
//! the limit (260 root events → two byte-budgeted chunks × three tag variants
//! = six filters). Unbounded concurrency draws rejections; the bounded client must
//! draw none while still overlapping rounds and completing the sync.
//!
//! See docs/explanation/sync-scaling-constraints.md for the budget model.

use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::neg_limiting_proxy::NegLimitingProxy;
use crate::common::purgatory_helpers::{
    create_state_event, create_test_repo_with_commit, push_to_relay, CommitVariant,
};
use crate::common::sync_helpers::{
    build_layer2_issue_event, repo_coord, send_to_relay, wait_for_event_on_relay,
};
use crate::common::{port, TestRelay};

/// Concurrency limit enforced by the proxy.
///
/// Matches `MAX_CONCURRENT_NEG_DIFFS` in `sync::relay_connection`: the test
/// relay must stay within its own advertised bound, so a relay enforcing
/// exactly that bound must never reject a round.
const PROXY_NEG_LIMIT: usize = 4;

/// Root events to seed. Byte-budgeted chunking fits ~244 hex event IDs per
/// filter (16 KB of serialized tag values), so 260 IDs split into two chunks;
/// two chunks × three tag variants (e/E/q) give six negentropy filters in a
/// single historic batch — more rounds than the bound, so bounded scheduling
/// is required to avoid rejections.
const ISSUE_COUNT: usize = 260;

/// Wait until the proxy has seen at least `min_total` NEG rounds
/// (opened + rejected) and the count has been stable for `stable_for`.
///
/// Returns the final (opened, rejected) pair, or `None` on deadline.
async fn wait_for_neg_quiescence(
    proxy: &NegLimitingProxy,
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
/// 1. Source relay hosts one repository (announcement + state + git data) and
///    260 historic issues, each a root event of that repository.
/// 2. A proxy in front of the source enforces the strfry-style limit of 4
///    concurrent NEG rounds and records peak concurrency and rejections.
/// 3. The syncing relay bootstraps through the proxy. Syncing the issues
///    registers 260 root events, whose next historic batch needs six
///    negentropy rounds — more than the limit.
/// 4. The syncing relay must complete historic sync without a single
///    rejection while still running rounds concurrently.
#[tokio::test]
async fn startup_historic_sync_stays_within_relay_neg_concurrency_limit() {
    // 1. Pre-allocate the syncing relay port for announcement tags.
    let syncing_reservation = port::reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_reservation.port());

    // 2. Source relay with the strfry-style limiting proxy in front. The
    //    announcement's relays tag lists the proxy (so the syncing relay
    //    targets the proxied connection), not the source itself, so the
    //    source runs in archive-all mode to accept it.
    let source = TestRelay::start_with_archive_config(true, false).await;
    let proxy = NegLimitingProxy::start(source.url(), PROXY_NEG_LIMIT).await;

    // 3. One hosted repository: announcement + state event + git data. The
    //    relays tag lists the proxy so the syncing relay targets the proxied
    //    connection for this repository's sync work.
    let git_temp_dir = tempfile::tempdir().expect("create temp dir for git repo");
    let commit_hash = create_test_repo_with_commit(git_temp_dir.path(), CommitVariant::StateTest)
        .expect("create test git repo");

    let keys = Keys::generate();
    let npub = keys.public_key().to_bech32().expect("npub");
    let clone_urls = vec![
        format!("http://{}/{}/neg-repo.git", source.domain(), npub),
        format!("http://{}/{}/neg-repo.git", syncing_domain, npub),
    ];
    let relay_urls = vec![proxy.url().to_string(), format!("ws://{}", syncing_domain)];

    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Repository state")
        .tags(vec![
            Tag::identifier("neg-repo"),
            Tag::custom("clone", clone_urls.clone()),
            Tag::custom("relays", relay_urls.clone()),
        ])
        .finalize(&keys)
        .expect("sign repo announcement");
    let state_event = create_state_event(
        &keys,
        "neg-repo",
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
    push_to_relay(git_temp_dir.path(), &source.domain(), &npub, "neg-repo")
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

    // 4. Seed historic issues; each becomes a tracked root event once synced.
    let coordinate = repo_coord(&keys, "neg-repo");
    let mut issue_ids = Vec::with_capacity(ISSUE_COUNT);
    for index in 0..ISSUE_COUNT {
        let issue = build_layer2_issue_event(&keys, &coordinate, &format!("Issue {index}"))
            .expect("build issue event");
        issue_ids.push(issue.id);
        send_to_relay(&source, &issue)
            .await
            .expect("send issue to source");
    }

    // 5. Syncing relay bootstraps through the proxy.
    let syncing = TestRelay::start_on_reservation_with_options(
        syncing_reservation,
        Some(proxy.url().to_string()),
        false,
    )
    .await;

    // 6. The issues must arrive via the bounded historic sync (sampled ends
    //    of the range cover both byte-budgeted chunks).
    for issue_id in [issue_ids[0], issue_ids[ISSUE_COUNT / 2], issue_ids[ISSUE_COUNT - 1]] {
        assert!(
            wait_for_event_on_relay(
                syncing.url(),
                Filter::new().id(issue_id),
                Duration::from_secs(90),
            )
            .await,
            "issue should reach the syncing relay through bounded historic sync"
        );
    }

    // 7. Wait for negentropy activity to include the root-event batch and
    //    settle. Layer-1 plus the repository batch plus the six root-event
    //    rounds put the floor at eight.
    let (opened, rejected) = wait_for_neg_quiescence(
        &proxy,
        8,
        Duration::from_secs(3),
        Duration::from_secs(60),
    )
    .await
    .expect("negentropy rounds should reach the root-event batch and settle");

    // 8. The regression assertions.
    assert_eq!(
        rejected, 0,
        "relay exceeded the per-connection NEG concurrency limit \
         (opened: {opened}, peak: {})",
        proxy.peak_concurrent()
    );
    assert!(
        proxy.peak_concurrent() <= PROXY_NEG_LIMIT,
        "peak concurrent NEG rounds {} exceeded the bound {PROXY_NEG_LIMIT}",
        proxy.peak_concurrent()
    );
    assert!(
        proxy.peak_concurrent() >= 2,
        "negentropy rounds should still overlap under the bound, peak: {}",
        proxy.peak_concurrent()
    );
    assert!(
        opened > PROXY_NEG_LIMIT,
        "scenario must run more rounds than the bound to exercise queueing, opened: {opened}"
    );

    syncing.stop().await;
    proxy.stop().await;
    source.stop().await;
}
