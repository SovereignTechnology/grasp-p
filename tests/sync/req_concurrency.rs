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
//! therefore seeds a complete persistent event database before starting
//! the relay, exactly the production startup shape. Unbounded subscription
//! creation draws rejections at that startup; the bounded client must draw
//! none while still overlapping REQs and completing the sync.
//!
//! See docs/explanation/sync-scaling-constraints.md for the budget model.

use std::time::Duration;

use nostr_lmdb::NostrLmdb;
use nostr_sdk::prelude::*;

use crate::common::purgatory_helpers::{
    create_state_event, create_test_repo_with_commit, push_to_relay, CommitVariant,
};
use crate::common::req_limiting_proxy::ReqLimitingProxy;
use crate::common::sync_helpers::{
    build_layer3_reply_with_e_tag, fetch_metrics, repo_coord, send_to_relay,
    wait_for_event_on_relay, TestClient,
};
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

/// Wait for confirmed historic coverage, not total network silence. The
/// responsive actor continues NIP-65 discovery while history is complete.
async fn wait_for_historic_completion(
    syncing: &TestRelay,
    proxy: &ReqLimitingProxy,
    min_total: usize,
    deadline: Duration,
) -> Option<(usize, usize)> {
    let status_prefix = format!("ngit_sync_relay_connected{{relay=\"{}\"}} ", proxy.url());
    tokio::time::timeout(deadline, async {
        loop {
            let opened = proxy.opened_count();
            let rejected = proxy.rejected_count();
            let confirmed = fetch_metrics(syncing.url())
                .await
                .ok()
                .is_some_and(|metrics| {
                    metrics
                        .lines()
                        .any(|line| line.strip_prefix(&status_prefix) == Some("3"))
                });
            if confirmed && opened + rejected >= min_total {
                return (opened, rejected);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .ok()
}

/// Scenario:
/// 1. Source relay hosts one repository (announcement + state + git data)
///    and 2500 historic issues, each a root event of that repository.
/// 2. A proxy in front of the source enforces the strfry-style limit of 5
///    concurrent transient REQs and records peak concurrency and
///    rejections.
/// 3. Seed all roots and repository metadata in the stopped target's LMDB,
///    verifying that every root is present before starting it.
/// 4. Startup reconstructs filters from those 2500 root events, producing
///    one historic batch with more REQ groups than the concurrency limit.
/// 5. Source-only descendants must arrive and startup sync must complete
///    without a single rejection while keeping REQs overlapping.
#[tokio::test]
async fn startup_historic_sync_stays_within_relay_req_concurrency_limit() {
    // 1. Pre-allocate the syncing relay port for announcement tags.
    let syncing_reservation = port::reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_reservation.port());

    // 2. Source relay with the strfry-style limiting proxy in front. The
    //    announcement's relays tag lists the proxy (so the syncing relay
    //    targets the proxied connection), not the source itself, so the
    //    source runs in archive-all mode to accept it.
    // The source applies the production outbound target policy so it does
    // not itself sync through the proxy that fronts it: the proxy's REQ
    // budget belongs to the syncing relay under test.
    let source = TestRelay::start_archive_source_behind_proxy().await;
    // Production starts background queries one second apart. Hold EOSE long
    // enough for six starts so the five-request cap, not pacing, prevents the
    // sixth concurrent subscription. The proxy keeps reading while delaying.
    let proxy = ReqLimitingProxy::start_with_eose_delay(
        source.url(),
        PROXY_REQ_LIMIT,
        Duration::from_secs(6),
    )
    .await;

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
    let mut issues = Vec::with_capacity(ISSUE_COUNT);
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
            issues.push(issue);
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

    // Prepare exactly the state this regression targets: a previously populated
    // persistent database. Incremental discovery of 2500 roots exercises a
    // different path and spends its time rebuilding live/mailbox inventories;
    // requiring that bootstrap here made setup depend on CPU throughput.
    let syncing_git_dir = tempfile::tempdir().expect("create syncing git dir");
    let syncing_data_dir = tempfile::tempdir().expect("create syncing relay data dir");
    let repository_path = syncing_git_dir.path().join(&npub).join("req-repo.git");
    std::fs::create_dir_all(repository_path.parent().unwrap()).expect("create repository owner");
    let clone = grasp_audit::git_command()
        .arg("clone")
        .arg("--bare")
        .arg(git_temp_dir.path())
        .arg(&repository_path)
        .output()
        .expect("clone persisted repository");
    assert!(
        clone.status.success(),
        "{}",
        String::from_utf8_lossy(&clone.stderr)
    );
    // SovTech seam: a bare clone is the legacy storage layout, so the relay
    // would first migrate it to identifier families, before serving HTTP and
    // inside the harness's 5 s readiness budget, which a slow CI runner
    // overran. A node that ran before already has current storage.
    let migration = ngit_grasp::git::migration::migrate_on_startup(
        &ngit_grasp::git::storage::LocalGitStorage::new(syncing_git_dir.path()),
    )
    .await
    .expect("migrate persisted repository");
    // A retained backup would leave the relay its own retirement to finish.
    assert_eq!(
        (migration.migrated_views, migration.retained_backups),
        (1, 0),
        "the persisted repository must be on current storage before startup"
    );
    {
        let database = NostrLmdb::builder(syncing_data_dir.path())
            .process_nip09(false)
            .process_nip62(false)
            .build()
            .await
            .expect("open fixture database");
        for event in [&announcement, &state_event]
            .into_iter()
            .chain(issues.iter())
        {
            database
                .save_event(event)
                .await
                .expect("seed persisted event");
        }
        let persisted = database
            .query(Filter::new().ids(issue_ids.clone()))
            .await
            .expect("query persisted roots");
        assert_eq!(
            persisted.len(),
            ISSUE_COUNT,
            "every root must be persisted before startup"
        );
    }

    // Replies exist only at the source. Their parents span the sorted root
    // inventory, so successful startup must hydrate descendants from its
    // reconstructed byte-budgeted filters, not merely read our seeded events.
    let mut sorted_roots = issue_ids.clone();
    sorted_roots.sort();
    let mut replies = Vec::new();
    for index in [0, ISSUE_COUNT / 2, ISSUE_COUNT - 1] {
        let reply = build_layer3_reply_with_e_tag(
            &keys,
            &sorted_roots[index],
            &format!("Startup descendant {index}"),
        )
        .expect("build source-only reply");
        send_to_relay(&source, &reply)
            .await
            .expect("seed source-only reply");
        replies.push(reply);
    }

    let syncing = TestRelay::start_on_reservation_persistent_sync(
        syncing_reservation,
        Some(proxy.url().to_string()),
        true,
        syncing_git_dir.path().to_path_buf(),
        syncing_data_dir.path().to_path_buf(),
    )
    .await;

    for reply in replies {
        assert!(
            wait_for_event_on_relay(
                syncing.url(),
                Filter::new().id(reply.id),
                Duration::from_secs(120)
            )
            .await,
            "source-only descendant must arrive through startup historic sync"
        );
    }
    let (opened, rejected) =
        wait_for_historic_completion(&syncing, &proxy, 7, Duration::from_secs(120))
            .await
            .expect("startup historic coverage should be confirmed");

    // The regression assertions apply to the populated-index startup.
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
        proxy.peak_concurrent() > 1,
        "startup must overlap transient REQs to exercise concurrent admission"
    );
    assert!(
        opened > PROXY_REQ_LIMIT,
        "scenario must open more REQs than the bound to exercise queueing, opened: {opened}"
    );

    syncing.stop().await;
    proxy.stop().await;
    source.stop().await;
}
