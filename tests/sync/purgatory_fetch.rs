//! Purgatory Git Fetch Strategy Tests
//!
//! Regression coverage for a production failure observed on gitnostr.com
//! (2026-08-05, 07:56–08:41 UTC window): purgatory git sync requested every
//! needed commit id as an explicit want in a single
//! `git fetch <url> <oid1> <oid2> …`. When the remote's upload-pack rejected
//! one want with "not our ref", the retry loop parsed that single oid out of
//! stderr, removed it, and re-sent the entire remaining batch. Against the
//! `market` repository — whose state event declares ~470 ref tips that exist
//! on no reachable server — this produced a sorted oid-by-oid crawl:
//! 4,521 `Git upload-pack failed after streaming stdout: … not our ref`
//! errors in 45 minutes on the serving side, one failed upload-pack round
//! trip per missing tip with O(N²) want retransmission, and nothing fetched
//! until the loop had crawled through every missing oid.
//!
//! The agreed fix compares the remote's advertised ref list (`git ls-remote`
//! through the same hardened subprocess machinery) against the needed oids
//! first, batch-fetches only advertised tips (always valid wants, so
//! "not our ref" cannot occur for them), and only then requests residual
//! oids one at a time so a single missing object cannot fail a batch.
//!
//! The scenario drives the real purgatory sync path end to end: a genuine
//! ngit-grasp relay serves a repository with two real branch tips behind a
//! counting proxy, and the relay under test holds a state event declaring
//! those two tips plus eight tips that exist nowhere (mirroring `market`).
//! The proxy records every upload-pack POST with its `want` lines, so the
//! test can assert the shape of the outbound fetching, not just the result.

use crate::common::event_ordering::timestamp_after;
use std::path::Path;
use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::purgatory_helpers::{
    add_commit_to_repo, create_branch, create_state_event, create_test_repo_with_commit,
    push_to_relay, verify_event_not_served, wait_for_event_served, CommitVariant,
};
use crate::common::upload_pack_counting_proxy::UploadPackCountingProxy;
use crate::common::{port, MockRelay, TestRelay};

/// Declared ref tips that exist on no reachable server, mirroring the
/// `market` repository's unfetchable state event.
const MISSING_TIP_COUNT: usize = 8;

/// Wait until every given oid exists in the bare repository at `repo_path`.
async fn wait_for_oids_in_repo(repo_path: &Path, oids: &[&str], deadline: Duration) -> bool {
    let end = tokio::time::Instant::now() + deadline;
    loop {
        let all_present = repo_path.exists()
            && oids.iter().all(|oid| {
                grasp_audit::git_command()
                    .args(["cat-file", "-e", oid])
                    .current_dir(repo_path)
                    .output()
                    .map(|output| output.status.success())
                    .unwrap_or(false)
            });
        if all_present {
            return true;
        }
        if tokio::time::Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Wait until the proxy has observed at least `min_total` upload-pack
/// exchanges and the count has been stable for `stable_for`.
async fn wait_for_upload_pack_quiescence(
    proxy: &UploadPackCountingProxy,
    min_total: usize,
    stable_for: Duration,
    deadline: Duration,
) -> bool {
    let end = tokio::time::Instant::now() + deadline;
    let mut last_total = 0usize;
    let mut stable_since = tokio::time::Instant::now();
    loop {
        let total = proxy.exchanges().len();
        if total != last_total {
            last_total = total;
            stable_since = tokio::time::Instant::now();
        } else if total >= min_total && stable_since.elapsed() >= stable_for {
            return true;
        }
        if tokio::time::Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Scenario:
/// 1. A source relay hosts one repository with two distinct branch tips
///    (`main`, `feature`). Its own announcement/state clone URLs point only
///    at itself, so the source never fetches outbound.
/// 2. A counting proxy fronts the source's git smart-HTTP endpoint.
/// 3. The relay under test bootstrap-syncs from a MockRelay serving a
///    later announcement whose clone tag points at the proxy, plus a state
///    event declaring the two real tips and eight tips that exist nowhere.
///    Both events sit in purgatory; the purgatory sync loop fetches
///    through the proxy.
/// 4. The two real tips must arrive, and the outbound request shape must
///    not degrade into the production oid crawl:
///    - the first upload-pack request must succeed (available tips are
///      batch-fetched first, not after crawling through every missing oid);
///    - every failed upload-pack request must carry at most one want (a
///      single missing object must never fail a batch).
#[tokio::test]
async fn purgatory_fetch_batches_available_tips_and_isolates_missing_oids() {
    // 1. Source relay + counting proxy in front of its git endpoint, and
    //    the MockRelay that will carry the events for the relay under test.
    let source = TestRelay::start().await;
    let proxy = UploadPackCountingProxy::start(&format!("http://{}", source.domain())).await;
    let mock = MockRelay::start().await;

    // 2. Repository with two distinct branch tips: main → commit_b,
    //    feature → commit_a (commit_a is commit_b's parent).
    let git_dir = tempfile::tempdir().expect("create git repo dir");
    let commit_a = create_test_repo_with_commit(git_dir.path(), CommitVariant::StateTest)
        .expect("create first commit");
    let commit_b = add_commit_to_repo(git_dir.path(), CommitVariant::SecondCommit)
        .expect("create second commit");
    create_branch(git_dir.path(), "feature", Some(&commit_a)).expect("create feature branch");

    let keys = Keys::generate();
    let npub = keys.public_key().to_bech32().expect("npub");
    let identifier = "fetch-strategy-repo";

    // 3. Source-side events reference only the source itself, so the
    //    source's own purgatory sync has no external URL to fetch from and
    //    the proxy sees exclusively the relay under test.
    let source_clone_url = format!("http://{}/{}/{}.git", source.domain(), npub, identifier);
    let source_relay_url = format!("ws://{}", source.domain());
    let source_announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Fetch strategy repo")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom("clone", vec![source_clone_url.clone()]),
            Tag::custom("relays", vec![source_relay_url.clone()]),
        ])
        .finalize(&keys)
        .expect("sign source announcement");
    let source_state = create_state_event(
        &keys,
        identifier,
        &[("main", &commit_b), ("feature", &commit_a)],
        &[],
        &[&source_clone_url],
        &[&source_relay_url],
    )
    .expect("create source state event");

    let source_client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys.clone()))
        .build();
    source_client
        .add_relay(source.url())
        .await
        .expect("add source relay");
    source_client
        .connect()
        .and_wait(Duration::from_secs(30))
        .await;
    source_client
        .send_event(&source_announcement)
        .await
        .expect("send announcement to source");
    source_client
        .send_event(&source_state)
        .await
        .expect("send state event to source");

    // The state event in purgatory authorizes this push; the push releases
    // it, after which the source serves both branches over git HTTP.
    push_to_relay(git_dir.path(), &source.domain(), &npub, identifier)
        .expect("push git data to source relay");
    wait_for_event_served(source.url(), &source_state.id, Duration::from_secs(15))
        .await
        .expect("source state event should be released after push");

    // 4. Relay under test: a later announcement whose clone tag points at
    //    the proxy, plus a state event declaring the two real tips and
    //    MISSING_TIP_COUNT tips that exist nowhere. Both are served by a
    //    MockRelay (no validation, no purgatory, no outbound fetching of
    //    its own) configured as the bootstrap relay: events arriving via
    //    sync take the immediate purgatory-sync path instead of the
    //    3-minute wait-for-push delay applied to direct submissions.
    let syncing_reservation = port::reserve_port();
    let syncing_domain = format!("127.0.0.1:{}", syncing_reservation.port());
    let proxy_clone_url = format!("{}/{}/{}.git", proxy.url(), npub, identifier);
    let syncing_clone_url = format!("http://{}/{}/{}.git", syncing_domain, npub, identifier);
    let syncing_relay_url = format!("ws://{}", syncing_domain);

    // The relays tag must list the relay under test (so it accepts the
    // announcement) and the MockRelay (so the per-repo state subscription
    // targets the MockRelay and delivers the state event via sync).
    let syncing_announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Fetch strategy repo")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![proxy_clone_url.clone(), syncing_clone_url.clone()],
            ),
            Tag::custom(
                "relays",
                vec![syncing_relay_url.clone(), mock.url().to_string()],
            ),
        ])
        .finalize(&keys)
        .expect("sign syncing announcement");

    let missing_tips: Vec<String> = (0..MISSING_TIP_COUNT)
        .map(|index| format!("beef{index:036x}"))
        .collect();
    let missing_branch_names: Vec<String> = (0..MISSING_TIP_COUNT)
        .map(|index| format!("missing-{index}"))
        .collect();
    let mut branches: Vec<(&str, &str)> =
        vec![("main", commit_b.as_str()), ("feature", commit_a.as_str())];
    for (name, tip) in missing_branch_names.iter().zip(missing_tips.iter()) {
        branches.push((name.as_str(), tip.as_str()));
    }
    let syncing_state = create_state_event(
        &keys,
        identifier,
        &branches,
        &[],
        &[&proxy_clone_url, &syncing_clone_url],
        &[&syncing_relay_url, mock.url()],
    )
    .expect("create syncing state event");

    let mock_client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys.clone()))
        .build();
    mock_client
        .add_relay(mock.url())
        .await
        .expect("add mock relay");
    mock_client
        .connect()
        .and_wait(Duration::from_secs(30))
        .await;
    mock_client
        .send_event(&syncing_announcement)
        .await
        .expect("send announcement to mock relay");
    mock_client
        .send_event(&syncing_state)
        .await
        .expect("send state event to mock relay");

    // Negentropy is disabled because MockRelay does not support NIP-77.
    let syncing = TestRelay::start_on_reservation_with_options(
        syncing_reservation,
        Some(mock.url().to_string()),
        true,
    )
    .await;

    // 5. The two real tips must arrive through purgatory sync.
    let repo_path = syncing
        .git_data_path()
        .join(&npub)
        .join(format!("{identifier}.git"));
    assert!(
        wait_for_oids_in_repo(
            &repo_path,
            &[commit_a.as_str(), commit_b.as_str()],
            Duration::from_secs(90),
        )
        .await,
        "available tips should be fetched into {} despite the unfetchable \
         tips declared alongside them (proxy exchanges: {:?})",
        repo_path.display(),
        proxy.exchanges(),
    );

    // 6. Let the sync pass finish so requests aimed at the missing tips
    //    (however the client shapes them) are all recorded.
    wait_for_upload_pack_quiescence(&proxy, 1, Duration::from_secs(3), Duration::from_secs(60))
        .await;

    // 7. Regression assertions on the outbound request shape.
    let exchanges = proxy.exchanges();
    assert!(
        !exchanges.is_empty(),
        "purgatory sync should fetch through the proxy"
    );
    assert!(
        exchanges.iter().all(|exchange| !exchange.opaque_body),
        "upload-pack request bodies should be inspectable (no compression)"
    );
    // Protocol v2 sends a want-less `ls-refs` POST before each fetch; the
    // ordering guarantee is about the first request that names wants.
    let first_want_exchange = exchanges
        .iter()
        .find(|exchange| !exchange.wants.is_empty())
        .expect("at least one upload-pack request should carry wants");
    assert!(
        first_want_exchange.ok,
        "the first want-carrying upload-pack request must batch-fetch the \
         available tips and succeed; instead it {} with wants {:?} — the \
         client crawled instead of consulting the advertised refs first",
        if first_want_exchange.not_our_ref {
            "failed with 'not our ref'"
        } else {
            "failed"
        },
        first_want_exchange.wants,
    );
    for (index, exchange) in exchanges.iter().enumerate() {
        if !exchange.ok {
            assert!(
                exchange.wants.len() <= 1,
                "failed upload-pack request #{index} carried {} wants {:?}; \
                 a missing object must cost one single-want round trip and \
                 must never fail a batch",
                exchange.wants.len(),
                exchange.wants,
            );
        }
    }

    // 8. The state event stays in purgatory — its declared tips are
    //    unfetchable, exactly like `market` in production.
    verify_event_not_served(syncing.url(), &syncing_state.id, Duration::from_secs(1))
        .await
        .expect("state event with unfetchable tips must stay in purgatory");

    // 9. A fresh replaceable state event resets the queue backoff and
    //    deterministically triggers another pass. With an unchanged remote
    //    advertisement, the miss memo must suppress every failed fetch.
    let failed_after_first_pass = proxy
        .exchanges()
        .iter()
        .filter(|exchange| !exchange.ok)
        .count();
    let info_refs_before_second_pass = proxy.info_refs_count();
    let syncing_state_v2 = EventBuilder::new(Kind::RepoState, "")
        .tags(syncing_state.tags.clone())
        .custom_created_at(timestamp_after(syncing_state.created_at))
        .finalize(&keys)
        .expect("create fresh syncing state event");
    mock_client
        .send_event(&syncing_state_v2)
        .await
        .expect("send fresh state event to mock relay");

    let second_pass_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while proxy.info_refs_count() <= info_refs_before_second_pass {
        assert!(
            tokio::time::Instant::now() < second_pass_deadline,
            "fresh state event should trigger a second ls-remote"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        wait_for_upload_pack_quiescence(
            &proxy,
            proxy.exchanges().len(),
            Duration::from_secs(3),
            Duration::from_secs(60),
        )
        .await,
        "second fetch pass should become quiescent"
    );
    let failed_after_second_pass = proxy
        .exchanges()
        .iter()
        .filter(|exchange| !exchange.ok)
        .count();
    assert_eq!(
        failed_after_second_pass, failed_after_first_pass,
        "unchanged advertisement must produce no new failed upload-pack exchanges"
    );

    source_client.disconnect().await;
    mock_client.disconnect().await;
    syncing.stop().await;
    mock.stop().await;
    proxy.stop().await;
    source.stop().await;
}
