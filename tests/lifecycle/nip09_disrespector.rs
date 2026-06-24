//! NIP-09 deletion-request "disrespector" (archival) mode integration tests
//!
//! Exercises the end-to-end, observable behaviour of the
//! `NGIT_DELETION_REQUEST_DISRESPECTOR` archival mode against a live
//! ngit-grasp instance driven by the [`TestRelay`] fixture.
//!
//! These tests deliberately assert only on observable contract, not on any
//! internal "holding database" — the current implementation is tombstone /
//! purgatory based, so the disrespector simply accepts the kind-5 request and
//! does nothing with it. The two properties under test are:
//!
//! 1. **Disrespector accepts but ignores deletion/vanish** — a kind-5 or
//!    kind-62 request gets an `OK`, yet the targeted/author events remain
//!    queryable afterwards and no vanish tombstone is laid down.
//! 2. **NIP-11 advertisement** — a disrespector relay omits `9` and `62` from
//!    `supported_nips`; a normal relay advertises both.
//!
//! The normal-mode baseline ("a default relay honours the deletion") lives in
//! `nip09_validation.rs` as `normal_mode_honours_deletion`. Shared helpers
//! (`publish_served_repo`, `announcement_served_by_coordinate`,
//! `announcement_coordinate`, `build_deletion`, `build_vanish`) live in
//! `tests/common/nip09_helpers.rs`.
//!
//! # Running
//!
//! ```bash
//! cargo test --test nip09_disrespector
//! cargo test --test nip09_disrespector -- --nocapture
//! ```

#[path = "../common/mod.rs"]
mod common;

use common::{
    announcement_coordinate, announcement_served_by_coordinate, build_deletion, build_vanish,
    publish_served_repo, TestRelay,
};

use grasp_audit::{AuditClient, AuditConfig};

/// Disrespector mode: the kind-5 deletion is accepted (OK) but ignored — the
/// targeted announcement remains queryable.
#[tokio::test]
async fn disrespector_accepts_but_ignores_deletion() {
    let relay = TestRelay::start_with_deletion_disrespector().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "disrespector-ignores").await;

    let coordinate = announcement_coordinate(&announcement, &repo_id);
    let deletion = build_deletion(&client, &[announcement.id], &[coordinate]);
    let deletion_id = deletion.id;

    // The relay MUST accept the deletion (archival mode still stores/acks it).
    client
        .send_event(deletion)
        .await
        .expect("disrespector relay should OK the kind-5 deletion");

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Contract part 1: the kind-5 request itself MUST be stored/served — the
    // archival relay accepts and preserves the request rather than dropping it.
    let deletion_served = client
        .is_event_on_relay(deletion_id)
        .await
        .expect("query kind-5 deletion after send");

    // Contract part 2: the target MUST still be served, both by direct id lookup
    // and via a real client's author+kind+identifier query (which is the path a
    // normal NIP-09-aware client would use and where query-time deletion
    // suppression would bite).
    let target_served_by_id = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement by id after deletion");
    let target_served_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement, &repo_id).await;

    relay.stop().await;

    assert!(
        deletion_served,
        "disrespector relay must store/serve the kind-5 deletion request itself (id {})",
        deletion_id
    );
    assert!(
        target_served_by_id,
        "disrespector relay must ignore the deletion: announcement {} should still be \
         queryable by id",
        announcement.id
    );
    assert!(
        target_served_by_coordinate,
        "disrespector relay must ignore the deletion: announcement {} should still be \
         served for an author+kind+identifier query",
        announcement.id
    );
}

/// Disrespector mode: the kind-62 vanish request is accepted (OK) but ignored —
/// the author's events remain queryable and future writes are not blocked by a
/// vanish tombstone.
#[tokio::test]
async fn disrespector_accepts_but_ignores_vanish() {
    let relay = TestRelay::start_with_deletion_disrespector().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "disrespector-vanish").await;
    let vanish = build_vanish(&client, None);
    let vanish_id = vanish.id;

    // The relay MUST accept the vanish request (archival mode still stores/acks it).
    client
        .send_event(vanish)
        .await
        .expect("disrespector relay should OK the kind-62 vanish request");

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let vanish_served = client
        .is_event_on_relay(vanish_id)
        .await
        .expect("query kind-62 vanish after send");
    let target_served_by_id = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement by id after vanish");
    let target_served_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement, &repo_id).await;

    let later_issue = client
        .create_issue(
            &announcement,
            "Post-ignored-vanish issue",
            "still allowed",
            vec![],
        )
        .expect("build post-vanish issue");
    let later_issue_id = later_issue.id;
    let later_issue_result = client.send_event(later_issue).await;

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let later_issue_served = client
        .is_event_on_relay(later_issue_id)
        .await
        .expect("query post-ignored-vanish issue");

    relay.stop().await;

    assert!(
        vanish_served,
        "disrespector relay must store/serve the kind-62 vanish request itself (id {})",
        vanish_id
    );
    assert!(
        target_served_by_id,
        "disrespector relay must ignore vanish: announcement {} should still be \
         queryable by id",
        announcement.id
    );
    assert!(
        target_served_by_coordinate,
        "disrespector relay must ignore vanish: announcement {} should still be \
         served for an author+kind+identifier query",
        announcement.id
    );
    assert!(
        later_issue_result.is_ok(),
        "disrespector relay must not lay down a vanish tombstone; later write was {:?}",
        later_issue_result
    );
    assert!(
        later_issue_served,
        "later event {} must be served because disrespector mode ignored vanish",
        later_issue_id
    );
}

/// Fetch the NIP-11 relay information document via HTTP and return the list of
/// advertised `supported_nips`.
///
/// Parsed from raw JSON rather than into a typed document so the test does not
/// couple to the relay's internal NIP-11 struct (which is not exported to the
/// test crate).
async fn fetch_supported_nips(relay: &TestRelay) -> Vec<u64> {
    let http_url = format!("http://{}", relay.domain());
    let resp = reqwest::Client::new()
        .get(&http_url)
        .header("Accept", "application/nostr+json")
        .send()
        .await
        .expect("NIP-11 HTTP request");

    assert!(
        resp.status().is_success(),
        "NIP-11 request failed: status {}",
        resp.status()
    );

    let doc: serde_json::Value = resp.json().await.expect("parse NIP-11 document");

    doc.get("supported_nips")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|n| n.as_u64()).collect())
        .expect("NIP-11 document must contain a supported_nips array")
}

/// NIP-11 advertisement: disrespector omits NIP-09/NIP-62, normal mode
/// advertises both.
#[tokio::test]
async fn nip11_advertisement_reflects_deletion_support() {
    // Disrespector relay: NIP-09 (9) and NIP-62 (62) MUST be absent.
    let disrespector = TestRelay::start_with_deletion_disrespector().await;
    let supported = fetch_supported_nips(&disrespector).await;
    disrespector.stop().await;

    assert!(
        !supported.contains(&9),
        "disrespector relay must NOT advertise NIP-09; supported_nips = {:?}",
        supported
    );
    assert!(
        !supported.contains(&62),
        "disrespector relay must NOT advertise NIP-62; supported_nips = {:?}",
        supported
    );

    // Normal relay: NIP-09 (9) and NIP-62 (62) MUST be present.
    let normal = TestRelay::start().await;
    let supported = fetch_supported_nips(&normal).await;
    normal.stop().await;

    assert!(
        supported.contains(&9),
        "normal relay must advertise NIP-09; supported_nips = {:?}",
        supported
    );
    assert!(
        supported.contains(&62),
        "normal relay must advertise NIP-62; supported_nips = {:?}",
        supported
    );
}
