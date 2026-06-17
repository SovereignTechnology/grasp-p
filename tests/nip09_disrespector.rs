//! NIP-09 deletion-request "disrespector" (archival) mode integration tests
//!
//! Exercises the end-to-end, observable behaviour of the
//! `NGIT_DELETION_REQUEST_DISRESPECTOR` archival mode against a live
//! ngit-grasp instance driven by the [`TestRelay`] fixture.
//!
//! These tests deliberately assert only on observable contract, not on any
//! internal "holding database" — the current implementation is tombstone /
//! purgatory based, so the disrespector simply accepts the kind-5 request and
//! does nothing with it. The three properties under test are:
//!
//! 1. **Disrespector accepts but ignores deletion** — a kind-5 request gets an
//!    `OK`, yet the targeted announcement remains queryable afterwards.
//! 2. **Normal mode honours deletion** — the same flow against a default relay
//!    removes the target.
//! 3. **NIP-11 advertisement** — a disrespector relay omits `9` and `62` from
//!    `supported_nips`; a normal relay advertises both.
//!
//! # Running
//!
//! ```bash
//! cargo test --test nip09_disrespector
//! cargo test --test nip09_disrespector -- --nocapture
//! ```

mod common;

use common::TestRelay;

use grasp_audit::{
    clone_repo, create_deterministic_commit, try_push, AuditClient, AuditConfig,
    DETERMINISTIC_COMMIT_HASH,
};
use nostr_sdk::prelude::*;
use std::path::PathBuf;
use std::time::Duration;

/// Publish a repo announcement, submit a matching state event, and push the
/// deterministic git data so the announcement is promoted out of purgatory and
/// becomes queryable.
///
/// Returns the announcement event (kind 30617) and its repo identifier.
///
/// This is a self-contained replica of the `PurgatoryOwnerStateDataPushed`
/// fixture lifecycle. It is inlined here (rather than reusing the fixture)
/// because the disrespector tests need the *announcement* event itself to
/// target with the kind-5 deletion, whereas the fixture returns the state
/// event.
async fn publish_served_repo(client: &AuditClient, test_name: &str) -> (Event, String) {
    let relay_url = client
        .relay_url()
        .await
        .expect("client should have a relay");
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let http_url = format!("http://{}", relay_domain);

    let npub = client.public_key().to_bech32().expect("pubkey to bech32");

    let repo_id = format!(
        "{}-{}",
        test_name,
        &Keys::generate().public_key().to_hex()[..8]
    );

    // Stage 1: announcement (enters purgatory until git data arrives)
    let announcement = client
        .event_builder(Kind::GitRepoAnnouncement, "")
        .tag(Tag::identifier(&repo_id))
        .tag(Tag::custom("name", vec![repo_id.clone()]))
        .tag(Tag::custom(
            "clone",
            vec![format!("{}/{}/{}.git", http_url, npub, repo_id)],
        ))
        .tag(Tag::custom("relays", vec![relay_url.clone()]))
        .build(client.keys())
        .expect("build announcement");

    client
        .send_event(announcement.clone())
        .await
        .expect("relay should accept announcement");

    // Stage 2: state event pointing at the deterministic commit (purgatory)
    let state_event = client
        .event_builder(Kind::RepoState, "")
        .tag(Tag::identifier(&repo_id))
        .tag(Tag::custom(
            "refs/heads/main",
            vec![DETERMINISTIC_COMMIT_HASH.to_string()],
        ))
        .tag(Tag::custom(
            "HEAD",
            vec!["ref: refs/heads/main".to_string()],
        ))
        .build(client.keys())
        .expect("build state event");

    client
        .send_event_and_note_purgatory(state_event.clone())
        .await
        .expect("relay should accept state event");

    // Stage 3: clone, create the deterministic commit, push — promotes the repo
    let clone_path =
        clone_repo(&relay_domain, &npub, &repo_id).expect("clone purgatory repo over git http");

    let cleanup = |path: &PathBuf| {
        let _ = std::fs::remove_dir_all(path);
    };

    let commit_hash = match create_deterministic_commit(&clone_path, "Initial commit") {
        Ok(h) => h,
        Err(e) => {
            cleanup(&clone_path);
            panic!("failed to create deterministic commit: {}", e);
        }
    };
    assert_eq!(
        commit_hash, DETERMINISTIC_COMMIT_HASH,
        "deterministic commit hash mismatch"
    );

    let _ = std::process::Command::new("git")
        .args(["branch", "main"])
        .current_dir(&clone_path)
        .output();
    let _ = std::process::Command::new("git")
        .args(["checkout", "main"])
        .current_dir(&clone_path)
        .output();

    let pushed = try_push(&clone_path);
    cleanup(&clone_path);
    match pushed {
        Ok(true) => {}
        Ok(false) => panic!("git push rejected while promoting repo out of purgatory"),
        Err(e) => panic!("git push error while promoting repo: {}", e),
    }

    // Give the relay a moment to promote the events out of purgatory.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        client
            .is_event_on_relay(announcement.id)
            .await
            .expect("query announcement"),
        "announcement should be served after git data arrives"
    );

    (announcement, repo_id)
}

/// Query the relay for a served repo announcement using a real client's access
/// pattern: author + kind + `d` identifier (a NIP-01 addressable-event query),
/// rather than a by-id lookup. Returns whether the relay serves it.
async fn announcement_served_by_coordinate(
    client: &AuditClient,
    announcement: &Event,
    repo_id: &str,
) -> bool {
    let filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(announcement.pubkey)
        .identifier(repo_id);

    client
        .query(filter)
        .await
        .expect("query announcement by coordinate")
        .iter()
        .any(|e| e.id == announcement.id)
}

/// Build a kind-5 deletion request from the announcement's author targeting the
/// announcement both by event id and by `a` coordinate (replaceable event).
fn build_deletion(client: &AuditClient, announcement: &Event, repo_id: &str) -> Event {
    let coordinate = format!(
        "{}:{}:{}",
        Kind::GitRepoAnnouncement.as_u16(),
        announcement.pubkey.to_hex(),
        repo_id
    );

    client
        .event_builder(Kind::EventDeletion, "")
        .tag(Tag::event(announcement.id))
        .tag(Tag::custom("a", vec![coordinate]))
        .tag(Tag::custom(
            "k",
            vec![Kind::GitRepoAnnouncement.as_u16().to_string()],
        ))
        .build(client.keys())
        .expect("build deletion event")
}

/// Disrespector mode: the kind-5 deletion is accepted (OK) but ignored — the
/// targeted announcement remains queryable.
#[tokio::test]
async fn disrespector_accepts_but_ignores_deletion() {
    let relay = TestRelay::start_with_deletion_disrespector().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "disrespector-ignores").await;

    let deletion = build_deletion(&client, &announcement, &repo_id);
    let deletion_id = deletion.id;

    // The relay MUST accept the deletion (archival mode still stores/acks it).
    client
        .send_event(deletion)
        .await
        .expect("disrespector relay should OK the kind-5 deletion");

    tokio::time::sleep(Duration::from_millis(300)).await;

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

/// Normal mode (default relay) honours the deletion: after a kind-5 request the
/// targeted announcement is gone.
#[tokio::test]
async fn normal_mode_honours_deletion() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create audit client");

    let (announcement, repo_id) = publish_served_repo(&client, "normal-honours").await;

    let deletion = build_deletion(&client, &announcement, &repo_id);

    client
        .send_event(deletion)
        .await
        .expect("normal relay should OK the kind-5 deletion");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let served_by_id = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement by id after deletion");
    let served_by_coordinate =
        announcement_served_by_coordinate(&client, &announcement, &repo_id).await;

    relay.stop().await;

    assert!(
        !served_by_id,
        "normal relay must honour the deletion: announcement {} should no longer be \
         queryable by id",
        announcement.id
    );
    assert!(
        !served_by_coordinate,
        "normal relay must honour the deletion: announcement {} should no longer be served \
         for an author+kind+identifier query",
        announcement.id
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
