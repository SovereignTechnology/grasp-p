//! Shared NIP-09 deletion-request test helpers.
//!
//! These utilities are shared by the NIP-09 integration test suites
//! (`nip09_validation.rs` and `nip09_disrespector.rs`) so the announcement
//! promotion dance, coordinate-query helper and kind-5 deletion builder are
//! defined exactly once.
//!
//! All helpers drive a live ngit-grasp instance via [`AuditClient`].

use grasp_audit::{
    clone_repo, create_deterministic_commit, try_push, AuditClient, DETERMINISTIC_COMMIT_HASH,
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
/// A kind-30617 announcement is NOT queryable until git data is pushed; the
/// tests that target the announcement therefore need it promoted first. Layer-2
/// events (issues/notes) that reference the promoted repo are served
/// immediately and do not need this dance.
pub async fn publish_served_repo(client: &AuditClient, test_name: &str) -> (Event, String) {
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
pub async fn announcement_served_by_coordinate(
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

/// Coordinate string for a kind-30617 announcement: `30617:<pubkey-hex>:<d>`.
pub fn announcement_coordinate(announcement: &Event, repo_id: &str) -> String {
    format!(
        "{}:{}:{}",
        Kind::GitRepoAnnouncement.as_u16(),
        announcement.pubkey.to_hex(),
        repo_id
    )
}

/// Build a kind-5 deletion request signed by `client` carrying the supplied
/// `e`-tag event ids and `a`-tag coordinate strings.
pub fn build_deletion(
    client: &AuditClient,
    event_ids: &[EventId],
    coordinates: &[String],
) -> Event {
    let mut builder = client.event_builder(Kind::EventDeletion, "delete");

    for id in event_ids {
        builder = builder.tag(Tag::event(*id));
    }
    for coord in coordinates {
        builder = builder.tag(Tag::custom("a", vec![coord.clone()]));
    }

    builder.build(client.keys()).expect("build deletion event")
}

/// Build a kind-62 NIP-62 request-to-vanish signed by `client`.
///
/// The relay validates vanish requests with
/// `nip62::is_valid_vanish_request_for_relay(tags, None)`, so a request is
/// only *actioned* (the author's events deleted and future events blocked) when
/// it carries a `["relay", "ALL_RELAYS"]` tag. A request that names a specific
/// relay URL never matches `None` and is therefore accepted-but-ignored.
///
/// When `relay_target` is `None` the request targets `ALL_RELAYS` (actioned);
/// otherwise it targets the supplied relay URL string (stored, not actioned).
pub fn build_vanish(client: &AuditClient, relay_target: Option<&str>) -> Event {
    let relay_value = relay_target.unwrap_or("ALL_RELAYS").to_string();

    client
        .event_builder(Kind::RequestToVanish, "")
        .tag(Tag::custom("relay", vec![relay_value]))
        .build(client.keys())
        .expect("build vanish event")
}
