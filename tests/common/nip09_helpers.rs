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

use super::purgatory_helpers::{
    create_state_event, create_test_repo_with_commit, push_to_relay, CommitVariant,
};
use super::sync_helpers::create_repo_announcement;

/// Deadline for observable effects that complete outside the relay's reply,
/// such as purgatory promotion after a Git push.
pub const OBSERVABLE_EFFECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll `condition` at a short fixed interval until it holds or the deadline
/// passes, panicking with `description` on timeout.
///
/// The relay applies write-policy effects, including NIP-09 and NIP-62
/// lifecycle deletions, before it replies `OK`, so an awaited send already
/// proves those effects. Use this helper for effects that complete in a
/// spawned task after the reply, or to make an absence assertion robust to a
/// future asynchronous implementation, never as a substitute for a fixed
/// delay before an assertion that the reply already covers.
pub async fn wait_for<F, Fut>(description: &str, timeout: Duration, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(timeout, async {
        loop {
            if condition().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{description} did not hold within {timeout:?}"));
}

/// Wait until the relay serves `event_id`, bounded by
/// [`OBSERVABLE_EFFECT_TIMEOUT`]. Use after a Git push or another action whose
/// promotion completes outside the relay's reply.
pub async fn wait_until_served(client: &AuditClient, event_id: EventId) {
    wait_for(
        &format!("event {event_id} being served"),
        OBSERVABLE_EFFECT_TIMEOUT,
        || async {
            client
                .is_event_on_relay(event_id)
                .await
                .expect("query event expected to become served")
        },
    )
    .await;
}

/// Wait until the relay stops serving `event_id`, bounded by
/// [`OBSERVABLE_EFFECT_TIMEOUT`].
pub async fn wait_until_not_served(client: &AuditClient, event_id: EventId) {
    wait_for(
        &format!("event {event_id} no longer being served"),
        OBSERVABLE_EFFECT_TIMEOUT,
        || async {
            !client
                .is_event_on_relay(event_id)
                .await
                .expect("query event expected to stop being served")
        },
    )
    .await;
}

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
    let (announcement, repo_id, _) = publish_served_audit_repo_with_state(client, test_name).await;
    (announcement, repo_id)
}

/// Publish the audit repository at DETERMINISTIC_COMMIT_HASH and return its
/// signed initial state so replacement tests can order revisions explicitly.
pub async fn publish_served_audit_repo_with_state(
    client: &AuditClient,
    test_name: &str,
) -> (Event, String, Event) {
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

    // Create or reset `main` at the deterministic commit and check it out.
    // `-B` tolerates a pre-existing local `main` (the clone's initial branch
    // follows the branch the server advertises as HEAD).
    let checkout = grasp_audit::git_command()
        .args(["checkout", "-B", "main"])
        .current_dir(&clone_path)
        .output()
        .expect("spawn git checkout -B main");
    if !checkout.status.success() {
        cleanup(&clone_path);
        panic!(
            "failed to create/checkout main before push: {}",
            String::from_utf8_lossy(&checkout.stderr)
        );
    }

    let pushed = try_push(&clone_path);
    cleanup(&clone_path);
    match pushed {
        Ok(true) => {}
        Ok(false) => panic!("git push rejected while promoting repo out of purgatory"),
        Err(e) => panic!("git push error while promoting repo: {}", e),
    }

    wait_until_served(client, announcement.id).await;

    (announcement, repo_id, state_event)
}

/// Publish a served repository announcement while listing additional
/// maintainers in the NIP-34 `maintainers` tag.
///
/// Multi-maintainer cascade tests use this helper so second maintainers can be
/// accepted through the maintainer exception path.
pub async fn publish_served_repo_with_maintainers(
    client: &AuditClient,
    test_name: &str,
    maintainer_pubkeys: &[String],
) -> (Event, String) {
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

    let mut builder = client
        .event_builder(Kind::GitRepoAnnouncement, "")
        .tag(Tag::identifier(&repo_id))
        .tag(Tag::custom("name", vec![repo_id.clone()]))
        .tag(Tag::custom(
            "clone",
            vec![format!("{}/{}/{}.git", http_url, npub, repo_id)],
        ))
        .tag(Tag::custom("relays", vec![relay_url.clone()]));
    if !maintainer_pubkeys.is_empty() {
        builder = builder.tag(Tag::custom("maintainers", maintainer_pubkeys.to_vec()));
    }
    let announcement = builder.build(client.keys()).expect("build announcement");

    client
        .send_event(announcement.clone())
        .await
        .expect("relay should accept announcement");

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

    // Create or reset `main` at the deterministic commit and check it out.
    // `-B` tolerates a pre-existing local `main` (the clone's initial branch
    // follows the branch the server advertises as HEAD).
    let checkout = grasp_audit::git_command()
        .args(["checkout", "-B", "main"])
        .current_dir(&clone_path)
        .output()
        .expect("spawn git checkout -B main");
    if !checkout.status.success() {
        cleanup(&clone_path);
        panic!(
            "failed to create/checkout main before push: {}",
            String::from_utf8_lossy(&checkout.stderr)
        );
    }

    let pushed = try_push(&clone_path);
    cleanup(&clone_path);
    match pushed {
        Ok(true) => {}
        Ok(false) => panic!("git push rejected while promoting repo out of purgatory"),
        Err(e) => panic!("git push error while promoting repo: {}", e),
    }

    wait_until_served(client, announcement.id).await;

    (announcement, repo_id)
}

/// Publish a served announcement + served state event for one repository.
///
/// Unlike [`publish_served_repo`], this helper returns the exact kind-30618
/// state event it published so cascade tests can assert strict pre/post
/// conditions by event id.
pub async fn publish_served_repo_with_state_event(
    client: &AuditClient,
    test_name: &str,
) -> (Event, String, Event) {
    let relay_url = client
        .relay_url()
        .await
        .expect("client should have a relay");
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let npub = client.public_key().to_bech32().expect("pubkey to bech32");

    let repo_id = format!(
        "{}-{}",
        test_name,
        &Keys::generate().public_key().to_hex()[..8]
    );

    let temp_dir = tempfile::tempdir().expect("create temp dir for repo push");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("create deterministic state-test commit");

    let announcement = create_repo_announcement(client.keys(), &[relay_domain.as_str()], &repo_id);
    client
        .send_event(announcement.clone())
        .await
        .expect("relay should accept announcement");

    let clone_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);
    let state_event = create_state_event(
        client.keys(),
        &repo_id,
        &[("main", commit_hash.as_str())],
        &[],
        &[clone_url.as_str()],
        &[relay_url.as_str()],
    )
    .expect("build repo state event");

    client
        .send_event_and_note_purgatory(state_event.clone())
        .await
        .expect("relay should accept state event");

    push_to_relay(temp_dir.path(), &relay_domain, &npub, &repo_id)
        .expect("git push should promote announcement + state event out of purgatory");

    wait_until_served(client, announcement.id).await;
    wait_until_served(client, state_event.id).await;

    (announcement, repo_id, state_event)
}

/// Publish a served announcement + served state event while listing additional
/// maintainers in the NIP-34 `maintainers` tag.
pub async fn publish_served_repo_with_state_event_and_maintainers(
    client: &AuditClient,
    test_name: &str,
    maintainer_pubkeys: &[String],
) -> (Event, String, Event) {
    let relay_url = client
        .relay_url()
        .await
        .expect("client should have a relay");
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let npub = client.public_key().to_bech32().expect("pubkey to bech32");

    let repo_id = format!(
        "{}-{}",
        test_name,
        &Keys::generate().public_key().to_hex()[..8]
    );

    let temp_dir = tempfile::tempdir().expect("create temp dir for repo push");
    let commit_hash = create_test_repo_with_commit(temp_dir.path(), CommitVariant::StateTest)
        .expect("create deterministic state-test commit");

    let mut announcement_builder = client
        .event_builder(Kind::GitRepoAnnouncement, "")
        .tag(Tag::identifier(&repo_id))
        .tag(Tag::custom(
            "clone",
            vec![format!("http://{}/{}/{}.git", relay_domain, npub, repo_id)],
        ))
        .tag(Tag::custom("relays", vec![relay_url.clone()]));
    if !maintainer_pubkeys.is_empty() {
        announcement_builder =
            announcement_builder.tag(Tag::custom("maintainers", maintainer_pubkeys.to_vec()));
    }
    let announcement = announcement_builder
        .build(client.keys())
        .expect("build announcement");
    client
        .send_event(announcement.clone())
        .await
        .expect("relay should accept announcement");

    let clone_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);
    let state_event = create_state_event(
        client.keys(),
        &repo_id,
        &[("main", commit_hash.as_str())],
        &[],
        &[clone_url.as_str()],
        &[relay_url.as_str()],
    )
    .expect("build repo state event");

    client
        .send_event_and_note_purgatory(state_event.clone())
        .await
        .expect("relay should accept state event");

    push_to_relay(temp_dir.path(), &relay_domain, &npub, &repo_id)
        .expect("git push should promote announcement + state event out of purgatory");

    wait_until_served(client, announcement.id).await;
    wait_until_served(client, state_event.id).await;

    (announcement, repo_id, state_event)
}

/// Publish and serve an additional announcement (kind 30617) for an existing
/// repository identifier using a distinct maintainer client.
///
/// This helper is used by multi-maintainer cascade tests where maintainer A
/// already listed this maintainer in a `maintainers` tag. That allows the
/// second maintainer to independently announce the same identifier and complete
/// git promotion for their own `/<npub>/<identifier>.git` repository.
pub async fn publish_served_announcement_for_identifier(
    client: &AuditClient,
    identifier: &str,
) -> Event {
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

    let announcement = client
        .event_builder(Kind::GitRepoAnnouncement, "")
        .tag(Tag::identifier(identifier))
        .tag(Tag::custom("name", vec![identifier.to_string()]))
        .tag(Tag::custom(
            "clone",
            vec![format!("{}/{}/{}.git", http_url, npub, identifier)],
        ))
        .tag(Tag::custom("relays", vec![relay_url.clone()]))
        .build(client.keys())
        .expect("build announcement");
    client
        .send_event(announcement.clone())
        .await
        .expect("relay should accept announcement");

    let state_event = client
        .event_builder(Kind::RepoState, "")
        .tag(Tag::identifier(identifier))
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
        .send_event_and_note_purgatory(state_event)
        .await
        .expect("relay should accept state event");

    if client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement")
    {
        return announcement;
    }

    let clone_path =
        clone_repo(&relay_domain, &npub, identifier).expect("clone purgatory repo over git http");

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

    // Create or reset `main` at the deterministic commit and check it out.
    // `-B` tolerates a pre-existing local `main` (the clone's initial branch
    // follows the branch the server advertises as HEAD).
    let checkout = grasp_audit::git_command()
        .args(["checkout", "-B", "main"])
        .current_dir(&clone_path)
        .output()
        .expect("spawn git checkout -B main");
    if !checkout.status.success() {
        cleanup(&clone_path);
        panic!(
            "failed to create/checkout main before push: {}",
            String::from_utf8_lossy(&checkout.stderr)
        );
    }

    let pushed = try_push(&clone_path);
    cleanup(&clone_path);
    match pushed {
        Ok(true) => {}
        Ok(false) => panic!("git push rejected while promoting repo out of purgatory"),
        Err(e) => panic!("git push error while promoting repo: {}", e),
    }

    wait_until_served(client, announcement.id).await;

    announcement
}

/// Publish and serve an additional announcement+state pair for an existing
/// repository identifier using a distinct maintainer client.
///
/// Returns the served announcement and the exact served state event for strict
/// by-id assertions in multi-maintainer 30618 cascade tests.
pub async fn publish_served_announcement_with_state_for_identifier(
    client: &AuditClient,
    identifier: &str,
) -> (Event, Event) {
    let relay_url = client
        .relay_url()
        .await
        .expect("client should have a relay");
    let relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    let npub = client.public_key().to_bech32().expect("pubkey to bech32");
    let http_url = format!("http://{}", relay_domain);

    let announcement = client
        .event_builder(Kind::GitRepoAnnouncement, "")
        .tag(Tag::identifier(identifier))
        .tag(Tag::custom("name", vec![identifier.to_string()]))
        .tag(Tag::custom(
            "clone",
            vec![format!("{}/{}/{}.git", http_url, npub, identifier)],
        ))
        .tag(Tag::custom("relays", vec![relay_url.clone()]))
        .build(client.keys())
        .expect("build announcement");
    client
        .send_event(announcement.clone())
        .await
        .expect("relay should accept announcement");

    let clone_url = format!("{}/{}/{}.git", http_url, npub, identifier);
    let state_event = create_state_event(
        client.keys(),
        identifier,
        &[("main", DETERMINISTIC_COMMIT_HASH)],
        &[],
        &[clone_url.as_str()],
        &[relay_url.as_str()],
    )
    .expect("build repo state event");

    client
        .send_event_and_note_purgatory(state_event.clone())
        .await
        .expect("relay should accept state event");

    let announcement_served = client
        .is_event_on_relay(announcement.id)
        .await
        .expect("query announcement");
    let state_served = client
        .is_event_on_relay(state_event.id)
        .await
        .expect("query state event");
    if announcement_served && state_served {
        return (announcement, state_event);
    }

    let clone_path =
        clone_repo(&relay_domain, &npub, identifier).expect("clone purgatory repo over git http");

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

    // Create or reset `main` at the deterministic commit and check it out.
    // `-B` tolerates a pre-existing local `main` (the clone's initial branch
    // follows the branch the server advertises as HEAD).
    let checkout = grasp_audit::git_command()
        .args(["checkout", "-B", "main"])
        .current_dir(&clone_path)
        .output()
        .expect("spawn git checkout -B main");
    if !checkout.status.success() {
        cleanup(&clone_path);
        panic!(
            "failed to create/checkout main before push: {}",
            String::from_utf8_lossy(&checkout.stderr)
        );
    }

    let pushed = try_push(&clone_path);
    cleanup(&clone_path);
    match pushed {
        Ok(true) => {}
        Ok(false) => panic!("git push rejected while promoting repo out of purgatory"),
        Err(e) => panic!("git push error while promoting repo: {}", e),
    }

    wait_until_served(client, announcement.id).await;
    wait_until_served(client, state_event.id).await;

    (announcement, state_event)
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
/// The relay actions requests that target `ALL_RELAYS` or one of the relay URL
/// candidates derived from `NGIT_DOMAIN` (`wss://<domain>` and `ws://<domain>`
/// when the domain is configured without a scheme). Requests naming another
/// relay URL are accepted but not actioned.
///
/// When `relay_target` is `None` the request targets `ALL_RELAYS`; otherwise it
/// targets the supplied relay URL string.
pub fn build_vanish(client: &AuditClient, relay_target: Option<&str>) -> Event {
    let relay_value = relay_target.unwrap_or("ALL_RELAYS").to_string();

    client
        .event_builder(Kind::RequestToVanish, "")
        .tag(Tag::custom("relay", vec![relay_value]))
        .build(client.keys())
        .expect("build vanish event")
}
