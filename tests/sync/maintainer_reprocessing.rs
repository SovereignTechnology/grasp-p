//! Integration tests for GRASP-02 PR3: Maintainer Announcement Re-Processing
//!
//! Tests the two-tier rejected events index and immediate re-processing of
//! maintainer announcements when owner announcements are accepted.
//!
//! ## Test design
//!
//! Announcements require git data before they are released from purgatory and
//! served to other relays. The tests exercise dependency and source recovery:
//!
//!   relay_b syncs maintainer announcement from relay_a
//!     → write policy rejects it (no owner announcement in DB yet)
//!     → event stored in hot cache and cold index
//!   reciprocal owner announcement reaches relay_b
//!     → hot copy is re-processed immediately when available
//!     → expired hot copy is fetched by its retained cold-index event ID
//!     → maintainer announcement supplies the source clone and git data syncs
//!   an existing owner publishes an invitation for a new maintainer
//!     → the invitee publishes only their reciprocal announcement
//!     → GRASP-02 distributes both announcements across owner-only, invitee-only,
//!       and shared servers
//!     → the owner's state and Git data align the invitee repositories without
//!       an invitee state event or Git push
//!
//! To guarantee the maintainer announcements arrive at relay_b *before* the owner
//! git push, relay_b is started with relay_a as its bootstrap relay.  That way
//! relay_b's SyncManager connects to relay_a immediately and syncs whatever is
//! already in relay_a's DB.  We push the maintainer git data first (so the
//! announcements are in relay_a's DB), wait briefly for the sync round-trip, then
//! send the owner announcement + git push.

use grasp_audit::git_command;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::common::{
    censoring_proxy::CensoringProxy, mock_relay::MockRelay, sync_helpers::*, TestRelay,
};

async fn wait_for_log(path: &Path, needle: &str, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if std::fs::read_to_string(path).is_ok_and(|contents| contents.contains(needle)) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn repository_urls(
    keys: &Keys,
    relays: &[&TestRelay],
    identifier: &str,
) -> (Vec<String>, Vec<String>) {
    let npub = keys
        .public_key()
        .to_bech32()
        .expect("Failed to encode repository owner npub");
    let clone_urls = relays
        .iter()
        .map(|relay| format!("http://{}/{}/{}.git", relay.domain(), npub, identifier))
        .collect();
    let relay_urls = relays.iter().map(|relay| relay.url().to_string()).collect();
    (clone_urls, relay_urls)
}

fn repository_announcement(
    keys: &Keys,
    relays: &[&TestRelay],
    maintainers: &[PublicKey],
    identifier: &str,
) -> EventBuilder {
    let (clone_urls, relay_urls) = repository_urls(keys, relays, identifier);
    let mut tags = vec![
        Tag::identifier(identifier),
        Tag::custom("clone", clone_urls),
        Tag::custom("relays", relay_urls),
    ];
    if !maintainers.is_empty() {
        tags.push(Tag::custom(
            "maintainers",
            maintainers
                .iter()
                .map(PublicKey::to_hex)
                .collect::<Vec<_>>(),
        ));
    }
    EventBuilder::new(Kind::GitRepoAnnouncement, "Repository announcement").tags(tags)
}

fn repository_state_with_default_branch(
    clone_urls: &[String],
    relay_urls: &[String],
    identifier: &str,
    default_branch: &str,
    commit: &str,
) -> EventBuilder {
    EventBuilder::new(Kind::RepoState, "").tags(vec![
        Tag::identifier(identifier),
        Tag::custom("clone", clone_urls.to_vec()),
        Tag::custom("relays", relay_urls.to_vec()),
        Tag::custom(
            format!("refs/heads/{default_branch}"),
            vec![commit.to_string()],
        ),
        Tag::custom("HEAD", vec![format!("refs/heads/{default_branch}")]),
    ])
}

async fn assert_exact_event_served(relay: &TestRelay, event: &Event, description: &str) {
    let found = wait_for_event_on_relay(
        relay.url(),
        Filter::new().id(event.id),
        Duration::from_secs(20),
    )
    .await;
    assert!(
        found,
        "{description} should be served by {}",
        relay.domain()
    );
}

async fn push_counts(relay: &TestRelay) -> (u64, u64) {
    let text = fetch_metrics(relay.url())
        .await
        .expect("Failed to fetch relay metrics");
    let metrics = ParsedMetrics::parse(&text);
    let success = metrics
        .counter(
            "ngit_git_operations_total",
            &[("operation", "push"), ("status", "success")],
        )
        .unwrap_or(0);
    let error = metrics
        .counter(
            "ngit_git_operations_total",
            &[("operation", "push"), ("status", "error")],
        )
        .unwrap_or(0);
    (success, error)
}

fn list_remote_refs(clone_url: &str) -> Result<BTreeMap<String, String>, String> {
    let output = git_command()
        .args(["ls-remote", "--refs", clone_url])
        .output()
        .map_err(|error| format!("Failed to list refs from {clone_url}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to list refs from {clone_url}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    String::from_utf8(output.stdout)
        .map_err(|error| format!("Invalid UTF-8 from {clone_url}: {error}"))?
        .lines()
        .map(|line| {
            let (commit, name) = line
                .split_once('\t')
                .ok_or_else(|| format!("Invalid ls-remote line from {clone_url}: {line}"))?;
            Ok((name.to_string(), commit.to_string()))
        })
        .collect()
}

fn announcement_clone_urls(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .find(|tag| tag.kind() == "clone")
        .expect("Repository announcement should have a clone tag")
        .clone()
        .to_vec()
        .into_iter()
        .skip(1)
        .collect()
}

async fn assert_remote_refs(
    clone_url: &str,
    expected: &BTreeMap<String, String>,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let actual = list_remote_refs(clone_url);
        if actual.as_ref().is_ok_and(|refs| refs == expected) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Announced Git endpoint should exactly match the owner state: {clone_url}\n\
             expected: {expected:?}\nactual: {actual:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn rename_default_branch(repository: &Path, branch: &str) {
    let output = git_command()
        .args(["branch", "-m", branch])
        .current_dir(repository)
        .output()
        .expect("Failed to rename test repository default branch");
    assert!(
        output.status.success(),
        "Failed to rename test repository default branch: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn remote_default_branch(clone_url: &str) -> Result<String, String> {
    let output = git_command()
        .args(["ls-remote", "--symref", clone_url, "HEAD"])
        .output()
        .map_err(|error| format!("Failed to inspect HEAD from {clone_url}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to inspect HEAD from {clone_url}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    String::from_utf8(output.stdout)
        .map_err(|error| format!("Invalid UTF-8 from {clone_url}: {error}"))?
        .lines()
        .find_map(|line| {
            line.strip_prefix("ref: ")
                .and_then(|line| line.strip_suffix("\tHEAD"))
                .map(str::to_string)
        })
        .ok_or_else(|| format!("No symbolic HEAD returned by {clone_url}"))
}

async fn assert_remote_default_branch(clone_url: &str, expected: &str, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let actual = remote_default_branch(clone_url);
        if actual.as_deref() == Ok(expected) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Announced Git endpoint should use {expected} as its default branch: {clone_url}\n\
             actual: {actual:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Exercise the production invitation flow for a repository that already has
/// owner state and Git data.
///
/// The owner selects an owner-only server and a server shared with the invitee.
/// The invitee selects an invitee-only server and that shared server. Acceptance
/// publishes only the invitee's reciprocal announcement: no invitee state event
/// is created and the invitee never pushes Git. GRASP-02 must distribute the
/// signed announcements and use the owner's state and Git data to create both
/// invitee repositories.
#[tokio::test]
async fn test_existing_repository_invitation_acceptance_syncs_without_invitee_push() {
    use crate::common::{create_state_event, create_test_repo_with_commit, CommitVariant};

    let owner_relay = TestRelay::start_with_sync(None).await;
    let invitee_relay = TestRelay::start_with_sync(None).await;
    let shared_relay = TestRelay::start_with_sync(None).await;
    let owner_keys = Keys::generate();
    let invitee_keys = Keys::generate();
    let identifier = "existing-repository-invitation-acceptance";

    let owner_git = tempfile::tempdir().expect("Failed to create owner repository directory");
    let commit = create_test_repo_with_commit(owner_git.path(), CommitVariant::StateTest)
        .expect("Failed to create owner repository commit");
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to encode owner npub");
    let owner_servers = [&owner_relay, &shared_relay];
    let (owner_clone_urls, owner_relay_urls) =
        repository_urls(&owner_keys, &owner_servers, identifier);
    let initial_announcement =
        repository_announcement(&owner_keys, &owner_servers, &[], identifier)
            .finalize(&owner_keys)
            .expect("Failed to create initial owner announcement");
    let owner_state = create_state_event(
        &owner_keys,
        identifier,
        &[("main", &commit)],
        &[],
        &owner_clone_urls
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        &owner_relay_urls
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
    .expect("Failed to create owner state event");

    for relay in owner_servers {
        send_to_relay(relay, &initial_announcement)
            .await
            .expect("Failed to publish initial owner announcement");
        send_to_relay(relay, &owner_state)
            .await
            .expect("Failed to publish owner state");
        crate::common::push_to_relay(owner_git.path(), &relay.domain(), &owner_npub, identifier)
            .expect("Failed to push existing owner repository");
        assert_exact_event_served(relay, &initial_announcement, "Initial owner announcement").await;
        assert_exact_event_served(relay, &owner_state, "Owner state event").await;
        let owner_ref_aligned = crate::common::check_ref_at_commit(
            &relay.domain(),
            &owner_npub,
            identifier,
            "refs/heads/main",
            &commit,
        )
        .await
        .expect("Failed to inspect owner repository ref");
        assert!(
            owner_ref_aligned,
            "Owner repository should be aligned on {}",
            relay.domain()
        );
    }

    let invitation = repository_announcement(
        &owner_keys,
        &owner_servers,
        &[invitee_keys.public_key()],
        identifier,
    )
    .custom_created_at(Timestamp::from_secs(
        initial_announcement.created_at.as_secs() + 1,
    ))
    .finalize(&owner_keys)
    .expect("Failed to create owner invitation announcement");
    for relay in owner_servers {
        send_to_relay(relay, &invitation)
            .await
            .expect("Failed to publish owner invitation");
        assert_exact_event_served(relay, &invitation, "Owner invitation announcement").await;
    }

    let pushes_before_acceptance = [
        push_counts(&owner_relay).await,
        push_counts(&invitee_relay).await,
        push_counts(&shared_relay).await,
    ];
    let invitee_servers = [&invitee_relay, &shared_relay];
    let acceptance = repository_announcement(
        &invitee_keys,
        &invitee_servers,
        &[owner_keys.public_key()],
        identifier,
    )
    .finalize(&invitee_keys)
    .expect("Failed to create invitee acceptance announcement");
    let (invitee_clone_urls, _) = repository_urls(&invitee_keys, &invitee_servers, identifier);
    for relay in invitee_servers {
        send_to_relay(relay, &acceptance)
            .await
            .expect("Failed to publish invitee acceptance announcement");
    }

    for relay in [&owner_relay, &invitee_relay, &shared_relay] {
        assert_exact_event_served(relay, &invitation, "Owner invitation announcement").await;
        assert_exact_event_served(relay, &acceptance, "Invitee acceptance announcement").await;
        assert_exact_event_served(relay, &owner_state, "Owner state event").await;
    }
    for relay in [&owner_relay, &invitee_relay, &shared_relay] {
        let invitee_state_exists = wait_for_event_on_relay(
            relay.url(),
            Filter::new()
                .kind(Kind::RepoState)
                .author(invitee_keys.public_key())
                .identifier(identifier),
            Duration::from_secs(1),
        )
        .await;
        assert!(
            !invitee_state_exists,
            "Invitee must not issue a state event served by {}",
            relay.domain()
        );
    }

    let pushes_after_acceptance = [
        push_counts(&owner_relay).await,
        push_counts(&invitee_relay).await,
        push_counts(&shared_relay).await,
    ];
    assert_eq!(
        pushes_after_acceptance, pushes_before_acceptance,
        "Invitation acceptance must not perform or attempt a client Git push"
    );

    let expected_refs = BTreeMap::from([("refs/heads/main".to_string(), commit.clone())]);
    let announced_owner_clones = announcement_clone_urls(&invitation);
    let announced_invitee_clones = announcement_clone_urls(&acceptance);
    assert_eq!(announced_owner_clones, owner_clone_urls);
    assert_eq!(announced_invitee_clones, invitee_clone_urls);
    assert_eq!(
        announced_owner_clones.len() + announced_invitee_clones.len(),
        4,
        "Owner and invitee announcements should advertise two Git endpoints each"
    );
    for clone_url in announced_owner_clones
        .iter()
        .chain(announced_invitee_clones.iter())
    {
        assert_remote_refs(clone_url, &expected_refs, Duration::from_secs(20)).await;
    }

    shared_relay.stop().await;
    invitee_relay.stop().await;
    owner_relay.stop().await;
}

/// Acceptance on an invitee-only server must recover an expired owner
/// invitation from the owner-only server that originally supplied it.
///
/// This matches the CLI flow where the owner has already pushed and issued a
/// state event, while the invitee publishes only a reciprocal announcement.
/// The rejected owner announcement is allowed to leave the one-second hot
/// cache before acceptance, so convergence depends on the persisted source
/// relay hint and exact-ID recovery rather than a shared GRASP server.
#[tokio::test]
async fn test_invitee_only_acceptance_recovers_cold_owner_invitation() {
    use crate::common::{create_state_event, create_test_repo_with_commit, CommitVariant};

    let owner_relay = TestRelay::start_with_sync(None).await;
    let owner_keys = Keys::generate();
    let invitee_keys = Keys::generate();
    let identifier = "cold-owner-invitation-acceptance";
    let owner_git = tempfile::tempdir().expect("Failed to create owner repository directory");
    let owner_commit = create_test_repo_with_commit(owner_git.path(), CommitVariant::StateTest)
        .expect("Failed to create owner repository commit");
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to encode owner npub");
    let owner_servers = [&owner_relay];
    let (owner_clone_urls, owner_relay_urls) =
        repository_urls(&owner_keys, &owner_servers, identifier);
    let invitation = repository_announcement(
        &owner_keys,
        &owner_servers,
        &[invitee_keys.public_key()],
        identifier,
    )
    .finalize(&owner_keys)
    .expect("Failed to create owner invitation");
    let owner_state = create_state_event(
        &owner_keys,
        identifier,
        &[("main", &owner_commit)],
        &[],
        &owner_clone_urls
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        &owner_relay_urls
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
    .expect("Failed to create owner state");

    send_to_relay(&owner_relay, &invitation)
        .await
        .expect("Failed to publish owner invitation");
    send_to_relay(&owner_relay, &owner_state)
        .await
        .expect("Failed to publish owner state");
    crate::common::push_to_relay(
        owner_git.path(),
        &owner_relay.domain(),
        &owner_npub,
        identifier,
    )
    .expect("Failed to push owner repository");
    assert_exact_event_served(&owner_relay, &invitation, "Owner invitation").await;
    assert_exact_event_served(&owner_relay, &owner_state, "Owner state").await;

    let invitee_relay =
        TestRelay::start_with_sync_and_rejected_hot_cache(Some(owner_relay.url().to_string()), 1)
            .await;
    let invitation_note = invitation
        .id
        .to_bech32()
        .expect("Failed to encode invitation event ID");
    assert!(
        wait_for_log(
            &invitee_relay.log_path(),
            &invitation_note,
            Duration::from_secs(10),
        )
        .await,
        "Invitee-only server should reject and index the owner invitation"
    );
    // Passage of the configured one-second hot-cache TTL is required so the
    // acceptance below exercises cold exact-ID recovery, not the hot copy.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let pushes_before_acceptance = [
        push_counts(&owner_relay).await,
        push_counts(&invitee_relay).await,
    ];
    let invitee_servers = [&invitee_relay];
    let acceptance = repository_announcement(
        &invitee_keys,
        &invitee_servers,
        &[owner_keys.public_key()],
        identifier,
    )
    .custom_created_at(Timestamp::from_secs(invitation.created_at.as_secs() + 1))
    .finalize(&invitee_keys)
    .expect("Failed to create invitee acceptance");
    let (invitee_clone_urls, _) = repository_urls(&invitee_keys, &invitee_servers, identifier);
    assert_eq!(announcement_clone_urls(&acceptance), invitee_clone_urls);
    assert!(
        !announcement_clone_urls(&acceptance)
            .iter()
            .any(|url| owner_clone_urls.contains(url)),
        "Acceptance must not copy the owner's Git endpoint"
    );

    send_to_relay(&invitee_relay, &acceptance)
        .await
        .expect("Failed to publish invitee acceptance");
    assert!(
        wait_for_log(
            &invitee_relay.log_path(),
            "Fetched purgatory dependencies by exact event ID",
            Duration::from_secs(20),
        )
        .await,
        "Invitee-only server should recover the expired invitation by exact event ID"
    );

    assert_exact_event_served(&invitee_relay, &invitation, "Recovered owner invitation").await;
    assert_exact_event_served(&invitee_relay, &owner_state, "Recovered owner state").await;
    assert_exact_event_served(&invitee_relay, &acceptance, "Invitee acceptance").await;

    let expected_refs = BTreeMap::from([("refs/heads/main".to_string(), owner_commit.clone())]);
    assert_remote_refs(
        &invitee_clone_urls[0],
        &expected_refs,
        Duration::from_secs(20),
    )
    .await;
    assert_remote_default_branch(
        &invitee_clone_urls[0],
        "refs/heads/main",
        Duration::from_secs(20),
    )
    .await;

    let invitee_state_exists = wait_for_event_on_relay(
        invitee_relay.url(),
        Filter::new()
            .kind(Kind::RepoState)
            .author(invitee_keys.public_key())
            .identifier(identifier),
        Duration::from_secs(1),
    )
    .await;
    assert!(
        !invitee_state_exists,
        "Invitation acceptance must not publish an invitee state event"
    );
    assert_eq!(
        [
            push_counts(&owner_relay).await,
            push_counts(&invitee_relay).await,
        ],
        pushes_before_acceptance,
        "Invitation acceptance must converge without a client Git push"
    );

    invitee_relay.stop().await;
    owner_relay.stop().await;
}

/// Cold dependency polling for separate repositories sharing a relay is
/// combined into one exact-ID query on each maintenance round.
#[tokio::test]
async fn unresolved_repositories_share_one_dependency_poll_per_relay() {
    let source = MockRelay::start().await;
    let proxy = CensoringProxy::start(source.url()).await;
    let invitee_relay =
        TestRelay::start_with_sync_and_rejected_hot_cache(Some(proxy.url().to_string()), 1).await;
    let invitee_keys = Keys::generate();
    let owners = [Keys::generate(), Keys::generate()];
    let identifiers = ["batched-dependency-one", "batched-dependency-two"];

    let mut invitations = Vec::new();
    for (owner, identifier) in owners.iter().zip(identifiers) {
        let invitation = EventBuilder::new(Kind::GitRepoAnnouncement, "Owner invitation")
            .tags([
                Tag::identifier(identifier),
                Tag::custom(
                    "clone",
                    [format!(
                        "https://example.invalid/{}/{}.git",
                        owner.public_key().to_hex(),
                        identifier
                    )],
                ),
                Tag::custom("relays", [proxy.url().to_string()]),
                Tag::custom("maintainers", [invitee_keys.public_key().to_hex()]),
            ])
            .finalize(owner)
            .expect("Failed to create owner invitation");
        send_to_relay_url(source.url(), &invitation)
            .await
            .expect("Failed to seed owner invitation");
        invitations.push(invitation);
    }

    for invitation in &invitations {
        let invitation_note = invitation
            .id
            .to_bech32()
            .expect("Failed to encode invitation event ID");
        assert!(
            wait_for_log(
                &invitee_relay.log_path(),
                &invitation_note,
                Duration::from_secs(10),
            )
            .await,
            "Invitee relay should reject and index both owner invitations"
        );
        proxy.withhold(invitation.id);
    }

    // Passage of the configured one-second hot-cache TTL is required so both
    // repositories exercise cold exact-ID recovery on the same relay.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let acceptances: Vec<Event> = owners
        .iter()
        .zip(identifiers)
        .zip(&invitations)
        .map(|((owner, identifier), invitation)| {
            repository_announcement(
                &invitee_keys,
                &[&invitee_relay],
                &[owner.public_key()],
                identifier,
            )
            .custom_created_at(Timestamp::from_secs(invitation.created_at.as_secs() + 1))
            .finalize(&invitee_keys)
            .expect("Failed to create invitee acceptance")
        })
        .collect();
    let client = Client::default();
    client
        .add_relay(invitee_relay.url())
        .await
        .expect("Failed to add invitee relay");
    client.connect().await;
    for acceptance in &acceptances {
        client
            .send_event(acceptance)
            .await
            .expect("Failed to publish invitee acceptance");
    }
    client.disconnect().await;

    assert!(
        wait_for_log(
            &invitee_relay.log_path(),
            "repository_count=2 requested_count=2 fetched_count=0",
            Duration::from_secs(20),
        )
        .await,
        "Separate repositories should share one dependency query to their common relay"
    );

    invitee_relay.stop().await;
    proxy.stop().await;
    source.stop().await;
}

/// Listing a maintainer immediately authorizes that maintainer's state for the
/// inviting owner's repository; reciprocal acceptance is not required.
///
/// The owner first publishes an older state on an owner-only and shared server.
/// The invitee later publishes a newer, different state on an invitee-only and
/// shared server. When the owner lists the invitee, GRASP-02 must apply the
/// invitee's newer state to both owner endpoints without changing the invitee's
/// announcement or requiring another Git push.
#[tokio::test]
async fn test_invitation_applies_newer_invitee_state_to_owner_before_acceptance() {
    use crate::common::{create_test_repo_with_commit, CommitVariant};

    let owner_relay = TestRelay::start_with_sync(None).await;
    let invitee_relay = TestRelay::start_with_sync(None).await;
    let shared_relay = TestRelay::start_with_sync(None).await;
    let owner_keys = Keys::generate();
    let invitee_keys = Keys::generate();
    let identifier = "one-way-invitation-newer-maintainer-state";
    let owner_branch = "owner-default";
    let invitee_branch = "invitee-default";
    let owner_servers = [&owner_relay, &shared_relay];
    let invitee_servers = [&invitee_relay, &shared_relay];

    let owner_git = tempfile::tempdir().expect("Failed to create owner repository directory");
    let owner_commit = create_test_repo_with_commit(owner_git.path(), CommitVariant::StateTest)
        .expect("Failed to create owner repository commit");
    rename_default_branch(owner_git.path(), owner_branch);
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to encode owner npub");
    let (owner_clone_urls, owner_relay_urls) =
        repository_urls(&owner_keys, &owner_servers, identifier);
    let initial_owner_announcement =
        repository_announcement(&owner_keys, &owner_servers, &[], identifier)
            .finalize(&owner_keys)
            .expect("Failed to create initial owner announcement");
    let owner_state = repository_state_with_default_branch(
        &owner_clone_urls,
        &owner_relay_urls,
        identifier,
        owner_branch,
        &owner_commit,
    )
    .finalize(&owner_keys)
    .expect("Failed to create owner state");
    let owner_refs = BTreeMap::from([(format!("refs/heads/{owner_branch}"), owner_commit)]);

    for relay in owner_servers {
        send_to_relay(relay, &initial_owner_announcement)
            .await
            .expect("Failed to publish initial owner announcement");
        send_to_relay(relay, &owner_state)
            .await
            .expect("Failed to publish owner state");
        crate::common::push_to_relay(owner_git.path(), &relay.domain(), &owner_npub, identifier)
            .expect("Failed to push owner repository");
        assert_exact_event_served(
            relay,
            &initial_owner_announcement,
            "Initial owner announcement",
        )
        .await;
        assert_exact_event_served(relay, &owner_state, "Owner state event").await;
    }
    for clone_url in &owner_clone_urls {
        assert_remote_refs(clone_url, &owner_refs, Duration::from_secs(20)).await;
        assert_remote_default_branch(
            clone_url,
            &format!("refs/heads/{owner_branch}"),
            Duration::from_secs(20),
        )
        .await;
    }

    // Deliberate timestamp spacing: the invitee events below are dated one
    // second after the owner state, so let wall-clock time pass that mark.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let invitee_git = tempfile::tempdir().expect("Failed to create invitee repository directory");
    let invitee_commit = create_test_repo_with_commit(invitee_git.path(), CommitVariant::PrTest)
        .expect("Failed to create invitee repository commit");
    rename_default_branch(invitee_git.path(), invitee_branch);
    let invitee_npub = invitee_keys
        .public_key()
        .to_bech32()
        .expect("Failed to encode invitee npub");
    let (invitee_clone_urls, invitee_relay_urls) =
        repository_urls(&invitee_keys, &invitee_servers, identifier);
    let invitee_created_at = Timestamp::from_secs(owner_state.created_at.as_secs() + 1);
    let invitee_announcement =
        repository_announcement(&invitee_keys, &invitee_servers, &[], identifier)
            .custom_created_at(invitee_created_at)
            .finalize(&invitee_keys)
            .expect("Failed to create invitee announcement");
    let invitee_state = repository_state_with_default_branch(
        &invitee_clone_urls,
        &invitee_relay_urls,
        identifier,
        invitee_branch,
        &invitee_commit,
    )
    .custom_created_at(invitee_created_at)
    .finalize(&invitee_keys)
    .expect("Failed to create invitee state");
    assert!(
        invitee_state.created_at > owner_state.created_at,
        "Invitee state must be newer than the owner's existing state"
    );
    let invitee_refs = BTreeMap::from([(
        format!("refs/heads/{invitee_branch}"),
        invitee_commit.clone(),
    )]);

    for relay in invitee_servers {
        send_to_relay(relay, &invitee_announcement)
            .await
            .expect("Failed to publish invitee announcement");
        send_to_relay(relay, &invitee_state)
            .await
            .expect("Failed to publish invitee state");
        crate::common::push_to_relay(
            invitee_git.path(),
            &relay.domain(),
            &invitee_npub,
            identifier,
        )
        .expect("Failed to push invitee repository");
        assert_exact_event_served(relay, &invitee_announcement, "Invitee announcement").await;
        assert_exact_event_served(relay, &invitee_state, "Invitee state event").await;
    }
    for clone_url in &invitee_clone_urls {
        assert_remote_refs(clone_url, &invitee_refs, Duration::from_secs(20)).await;
        assert_remote_default_branch(
            clone_url,
            &format!("refs/heads/{invitee_branch}"),
            Duration::from_secs(20),
        )
        .await;
    }

    for clone_url in &owner_clone_urls {
        assert_remote_refs(clone_url, &owner_refs, Duration::from_secs(5)).await;
    }

    let pushes_before_invitation = [
        push_counts(&owner_relay).await,
        push_counts(&invitee_relay).await,
        push_counts(&shared_relay).await,
    ];
    let invitation = repository_announcement(
        &owner_keys,
        &owner_servers,
        &[invitee_keys.public_key()],
        identifier,
    )
    .custom_created_at(Timestamp::from_secs(invitee_created_at.as_secs() + 1))
    .finalize(&owner_keys)
    .expect("Failed to create owner invitation");
    for relay in owner_servers {
        send_to_relay(relay, &invitation)
            .await
            .expect("Failed to publish owner invitation");
    }

    for relay in owner_servers {
        assert_exact_event_served(relay, &invitation, "Owner invitation announcement").await;
        assert_exact_event_served(
            relay,
            &invitee_announcement,
            "Invited maintainer announcement",
        )
        .await;
        assert_exact_event_served(relay, &invitee_state, "Newer invited maintainer state").await;
    }
    for clone_url in &owner_clone_urls {
        assert_remote_refs(clone_url, &invitee_refs, Duration::from_secs(20)).await;
        assert_remote_default_branch(
            clone_url,
            &format!("refs/heads/{invitee_branch}"),
            Duration::from_secs(20),
        )
        .await;
    }
    for clone_url in &invitee_clone_urls {
        assert_remote_refs(clone_url, &invitee_refs, Duration::from_secs(20)).await;
        assert_remote_default_branch(
            clone_url,
            &format!("refs/heads/{invitee_branch}"),
            Duration::from_secs(20),
        )
        .await;
    }

    let pushes_after_invitation = [
        push_counts(&owner_relay).await,
        push_counts(&invitee_relay).await,
        push_counts(&shared_relay).await,
    ];
    assert_eq!(
        pushes_after_invitation, pushes_before_invitation,
        "One-way maintainer authorization must sync the owner without a client Git push"
    );

    shared_relay.stop().await;
    invitee_relay.stop().await;
    owner_relay.stop().await;
}

/// An invitation must not overwrite an invitee's unrelated repository merely
/// because the inviter's state is newer.
///
/// Both users first create a repository with the same identifier but different
/// default branches. The invitee's repository remains on its own state while
/// the one-way invitation syncs. Once the invitee publishes a reciprocal
/// announcement, the newer owner state becomes authoritative for the combined
/// maintainer set and replaces the invitee repository's refs without a new push.
#[tokio::test]
async fn test_acceptance_replaces_existing_invitee_repository_with_newer_owner_state() {
    use crate::common::{create_test_repo_with_commit, CommitVariant};

    let owner_relay = TestRelay::start_with_sync(None).await;
    let invitee_relay = TestRelay::start_with_sync_debug(None).await;
    let shared_relay = TestRelay::start_with_sync(None).await;
    let owner_keys = Keys::generate();
    let invitee_keys = Keys::generate();
    let identifier = "existing-invitee-repository-acceptance";
    let invitee_branch = "invitee-default";
    let owner_branch = "owner-default";
    let invitee_servers = [&invitee_relay, &shared_relay];
    let owner_servers = [&owner_relay, &shared_relay];

    let invitee_git = tempfile::tempdir().expect("Failed to create invitee repository directory");
    let invitee_commit = create_test_repo_with_commit(invitee_git.path(), CommitVariant::StateTest)
        .expect("Failed to create invitee repository commit");
    rename_default_branch(invitee_git.path(), invitee_branch);
    let invitee_npub = invitee_keys
        .public_key()
        .to_bech32()
        .expect("Failed to encode invitee npub");
    let (invitee_clone_urls, invitee_relay_urls) =
        repository_urls(&invitee_keys, &invitee_servers, identifier);
    let initial_invitee_announcement =
        repository_announcement(&invitee_keys, &invitee_servers, &[], identifier)
            .finalize(&invitee_keys)
            .expect("Failed to create initial invitee announcement");
    let invitee_state = repository_state_with_default_branch(
        &invitee_clone_urls,
        &invitee_relay_urls,
        identifier,
        invitee_branch,
        &invitee_commit,
    )
    .finalize(&invitee_keys)
    .expect("Failed to create invitee state");
    let invitee_refs = BTreeMap::from([(
        format!("refs/heads/{invitee_branch}"),
        invitee_commit.clone(),
    )]);

    for relay in invitee_servers {
        send_to_relay(relay, &initial_invitee_announcement)
            .await
            .expect("Failed to publish initial invitee announcement");
        send_to_relay(relay, &invitee_state)
            .await
            .expect("Failed to publish invitee state");
        crate::common::push_to_relay(
            invitee_git.path(),
            &relay.domain(),
            &invitee_npub,
            identifier,
        )
        .expect("Failed to push existing invitee repository");
        assert_exact_event_served(
            relay,
            &initial_invitee_announcement,
            "Initial invitee announcement",
        )
        .await;
        assert_exact_event_served(relay, &invitee_state, "Invitee state event").await;
    }
    for clone_url in &invitee_clone_urls {
        assert_remote_refs(clone_url, &invitee_refs, Duration::from_secs(20)).await;
        assert_remote_default_branch(
            clone_url,
            &format!("refs/heads/{invitee_branch}"),
            Duration::from_secs(20),
        )
        .await;
    }

    // Deliberate timestamp spacing: the owner events below are dated one
    // second after the invitee state, so let wall-clock time pass that mark.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let owner_git = tempfile::tempdir().expect("Failed to create owner repository directory");
    let owner_commit = create_test_repo_with_commit(owner_git.path(), CommitVariant::PrTest)
        .expect("Failed to create owner repository commit");
    rename_default_branch(owner_git.path(), owner_branch);
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to encode owner npub");
    let (owner_clone_urls, owner_relay_urls) =
        repository_urls(&owner_keys, &owner_servers, identifier);
    let owner_created_at = Timestamp::from_secs(invitee_state.created_at.as_secs() + 1);
    let initial_owner_announcement =
        repository_announcement(&owner_keys, &owner_servers, &[], identifier)
            .custom_created_at(owner_created_at)
            .finalize(&owner_keys)
            .expect("Failed to create initial owner announcement");
    let owner_state = repository_state_with_default_branch(
        &owner_clone_urls,
        &owner_relay_urls,
        identifier,
        owner_branch,
        &owner_commit,
    )
    .custom_created_at(owner_created_at)
    .finalize(&owner_keys)
    .expect("Failed to create owner state");
    assert!(
        owner_state.created_at > invitee_state.created_at,
        "Owner state must be newer than the invitee's existing state"
    );

    for relay in owner_servers {
        send_to_relay(relay, &initial_owner_announcement)
            .await
            .expect("Failed to publish initial owner announcement");
        send_to_relay(relay, &owner_state)
            .await
            .expect("Failed to publish owner state");
        crate::common::push_to_relay(owner_git.path(), &relay.domain(), &owner_npub, identifier)
            .expect("Failed to push owner repository");
        assert_exact_event_served(
            relay,
            &initial_owner_announcement,
            "Initial owner announcement",
        )
        .await;
        assert_exact_event_served(relay, &owner_state, "Owner state event").await;
    }

    let invitation = repository_announcement(
        &owner_keys,
        &owner_servers,
        &[invitee_keys.public_key()],
        identifier,
    )
    .custom_created_at(Timestamp::from_secs(owner_created_at.as_secs() + 1))
    .finalize(&owner_keys)
    .expect("Failed to create owner invitation");
    for relay in owner_servers {
        send_to_relay(relay, &invitation)
            .await
            .expect("Failed to publish owner invitation");
        assert_exact_event_served(relay, &invitation, "Owner invitation announcement").await;
    }

    let invitation_note = invitation
        .id
        .to_bech32()
        .expect("Failed to encode owner invitation note ID");
    assert!(
        wait_for_log(
            &invitee_relay.log_path(),
            &invitation_note,
            Duration::from_secs(20),
        )
        .await,
        "Invitee-only server should process the unilateral invitation before acceptance"
    );
    // Deliberate observation window: give a wrongful state replacement time
    // to manifest before asserting the invitee state is still intact.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for relay in invitee_servers {
        assert_exact_event_served(relay, &invitee_state, "Invitee state before acceptance").await;
    }
    for clone_url in &invitee_clone_urls {
        assert_remote_refs(clone_url, &invitee_refs, Duration::from_secs(5)).await;
        assert_remote_default_branch(
            clone_url,
            &format!("refs/heads/{invitee_branch}"),
            Duration::from_secs(5),
        )
        .await;
    }

    let pushes_before_acceptance = [
        push_counts(&owner_relay).await,
        push_counts(&invitee_relay).await,
        push_counts(&shared_relay).await,
    ];
    let acceptance = repository_announcement(
        &invitee_keys,
        &invitee_servers,
        &[owner_keys.public_key()],
        identifier,
    )
    .custom_created_at(Timestamp::from_secs(owner_created_at.as_secs() + 2))
    .finalize(&invitee_keys)
    .expect("Failed to create invitee acceptance");
    for relay in invitee_servers {
        send_to_relay(relay, &acceptance)
            .await
            .expect("Failed to publish invitee acceptance");
    }

    for relay in [&owner_relay, &invitee_relay, &shared_relay] {
        assert_exact_event_served(relay, &invitation, "Owner invitation announcement").await;
        assert_exact_event_served(relay, &acceptance, "Invitee acceptance announcement").await;
        assert_exact_event_served(relay, &owner_state, "Newer owner state event").await;
    }

    let owner_refs = BTreeMap::from([(format!("refs/heads/{owner_branch}"), owner_commit.clone())]);
    for clone_url in &invitee_clone_urls {
        assert_remote_refs(clone_url, &owner_refs, Duration::from_secs(20)).await;
        assert_remote_default_branch(
            clone_url,
            &format!("refs/heads/{owner_branch}"),
            Duration::from_secs(20),
        )
        .await;
    }
    for clone_url in &owner_clone_urls {
        assert_remote_refs(clone_url, &owner_refs, Duration::from_secs(20)).await;
        assert_remote_default_branch(
            clone_url,
            &format!("refs/heads/{owner_branch}"),
            Duration::from_secs(20),
        )
        .await;
    }

    let pushes_after_acceptance = [
        push_counts(&owner_relay).await,
        push_counts(&invitee_relay).await,
        push_counts(&shared_relay).await,
    ];
    assert_eq!(
        pushes_after_acceptance, pushes_before_acceptance,
        "Invitation acceptance must converge existing repositories without a client Git push"
    );

    shared_relay.stop().await;
    invitee_relay.stop().await;
    owner_relay.stop().await;
}

/// A reciprocal owner announcement in purgatory must be enough to unlock an
/// earlier rejected maintainer announcement and use that maintainer's clone URL.
///
/// The new owner deliberately advertises only their own empty target-repo clone
/// URL. The source clone remains owned by the existing maintainer announcement.
/// No client-side copy of another maintainer's `clone` tag is required.
#[tokio::test]
async fn test_purgatory_owner_uses_rejected_maintainer_clone_to_sync_git() {
    let source_relay = TestRelay::start().await;
    let maintainer_keys = Keys::generate();
    let owner_keys = Keys::generate();
    let identifier = "purgatory-owner-maintainer-source";

    let maintainer_npub = maintainer_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get maintainer npub");
    let maintainer_clone = format!(
        "http://{}/{}/{}.git",
        source_relay.domain(),
        maintainer_npub,
        identifier
    );
    let maintainer_announcement =
        EventBuilder::new(Kind::GitRepoAnnouncement, "Existing maintainer repository")
            .tags(vec![
                Tag::identifier(identifier),
                Tag::custom("clone", vec![maintainer_clone.clone()]),
                Tag::custom("relays", vec![source_relay.url().to_string()]),
            ])
            .finalize(&maintainer_keys)
            .expect("Failed to create maintainer announcement");
    let maintainer_announcement_note = maintainer_announcement
        .id
        .to_bech32()
        .expect("Failed to encode maintainer announcement ID");

    send_to_relay(&source_relay, &maintainer_announcement)
        .await
        .expect("Failed to send maintainer announcement");
    let maintainer_git = push_git_data_to_relay(
        &source_relay,
        &maintainer_keys,
        identifier,
        &[&source_relay.domain()],
    )
    .await;
    let commit_output = git_command()
        .args(["rev-parse", "HEAD"])
        .current_dir(maintainer_git.path())
        .output()
        .expect("Failed to read maintainer commit");
    assert!(commit_output.status.success());
    let maintainer_commit = String::from_utf8(commit_output.stdout)
        .expect("Commit hash should be UTF-8")
        .trim()
        .to_string();

    let source_announcement_found = wait_for_event_on_relay(
        source_relay.url(),
        Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(maintainer_keys.public_key())
            .identifier(identifier),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        source_announcement_found,
        "Maintainer announcement should be served by source relay"
    );

    // Bootstrap first so the source announcement is rejected before the
    // reciprocal owner relationship exists. Observe that rejection before
    // waiting out a one-second hot-cache TTL; this makes the cold-only ordering
    // deterministic even on a slow test host.
    let target_relay =
        TestRelay::start_with_sync_and_rejected_hot_cache(Some(source_relay.url().to_string()), 1)
            .await;
    assert!(
        wait_for_log(
            &target_relay.log_path(),
            &maintainer_announcement_note,
            Duration::from_secs(10),
        )
        .await,
        "Target should reject and index the maintainer announcement before the invite arrives"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;

    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get owner npub");
    let owner_clone = format!(
        "http://{}/{}/{}.git",
        target_relay.domain(),
        owner_npub,
        identifier
    );
    let owner_announcement =
        EventBuilder::new(Kind::GitRepoAnnouncement, "New reciprocal owner repository")
            .tags(vec![
                Tag::identifier(identifier),
                Tag::custom("clone", vec![owner_clone.clone()]),
                // The reciprocal announcement intentionally advertises only the
                // target. Cold dependency recovery must remember that the
                // rejected maintainer event was actually received from source.
                Tag::custom("relays", vec![target_relay.url().to_string()]),
                Tag::custom("maintainers", vec![maintainer_keys.public_key().to_hex()]),
            ])
            .finalize(&owner_keys)
            .expect("Failed to create owner announcement");

    let owner_clone_values: Vec<String> = owner_announcement
        .tags
        .iter()
        .find(|tag| tag.kind() == "clone")
        .expect("Owner announcement should have clone tag")
        .clone()
        .to_vec()
        .into_iter()
        .skip(1)
        .collect();
    assert_eq!(owner_clone_values, vec![owner_clone]);
    assert!(
        !owner_clone_values.contains(&maintainer_clone),
        "Owner must not claim the maintainer's clone URL"
    );

    let started = std::time::Instant::now();
    send_to_relay(&target_relay, &owner_announcement)
        .await
        .expect("Failed to send reciprocal owner announcement");

    let owner_found = wait_for_event_on_relay(
        target_relay.url(),
        Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(owner_keys.public_key())
            .identifier(identifier),
        Duration::from_secs(30),
    )
    .await;
    assert!(
        owner_found,
        "Owner announcement should promote after fetching the maintainer's git data"
    );

    let maintainer_found = wait_for_event_on_relay(
        target_relay.url(),
        Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(maintainer_keys.public_key())
            .identifier(identifier),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        maintainer_found,
        "Rejected maintainer announcement should be reprocessed before owner promotion"
    );

    let state_found = wait_for_event_on_relay(
        target_relay.url(),
        Filter::new()
            .kind(Kind::RepoState)
            .author(maintainer_keys.public_key())
            .identifier(identifier),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        state_found,
        "Maintainer state should be served after git synchronization"
    );

    let ref_aligned = crate::common::check_ref_at_commit(
        &target_relay.domain(),
        &owner_npub,
        identifier,
        "refs/heads/main",
        &maintainer_commit,
    )
    .await
    .expect("Failed to inspect target owner ref");
    assert!(
        ref_aligned,
        "Target owner repository should align to the maintainer's state"
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "Reciprocal owner synchronization should not inherit a long retry delay"
    );

    target_relay.stop().await;
    source_relay.stop().await;
}

/// Test that a maintainer announcement is re-processed immediately when the owner
/// announcement is promoted from purgatory via a git push.
///
/// Flow:
/// 1. relay_a: Maintainer sends announcement + git data → accepted into relay_a's DB
/// 2. relay_b (bootstrapped from relay_a): SyncManager syncs maintainer announcement
///    → rejected by write policy (no owner in DB) → stored in hot cache
/// 3. relay_b: Owner sends announcement → purgatory (no git data yet)
/// 4. relay_b: Owner git push → owner announcement promoted from purgatory
///    → hot-cache re-processing fires → maintainer announcement accepted
/// 5. Both announcements should be in relay_b's database
#[tokio::test]
async fn test_maintainer_announcement_reprocessed_immediately() {
    // Start relay_a (where maintainer announcement will be sent)
    let relay_a = TestRelay::start().await;
    println!("relay_a started at {}", relay_a.url());

    // Create keys
    let owner_keys = Keys::generate();
    let maintainer_keys = Keys::generate();
    let identifier = "test-repo";

    // Step 1: Send maintainer announcement to relay_a then push git data so it lands in
    // relay_a's DB.  The announcement lists relay_a only (not relay_b), so relay_b's write
    // policy will reject it when it arrives via sync.
    let maintainer_npub = maintainer_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");
    let maintainer_announcement =
        EventBuilder::new(Kind::GitRepoAnnouncement, "Maintainer's repository")
            .tags(vec![
                Tag::identifier(identifier),
                Tag::custom(
                    "clone",
                    vec![format!(
                        "http://{}/{}/{}.git",
                        relay_a.domain(),
                        maintainer_npub,
                        identifier
                    )],
                ),
                Tag::custom("relays", vec![relay_a.url().to_string()]),
            ])
            .finalize(&maintainer_keys)
            .unwrap();
    send_to_relay(&relay_a, &maintainer_announcement)
        .await
        .unwrap();
    let _git_dir_maintainer =
        push_git_data_to_relay(&relay_a, &maintainer_keys, identifier, &[&relay_a.domain()]).await;
    println!("✓ Maintainer announcement + git data pushed to relay_a");

    // Step 2: Start relay_b with relay_a as bootstrap so its SyncManager connects immediately.
    // relay_b's initial negentropy sync will pick up the maintainer announcement and reject it
    // (no owner announcement in relay_b's DB yet), storing it in the hot cache.
    let relay_b = TestRelay::start_with_sync_debug(Some(relay_a.url().to_string())).await;
    println!("relay_b started at {}", relay_b.url());

    // Wait for relay_b's initial negentropy sync on its observable outcome:
    // the rejected maintainer announcement is logged by its note ID.
    let maintainer_note = maintainer_announcement
        .id
        .to_bech32()
        .expect("Failed to encode maintainer announcement ID");
    assert!(
        wait_for_log(
            &relay_b.log_path(),
            &maintainer_note,
            Duration::from_secs(30),
        )
        .await,
        "relay_b should sync, reject and index the maintainer announcement"
    );
    println!("✓ relay_b synced from relay_a (maintainer announcement in hot cache)");

    let start = std::time::Instant::now();

    // Step 3: Send owner announcement to relay_b → goes to purgatory (no git data yet).
    // The announcement lists relay_a + relay_b and names the maintainer.
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");

    let owner_announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Owner's repository")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{}/{}.git",
                    relay_b.domain(),
                    owner_npub,
                    identifier
                )],
            ),
            Tag::custom(
                "relays",
                vec![relay_a.url().to_string(), relay_b.url().to_string()],
            ),
            Tag::custom("maintainers", vec![maintainer_keys.public_key().to_hex()]),
        ])
        .finalize(&owner_keys)
        .unwrap();

    send_to_relay(&relay_b, &owner_announcement).await.unwrap();
    println!("✓ Owner announcement sent to relay_b (now in purgatory)");

    // Step 4: Push owner git data to relay_b.
    // This promotes the owner announcement from purgatory, which triggers hot-cache
    // re-processing of the maintainer announcement via our new code path.
    let _git_dir_owner =
        push_git_data_to_relay(&relay_b, &owner_keys, identifier, &[&relay_b.domain()]).await;
    println!(
        "✓ Owner git data pushed to relay_b (owner announcement promoted, hot cache re-processed)"
    );

    // Step 5/6: Verify both announcements are in relay_b's database. Bounded
    // polls on the served events replace a fixed post-push sleep.
    let owner_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(owner_keys.public_key())
        .identifier(identifier);

    let owner_found =
        wait_for_event_on_relay(relay_b.url(), owner_filter, Duration::from_secs(30)).await;
    assert!(owner_found, "Owner announcement should be in relay_b");

    let maintainer_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(maintainer_keys.public_key())
        .identifier(identifier);

    let maintainer_found =
        wait_for_event_on_relay(relay_b.url(), maintainer_filter, Duration::from_secs(30)).await;
    assert!(
        maintainer_found,
        "Maintainer announcement should be re-processed and accepted in relay_b"
    );

    // Immediate hot-cache re-processing must beat the scheduled retry path.
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 15,
        "Re-processing should happen in <15 seconds, took {:?}",
        elapsed
    );

    println!("✅ Maintainer announcement re-processed in {:?}", elapsed);

    relay_a.stop().await;
    relay_b.stop().await;
}

/// Test that all maintainer announcements are re-processed when the owner announcement
/// is promoted from purgatory via a git push.
///
/// Flow:
/// 1. relay_a: Three maintainers send announcements + git data → in relay_a's DB
/// 2. relay_b (bootstrapped from relay_a): SyncManager syncs all three maintainer
///    announcements → all rejected (no owner in DB) → all in hot cache
/// 3. relay_b: Owner sends announcement → purgatory
/// 4. relay_b: Owner git push → owner promoted → hot-cache re-processing fires for
///    all three maintainers
/// 5. All four announcements should be in relay_b's database
#[tokio::test]
async fn test_multiple_maintainers_all_reprocessed() {
    // Start relay_a (where maintainer announcements will be sent)
    let relay_a = TestRelay::start().await;
    println!("relay_a started at {}", relay_a.url());

    // Create keys
    let owner_keys = Keys::generate();
    let maintainer1_keys = Keys::generate();
    let maintainer2_keys = Keys::generate();
    let maintainer3_keys = Keys::generate();

    // Use a unique identifier per test run to avoid cross-test interference when
    // tests run in parallel (each test gets its own namespace on relay_a).
    let identifier = &format!(
        "multi-maintainer-repo-{}",
        &owner_keys.public_key().to_hex()[..8]
    );

    // Step 1: Send each maintainer announcement to relay_a then push git data so all three
    // land in relay_a's DB.  Each announcement lists relay_a only, so relay_b will reject
    // them when syncing (no owner announcement in relay_b's DB yet).
    let mut git_dirs = Vec::new();
    let mut maintainer_notes = Vec::new();
    for (idx, maintainer_keys) in [&maintainer1_keys, &maintainer2_keys, &maintainer3_keys]
        .iter()
        .enumerate()
    {
        let m_npub = maintainer_keys
            .public_key()
            .to_bech32()
            .expect("Failed to get npub");
        let announcement = EventBuilder::new(
            Kind::GitRepoAnnouncement,
            format!("Maintainer {} repository", idx + 1),
        )
        .tags(vec![
            Tag::identifier(identifier.as_str()),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{}/{}.git",
                    relay_a.domain(),
                    m_npub,
                    identifier
                )],
            ),
            Tag::custom("relays", vec![relay_a.url().to_string()]),
        ])
        .finalize(*maintainer_keys)
        .unwrap();
        maintainer_notes.push(
            announcement
                .id
                .to_bech32()
                .expect("Failed to encode maintainer announcement ID"),
        );
        send_to_relay(&relay_a, &announcement).await.unwrap();
        // Use push_unique_git_data_to_relay so each maintainer gets a distinct commit
        // hash.  Identical hashes cause git to skip pack transfer when the object
        // already exists on the server, leaving the announcement in purgatory.
        let git_dir = push_unique_git_data_to_relay(
            &relay_a,
            maintainer_keys,
            identifier,
            &[&relay_a.domain()],
            &m_npub,
        )
        .await;
        git_dirs.push(git_dir);
    }
    println!("✓ Three maintainer announcements + git data pushed to relay_a");

    // Confirm all three announcements are queryable on relay_a before starting relay_b.
    // This eliminates the race between relay_a's DB writes and relay_b's initial negentropy sync.
    for (name, keys) in [
        ("maintainer1", &maintainer1_keys),
        ("maintainer2", &maintainer2_keys),
        ("maintainer3", &maintainer3_keys),
    ] {
        let filter = Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(keys.public_key())
            .identifier(identifier);
        let found = wait_for_event_on_relay(relay_a.url(), filter, Duration::from_secs(10)).await;
        assert!(
            found,
            "{} announcement should be in relay_a before starting relay_b",
            name
        );
    }
    println!("✓ All three maintainer announcements confirmed in relay_a's DB");

    // Step 2: Start relay_b with relay_a as bootstrap so its SyncManager connects immediately.
    // Because all three maintainer announcements are confirmed in relay_a's DB, relay_b's
    // initial negentropy sync will pick them all up and reject them (no owner announcement
    // in relay_b's DB yet), storing them in the hot cache.
    let relay_b = TestRelay::start_with_sync_debug(Some(relay_a.url().to_string())).await;
    println!("relay_b started at {}", relay_b.url());

    // Wait for relay_b's initial negentropy sync on its observable outcome:
    // every rejected maintainer announcement is logged by its note ID.
    for note in &maintainer_notes {
        assert!(
            wait_for_log(&relay_b.log_path(), note, Duration::from_secs(30)).await,
            "relay_b should sync, reject and index maintainer announcement {note}"
        );
    }
    println!("✓ relay_b synced from relay_a (maintainer announcements in hot cache)");

    // Step 3: Send owner announcement to relay_b → goes to purgatory.
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");

    let owner_announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Owner's repository")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{}/{}.git",
                    relay_b.domain(),
                    owner_npub,
                    identifier
                )],
            ),
            Tag::custom(
                "relays",
                vec![relay_a.url().to_string(), relay_b.url().to_string()],
            ),
            Tag::custom(
                "maintainers",
                vec![
                    maintainer1_keys.public_key().to_hex(),
                    maintainer2_keys.public_key().to_hex(),
                    maintainer3_keys.public_key().to_hex(),
                ],
            ),
        ])
        .finalize(&owner_keys)
        .unwrap();

    send_to_relay(&relay_b, &owner_announcement).await.unwrap();
    println!("✓ Owner announcement sent to relay_b (now in purgatory)");

    // Step 4: Push owner git data to relay_b.
    // This promotes the owner announcement from purgatory and triggers hot-cache
    // re-processing for all three maintainer announcements.
    let _git_dir_owner =
        push_git_data_to_relay(&relay_b, &owner_keys, identifier, &[&relay_b.domain()]).await;
    println!("✓ Owner git data pushed to relay_b (hot-cache re-processing should fire)");

    // Step 5/6: Verify all four announcements are in relay_b's database.
    // Bounded polls on the served events replace a fixed post-push sleep.
    for (name, keys) in [
        ("owner", &owner_keys),
        ("maintainer1", &maintainer1_keys),
        ("maintainer2", &maintainer2_keys),
        ("maintainer3", &maintainer3_keys),
    ] {
        let filter = Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(keys.public_key())
            .identifier(identifier);

        let found = wait_for_event_on_relay(relay_b.url(), filter, Duration::from_secs(30)).await;
        assert!(found, "{} announcement should be in relay_b", name);
    }

    println!("✅ All three maintainer announcements re-processed successfully");

    relay_a.stop().await;
    relay_b.stop().await;
}

/// Test that invalid maintainer public keys don't cause panics
///
/// Flow:
/// 1. Maintainer announcement arrives → Rejected (doesn't list our relay)
/// 2. Owner announcement + git push → accepted, with INVALID maintainer hex in maintainers tag
/// 3. Owner announcement should be accepted
/// 4. Maintainer announcement should NOT be re-processed (invalid pubkey can't be parsed)
#[tokio::test]
async fn test_invalid_maintainer_pubkey_handled_gracefully() {
    let relay = TestRelay::start().await;

    // Create keys
    let owner_keys = Keys::generate();
    let maintainer_keys = Keys::generate();

    let identifier = "invalid-maintainer-repo";

    // Create client using TestClient helper
    let client = TestClient::new(relay.url(), owner_keys.clone())
        .await
        .expect("Failed to connect to relay");

    // Step 1: Send maintainer announcement (will be rejected - doesn't list our relay)
    let maintainer_announcement =
        EventBuilder::new(Kind::GitRepoAnnouncement, "Maintainer's repository")
            .tags(vec![
                Tag::identifier(identifier),
                Tag::custom(
                    "clone",
                    vec![format!("https://example.com/{}.git", identifier)],
                ),
                Tag::custom("relays", vec!["wss://example.com".to_string()]),
            ])
            .finalize(&maintainer_keys)
            .unwrap();

    // Send maintainer announcement - expect it to be rejected. `send_event`
    // waits for the relay's OK response, so the rejection has already been
    // processed when it returns.
    let _ = client.send_event(&maintainer_announcement).await;

    // Step 2: Send owner announcement with INVALID maintainer hex, then push git data.
    // The announcement goes to purgatory first; the git push promotes it.
    // The invalid maintainer hex should be handled gracefully (no panic).
    let owner_npub = owner_keys
        .public_key()
        .to_bech32()
        .expect("Failed to get npub");

    let owner_announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "Owner's repository")
        .tags(vec![
            Tag::identifier(identifier),
            Tag::custom(
                "clone",
                vec![format!(
                    "http://{}/{}/{}.git",
                    relay.domain(),
                    owner_npub,
                    identifier
                )],
            ),
            Tag::custom("relays", vec![relay.url().to_string()]),
            Tag::custom("maintainers", vec!["invalid-hex-not-a-pubkey".to_string()]),
        ])
        .finalize(&owner_keys)
        .unwrap();

    send_to_relay(&relay, &owner_announcement).await.unwrap();
    let _git_dir =
        push_git_data_to_relay(&relay, &owner_keys, identifier, &[&relay.domain()]).await;

    // Step 3: Verify owner announcement accepted, maintainer not re-processed.
    // The bounded poll on the served announcement replaces a fixed sleep.
    let owner_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(owner_keys.public_key())
        .identifier(identifier);

    let owner_found =
        wait_for_event_on_relay(relay.url(), owner_filter, Duration::from_secs(30)).await;
    assert!(
        owner_found,
        "Owner announcement should be accepted despite invalid maintainer"
    );

    let maintainer_filter = Filter::new()
        .kind(Kind::GitRepoAnnouncement)
        .author(maintainer_keys.public_key())
        .identifier(identifier);

    let maintainer_found =
        wait_for_event_on_relay(relay.url(), maintainer_filter, Duration::from_millis(500)).await;
    assert!(
        !maintainer_found,
        "Maintainer announcement should NOT be re-processed (invalid pubkey)"
    );

    println!("✅ Invalid maintainer pubkey handled gracefully without panic");

    client.disconnect().await;
    relay.stop().await;
}
