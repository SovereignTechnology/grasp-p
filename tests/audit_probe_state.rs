mod common;

use common::{publish_served_audit_repo_with_state, wait_for_event_served, TestRelay};
use grasp_audit::{probe::run_probe, AuditClient, AuditConfig, DETERMINISTIC_COMMIT_HASH};
use nostr_sdk::prelude::*;
use std::time::Duration;

#[tokio::test]
async fn probe_scopes_same_identifier_states_and_reports_extra_refs() {
    let relay = TestRelay::start().await;
    let client = AuditClient::new(relay.url(), AuditConfig::shared())
        .await
        .unwrap();
    let (announcement, identifier, initial_state) =
        publish_served_audit_repo_with_state(&client, "probe-scope").await;
    let owner_path = relay.git_data_path().join(
        ngit_grasp::nostr::events::RepositoryAnnouncement::from_event(announcement.clone())
            .unwrap()
            .repo_path(),
    );
    let unrelated = Keys::generate();
    let foreign_announcement =
        common::create_repo_announcement(&unrelated, &[&relay.domain()], &identifier);
    // Ensure the probe selects the owner's announcement, while the unrelated
    // repository supplies the newest state for this identifier.
    let foreign_announcement = EventBuilder::new(foreign_announcement.kind, "")
        .tags(foreign_announcement.tags.iter().cloned())
        .custom_created_at(Timestamp::from_secs(announcement.created_at.as_secs() - 1))
        .finalize(&unrelated)
        .unwrap();
    let foreign_path = relay.git_data_path().join(
        ngit_grasp::nostr::events::RepositoryAnnouncement::from_event(foreign_announcement.clone())
            .unwrap()
            .repo_path(),
    );
    std::fs::create_dir_all(foreign_path.parent().unwrap()).unwrap();
    let cloned = grasp_audit::git_command()
        .args(["clone", "--bare"])
        .arg(&owner_path)
        .arg(&foreign_path)
        .output()
        .unwrap();
    assert!(
        cloned.status.success(),
        "{}",
        String::from_utf8_lossy(&cloned.stderr)
    );
    client
        .send_event(foreign_announcement.clone())
        .await
        .unwrap();
    let foreign_state = EventBuilder::new(Kind::RepoState, "")
        .tags([
            Tag::identifier(&identifier),
            Tag::custom("refs/heads/foreign", [DETERMINISTIC_COMMIT_HASH]),
            Tag::custom("HEAD", ["ref: refs/heads/foreign"]),
        ])
        .custom_created_at(Timestamp::from_secs(initial_state.created_at.as_secs() + 1))
        .finalize(&unrelated)
        .unwrap();
    client.send_event(foreign_state.clone()).await.unwrap();
    for event in [&foreign_announcement, &foreign_state, &initial_state] {
        wait_for_event_served(relay.url(), &event.id, Duration::from_secs(10))
            .await
            .unwrap();
    }

    let report = run_probe(relay.url(), None, true, 10, 30).await;
    let selection = report
        .checks
        .iter()
        .find(|check| check.name == "serves_latest_announcement")
        .unwrap();
    assert_eq!(
        selection.detail.as_deref(),
        Some(
            format!(
                "{}/{}",
                client.public_key().to_bech32().unwrap(),
                identifier
            )
            .as_str()
        )
    );
    let check = report
        .checks
        .iter()
        .find(|check| check.name == "git_refs_match_state")
        .unwrap();
    assert!(check.passed, "{check:?}");

    for name in ["refs/heads/stale", "refs/tags/stale"] {
        let result = grasp_audit::git_command()
            .arg("--git-dir")
            .arg(&owner_path)
            .args(["update-ref", name, DETERMINISTIC_COMMIT_HASH])
            .output()
            .unwrap();
        assert!(result.status.success());
    }
    let report = run_probe(relay.url(), None, true, 10, 30).await;
    let check = report
        .checks
        .iter()
        .find(|check| check.name == "git_refs_match_state")
        .unwrap();
    assert!(!check.passed);
    let error = check.error.as_deref().unwrap();
    assert!(
        error.contains("refs/heads/stale: unexpected ref"),
        "{error}"
    );
    assert!(error.contains("refs/tags/stale: unexpected ref"), "{error}");
    relay.stop().await;
}
