//! Unsigned uploads are staged in their view and earn family storage only
//! when a signed event names them.
//!
//! ```bash
//! cargo test --test pending_upload_staging
//! ```

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{CommitVariant, TestRelay};
use grasp_audit::{AuditClient, AuditConfig};
use ngit_grasp::git::staging;
use nostr_sdk::prelude::*;

const DEADLINE: Duration = Duration::from_secs(20);

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    grasp_audit::git_command()
        .current_dir(repo)
        .args(args)
        .output()
        .expect("spawn git")
}

/// Every object in the family, which has no alternates of its own.
fn family_objects(family: &Path) -> String {
    let output = git(
        family,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
    );
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

/// Object files in the view's own object directory, which is its staging.
fn staged_files(view: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(view.join("objects")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == "info" || !entry.file_type().unwrap().is_dir() {
            continue;
        }
        for file in std::fs::read_dir(entry.path()).unwrap() {
            files.push(file.unwrap().path());
        }
    }
    files
}

/// Whether `repo` holds `tip` and its whole history without any other store.
fn holds_history(repo: &Path, tip: &str) -> bool {
    git(repo, &["rev-list", "--objects", "--missing=error", tip])
        .status
        .success()
}

struct Served {
    _persistent: tempfile::TempDir,
    relay: TestRelay,
    client: AuditClient,
    announcement: Event,
    state: Event,
    identifier: String,
    npub: String,
    view: PathBuf,
    family: PathBuf,
}

impl Served {
    /// A relay serving one repository whose maintainer push has completed.
    async fn start(name: &str) -> Self {
        let persistent = tempfile::tempdir().unwrap();
        let git_data = persistent.path().join("git");
        let relay = TestRelay::start_with_existing_lmdb_paths(
            git_data.clone(),
            persistent.path().join("relay"),
            None,
            false,
        )
        .await;
        let client = AuditClient::new(relay.url(), AuditConfig::isolated())
            .await
            .unwrap();
        let (announcement, identifier, state) =
            common::publish_served_audit_repo_with_state(&client, name).await;
        let npub = client.public_key().to_bech32().unwrap();
        let view = git_data.join(&npub).join(format!("{identifier}.git"));
        let family = git_data
            .join(".grasp/families/sha1")
            .join(format!("{identifier}.git"));
        Self {
            _persistent: persistent,
            relay,
            client,
            announcement,
            state,
            identifier,
            npub,
            view,
            family,
        }
    }

    fn pr_event(&self, tip: &str, title: &str) -> Event {
        common::create_pr_event(
            self.client.keys(),
            &common::announcement_coordinate(&self.announcement, &self.identifier),
            tip,
            title,
        )
        .unwrap()
    }

    fn push(&self, local: &Path, tip: &str, event: &Event) {
        common::push_ref_to_relay(
            local,
            &self.relay.domain(),
            &self.npub,
            &self.identifier,
            tip,
            &format!("refs/nostr/{}", event.id),
        )
        .unwrap();
    }

    async fn accept(&self, event: &Event) {
        let client = AuditClient::new(self.relay.url(), AuditConfig::isolated())
            .await
            .unwrap();
        client.send_event(event.clone()).await.unwrap();
        common::wait_for_event_served(self.relay.url(), &event.id, DEADLINE)
            .await
            .unwrap();
    }

    async fn wait_until_unstaged(&self) {
        common::wait_for("staging to be reclaimed", DEADLINE, || async {
            !staging::is_staged(&self.view) && staged_files(&self.view).is_empty()
        })
        .await;
    }
}

#[tokio::test]
async fn signed_push_is_received_into_the_family_without_staging() {
    let served = Served::start("staging-signed-push").await;

    assert!(!staging::is_staged(&served.view));
    assert_eq!(staged_files(&served.view), Vec::<PathBuf>::new());
    let main = ngit_grasp::git::get_ref_commit(&served.view, "refs/heads/main").unwrap();
    assert!(holds_history(&served.family, &main));

    served.relay.stop().await;
}

#[tokio::test]
async fn unsigned_upload_is_staged_across_a_crash_and_promoted_on_acceptance() {
    let mut served = Served::start("staging-unsigned-upload").await;
    let family_before = family_objects(&served.family);
    let local = tempfile::tempdir().unwrap();
    let tip = common::create_test_repo_with_commit(local.path(), CommitVariant::PrTest).unwrap();
    let event = served.pr_event(&tip, "staged until signed");

    served.push(local.path(), &tip, &event);

    assert!(staging::is_staged(&served.view));
    assert!(ngit_grasp::git::oid_exists(&served.view, &tip));
    assert_eq!(
        family_objects(&served.family),
        family_before,
        "an unsigned upload reached the family"
    );

    // Killing the relay loses any purgatory placeholder not yet checkpointed;
    // the staged ref and objects must not depend on it.
    served.relay = served.relay.restart().await;
    assert!(staging::is_staged(&served.view));
    assert!(holds_history(&served.view, &tip));
    assert_eq!(family_objects(&served.family), family_before);

    served.accept(&event).await;

    assert!(
        holds_history(&served.family, &tip),
        "an accepted PR must be complete in the family alone"
    );
    served.wait_until_unstaged().await;
    assert!(holds_history(&served.view, &tip));

    served.relay.stop().await;
}

#[tokio::test]
async fn signed_push_onto_staged_history_is_complete_in_the_family() {
    let served = Served::start("staging-signed-onto-staged").await;
    let local = tempfile::tempdir().unwrap();
    let pending_tip =
        common::create_test_repo_with_commit(local.path(), CommitVariant::PrTest).unwrap();
    let pending = served.pr_event(&pending_tip, "never signed");
    served.push(local.path(), &pending_tip, &pending);
    assert!(staging::is_staged(&served.view));

    // The view advertises the pending tip, so this push omits its objects.
    let signed_tip = common::add_commit_to_repo(local.path(), CommitVariant::SecondCommit).unwrap();
    let signed = served.pr_event(&signed_tip, "signed before its push");
    let client = AuditClient::new(served.relay.url(), AuditConfig::isolated())
        .await
        .unwrap();
    client
        .send_event_and_note_purgatory(signed.clone())
        .await
        .unwrap();
    served.push(local.path(), &signed_tip, &signed);

    common::wait_for_event_served(served.relay.url(), &signed.id, DEADLINE)
        .await
        .unwrap();
    assert!(
        holds_history(&served.family, &signed_tip),
        "signed history depends on objects that only staging holds"
    );
    // The pending ref is untouched. Its history is now an ancestor of signed
    // history, so the family holds it and nothing is left to stage.
    assert!(holds_history(&served.view, &pending_tip));
    served.wait_until_unstaged().await;

    served.relay.stop().await;
}

#[tokio::test]
async fn maintainer_push_into_a_staged_view_reaches_the_family() {
    let served = Served::start("staging-maintainer-push").await;
    let local = tempfile::tempdir().unwrap();
    let pending_tip =
        common::create_test_repo_with_commit(local.path(), CommitVariant::PrTest).unwrap();
    let pending = served.pr_event(&pending_tip, "never signed");
    served.push(local.path(), &pending_tip, &pending);
    assert!(staging::is_staged(&served.view));

    let clone =
        grasp_audit::clone_repo(&served.relay.domain(), &served.npub, &served.identifier).unwrap();
    std::fs::write(clone.join("next.txt"), "next state").unwrap();
    assert!(git(&clone, &["add", "."]).status.success());
    assert!(git(&clone, &["commit", "-m", "next state"])
        .status
        .success());
    let next = String::from_utf8(git(&clone, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_owned();
    let state = common::event_ordering::event_after(
        common::create_state_event(
            served.client.keys(),
            &served.identifier,
            &[("main", &next)],
            &[],
            &[],
            &[],
        )
        .unwrap(),
        served.client.keys(),
        served.state.created_at,
    );
    served
        .client
        .send_event_and_note_purgatory(state.clone())
        .await
        .unwrap();
    assert!(grasp_audit::try_push(&clone).unwrap());
    let _ = std::fs::remove_dir_all(&clone);

    common::wait_for_event_served(served.relay.url(), &state.id, DEADLINE)
        .await
        .unwrap();
    // Rollback after a State deletion depends on this history, whatever
    // becomes of the view's refs.
    assert!(holds_history(&served.family, &next));
    assert!(!staging::owes_history(&served.view));

    served.relay.stop().await;
}
