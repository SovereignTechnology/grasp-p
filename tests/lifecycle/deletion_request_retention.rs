//! Live-relay contracts for bounded deletion-request retention.
//!
//! These deliberately cover only the subprocess-visible lifecycle boundaries:
//! main-database serving, admission gates, periodic cleanup, LMDB persistence,
//! and policy-mode restart reconciliation. Component edge cases live in Stage
//! 10A's unit tests.

#[path = "../common/mod.rs"]
mod common;

use common::{
    build_deletion, build_vanish, publish_served_repo, DeletionLifecycleOptions, TestRelay,
};
use grasp_audit::{AuditClient, AuditConfig};
use ngit_grasp::nostr::lifecycle::Tombstones;
use nostr_sdk::prelude::*;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const POLL_TIMEOUT: Duration = Duration::from_secs(10);

fn lifecycle_options() -> DeletionLifecycleOptions {
    DeletionLifecycleOptions {
        // Durations are whole seconds because lifecycle timestamps are durable
        // Unix seconds. The non-zero two/four-second boundaries leave a full
        // scheduler tick of slack without making this subprocess suite costly.
        unused_served_retention_secs: 2,
        unused_gating_additional_secs: 4,
        used_served_after_last_use_secs: 2,
        used_gating_additional_secs: 4,
        cleanup_interval_secs: 1,
        git_data_path: None,
        relay_data_path: None,
        deletion_request_disrespector: false,
    }
}

async fn wait_until<F, Fut>(description: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + POLL_TIMEOUT;
    loop {
        if condition().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out after {:?}: {description}",
            POLL_TIMEOUT
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn is_served(client: &AuditClient, id: EventId) -> bool {
    client
        .is_event_on_relay(id)
        .await
        .expect("query relay event")
}

async fn open_tombstones(relay_data_path: PathBuf) -> Tombstones {
    Tombstones::open_lmdb(&relay_data_path)
        .await
        .expect("open persistent tombstone store")
}

#[tokio::test]
async fn unused_request_moves_from_served_probation_to_unserved_gate() {
    let relay = TestRelay::start_with_deletion_lifecycle(lifecycle_options()).await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");
    let (announcement, _) = publish_served_repo(&client, "unused-gate").await;
    let target = client
        .create_issue(
            &announcement,
            "late target",
            "blocked after probation",
            vec![],
        )
        .expect("build target");
    let request = build_deletion(&client, &[target.id], &[]);

    client
        .send_event(request.clone())
        .await
        .expect("accept pre-emptive deletion request");
    assert!(
        is_served(&client, request.id).await,
        "new request is served"
    );

    wait_until(
        "unused request removed from normal relay queries",
        || async { !is_served(&client, request.id).await },
    )
    .await;

    let rejected = client.send_event(target).await;
    assert!(
        rejected.is_err(),
        "unserved request must still gate its target"
    );
    wait_until(
        "gating use promotes request back to served state",
        || async { is_served(&client, request.id).await },
    )
    .await;

    let store = open_tombstones(relay.relay_data_path().clone()).await;
    assert!(
        store
            .lifecycle_for_request_result(&request.id)
            .await
            .expect("read lifecycle")
            .expect("retained lifecycle")
            .last_used_at
            .is_some(),
        "admission rejection must persist a last-used timestamp"
    );
    relay.stop().await;
}

#[tokio::test]
async fn unused_request_expires_completely_after_its_gate_period() {
    let relay = TestRelay::start_with_deletion_lifecycle(lifecycle_options()).await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");
    let (announcement, _) = publish_served_repo(&client, "unused-expiry").await;
    let target = client
        .create_issue(
            &announcement,
            "future target",
            "accepted after expiry",
            vec![],
        )
        .expect("build target");
    let request = build_deletion(&client, &[target.id], &[]);
    client
        .send_event(request.clone())
        .await
        .expect("accept pre-emptive deletion request");

    let relay_data_path = relay.relay_data_path().clone();
    wait_until(
        "unused request payload and lifecycle metadata permanently removed",
        || {
            let relay_data_path = relay_data_path.clone();
            async move {
                let store = open_tombstones(relay_data_path).await;
                store
                    .lifecycle_for_request_result(&request.id)
                    .await
                    .expect("read lifecycle")
                    .is_none()
                    && store
                        .request_payloads()
                        .await
                        .expect("read request payloads")
                        .into_iter()
                        .all(|payload| payload.id != request.id)
            }
        },
    )
    .await;
    assert!(
        !is_served(&client, request.id).await,
        "expired request is unserved"
    );

    client
        .send_event(target.clone())
        .await
        .expect("expired request must no longer reject target");
    wait_until(
        "target accepted after request expiry is queryable",
        || async { is_served(&client, target.id).await },
    )
    .await;
    relay.stop().await;
}

#[tokio::test]
async fn used_request_reset_from_unserved_gate_outlives_original_expiry() {
    let relay = TestRelay::start_with_deletion_lifecycle(lifecycle_options()).await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");
    let (announcement, _) = publish_served_repo(&client, "used-reset").await;
    let target = client
        .create_issue(&announcement, "delete then retry", "used lifecycle", vec![])
        .expect("build target");
    client
        .send_event(target.clone())
        .await
        .expect("accept target before deletion");
    let request = build_deletion(&client, &[target.id], &[]);
    client
        .send_event(request.clone())
        .await
        .expect("accept deletion of existing target");
    wait_until("used request initially served", || async {
        is_served(&client, request.id).await
    })
    .await;
    let initial_last_used_at = open_tombstones(relay.relay_data_path().clone())
        .await
        .lifecycle_for_request_result(&request.id)
        .await
        .expect("read initial lifecycle")
        .expect("used lifecycle exists")
        .last_used_at
        .expect("deletion of existing target records last use");

    wait_until("used request moves to its unserved gate", || async {
        !is_served(&client, request.id).await
    })
    .await;
    assert!(
        client.send_event(target).await.is_err(),
        "used request must still reject during its unserved gate"
    );
    wait_until("gate rejection restores served request", || async {
        is_served(&client, request.id).await
    })
    .await;

    // The original deadline is six seconds after first use. Poll past it rather
    // than sleeping for a scheduler-dependent duration; the reset request is
    // still inside its own additional gate window at this point.
    wait_until(
        "reset lifecycle survives its original expiry deadline",
        || {
            let relay_data_path = relay.relay_data_path().clone();
            async move {
                if Timestamp::now().as_secs() < initial_last_used_at.as_secs() + 7 {
                    return false;
                }
                open_tombstones(relay_data_path)
                    .await
                    .lifecycle_for_request_result(&request.id)
                    .await
                    .expect("read lifecycle")
                    .and_then(|record| record.last_used_at)
                    .is_some()
            }
        },
    )
    .await;
    relay.stop().await;
}

#[tokio::test]
async fn lmdb_restart_reconciles_current_mode_without_resetting_lifecycle() {
    let directories = tempfile::tempdir().expect("create persistent parent directory");
    let git_data_path = directories.path().join("git");
    let relay_data_path = directories.path().join("relay");
    let options = DeletionLifecycleOptions {
        unused_served_retention_secs: 15,
        unused_gating_additional_secs: 15,
        used_served_after_last_use_secs: 15,
        used_gating_additional_secs: 15,
        cleanup_interval_secs: 1,
        git_data_path: Some(git_data_path),
        relay_data_path: Some(relay_data_path.clone()),
        deletion_request_disrespector: false,
    };
    let normal = TestRelay::start_with_deletion_lifecycle(options.clone()).await;
    let author = AuditClient::new(normal.url(), AuditConfig::isolated())
        .await
        .expect("create author");
    let (announcement, _) = publish_served_repo(&author, "restart-reconcile").await;
    let accepted_in_archive = author
        .create_issue(&announcement, "archive mode target", "must survive", vec![])
        .expect("build archive target");
    let normally_gated = author
        .create_issue(
            &announcement,
            "normal mode target",
            "must be blocked",
            vec![],
        )
        .expect("build normal target");
    let already_used_target = author
        .create_issue(
            &announcement,
            "already used target",
            "timestamps survive mode changes",
            vec![],
        )
        .expect("build already-used target");
    author
        .send_event(already_used_target.clone())
        .await
        .expect("store target for an immediately used request");
    let archive_request = build_deletion(&author, &[accepted_in_archive.id], &[]);
    let gate_request = build_deletion(&author, &[normally_gated.id], &[]);
    let used_request = build_deletion(&author, &[already_used_target.id], &[]);
    for request in [&archive_request, &gate_request, &used_request] {
        author
            .send_event(request.clone())
            .await
            .expect("persist retained request");
    }
    let before = open_tombstones(relay_data_path.clone())
        .await
        .lifecycle_for_request_result(&used_request.id)
        .await
        .expect("read retained lifecycle")
        .expect("retained lifecycle exists");
    assert!(
        before.last_used_at.is_some(),
        "request that deleted an existing target must be marked used"
    );
    normal.stop().await;

    let mut archival_options = options.clone();
    archival_options.deletion_request_disrespector = true;
    let archival = TestRelay::start_with_deletion_lifecycle(archival_options).await;
    let archive_client = AuditClient::new_with_keys(
        archival.url(),
        AuditConfig::isolated(),
        author.keys().clone(),
    )
    .await
    .expect("reconnect author to archival relay");
    assert!(
        is_served(&archive_client, gate_request.id).await,
        "request remains served"
    );
    archive_client
        .send_event(accepted_in_archive.clone())
        .await
        .expect("disrespector mode accepts previously targeted event");
    wait_until("disrespector leaves stored target queryable", || async {
        is_served(&archive_client, accepted_in_archive.id).await
    })
    .await;
    archival.stop().await;

    let restored = TestRelay::start_with_deletion_lifecycle(options).await;
    let restored_client = AuditClient::new_with_keys(
        restored.url(),
        AuditConfig::isolated(),
        author.keys().clone(),
    )
    .await
    .expect("reconnect author to normal relay");
    assert!(
        is_served(&restored_client, accepted_in_archive.id).await,
        "normal-mode reconciliation must not mutate target stored in archival mode"
    );
    assert!(
        restored_client.send_event(normally_gated).await.is_err(),
        "normal-mode restart must restore retained deletion gates"
    );
    let after = open_tombstones(relay_data_path).await;
    let after = after
        .lifecycle_for_request_result(&used_request.id)
        .await
        .expect("read reconciled lifecycle")
        .expect("reconciled lifecycle exists");
    assert_eq!(
        before.first_seen_at, after.first_seen_at,
        "restart must not reset first seen"
    );
    assert_eq!(
        before.last_used_at, after.last_used_at,
        "restart must not reset last use"
    );
    restored.stop().await;
}

#[tokio::test]
async fn nip62_targeting_gates_while_non_targeting_request_never_does() {
    let relay = TestRelay::start_with_deletion_lifecycle(lifecycle_options()).await;
    let repo_owner = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create repository owner");
    let (announcement, _) = publish_served_repo(&repo_owner, "nip62-retention").await;
    let targeted_author = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create targeted author");
    let non_targeted_author = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create non-targeted author");

    let targeting = build_vanish(&targeted_author, None);
    targeted_author
        .send_event(targeting.clone())
        .await
        .expect("accept targeting vanish request");
    let blocked = targeted_author
        .create_issue(&announcement, "blocked by vanish", "must reject", vec![])
        .expect("build later targeted event");
    assert!(
        targeted_author.send_event(blocked).await.is_err(),
        "targeting vanish must gate later author events"
    );

    let non_targeting = build_vanish(&non_targeted_author, Some("wss://other.example"));
    non_targeted_author
        .send_event(non_targeting.clone())
        .await
        .expect("accept non-targeting vanish request");
    assert!(is_served(&non_targeted_author, non_targeting.id).await);
    wait_until("non-targeting vanish follows served retention", || async {
        !is_served(&non_targeted_author, non_targeting.id).await
    })
    .await;
    let allowed = non_targeted_author
        .create_issue(&announcement, "not locally vanished", "must accept", vec![])
        .expect("build later non-targeted event");
    non_targeted_author
        .send_event(allowed.clone())
        .await
        .expect("non-targeting vanish must never gate its author");
    wait_until("non-targeted author event is queryable", || async {
        is_served(&non_targeted_author, allowed.id).await
    })
    .await;
    relay.stop().await;
}

#[tokio::test]
async fn normal_mode_nip62_replay_from_unserved_gate_does_not_make_a_noop_request_used() {
    let relay = TestRelay::start_with_deletion_lifecycle(lifecycle_options()).await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");
    let request = build_vanish(&client, None);

    client
        .send_event(request.clone())
        .await
        .expect("accept initial no-op vanish request");
    wait_until(
        "no-op vanish request moves to its unserved gate",
        || async { !is_served(&client, request.id).await },
    )
    .await;
    client
        .send_event(request.clone())
        .await
        .expect("accept exact no-op vanish replay from its unserved gate");

    let record = open_tombstones(relay.relay_data_path().clone())
        .await
        .lifecycle_for_request_result(&request.id)
        .await
        .expect("read request lifecycle")
        .expect("retain request lifecycle");
    assert_eq!(
        record.last_used_at, None,
        "replaying a no-op vanish must not let it delete itself or count as use"
    );
    relay.stop().await;
}

#[tokio::test]
async fn disrespector_nip62_replay_does_not_make_a_noop_request_used() {
    let mut options = lifecycle_options();
    options.deletion_request_disrespector = true;
    let relay = TestRelay::start_with_deletion_lifecycle(options).await;
    let client = AuditClient::new(relay.url(), AuditConfig::isolated())
        .await
        .expect("create client");
    let request = build_vanish(&client, None);

    client
        .send_event(request.clone())
        .await
        .expect("accept initial no-op vanish request");
    client
        .send_event(request.clone())
        .await
        .expect("accept exact no-op vanish replay");

    let record = open_tombstones(relay.relay_data_path().clone())
        .await
        .lifecycle_for_request_result(&request.id)
        .await
        .expect("read request lifecycle")
        .expect("retain request lifecycle");
    assert_eq!(
        record.last_used_at, None,
        "replaying a no-op vanish must not make it indefinitely retained in disrespector mode"
    );
    relay.stop().await;
}
