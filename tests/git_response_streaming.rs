//! Integration coverage for Git Smart HTTP response streaming.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use clap::Parser;
use http_body_util::BodyExt;
use hyper::body::{Bytes, Frame};
use ngit_grasp::config::Config;
use ngit_grasp::git::handlers::handle_receive_pack;
use ngit_grasp::git::sync::PurgatoryPromotionHooks;
use ngit_grasp::grasp06::endpoint::PrsUrl;
use ngit_grasp::grasp06::paths::prs_repo_path;
use ngit_grasp::grasp06::receive::{handle_prs_receive_pack, new_repo_init_locks};
use ngit_grasp::nostr::builder::Nip34WritePolicy;
use ngit_grasp::nostr::lifecycle::{
    HoldingStore, ReplaceableHistoryStore, RepositoryLifecycle, Tombstones,
};
use ngit_grasp::nostr::SharedDatabase;
use ngit_grasp::purgatory::Purgatory;
use ngit_grasp::sync::rejected_index::RejectedEventsIndex;
use nostr_sdk::prelude::LocalRelayBuilder;
use nostr_sdk::prelude::*;
use tokio::sync::Semaphore;
use tokio::time::timeout;

static PATH_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct PathOverride {
    original: Option<std::ffi::OsString>,
}

impl PathOverride {
    fn prepend(dir: &Path) -> Self {
        let original = std::env::var_os("PATH");
        let mut paths = vec![dir.to_path_buf()];
        if let Some(existing) = original.as_ref() {
            paths.extend(std::env::split_paths(existing));
        }
        let joined = std::env::join_paths(paths).expect("join PATH entries");
        std::env::set_var("PATH", joined);
        Self { original }
    }
}

impl Drop for PathOverride {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            std::env::set_var("PATH", original);
        } else {
            std::env::remove_var("PATH");
        }
    }
}

#[tokio::test]
async fn receive_pack_response_streams_stdout_before_subprocess_exit() {
    let _env_lock = PATH_ENV_LOCK.lock().await;

    let fake_bin = tempfile::tempdir().expect("fake git bin tempdir");
    write_fake_git(fake_bin.path());
    let _path = PathOverride::prepend(fake_bin.path());

    let repo = tempfile::tempdir().expect("repo tempdir");
    let git_data = tempfile::tempdir().expect("git data tempdir");
    let database: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let relay = LocalRelayBuilder::default().build();
    let purgatory = Arc::new(Purgatory::new(git_data.path().to_path_buf()));
    let owner_pubkey = "0".repeat(64);
    let request_body = receive_pack_request_body();

    let response = handle_receive_pack(
        repo.path().to_path_buf(),
        request_body,
        database,
        relay,
        "streaming-test",
        &owner_pubkey,
        purgatory,
        git_data.path().to_str().expect("utf-8 temp path"),
        None,
        None,
        None,
        None,
    )
    .await
    .expect("receive-pack handler should start fake subprocess");

    let mut body = response.into_body();

    let first = timeout(Duration::from_secs(1), body.frame())
        .await
        .expect("first stdout chunk should arrive before fake git exits")
        .expect("body should still be open")
        .expect("first frame should not be an HTTP body error");
    let first = frame_data(first);
    assert!(
        !first.is_empty(),
        "first progress frame should contain data"
    );

    let no_second_yet = timeout(Duration::from_millis(250), body.frame()).await;
    assert!(
        no_second_yet.is_err(),
        "body produced another frame while fake git was still sleeping; \
         this test needs the first frame to be observed before subprocess EOF"
    );

    let mut streamed = first.to_vec();
    loop {
        let frame = timeout(Duration::from_secs(3), body.frame())
            .await
            .expect("remaining stdout should arrive after fake git wakes");
        let Some(frame) = frame else {
            break;
        };
        streamed.extend_from_slice(
            &frame
                .expect("remaining frame should not be an HTTP body error")
                .into_data()
                .expect("remaining frame should contain data"),
        );
    }
    assert_eq!(streamed, b"first-progress\nsecond-progress\n");
}

#[derive(Clone)]
struct BlockingAnnouncementPromotion {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

#[async_trait]
impl PurgatoryPromotionHooks for BlockingAnnouncementPromotion {
    async fn before_announcement_promote(&self, _event: &Event, _identifier: &str) {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("promotion release semaphore should remain open")
            .forget();
    }
}

#[tokio::test]
async fn receive_pack_terminal_flush_waits_for_purgatory_promotion() {
    let _env_lock = PATH_ENV_LOCK.lock().await;

    let fake_bin = tempfile::tempdir().expect("fake git bin tempdir");
    write_fake_git_with_terminal_flush(fake_bin.path());
    let _path = PathOverride::prepend(fake_bin.path());

    let keys = Keys::generate();
    let owner_npub = keys.public_key().to_bech32().expect("encode owner npub");
    let identifier = "push-readiness";
    let git_data = tempfile::tempdir().expect("git data tempdir");
    let repo_path = git_data
        .path()
        .join(&owner_npub)
        .join(format!("{identifier}.git"));
    std::fs::create_dir_all(&repo_path).expect("create fake bare repo path");

    let database: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let relay = LocalRelayBuilder::default().build();
    let purgatory = Arc::new(Purgatory::new(git_data.path().to_path_buf()));
    let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags(vec![Tag::identifier(identifier)])
        .finalize(&keys)
        .expect("build announcement");
    purgatory.add_announcement(
        announcement.clone(),
        identifier.to_string(),
        keys.public_key(),
        repo_path.clone(),
        HashSet::new(),
    );

    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let hooks = BlockingAnnouncementPromotion {
        entered: entered.clone(),
        release: release.clone(),
    };

    let response = handle_receive_pack(
        repo_path,
        receive_pack_request_body(),
        database.clone(),
        relay,
        identifier,
        &keys.public_key().to_hex(),
        purgatory,
        git_data.path().to_str().expect("utf-8 temp path"),
        None,
        None,
        Some(Arc::new(hooks)),
        None,
    )
    .await
    .expect("receive-pack handler should start fake subprocess");

    let mut body = response.into_body();
    let first = timeout(Duration::from_secs(1), body.frame())
        .await
        .expect("receive-pack progress should stream before promotion")
        .expect("body should contain progress")
        .expect("progress frame should not be an HTTP body error");
    let mut streamed = frame_data(first).to_vec();

    timeout(Duration::from_secs(3), entered.acquire())
        .await
        .expect("post-push promotion hook should run")
        .expect("promotion semaphore should remain open")
        .forget();

    let before_save = database
        .query(Filter::new().id(announcement.id))
        .await
        .expect("query announcement before promotion");
    assert!(
        before_save.is_empty(),
        "announcement must not be queryable while promotion is blocked"
    );

    while let Ok(Some(frame)) = timeout(Duration::from_millis(25), body.frame()).await {
        streamed.extend_from_slice(
            &frame
                .expect("progress frame should not be an HTTP body error")
                .into_data()
                .expect("progress frame should contain data"),
        );
    }
    assert!(
        !streamed.ends_with(b"0000"),
        "receive-pack terminal flush must remain hidden while promotion is blocked"
    );

    let keepalive = timeout(Duration::from_secs(6), body.frame())
        .await
        .expect("sideband keepalive should arrive during blocked promotion")
        .expect("body should remain open while promotion is blocked")
        .expect("keepalive should not be an HTTP body error");
    streamed.extend_from_slice(
        &keepalive
            .into_data()
            .expect("keepalive frame should contain data"),
    );
    assert!(
        streamed
            .windows(b"GRASP is finalizing the push\n".len())
            .any(|window| window == b"GRASP is finalizing the push\n"),
        "blocked post-push processing should emit sideband progress"
    );
    assert!(
        !streamed.ends_with(b"0000"),
        "keepalive must not expose the terminal flush"
    );

    release.add_permits(1);

    loop {
        let frame = timeout(Duration::from_secs(1), body.frame())
            .await
            .expect("response should finish after promotion is released");
        let Some(frame) = frame else {
            break;
        };
        streamed.extend_from_slice(
            &frame
                .expect("terminal frame should not be an HTTP body error")
                .into_data()
                .expect("terminal frame should contain data"),
        );
    }

    assert!(
        streamed.starts_with(b"first-progress\nsecond-progress\n"),
        "git progress should remain at the start of the response"
    );
    assert!(
        streamed.ends_with(b"0000"),
        "terminal flush should remain the final client-visible bytes"
    );
    let after_save = database
        .query(Filter::new().id(announcement.id))
        .await
        .expect("query announcement after promotion");
    assert_eq!(
        after_save.len(),
        1,
        "announcement must be queryable before push success is exposed"
    );
}

#[tokio::test]
async fn prs_receive_pack_streams_stdout_before_cleanup_removes_empty_repo() {
    let _env_lock = PATH_ENV_LOCK.lock().await;

    let fake_bin = tempfile::tempdir().expect("fake git bin tempdir");
    write_fake_git_with_terminal_flush(fake_bin.path());
    let _path = PathOverride::prepend(fake_bin.path());

    let keys = Keys::generate();
    let git_data = tempfile::tempdir().expect("git data tempdir");
    let database: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let relay = LocalRelayBuilder::default().build();
    let purgatory = Arc::new(Purgatory::new(git_data.path().to_path_buf()));
    let repo_init_locks = new_repo_init_locks();
    let write_policy = Arc::new(test_write_policy(
        database.clone(),
        purgatory.clone(),
        repo_init_locks.clone(),
        git_data.path(),
    ));
    let rejected_events_index = Arc::new(RejectedEventsIndex::new(
        Duration::from_secs(120),
        Duration::from_secs(7 * 24 * 60 * 60),
    ));
    let prs = PrsUrl {
        submitter: keys.public_key(),
        identifier: "prs-streaming-cleanup".to_string(),
        subpath: "git-receive-pack".to_string(),
    };
    let repo_path = prs_repo_path(git_data.path(), &prs.submitter.to_hex(), &prs.identifier);

    let response = handle_prs_receive_pack(
        &prs,
        receive_pack_request_body(),
        database,
        relay,
        purgatory,
        write_policy,
        rejected_events_index,
        git_data.path().to_str().expect("utf-8 temp path"),
        None,
        repo_init_locks,
        "streaming-test.example",
        None,
    )
    .await
    .expect("/prs/ receive-pack handler should start fake subprocess");

    assert!(
        repo_path.exists(),
        "/prs/ repo should exist while fake receive-pack is in flight"
    );

    let mut body = response.into_body();

    let first = timeout(Duration::from_secs(1), body.frame())
        .await
        .expect("first /prs/ stdout chunk should arrive before fake git exits")
        .expect("/prs/ body should still be open")
        .expect("first /prs/ frame should not be an HTTP body error");
    let mut streamed = frame_data(first).to_vec();
    assert!(
        b"first-progress\n".starts_with(&streamed),
        "the four-byte terminal look-behind may split the first progress chunk"
    );

    assert!(
        repo_path.exists(),
        "/prs/ cleanup must not remove the repo before receive-pack exits"
    );

    let no_second_yet = timeout(Duration::from_millis(250), body.frame()).await;
    assert!(
        no_second_yet.is_err(),
        "/prs/ body produced another frame while fake git was still sleeping; \
         this test needs the first frame to be observed before subprocess EOF"
    );

    let second = timeout(Duration::from_secs(3), body.frame())
        .await
        .expect("second /prs/ stdout chunk should arrive after fake git wakes")
        .expect("/prs/ body should still be open for second chunk")
        .expect("second /prs/ frame should not be an HTTP body error");
    streamed.extend_from_slice(&frame_data(second));

    // Family ref retention happens behind this boundary. Keep the deadline
    // bounded but allow finalization the same scheduling headroom as the
    // subprocess wake above.
    let terminal = timeout(Duration::from_secs(3), body.frame())
        .await
        .expect("/prs/ terminal flush should arrive after cleanup")
        .expect("/prs/ body should contain the terminal flush")
        .expect("/prs/ terminal frame should not be an HTTP body error");
    streamed.extend_from_slice(&frame_data(terminal));
    assert_eq!(streamed, b"first-progress\nsecond-progress\n0000");

    let eof = timeout(Duration::from_secs(1), body.frame())
        .await
        .expect("/prs/ body should close after cleanup");
    assert!(
        eof.is_none(),
        "/prs/ body should be closed after fake git exits"
    );

    assert!(
        !repo_path.exists(),
        "/prs/ cleanup should remove zero-ref repo after receive-pack exits"
    );
}

fn frame_data(frame: Frame<Bytes>) -> Bytes {
    frame.into_data().expect("frame should contain data")
}

fn receive_pack_request_body() -> Bytes {
    let old_oid = "0".repeat(40);
    let new_oid = "1".repeat(40);
    let event_id = "a".repeat(64);
    let mut payload = Vec::new();
    payload.extend_from_slice(format!("{old_oid} {new_oid} refs/nostr/{event_id}").as_bytes());
    payload.push(0);
    payload.extend_from_slice(b"report-status side-band-64k\n");

    let mut request = Vec::new();
    request.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
    request.extend_from_slice(&payload);
    request.extend_from_slice(b"0000");
    Bytes::from(request)
}

fn test_write_policy(
    database: SharedDatabase,
    purgatory: Arc<Purgatory>,
    repo_init_locks: ngit_grasp::grasp06::receive::RepoInitLocks,
    git_data_path: &Path,
) -> Nip34WritePolicy {
    let config = Config::parse_from([
        "ngit-grasp-test",
        "--domain",
        "streaming-test.example",
        "--grasp06-enable",
    ]);

    Nip34WritePolicy::new(
        database,
        Tombstones::in_memory(),
        HoldingStore::in_memory(),
        RepositoryLifecycle::in_memory(),
        ReplaceableHistoryStore::in_memory(),
        git_data_path.to_path_buf(),
        purgatory,
        config,
        repo_init_locks,
        None,
    )
}

fn write_fake_git(bin_dir: &Path) {
    write_fake_git_script(bin_dir, false);
}

fn write_fake_git_with_terminal_flush(bin_dir: &Path) {
    write_fake_git_script(bin_dir, true);
}

fn write_fake_git_script(bin_dir: &Path, terminal_flush: bool) {
    let git_path = bin_dir.join("git");
    let terminal_flush = if terminal_flush {
        "printf '0000'\n"
    } else {
        ""
    };
    std::fs::write(
        &git_path,
        r#"#!/usr/bin/env bash
set -euo pipefail

is_receive_pack=0
for arg in "$@"; do
  if [ "$arg" = "receive-pack" ]; then
    is_receive_pack=1
  fi
done

if [ "$is_receive_pack" = "1" ]; then
cat >/dev/null
printf 'first-progress\n'
sleep 2
printf 'second-progress\n'
__TERMINAL_FLUSH__exit 0
fi

if [ "$1" = "init" ]; then
  repo="${@: -1}"
  mkdir -p "$repo/objects/info"
  exit 0
fi

if [ "$1" = "config" ]; then
  exit 0
fi

if [ "$1" = "rev-parse" ] && [ "${2:-}" = "--show-object-format" ]; then
  printf 'sha1\n'
  exit 0
fi

if [ "$1" = "cat-file" ]; then
  exit 1
fi

if [ "$1" = "for-each-ref" ]; then
  exit 0
fi

echo "unsupported fake git invocation: $*" >&2
exit 1
"#
        .replace("__TERMINAL_FLUSH__", terminal_flush),
    )
    .expect("write fake git executable");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&git_path)
            .expect("fake git metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&git_path, perms).expect("chmod fake git");
    }
}
