//! Integration coverage for Git Smart HTTP response streaming.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use clap::Parser;
use http_body_util::BodyExt;
use hyper::body::{Body, Bytes, Frame};
use ngit_grasp::config::Config;
use ngit_grasp::git::handlers::handle_receive_pack;
use ngit_grasp::git::protocol::PktLine;
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
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
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
    exercise_receive_pack_stream(false).await;
}

#[tokio::test]
async fn receive_pack_failed_exit_does_not_emit_a_buffered_success_report() {
    exercise_receive_pack_stream(true).await;
}

async fn exercise_receive_pack_stream(failed_exit: bool) {
    let _env_lock = PATH_ENV_LOCK.lock().await;

    let fake_bin = tempfile::tempdir().expect("fake git bin tempdir");
    let git_gate = GitGate::new().await;
    write_fake_git_script(fake_bin.path(), git_gate.port());
    // Force output before consuming an upload larger than a pipe buffer.
    let script_path = fake_bin.path().join("git");
    let script = std::fs::read_to_string(&script_path).unwrap();
    let script = if failed_exit {
        script.replacen("exit 0", "exit 1", 1)
    } else {
        script
    };
    std::fs::write(
        &script_path,
        script
            .replace("cat >/dev/null\n", "head -c 1048576 /dev/zero >&2\n")
            .replace("exec 3<&-\n", "exec 3<&-\ncat >/dev/null\n"),
    )
    .unwrap();
    let _path = PathOverride::prepend(fake_bin.path());

    let repo = tempfile::tempdir().expect("repo tempdir");
    let git_data = tempfile::tempdir().expect("git data tempdir");
    let database: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let relay = LocalRelayBuilder::default().build();
    let purgatory = Arc::new(Purgatory::new(git_data.path().to_path_buf()));
    let owner_pubkey = "0".repeat(64);
    let mut request_body = receive_pack_request_body().to_vec();
    request_body.resize(2 * 1024 * 1024, 0);
    let request_body = Bytes::from(request_body);

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

    let mut streamed = read_first_progress(&mut body).await;
    // Git cannot exit until this test releases it, regardless of scheduling.
    git_gate.release().await;
    if failed_exit {
        timeout(Duration::from_secs(3), async {
            while let Ok(frame) = body.frame().await.expect("transport error before EOF") {
                streamed.extend_from_slice(&frame_data(frame));
            }
        })
        .await
        .expect("failed Git exit should fail the response");
        assert!(!streamed
            .windows(b"unpack ok".len())
            .any(|part| part == b"unpack ok"));
        return;
    }
    finish_body(&mut body, &mut streamed).await;
    assert_eq!(streamed, expected_git_output());
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
    let git_gate = GitGate::new().await;
    write_fake_git_script(fake_bin.path(), git_gate.port());
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
    let mut streamed = read_first_progress(&mut body).await;
    git_gate.release().await;

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

    // Accumulate across arbitrary frame boundaries until the finalization
    // keepalive is visible. Promotion remains blocked throughout this read.
    timeout(Duration::from_secs(6), async {
        while !streamed
            .windows(b"GRASP is finalizing the push\n".len())
            .any(|window| window == b"GRASP is finalizing the push\n")
        {
            let frame = body
                .frame()
                .await
                .expect("body should remain open while promotion is blocked")
                .expect("progress frame should not be an HTTP body error");
            streamed.extend_from_slice(&frame_data(frame));
            assert!(
                !streamed.ends_with(b"0000"),
                "terminal flush must remain hidden while promotion is blocked"
            );
        }
    })
    .await
    .expect("sideband keepalive should arrive during blocked promotion");

    release.add_permits(1);

    finish_body(&mut body, &mut streamed).await;

    assert!(
        streamed.starts_with(
            &[
                progress_packet("first-progress\n"),
                progress_packet("second-progress\n")
            ]
            .concat()
        ),
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
    let git_gate = GitGate::new().await;
    write_fake_git_script(fake_bin.path(), git_gate.port());
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

    let mut streamed = read_first_progress(&mut body).await;
    assert!(
        repo_path.exists(),
        "/prs/ cleanup must not remove the repo before receive-pack exits"
    );
    git_gate.release().await;
    finish_body(&mut body, &mut streamed).await;
    assert_eq!(streamed, expected_git_output());

    assert!(
        !repo_path.exists(),
        "/prs/ cleanup should remove zero-ref repo after receive-pack exits"
    );
}

// Keep the listener bound until Git has observed the parent's release.
struct GitGate(TcpListener);

impl GitGate {
    async fn new() -> Self {
        Self(
            TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake git gate"),
        )
    }

    fn port(&self) -> u16 {
        self.0.local_addr().expect("fake git gate address").port()
    }

    async fn release(self) {
        timeout(Duration::from_secs(3), async {
            let (mut stream, _) = self.0.accept().await.expect("accept fake git gate");
            stream
                .write_all(b"release\n")
                .await
                .expect("release fake git");
        })
        .await
        .expect("fake git should connect to its gate");
    }
}

async fn read_first_progress<B>(body: &mut B) -> Vec<u8>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    let first = progress_packet("first-progress\n");
    timeout(Duration::from_secs(3), async {
        let mut streamed = Vec::new();
        // Receive-pack can retain the last four bytes until further stdout
        // arrives, and pipe reads need not match writes or HTTP frames.
        while streamed.len() < first.len() - 4 {
            let frame = body
                .frame()
                .await
                .expect("progress before fake git exit")
                .expect("progress body frame");
            streamed.extend_from_slice(&frame_data(frame));
            assert!(
                first.starts_with(&streamed),
                "unexpected initial git progress"
            );
        }
        streamed
    })
    .await
    .expect("first progress should stream before git is released")
}

async fn finish_body<B>(body: &mut B, streamed: &mut Vec<u8>)
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    timeout(Duration::from_secs(3), async {
        while let Some(frame) = body.frame().await {
            streamed.extend_from_slice(&frame_data(frame.expect("remaining body frame")));
        }
    })
    .await
    .expect("response should finish after fixture release");
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

fn progress_packet(message: &str) -> Vec<u8> {
    let mut payload = vec![2];
    payload.extend(message.as_bytes());
    PktLine::data(payload).encode()
}

fn git_status_packet() -> Vec<u8> {
    let mut payload = vec![1];
    payload.extend(PktLine::data(b"unpack ok\n".to_vec()).encode());
    payload
        .extend(PktLine::data(format!("ok refs/nostr/{}\n", "a".repeat(64)).into_bytes()).encode());
    payload.extend(b"0000");
    [PktLine::data(payload).encode(), b"0000".to_vec()].concat()
}

fn expected_git_output() -> Vec<u8> {
    [
        progress_packet("first-progress\n"),
        progress_packet("second-progress\n"),
        git_status_packet(),
    ]
    .concat()
}

fn shell_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:03o}")).collect()
}

fn write_fake_git_script(bin_dir: &Path, gate_port: u16) {
    let git_path = bin_dir.join("git");
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
exec 3<>/dev/tcp/127.0.0.1/__GATE_PORT__
printf '%b' '__FIRST__'
IFS= read -r -t 10 release <&3
[ "$release" = release ]
exec 3<&-
printf '%b' '__SECOND__'
printf '%b' '__STATUS__'
exit 0
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
        .replace(
            "__FIRST__",
            &shell_bytes(&progress_packet("first-progress\n")),
        )
        .replace(
            "__SECOND__",
            &shell_bytes(&progress_packet("second-progress\n")),
        )
        .replace("__STATUS__", &shell_bytes(&git_status_packet()))
        .replace("__GATE_PORT__", &gate_port.to_string()),
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
