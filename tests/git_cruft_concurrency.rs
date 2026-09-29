//! Git-level probes for concurrent staging expiry. No relay is started here.
//! Hooks impose scheduling boundaries without changing Git's commands or results.

use std::{
    fs::{self, FileTimes},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::{Duration, SystemTime},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(20);
const EXPIRED: &str = "refs/nostr/1111111111111111111111111111111111111111111111111111111111111111";
const LIVE: &str = "refs/nostr/2222222222222222222222222222222222222222222222222222222222222222";

fn command(repo: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .current_dir(repo)
        .args(args)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

async fn output(cmd: &mut Command) -> Output {
    timeout(DEADLINE, cmd.output()).await.unwrap().unwrap()
}

async fn git(repo: &Path, args: &[&str]) -> String {
    let result = output(&mut command(repo, args)).await;
    assert!(result.status.success(), "{args:?}: {result:?}");
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

struct Fixture {
    _dir: TempDir,
    view: PathBuf,
    family: PathBuf,
    client: PathBuf,
    base: String,
    live: String,
    family_objects: String,
}

impl Fixture {
    async fn new(old_objects: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let view = dir.path().join("view");
        let family = dir.path().join("family");
        let client = dir.path().join("client");
        for repo in [&view, &family, &client] {
            fs::create_dir(repo).unwrap();
            git(
                repo,
                &["init", "--bare", "--quiet", "--initial-branch=main"],
            )
            .await;
            git(repo, &["config", "gc.auto", "0"]).await;
        }
        let family_tree = git(&family, &["mktree"]).await;
        let family_tip = git(&family, &["commit-tree", &family_tree, "-m", "family"]).await;
        git(&family, &["update-ref", "refs/heads/main", &family_tip]).await;
        fs::write(
            view.join("objects/info/alternates"),
            format!("{}\n", family.join("objects").display()),
        )
        .unwrap();
        let tree = git(&view, &["mktree"]).await;
        let base = git(&view, &["commit-tree", &tree, "-m", "expired pending"]).await;
        let live = git(&view, &["commit-tree", &tree, "-m", "live pending"]).await;
        git(&view, &["update-ref", EXPIRED, &base]).await;
        git(&view, &["update-ref", LIVE, &live]).await;
        let family_objects = Self::objects(&family).await;
        let fixture = Self {
            _dir: dir,
            view,
            family,
            client,
            base,
            live,
            family_objects,
        };
        fixture.repack().await;
        if old_objects {
            // Model elapsed object age without sleeping. The first cruft pack
            // derives these objects' ages from their previous pack's mtime.
            let old = SystemTime::now() - Duration::from_secs(7200);
            let mut packs = 0;
            for entry in fs::read_dir(fixture.view.join("objects/pack")).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|ext| ext == "pack") {
                    fs::File::open(path)
                        .unwrap()
                        .set_times(FileTimes::new().set_modified(old))
                        .unwrap();
                    packs += 1;
                }
            }
            assert!(packs > 0);
        }
        fixture
    }

    async fn objects(repo: &Path) -> String {
        git(
            repo,
            &[
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname)",
            ],
        )
        .await
    }

    async fn repack(&self) {
        git(
            &self.view,
            &[
                "repack",
                "-d",
                "-l",
                "--cruft",
                "--cruft-expiration=30.minutes.ago",
            ],
        )
        .await;
    }

    async fn expire(&self) {
        git(&self.view, &["update-ref", "-d", EXPIRED, &self.base]).await;
    }

    async fn assert_live_and_family_intact(&self) {
        assert_eq!(git(&self.view, &["rev-parse", LIVE]).await, self.live);
        git(
            &self.view,
            &["rev-list", "--objects", "--missing=error", LIVE],
        )
        .await;
        assert_eq!(Self::objects(&self.family).await, self.family_objects);
        git(&self.family, &["fsck", "--full"]).await;
    }
}

struct Gate {
    listener: TcpListener,
    hook: PathBuf,
}

impl Gate {
    async fn new(repo: &Path, name: &str, exec_args: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hook = repo.join("hooks").join(name);
        fs::write(&hook, format!(
            "#!/bin/sh\n\"$GRASP_CRUFT_TEST_BINARY\" --exact git_hook_barrier --nocapture >&2 || exit 1\n{}\n",
            if exec_args { "exec \"$@\"" } else { "exit 0" },
        )).unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
        Self { listener, hook }
    }

    fn spawn(&self, cmd: &mut Command) -> Child {
        cmd.env("GRASP_CRUFT_TEST_BINARY", std::env::current_exe().unwrap())
            .env(
                "GRASP_CRUFT_GATE",
                self.listener.local_addr().unwrap().to_string(),
            )
            .spawn()
            .unwrap()
    }

    async fn reached(&self) -> TcpStream {
        timeout(DEADLINE, async {
            let (mut stream, _) = self.listener.accept().await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), b'R');
            stream
        })
        .await
        .expect("Git did not reach the hook barrier")
    }
}

// The hook runs this same test binary in a child process. No Python or global
// environment mutation is needed. Outside a hook invocation this is a no-op.
#[test]
fn git_hook_barrier() {
    let Ok(address) = std::env::var("GRASP_CRUFT_GATE") else {
        return;
    };
    let mut stream =
        std::net::TcpStream::connect_timeout(&address.parse().unwrap(), DEADLINE).unwrap();
    stream.set_read_timeout(Some(DEADLINE)).unwrap();
    stream.set_write_timeout(Some(DEADLINE)).unwrap();
    stream.write_all(b"R").unwrap();
    let mut release = [0];
    stream.read_exact(&mut release).unwrap();
    assert_eq!(release, [b'G']);
}

async fn upload_race(expire: bool, old: bool) -> Output {
    let f = Fixture::new(old).await;
    let gate = Gate::new(&f.view, "pack-gate", true).await;
    let upload = format!(
        "git -c uploadpack.packObjectsHook={} upload-pack",
        gate.hook.display()
    );
    let mut child = gate.spawn(&mut command(
        &f.client,
        &[
            "-c",
            "protocol.version=0",
            "fetch",
            "--no-tags",
            &format!("--upload-pack={upload}"),
            f.view.to_str().unwrap(),
            EXPIRED,
        ],
    ));
    let mut release = gate.reached().await;
    assert!(child.try_wait().unwrap().is_none());
    if expire {
        f.expire().await;
    }
    f.repack().await;
    f.assert_live_and_family_intact().await;
    release.write_all(b"G").await.unwrap();
    let result = timeout(DEADLINE, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    if result.status.success() {
        assert_eq!(git(&f.client, &["rev-parse", "FETCH_HEAD"]).await, f.base);
        git(&f.client, &["fsck", "--full"]).await;
    }
    // A second fetch demonstrates that failure is confined to the expired ref.
    git(&f.client, &["fetch", f.view.to_str().unwrap(), LIVE]).await;
    git(&f.client, &["fsck", "--full"]).await;
    result
}

#[tokio::test]
async fn retained_ref_survives_repack_during_upload() {
    let result = upload_race(false, true).await;
    assert!(result.status.success(), "{result:?}");
}

#[tokio::test]
async fn recent_objects_survive_repack_after_ref_deletion() {
    let result = upload_race(true, false).await;
    assert!(result.status.success(), "{result:?}");
}

#[tokio::test]
async fn expired_ref_upload_may_fail_without_harming_live_ref() {
    let result = upload_race(true, true).await;
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(128), "{result:?}");
    assert!(stderr.contains("bad object"), "{stderr}");
    assert!(stderr.contains("bad pack header"), "{stderr}");
}

#[tokio::test]
// This characterizes a failure of revised gate property 2, not an acceptable
// server outcome. Keep it explicit until a revised design prevents this race.
async fn concurrent_repack_can_leave_a_successful_push_with_missing_parent() {
    const NEW: &str = "refs/nostr/3333333333333333333333333333333333333333333333333333333333333333";
    let f = Fixture::new(true).await;
    git(
        &f.client,
        &[
            "fetch",
            f.view.to_str().unwrap(),
            &format!("{EXPIRED}:refs/heads/base"),
        ],
    )
    .await;
    let advertisement = git(&f.view, &["receive-pack", "--advertise-refs", "."]).await;
    assert!(advertisement.contains(&format!("{} {EXPIRED}", f.base)));
    let tree = git(&f.client, &["rev-parse", "refs/heads/base^{tree}"]).await;
    let new = git(
        &f.client,
        &["commit-tree", &tree, "-p", &f.base, "-m", "new pending"],
    )
    .await;

    git(
        &f.client,
        &["rev-list", "--objects", "--missing=error", &new],
    )
    .await;

    // Build the pack a client may send using that advertisement: only the new
    // commit, omitting its previously advertised parent. No malformed objects.
    let mut pack = command(&f.client, &["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    pack.stdin
        .take()
        .unwrap()
        .write_all(format!("{new}\n^{}\n", f.base).as_bytes())
        .await
        .unwrap();
    let pack = timeout(DEADLINE, pack.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(pack.status.success(), "{pack:?}");
    let update = format!("{} {new} {NEW}\0report-status\n", "0".repeat(40));
    let mut request = format!("{:04x}{update}0000", update.len() + 4).into_bytes();
    request.extend(pack.stdout);

    // Expiry precedes repack, rather than racing its initial ref snapshot.
    // The old pack models an idle view eligible for compaction. Any quiet wait
    // between deletion and repack leaves the following interleaving unchanged:
    // the new receive-pack begins only AFTER repack has selected its survivors.
    f.expire().await;
    let repack_gate = Gate::new(&f.view, "repack-gate", false).await;
    let wrappers = f._dir.path().join("git-wrappers");
    fs::create_dir(&wrappers).unwrap();
    let wrapper = wrappers.join("git");
    fs::write(
        &wrapper,
        r#"#!/bin/sh
case " $* " in
  *" --cruft "*)
    "$GRASP_CRUFT_REAL_GIT" "$@" || exit $?
    exec "$GRASP_CRUFT_REPACK_GATE"
    ;;
  *) exec "$GRASP_CRUFT_REAL_GIT" "$@" ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let real_git = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|dir| dir.join("git"))
        .find(|path| path.is_file())
        .unwrap();
    let mut repack = repack_gate.spawn(
        command(
            &f.view,
            &[
                "repack",
                "-d",
                "-l",
                "--cruft",
                "--cruft-expiration=30.minutes.ago",
            ],
        )
        .env("GIT_EXEC_PATH", &wrappers)
        .env("GRASP_CRUFT_REAL_GIT", real_git)
        .env("GRASP_CRUFT_REPACK_GATE", &repack_gate.hook),
    );
    let mut finish_repack = repack_gate.reached().await;
    assert!(repack.try_wait().unwrap().is_none());
    // Git has finished preparing its cruft pack, but not deleted the old pack.
    git(&f.view, &["cat-file", "-e", &f.base]).await;

    let receive_gate = Gate::new(&f.view, "pre-receive", false).await;
    let mut receive = receive_gate.spawn(
        command(
            &f.view,
            &[
                "-c",
                &format!("core.hooksPath={}", f.view.join("hooks").display()),
                "receive-pack",
                "--stateless-rpc",
                ".",
            ],
        )
        .stdin(Stdio::piped()),
    );
    receive
        .stdin
        .take()
        .unwrap()
        .write_all(&request)
        .await
        .unwrap();
    let mut finish_receive = receive_gate.reached().await;
    assert!(receive.try_wait().unwrap().is_none());
    // receive-pack has now checked connectivity against the old parent.
    finish_repack.write_all(b"G").await.unwrap();
    let repack = timeout(DEADLINE, repack.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(repack.status.success(), "{repack:?}");
    f.assert_live_and_family_intact().await;
    let parent = output(&mut command(&f.view, &["cat-file", "-e", &f.base])).await;
    assert!(!parent.status.success());
    finish_receive.write_all(b"G").await.unwrap();
    let result = timeout(DEADLINE, receive.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let installed = output(&mut command(&f.view, &["rev-parse", "--verify", NEW])).await;
    let closure = output(&mut command(
        &f.view,
        &["rev-list", "--objects", "--missing=error", NEW],
    ))
    .await;
    eprintln!(
        "receive status: {}\nreport: {}\ninstalled ref: {}\nclosure status: {}\nclosure stderr: {}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&installed.stdout),
        closure.status,
        String::from_utf8_lossy(&closure.stderr)
    );
    assert!(result.status.success(), "{result:?}");
    let report = String::from_utf8_lossy(&result.stdout);
    assert!(report.contains("unpack ok"), "{report}");
    assert!(report.contains(&format!("ok {NEW}")), "{report}");
    assert!(installed.status.success(), "{installed:?}");
    assert_eq!(String::from_utf8_lossy(&installed.stdout).trim(), new);
    assert!(
        !closure.status.success(),
        "the counterexample no longer reproduces"
    );
    assert!(
        String::from_utf8_lossy(&closure.stderr).contains(&f.base),
        "{closure:?}"
    );
    f.assert_live_and_family_intact().await;
}
