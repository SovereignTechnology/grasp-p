//! Keep already-completed deletions out of receive-pack (zero-to-zero deletes
//! are unconditional there). Verify them separately and merge their per-ref
//! statuses into Git's report. Atomic pushes hold verification locks until Git exits.

use super::{authorization::parse_ref_line, handlers::PumpResult, protocol::PktLine};
use hyper::body::{Bytes, Frame};
use std::{
    collections::{HashMap, HashSet},
    io::{self, BufRead, BufReader, Write},
    path::Path,
    process::{Child, Command, Stdio},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::mpsc,
};

const ZERO: &str = "0000000000000000000000000000000000000000";

struct CommandRef {
    old: String,
    new: String,
    name: String,
    completed: bool,
    verified: Option<bool>,
}

pub(super) struct ReceivePackPlan {
    /// Authorization only: completed deletions appear as no-op commands.
    pub authorization_body: Bytes,
    pub forwarded_body: Bytes,
    commands: Vec<CommandRef>,
    report_status: bool,
    sideband: bool,
    atomic: bool,
    abort: bool,
    pub failed: bool,
    locks: Option<RefLocks>,
}

/// A prepared verify-only transaction. Closing stdin makes Git release its
/// locks without changing refs, including on early returns or cancellation.
struct RefLocks(Child);
impl RefLocks {
    fn prepare(repo: &Path, targets: &[(&str, &str)]) -> io::Result<Self> {
        let child = Command::new("git")
            .current_dir(repo)
            .args(["update-ref", "--stdin", "-z"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut guard = Self(child);
        let mut commands = b"start\0".to_vec();
        for (name, oid) in targets {
            commands.extend(format!("option no-deref\0verify {name}\0{oid}\0").as_bytes());
        }
        commands.extend(b"prepare\0");
        guard
            .0
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(&commands)?;
        let mut output = BufReader::new(guard.0.stdout.take().expect("piped stdout"));
        for expected in ["start: ok\n", "prepare: ok\n"] {
            let mut line = String::new();
            output.read_line(&mut line)?;
            if line != expected {
                return Err(io::Error::other("ref absence verification failed"));
            }
        }
        Ok(guard)
    }
}
impl Drop for RefLocks {
    fn drop(&mut self) {
        // No commit is needed: only verification was prepared, never a write.
        self.0.stdin.take();
        let _ = self.0.wait();
    }
}

impl ReceivePackPlan {
    /// Only unsigned canonical commands qualify; retain pack/options bytes.
    /// Non-deletion commands are already normalized by the ordinary push path.
    pub fn prepare(request: &[u8], local_refs: &HashMap<String, String>) -> Option<Self> {
        let mut input = request;
        let mut commands = Vec::new();
        let mut seen = HashSet::new();
        let mut caps = String::new();
        loop {
            let (packet, remaining) = PktLine::parse(input).ok()?;
            input = remaining;
            let PktLine::Data(payload) = packet else {
                break;
            };
            let (old, new, name) = parse_ref_line(&payload)?;
            let line = std::str::from_utf8(&payload).ok()?.trim_end_matches('\n');
            let (command, capabilities) = line.split_once('\0').unwrap_or((line, ""));
            if command != format!("{old} {new} {name}")
                || !name.starts_with("refs/")
                || !seen.insert(name.clone())
                || (!commands.is_empty() && line.contains('\0'))
            {
                return None;
            }
            if commands.is_empty() {
                caps = capabilities.to_owned();
            }
            let completed = !name.starts_with("refs/nostr/")
                && if new == ZERO {
                    !local_refs.contains_key(&name)
                } else {
                    local_refs.get(&name) == Some(&new)
                };
            commands.push(CommandRef {
                old,
                new,
                name,
                completed,
                verified: None,
            });
        }
        if commands.is_empty() {
            return None;
        }
        // Ordinary pushes remain entirely in receive-pack. Only its unsafe
        // already-absent deletion case needs separate verification.
        if !commands.iter().any(|c| c.completed && c.new == ZERO) {
            for command in &mut commands {
                command.completed = false;
            }
        }
        let report_status = caps
            .split_whitespace()
            .any(|c| matches!(c, "report-status" | "report-status-v2"));
        let sideband = caps.split_whitespace().any(|c| c == "side-band-64k");
        let atomic = caps.split_whitespace().any(|c| c == "atomic");
        // We need Git's individual outcomes even if the client omitted reports.
        if !report_status {
            caps.push_str(" report-status");
        }
        let mut authorization = Vec::new();
        let mut forwarded = Vec::new();
        for command in &commands {
            let old = if command.completed {
                &command.new
            } else {
                &command.old
            };
            authorization.extend(
                PktLine::data(format!("{old} {} {}\n", command.new, command.name).into_bytes())
                    .encode(),
            );
            if !command.completed {
                let suffix = if forwarded.is_empty() {
                    format!("\0{caps}")
                } else {
                    String::new()
                };
                forwarded.extend(
                    PktLine::data(
                        format!("{} {} {}{suffix}\n", command.old, command.new, command.name)
                            .into_bytes(),
                    )
                    .encode(),
                );
            }
        }
        authorization.extend(PktLine::flush().encode());
        forwarded.extend(PktLine::flush().encode());
        forwarded.extend(input);
        Some(Self {
            authorization_body: authorization.into(),
            forwarded_body: forwarded.into(),
            commands,
            report_status,
            sideband,
            atomic,
            abort: false,
            failed: false,
            locks: None,
        })
    }

    /// Non-atomic no-ops complete independently. Atomic no-ops retain every
    /// ref lock across receive-pack's transaction on the other refs.
    pub fn verify(&mut self, repo: &Path) {
        if self.atomic {
            let names: Vec<_> = self
                .commands
                .iter()
                .filter(|c| c.completed)
                .map(|c| (c.name.as_str(), c.new.as_str()))
                .collect();
            if names.is_empty() {
                return;
            }
            match RefLocks::prepare(repo, &names) {
                Ok(locks) => self.locks = Some(locks),
                Err(_) => self.abort = true,
            }
            for command in &mut self.commands {
                if command.completed {
                    command.verified = Some(!self.abort);
                }
            }
        } else {
            for command in &mut self.commands {
                if command.completed {
                    command.verified =
                        Some(RefLocks::prepare(repo, &[(&command.name, &command.new)]).is_ok());
                }
            }
        }
    }

    pub fn needs_git(&self) -> bool {
        !self.abort && self.commands.iter().any(|c| !c.completed)
    }

    pub fn release_locks(&mut self) {
        self.locks.take();
    }

    /// Merge native Git outcomes with verified deletion outcomes. Preserve v2
    /// option lines and request ordering; only atomic requests couple failures.
    pub fn response(&mut self, git_report: &[u8]) -> Vec<u8> {
        let mut input = git_report;
        let mut unpack = if self.needs_git() {
            "unpack missing Git status\n".to_owned()
        } else {
            "unpack ok\n".to_owned()
        };
        let mut statuses: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let mut last_ref = None;
        while let Ok((packet, tail)) = PktLine::parse(input) {
            input = tail;
            let PktLine::Data(payload) = packet else {
                break;
            };
            let line = String::from_utf8_lossy(&payload);
            if line.starts_with("unpack ") {
                unpack = line.into_owned();
            } else if line.starts_with("ok ") || line.starts_with("ng ") {
                if let Some(name) = line.split_whitespace().nth(1) {
                    last_ref = Some(name.to_owned());
                    statuses.insert(name.to_owned(), vec![payload]);
                }
            } else if line.starts_with("option ") {
                if let Some(lines) = last_ref.as_ref().and_then(|name| statuses.get_mut(name)) {
                    lines.push(payload);
                }
            }
        }
        let mut outcomes = Vec::new();
        for command in &self.commands {
            let lines = if command.completed {
                let status = if command.verified == Some(true) {
                    format!("ok {}\n", command.name)
                } else {
                    format!("ng {} ref absence verification failed\n", command.name)
                };
                vec![status.into_bytes()]
            } else {
                statuses.remove(&command.name).unwrap_or_else(|| {
                    vec![format!("ng {} missing Git status\n", command.name).into_bytes()]
                })
            };
            outcomes.push(lines);
        }
        self.failed = self.abort
            || unpack != "unpack ok\n"
            || outcomes.iter().any(|lines| !lines[0].starts_with(b"ok "));
        let atomic_failed = self.atomic
            && (self.abort
                || unpack != "unpack ok\n"
                || outcomes.iter().any(|lines| !lines[0].starts_with(b"ok ")));
        let mut report = Vec::new();
        if self.report_status {
            report.extend(PktLine::data(unpack.as_bytes().to_vec()).encode());
            for (command, lines) in self.commands.iter().zip(outcomes) {
                // Native statuses describe actual Git effects. Never turn a
                // native success into a claimed rollback; only synthesize
                // atomic failures for omitted commands or a pre-Git abort.
                if self.abort || (command.completed && atomic_failed) || unpack != "unpack ok\n" {
                    let reason = if atomic_failed {
                        "atomic push failure"
                    } else {
                        "unpacker error"
                    };
                    report.extend(
                        PktLine::data(format!("ng {} {reason}\n", command.name).into_bytes())
                            .encode(),
                    );
                } else {
                    for line in lines {
                        report.extend(PktLine::data(line).encode());
                    }
                }
            }
            report.extend(PktLine::flush().encode());
        }
        if !self.sideband {
            return report;
        }
        let mut response = Vec::new();
        for chunk in report.chunks(65515) {
            let mut payload = vec![1];
            payload.extend(chunk);
            response.extend(PktLine::data(payload).encode());
        }
        response.extend(PktLine::flush().encode());
        response
    }

    /// Forward sideband progress immediately; only the small status report is
    /// retained for merging. Native receive-pack streams no pack bytes here.
    pub async fn pump<R: AsyncRead + Unpin>(
        &mut self,
        mut stdout: R,
        tx: &mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
    ) -> (PumpResult, Option<Vec<u8>>) {
        let mut report = Vec::new();
        let mut sent_stdout = false;
        let reading = async {
            loop {
                let mut header = [0; 4];
                let first = stdout.read(&mut header[..1]).await?;
                if first == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Git status ended before flush",
                    ));
                }
                stdout.read_exact(&mut header[1..]).await?;
                let len = std::str::from_utf8(&header)
                    .ok()
                    .and_then(|s| usize::from_str_radix(s, 16).ok())
                    .ok_or_else(|| io::Error::other("invalid Git status framing"))?;
                if len == 0 {
                    if !self.sideband {
                        report.extend(b"0000");
                    }
                    break;
                }
                if !(5..=65520).contains(&len) {
                    return Err(io::Error::other("invalid Git status packet length"));
                }
                let mut payload = vec![0; len - 4];
                stdout.read_exact(&mut payload).await?;
                if self.sideband {
                    if payload[0] == 1 {
                        report.extend(&payload[1..]);
                    } else {
                        sent_stdout = true;
                        tx.send(Ok(Frame::data(PktLine::data(payload).encode().into())))
                            .await
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "push client disconnected",
                                )
                            })?;
                    }
                } else {
                    report.extend(PktLine::data(payload).encode());
                }
                if report.len()
                    > self
                        .commands
                        .len()
                        .saturating_mul(4096)
                        .saturating_add(65536)
                {
                    return Err(io::Error::other("Git status report exceeds command budget"));
                }
            }
            // Sideband can split the inner report at any byte. Validate its
            // complete framing before manufacturing a merged terminal response.
            let mut remaining = report.as_slice();
            loop {
                let (packet, tail) = PktLine::parse(remaining).map_err(|_| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete Git status report")
                })?;
                remaining = tail;
                if packet == PktLine::Flush {
                    if !remaining.is_empty() {
                        return Err(io::Error::other("trailing Git status data"));
                    }
                    break;
                }
            }
            Ok(())
        };
        let result: io::Result<()> = tokio::select! {
            result = reading => result,
            _ = tx.closed() => return (PumpResult::ClientDisconnected, None),
        };
        match result {
            Ok(()) => (
                PumpResult::Eof { sent_stdout },
                Some(self.response(&report)),
            ),
            Err(error) => {
                let _ = tx.send(Err(error)).await;
                (PumpResult::ReadError, None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(repo)
            .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().into()
    }
    fn fixture() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "--bare"]);
        let tree = git(dir.path(), &["mktree"]);
        let oid = git(dir.path(), &["commit-tree", &tree, "-m", "available"]);
        (dir, oid)
    }
    fn request(oid: &str, caps: &str, second_delete: bool) -> Vec<u8> {
        let lines = [
            format!("{oid} {ZERO} refs/heads/gone\0{caps}\n"),
            if second_delete {
                format!("{oid} {ZERO} refs/heads/other\n")
            } else {
                format!("{ZERO} {oid} refs/heads/feature\n")
            },
        ];
        let mut bytes = Vec::new();
        for line in lines {
            bytes.extend(PktLine::data(line.into_bytes()).encode());
        }
        bytes.extend(b"0000PACK-tail-preserved");
        bytes
    }
    fn native_report(status: &str) -> Vec<u8> {
        [
            PktLine::data(b"unpack ok\n".to_vec()).encode(),
            PktLine::data(status.as_bytes().to_vec()).encode(),
            PktLine::flush().encode(),
        ]
        .concat()
    }

    #[test]
    fn non_atomic_deletions_verify_independently_and_preserve_recreated_refs() {
        let (dir, oid) = fixture();
        let mut plan =
            ReceivePackPlan::prepare(&request(&oid, "report-status", true), &HashMap::new())
                .unwrap();
        git(dir.path(), &["update-ref", "refs/heads/gone", &oid]);
        plan.verify(dir.path());
        assert!(!plan.needs_git());
        let response = String::from_utf8(plan.response(&[])).unwrap();
        assert!(response.contains("ng refs/heads/gone ref absence verification failed"));
        assert!(response.contains("ok refs/heads/other"));
        assert_eq!(git(dir.path(), &["rev-parse", "refs/heads/gone"]), oid);
    }

    #[test]
    fn atomic_verification_failure_aborts_other_commands() {
        let (dir, oid) = fixture();
        let mut plan = ReceivePackPlan::prepare(
            &request(&oid, "report-status atomic", false),
            &HashMap::new(),
        )
        .unwrap();
        git(dir.path(), &["update-ref", "refs/heads/gone", &oid]);
        plan.verify(dir.path());
        assert!(!plan.needs_git());
        let response = String::from_utf8(plan.response(&[])).unwrap();
        assert!(response.contains("ng refs/heads/gone atomic push failure"));
        assert!(response.contains("ng refs/heads/feature atomic push failure"));
        assert!(git(dir.path(), &["for-each-ref", "refs/heads/feature"]).is_empty());
        assert_eq!(git(dir.path(), &["rev-parse", "refs/heads/gone"]), oid);
    }

    #[test]
    fn atomic_absence_lock_survives_until_git_finishes_and_cleans_up() {
        let (dir, oid) = fixture();
        let mut plan = ReceivePackPlan::prepare(
            &request(&oid, "report-status atomic", false),
            &HashMap::new(),
        )
        .unwrap();
        plan.verify(dir.path());
        assert!(plan.needs_git());
        let create = || {
            Command::new("git")
                .current_dir(dir.path())
                .args([
                    "-c",
                    "core.filesRefLockTimeout=0",
                    "update-ref",
                    "refs/heads/gone",
                    &oid,
                ])
                .output()
                .unwrap()
        };
        assert!(
            !create().status.success(),
            "absence lock must prevent recreation during atomic push"
        );
        let response =
            String::from_utf8(plan.response(&native_report("ok refs/heads/feature\n"))).unwrap();
        assert!(response.contains("ok refs/heads/gone"));
        plan.release_locks();
        assert!(
            create().status.success(),
            "release must not leave a stale ref lock"
        );
    }

    #[test]
    fn forwarding_preserves_pack_and_moves_capabilities_without_zero_deletes() {
        let request = request(
            &"1".repeat(40),
            "report-status-v2 side-band-64k atomic",
            false,
        );
        let plan = ReceivePackPlan::prepare(&request, &HashMap::new()).unwrap();
        let (packet, tail) = PktLine::parse(&plan.forwarded_body).unwrap();
        let PktLine::Data(payload) = packet else {
            panic!("command missing")
        };
        assert!(String::from_utf8(payload)
            .unwrap()
            .contains("refs/heads/feature\0report-status-v2 side-band-64k atomic"));
        assert_eq!(tail, b"0000PACK-tail-preserved");
        let mut signed = PktLine::data(b"push-cert\0report-status\n".to_vec()).encode();
        signed.extend(&request);
        assert!(ReceivePackPlan::prepare(&signed, &HashMap::new()).is_none());
        assert!(ReceivePackPlan::prepare(b"0009bad!!", &HashMap::new()).is_none());
    }

    #[test]
    fn atomic_native_failure_changes_every_status_but_non_atomic_does_not() {
        for atomic in [false, true] {
            let (dir, oid) = fixture();
            let caps = if atomic {
                "report-status atomic"
            } else {
                "report-status"
            };
            let mut plan =
                ReceivePackPlan::prepare(&request(&oid, caps, false), &HashMap::new()).unwrap();
            plan.verify(dir.path());
            let response = String::from_utf8(
                plan.response(&native_report("ng refs/heads/feature rejected\n")),
            )
            .unwrap();
            assert!(
                response.contains(&format!(
                    "{} refs/heads/gone",
                    if atomic { "ng" } else { "ok" }
                )),
                "{response}"
            );
            assert!(response.contains("ng refs/heads/feature"));
        }
    }

    #[test]
    fn changed_companion_noop_does_not_fail_an_independent_deletion() {
        let (dir, oid) = fixture();
        git(dir.path(), &["update-ref", "refs/heads/feature", &oid]);
        let refs = HashMap::from([("refs/heads/feature".into(), oid.clone())]);
        let mut plan =
            ReceivePackPlan::prepare(&request(&oid, "report-status", false), &refs).unwrap();
        let tree = git(dir.path(), &["mktree"]);
        let later = git(dir.path(), &["commit-tree", &tree, "-m", "later"]);
        git(dir.path(), &["update-ref", "refs/heads/feature", &later]);
        plan.verify(dir.path());
        assert!(!plan.needs_git());
        let response = String::from_utf8(plan.response(&[])).unwrap();
        assert!(response.contains("ok refs/heads/gone"));
        assert!(response.contains("ng refs/heads/feature"));
        assert_eq!(git(dir.path(), &["rev-parse", "refs/heads/feature"]), later);
    }

    #[test]
    fn internal_status_negotiation_is_not_exposed_to_clients_without_reports() {
        for caps in ["", "side-band-64k"] {
            let (dir, oid) = fixture();
            let mut plan =
                ReceivePackPlan::prepare(&request(&oid, caps, false), &HashMap::new()).unwrap();
            assert!(String::from_utf8_lossy(&plan.forwarded_body).contains("report-status"));
            plan.verify(dir.path());
            let response = plan.response(&native_report("ok refs/heads/feature\n"));
            assert_eq!(
                response,
                if caps.is_empty() {
                    Vec::new()
                } else {
                    b"0000".to_vec()
                }
            );
            assert!(!plan.failed);
        }
    }

    #[test]
    fn native_success_is_never_relabelled_as_a_rollback() {
        let (dir, oid) = fixture();
        let mut plan = ReceivePackPlan::prepare(
            &request(&oid, "report-status atomic", false),
            &HashMap::new(),
        )
        .unwrap();
        plan.commands.push(CommandRef {
            old: ZERO.into(),
            new: oid,
            name: "refs/heads/refused".into(),
            completed: false,
            verified: None,
        });
        plan.verify(dir.path());
        let mut report = native_report("ok refs/heads/feature\n");
        report.truncate(report.len() - 4);
        report.extend(PktLine::data(b"ng refs/heads/refused rejected\n".to_vec()).encode());
        report.extend(b"0000");
        let response = String::from_utf8(plan.response(&report)).unwrap();
        assert!(response.contains("ok refs/heads/feature"));
        assert!(response.contains("ng refs/heads/refused"));
        assert!(response.contains("ng refs/heads/gone"));
        assert!(plan.failed);
    }

    #[tokio::test]
    async fn disconnected_client_stops_waiting_for_git_and_releases_verification_locks() {
        let (dir, oid) = fixture();
        let mut plan = ReceivePackPlan::prepare(
            &request(&oid, "report-status atomic", false),
            &HashMap::new(),
        )
        .unwrap();
        plan.verify(dir.path());
        assert!(plan.locks.is_some());
        let (_writer, reader) = tokio::io::duplex(32);
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::spawn(async move { plan.pump(reader, &tx).await });
        drop(rx);
        let (outcome, report) = timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome, PumpResult::ClientDisconnected);
        assert!(report.is_none());
        // This would fail immediately if the abandoned transaction kept a lock.
        git(
            dir.path(),
            &[
                "-c",
                "core.filesRefLockTimeout=0",
                "update-ref",
                "refs/heads/gone",
                &oid,
            ],
        );
    }

    #[tokio::test]
    async fn truncated_reports_are_transport_errors_not_synthetic_successes() {
        for sideband in [false, true] {
            for missing_inner_flush in [false, true] {
                let (dir, oid) = fixture();
                let caps = if sideband {
                    "report-status side-band-64k"
                } else {
                    "report-status"
                };
                let mut plan =
                    ReceivePackPlan::prepare(&request(&oid, caps, false), &HashMap::new()).unwrap();
                plan.verify(dir.path());
                let mut report = native_report("ok refs/heads/feature\n");
                if missing_inner_flush || !sideband {
                    report.truncate(report.len() - 4);
                }
                let bytes = if sideband {
                    let mut payload = vec![1];
                    payload.extend(report);
                    let mut bytes = PktLine::data(payload).encode();
                    if missing_inner_flush {
                        bytes.extend(b"0000");
                    }
                    bytes
                } else {
                    report
                };
                let (tx, mut rx) = mpsc::channel(4);
                let (outcome, response) =
                    timeout(Duration::from_secs(5), plan.pump(bytes.as_slice(), &tx))
                        .await
                        .expect("truncated report should terminate");
                assert_eq!(outcome, PumpResult::ReadError);
                assert!(response.is_none());
                assert!(rx.try_recv().unwrap().is_err());
            }
        }
    }

    #[tokio::test]
    async fn sideband_progress_streams_before_final_status_and_status_v2_survives() {
        let (dir, oid) = fixture();
        let mut plan = ReceivePackPlan::prepare(
            &request(&oid, "report-status-v2 side-band-64k", false),
            &HashMap::new(),
        )
        .unwrap();
        plan.verify(dir.path());
        let (mut writer, reader) = tokio::io::duplex(4096);
        let (tx, mut rx) = mpsc::channel(4);
        let task = tokio::spawn(async move { plan.pump(reader, &tx).await });
        use tokio::io::AsyncWriteExt;
        let progress = PktLine::data(b"\x02counting objects\n".to_vec()).encode();
        writer.write_all(&progress).await.unwrap();
        let frame = timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.into_data().unwrap().as_ref(), progress.as_slice());
        let mut native = native_report("ok refs/heads/feature\n");
        native.truncate(native.len() - 4);
        native.extend(PktLine::data(b"option refname refs/heads/feature\n".to_vec()).encode());
        native.extend(b"0000");
        let mut band = vec![1];
        band.extend(native);
        writer
            .write_all(&PktLine::data(band).encode())
            .await
            .unwrap();
        writer.write_all(b"0000").await.unwrap();
        drop(writer);
        let (_, final_report) = timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        let report = String::from_utf8(final_report.unwrap()).unwrap();
        assert!(report.contains("ok refs/heads/gone"));
        assert!(report.contains("ok refs/heads/feature"));
        assert!(report.contains("option refname refs/heads/feature"));
    }
}
