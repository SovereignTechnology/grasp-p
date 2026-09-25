//! Complete fully satisfied pushes containing deletions without issuing writes.
//! A zero-to-zero receive-pack deletion is not a compare-and-swap: Git can
//! delete a concurrently recreated ref. Verify all targets in one transaction
//! instead, then report the push as satisfied at that point in time.

use super::{authorization::parse_ref_line, protocol::PktLine};
use hyper::body::Bytes;
use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    path::Path,
    process::{Command, Stdio},
};

const ZERO: &str = "0000000000000000000000000000000000000000";

pub(super) struct CompletedPush {
    /// Only for authorization. Never pass these zero-to-zero commands to Git.
    pub authorization_body: Bytes,
    targets: Vec<(String, String)>,
    report_status: bool,
    sideband: bool,
}

impl CompletedPush {
    /// Only unsigned, well-formed commands with every target already satisfied
    /// qualify. Pushes making any change continue through receive-pack.
    pub fn prepare(request: &[u8], local_refs: &HashMap<String, String>) -> Option<Self> {
        let mut input = request;
        let mut targets = Vec::new();
        let mut seen = HashSet::new();
        let mut authorization = Vec::new();
        let mut has_deletion = false;
        let mut report_status = false;
        let mut sideband = false;
        loop {
            let (packet, remaining) = PktLine::parse(input).ok()?;
            input = remaining;
            let PktLine::Data(payload) = packet else {
                break;
            };
            // Certificates and malformed commands cannot parse as a ref line.
            let (old, new, name) = parse_ref_line(&payload)?;
            let line = std::str::from_utf8(&payload).ok()?.trim_end_matches('\n');
            let (command, caps) = line.split_once('\0').unwrap_or((line, ""));
            if command != format!("{old} {new} {name}")
                || !name.starts_with("refs/")
                || !seen.insert(name.clone())
                || (!targets.is_empty() && line.contains('\0'))
            {
                return None;
            }
            if targets.is_empty() {
                report_status = caps
                    .split_whitespace()
                    .any(|c| matches!(c, "report-status" | "report-status-v2"));
                sideband = caps.split_whitespace().any(|c| c == "side-band-64k");
            }
            let satisfied = if new == ZERO {
                !local_refs.contains_key(&name)
            } else {
                local_refs.get(&name) == Some(&new)
            };
            if !satisfied {
                return None;
            }
            let ordinary = !name.starts_with("refs/nostr/");
            has_deletion |= ordinary && new == ZERO;
            let auth_old = if ordinary { &new } else { &old };
            authorization
                .extend(PktLine::data(format!("{auth_old} {new} {name}\n").into_bytes()).encode());
            targets.push((name, new));
        }
        if !has_deletion {
            return None;
        }
        authorization.extend(PktLine::flush().encode());
        Some(Self {
            authorization_body: authorization.into(),
            targets,
            report_status,
            sideband,
        })
    }

    /// Git locks every ref during prepare. A ref recreated or changed since
    /// inspection rejects the whole verification; no update or delete is sent.
    pub fn verify(&self, repo: &Path) -> io::Result<()> {
        let mut commands = b"start\0option no-deref\0".to_vec();
        for (name, oid) in &self.targets {
            commands.extend(format!("verify {name}\0{oid}\0").as_bytes());
        }
        commands.extend(b"prepare\0commit\0");
        let mut child = Command::new("git")
            .current_dir(repo)
            .args(["update-ref", "--stdin", "-z"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let write_result = child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(&commands);
        let output = child.wait_with_output()?;
        write_result?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        Ok(())
    }

    pub fn response(&self) -> Vec<u8> {
        let mut report = Vec::new();
        if self.report_status {
            report.extend(PktLine::data(b"unpack ok\n".to_vec()).encode());
            for (name, _) in &self.targets {
                report.extend(PktLine::data(format!("ok {name}\n").into_bytes()).encode());
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn request(oid: &str, caps: &str) -> Vec<u8> {
        let mut bytes =
            PktLine::data(format!("{oid} {ZERO} refs/heads/gone\0{caps}\n").into_bytes()).encode();
        bytes.extend(PktLine::flush().encode());
        bytes
    }

    #[test]
    fn verification_rejects_recreated_ref_without_deleting_it() {
        let temp = tempfile::tempdir().unwrap();
        git(temp.path(), &["init", "--bare"]);
        let tree = git(temp.path(), &["mktree"]);
        let oid = git(
            temp.path(),
            &["commit-tree", &tree, "-m", "existing object"],
        );
        let push =
            CompletedPush::prepare(&request(&oid, "report-status"), &HashMap::new()).unwrap();
        push.verify(temp.path()).unwrap();
        assert!(git(temp.path(), &["for-each-ref"]).is_empty());
        // Recreate exactly the stale client's old target between inspection
        // and verification. It must survive, not become an authorized delete.
        git(temp.path(), &["update-ref", "refs/heads/gone", &oid]);
        assert!(push.verify(temp.path()).is_err());
        assert_eq!(git(temp.path(), &["rev-parse", "refs/heads/gone"]), oid);
        assert!(CompletedPush::prepare(
            &request(&oid, "report-status"),
            &HashMap::from([("refs/heads/gone".into(), oid)])
        )
        .is_none());
    }

    #[test]
    fn verification_checks_companion_refs_without_reverting_them() {
        let temp = tempfile::tempdir().unwrap();
        git(temp.path(), &["init", "--bare"]);
        let tree = git(temp.path(), &["mktree"]);
        let first = git(temp.path(), &["commit-tree", &tree, "-m", "first"]);
        let second = git(temp.path(), &["commit-tree", &tree, "-m", "second"]);
        git(temp.path(), &["update-ref", "refs/heads/main", &first]);
        let mut bytes = request(&first, "report-status");
        bytes.truncate(bytes.len() - 4);
        bytes.extend(
            PktLine::data(format!("{ZERO} {first} refs/heads/main\n").into_bytes()).encode(),
        );
        bytes.extend(PktLine::flush().encode());
        let push =
            CompletedPush::prepare(&bytes, &HashMap::from([("refs/heads/main".into(), first)]))
                .unwrap();
        push.verify(temp.path()).unwrap();
        git(temp.path(), &["update-ref", "refs/heads/main", &second]);
        assert!(push.verify(temp.path()).is_err());
        assert_eq!(git(temp.path(), &["rev-parse", "refs/heads/main"]), second);
        assert!(git(temp.path(), &["for-each-ref", "refs/heads/gone"]).is_empty());
    }

    #[test]
    fn response_respects_status_capabilities_and_sideband_framing() {
        for caps in [
            "",
            "report-status",
            "report-status-v2",
            "report-status side-band-64k",
            "report-status-v2 side-band-64k",
            "side-band-64k",
        ] {
            let push =
                CompletedPush::prepare(&request(&"1".repeat(40), caps), &HashMap::new()).unwrap();
            let wire = push.response();
            let mut report = Vec::new();
            if caps.contains("side-band-64k") {
                let mut remaining = wire.as_slice();
                loop {
                    let (packet, tail) = PktLine::parse(remaining).unwrap();
                    remaining = tail;
                    match packet {
                        PktLine::Data(payload) => {
                            assert_eq!(payload[0], 1);
                            report.extend(&payload[1..]);
                        }
                        PktLine::Flush => {
                            assert!(remaining.is_empty());
                            break;
                        }
                    }
                }
            } else {
                report = wire;
            }
            let expected = if caps.contains("report-status") {
                [
                    PktLine::data(b"unpack ok\n".to_vec()).encode(),
                    PktLine::data(b"ok refs/heads/gone\n".to_vec()).encode(),
                    PktLine::flush().encode(),
                ]
                .concat()
            } else {
                Vec::new()
            };
            assert_eq!(report, expected, "{caps}");
        }
    }

    #[test]
    fn signed_malformed_and_duplicate_commands_do_not_take_shortcut() {
        let line = request(&"1".repeat(40), "report-status");
        let mut signed = PktLine::data(b"push-cert\0report-status\n".to_vec()).encode();
        signed.extend(&line);
        assert!(CompletedPush::prepare(&signed, &HashMap::new()).is_none());
        assert!(CompletedPush::prepare(&line[..line.len() - 4], &HashMap::new()).is_none());
        let mut duplicate = line[..line.len() - 4].to_vec();
        duplicate.extend(&line);
        assert!(CompletedPush::prepare(&duplicate, &HashMap::new()).is_none());
    }
}
