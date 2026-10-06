//! The git this server needs, checked once at startup.
//!
//! Every git call runs whatever `git` is first on `PATH`. Since upstream
//! v3.0.6 the server passes `--not` and `--glob=` on the stdin of
//! `git rev-list --stdin`, which git accepts from 2.42. An older git does
//! not fail loudly: pushes are accepted, promotion reports "promoted history
//! is incomplete in the family", and the pushed history stays staged for
//! good. Debian 12 ships 2.39.5, so that fault is easy to deploy by accident.

use std::fmt;
use std::process::Command;

use anyhow::{anyhow, Result};
use tracing::warn;

/// A git release number.
///
/// Whatever follows the third number (`.windows.1`, `.rc1`, a vendor note in
/// brackets) is dropped: the check only needs to place a version before or
/// after [`MINIMUM`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// The oldest git that accepts `--not` and `--glob=` on the stdin of
/// `git rev-list --stdin`.
pub const MINIMUM: GitVersion = GitVersion {
    major: 2,
    minor: 42,
    patch: 0,
};

impl fmt::Display for GitVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What the output of `git --version` says about the git that printed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assessment {
    Supported(GitVersion),
    TooOld(GitVersion),
    /// No version could be read from the output.
    Unrecognised,
}

/// Read the version out of what `git --version` prints.
pub fn parse(output: &str) -> Option<GitVersion> {
    let number = output
        .trim()
        .strip_prefix("git version ")?
        .split_whitespace()
        .next()?;
    let mut parts = number.split(['.', '-']);
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    // Two numbers are enough to place a version. A third part that is not a
    // number is a suffix such as `rc0` or `GIT`.
    let patch: u32 = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    Some(GitVersion {
        major,
        minor,
        patch,
    })
}

/// Judge the output of `git --version` against [`MINIMUM`].
pub fn assess(output: &str) -> Assessment {
    match parse(output) {
        Some(found) if found >= MINIMUM => Assessment::Supported(found),
        Some(found) => Assessment::TooOld(found),
        None => Assessment::Unrecognised,
    }
}

/// Check the git on `PATH` before anything relies on it.
///
/// With `fatal` set, a git older than [`MINIMUM`], or no usable git at all,
/// is an error. Without it the same finding is one warning, so a caller that
/// passes `false` starts wherever it started before this check existed.
/// Output with no readable version only ever warns.
pub fn ensure_supported(fatal: bool) -> Result<()> {
    let probe = run_git_version();
    match verdict(probe.as_deref().map_err(String::as_str), fatal) {
        Verdict::Proceed => Ok(()),
        Verdict::Warn(message) => {
            warn!("{message}");
            Ok(())
        }
        Verdict::Refuse(message) => Err(anyhow!(message)),
    }
}

/// What the startup check does about the git it found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Proceed,
    Warn(String),
    Refuse(String),
}

/// Decide from the result of running `git --version`: its output, or the
/// reason it could not be run.
fn verdict(probe: Result<&str, &str>, fatal: bool) -> Verdict {
    let problem = match probe {
        Ok(output) => match assess(output) {
            Assessment::Supported(_) => return Verdict::Proceed,
            Assessment::TooOld(found) => too_old_message(found),
            // A wrapper or a vendor build may print something else. Refusing
            // to start over a string this code cannot read would be a worse
            // fault than the one the check exists to catch.
            Assessment::Unrecognised => return Verdict::Warn(unrecognised_message(output)),
        },
        Err(reason) => unusable_message(reason),
    };
    if fatal {
        Verdict::Refuse(problem)
    } else {
        Verdict::Warn(problem)
    }
}

fn run_git_version() -> Result<String, String> {
    let output = Command::new("git")
        .arg("--version")
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("`git --version` ended with {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn too_old_message(found: GitVersion) -> String {
    format!(
        "git {found} is older than {MINIMUM}, the oldest this server works with: pushes are \
         accepted but their history is never promoted (\"promoted history is incomplete in \
         the family\"). Put git {}.{} or newer first on PATH",
        MINIMUM.major, MINIMUM.minor
    )
}

fn unusable_message(reason: &str) -> String {
    format!(
        "git could not be run ({reason}): the server needs git {MINIMUM} or newer on PATH, \
         and without it no repository can be read or written"
    )
}

fn unrecognised_message(output: &str) -> String {
    format!(
        "no version could be read from `git --version` ({:?}); continuing, but a git older \
         than {MINIMUM} accepts pushes and never promotes their history",
        output.lines().next().unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(major: u32, minor: u32, patch: u32) -> GitVersion {
        GitVersion {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn parses_plain_and_vendor_suffixed_versions() {
        for (output, expected) in [
            ("git version 2.47.3", version(2, 47, 3)),
            ("git version 2.47.3\n", version(2, 47, 3)),
            ("git version 2.39.5 (Apple Git-154)", version(2, 39, 5)),
            ("git version 2.42.0.windows.1", version(2, 42, 0)),
            ("git version 2.48.0.rc1", version(2, 48, 0)),
            ("git version 2.48.0-rc1", version(2, 48, 0)),
            ("git version 2.43.GIT", version(2, 43, 0)),
            ("git version 2.42", version(2, 42, 0)),
            ("git version 10.1.12", version(10, 1, 12)),
        ] {
            assert_eq!(parse(output), Some(expected), "{output:?}");
        }
    }

    #[test]
    fn output_without_a_version_does_not_parse() {
        for output in [
            "",
            "git",
            "git version",
            "git version unknown",
            "git version 2",
            "git version two.47.3",
            "version 2.47.3",
            "2.47.3",
            "hub version 2.14.2",
        ] {
            assert_eq!(parse(output), None, "{output:?}");
        }
    }

    /// 2.9 is older than 2.42: the parts are compared as numbers, not as text.
    #[test]
    fn versions_are_ordered_by_number() {
        assert!(version(2, 9, 0) < version(2, 42, 0));
        assert!(version(2, 41, 9) < version(2, 42, 0));
        assert!(version(2, 100, 0) > version(2, 42, 0));
        assert!(version(3, 0, 0) > version(2, 42, 0));
        assert!(version(1, 99, 99) < version(2, 42, 0));
    }

    #[test]
    fn git_below_the_minimum_is_too_old() {
        for (output, found) in [
            ("git version 2.39.5", version(2, 39, 5)),
            ("git version 2.41.9", version(2, 41, 9)),
            ("git version 2.9.5", version(2, 9, 5)),
            ("git version 1.8.3.1", version(1, 8, 3)),
        ] {
            assert_eq!(assess(output), Assessment::TooOld(found), "{output:?}");
        }
    }

    #[test]
    fn git_at_or_above_the_minimum_is_supported() {
        for (output, found) in [
            ("git version 2.42.0", version(2, 42, 0)),
            ("git version 2.47.3", version(2, 47, 3)),
            ("git version 3.0.0", version(3, 0, 0)),
        ] {
            assert_eq!(assess(output), Assessment::Supported(found), "{output:?}");
            assert_eq!(verdict(Ok(output), true), Verdict::Proceed, "{output:?}");
            assert_eq!(verdict(Ok(output), false), Verdict::Proceed, "{output:?}");
        }
    }

    /// The message has to be enough to act on by itself: it is the last line
    /// of a server that refused to start.
    #[test]
    fn old_git_is_refused_only_when_fatal_and_says_why() {
        let Verdict::Refuse(message) = verdict(Ok("git version 2.39.5\n"), true) else {
            panic!("git 2.39.5 must stop a start that asked for a working git");
        };
        assert!(message.contains("2.39.5"), "the version found: {message}");
        assert!(message.contains("2.42"), "the minimum: {message}");
        assert!(message.contains("never promoted"), "the symptom: {message}");

        assert_eq!(
            verdict(Ok("git version 2.39.5\n"), false),
            Verdict::Warn(message),
            "without `fatal` the same finding is a warning"
        );
    }

    #[test]
    fn missing_git_is_refused_only_when_fatal_and_says_why() {
        let reason = "No such file or directory (os error 2)";
        let Verdict::Refuse(message) = verdict(Err(reason), true) else {
            panic!("a missing git must stop a start that asked for a working git");
        };
        assert!(message.contains(reason), "the cause: {message}");
        assert!(message.contains("2.42"), "the minimum: {message}");

        assert_eq!(verdict(Err(reason), false), Verdict::Warn(message));
    }

    #[test]
    fn unrecognised_output_is_not_fatal() {
        for output in ["", "gitoxide 0.44", "git version unknown"] {
            assert_eq!(assess(output), Assessment::Unrecognised, "{output:?}");
            for fatal in [true, false] {
                let Verdict::Warn(message) = verdict(Ok(output), fatal) else {
                    panic!("{output:?} must warn and continue (fatal={fatal})");
                };
                assert!(message.contains("2.42"), "the minimum: {message}");
            }
        }
    }
}
