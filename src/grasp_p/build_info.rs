//! What a build says about itself: the text behind `--version` on both
//! binaries and the `build` field of the startup log line.
//!
//! Upstream's version number cannot tell a GRASP-P build from upstream's, or
//! one GRASP-P release from the next, and the two nodes of a pair have to run
//! the same build. The release name is the tag the release job built, handed
//! over in the build-time variable `GRASP_P_BUILD_RELEASE`. The commit is the
//! `GIT_COMMIT` that upstream's `build.rs` already exports.

use std::sync::OnceLock;

/// Characters of the commit hash shown. The release job looks for exactly
/// this many in the version line of the binary it built.
const COMMIT_LENGTH: usize = 12;

/// Join upstream's version, the GRASP-P release and the commit into one line.
///
/// A build with no release name is `unreleased`, so that a deployment can
/// refuse anything that was not built from a tag. A variable that is set but
/// empty counts as absent: that is what a CI variable holding the name of a
/// tag expands to on a branch.
pub fn describe(upstream: &str, release: Option<&str>, commit: Option<&str>) -> String {
    let release = non_empty(release).unwrap_or("unreleased");
    let commit = non_empty(commit).map_or("unknown", |commit| {
        commit.get(..COMMIT_LENGTH).unwrap_or(commit)
    });
    format!("{upstream} (grasp-p {release}, commit {commit})")
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// The version line of this build.
///
/// `'static` because clap, built without its `string` feature, takes a
/// version only as a `&'static str`.
pub fn version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        describe(
            env!("CARGO_PKG_VERSION"),
            option_env!("GRASP_P_BUILD_RELEASE"),
            option_env!("GIT_COMMIT"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "83b63ac0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6";

    #[test]
    fn describe_names_release_and_commit() {
        assert_eq!(
            describe("3.0.7", Some("sovtech-v1.0.0"), Some(COMMIT)),
            "3.0.7 (grasp-p sovtech-v1.0.0, commit 83b63ac0d1e2)"
        );
    }

    #[test]
    fn describe_marks_an_untagged_build_unreleased() {
        for release in [None, Some(""), Some("  ")] {
            assert_eq!(
                describe("3.0.7", release, Some(COMMIT)),
                "3.0.7 (grasp-p unreleased, commit 83b63ac0d1e2)",
                "{release:?}"
            );
        }
    }

    #[test]
    fn describe_without_a_commit_says_unknown() {
        for commit in [None, Some("")] {
            assert_eq!(
                describe("3.0.7", Some("sovtech-v1.0.0"), commit),
                "3.0.7 (grasp-p sovtech-v1.0.0, commit unknown)",
                "{commit:?}"
            );
        }
    }

    #[test]
    fn describe_keeps_a_commit_shorter_than_the_cut() {
        assert_eq!(
            describe("3.0.7", None, Some("83b63ac")),
            "3.0.7 (grasp-p unreleased, commit 83b63ac)"
        );
    }

    /// The release job greps the version line for the first twelve
    /// characters of the commit it built. This is the same check on the
    /// build under test, for the case where the build knows its commit.
    #[test]
    fn version_of_this_build_names_its_commit() {
        let version = version();
        assert!(
            version.starts_with(concat!(env!("CARGO_PKG_VERSION"), " (grasp-p ")),
            "{version}"
        );
        if let Some(commit) = non_empty(option_env!("GIT_COMMIT")) {
            let short = commit.get(..COMMIT_LENGTH).unwrap_or(commit);
            assert!(version.contains(&format!("commit {short})")), "{version}");
        }
    }
}
