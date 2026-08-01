//! Hermetic git subprocess construction.
//!
//! Fixtures and tests spawn many `git` subprocesses and several of them feed
//! hard-coded deterministic commit hashes. Those hashes (and the surrounding
//! control flow) are only meaningful if every input git reads is supplied by
//! the fixture itself rather than inherited from whatever the host happens to
//! have configured.

use std::process::Command;

/// Build a `git` [`Command`] that is hermetic with respect to ambient git
/// configuration.
///
/// Ambient configuration — the system `/etc/gitconfig`, the user's
/// `~/.gitconfig` or `$XDG_CONFIG_HOME/git/config`, and config injected via
/// the `GIT_CONFIG_COUNT` / `GIT_CONFIG_PARAMETERS` environment — can change
/// fixture behaviour: a failing hook reached through `core.hooksPath` or
/// `init.templateDir` breaks every commit, `init.defaultBranch` renames
/// branches fixtures rely on, and credential helpers can stall network
/// operations waiting for input.
///
/// Every git subprocess spawned by fixtures or tests must be built through
/// this helper. The invocation then sees only configuration it supplies
/// itself: repo-local `git config`, `-c` flags, or `GIT_*` environment
/// variables set at the call site.
///
/// Requires git >= 2.32 (June 2021) for `GIT_CONFIG_GLOBAL` /
/// `GIT_CONFIG_SYSTEM`; the flake pins a far newer git.
pub fn git_command() -> Command {
    let mut cmd = Command::new("git");
    // Mask the system config and the user-global config in both of its
    // locations (~/.gitconfig and $XDG_CONFIG_HOME/git/config).
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
    // Fail fast instead of stalling the suite on a credential prompt.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    // Config can also be injected through the environment. GIT_CONFIG_KEY_n /
    // GIT_CONFIG_VALUE_n are only honoured while GIT_CONFIG_COUNT is set, so
    // removing the count neutralises the whole family.
    cmd.env_remove("GIT_CONFIG_COUNT");
    cmd.env_remove("GIT_CONFIG_PARAMETERS");
    // Repository discovery must come from `current_dir`, not from a parent
    // process that happens to run inside a git hook, alias, or rebase.
    cmd.env_remove("GIT_DIR");
    cmd.env_remove("GIT_WORK_TREE");
    cmd.env_remove("GIT_INDEX_FILE");
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        create_deterministic_commit_with_variant, CommitVariant, DETERMINISTIC_COMMIT_HASH,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// Write a global gitconfig whose settings demonstrably break the fixture
    /// recipe when they leak in: `core.hooksPath` and `init.templateDir` both
    /// deliver a pre-commit hook that always fails, `init.defaultBranch`
    /// renames the initial branch, and gpgsign/autocrlf cover the remaining
    /// commit inputs.
    fn write_hostile_gitconfig(dir: &Path) -> PathBuf {
        let hooks = dir.join("hooks");
        fs::create_dir_all(&hooks).expect("create hooks dir");
        let hook = hooks.join("pre-commit");
        fs::write(
            &hook,
            "#!/bin/sh\necho 'hostile ambient git config leaked into a fixture' >&2\nexit 1\n",
        )
        .expect("write pre-commit hook");
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("chmod hook");

        let template_hooks = dir.join("template").join("hooks");
        fs::create_dir_all(&template_hooks).expect("create template hooks dir");
        fs::copy(&hook, template_hooks.join("pre-commit")).expect("copy hook into template");

        let config = dir.join("gitconfig");
        fs::write(
            &config,
            format!(
                "[init]\n\
                 \tdefaultBranch = main\n\
                 \ttemplateDir = {template}\n\
                 [core]\n\
                 \thooksPath = {hooks}\n\
                 \tautocrlf = true\n\
                 [commit]\n\
                 \tgpgsign = true\n",
                template = dir.join("template").display(),
                hooks = hooks.display(),
            ),
        )
        .expect("write hostile gitconfig");
        config
    }

    /// Restores the mutated process environment even if the test panics.
    struct EnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn set(vars: &[(&'static str, &Path)]) -> Self {
            let saved = vars
                .iter()
                .map(|(key, value)| {
                    let previous = std::env::var_os(key);
                    std::env::set_var(key, value);
                    (*key, previous)
                })
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, previous) in self.saved.drain(..) {
                match previous {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn init_repo_with_identity(git: impl Fn() -> Command, repo: &Path) {
        let init = git()
            .args(["init", repo.to_str().expect("utf-8 repo path")])
            .output()
            .expect("spawn git init");
        assert!(
            init.status.success(),
            "git init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        for (key, value) in [
            ("user.email", "test@grasp-audit.local"),
            ("user.name", "GRASP Audit Test"),
        ] {
            let config = git()
                .args(["config", key, value])
                .current_dir(repo)
                .output()
                .expect("spawn git config");
            assert!(
                config.status.success(),
                "git config {key} failed: {}",
                String::from_utf8_lossy(&config.stderr)
            );
        }
    }

    /// Regression test for hermeticity: the deterministic commit fixture must
    /// produce its pinned hash even when the surrounding process advertises a
    /// hostile git configuration.
    ///
    /// The test first proves the hostile configuration is potent (a plain git
    /// invocation honouring it cannot commit at all), then proves
    /// [`git_command`]-based fixtures neutralise it.
    #[test]
    fn deterministic_commit_survives_hostile_ambient_git_config() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let hostile_config = write_hostile_gitconfig(dir.path());

        // Potency check: a non-hermetic git honouring the hostile config must
        // fail to commit (the pre-commit hook fires). If this stops failing,
        // the hostile config has rotted and no longer guards anything.
        let raw_repo = dir.path().join("raw");
        let raw_git = || {
            let mut cmd = Command::new("git");
            cmd.env("GIT_CONFIG_GLOBAL", &hostile_config);
            cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
            cmd
        };
        init_repo_with_identity(raw_git, &raw_repo);
        let err = create_deterministic_commit_with_variant(&raw_repo, CommitVariant::Owner)
            .expect_err("hostile config should break a commit that inherits it");
        assert!(
            err.contains("hostile ambient git config leaked"),
            "expected the hostile hook to fire, got: {err}"
        );

        // Hermetic check: with the hostile config exposed the way a real host
        // exposes it (global/system config paths in the environment), the
        // fixture recipe must still produce the pinned deterministic hash.
        let _guard = EnvGuard::set(&[
            ("HOME", dir.path()),
            ("GIT_CONFIG_GLOBAL", &hostile_config),
            ("GIT_CONFIG_SYSTEM", &hostile_config),
        ]);
        let hermetic_repo = dir.path().join("hermetic");
        init_repo_with_identity(git_command, &hermetic_repo);
        let hash = create_deterministic_commit_with_variant(&hermetic_repo, CommitVariant::Owner)
            .expect("hermetic fixture commit should succeed under hostile ambient config");
        assert_eq!(
            hash, DETERMINISTIC_COMMIT_HASH,
            "deterministic hash must not depend on ambient git configuration"
        );
    }
}
