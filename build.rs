use std::{env, process::Command};

fn main() {
    if let Some(commit) = build_revision() {
        let short: String = commit.chars().take(8).collect();
        println!("cargo:rustc-env=GIT_COMMIT={commit}");
        println!("cargo:rustc-env=GIT_COMMIT_SHORT={short}");
    }

    // Nix builds inject the locked flake revision because their source archive
    // intentionally excludes .git. Development builds fall back to Git.
    println!("cargo:rerun-if-env-changed=NGIT_BUILD_REVISION");
    // Re-run if HEAD changes (new commits)
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");
}

fn build_revision() -> Option<String> {
    env::var("NGIT_BUILD_REVISION")
        .ok()
        .filter(|revision| !revision.is_empty() && revision != "unknown")
        .or_else(|| {
            let output = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()?;
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
                .filter(|revision| !revision.is_empty())
        })
}
