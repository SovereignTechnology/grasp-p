//! Git Subprocess Management
//!
//! This module provides utilities for spawning and managing Git subprocesses
//! for upload-pack and receive-pack operations.

use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, Command};

use super::protocol::GitService;

/// Git subprocess wrapper
pub struct GitSubprocess {
    /// `None` once the child has been reaped.
    child: Option<Child>,
}

impl GitSubprocess {
    /// Spawn a git subprocess for the given service and repository path
    ///
    /// # Arguments
    /// * `service` - The Git service (upload-pack or receive-pack)
    /// * `repo_path` - Path to the bare Git repository
    /// * `advertise` - If true, run with --advertise-refs flag
    /// * `git_protocol` - Optional Git protocol version (e.g., "version=2")
    pub fn spawn(
        service: GitService,
        repo_path: impl AsRef<Path>,
        advertise: bool,
        git_protocol: Option<&str>,
    ) -> std::io::Result<Self> {
        Self::spawn_with_object_directory(
            service,
            repo_path,
            advertise,
            git_protocol,
            None::<&Path>,
        )
    }

    /// Spawn Git with an optional writable object database override.
    ///
    /// Thin views normally read through `objects/info/alternates`. Commands
    /// that create objects use this override so receive-pack quarantine output
    /// and fetched objects land directly in the identifier family.
    pub fn spawn_with_object_directory(
        service: GitService,
        repo_path: impl AsRef<Path>,
        advertise: bool,
        git_protocol: Option<&str>,
        object_directory: Option<impl AsRef<Path>>,
    ) -> std::io::Result<Self> {
        let repo_path = repo_path.as_ref();

        let mut cmd = Command::new("git");

        // GRASP-01 requirement: MUST include `allow-reachable-sha1-in-want`,
        // `allow-tip-sha1-in-want`, and `uploadpack.allowFilter` in advertisement
        // and serve available oids and filtered requests.
        // These config options must be passed before the command name.
        cmd.arg("-c");
        cmd.arg("uploadpack.allowReachableSHA1InWant=true");
        cmd.arg("-c");
        cmd.arg("uploadpack.allowTipSHA1InWant=true");
        cmd.arg("-c");
        cmd.arg("uploadpack.allowFilter=true");

        cmd.arg(service.command_name());

        if advertise {
            cmd.arg("--advertise-refs");
        }

        cmd.arg("--stateless-rpc");
        cmd.arg(repo_path);

        cmd.kill_on_drop(true);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Set GIT_PROTOCOL environment variable if provided
        // This enables Git protocol v2 support for modern git clients
        if let Some(protocol) = git_protocol {
            cmd.env("GIT_PROTOCOL", protocol);
        }
        if let Some(object_directory) = object_directory {
            cmd.env("GIT_OBJECT_DIRECTORY", object_directory.as_ref());
        }

        let child = cmd.spawn()?;

        Ok(Self { child: Some(child) })
    }

    /// Get a mutable reference to stdin
    pub fn stdin(&mut self) -> Option<&mut (impl AsyncWrite + Unpin)> {
        self.child.as_mut().expect("live child").stdin.as_mut()
    }

    /// Get a mutable reference to stdout
    pub fn stdout(&mut self) -> Option<&mut (impl AsyncRead + Unpin)> {
        self.child.as_mut().expect("live child").stdout.as_mut()
    }

    /// Get a mutable reference to stderr
    pub fn stderr(&mut self) -> Option<&mut (impl AsyncRead + Unpin)> {
        self.child.as_mut().expect("live child").stderr.as_mut()
    }

    /// Take ownership of stdin
    pub fn take_stdin(&mut self) -> Option<impl AsyncWrite> {
        self.child.as_mut().expect("live child").stdin.take()
    }

    /// Take ownership of stdout
    pub fn take_stdout(&mut self) -> Option<impl AsyncRead> {
        self.child.as_mut().expect("live child").stdout.take()
    }

    /// Take ownership of stderr  
    pub fn take_stderr(&mut self) -> Option<impl AsyncRead> {
        self.child.as_mut().expect("live child").stderr.take()
    }

    /// Wait for the subprocess to complete
    pub async fn wait(mut self) -> std::io::Result<std::process::ExitStatus> {
        let result = self.child.as_mut().expect("live child").wait().await;
        if result.is_ok() {
            self.child.take();
        }
        result
    }

    /// Kill the subprocess
    pub async fn kill(&mut self) -> std::io::Result<()> {
        self.child.as_mut().expect("live child").kill().await
    }
}

impl Drop for GitSubprocess {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            // Blocking tasks cannot be aborted by task cancellation or runtime
            // shutdown, so the killed child is always reaped.
            let reaper = runtime.clone();
            runtime.spawn_blocking(move || {
                let _ = reaper.block_on(child.wait());
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;
    use tempfile::TempDir;

    fn create_bare_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        let status = StdCommand::new("git")
            .args(["init", "--bare", "--quiet", "--initial-branch=main"])
            .arg(dir.path())
            .status()
            .expect("Failed to run git init");
        assert!(status.success());
        dir
    }

    #[tokio::test]
    async fn dropped_subprocess_is_killed_and_reaped() {
        let repo = create_bare_repo();
        let child =
            GitSubprocess::spawn(GitService::ReceivePack, repo.path(), false, None).unwrap();
        let pid = child.child.as_ref().unwrap().id().unwrap();
        let process = std::path::PathBuf::from(format!("/proc/{pid}"));
        assert!(process.exists());
        drop(child);
        // A killed but unreaped child remains visible as a zombie.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while process.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped child was not reaped");
    }

    #[tokio::test]
    async fn test_spawn_upload_pack_advertise() {
        let repo = create_bare_repo();
        let mut proc = GitSubprocess::spawn(GitService::UploadPack, repo.path(), true, None)
            .expect("Failed to spawn git");

        // Should have spawned successfully
        assert!(proc.stdout().is_some());
        assert!(proc.stdin().is_some());

        // Clean up
        let _ = proc.kill().await;
    }

    #[tokio::test]
    async fn test_spawn_receive_pack() {
        let repo = create_bare_repo();
        let mut proc = GitSubprocess::spawn(GitService::ReceivePack, repo.path(), false, None)
            .expect("Failed to spawn git");

        assert!(proc.stdout().is_some());
        assert!(proc.stdin().is_some());

        let _ = proc.kill().await;
    }
}
