//! Identifier-family Git object storage.
//!
//! Public repository paths remain ordinary bare repositories, but their object
//! database is an alternate shared by every view with the same identifier and
//! object format. This module owns the local layout and the small amount of Git
//! configuration needed to make those views safe to serve.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bitcoin_hashes::{sha256, Hash};
use dashmap::DashMap;
use tempfile::Builder;
use tokio::sync::{Mutex, OwnedMutexGuard};

use super::validate_repository_identifier;

/// Internal directory beneath the configured Git data root.
pub const INTERNAL_DIR: &str = ".grasp";
/// Current family storage format written by startup migration.
pub const STORAGE_VERSION: u32 = 1;
const FAMILY_DIR: &str = "families";
const BASE_REFS_PREFIX: &str = "refs/grasp/bases/";
const RETAINED_REFS_PREFIX: &str = "refs/grasp/retained/";

/// Git object hash algorithms are separate family namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectFormat {
    Sha1,
    Sha256,
}

impl ObjectFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Discover the object format used by an existing repository.
    pub fn detect(repo_path: &Path) -> Result<Self> {
        let output = Command::new("git")
            .args(["rev-parse", "--show-object-format"])
            .current_dir(repo_path)
            .output()
            .with_context(|| format!("discover object format for {}", repo_path.display()))?;
        if !output.status.success() {
            return Err(anyhow!(
                "git rev-parse --show-object-format failed for {}: {}",
                repo_path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        match String::from_utf8_lossy(&output.stdout).trim() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            other => Err(anyhow!("unsupported Git object format {other:?}")),
        }
    }
}

impl fmt::Display for ObjectFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The storage and locking boundary for related repository views.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FamilyKey {
    pub object_format: ObjectFormat,
    pub identifier: String,
}

impl FamilyKey {
    pub fn new(object_format: ObjectFormat, identifier: impl Into<String>) -> Result<Self> {
        let identifier = identifier.into();
        if !validate_repository_identifier(&identifier) {
            return Err(anyhow!("invalid repository identifier {identifier:?}"));
        }
        Ok(Self {
            object_format,
            identifier,
        })
    }

    pub fn sha1(identifier: impl Into<String>) -> Result<Self> {
        Self::new(ObjectFormat::Sha1, identifier)
    }
}

/// Always-on local family storage.
///
/// Later backends use the same family paths as a hydrated Git execution
/// surface. The default remains this durable local implementation.
#[derive(Clone)]
pub struct LocalGitStorage {
    git_data_path: PathBuf,
    family_locks: Arc<DashMap<FamilyKey, Arc<Mutex<()>>>>,
}

impl LocalGitStorage {
    pub fn new(git_data_path: impl Into<PathBuf>) -> Self {
        Self {
            git_data_path: git_data_path.into(),
            family_locks: Arc::new(DashMap::new()),
        }
    }

    pub fn git_data_path(&self) -> &Path {
        &self.git_data_path
    }

    pub fn internal_path(&self) -> PathBuf {
        self.git_data_path.join(INTERNAL_DIR)
    }

    pub fn storage_version_path(&self) -> PathBuf {
        self.internal_path().join("storage-version")
    }

    pub fn family_repo_path(&self, key: &FamilyKey) -> PathBuf {
        self.internal_path()
            .join(FAMILY_DIR)
            .join(key.object_format.as_str())
            .join(format!("{}.git", key.identifier))
    }

    pub fn family_objects_path(&self, key: &FamilyKey) -> PathBuf {
        self.family_repo_path(key).join("objects")
    }

    /// Serialize mutations to one identifier family.
    pub async fn write_lease(&self, key: &FamilyKey) -> Result<FamilyWriteLease> {
        let lock = self
            .family_locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let guard = lock.lock_owned().await;
        self.ensure_family(key)?;
        Ok(FamilyWriteLease {
            key: key.clone(),
            family_repo_path: self.family_repo_path(key),
            family_objects_path: self.family_objects_path(key),
            _guard: guard,
        })
    }

    /// Create an empty family inventory if necessary.
    pub fn ensure_family(&self, key: &FamilyKey) -> Result<PathBuf> {
        let repo_path = self.family_repo_path(key);
        if repo_path.exists() {
            let actual = ObjectFormat::detect(&repo_path)?;
            if actual != key.object_format {
                return Err(anyhow!(
                    "family {} has object format {}, expected {}",
                    repo_path.display(),
                    actual,
                    key.object_format
                ));
            }
            return Ok(repo_path);
        }

        let parent = repo_path
            .parent()
            .context("family repository has no parent directory")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create family directory {}", parent.display()))?;
        let staging = Builder::new()
            .prefix(".family-")
            .tempdir_in(parent)
            .with_context(|| format!("create family staging directory in {}", parent.display()))?;

        run_git(
            None,
            &[
                "init",
                "--bare",
                "--quiet",
                &format!("--object-format={}", key.object_format),
                staging.path().to_string_lossy().as_ref(),
            ],
            "initialize family inventory",
        )?;
        configure_family(staging.path())?;

        match std::fs::rename(staging.path(), &repo_path) {
            Ok(()) => {
                // The directory has moved out of TempDir ownership.
                let _ = staging.keep();
            }
            Err(error) if repo_path.exists() => {
                // Another process created the same content-addressed family.
                tracing::debug!(
                    family = %repo_path.display(),
                    %error,
                    "Family inventory already initialized"
                );
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("install family inventory at {}", repo_path.display())
                });
            }
        }
        ObjectFormat::detect(&repo_path)?;
        Ok(repo_path)
    }

    /// Create a new thin bare repository without modifying an existing path.
    pub fn create_thin_view(&self, key: &FamilyKey, view_path: &Path) -> Result<()> {
        self.ensure_family(key)?;
        if view_path.exists() {
            return Err(anyhow!(
                "refusing to replace existing repository view {}",
                view_path.display()
            ));
        }

        let parent = view_path
            .parent()
            .context("repository view has no parent directory")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create view directory {}", parent.display()))?;
        let staging = Builder::new()
            .prefix(".view-")
            .tempdir_in(parent)
            .with_context(|| format!("create view staging directory in {}", parent.display()))?;

        run_git(
            None,
            &[
                "init",
                "--bare",
                "--quiet",
                "--initial-branch=main",
                &format!("--object-format={}", key.object_format),
                staging.path().to_string_lossy().as_ref(),
            ],
            "initialize thin repository view",
        )?;
        self.configure_thin_view(key, staging.path())?;

        std::fs::rename(staging.path(), view_path)
            .with_context(|| format!("install repository view at {}", view_path.display()))?;
        let _ = staging.keep();
        Ok(())
    }

    /// Install or repair the family alternate on an existing thin view.
    pub fn configure_thin_view(&self, key: &FamilyKey, view_path: &Path) -> Result<()> {
        let family_objects = self.family_objects_path(key);
        if !family_objects.is_dir() {
            return Err(anyhow!(
                "family object directory is missing: {}",
                family_objects.display()
            ));
        }
        let view_format = ObjectFormat::detect(view_path)?;
        if view_format != key.object_format {
            return Err(anyhow!(
                "view {} has object format {}, expected {}",
                view_path.display(),
                view_format,
                key.object_format
            ));
        }

        let info = view_path.join("objects/info");
        std::fs::create_dir_all(&info)
            .with_context(|| format!("create alternate directory {}", info.display()))?;
        let absolute_objects = std::fs::canonicalize(&family_objects).with_context(|| {
            format!(
                "canonicalize family object path {}",
                family_objects.display()
            )
        })?;
        let alternates = info.join("alternates");
        let pending = info.join("alternates.pending");
        std::fs::write(
            &pending,
            format!("{}\n", absolute_objects.to_string_lossy()),
        )
        .with_context(|| format!("write alternate {}", pending.display()))?;
        std::fs::rename(&pending, &alternates)
            .with_context(|| format!("install alternate {}", alternates.display()))?;

        run_git(
            Some(view_path),
            &[
                "config",
                "--local",
                "core.alternateRefsPrefixes",
                BASE_REFS_PREFIX,
            ],
            "configure alternate ref advertisement",
        )?;
        run_git(
            Some(view_path),
            &["config", "--local", "gc.auto", "0"],
            "disable view auto gc",
        )?;
        run_git(
            Some(view_path),
            &["config", "--local", "maintenance.auto", "false"],
            "disable view auto maintenance",
        )?;
        Ok(())
    }

    /// Point a Git command's writable object database at the family.
    pub fn configure_write_command(&self, key: &FamilyKey, command: &mut Command) {
        command.env("GIT_OBJECT_DIRECTORY", self.family_objects_path(key));
    }

    /// Keep an accepted object tip reachable without exposing it as a view ref.
    pub fn retain_tip(&self, key: &FamilyKey, source_ref: &str, oid: &str) -> Result<String> {
        self.update_internal_tip(key, RETAINED_REFS_PREFIX, source_ref, oid)
    }

    /// Make a useful tip available to receive-pack's anonymous `.have` set.
    pub fn advertise_base_tip(
        &self,
        key: &FamilyKey,
        source_ref: &str,
        oid: &str,
    ) -> Result<String> {
        self.update_internal_tip(key, BASE_REFS_PREFIX, source_ref, oid)
    }

    fn update_internal_tip(
        &self,
        key: &FamilyKey,
        prefix: &str,
        source_ref: &str,
        oid: &str,
    ) -> Result<String> {
        let family_repo = self.family_repo_path(key);
        if !oid_exists_in(&family_repo, oid)? {
            return Err(anyhow!(
                "cannot retain missing object {oid} in family {}",
                family_repo.display()
            ));
        }
        let digest = sha256::Hash::hash(format!("{source_ref}\0{oid}").as_bytes());
        let internal_ref = format!("{prefix}{digest}");
        run_git(
            Some(&family_repo),
            &["update-ref", &internal_ref, oid],
            "update family internal ref",
        )?;
        Ok(internal_ref)
    }
}

/// Exclusive access to a family's writable object database.
pub struct FamilyWriteLease {
    pub key: FamilyKey,
    pub family_repo_path: PathBuf,
    pub family_objects_path: PathBuf,
    _guard: OwnedMutexGuard<()>,
}

fn configure_family(repo_path: &Path) -> Result<()> {
    for (name, value) in [
        ("gc.auto", "0"),
        ("gc.autoDetach", "false"),
        ("maintenance.auto", "false"),
    ] {
        run_git(
            Some(repo_path),
            &["config", "--local", name, value],
            "disable automatic family maintenance",
        )?;
    }
    Ok(())
}

fn oid_exists_in(repo_path: &Path, oid: &str) -> Result<bool> {
    let status = Command::new("git")
        .args(["cat-file", "-e", oid])
        .current_dir(repo_path)
        .status()
        .with_context(|| format!("check object {oid} in {}", repo_path.display()))?;
    Ok(status.success())
}

fn run_git(current_dir: Option<&Path>, args: &[&str], description: &'static str) -> Result<()> {
    let mut command = Command::new("git");
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    let output = command
        .args(args)
        .output()
        .with_context(|| format!("{description}: spawn git"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "{description} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::process::Stdio;

    use super::*;

    fn git_output(current_dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(current_dir)
            .output()
            .expect("spawn git");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn seed_commit(family_repo: &Path) -> String {
        let tree = git_output(family_repo, &["mktree"]);
        let output = Command::new("git")
            .args([
                "-c",
                "user.name=storage test",
                "-c",
                "user.email=storage@example.invalid",
                "commit-tree",
                &tree,
                "-m",
                "seed",
            ])
            .current_dir(family_repo)
            .output()
            .expect("create commit");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    #[test]
    fn family_key_rejects_unsafe_identifiers() {
        for identifier in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(
                FamilyKey::sha1(identifier).is_err(),
                "accepted {identifier:?}"
            );
        }
        assert!(FamilyKey::sha1("my repository.git").is_ok());
    }

    #[test]
    fn thin_view_advertises_family_bases_anonymously() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path());
        let key = FamilyKey::sha1("example").unwrap();
        let family = storage.ensure_family(&key).unwrap();
        let oid = seed_commit(&family);
        storage
            .advertise_base_tip(&key, "refs/heads/main", &oid)
            .unwrap();
        storage.retain_tip(&key, "refs/heads/main", &oid).unwrap();

        let view = temp.path().join("owner/example.git");
        storage.create_thin_view(&key, &view).unwrap();

        let receive = Command::new("git")
            .args(["receive-pack", "--stateless-rpc", "--advertise-refs"])
            .arg(&view)
            .output()
            .unwrap();
        assert!(receive.status.success());
        let advertisement = String::from_utf8_lossy(&receive.stdout);
        assert!(advertisement.contains(&format!("{oid} .have")));
        assert!(!advertisement.contains("refs/grasp/bases/"));
        assert!(!advertisement.contains("refs/grasp/retained/"));

        let upload = Command::new("git")
            .args(["upload-pack", "--stateless-rpc", "--advertise-refs"])
            .arg(&view)
            .output()
            .unwrap();
        assert!(upload.status.success());
        let advertisement = String::from_utf8_lossy(&upload.stdout);
        assert!(!advertisement.contains(&oid));
        assert!(!advertisement.contains("refs/grasp/"));
    }

    #[test]
    fn configured_writes_land_in_family_object_database() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path());
        let key = FamilyKey::sha1("example").unwrap();
        storage.ensure_family(&key).unwrap();
        let view = temp.path().join("owner/example.git");
        storage.create_thin_view(&key, &view).unwrap();

        let mut command = Command::new("git");
        command
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(&view)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        storage.configure_write_command(&key, &mut command);
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"shared object\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let oid = String::from_utf8_lossy(&output.stdout).trim().to_string();

        assert!(oid_exists_in(&storage.family_repo_path(&key), &oid).unwrap());
        let local_object = view.join("objects").join(&oid[..2]).join(&oid[2..]);
        assert!(!local_object.exists());
        assert!(super::super::oid_exists(&view, &oid));
    }

    #[tokio::test]
    async fn write_leases_serialize_one_family() {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path());
        let key = FamilyKey::sha1("example").unwrap();
        let first = storage.write_lease(&key).await.unwrap();

        let waiting_storage = storage.clone();
        let waiting_key = key.clone();
        let waiting =
            tokio::spawn(async move { waiting_storage.write_lease(&waiting_key).await.unwrap() });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(first);
        waiting.await.unwrap();
    }
}
