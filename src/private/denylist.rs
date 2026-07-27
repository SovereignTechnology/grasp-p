//! Node-local legal takedown denylist (Phase-4b D1).
//!
//! The denylist is a set of blob sha256 hex digests the operator must not
//! serve or store (court orders, CSAM reports, …). It is deliberately
//! NODE-LOCAL legal config: two paired nodes in different jurisdictions may
//! legitimately enforce different lists, so it is NOT part of the
//! `policy_fingerprint` preimage.
//!
//! Semantics:
//!
//! - **Multi-file**: `NGIT_PRIVATE_DENYLIST_PATH` is a comma-separated list
//!   of files (per-node / per-jurisdiction lists). A MISSING file is
//!   tolerated (warn + treated as empty); a present-but-unreadable file is
//!   a hard boot error (fail loud on misconfig). During reload an
//!   unreadable file keeps its last-known entries (a transient read error
//!   must not silently unblock taken-down content) and is retried every
//!   tick.
//! - **Atomic swap**: the live set sits behind an `RwLock`; a reload
//!   builds the new union off-lock and swaps it in one write critical
//!   section. Reads (GET/HEAD 451, upload preflight, finish() race
//!   re-check, mirror skip sites) take the read lock only.
//! - **Purge-on-add**: hashes NEWLY present after a reload are purged
//!   immediately via [`gc::purge_blob`] — the same meta-`with_write`
//!   primitive GC uses — freeing every claim (releasing ledger charges per
//!   the established discipline) and unlinking the bytes. The swap happens
//!   BEFORE the purge so the five mirror skip sites (which consult
//!   `is_denylisted`) can never re-enqueue a blob that is about to be
//!   purged, and reads start returning 451 immediately.
//! - **Removal**: a hash dropped from the files unblocks reads on the next
//!   swap; bytes already purged stay gone (a client re-upload is required).
//! - **File caps (FS-6)**: each file is limited to 64 MiB / 1M lines —
//!   over-cap is a hard boot error, and on reload the file keeps its
//!   last-known entries (error logged, retried every tick). Writers MUST
//!   update files atomically (write-temp-then-rename): the reload keys off
//!   mtime, and a torn write is a known staleness window (L1-F7).

use std::collections::HashSet;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use tokio::task::JoinHandle;

use super::{blossom_auth, gc, PrivateService};

/// Shared handle to the live denylist set (one per [`PrivateService`]).
pub(crate) type SharedDenylist = Arc<RwLock<HashSet<String>>>;

/// Hard per-file caps (FS-6, review L2-F7): an uncapped multi-million-line
/// file costs GBs of memory (every raw line becomes a String before
/// normalization filters it). Exceeding either cap is a hard boot error;
/// on reload the file keeps its last-known entries and the error is
/// logged — the same boot-loud / reload-keep semantics as an unreadable
/// file.
pub(crate) const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_LINES: usize = 1_000_000;

/// Read one denylist file with the byte cap enforced mid-stream (a bare
/// metadata size check would race a growing file).
fn read_file_capped(path: &str) -> std::io::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut buf = String::new();
    file.by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut buf)?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("private denylist file exceeds the {MAX_FILE_BYTES}-byte cap"),
        ));
    }
    Ok(buf)
}

/// Parse denylist file contents: one sha256 per line, trimmed, lowercased,
/// and filtered to 64-char lowercase hex (blank/comment/garbage lines are
/// dropped). Errors when the file exceeds [`MAX_LINES`].
pub(crate) fn parse_contents(contents: &str) -> Result<HashSet<String>> {
    let mut set = HashSet::new();
    for (index, line) in contents.lines().enumerate() {
        if index >= MAX_LINES {
            anyhow::bail!("private denylist file exceeds the {MAX_LINES}-line cap");
        }
        let line = line.trim().to_lowercase();
        if blossom_auth::is_lower_hex_64(&line) {
            set.insert(line);
        }
    }
    Ok(set)
}

/// Read the set poisoning-tolerantly: it is only ever replaced wholesale,
/// so a poisoned lock (a panicked reload writer) still holds a coherent
/// set and readers must neither panic nor fail open.
pub(crate) fn read_set(lock: &RwLock<HashSet<String>>) -> RwLockReadGuard<'_, HashSet<String>> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

/// Swap in a newly built set, returning the previous one (for the
/// purge-on-add set difference). Poisoning-tolerant, see [`read_set`].
fn swap_set(lock: &RwLock<HashSet<String>>, new: HashSet<String>) -> HashSet<String> {
    let mut guard = lock.write().unwrap_or_else(|e| e.into_inner());
    std::mem::replace(&mut *guard, new)
}

/// Boot-time load with multi-file semantics: a MISSING file is tolerated
/// (warn + treated as empty — per-node / per-jurisdiction lists may simply
/// not be mounted here), but a present-but-unreadable or over-cap file is
/// a hard boot error (fail loud on misconfig).
pub(crate) fn load_boot(paths: &[String]) -> Result<HashSet<String>> {
    let mut set = HashSet::new();
    for path in paths {
        match read_file_capped(path) {
            Ok(contents) => set.extend(
                parse_contents(&contents)
                    .with_context(|| format!("failed to parse private denylist at {path}"))?,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!("private denylist file {path} not found; treating it as empty");
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to read private denylist at {path}"));
            }
        }
    }
    Ok(set)
}

/// Per-file reload state: the last observed mtime and the last parsed set,
/// so a tick only re-reads files that actually changed.
struct FileState {
    path: String,
    mtime: Option<SystemTime>,
    hashes: HashSet<String>,
}

impl FileState {
    fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            mtime: None,
            hashes: HashSet::new(),
        }
    }

    /// Re-stat + re-read when the file changed since the last call.
    /// Returns true when the parsed set may have changed.
    fn refresh(&mut self) -> bool {
        let mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        if mtime == self.mtime {
            return false;
        }
        match read_file_capped(&self.path) {
            Ok(contents) => match parse_contents(&contents) {
                Ok(hashes) => {
                    self.mtime = mtime;
                    self.hashes = hashes;
                    true
                }
                Err(e) => {
                    // Over the line cap: same reload-keep semantics as an
                    // unreadable file — keep enforcing the last-good set
                    // and retry every tick (mtime deliberately NOT
                    // advanced).
                    tracing::error!(
                        "private denylist file {} could not be parsed ({e}); \
                         keeping last-known entries",
                        self.path
                    );
                    false
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Disappeared (or still absent): treat as empty. Warn only
                // on the transition (mtime Some -> None), not every tick.
                if self.mtime.is_some() {
                    tracing::warn!(
                        "private denylist file {} no longer found; treating it as empty",
                        self.path
                    );
                }
                self.mtime = None;
                let changed = !self.hashes.is_empty();
                self.hashes = HashSet::new();
                changed
            }
            Err(e) => {
                // Present but unreadable: boot fails loud, but a live node
                // keeps enforcing the last-good entries and retries every
                // tick — a transient read error must not silently unblock
                // taken-down content.
                tracing::error!(
                    "private denylist file {} is unreadable ({e}); keeping last-known entries",
                    self.path
                );
                false
            }
        }
    }

    /// One reload tick: re-read changed files; on any change, swap the live
    /// set and purge blobs whose sha is NEWLY denylisted.
    fn reload_once(svc: &PrivateService, files: &mut [FileState]) {
        let mut any_change = false;
        for file in files.iter_mut() {
            any_change |= file.refresh();
        }
        if !any_change {
            return;
        }
        let new_set: HashSet<String> = files
            .iter()
            .flat_map(|f| f.hashes.iter().cloned())
            .collect();
        // Swap BEFORE purging: reads 451 immediately, and the mirror skip
        // sites (which consult is_denylisted) can never re-enqueue a blob
        // that is about to be purged. `update_lag` likewise excludes
        // denylisted shas, and the purge deletes the claims outright, so
        // purged blobs leave ngit_private_mirror_lag_blobs.
        let old_set = swap_set(&svc.denylist, new_set.clone());
        crate::metrics::set_private_denylist_entries(new_set.len());

        // Purge-on-add: only the set difference (hashes newly present) —
        // re-purging the whole list every change would repeat the meta
        // scans for shas long gone. Removed hashes unblock reads with the
        // swap above; bytes already purged stay gone (re-upload required).
        let mut purged = 0_u64;
        for sha in new_set.difference(&old_set) {
            match gc::purge_blob(svc, sha, |_| true) {
                Ok(outcome) => {
                    if outcome.freed.is_some() || outcome.unlinked {
                        purged += 1;
                        tracing::info!(
                            sha256 = %sha,
                            freed = outcome.freed.is_some(),
                            "private denylist purge-on-add removed blob"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(sha256 = %sha, "private denylist purge-on-add failed: {e}")
                }
            }
        }
        if purged > 0 {
            crate::metrics::record_private_denylist_purged(purged);
            svc.refresh_gauges();
        }
    }
}

/// Spawn the periodic reload task. Returns `None` (no task) when reloading
/// is disabled (`NGIT_PRIVATE_DENYLIST_RELOAD_SECS=0`) or no denylist
/// files are configured.
pub(crate) fn spawn(svc: Arc<PrivateService>) -> Option<JoinHandle<()>> {
    let secs = svc.cfg.denylist_reload_secs;
    if svc.cfg.denylist_paths.is_empty() || secs == 0 {
        return None;
    }
    // NGIT_TEST=1 clamps the interval small (the mirror's repair-interval
    // idiom) so integration tests observe a reload within seconds.
    let interval_secs = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        secs.min(1)
    } else {
        secs
    };
    let mut files: Vec<FileState> = svc
        .cfg
        .denylist_paths
        .iter()
        .map(|p| FileState::new(p))
        .collect();
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        // First tick fires immediately; skip it so boot isn't a reload pass.
        interval.tick().await;
        loop {
            interval.tick().await;
            FileState::reload_once(&svc, &mut files);
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_contents_filters_and_normalizes() {
        let sha_a = "a".repeat(64);
        let sha_b = "B".repeat(64);
        let contents = format!(
            "# comment line\n\n  {sha_a}  \n{sha_b}\nnot-a-hash\n{}\n",
            "0".repeat(63)
        );
        let set = parse_contents(&contents).expect("parse");
        assert_eq!(set.len(), 2);
        assert!(set.contains(&sha_a));
        assert!(set.contains(&sha_b.to_lowercase()));
    }

    /// FS-6: the line cap rejects over-long files (each raw line would
    /// become a String before normalization filters it).
    #[test]
    fn parse_contents_enforces_line_cap() {
        let under = "x\n".repeat(MAX_LINES);
        assert!(
            parse_contents(&under).is_ok(),
            "exactly MAX_LINES garbage lines must parse (to an empty set)"
        );
        let over = "x\n".repeat(MAX_LINES + 1);
        assert!(
            parse_contents(&over).is_err(),
            "MAX_LINES + 1 lines must be rejected"
        );
    }

    /// FS-6: an over-byte-cap file is a HARD BOOT ERROR, and a reload
    /// keeps the file's last-known entries (same semantics as a
    /// present-but-unreadable file).
    #[test]
    fn over_cap_file_is_boot_fatal_and_reload_keeps_last_known() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.txt");
        let sha = "e".repeat(64);

        // Last-known good state.
        std::fs::write(&path, format!("{sha}\n")).unwrap();
        let mut f = FileState::new(&path.to_string_lossy());
        assert!(f.refresh());
        assert!(f.hashes.contains(&sha));

        // Grow past the byte cap (cap + 2 bytes), bumping the mtime so the
        // refresh re-reads even on coarse-mtime filesystems.
        std::fs::write(&path, vec![b'x'; MAX_FILE_BYTES as usize + 2]).unwrap();
        let bumped = f.mtime.unwrap() + Duration::from_secs(2);
        let file = std::fs::File::open(&path).unwrap();
        file.set_modified(bumped).unwrap();
        drop(file);

        // Boot fails loud.
        let err = load_boot(&[path.to_string_lossy().into_owned()])
            .expect_err("an over-cap file must fail boot");
        assert!(
            err.to_string().contains("failed to read private denylist"),
            "unexpected error: {err}"
        );

        // Reload keeps the last-known entries.
        assert!(
            !f.refresh(),
            "an over-cap reload must report no change (last-known kept)"
        );
        assert!(f.hashes.contains(&sha));
    }

    #[test]
    fn load_boot_missing_file_is_empty_but_present_unreadable_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.txt").to_string_lossy().into_owned();

        // Missing file → warn + empty (multi-file semantics).
        let set = load_boot(&[missing.clone()]).unwrap();
        assert!(set.is_empty());

        // Present + readable mixed with missing → union of the readable.
        let present = dir.path().join("present.txt");
        std::fs::write(&present, format!("{}\n", "c".repeat(64))).unwrap();
        let set = load_boot(&[missing, present.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(set.len(), 1);

        // Present but unreadable (a directory is not readable as a file) →
        // hard boot error regardless of uid (chmod-based unreadability is
        // bypassed by root).
        let dir_path = dir.path().join("as-dir");
        std::fs::create_dir(&dir_path).unwrap();
        let err = load_boot(&[dir_path.to_string_lossy().into_owned()])
            .expect_err("present-but-unreadable must fail boot");
        assert!(
            err.to_string().contains("failed to read private denylist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn refresh_detects_only_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.txt");
        let sha = "d".repeat(64);

        // Absent → present is a change.
        std::fs::write(&path, format!("{sha}\n")).unwrap();
        let mut f = FileState::new(&path.to_string_lossy());
        assert!(f.refresh());
        assert!(f.hashes.contains(&sha));
        // Same mtime → no change.
        assert!(!f.refresh());

        // Modify (bump mtime into the future so coarse-granularity
        // filesystems cannot alias the previous write).
        std::fs::write(&path, "").unwrap();
        let bumped = f.mtime.unwrap() + Duration::from_secs(2);
        let file = std::fs::File::open(&path).unwrap();
        file.set_modified(bumped).unwrap();
        drop(file);
        assert!(f.refresh());
        assert!(f.hashes.is_empty());

        // Repopulate, then remove: present-with-entries → absent is a
        // change; still-absent afterwards is not.
        std::fs::write(&path, format!("{sha}\n")).unwrap();
        let bumped = f.mtime.unwrap() + Duration::from_secs(2);
        let file = std::fs::File::open(&path).unwrap();
        file.set_modified(bumped).unwrap();
        drop(file);
        assert!(f.refresh());
        assert!(f.hashes.contains(&sha));
        std::fs::remove_file(&path).unwrap();
        assert!(f.refresh());
        assert!(f.hashes.is_empty());
        assert!(!f.refresh());
    }
}
