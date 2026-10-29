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
//! - **Multi-file**: `NGIT_GRASP_P_DENYLIST_PATH` is a comma-separated list
//!   of files (per-node / per-jurisdiction lists). A file MISSING AT BOOT is
//!   tolerated (warn + treated as empty); a present-but-unreadable file is
//!   a hard boot error (fail loud on misconfig). During reload a file that
//!   is unreadable, no longer parses, or has disappeared keeps its
//!   last-known entries, logs an error and is retried every tick (decision
//!   D11): an unmounted volume or a deploy that deletes before it writes
//!   must not lift takedowns. A takedown is lifted only by a readable file
//!   that no longer lists the hash. A file that had entries and is read
//!   back empty keeps them too, as a deploy that truncates before it writes
//!   leaves it for a moment; to clear a list on purpose, leave a comment
//!   line in it. The reload starts from what the boot load read, file by
//!   file, so "last-known" includes the entries a file had at boot.
//! - **Atomic swap**: the live set sits behind an `RwLock`; a reload
//!   builds the new union off-lock and swaps it in one write critical
//!   section. Reads (GET/HEAD 451, upload preflight, finish() race
//!   re-check, mirror skip sites) take the read lock only.
//! - **Purge-on-add**: hashes NEWLY present after a reload are purged
//!   immediately via [`gc::purge_blob`] — the same meta-`with_write`
//!   primitive GC uses — freeing every claim (releasing ledger charges per
//!   the established discipline) and unlinking the bytes. The swap happens
//!   BEFORE the purge so the mirror's skip sites (which consult
//!   `is_denylisted`) can never re-enqueue a blob that is about to be
//!   purged, and reads start returning 451 immediately.
//! - **Removal**: a hash dropped from the files unblocks reads on the next
//!   swap; bytes already purged stay gone (a client re-upload is required).
//! - **File caps (FS-6)**: each file is limited to 64 MiB / 1M lines —
//!   over-cap is a hard boot error, and on reload the file keeps its
//!   last-known entries (error logged, retried every tick). Writers MUST
//!   update files atomically (write-temp-then-rename): the reload keys off
//!   mtime and length, and a torn write that is read half-written is a
//!   known staleness window (L1-F7).

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
///
/// Returns one state per configured file, in order. Their [`union`] is the
/// set the node enforces from boot, and the states themselves are what the
/// periodic reload starts from ([`spawn`]): a reload that began from empty
/// states forgot the boot entries of any file it could not read again.
pub(crate) fn load_boot(paths: &[String]) -> Result<Vec<FileState>> {
    paths
        .iter()
        .map(|path| FileState::load_boot(path))
        .collect()
}

/// Every hash listed by any of `files`: the set the node enforces.
pub(crate) fn union(files: &[FileState]) -> HashSet<String> {
    files
        .iter()
        .flat_map(|file| file.hashes.iter().cloned())
        .collect()
}

/// The file's length, `None` when it cannot be read. Compared with the
/// time: a rewrite on a filesystem with coarse times can keep the time of
/// a torn read, and would otherwise not be read again until the next one.
fn file_len(path: &str) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

/// The file's modification time. `Ok(None)` when the file does not exist.
fn modified_time(path: &str) -> std::io::Result<Option<SystemTime>> {
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => Ok(Some(mtime)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Per-file reload state: the last observed mtime and the last parsed set,
/// so a tick only re-reads files that actually changed.
#[derive(Debug)]
pub(crate) struct FileState {
    path: String,
    mtime: Option<SystemTime>,
    len: Option<u64>,
    hashes: HashSet<String>,
}

impl FileState {
    /// A state that has read nothing yet.
    #[cfg(test)]
    fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            mtime: None,
            len: None,
            hashes: HashSet::new(),
        }
    }

    /// Read one file at boot (see [`load_boot`] for what fails the boot).
    fn load_boot(path: &str) -> Result<Self> {
        // Taken before the read: if the file is rewritten between the two,
        // the first reload sees a newer time and reads it again. Taken
        // after, that rewrite would be missed until the next one. A time
        // that cannot be read is treated as unknown, which also makes the
        // first reload read the file again.
        let mtime = modified_time(path).ok().flatten();
        let len = file_len(path);
        match read_file_capped(path) {
            Ok(contents) => Ok(Self {
                path: path.to_string(),
                mtime,
                len,
                hashes: parse_contents(&contents)
                    .with_context(|| format!("failed to parse private denylist at {path}"))?,
            }),
            // Missing at boot: tolerated, since a jurisdiction's list may
            // simply not be mounted on this node. Unlike a file that
            // disappears later, there are no entries to keep.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!("private denylist file {path} not found; treating it as empty");
                Ok(Self {
                    path: path.to_string(),
                    mtime: None,
                    len: None,
                    hashes: HashSet::new(),
                })
            }
            Err(e) => Err(e).with_context(|| format!("failed to read private denylist at {path}")),
        }
    }

    /// Re-stat + re-read when the file changed since the last call.
    /// Returns true when the parsed set may have changed.
    fn refresh(&mut self) -> bool {
        let mtime = match modified_time(&self.path) {
            Ok(mtime) => mtime,
            Err(e) => {
                // The file may well be there, but it cannot be inspected
                // (a directory in its path lost its permissions, say). Same
                // rule as a file that cannot be read: keep, and retry.
                tracing::error!(
                    "private denylist file {} cannot be inspected ({e}); \
                     keeping last-known entries",
                    self.path
                );
                return false;
            }
        };
        let len = file_len(&self.path);
        if mtime == self.mtime && len == self.len {
            return false;
        }
        match read_file_capped(&self.path) {
            Ok(contents) if contents.trim().is_empty() && !self.hashes.is_empty() => {
                // Decision D11: a list that had entries and reads back empty
                // is most likely a deploy that truncated before it wrote,
                // read in between; keep the entries and look again next
                // tick. A list is cleared on purpose by leaving a comment
                // line in it.
                tracing::error!(
                    "private denylist file {} is empty; keeping last-known entries \
                     (leave a comment line in it to clear it)",
                    self.path
                );
                false
            }
            Ok(contents) => match parse_contents(&contents) {
                Ok(hashes) => {
                    self.mtime = mtime;
                    self.len = len;
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
            // Decision D11: a file that disappeared keeps its last-known
            // entries, like one that cannot be read, so an unmounted volume
            // or a non-atomic deploy lifts no takedown. The time is not
            // advanced, so the error repeats every tick until the file is
            // back; a file that was never there has no time and never gets
            // this far.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::error!(
                    "private denylist file {} has disappeared; keeping last-known entries",
                    self.path
                );
                false
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
        let Some(new_set) = refresh_all(files) else {
            return;
        };
        // Swap BEFORE purging: reads 451 immediately, and the mirror skip
        // sites (which consult is_denylisted) can never re-enqueue a blob
        // that is about to be purged. The repair scan, which sets the lag
        // gauge, likewise excludes denylisted shas, and the purge deletes
        // the claims outright, so purged blobs leave
        // ngit_private_mirror_lag_blobs at the next scan.
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

/// Refresh every file, and return the new union when any of them may have
/// changed. A file that could not be read or parsed, or has disappeared,
/// keeps the entries it had, so they are in the union whatever happened to
/// the other files.
///
/// Kept apart from the swap and the purge so that the rule can be tested
/// without a service or a timer.
fn refresh_all(files: &mut [FileState]) -> Option<HashSet<String>> {
    let mut any_change = false;
    for file in files.iter_mut() {
        any_change |= file.refresh();
    }
    if any_change {
        Some(union(files))
    } else {
        None
    }
}

/// Spawn the periodic reload task. Returns `None` (no task) when reloading
/// is disabled (`NGIT_GRASP_P_DENYLIST_RELOAD_SECS=0`) or no denylist
/// files are configured.
///
/// The task starts from the per-file states of the boot load, which it
/// takes from the service. With reloading disabled they are dropped here:
/// the live set already holds every entry.
pub(crate) fn spawn(svc: Arc<PrivateService>) -> Option<JoinHandle<()>> {
    let boot_files = svc.take_denylist_boot_files();
    let secs = svc.cfg.denylist_reload_secs;
    if svc.cfg.denylist_paths.is_empty() || secs == 0 {
        return None;
    }
    let Some(mut files) = boot_files else {
        // A second reload task would have to start from empty states and
        // would drop the boot entries of a file it cannot read.
        tracing::error!("private denylist reload was already started; not starting another");
        return None;
    };
    // NGIT_TEST=1 clamps the interval small (the mirror's repair-interval
    // idiom) so integration tests observe a reload within seconds.
    let interval_secs = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        secs.min(1)
    } else {
        secs
    };
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
        let set = union(&load_boot(std::slice::from_ref(&missing)).unwrap());
        assert!(set.is_empty());

        // Present + readable mixed with missing → union of the readable.
        let present = dir.path().join("present.txt");
        std::fs::write(&present, format!("{}\n", "c".repeat(64))).unwrap();
        let set = union(&load_boot(&[missing, present.to_string_lossy().into_owned()]).unwrap());
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
        // filesystems cannot alias the previous write). A comment line
        // clears the list; an empty file would keep it (D11).
        std::fs::write(&path, "# cleared\n").unwrap();
        let bumped = f.mtime.unwrap() + Duration::from_secs(2);
        let file = std::fs::File::open(&path).unwrap();
        file.set_modified(bumped).unwrap();
        drop(file);
        assert!(f.refresh());
        assert!(f.hashes.is_empty());

        // Repopulate, then remove: the entries are kept (D11), and so is
        // the time, so the file is looked for again every tick.
        std::fs::write(&path, format!("{sha}\n")).unwrap();
        let bumped = f.mtime.unwrap() + Duration::from_secs(2);
        let file = std::fs::File::open(&path).unwrap();
        file.set_modified(bumped).unwrap();
        drop(file);
        assert!(f.refresh());
        assert!(f.hashes.contains(&sha));
        std::fs::remove_file(&path).unwrap();
        assert!(!f.refresh());
        assert!(f.hashes.contains(&sha));
        assert!(f.mtime.is_some());
    }

    /// Write `contents` and move the file's time forward, so that a refresh
    /// sees a change even where the filesystem keeps coarse times.
    fn rewrite(path: &std::path::Path, contents: &str, previous: Option<SystemTime>) {
        std::fs::write(path, contents).unwrap();
        let base = previous.unwrap_or_else(SystemTime::now);
        let file = std::fs::File::open(path).unwrap();
        file.set_modified(base + Duration::from_secs(2)).unwrap();
    }

    fn path_string(path: &std::path::Path) -> String {
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn load_boot_seeds_per_file_state() {
        let dir = tempfile::tempdir().unwrap();
        let (sha_a, sha_b) = ("a".repeat(64), "b".repeat(64));
        let path_a = dir.path().join("a.txt");
        let path_b = dir.path().join("b.txt");
        let missing = dir.path().join("absent.txt");
        std::fs::write(&path_a, format!("{sha_a}\n")).unwrap();
        std::fs::write(&path_b, format!("{sha_b}\n# note\n")).unwrap();

        let files = load_boot(&[
            path_string(&path_a),
            path_string(&missing),
            path_string(&path_b),
        ])
        .unwrap();

        assert_eq!(files.len(), 3, "one state per configured file, in order");
        assert_eq!(files[0].hashes, HashSet::from([sha_a.clone()]));
        assert!(files[0].mtime.is_some(), "a file that was read has a time");
        assert!(files[1].hashes.is_empty());
        assert!(files[1].mtime.is_none(), "a missing file has none");
        assert_eq!(files[2].hashes, HashSet::from([sha_b.clone()]));
        assert_eq!(union(&files), HashSet::from([sha_a, sha_b]));
    }

    #[test]
    fn first_reload_after_boot_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.txt");
        let missing = dir.path().join("absent.txt");
        std::fs::write(&path, format!("{}\n", "a".repeat(64))).unwrap();

        let mut files = load_boot(&[path_string(&path), path_string(&missing)]).unwrap();
        let boot = union(&files);

        assert!(
            refresh_all(&mut files).is_none(),
            "nothing changed on disk, so the first reload must not swap the set"
        );
        assert_eq!(union(&files), boot);
    }

    /// The fault this pins: the reload used to start from empty states, so
    /// a file it could not read again had no entries to keep, and the next
    /// change to any other file swapped in a set without them.
    #[test]
    fn reload_keeps_boot_entries_of_file_that_became_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let (sha_a, sha_a2, sha_b) = ("a".repeat(64), "c".repeat(64), "b".repeat(64));
        let path_a = dir.path().join("a.txt");
        let path_b = dir.path().join("b.txt");
        std::fs::write(&path_a, format!("{sha_a}\n")).unwrap();
        std::fs::write(&path_b, format!("{sha_b}\n")).unwrap();
        let mut files = load_boot(&[path_string(&path_a), path_string(&path_b)]).unwrap();

        // B can no longer be read as a file (a directory in its place fails
        // for root too, which a permission change would not), and A gains
        // an entry.
        std::fs::remove_file(&path_b).unwrap();
        std::fs::create_dir(&path_b).unwrap();
        rewrite(&path_a, &format!("{sha_a}\n{sha_a2}\n"), files[0].mtime);

        let reloaded = refresh_all(&mut files).expect("A changed, so the set is rebuilt");
        assert_eq!(
            reloaded,
            HashSet::from([sha_a, sha_a2, sha_b.clone()]),
            "B's boot entries must survive a reload that could not read B"
        );
        assert!(
            refresh_all(&mut files).is_none(),
            "and nothing changes while B stays unreadable"
        );
        assert!(files[1].hashes.contains(&sha_b));
    }

    #[test]
    fn reload_keeps_boot_entries_when_file_stops_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let (sha_a, sha_a2, sha_b, sha_b2) = (
            "a".repeat(64),
            "c".repeat(64),
            "b".repeat(64),
            "d".repeat(64),
        );
        let path_a = dir.path().join("a.txt");
        let path_b = dir.path().join("b.txt");
        std::fs::write(&path_a, format!("{sha_a}\n")).unwrap();
        std::fs::write(&path_b, format!("{sha_b}\n")).unwrap();
        let mut files = load_boot(&[path_string(&path_a), path_string(&path_b)]).unwrap();

        // B grows past the line cap, which is the one way a file that can
        // be read fails to parse. A gains an entry.
        rewrite(&path_b, &"x\n".repeat(MAX_LINES + 1), files[1].mtime);
        rewrite(&path_a, &format!("{sha_a}\n{sha_a2}\n"), files[0].mtime);

        let reloaded = refresh_all(&mut files).expect("A changed, so the set is rebuilt");
        assert_eq!(
            reloaded,
            HashSet::from([sha_a.clone(), sha_a2.clone(), sha_b]),
            "B's boot entries must survive a reload that could not parse B"
        );

        // Once B parses again its new contents replace the kept ones. The
        // time B was last read with is still the boot one, so the base for
        // the new time is taken from the file itself.
        let unparsable = modified_time(&path_string(&path_b)).unwrap();
        rewrite(&path_b, &format!("{sha_b2}\n"), unparsable);
        assert_eq!(
            refresh_all(&mut files),
            Some(HashSet::from([sha_a, sha_a2, sha_b2]))
        );
    }

    /// Decision D11: a file that disappears keeps its takedowns, also when
    /// another file changes and the set is rebuilt, until a readable file
    /// stops listing them. Without this an unmounted volume lifted every
    /// takedown in it within one reload interval.
    #[test]
    fn a_file_that_disappears_keeps_its_entries_until_a_readable_file_drops_them() {
        let dir = tempfile::tempdir().unwrap();
        let (sha_a, sha_b, sha_b2) = ("a".repeat(64), "b".repeat(64), "d".repeat(64));
        let path_a = dir.path().join("a.txt");
        let path_b = dir.path().join("b.txt");
        std::fs::write(&path_a, format!("{sha_a}\n")).unwrap();
        std::fs::write(&path_b, format!("{sha_b}\n")).unwrap();
        let mut files = load_boot(&[path_string(&path_a), path_string(&path_b)]).unwrap();

        std::fs::remove_file(&path_a).unwrap();
        assert!(
            refresh_all(&mut files).is_none(),
            "a disappearance alone changes nothing"
        );
        rewrite(&path_b, &format!("{sha_b}\n{sha_b2}\n"), files[1].mtime);
        assert_eq!(
            refresh_all(&mut files),
            Some(HashSet::from([
                sha_a.clone(),
                sha_b.clone(),
                sha_b2.clone()
            ])),
            "A's entries survive a rebuild while A is gone"
        );

        // A comes back without its hash: the takedown is lifted now.
        rewrite(&path_a, "# lifted\n", files[0].mtime);
        assert_eq!(
            refresh_all(&mut files),
            Some(HashSet::from([sha_b, sha_b2]))
        );
    }

    /// Decision D11 against a deploy that truncates before it writes: a list
    /// read back empty keeps its entries, and the rewrite is read even when
    /// it keeps the time of the torn read, as a filesystem with coarse times
    /// can; without the length that read would stay in force until the next
    /// change. A comment line clears a list on purpose.
    #[test]
    fn an_emptied_file_keeps_its_entries_and_a_rewrite_at_the_same_time_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.txt");
        let (sha, sha2) = ("a".repeat(64), "b".repeat(64));
        std::fs::write(&path, format!("{sha}\n")).unwrap();
        let mut files = load_boot(&[path_string(&path)]).unwrap();
        let time = files[0].mtime.expect("read at boot");

        rewrite(&path, "", Some(time));
        assert!(
            refresh_all(&mut files).is_none(),
            "an emptied file keeps its entries"
        );
        assert_eq!(union(&files), HashSet::from([sha.clone()]));

        std::fs::write(&path, format!("{sha}\n{sha2}\n")).unwrap();
        std::fs::File::open(&path)
            .unwrap()
            .set_modified(time)
            .unwrap();
        assert_eq!(
            refresh_all(&mut files),
            Some(HashSet::from([sha.clone(), sha2.clone()])),
            "same time, new length: read again"
        );

        rewrite(&path, "# cleared\n", files[0].mtime);
        assert_eq!(refresh_all(&mut files), Some(HashSet::new()));
    }

    /// A file missing at boot is still tolerated, and a later appearance
    /// is read like any change.
    #[test]
    fn a_file_missing_at_boot_is_tolerated_and_read_when_it_appears() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("late.txt");
        let mut files = load_boot(&[path_string(&path)]).unwrap();
        assert!(union(&files).is_empty());
        assert!(
            refresh_all(&mut files).is_none(),
            "still missing: no change"
        );

        let sha = "e".repeat(64);
        std::fs::write(&path, format!("{sha}\n")).unwrap();
        assert_eq!(refresh_all(&mut files), Some(HashSet::from([sha])));
    }
}
