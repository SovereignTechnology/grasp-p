//! Startup recovery for the GRASP-06 `/prs/` subtree.
//!
//! The inline cleanup paths in [`crate::grasp06::receive`],
//! [`crate::nostr::policy::pr_event`], and [`crate::purgatory::Purgatory::cleanup`]
//! remove `/prs/<submitter>/<identifier>.git` directories the moment they
//! go zero-ref while the process is running. They cannot, however, deal
//! with directories left zero-ref by a previous run:
//!
//! - A crash between writing a ref and the end-of-push cleanup.
//! - A crash between [`crate::git::delete_ref`] and `remove_dir_all` in
//!   one of the off-push cleanup paths.
//! - A clean shutdown with a scoped placeholder still in memory whose
//!   matching event then never arrives in the next run, after the
//!   purgatory state has been dropped or aged out.
//!
//! Without recovery the bare directory and any dangling refs persist
//! indefinitely. The standalone `cleanup-empty-repos` CLI tool
//! explicitly skips `/prs/` (see
//! [`crate::grasp06::paths::is_prs_repo_path`]) because its event-driven
//! model does not apply, so there is no operational lifeline either.
//!
//! [`scan_on_startup`] walks `<git_data_path>/prs/<hex>/<id>.git` once,
//! before the HTTP server starts accepting requests, and removes any
//! bare repository with zero refs. At startup nothing is in flight, so
//! the [`PrsPathState`] mutex and `in_flight` counter are unnecessary —
//! a direct filesystem scan is safe and the same `list_refs` /
//! `remove_dir_all` shape the runtime cleanup paths use applies.
//!
//! Empty `<hex>/` parent directories are removed too so `/prs/` does not
//! accumulate submitter dirs over time.
//!
//! [`PrsPathState`]: crate::grasp06::receive::PrsPathState

use std::path::Path;

use nostr_sdk::prelude::*;
use tracing::{debug, info, warn};

use crate::git::list_refs;
use crate::grasp06::paths::prs_base_path;

/// Walk `<git_data_path>/prs/` once and remove any bare repository
/// directory with zero refs, plus any submitter directory left empty as
/// a result. Returns `(repos_removed, submitter_dirs_removed)`.
///
/// Must be called *before* the HTTP server starts accepting requests —
/// the scan does no locking and assumes no concurrent writers to the
/// `/prs/` subtree.
pub fn scan_on_startup(git_data_path: &Path) -> (usize, usize) {
    let base = prs_base_path(git_data_path);
    let hex_entries = match std::fs::read_dir(&base) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, 0),
        Err(e) => {
            warn!(
                "/prs/ startup scan: failed to read {}: {}",
                base.display(),
                e
            );
            return (0, 0);
        }
    };

    let mut repos_removed = 0usize;
    let mut submitter_dirs_removed = 0usize;

    for hex_entry in hex_entries.flatten() {
        let hex_path = hex_entry.path();
        if !hex_path.is_dir() {
            continue;
        }
        let submitter_hex = hex_entry.file_name().to_string_lossy().into_owned();
        if PublicKey::from_hex(&submitter_hex).is_err() {
            // Skip directories whose name is not a valid pubkey — these
            // shouldn't exist under /prs/, but we don't want to delete
            // something we don't recognise.
            debug!(
                "/prs/ startup scan: skipping non-hex entry {}",
                hex_path.display()
            );
            continue;
        }

        let id_entries = match std::fs::read_dir(&hex_path) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(
                    "/prs/ startup scan: failed to read {}: {}",
                    hex_path.display(),
                    e
                );
                continue;
            }
        };

        for id_entry in id_entries.flatten() {
            let repo_path = id_entry.path();
            if !repo_path.is_dir() {
                continue;
            }
            // Must end in `.git` to match the on-disk shape produced by
            // `prs_repo_path` — anything else is suspicious; leave it
            // alone.
            if repo_path
                .file_name()
                .and_then(|s| s.to_str())
                .is_none_or(|s| !s.ends_with(".git"))
            {
                continue;
            }

            match list_refs(&repo_path) {
                // Signed history still owed to the family outlives its refs.
                Ok(refs) if refs.is_empty() && crate::git::staging::owes_history(&repo_path) => {}
                Ok(refs) if refs.is_empty() => {
                    if let Err(e) = std::fs::remove_dir_all(&repo_path) {
                        warn!(
                            "/prs/ startup scan: failed to remove zero-ref repo {}: {}",
                            repo_path.display(),
                            e
                        );
                    } else {
                        debug!(
                            "/prs/ startup scan: removed zero-ref repo {}",
                            repo_path.display()
                        );
                        repos_removed += 1;
                    }
                }
                Ok(_) => {
                    // Has refs — leave alone.
                }
                Err(e) => {
                    warn!(
                        "/prs/ startup scan: list_refs failed for {}: {}",
                        repo_path.display(),
                        e
                    );
                }
            }
        }

        // If we just emptied this submitter dir, drop it. `remove_dir`
        // fails if non-empty so we don't need an explicit check.
        if std::fs::remove_dir(&hex_path).is_ok() {
            debug!(
                "/prs/ startup scan: removed empty submitter dir {}",
                hex_path.display()
            );
            submitter_dirs_removed += 1;
        }
    }

    if repos_removed > 0 || submitter_dirs_removed > 0 {
        info!(
            "/prs/ startup scan: removed {} zero-ref repo(s) and {} empty submitter dir(s)",
            repos_removed, submitter_dirs_removed
        );
    } else {
        debug!("/prs/ startup scan: nothing to clean up");
    }

    (repos_removed, submitter_dirs_removed)
}
