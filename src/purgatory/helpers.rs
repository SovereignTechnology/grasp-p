//! Helper functions for purgatory state event processing.
//!
//! These functions handle the late-binding extraction and matching of git refs
//! from state events. Refs are extracted at git push time rather than event
//! arrival time to enable flexible matching logic.
//!
//! ## Key Functions
//!
//! - [`can_satisfy_state`]: Used for **push authorization** - checks if a push
//!   would transform the current refs into the declared state. This validates
//!   that the pushed refspecs match what the state event declares.
//!
//! - [`can_apply_state`]: Used for **purgatory processing** - checks if we have
//!   all the git OIDs needed to apply a state event. This validates that the
//!   git data is available locally, regardless of current ref state.

use super::{RefPair, RefUpdate};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::path::Path;

use crate::git::oid_exists;

/// Extract ref pairs from a state event (kind 30618).
///
/// Parses all `refs/heads/*` and `refs/tags/*` tags from the event,
/// creating RefPair instances with the full ref name and target object SHA.
///
/// # Arguments
/// * `event` - The state event to extract refs from
///
/// # Returns
/// Vector of RefPair instances, one for each ref tag found
///
/// # Tag Format
/// State events use custom tags where the tag kind is the ref name:
/// - Tag kind: "refs/heads/main" or "refs/tags/v1.0"
/// - First value: commit SHA or annotated tag SHA
///
/// # Example
/// ```ignore
/// // Event with tags:
/// // ["refs/heads/main", "abc123..."]
/// // ["refs/tags/v1.0", "def456..."]
/// let refs = extract_refs_from_state(&event);
/// // Returns: [
/// //   RefPair { ref_name: "refs/heads/main", object_sha: "abc123..." },
/// //   RefPair { ref_name: "refs/tags/v1.0", object_sha: "def456..." }
/// // ]
/// ```
pub fn extract_refs_from_state(event: &Event) -> Vec<RefPair> {
    event
        .tags
        .iter()
        .filter_map(|tag| {
            // Check if this is a custom tag with a ref name.
            // In nostr 0.45 `tag.kind()` returns the raw tag-name string for
            // all tags, so we match on the string directly. The downstream
            // `refs/heads/*` / `refs/tags/*` filter preserves the previous
            // behaviour (which only matched non-standardized custom kinds).
            {
                let ref_str: &str = tag.kind();

                // Only process refs/heads/* and refs/tags/*
                // Exclude peeled tag notation (e.g. "refs/tags/v1.0.0^{}") — these are
                // git's internal dereference markers, not real refs that get pushed.
                if (ref_str.starts_with("refs/heads/") || ref_str.starts_with("refs/tags/"))
                    && !ref_str.ends_with("^{}")
                {
                    // Get the object SHA (first value in tag)
                    let parts = tag.clone().to_vec();
                    if parts.len() >= 2 {
                        return Some(RefPair {
                            ref_name: ref_str.to_string(),
                            object_sha: parts[1].clone(),
                        });
                    }
                }
            }
            None
        })
        .collect()
}

/// Check if a state event can be applied given the available git data.
///
/// This is used for **purgatory processing** to determine if we have all the
/// git objects needed to apply a state event. Unlike `can_satisfy_state` which
/// validates push authorization, this function only checks OID availability.
///
/// Returns true if all OIDs referenced in the state event exist in the repository.
/// Symbolic refs (starting with "ref: ") are skipped as they don't require OID lookup.
///
/// # Arguments
/// * `event` - The state event to check
/// * `repo_path` - Path to the git repository to check OIDs against
///
/// # Returns
/// true if all required OIDs exist in the repository, false otherwise
///
/// # Example
/// ```ignore
/// // State event declares:
/// //   refs/heads/main -> abc123
/// //   refs/heads/dev -> def456
/// //   refs/heads/symlink -> ref: refs/heads/main (symbolic)
/// //
/// // If abc123 and def456 exist in repo: returns true
/// // If abc123 exists but def456 doesn't: returns false
/// // The symbolic ref doesn't require an OID check
/// ```
pub fn can_apply_state(event: &Event, repo_path: &Path) -> bool {
    let state_refs = extract_refs_from_state(event);

    for ref_pair in state_refs {
        // Skip symbolic refs (they don't require OID lookup)
        if ref_pair.object_sha.starts_with("ref: ") {
            continue;
        }

        // Check if the OID exists in the repository
        if !oid_exists(repo_path, &ref_pair.object_sha) {
            return false;
        }
    }

    true
}

/// Check if a state event can be satisfied by ref updates plus local refs.
///
/// This is used for **push authorization** to validate that a push would
/// transform the current refs into the declared state.
///
/// Returns true if applying the ref updates to local state results in exactly
/// the state declared in the event. This means:
/// 1. Filter local_refs to only branches (refs/heads/*) and tags (refs/tags/*)
/// 2. Apply pushed_updates to create a "would-be" state
/// 3. Compare would-be state with event's declared state - must match exactly
///
/// This implements correct authorization: the push must transform local state
/// into the declared state, accounting for additions, deletions, and modifications.
///
/// # Arguments
/// * `event` - The state event to check
/// * `pushed_updates` - Ref updates in the current push operation
/// * `local_refs` - Refs already existing locally (ref_name -> SHA)
///
/// # Returns
/// true if push transforms local state into declared state, false otherwise
///
/// # Example
/// ```ignore
/// // State event declares: refs/heads/main@abc123
/// // Local: refs/heads/main@old123, refs/heads/dev@def456
/// // Push updates: main old123->abc123, dev def456->0000 (delete)
/// // Result: false (event doesn't declare dev deletion)
/// ```
pub fn can_satisfy_state(
    event: &Event,
    pushed_updates: &[RefUpdate],
    local_refs: &HashMap<String, String>,
) -> bool {
    let state_refs = extract_refs_from_state(event);

    // Filter local_refs to only branches and tags
    let mut would_be_state: HashMap<String, String> = local_refs
        .iter()
        .filter(|(ref_name, _)| {
            ref_name.starts_with("refs/heads/") || ref_name.starts_with("refs/tags/")
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Apply all pushed updates to create the would-be state
    for update in pushed_updates {
        // Only process branches and tags
        if !update.ref_name.starts_with("refs/heads/") && !update.ref_name.starts_with("refs/tags/")
        {
            continue;
        }

        if update.is_deletion() {
            // Remove from would-be state
            would_be_state.remove(&update.ref_name);
        } else {
            // Create or modify in would-be state
            would_be_state.insert(update.ref_name.clone(), update.new_oid.clone());
        }
    }

    // Convert event's state refs to a HashMap for comparison
    let declared_state: HashMap<String, String> = state_refs
        .into_iter()
        .map(|r| (r.ref_name, r.object_sha))
        .collect();

    // would_be_state must exactly match declared_state
    would_be_state == declared_state
}

/// Get refs from state event that aren't in pushed_refs.
///
/// Returns refs that need to be present but aren't being pushed.
/// These refs should exist in local_refs for the state to be satisfiable.
/// Useful for error messages showing what's missing.
///
/// # Arguments
/// * `event` - The state event to check
/// * `pushed_refs` - Refs being pushed in the current operation
///
/// # Returns
/// Vector of RefPair instances for refs not in pushed_refs
///
/// # Example
/// ```ignore
/// // State event declares: refs/heads/main@abc123, refs/heads/dev@def456
/// // Pushed: refs/heads/main@abc123
/// // Result: [RefPair { ref_name: "refs/heads/dev", object_sha: "def456" }]
/// ```
pub fn get_unpushed_refs(event: &Event, pushed_refs: &[RefPair]) -> Vec<RefPair> {
    let state_refs = extract_refs_from_state(event);

    state_refs
        .into_iter()
        .filter(|state_ref| {
            // Include if NOT in pushed_refs (by name and SHA)
            !pushed_refs.iter().any(|pushed_ref| {
                pushed_ref.ref_name == state_ref.ref_name
                    && pushed_ref.object_sha == state_ref.object_sha
            })
        })
        .collect()
}

/// Diagnose why a state event doesn't match the push.
///
/// Returns a human-readable explanation of the mismatch between the state event
/// and what would result from applying the push to local refs.
///
/// # Arguments
/// * `event` - The state event to check
/// * `pushed_updates` - Ref updates in the current push operation
/// * `local_refs` - Refs already existing locally (ref_name -> SHA)
///
/// # Returns
/// String explaining why the state doesn't match, or None if it matches
pub fn diagnose_state_mismatch(
    event: &Event,
    pushed_updates: &[RefUpdate],
    local_refs: &HashMap<String, String>,
) -> Option<String> {
    let state_refs = extract_refs_from_state(event);

    // Filter local_refs to only branches and tags
    let mut would_be_state: HashMap<String, String> = local_refs
        .iter()
        .filter(|(ref_name, _)| {
            ref_name.starts_with("refs/heads/") || ref_name.starts_with("refs/tags/")
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Apply all pushed updates to create the would-be state
    for update in pushed_updates {
        // Only process branches and tags
        if !update.ref_name.starts_with("refs/heads/") && !update.ref_name.starts_with("refs/tags/")
        {
            continue;
        }

        if update.is_deletion() {
            would_be_state.remove(&update.ref_name);
        } else {
            would_be_state.insert(update.ref_name.clone(), update.new_oid.clone());
        }
    }

    // Convert event's state refs to a HashMap for comparison
    let declared_state: HashMap<String, String> = state_refs
        .into_iter()
        .map(|r| (r.ref_name, r.object_sha))
        .collect();

    // Check if they match
    if would_be_state == declared_state {
        return None; // No mismatch
    }

    // Build diagnostic message
    let mut reasons = Vec::new();

    // Check for refs in declared state but not in would-be state
    for (ref_name, declared_sha) in &declared_state {
        if let Some(would_be_sha) = would_be_state.get(ref_name) {
            if would_be_sha != declared_sha {
                let would_be_short = if would_be_sha.len() >= 8 {
                    &would_be_sha[..8]
                } else {
                    would_be_sha.as_str()
                };
                let declared_short = if declared_sha.len() >= 8 {
                    &declared_sha[..8]
                } else {
                    declared_sha.as_str()
                };
                reasons.push(format!(
                    "{} would be at {} but state declares {}",
                    ref_name, would_be_short, declared_short
                ));
            }
        } else {
            let declared_short = if declared_sha.len() >= 8 {
                &declared_sha[..8]
            } else {
                declared_sha.as_str()
            };
            reasons.push(format!(
                "{} missing (state declares {})",
                ref_name, declared_short
            ));
        }
    }

    // Check for refs in would-be state but not in declared state
    for (ref_name, would_be_sha) in &would_be_state {
        if !declared_state.contains_key(ref_name) {
            let would_be_short = if would_be_sha.len() >= 8 {
                &would_be_sha[..8]
            } else {
                would_be_sha.as_str()
            };
            reasons.push(format!(
                "{} would exist at {} but state doesn't declare it",
                ref_name, would_be_short
            ));
        }
    }

    if reasons.is_empty() {
        Some("Unknown mismatch".to_string())
    } else {
        Some(reasons.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Tag};

    fn create_test_state_event(identifier: &str, refs: Vec<(&str, &str)>) -> Event {
        let keys = Keys::generate();
        let mut tags = vec![Tag::custom("d", vec![identifier.to_string()])];

        for (ref_name, sha) in refs {
            tags.push(Tag::custom(ref_name, vec![sha.to_string()]));
        }

        EventBuilder::new(Kind::from(30618), "")
            .tags(tags)
            .finalize(&keys)
            .unwrap()
    }

    #[test]
    fn test_extract_refs_from_state() {
        let event = create_test_state_event(
            "test-repo",
            vec![
                ("refs/heads/main", "abc123"),
                ("refs/heads/dev", "def456"),
                ("refs/tags/v1.0", "789xyz"),
            ],
        );

        let refs = extract_refs_from_state(&event);

        assert_eq!(refs.len(), 3);
        assert!(refs
            .iter()
            .any(|r| r.ref_name == "refs/heads/main" && r.object_sha == "abc123"));
        assert!(refs
            .iter()
            .any(|r| r.ref_name == "refs/heads/dev" && r.object_sha == "def456"));
        assert!(refs
            .iter()
            .any(|r| r.ref_name == "refs/tags/v1.0" && r.object_sha == "789xyz"));
    }

    #[test]
    fn test_extract_refs_ignores_non_ref_tags() {
        let keys = Keys::generate();
        let tags = vec![
            Tag::custom("d", vec!["test-repo".to_string()]),
            Tag::custom("refs/heads/main", vec!["abc123".to_string()]),
            Tag::custom("some-other-tag", vec!["value".to_string()]),
        ];

        let event = EventBuilder::new(Kind::from(30618), "")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let refs = extract_refs_from_state(&event);

        // Should only extract the refs/heads/main tag
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].ref_name, "refs/heads/main");
    }

    #[test]
    fn test_can_satisfy_state_all_in_pushed() {
        let event = create_test_state_event(
            "test-repo",
            vec![("refs/heads/main", "abc123"), ("refs/heads/dev", "def456")],
        );

        let pushed_updates = vec![
            RefUpdate {
                old_oid: "0000000000000000000000000000000000000000".to_string(),
                new_oid: "abc123".to_string(),
                ref_name: "refs/heads/main".to_string(),
            },
            RefUpdate {
                old_oid: "0000000000000000000000000000000000000000".to_string(),
                new_oid: "def456".to_string(),
                ref_name: "refs/heads/dev".to_string(),
            },
        ];

        let local_refs = HashMap::new();

        assert!(can_satisfy_state(&event, &pushed_updates, &local_refs));
    }

    #[test]
    fn test_can_satisfy_state_split_between_pushed_and_local() {
        let event = create_test_state_event(
            "test-repo",
            vec![("refs/heads/main", "abc123"), ("refs/heads/dev", "def456")],
        );

        let pushed_updates = vec![RefUpdate {
            old_oid: "0000000000000000000000000000000000000000".to_string(),
            new_oid: "abc123".to_string(),
            ref_name: "refs/heads/main".to_string(),
        }];

        let mut local_refs = HashMap::new();
        local_refs.insert("refs/heads/dev".to_string(), "def456".to_string());

        assert!(can_satisfy_state(&event, &pushed_updates, &local_refs));
    }

    #[test]
    fn test_can_satisfy_state_missing_ref() {
        let event = create_test_state_event(
            "test-repo",
            vec![("refs/heads/main", "abc123"), ("refs/heads/dev", "def456")],
        );

        let pushed_updates = vec![RefUpdate {
            old_oid: "0000000000000000000000000000000000000000".to_string(),
            new_oid: "abc123".to_string(),
            ref_name: "refs/heads/main".to_string(),
        }];

        let local_refs = HashMap::new();

        // dev ref is missing
        assert!(!can_satisfy_state(&event, &pushed_updates, &local_refs));
    }

    #[test]
    fn test_can_satisfy_state_modification() {
        let event = create_test_state_event(
            "test-repo",
            vec![("refs/heads/main", "abc123"), ("refs/heads/dev", "def456")],
        );

        let pushed_updates = vec![
            RefUpdate {
                old_oid: "old123".to_string(),
                new_oid: "abc123".to_string(),
                ref_name: "refs/heads/main".to_string(),
            },
            RefUpdate {
                old_oid: "wrong-sha".to_string(),
                new_oid: "def456".to_string(),
                ref_name: "refs/heads/dev".to_string(),
            },
        ];

        let mut local_refs = HashMap::new();
        local_refs.insert("refs/heads/main".to_string(), "old123".to_string());
        local_refs.insert("refs/heads/dev".to_string(), "wrong-sha".to_string());

        // Should succeed because push updates both to match event
        assert!(can_satisfy_state(&event, &pushed_updates, &local_refs));
    }

    #[test]
    fn test_can_satisfy_state_rejects_extra_refs() {
        let event = create_test_state_event("test-repo", vec![("refs/heads/main", "abc123")]);

        let pushed_updates = vec![
            RefUpdate {
                old_oid: "0000000000000000000000000000000000000000".to_string(),
                new_oid: "abc123".to_string(),
                ref_name: "refs/heads/main".to_string(),
            },
            RefUpdate {
                old_oid: "old456".to_string(),
                new_oid: "def456".to_string(),
                ref_name: "refs/heads/dev".to_string(),
            },
        ];

        let mut local_refs = HashMap::new();
        local_refs.insert("refs/heads/dev".to_string(), "old456".to_string());

        // Should fail because event doesn't declare dev
        assert!(!can_satisfy_state(&event, &pushed_updates, &local_refs));
    }

    #[test]
    fn test_can_satisfy_state_filters_non_branch_tag_refs() {
        let event = create_test_state_event("test-repo", vec![("refs/heads/main", "abc123")]);

        let pushed_updates = vec![RefUpdate {
            old_oid: "0000000000000000000000000000000000000000".to_string(),
            new_oid: "abc123".to_string(),
            ref_name: "refs/heads/main".to_string(),
        }];

        let mut local_refs = HashMap::new();
        // Add some non-branch/non-tag refs that should be filtered out
        local_refs.insert("refs/pull/123/head".to_string(), "xyz789".to_string());
        local_refs.insert("refs/some/other/thing".to_string(), "aaa111".to_string());

        // Should succeed - non-branch/tag refs are filtered out
        assert!(can_satisfy_state(&event, &pushed_updates, &local_refs));
    }

    #[test]
    fn test_can_satisfy_state_empty_event() {
        let event = create_test_state_event("test-repo", vec![]);
        let pushed_refs = vec![];
        let local_refs = HashMap::new();

        // Empty state event is satisfied
        assert!(can_satisfy_state(&event, &pushed_refs, &local_refs));
    }

    #[test]
    fn test_get_unpushed_refs() {
        let event = create_test_state_event(
            "test-repo",
            vec![
                ("refs/heads/main", "abc123"),
                ("refs/heads/dev", "def456"),
                ("refs/tags/v1.0", "789xyz"),
            ],
        );

        let pushed_refs = vec![RefPair {
            ref_name: "refs/heads/main".to_string(),
            object_sha: "abc123".to_string(),
        }];

        let unpushed = get_unpushed_refs(&event, &pushed_refs);

        assert_eq!(unpushed.len(), 2);
        assert!(unpushed.iter().any(|r| r.ref_name == "refs/heads/dev"));
        assert!(unpushed.iter().any(|r| r.ref_name == "refs/tags/v1.0"));
    }

    #[test]
    fn test_get_unpushed_refs_all_pushed() {
        let event = create_test_state_event("test-repo", vec![("refs/heads/main", "abc123")]);

        let pushed_refs = vec![RefPair {
            ref_name: "refs/heads/main".to_string(),
            object_sha: "abc123".to_string(),
        }];

        let unpushed = get_unpushed_refs(&event, &pushed_refs);

        assert_eq!(unpushed.len(), 0);
    }

    #[test]
    fn test_get_unpushed_refs_sha_mismatch() {
        let event = create_test_state_event("test-repo", vec![("refs/heads/main", "abc123")]);

        let pushed_refs = vec![RefPair {
            ref_name: "refs/heads/main".to_string(),
            object_sha: "different-sha".to_string(), // Different SHA
        }];

        let unpushed = get_unpushed_refs(&event, &pushed_refs);

        // Should still be unpushed because SHA doesn't match
        assert_eq!(unpushed.len(), 1);
        assert_eq!(unpushed[0].ref_name, "refs/heads/main");
        assert_eq!(unpushed[0].object_sha, "abc123");
    }

    // =========================================================================
    // can_apply_state tests
    // =========================================================================

    /// Helper to create a temporary bare git repository with a commit.
    /// Returns (temp_dir, commit_hash) where commit_hash is Some if a commit was created.
    fn create_test_repo_with_commit() -> (tempfile::TempDir, Option<String>) {
        use std::process::Command;

        let temp_dir = tempfile::tempdir().unwrap();
        let bare_path = temp_dir.path();

        // Initialize bare repo
        Command::new("git")
            .args(["init", "--bare"])
            .current_dir(bare_path)
            .output()
            .expect("Failed to init bare git repo");

        // Create a working repo to generate a commit
        let work_dir = tempfile::tempdir().unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(work_dir.path())
            .output()
            .expect("Failed to init work repo");

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(work_dir.path())
            .output()
            .expect("Failed to set email");

        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(work_dir.path())
            .output()
            .expect("Failed to set name");

        // Disable GPG signing for tests (prevents yubikey prompts)
        Command::new("git")
            .args(["config", "commit.gpgsign", "false"])
            .current_dir(work_dir.path())
            .output()
            .expect("Failed to disable commit.gpgsign");

        Command::new("git")
            .args(["config", "tag.gpgsign", "false"])
            .current_dir(work_dir.path())
            .output()
            .expect("Failed to disable tag.gpgsign");

        // Create a commit
        std::fs::write(work_dir.path().join("file.txt"), "content").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(work_dir.path())
            .output()
            .expect("Failed to add");

        Command::new("git")
            .args(["commit", "-m", "test"])
            .current_dir(work_dir.path())
            .output()
            .expect("Failed to commit");

        // Get the commit hash from the working repo
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(work_dir.path())
            .output()
            .expect("Failed to get commit hash");

        let commit_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Push to bare repo
        Command::new("git")
            .args(["push", bare_path.to_str().unwrap(), "HEAD:refs/heads/main"])
            .current_dir(work_dir.path())
            .output()
            .expect("Failed to push");

        (temp_dir, Some(commit_hash))
    }

    /// Helper to create an empty bare git repository (no commits).
    fn create_empty_test_repo() -> tempfile::TempDir {
        use std::process::Command;

        let temp_dir = tempfile::tempdir().unwrap();

        Command::new("git")
            .args(["init", "--bare"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to init bare git repo");

        temp_dir
    }

    #[test]
    fn test_can_apply_state_with_existing_oid() {
        // Create a repo with a real commit
        let (temp_repo, commit_hash) = create_test_repo_with_commit();
        let repo_path = temp_repo.path();
        let commit_hash = commit_hash.expect("Should have a commit");

        // Create a state event referencing that commit
        let event = create_test_state_event("test-repo", vec![("refs/heads/main", &commit_hash)]);

        // Should return true since the OID exists
        assert!(can_apply_state(&event, repo_path));
    }

    #[test]
    fn test_can_apply_state_with_missing_oid() {
        // Create an empty repo
        let temp_repo = create_empty_test_repo();
        let repo_path = temp_repo.path();

        // Create a state event referencing a non-existent commit
        let event = create_test_state_event(
            "test-repo",
            vec![(
                "refs/heads/main",
                "0000000000000000000000000000000000000000",
            )],
        );

        // Should return false since the OID doesn't exist
        assert!(!can_apply_state(&event, repo_path));
    }

    #[test]
    fn test_can_apply_state_with_symbolic_ref() {
        // Create an empty repo (no commits needed for symbolic refs)
        let temp_repo = create_empty_test_repo();
        let repo_path = temp_repo.path();

        // Create a state event with only a symbolic ref
        let event = create_test_state_event(
            "test-repo",
            vec![("refs/heads/main", "ref: refs/heads/other")],
        );

        // Should return true - symbolic refs don't require OID lookup
        assert!(can_apply_state(&event, repo_path));
    }

    #[test]
    fn test_can_apply_state_mixed_existing_and_missing() {
        // Create a repo with a real commit
        let (temp_repo, commit_hash) = create_test_repo_with_commit();
        let repo_path = temp_repo.path();
        let commit_hash = commit_hash.expect("Should have a commit");

        // Create a state event with one existing and one missing OID
        let event = create_test_state_event(
            "test-repo",
            vec![
                ("refs/heads/main", &commit_hash), // exists
                ("refs/heads/dev", "0000000000000000000000000000000000000000"), // doesn't exist
            ],
        );

        // Should return false since one OID is missing
        assert!(!can_apply_state(&event, repo_path));
    }

    #[test]
    fn test_can_apply_state_empty_event() {
        let temp_repo = create_empty_test_repo();
        let repo_path = temp_repo.path();

        // Empty state event (no refs declared)
        let event = create_test_state_event("test-repo", vec![]);

        // Should return true - nothing to check
        assert!(can_apply_state(&event, repo_path));
    }

    #[test]
    fn test_can_apply_state_mixed_symbolic_and_real() {
        // Create a repo with a real commit
        let (temp_repo, commit_hash) = create_test_repo_with_commit();
        let repo_path = temp_repo.path();
        let commit_hash = commit_hash.expect("Should have a commit");

        // Create a state event with both a real OID and a symbolic ref
        let event = create_test_state_event(
            "test-repo",
            vec![
                ("refs/heads/main", &commit_hash), // real OID that exists
                ("refs/heads/alias", "ref: refs/heads/main"), // symbolic ref
            ],
        );

        // Should return true - real OID exists, symbolic ref skipped
        assert!(can_apply_state(&event, repo_path));
    }

    #[test]
    fn test_diagnose_state_mismatch_missing_ref() {
        // State declares both main and test branches
        let event = create_test_state_event(
            "test-repo",
            vec![("refs/heads/main", "abc123"), ("refs/heads/test", "def456")],
        );

        // Push only creates test branch
        let pushed_updates = vec![RefUpdate {
            old_oid: "0000000000000000000000000000000000000000".to_string(),
            new_oid: "def456".to_string(),
            ref_name: "refs/heads/test".to_string(),
        }];

        // No local refs
        let local_refs = HashMap::new();

        let diagnosis = diagnose_state_mismatch(&event, &pushed_updates, &local_refs);
        assert!(diagnosis.is_some());
        let msg = diagnosis.unwrap();
        assert!(msg.contains("refs/heads/main"));
        assert!(msg.contains("missing"));
    }

    #[test]
    fn test_diagnose_state_mismatch_wrong_sha() {
        // State declares main at abc123
        let event = create_test_state_event("test-repo", vec![("refs/heads/main", "abc123")]);

        // Push updates main to different SHA
        let pushed_updates = vec![RefUpdate {
            old_oid: "0000000000000000000000000000000000000000".to_string(),
            new_oid: "wrong123".to_string(),
            ref_name: "refs/heads/main".to_string(),
        }];

        let local_refs = HashMap::new();

        let diagnosis = diagnose_state_mismatch(&event, &pushed_updates, &local_refs);
        assert!(diagnosis.is_some());
        let msg = diagnosis.unwrap();
        assert!(msg.contains("refs/heads/main"));
        assert!(msg.contains("would be at"));
        assert!(msg.contains("state declares"));
    }

    #[test]
    fn test_diagnose_state_mismatch_extra_ref() {
        // State declares only main
        let event = create_test_state_event("test-repo", vec![("refs/heads/main", "abc123")]);

        // Push creates both main and test
        let pushed_updates = vec![
            RefUpdate {
                old_oid: "0000000000000000000000000000000000000000".to_string(),
                new_oid: "abc123".to_string(),
                ref_name: "refs/heads/main".to_string(),
            },
            RefUpdate {
                old_oid: "0000000000000000000000000000000000000000".to_string(),
                new_oid: "def456".to_string(),
                ref_name: "refs/heads/test".to_string(),
            },
        ];

        let local_refs = HashMap::new();

        let diagnosis = diagnose_state_mismatch(&event, &pushed_updates, &local_refs);
        assert!(diagnosis.is_some());
        let msg = diagnosis.unwrap();
        assert!(msg.contains("refs/heads/test"));
        assert!(msg.contains("doesn't declare"));
    }

    #[test]
    fn test_diagnose_state_mismatch_no_mismatch() {
        // State declares main
        let event = create_test_state_event("test-repo", vec![("refs/heads/main", "abc123")]);

        // Push creates main at correct SHA
        let pushed_updates = vec![RefUpdate {
            old_oid: "0000000000000000000000000000000000000000".to_string(),
            new_oid: "abc123".to_string(),
            ref_name: "refs/heads/main".to_string(),
        }];

        let local_refs = HashMap::new();

        let diagnosis = diagnose_state_mismatch(&event, &pushed_updates, &local_refs);
        assert!(diagnosis.is_none()); // No mismatch
    }
}
