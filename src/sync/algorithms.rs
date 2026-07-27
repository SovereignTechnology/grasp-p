//! Core Sync Algorithms for Proactive Sync
//!
//! This module provides the decision-making algorithms for the sync system:
//!
//! - `derive_relay_targets()` - Inverts RepoSyncIndex to per-relay view
//! - `compute_actions()` - Three-way diff to determine new sync actions
//!
//! See `docs/explanation/grasp-02-proactive-sync-v4.md` for full design details.

use std::collections::{HashMap, HashSet};

use nostr_sdk::prelude::*;

use crate::sync::PendingItems;

use super::{ConnectionStatus, PendingBatch, RelayState};

// =============================================================================
// Data Structures
// =============================================================================

/// Relay-centric view of what needs syncing
///
/// This is the inverted view of `RepoSyncNeeds` - instead of "what relays does
/// this repo need to sync from", it's "what repos does this relay need to sync".
#[derive(Debug, Clone, Default)]
pub struct RelaySyncNeeds {
    /// Repos that need full L2+L3 sync from this relay
    pub repos: HashSet<String>,
    /// Repos that only need state event sync (purgatory announcements)
    pub state_only_repos: HashSet<String>,
    /// Root events that need to be tracked from this relay
    pub root_events: HashSet<EventId>,
}

/// Action to add filters to a relay
///
/// Produced by `compute_actions()` to describe incremental sync work needed.
#[derive(Debug)]
pub struct AddFilters {
    /// The relay URL to add filters to
    pub relay_url: String,
    /// pending items - repos and root events
    pub items: PendingItems,
    /// The actual filters to subscribe with
    pub filters: Vec<Filter>,
}

// =============================================================================
// Core Algorithms
// =============================================================================

/// Inverts RepoSyncIndex to per-relay view
///
/// Takes the repo-centric index (repo -> {relays, root_events}) and inverts it
/// to a relay-centric view (relay -> {repos, root_events}).
///
/// # Arguments
/// * `repo_index` - Map of repo addressable refs to their sync needs
///
/// # Returns
/// Map of relay URLs to the combined sync needs from all repos
pub fn derive_relay_targets(
    repo_index: &HashMap<String, super::RepoSyncNeeds>,
) -> HashMap<String, RelaySyncNeeds> {
    let mut relay_targets: HashMap<String, RelaySyncNeeds> = HashMap::new();

    for (repo_id, needs) in repo_index {
        for relay_url in &needs.relays {
            let relay_key =
                super::canonical_relay_key(relay_url).unwrap_or_else(|_| relay_url.clone());
            let entry = relay_targets.entry(relay_key).or_default();

            match needs.sync_level {
                super::SyncLevel::Full => {
                    entry.repos.insert(repo_id.clone());
                    entry.root_events.extend(needs.root_events.iter().cloned());
                }
                super::SyncLevel::StateOnly => {
                    entry.state_only_repos.insert(repo_id.clone());
                }
            }
        }
    }

    relay_targets
}

/// Three-way diff: target - pending - confirmed = new
///
/// Computes what sync actions are needed by comparing:
/// 1. What we want (targets)
/// 2. What's already in-flight (pending)
/// 3. What's already confirmed (confirmed)
///
/// Only creates AddFilters actions for items not already pending or confirmed.
///
/// # Arguments
/// * `targets` - Per-relay sync needs (from `derive_relay_targets`)
/// * `pending` - In-flight batches per relay
/// * `confirmed` - Confirmed relay states
///
/// # Returns
/// Vec of AddFilters actions for new sync work
pub fn compute_actions(
    targets: &HashMap<String, RelaySyncNeeds>,
    pending: &HashMap<String, Vec<PendingBatch>>,
    confirmed: &HashMap<String, RelayState>,
) -> Vec<AddFilters> {
    use crate::sync::filters::build_sync_level_aware_filters;

    let mut actions = Vec::new();

    for (relay_url, target_needs) in targets {
        // Skip disconnected relays
        if let Some(state) = confirmed.get(relay_url) {
            if matches!(state.connection_status, ConnectionStatus::Disconnected) {
                continue;
            }
        }

        // Calculate what's already pending
        let pending_repos: HashSet<String> = pending
            .get(relay_url)
            .map(|batches| {
                batches
                    .iter()
                    .flat_map(|batch| batch.items.repos.iter().cloned())
                    .collect()
            })
            .unwrap_or_default();

        let pending_events: HashSet<EventId> = pending
            .get(relay_url)
            .map(|batches| {
                batches
                    .iter()
                    .flat_map(|batch| batch.items.root_events.iter().cloned())
                    .collect()
            })
            .unwrap_or_default();

        // Calculate what's already confirmed
        let confirmed_repos: HashSet<String> = confirmed
            .get(relay_url)
            .map(|state| state.repos.clone())
            .unwrap_or_default();

        let confirmed_events: HashSet<EventId> = confirmed
            .get(relay_url)
            .map(|state| state.root_events.clone())
            .unwrap_or_default();

        // Calculate what's NEW for full repos (not in pending, not in confirmed)
        let new_full_repos: HashSet<String> = target_needs
            .repos
            .difference(&pending_repos)
            .filter(|repo| !confirmed_repos.contains(*repo))
            .cloned()
            .collect();

        // Calculate what's NEW for state-only repos
        let new_state_only_repos: HashSet<String> = target_needs
            .state_only_repos
            .difference(&pending_repos)
            .filter(|repo| !confirmed_repos.contains(*repo))
            .cloned()
            .collect();

        let new_events: HashSet<EventId> = target_needs
            .root_events
            .difference(&pending_events)
            .filter(|event| !confirmed_events.contains(*event))
            .cloned()
            .collect();

        // If there's anything new, create an AddFilters action
        if !new_full_repos.is_empty() || !new_state_only_repos.is_empty() || !new_events.is_empty()
        {
            let filters = build_sync_level_aware_filters(
                &new_full_repos,
                &new_state_only_repos,
                &new_events,
                None,
            );

            // Combine all repos into pending items (pending tracking doesn't need sync level)
            let mut all_new_repos = new_full_repos;
            all_new_repos.extend(new_state_only_repos);

            actions.push(AddFilters {
                relay_url: relay_url.clone(),
                items: PendingItems {
                    repos: all_new_repos,
                    root_events: new_events,
                },
                filters,
            });
        }
    }

    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::RepoSyncNeeds as ModRepoSyncNeeds;
    use crate::sync::SyncMethod;

    // =========================================================================
    // derive_relay_targets tests
    // =========================================================================

    #[test]
    fn test_derive_relay_targets_empty() {
        let repo_index = HashMap::new();
        let targets = derive_relay_targets(&repo_index);
        assert!(targets.is_empty());
    }

    #[test]
    fn test_derive_relay_targets_single_repo_single_relay() {
        let mut repo_index = HashMap::new();
        let mut relays = HashSet::new();
        relays.insert("wss://relay1.com".to_string());

        let mut root_events = HashSet::new();
        root_events.insert(EventId::all_zeros());

        repo_index.insert(
            "repo1".to_string(),
            ModRepoSyncNeeds {
                relays,
                root_events,
                sync_level: Default::default(),
            },
        );

        let targets = derive_relay_targets(&repo_index);

        assert_eq!(targets.len(), 1);
        let relay_needs = targets.get("wss://relay1.com").unwrap();
        assert_eq!(relay_needs.repos.len(), 1);
        assert!(relay_needs.repos.contains("repo1"));
        assert_eq!(relay_needs.root_events.len(), 1);
    }

    #[test]
    fn test_derive_relay_targets_multiple_repos_same_relay() {
        let mut repo_index = HashMap::new();

        for i in 1..=3 {
            let mut relays = HashSet::new();
            relays.insert("wss://relay1.com".to_string());

            repo_index.insert(
                format!("repo{}", i),
                ModRepoSyncNeeds {
                    relays,
                    root_events: HashSet::new(),
                    sync_level: Default::default(),
                },
            );
        }

        let targets = derive_relay_targets(&repo_index);

        assert_eq!(targets.len(), 1);
        let relay_needs = targets.get("wss://relay1.com").unwrap();
        assert_eq!(relay_needs.repos.len(), 3);
    }

    #[test]
    fn test_derive_relay_targets_deduplicates_root_slash_variants() {
        let repo_index = HashMap::from([
            (
                "repo1".to_string(),
                ModRepoSyncNeeds {
                    relays: HashSet::from(["wss://relay1.com".to_string()]),
                    root_events: HashSet::new(),
                    sync_level: Default::default(),
                },
            ),
            (
                "repo2".to_string(),
                ModRepoSyncNeeds {
                    relays: HashSet::from(["wss://relay1.com/".to_string()]),
                    root_events: HashSet::new(),
                    sync_level: Default::default(),
                },
            ),
        ]);

        let targets = derive_relay_targets(&repo_index);

        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets
                .get("wss://relay1.com")
                .expect("root slash variants must share one key")
                .repos,
            HashSet::from(["repo1".to_string(), "repo2".to_string()])
        );
    }

    #[test]
    fn test_derive_relay_targets_repo_across_multiple_relays() {
        let mut repo_index = HashMap::new();
        let mut relays = HashSet::new();
        relays.insert("wss://relay1.com".to_string());
        relays.insert("wss://relay2.com".to_string());

        repo_index.insert(
            "repo1".to_string(),
            ModRepoSyncNeeds {
                relays,
                root_events: HashSet::new(),
                sync_level: Default::default(),
            },
        );

        let targets = derive_relay_targets(&repo_index);

        assert_eq!(targets.len(), 2);
        assert!(targets
            .get("wss://relay1.com")
            .unwrap()
            .repos
            .contains("repo1"));
        assert!(targets
            .get("wss://relay2.com")
            .unwrap()
            .repos
            .contains("repo1"));
    }

    #[test]
    fn test_derive_relay_targets_combines_root_events() {
        let mut repo_index = HashMap::new();

        // Repo1 has one root event
        let mut relays1 = HashSet::new();
        relays1.insert("wss://relay1.com".to_string());
        let mut root_events1 = HashSet::new();
        root_events1.insert(EventId::all_zeros());

        repo_index.insert(
            "repo1".to_string(),
            ModRepoSyncNeeds {
                relays: relays1,
                root_events: root_events1,
                sync_level: Default::default(),
            },
        );

        // Repo2 also points to same relay but should have same event combined
        let mut relays2 = HashSet::new();
        relays2.insert("wss://relay1.com".to_string());
        let mut root_events2 = HashSet::new();
        root_events2.insert(EventId::all_zeros()); // Same event

        repo_index.insert(
            "repo2".to_string(),
            ModRepoSyncNeeds {
                relays: relays2,
                root_events: root_events2,
                sync_level: Default::default(),
            },
        );

        let targets = derive_relay_targets(&repo_index);

        assert_eq!(targets.len(), 1);
        let relay_needs = targets.get("wss://relay1.com").unwrap();
        assert_eq!(relay_needs.repos.len(), 2);
        // Root events should be deduplicated
        assert_eq!(relay_needs.root_events.len(), 1);
    }

    // =========================================================================
    // compute_actions tests
    // =========================================================================

    #[test]
    fn test_compute_actions_empty() {
        let targets = HashMap::new();
        let pending = HashMap::new();
        let confirmed = HashMap::new();

        let actions = compute_actions(&targets, &pending, &confirmed);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_compute_actions_skips_disconnected() {
        let mut targets = HashMap::new();
        targets.insert(
            "wss://relay1.com".to_string(),
            RelaySyncNeeds {
                repos: vec!["repo1".to_string()].into_iter().collect(),
                state_only_repos: HashSet::new(),
                root_events: HashSet::new(),
            },
        );

        let pending = HashMap::new();

        let mut confirmed = HashMap::new();
        confirmed.insert(
            "wss://relay1.com".to_string(),
            RelayState {
                repos: HashSet::new(),
                root_events: HashSet::new(),
                is_bootstrap: false,
                connection_status: ConnectionStatus::Disconnected,
                last_connected: None,
                disconnected_at: None,
                announcements_synced: false,
                historic_sync_completed: false,
                historic_sync_completed_at: None,
                historic_sync_had_failures: false,
            },
        );

        let actions = compute_actions(&targets, &pending, &confirmed);
        assert!(actions.is_empty(), "Should skip disconnected relays");
    }

    #[test]
    fn test_compute_actions_new_repo() {
        let mut targets = HashMap::new();
        targets.insert(
            "wss://relay1.com".to_string(),
            RelaySyncNeeds {
                repos: vec!["repo1".to_string()].into_iter().collect(),
                state_only_repos: HashSet::new(),
                root_events: HashSet::new(),
            },
        );

        let pending = HashMap::new();
        let confirmed = HashMap::new();

        let actions = compute_actions(&targets, &pending, &confirmed);

        assert_eq!(actions.len(), 1);
        let action = &actions[0];
        assert_eq!(action.relay_url, "wss://relay1.com");
        assert!(action.items.repos.contains("repo1"));
        assert!(!action.filters.is_empty());
    }

    #[test]
    fn test_compute_actions_excludes_pending() {
        let mut targets = HashMap::new();
        targets.insert(
            "wss://relay1.com".to_string(),
            RelaySyncNeeds {
                repos: vec!["repo1".to_string()].into_iter().collect(),
                state_only_repos: HashSet::new(),
                root_events: HashSet::new(),
            },
        );

        let mut pending = HashMap::new();
        pending.insert(
            "wss://relay1.com".to_string(),
            vec![super::super::PendingBatch {
                batch_id: 1,
                items: super::super::PendingItems {
                    repos: vec!["repo1".to_string()].into_iter().collect(),
                    root_events: HashSet::new(),
                },
                outstanding_subs: HashSet::new(),
                sync_method: SyncMethod::ReqEose,
                pagination_state: HashMap::new(),
                requested_event_ids: None,
                received_event_ids: None,
                retry_count: 0,
                failed: false,
            }],
        );

        let confirmed = HashMap::new();

        let actions = compute_actions(&targets, &pending, &confirmed);
        assert!(
            actions.is_empty(),
            "Should not create action for pending items"
        );
    }

    #[test]
    fn test_compute_actions_excludes_confirmed() {
        let mut targets = HashMap::new();
        targets.insert(
            "wss://relay1.com".to_string(),
            RelaySyncNeeds {
                repos: vec!["repo1".to_string()].into_iter().collect(),
                state_only_repos: HashSet::new(),
                root_events: HashSet::new(),
            },
        );

        let pending = HashMap::new();

        let mut confirmed = HashMap::new();
        confirmed.insert(
            "wss://relay1.com".to_string(),
            RelayState {
                repos: vec!["repo1".to_string()].into_iter().collect(),
                root_events: HashSet::new(),
                is_bootstrap: false,
                connection_status: ConnectionStatus::Connected,
                last_connected: None,
                disconnected_at: None,
                announcements_synced: false,
                historic_sync_completed: false,
                historic_sync_completed_at: None,
                historic_sync_had_failures: false,
            },
        );

        let actions = compute_actions(&targets, &pending, &confirmed);
        assert!(
            actions.is_empty(),
            "Should not create action for confirmed items"
        );
    }

    #[test]
    fn test_compute_actions_allows_connecting_relays() {
        let mut targets = HashMap::new();
        targets.insert(
            "wss://relay1.com".to_string(),
            RelaySyncNeeds {
                repos: vec!["repo1".to_string()].into_iter().collect(),
                state_only_repos: HashSet::new(),
                root_events: HashSet::new(),
            },
        );

        let pending = HashMap::new();

        let mut confirmed = HashMap::new();
        confirmed.insert(
            "wss://relay1.com".to_string(),
            RelayState {
                repos: HashSet::new(),
                root_events: HashSet::new(),
                is_bootstrap: false,
                connection_status: ConnectionStatus::Connecting,
                last_connected: None,
                disconnected_at: None,
                announcements_synced: false,
                historic_sync_completed: false,
                historic_sync_completed_at: None,
                historic_sync_had_failures: false,
            },
        );

        let actions = compute_actions(&targets, &pending, &confirmed);
        assert_eq!(
            actions.len(),
            1,
            "Should create action for connecting relays"
        );
    }

    #[test]
    fn test_compute_actions_partial_overlap() {
        // Target has repo1, repo2, repo3
        let mut targets = HashMap::new();
        targets.insert(
            "wss://relay1.com".to_string(),
            RelaySyncNeeds {
                repos: vec![
                    "repo1".to_string(),
                    "repo2".to_string(),
                    "repo3".to_string(),
                ]
                .into_iter()
                .collect(),
                state_only_repos: HashSet::new(),
                root_events: HashSet::new(),
            },
        );

        // repo1 is pending
        let mut pending = HashMap::new();
        pending.insert(
            "wss://relay1.com".to_string(),
            vec![super::super::PendingBatch {
                batch_id: 1,
                items: super::super::PendingItems {
                    repos: vec!["repo1".to_string()].into_iter().collect(),
                    root_events: HashSet::new(),
                },
                outstanding_subs: HashSet::new(),
                sync_method: SyncMethod::ReqEose,
                pagination_state: HashMap::new(),
                requested_event_ids: None,
                received_event_ids: None,
                retry_count: 0,
                failed: false,
            }],
        );

        // repo2 is confirmed
        let mut confirmed = HashMap::new();
        confirmed.insert(
            "wss://relay1.com".to_string(),
            RelayState {
                repos: vec!["repo2".to_string()].into_iter().collect(),
                root_events: HashSet::new(),
                is_bootstrap: false,
                connection_status: ConnectionStatus::Connected,
                last_connected: None,
                disconnected_at: None,
                announcements_synced: false,
                historic_sync_completed: false,
                historic_sync_completed_at: None,
                historic_sync_had_failures: false,
            },
        );

        let actions = compute_actions(&targets, &pending, &confirmed);

        assert_eq!(actions.len(), 1);
        let action = &actions[0];
        // Only repo3 should be in the action (repo1 pending, repo2 confirmed)
        assert_eq!(action.items.repos.len(), 1);
        assert!(action.items.repos.contains("repo3"));
        assert!(!action.items.repos.contains("repo1"));
        assert!(!action.items.repos.contains("repo2"));
    }

    #[test]
    fn test_compute_actions_with_root_events() {
        let event_id = EventId::all_zeros();

        let mut targets = HashMap::new();
        targets.insert(
            "wss://relay1.com".to_string(),
            RelaySyncNeeds {
                repos: HashSet::new(),
                state_only_repos: HashSet::new(),
                root_events: vec![event_id].into_iter().collect(),
            },
        );

        let pending = HashMap::new();
        let confirmed = HashMap::new();

        let actions = compute_actions(&targets, &pending, &confirmed);

        assert_eq!(actions.len(), 1);
        let action = &actions[0];
        assert!(action.items.repos.is_empty());
        assert_eq!(action.items.root_events.len(), 1);
        assert!(action.items.root_events.contains(&event_id));
        // Should have 3 filters for the root event (e, E, q tags)
        assert_eq!(action.filters.len(), 3);
    }

    #[test]
    fn test_compute_actions_unknown_relay_creates_action() {
        // When a relay is not in confirmed at all, it should still create an action
        // (it's treated as connected by default if missing from confirmed)
        let mut targets = HashMap::new();
        targets.insert(
            "wss://new-relay.com".to_string(),
            RelaySyncNeeds {
                repos: vec!["repo1".to_string()].into_iter().collect(),
                state_only_repos: HashSet::new(),
                root_events: HashSet::new(),
            },
        );

        let pending = HashMap::new();
        let confirmed = HashMap::new(); // relay not in confirmed

        let actions = compute_actions(&targets, &pending, &confirmed);

        assert_eq!(
            actions.len(),
            1,
            "Should create action for unknown relay (not yet tracked)"
        );
        assert_eq!(actions[0].relay_url, "wss://new-relay.com");
    }
}
