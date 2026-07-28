//! Filter Building Functions for Proactive Sync
//!
//! This module provides functions to construct Nostr filters for the three-layer
//! sync strategy defined in GRASP-02 v4:
//!
//! - Layer 1: Repository announcements (30617 + 30618)
//! - Layer 2: Events tagging our repos (a/A/q tags)
//! - Layer 3: Events tagging our root events (e/E/q tags)
//!
//! See `docs/explanation/grasp-02-proactive-sync-v4.md` for full design details.

use std::collections::HashSet;

use nostr_sdk::prelude::*;

/// Layer 1: Announcements filter (kinds 30617 + 10317)
///
/// Subscribed ONCE on connect - NOT included in consolidation rebuilds.
/// Note: State events (30618) are now subscribed via identifier-based filters in Layer 2
///       to avoid receiving state events for repositories we don't host.
/// Note: 10317 (User Grasp List) is synced for better GRASP discovery.
pub fn build_announcement_filter(since: Option<Timestamp>) -> Filter {
    let filter = Filter::new().kinds([
        Kind::GitRepoAnnouncement, // Repository announcements
        Kind::GitUserGraspList,    // User Grasp List
    ]);

    match since {
        Some(ts) => filter.since(ts),
        None => filter,
    }
}

/// GRASP-P private-repo registration filter (kind 30640).
///
/// Layer-1-style: subscribed alongside the announcement filter on every
/// connect when `NGIT_PRIVATE_REPOS_ENABLE=true`, NOT part of consolidation
/// rebuilds. Registrations are small and bounded by the private global
/// budget, so an unscoped 30640 subscription is acceptable (mirrors the
/// unscoped 30617 Layer-1 treatment).
pub fn build_private_registration_filter(since: Option<Timestamp>) -> Filter {
    let filter = Filter::new().kind(Kind::Custom(crate::private::KIND_REGISTRATION));
    match since {
        Some(ts) => filter.since(ts),
        None => filter,
    }
}

/// GRASP-P derived private-repo filters, driven by accepted registrations.
///
/// For each 100-alias chunk: `kinds:[30641] #d:[aliases]` (state roots).
/// For each 100-key chunk of the registrations' w+aux keys:
/// `kinds:[3359(,1059)] authors:[keys]` (stored stream wraps). The ephemeral
/// wrap kinds are deliberately never synced.
///
/// Both stream-wrap kinds ride ONE filter while legacy accept is on, so
/// held/in-flight 1059s still drain during the migration window; the set
/// comes from [`crate::private::stream_wrap_kinds`] so it cannot drift from
/// what admission actually accepts.
///
/// # Arguments
/// * `regs` - (alias, w+aux key hex) pairs from accepted 30640 registrations
/// * `since` - Optional timestamp for incremental sync
/// * `accept_legacy_wrap_kind` - dual-accept 1059 alongside 3359
pub fn build_private_derived_filters(
    regs: &[(String, Vec<String>)],
    since: Option<Timestamp>,
    accept_legacy_wrap_kind: bool,
) -> Vec<Filter> {
    if regs.is_empty() {
        return vec![];
    }

    let mut aliases: Vec<&String> = Vec::new();
    let mut keys: HashSet<&String> = HashSet::new();
    {
        let mut seen_aliases: HashSet<&String> = HashSet::new();
        for (alias, reg_keys) in regs {
            if seen_aliases.insert(alias) {
                aliases.push(alias);
            }
            for key in reg_keys {
                keys.insert(key);
            }
        }
    }

    let mut filters = Vec::new();

    // Kind 30641 state roots, chunked 100 aliases per filter (same batching
    // as state_event_filters_for_our_repos).
    for chunk in aliases.chunks(100) {
        let mut filter = Filter::new().kind(Kind::Custom(crate::private::KIND_STATE_ROOT));
        for alias in chunk {
            filter = filter.custom_tag(SingleLetterTag::lowercase(Alphabet::D), alias.as_str());
        }
        if let Some(ts) = since {
            filter = filter.since(ts);
        }
        filters.push(filter);
    }

    // Stream wraps authored by registered w/aux keys, chunked per 100.
    let wrap_kinds: Vec<Kind> = crate::private::stream_wrap_kinds(accept_legacy_wrap_kind)
        .into_iter()
        .map(Kind::Custom)
        .collect();
    let mut authors: Vec<PublicKey> = keys
        .iter()
        .filter_map(|k| PublicKey::from_hex(k).ok())
        .collect();
    authors.sort();
    for chunk in authors.chunks(100) {
        let mut filter = Filter::new()
            .kinds(wrap_kinds.iter().copied())
            .authors(chunk.iter().copied());
        if let Some(ts) = since {
            filter = filter.since(ts);
        }
        filters.push(filter);
    }

    filters
}

/// State event filters for our hosted repositories
///
/// Subscribes to kind 30618 state events using #d (identifier) tags.
/// This is more efficient than Layer 1 broadcast subscription because:
/// - Only receives state events for repos we actually host
/// - One filter can include multiple identifiers (batched per 100)
/// - Avoids 1000+ rejections for repos we don't care about
///
/// # Arguments
/// * `repos` - Set of repo addressable refs (format: 30617:pubkey:identifier)
/// * `since` - Optional timestamp for incremental sync
///
/// # Returns
/// Vec of filters, one filter per 100-identifier chunk
pub fn state_event_filters_for_our_repos(
    repos: &HashSet<String>,
    since: Option<Timestamp>,
) -> Vec<Filter> {
    if repos.is_empty() {
        return vec![];
    }

    // Extract unique identifiers from addressable refs
    let mut identifiers: HashSet<String> = HashSet::new();
    for repo_ref in repos {
        // Format: 30617:pubkey:identifier
        if let Some(identifier) = repo_ref.split(':').nth(2) {
            identifiers.insert(identifier.to_string());
        }
    }

    if identifiers.is_empty() {
        return vec![];
    }

    let mut filters = Vec::new();
    let identifier_vec: Vec<_> = identifiers.iter().collect();

    // Batch by 100 identifiers per filter
    for chunk in identifier_vec.chunks(100) {
        let mut filter = Filter::new().kind(Kind::RepoState); // kind 30618

        // Add #d tags for all identifiers in this chunk
        for identifier in chunk {
            filter =
                filter.custom_tag(SingleLetterTag::lowercase(Alphabet::D), identifier.as_str());
        }

        if let Some(ts) = since {
            filter = filter.since(ts);
        }

        filters.push(filter);
    }

    filters
}

/// Layer 2: Events tagging one of our repos
///
/// Uses lowercase a, uppercase A, and q tags for comprehensive coverage.
/// Batched per 100 repo refs.
///
/// # Arguments
/// * `repos` - Set of repo addressable refs (format: 30617:pubkey:identifier)
/// * `since` - Optional timestamp for incremental sync
///
/// # Returns
/// Vec of filters, one set of 3 filters (a/A/q) per 100-repo chunk
pub fn tagged_one_of_our_repo_event_filters(
    repos: &HashSet<String>,
    since: Option<Timestamp>,
) -> Vec<Filter> {
    if repos.is_empty() {
        return vec![];
    }

    let mut filters = Vec::new();
    let repo_refs: Vec<_> = repos.iter().collect();

    for chunk in repo_refs.chunks(100) {
        // Lowercase 'a' tag - standard addressable reference
        let mut f1 = Filter::new();
        for repo in chunk {
            f1 = f1.custom_tag(SingleLetterTag::lowercase(Alphabet::A), repo.as_str());
        }

        // Uppercase 'A' tag - some clients use this
        let mut f2 = Filter::new();
        for repo in chunk {
            f2 = f2.custom_tag(SingleLetterTag::uppercase(Alphabet::A), repo.as_str());
        }

        // Quote 'q' tag - NIP-10 quote references to addressable events
        let mut f3 = Filter::new();
        for repo in chunk {
            f3 = f3.custom_tag(SingleLetterTag::lowercase(Alphabet::Q), repo.as_str());
        }

        if let Some(ts) = since {
            f1 = f1.since(ts);
            f2 = f2.since(ts);
            f3 = f3.since(ts);
        }

        filters.push(f1);
        filters.push(f2);
        filters.push(f3);
    }

    filters
}

/// Layer 3: Events tagging one of our root events
///
/// Uses lowercase e, uppercase E, and q tags for comprehensive coverage.
/// Batched per 100 event IDs.
///
/// # Arguments
/// * `root_events` - Set of event IDs (1617/1618/1621 root events)
/// * `since` - Optional timestamp for incremental sync
///
/// # Returns
/// Vec of filters, one set of 3 filters (e/E/q) per 100-event chunk
pub fn tagged_one_of_our_root_event_filters(
    root_events: &HashSet<EventId>,
    since: Option<Timestamp>,
) -> Vec<Filter> {
    if root_events.is_empty() {
        return vec![];
    }

    // DEBUG TRACING: Log the root events we're creating Layer 3 filters for
    tracing::debug!(
        root_event_count = root_events.len(),
        root_event_ids = ?root_events.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
        since = ?since,
        "Building Layer 3 filters for root events"
    );

    let mut filters = Vec::new();
    let event_ids: Vec<String> = root_events.iter().map(|id| id.to_hex()).collect();

    for (chunk_idx, chunk) in event_ids.chunks(100).enumerate() {
        // Lowercase 'e' tag - standard event reference
        let mut f1 = Filter::new();
        for event_id in chunk {
            f1 = f1.custom_tag(SingleLetterTag::lowercase(Alphabet::E), event_id.as_str());
        }

        // Uppercase 'E' tag - some clients use this
        let mut f2 = Filter::new();
        for event_id in chunk {
            f2 = f2.custom_tag(SingleLetterTag::uppercase(Alphabet::E), event_id.as_str());
        }

        // Quote 'q' tag - NIP-10 quote references to events
        let mut f3 = Filter::new();
        for event_id in chunk {
            f3 = f3.custom_tag(SingleLetterTag::lowercase(Alphabet::Q), event_id.as_str());
        }

        if let Some(ts) = since {
            f1 = f1.since(ts);
            f2 = f2.since(ts);
            f3 = f3.since(ts);
        }

        // DEBUG TRACING: Log the filters being created
        tracing::debug!(
            chunk_idx = chunk_idx,
            chunk_size = chunk.len(),
            event_ids_in_chunk = ?chunk,
            filter_e = ?f1,
            filter_E = ?f2,
            filter_q = ?f3,
            "Created Layer 3 filter chunk"
        );

        filters.push(f1);
        filters.push(f2);
        filters.push(f3);
    }

    filters
}

/// Builds Layer 2 + Layer 3 filters only (NOT Layer 1)
///
/// Used by:
/// - compute_actions for incremental subscriptions
/// - consolidation rebuilds (Layer 1 remains active)
///
/// Includes:
/// - State event filters (kind 30618 with #d tags for our repo identifiers)
/// - Repo-tagging filters (a/A/q tags)
/// - Root event filters (e/E/q tags)
///
/// # Arguments
/// * `repos` - Set of repo addressable refs
/// * `root_events` - Set of root event IDs
/// * `since` - Optional timestamp for incremental sync
pub fn build_layer2_and_layer3_filters(
    repos: &HashSet<String>,
    root_events: &HashSet<EventId>,
    since: Option<Timestamp>,
) -> Vec<Filter> {
    let mut filters = Vec::new();
    filters.extend(state_event_filters_for_our_repos(repos, since));
    filters.extend(tagged_one_of_our_repo_event_filters(repos, since));
    filters.extend(tagged_one_of_our_root_event_filters(root_events, since));
    filters
}

/// Builds filters respecting SyncLevel for each repo
///
/// StateOnly repos only get state event filters (kind 30618).
/// Full repos get all L2/L3 filters (state + repo-tagging + root event).
///
/// # Arguments
/// * `full_repos` - Repos needing full L2+L3 sync
/// * `state_only_repos` - Repos needing only state event sync (purgatory)
/// * `root_events` - Root event IDs (only used for Full repos)
/// * `since` - Optional timestamp for incremental sync
pub fn build_sync_level_aware_filters(
    full_repos: &HashSet<String>,
    state_only_repos: &HashSet<String>,
    root_events: &HashSet<EventId>,
    since: Option<Timestamp>,
) -> Vec<Filter> {
    let mut filters = Vec::new();

    // All repos (both Full and StateOnly) need state event filters
    let all_repos: HashSet<String> = full_repos.union(state_only_repos).cloned().collect();
    filters.extend(state_event_filters_for_our_repos(&all_repos, since));

    // Only Full repos get repo-tagging and root event filters
    if !full_repos.is_empty() {
        filters.extend(tagged_one_of_our_repo_event_filters(full_repos, since));
    }
    filters.extend(tagged_one_of_our_root_event_filters(root_events, since));

    filters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announcement_filter_no_since() {
        let filter = build_announcement_filter(None);

        // Verify it includes both kinds
        // Filter API: we can check by converting to JSON or inspecting structure
        // For now we just verify it doesn't panic and returns a valid filter
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_announcement_filter_with_since() {
        let since = Timestamp::from(1700000000);
        let filter = build_announcement_filter(Some(since));

        assert!(!filter.is_empty());
    }

    #[test]
    fn test_repo_filters_empty() {
        let repos: HashSet<String> = HashSet::new();
        let filters = tagged_one_of_our_repo_event_filters(&repos, None);

        assert!(filters.is_empty());
    }

    #[test]
    fn test_repo_filters_single_repo() {
        let mut repos = HashSet::new();
        repos.insert("30617:abc123:test-repo".to_string());

        let filters = tagged_one_of_our_repo_event_filters(&repos, None);

        // Should create 3 filters (a, A, q) for one chunk
        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_repo_filters_batching() {
        let mut repos = HashSet::new();
        for i in 0..250 {
            repos.insert(format!("30617:pubkey{}:repo{}", i, i));
        }

        let filters = tagged_one_of_our_repo_event_filters(&repos, None);

        // Should create 9 filters (3 chunks * 3 tag types)
        // 250 repos = 100 + 100 + 50 = 3 chunks
        assert_eq!(filters.len(), 9);
    }

    #[test]
    fn test_repo_filters_with_since() {
        let mut repos = HashSet::new();
        repos.insert("30617:abc123:test-repo".to_string());

        let since = Timestamp::from(1700000000);
        let filters = tagged_one_of_our_repo_event_filters(&repos, Some(since));

        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_root_event_filters_empty() {
        let root_events: HashSet<EventId> = HashSet::new();
        let filters = tagged_one_of_our_root_event_filters(&root_events, None);

        assert!(filters.is_empty());
    }

    #[test]
    fn test_root_event_filters_single_event() {
        let mut root_events = HashSet::new();
        // Create a valid event ID (all zeros for testing)
        root_events.insert(EventId::all_zeros());

        let filters = tagged_one_of_our_root_event_filters(&root_events, None);

        // Should create 3 filters (e, E, q) for one chunk
        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_root_event_filters_batching() {
        let mut root_events = HashSet::new();
        // EventId::all_zeros() will deduplicate, so we need unique IDs
        // For testing purposes, we'll just verify with one ID since HashSet
        // deduplicates all_zeros(). In real usage these would be unique.
        for _ in 0..250 {
            root_events.insert(EventId::all_zeros());
        }

        let filters = tagged_one_of_our_root_event_filters(&root_events, None);

        // With deduplication, we only have 1 unique ID, so 3 filters
        // In real usage with 250 unique IDs, it would be 9 filters
        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_root_event_filters_with_since() {
        let mut root_events = HashSet::new();
        root_events.insert(EventId::all_zeros());

        let since = Timestamp::from(1700000000);
        let filters = tagged_one_of_our_root_event_filters(&root_events, Some(since));

        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_combined_filters_empty() {
        let repos: HashSet<String> = HashSet::new();
        let root_events: HashSet<EventId> = HashSet::new();

        let filters = build_layer2_and_layer3_filters(&repos, &root_events, None);

        assert!(filters.is_empty());
    }

    #[test]
    fn test_combined_filters() {
        let mut repos = HashSet::new();
        repos.insert("30617:abc123:repo1".to_string());

        let mut root_events = HashSet::new();
        root_events.insert(EventId::all_zeros());

        let filters = build_layer2_and_layer3_filters(&repos, &root_events, None);

        // Should have 7 filters (1 state + 3 for repos + 3 for root events)
        assert_eq!(filters.len(), 7);
    }

    #[test]
    fn test_combined_filters_repos_only() {
        let mut repos = HashSet::new();
        repos.insert("30617:abc123:repo1".to_string());

        let root_events: HashSet<EventId> = HashSet::new();

        let filters = build_layer2_and_layer3_filters(&repos, &root_events, None);

        // Should have 4 filters (1 state + 3 for repos only)
        assert_eq!(filters.len(), 4);
    }

    #[test]
    fn test_combined_filters_root_events_only() {
        let repos: HashSet<String> = HashSet::new();

        let mut root_events = HashSet::new();
        root_events.insert(EventId::all_zeros());

        let filters = build_layer2_and_layer3_filters(&repos, &root_events, None);

        // Should have 3 filters (3 for root events only)
        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_combined_filters_with_since() {
        let mut repos = HashSet::new();
        repos.insert("30617:abc123:repo1".to_string());

        let mut root_events = HashSet::new();
        root_events.insert(EventId::all_zeros());

        let since = Timestamp::from(1700000000);
        let filters = build_layer2_and_layer3_filters(&repos, &root_events, Some(since));

        // Should have 7 filters (1 state + 3 for repos + 3 for root events)
        assert_eq!(filters.len(), 7);
    }

    #[test]
    fn test_private_full_reissue_filter_construction() {
        // Phase-4b B1: the periodic full re-issue set is the bare 30640
        // registration filter plus the current derived filters, ALL with
        // since=None (full backfill, never incremental).

        // Empty index (zero aliases): exactly the bare 30640 filter — still
        // re-issued as a cheap self-heal for missed registrations.
        let empty: Vec<(String, Vec<String>)> = vec![];
        let mut filters = vec![build_private_registration_filter(None)];
        filters.extend(build_private_derived_filters(&empty, None, true));
        assert_eq!(filters.len(), 1);
        assert!(
            filters[0]
                .kinds
                .as_ref()
                .is_some_and(|k| k.contains(&Kind::Custom(30640)))
        );
        assert_eq!(filters[0].since, None);

        // Populated index: 30640 + one 30641 #d chunk + one stream-wrap
        // authors chunk, none carrying a since filter.
        let regs = vec![(
            "a".repeat(32),
            vec![PublicKey::from_slice(&[1u8; 32]).unwrap().to_hex()],
        )];
        let mut filters = vec![build_private_registration_filter(None)];
        filters.extend(build_private_derived_filters(&regs, None, true));
        assert_eq!(filters.len(), 3);
        let want_kinds = [Kind::Custom(30640), Kind::Custom(30641), Kind::Custom(3359)];
        for (filter, want) in filters.iter().zip(want_kinds.iter()) {
            assert!(
                filter.kinds.as_ref().is_some_and(|k| k.contains(want)),
                "expected kind {want:?} in {filter:?}"
            );
            assert_eq!(filter.since, None, "re-issue filters must be since=None");
        }
    }

    /// Wire-kind migration: while legacy accept is on the derived wrap
    /// filter must request BOTH kinds in ONE filter, so held/in-flight
    /// 1059s keep draining from peers; with legacy accept off it must ask
    /// for 3359 only (asking for a kind we would reject is a refetch loop).
    #[test]
    fn test_private_derived_wrap_filter_kinds_follow_legacy_accept() {
        let regs = vec![(
            "b".repeat(32),
            vec![PublicKey::from_slice(&[2u8; 32]).unwrap().to_hex()],
        )];

        let dual = build_private_derived_filters(&regs, None, true);
        let wrap = dual.last().expect("wrap filter");
        let kinds = wrap.kinds.as_ref().expect("wrap filter kinds");
        assert!(kinds.contains(&Kind::Custom(3359)));
        assert!(kinds.contains(&Kind::Custom(1059)));
        assert_eq!(kinds.len(), 2, "both wrap kinds ride ONE filter");

        let strict = build_private_derived_filters(&regs, None, false);
        let wrap = strict.last().expect("wrap filter");
        let kinds = wrap.kinds.as_ref().expect("wrap filter kinds");
        assert!(kinds.contains(&Kind::Custom(3359)));
        assert!(!kinds.contains(&Kind::Custom(1059)));
        assert_eq!(kinds.len(), 1);
    }

    #[test]
    fn test_state_event_filters_empty() {
        let repos: HashSet<String> = HashSet::new();
        let filters = state_event_filters_for_our_repos(&repos, None);

        assert!(filters.is_empty());
    }

    #[test]
    fn test_state_event_filters_single_repo() {
        let mut repos = HashSet::new();
        repos.insert("30617:abc123:test-repo".to_string());

        let filters = state_event_filters_for_our_repos(&repos, None);

        // Should create 1 filter with kind 30618 and #d tag
        assert_eq!(filters.len(), 1);
    }

    #[test]
    fn test_state_event_filters_batching() {
        let mut repos = HashSet::new();
        for i in 0..250 {
            repos.insert(format!("30617:pubkey{}:repo{}", i, i));
        }

        let filters = state_event_filters_for_our_repos(&repos, None);

        // Should create 3 filters (250 identifiers = 100 + 100 + 50 = 3 chunks)
        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_state_event_filters_deduplicates_identifiers() {
        let mut repos = HashSet::new();
        // Same identifier with different pubkeys
        repos.insert("30617:pubkey1:same-repo".to_string());
        repos.insert("30617:pubkey2:same-repo".to_string());
        repos.insert("30617:pubkey3:same-repo".to_string());

        let filters = state_event_filters_for_our_repos(&repos, None);

        // Should create 1 filter with deduplicated identifier
        assert_eq!(filters.len(), 1);
    }

    #[test]
    fn test_state_event_filters_with_since() {
        let mut repos = HashSet::new();
        repos.insert("30617:abc123:test-repo".to_string());

        let since = Timestamp::from(1700000000);
        let filters = state_event_filters_for_our_repos(&repos, Some(since));

        assert_eq!(filters.len(), 1);
    }
}
