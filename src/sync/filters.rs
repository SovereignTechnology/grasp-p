//! Filter Building Functions for Proactive Sync
//!
//! This module provides functions to construct Nostr filters for the three-layer
//! sync strategy defined in GRASP-02 v4:
//!
//! - Layer 1: Repository announcements (30617 + 30618)
//! - Layer 2: Events tagging our repos (a/A/q tags)
//! - Layer 3: Events tagging our root events (e/E/q tags)
//!
//! See `docs/explanation/grasp-02-proactive-sync.md` for full design details.

use std::collections::HashSet;

use nostr_sdk::prelude::*;

/// Ordered live-coverage priorities. Lower-priority tiers may be served by
/// paced REQ+EOSE rotation when the connection cannot keep every filter live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoverageTier {
    EssentialCore,
    RootUppercase,
    CoreCompatibility,
    DescendantCanonical,
    DescendantQuote,
    HistoricOnly,
}

#[derive(Debug, Clone)]
pub struct TieredFilter {
    pub tier: CoverageTier,
    pub filter: Filter,
}

/// Build the live coverage that is never demoted under connection pressure.
pub fn build_essential_live_filters(
    full_repos: &HashSet<String>,
    state_only_repos: &HashSet<String>,
    root_events: &HashSet<EventId>,
    since: Option<Timestamp>,
) -> Vec<Filter> {
    let all_repos: HashSet<String> = full_repos.union(state_only_repos).cloned().collect();
    let mut filters = state_event_filters_for_our_repos(&all_repos, since);
    if !full_repos.is_empty() {
        filters.extend(
            tiered_repo_event_filters(full_repos, false, since)
                .into_iter()
                .filter(|entry| entry.tier == CoverageTier::EssentialCore)
                .map(|entry| entry.filter),
        );
    }
    filters.extend(
        tiered_root_event_filters(root_events, false, since)
            .into_iter()
            .filter(|entry| entry.tier == CoverageTier::EssentialCore)
            .map(|entry| entry.filter),
    );
    filters
}

/// Build the priority-ordered core reference coverage that can move between a
/// persistent subscription and paced REQ+EOSE rotation.
pub fn tiered_auxiliary_core_filters(
    full_repos: &HashSet<String>,
    root_events: &HashSet<EventId>,
    since: Option<Timestamp>,
) -> Vec<TieredFilter> {
    let mut filters = tiered_root_event_filters(root_events, false, since);
    filters.extend(tiered_repo_event_filters(full_repos, false, since));
    filters.retain(|entry| entry.tier != CoverageTier::EssentialCore);
    filters.sort_by_key(|entry| entry.tier);
    filters
}

fn tagged_filters<T: AsRef<str>>(
    values: &[T],
    tag: SingleLetterTag,
    since: Option<Timestamp>,
) -> Vec<Filter> {
    chunk_values_by_bytes(values)
        .into_iter()
        .map(|chunk| {
            let mut filter = Filter::new();
            for value in chunk {
                filter = filter.custom_tag(tag, value.as_ref());
            }
            match since {
                Some(timestamp) => filter.since(timestamp),
                None => filter,
            }
        })
        .collect()
}

fn tiered_tagged_filters<T: AsRef<str>>(
    values: &[T],
    tiers: &[(CoverageTier, SingleLetterTag)],
    since: Option<Timestamp>,
) -> Vec<TieredFilter> {
    tiers
        .iter()
        .flat_map(|(tier, tag)| {
            tagged_filters(values, *tag, since)
                .into_iter()
                .map(|filter| TieredFilter {
                    tier: *tier,
                    filter,
                })
        })
        .collect()
}

/// Priority-labelled filters for repository coordinates.
pub fn tiered_repo_event_filters(
    repos: &HashSet<String>,
    descendant: bool,
    since: Option<Timestamp>,
) -> Vec<TieredFilter> {
    let mut values: Vec<_> = repos.iter().collect();
    values.sort_unstable();
    let tiers = if descendant {
        [
            (
                CoverageTier::DescendantCanonical,
                SingleLetterTag::LOWERCASE_A,
            ),
            (CoverageTier::DescendantQuote, SingleLetterTag::LOWERCASE_Q),
            (CoverageTier::HistoricOnly, SingleLetterTag::UPPERCASE_A),
        ]
    } else {
        [
            (CoverageTier::EssentialCore, SingleLetterTag::LOWERCASE_A),
            (
                CoverageTier::CoreCompatibility,
                SingleLetterTag::UPPERCASE_A,
            ),
            (
                CoverageTier::CoreCompatibility,
                SingleLetterTag::LOWERCASE_Q,
            ),
        ]
    };
    tiered_tagged_filters(&values, &tiers, since)
}

/// Priority-labelled filters for event references.
pub fn tiered_root_event_filters(
    root_events: &HashSet<EventId>,
    descendant: bool,
    since: Option<Timestamp>,
) -> Vec<TieredFilter> {
    let mut values: Vec<String> = root_events.iter().map(EventId::to_hex).collect();
    values.sort_unstable();
    let tiers = if descendant {
        [
            (
                CoverageTier::DescendantCanonical,
                SingleLetterTag::LOWERCASE_E,
            ),
            (CoverageTier::DescendantQuote, SingleLetterTag::LOWERCASE_Q),
            (CoverageTier::HistoricOnly, SingleLetterTag::UPPERCASE_E),
        ]
    } else {
        [
            (CoverageTier::EssentialCore, SingleLetterTag::LOWERCASE_E),
            (CoverageTier::RootUppercase, SingleLetterTag::UPPERCASE_E),
            (
                CoverageTier::CoreCompatibility,
                SingleLetterTag::LOWERCASE_Q,
            ),
        ]
    };
    tiered_tagged_filters(&values, &tiers, since)
}

/// Serialized byte budget of tag values per filter chunk.
///
/// Relay filter limits are byte caps, not item counts: strfry bounds the
/// concatenated tag values of a filter set at 65535 bytes, and the whole
/// message must fit relay maximum message sizes (128 KB floor observed via
/// NIP-11, which cannot advertise per-filter limits at all). 32 KB per
/// filter is half strfry's per-filter cap, and a full chunk's ~33 KB
/// NEG-OPEN message keeps ~1.8× margin under the 60 KB negentropy frame
/// limit our own embedded relay (nostr-sdk local relay) enforces. Three
/// full chunks grouped into one REQ fit the 96 KB message budget — which
/// also matches strfry's optional strict `filterValidation` limit of three
/// filters per REQ. Persistent subscription count scales with how full
/// each REQ is packed and negentropy round count scales with chunk size,
/// so maximising both budgets together minimises both costs. See
/// docs/explanation/sync-scaling-constraints.md.
pub const FILTER_VALUE_BYTE_BUDGET: usize = 32 * 1024;

/// Split `values` into contiguous chunks whose serialized tag-value bytes
/// stay within [`FILTER_VALUE_BYTE_BUDGET`].
///
/// Each value costs its UTF-8 length plus JSON quoting and separator
/// overhead. A single value larger than the budget still gets its own
/// chunk, so progress is always made.
fn chunk_values_by_bytes<T: AsRef<str>>(values: &[T]) -> Vec<&[T]> {
    // Two quotes and a separator per value in the serialized JSON array.
    const VALUE_OVERHEAD: usize = 3;

    let mut chunks = Vec::new();
    let mut start = 0;
    let mut bytes = 0;
    for (idx, value) in values.iter().enumerate() {
        let cost = value.as_ref().len() + VALUE_OVERHEAD;
        if idx > start && bytes + cost > FILTER_VALUE_BYTE_BUDGET {
            chunks.push(&values[start..idx]);
            start = idx;
            bytes = 0;
        }
        bytes += cost;
    }
    if start < values.len() {
        chunks.push(&values[start..]);
    }
    chunks
}

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
/// connect when `NGIT_GRASP_P_REPOS_ENABLE=true`, NOT part of consolidation
/// rebuilds. Registrations are small and bounded by the private global
/// budget, so an unscoped 30640 subscription is acceptable (mirrors the
/// unscoped 30617 Layer-1 treatment).
pub fn build_private_registration_filter(since: Option<Timestamp>) -> Filter {
    let filter = Filter::new().kind(Kind::Custom(crate::grasp_p::KIND_REGISTRATION));
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
/// comes from [`crate::grasp_p::stream_wrap_kinds`] so it cannot drift from
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
        let mut filter = Filter::new().kind(Kind::Custom(crate::grasp_p::KIND_STATE_ROOT));
        for alias in chunk {
            filter = filter.custom_tag(SingleLetterTag::lowercase(Alphabet::D), alias.as_str());
        }
        if let Some(ts) = since {
            filter = filter.since(ts);
        }
        filters.push(filter);
    }

    // Stream wraps authored by registered w/aux keys, chunked per 100.
    let wrap_kinds: Vec<Kind> = crate::grasp_p::stream_wrap_kinds(accept_legacy_wrap_kind)
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
/// - One filter can include multiple identifiers (byte-budgeted batches)
/// - Avoids 1000+ rejections for repos we don't care about
///
/// # Arguments
/// * `repos` - Set of repo addressable refs (format: 30617:pubkey:identifier)
/// * `since` - Optional timestamp for incremental sync
///
/// # Returns
/// Vec of filters, one filter per byte-budgeted identifier chunk
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
    let mut identifier_vec: Vec<_> = identifiers.iter().collect();
    identifier_vec.sort_unstable();

    // Batch identifiers per filter within the serialized byte budget
    for chunk in chunk_values_by_bytes(&identifier_vec) {
        let mut filter = Filter::new().kind(Kind::RepoState); // kind 30618

        // Add #d tags for all identifiers in this chunk
        for identifier in chunk {
            filter = filter.custom_tag(SingleLetterTag::LOWERCASE_D, identifier.as_str());
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
/// Batched by serialized byte budget.
///
/// # Arguments
/// * `repos` - Set of repo addressable refs (format: 30617:pubkey:identifier)
/// * `since` - Optional timestamp for incremental sync
///
/// # Returns
/// Vec of filters, one set of 3 filters (a/A/q) per byte-budgeted chunk
pub fn tagged_one_of_our_repo_event_filters(
    repos: &HashSet<String>,
    since: Option<Timestamp>,
) -> Vec<Filter> {
    if repos.is_empty() {
        return vec![];
    }

    let mut filters = Vec::new();
    let mut repo_refs: Vec<_> = repos.iter().collect();
    repo_refs.sort_unstable();

    for chunk in chunk_values_by_bytes(&repo_refs) {
        // Lowercase 'a' tag - standard addressable reference
        let mut f1 = Filter::new();
        for repo in chunk {
            f1 = f1.custom_tag(SingleLetterTag::LOWERCASE_A, repo.as_str());
        }

        // Uppercase 'A' tag - some clients use this
        let mut f2 = Filter::new();
        for repo in chunk {
            f2 = f2.custom_tag(SingleLetterTag::UPPERCASE_A, repo.as_str());
        }

        // Quote 'q' tag - NIP-10 quote references to addressable events
        let mut f3 = Filter::new();
        for repo in chunk {
            f3 = f3.custom_tag(SingleLetterTag::LOWERCASE_Q, repo.as_str());
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
/// Batched by serialized byte budget.
///
/// # Arguments
/// * `root_events` - Set of event IDs (1617/1618/1621 root events)
/// * `since` - Optional timestamp for incremental sync
///
/// # Returns
/// Vec of filters, one set of 3 filters (e/E/q) per byte-budgeted chunk
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
    let mut event_ids: Vec<String> = root_events.iter().map(|id| id.to_hex()).collect();
    event_ids.sort_unstable();

    for (chunk_idx, chunk) in chunk_values_by_bytes(&event_ids).into_iter().enumerate() {
        // Lowercase 'e' tag - standard event reference
        let mut f1 = Filter::new();
        for event_id in chunk {
            f1 = f1.custom_tag(SingleLetterTag::LOWERCASE_E, event_id.as_str());
        }

        // Uppercase 'E' tag - some clients use this
        let mut f2 = Filter::new();
        for event_id in chunk {
            f2 = f2.custom_tag(SingleLetterTag::UPPERCASE_E, event_id.as_str());
        }

        // Quote 'q' tag - NIP-10 quote references to events
        let mut f3 = Filter::new();
        for event_id in chunk {
            f3 = f3.custom_tag(SingleLetterTag::LOWERCASE_Q, event_id.as_str());
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
    fn core_reference_filters_have_stable_priority_tiers() {
        let repos = HashSet::from(["30617:pubkey:repo".to_string()]);
        let roots = HashSet::from([EventId::from_byte_array([0; 32])]);

        let repo_tiers: Vec<_> = tiered_repo_event_filters(&repos, false, None)
            .into_iter()
            .map(|entry| entry.tier)
            .collect();
        assert_eq!(
            repo_tiers,
            [
                CoverageTier::EssentialCore,
                CoverageTier::CoreCompatibility,
                CoverageTier::CoreCompatibility,
            ]
        );

        let root_tiers: Vec<_> = tiered_root_event_filters(&roots, false, None)
            .into_iter()
            .map(|entry| entry.tier)
            .collect();
        assert_eq!(
            root_tiers,
            [
                CoverageTier::EssentialCore,
                CoverageTier::RootUppercase,
                CoverageTier::CoreCompatibility,
            ]
        );
    }

    #[test]
    fn descendant_reference_filters_put_uppercase_tags_in_history_only() {
        let repos = HashSet::from(["1621:pubkey:patch".to_string()]);
        let roots = HashSet::from([EventId::from_byte_array([0; 32])]);

        for tiers in [
            tiered_repo_event_filters(&repos, true, None),
            tiered_root_event_filters(&roots, true, None),
        ] {
            assert_eq!(
                tiers
                    .into_iter()
                    .map(|entry| entry.tier)
                    .collect::<Vec<_>>(),
                [
                    CoverageTier::DescendantCanonical,
                    CoverageTier::DescendantQuote,
                    CoverageTier::HistoricOnly,
                ]
            );
        }
    }

    #[test]
    fn test_repo_filters_batching() {
        // Each ref serializes to exactly 1024 bytes (1021 + quoting overhead),
        // so a chunk holds exactly FILTER_VALUE_BYTE_BUDGET / 1024 refs;
        // build two full chunks plus a partial third.
        let per_chunk = FILTER_VALUE_BYTE_BUDGET / 1024;
        let mut repos = HashSet::new();
        for i in 0..(2 * per_chunk + per_chunk / 2) {
            let identifier = format!("{i:0>4}{}", "x".repeat(1021 - 4 - "30617:pubkey:".len()));
            repos.insert(format!("30617:pubkey:{identifier}"));
        }

        let filters = tagged_one_of_our_repo_event_filters(&repos, None);

        // Should create 9 filters (3 byte-budgeted chunks * 3 tag types)
        assert_eq!(filters.len(), 9);
    }

    #[test]
    fn test_repo_filters_small_refs_consolidate_into_one_chunk() {
        // 250 short refs fit one byte-budgeted chunk (previously 3 chunks
        // under the fixed 100-item rule).
        let mut repos = HashSet::new();
        for i in 0..250 {
            repos.insert(format!("30617:pubkey{}:repo{}", i, i));
        }

        let filters = tagged_one_of_our_repo_event_filters(&repos, None);

        // One chunk * 3 tag types
        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn repo_and_state_filter_serialization_is_insertion_order_independent() {
        let ascending: HashSet<String> = (0..700)
            .map(|index| format!("30617:pubkey:{index:04}-{}", "x".repeat(48)))
            .collect();
        let descending: HashSet<String> = (0..700)
            .rev()
            .map(|index| format!("30617:pubkey:{index:04}-{}", "x".repeat(48)))
            .collect();

        let repo_ascending: Vec<String> = tagged_one_of_our_repo_event_filters(&ascending, None)
            .into_iter()
            .map(|filter| filter.as_json())
            .collect();
        let repo_descending: Vec<String> = tagged_one_of_our_repo_event_filters(&descending, None)
            .into_iter()
            .map(|filter| filter.as_json())
            .collect();
        assert_eq!(repo_ascending, repo_descending);

        let state_ascending: Vec<String> = state_event_filters_for_our_repos(&ascending, None)
            .into_iter()
            .map(|filter| filter.as_json())
            .collect();
        let state_descending: Vec<String> = state_event_filters_for_our_repos(&descending, None)
            .into_iter()
            .map(|filter| filter.as_json())
            .collect();
        assert_eq!(state_ascending, state_descending);
    }

    #[test]
    fn test_chunk_values_by_bytes_edge_cases() {
        // Empty input -> no chunks.
        let empty: Vec<String> = vec![];
        assert!(chunk_values_by_bytes(&empty).is_empty());

        // A single value larger than the whole budget still gets a chunk.
        let oversized = vec!["x".repeat(FILTER_VALUE_BYTE_BUDGET * 2)];
        let chunks = chunk_values_by_bytes(&oversized);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 1);

        // Exact fit: values costing 1024 bytes each fill a chunk exactly.
        let per_chunk = FILTER_VALUE_BYTE_BUDGET / 1024;
        let values: Vec<String> = (0..per_chunk + 1).map(|i| format!("{i:0>1021}")).collect();
        let chunks = chunk_values_by_bytes(&values);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), per_chunk);
        assert_eq!(chunks[1].len(), 1);
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
        root_events.insert(EventId::from_byte_array([0; 32]));

        let filters = tagged_one_of_our_root_event_filters(&root_events, None);

        // Should create 3 filters (e, E, q) for one chunk
        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_root_event_filters_batching() {
        let mut root_events = HashSet::new();
        // EventId::from_byte_array([0; 32]) will deduplicate, so we need unique IDs
        // For testing purposes, we'll just verify with one ID since HashSet
        // deduplicates all_zeros(). In real usage these would be unique.
        for _ in 0..250 {
            root_events.insert(EventId::from_byte_array([0; 32]));
        }

        let filters = tagged_one_of_our_root_event_filters(&root_events, None);

        // With deduplication, we only have 1 unique ID, so 3 filters
        // In real usage with 250 unique IDs, it would be 9 filters
        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_root_event_filters_with_since() {
        let mut root_events = HashSet::new();
        root_events.insert(EventId::from_byte_array([0; 32]));

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
        root_events.insert(EventId::from_byte_array([0; 32]));

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
        root_events.insert(EventId::from_byte_array([0; 32]));

        let filters = build_layer2_and_layer3_filters(&repos, &root_events, None);

        // Should have 3 filters (3 for root events only)
        assert_eq!(filters.len(), 3);
    }

    #[test]
    fn test_combined_filters_with_since() {
        let mut repos = HashSet::new();
        repos.insert("30617:abc123:repo1".to_string());

        let mut root_events = HashSet::new();
        root_events.insert(EventId::from_byte_array([0; 32]));

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
        // Each identifier costs exactly 1024 serialized bytes, so a chunk
        // holds exactly FILTER_VALUE_BYTE_BUDGET / 1024 identifiers; build
        // two full chunks plus a partial third.
        let per_chunk = FILTER_VALUE_BYTE_BUDGET / 1024;
        let mut repos = HashSet::new();
        for i in 0..(2 * per_chunk + per_chunk / 2) {
            let identifier = format!("{i:0>4}{}", "x".repeat(1021 - 4));
            repos.insert(format!("30617:pubkey{i}:{identifier}"));
        }

        let filters = state_event_filters_for_our_repos(&repos, None);

        // Should create 3 byte-budgeted filters
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
