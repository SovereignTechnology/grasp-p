//! Narrow GRASP-03 mailbox discovery primitives.

use std::collections::{HashMap, HashSet};

use nostr::nips::nip65::{self, RelayMetadata};
use nostr_sdk::prelude::*;

use super::{
    algorithms::RelaySyncNeeds, canonical_relay_key, target_hygiene, RepoSyncNeeds, SyncLevel,
};
use crate::outbound::OutboundTargetPolicy;

/// Hard ceiling on the relays selected per author and purpose from one kind
/// 10002 list. NIP-65 already guides users toward two to four relays per
/// category; this is a defensive resource boundary, deliberately not a
/// configuration option, so one hostile list cannot inflate mailbox
/// inventory regardless of its size.
pub const MAX_RELAYS_PER_AUTHOR_PURPOSE: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRoot {
    pub id: EventId,
    pub author: PublicKey,
    pub repository: String,
}

pub fn accepted_root_candidates<'a>(
    candidates: impl IntoIterator<Item = &'a AcceptedRoot>,
    repositories: &HashMap<String, RepoSyncNeeds>,
) -> Vec<AcceptedRoot> {
    candidates
        .into_iter()
        .filter(|root| {
            repositories
                .get(&root.repository)
                .is_some_and(|needs| needs.sync_level == SyncLevel::Full)
        })
        .cloned()
        .collect()
}

pub fn accepted_roots<'a>(
    events: impl IntoIterator<Item = &'a Event>,
    accepted_repositories: &HashSet<String>,
) -> Vec<AcceptedRoot> {
    events
        .into_iter()
        .filter(|event| {
            matches!(
                event.kind,
                Kind::GitPatch | Kind::GitIssue | Kind::GitPullRequest
            ) && event.tags.iter().any(|tag| {
                let values = tag.as_slice();
                values.len() >= 2
                    && matches!(values[0].as_str(), "a" | "A" | "q")
                    && accepted_repositories.contains(&values[1])
            })
        })
        .filter_map(|event| {
            let repository = event.tags.iter().find_map(|tag| {
                let values = tag.as_slice();
                (values.len() >= 2
                    && matches!(values[0].as_str(), "a" | "A" | "q")
                    && accepted_repositories.contains(&values[1]))
                .then(|| values[1].clone())
            })?;
            Some(AcceptedRoot {
                id: event.id,
                author: event.pubkey,
                repository,
            })
        })
        .collect()
}

pub fn latest_relay_lists(
    events: impl IntoIterator<Item = Event>,
    requested_authors: &HashSet<PublicKey>,
) -> HashMap<PublicKey, Event> {
    let mut latest = HashMap::<PublicKey, Event>::new();
    for event in events {
        if event.kind != Kind::RelayList || !requested_authors.contains(&event.pubkey) {
            continue;
        }
        let replace = latest.get(&event.pubkey).is_none_or(|current| {
            event.created_at > current.created_at
                || (event.created_at == current.created_at && event.id < current.id)
        });
        if replace {
            latest.insert(event.pubkey, event);
        }
    }
    latest
}

/// Select the NIP-01-preferred profile and relay list for each requested
/// author. Keeping selection here prevents a permissive source from making us
/// process retained replaceable history that clients will never query.
pub fn latest_identity_events(
    events: impl IntoIterator<Item = Event>,
    requested_authors: &HashSet<PublicKey>,
) -> Vec<Event> {
    let mut latest = HashMap::<(PublicKey, u16), Event>::new();
    for event in events {
        if !matches!(event.kind, Kind::Metadata | Kind::RelayList)
            || !requested_authors.contains(&event.pubkey)
        {
            continue;
        }
        let key = (event.pubkey, event.kind.as_u16());
        let replace = latest.get(&key).is_none_or(|current| {
            event.created_at > current.created_at
                || (event.created_at == current.created_at && event.id < current.id)
        });
        if replace {
            latest.insert(key, event);
        }
    }
    let mut events: Vec<Event> = latest.into_values().collect();
    events.sort_by_key(|event| (event.pubkey.to_hex(), event.kind.as_u16()));
    events
}

/// Hygiene-filtered, canonicalized relay entries in published tag order,
/// deduplicated by canonical key so trailing-root-slash and default-port
/// variants cannot consume multiple selection slots. A duplicate keeps its
/// first position; when duplicate listings disagree on markers, the entry
/// widens to unmarked (both roles), matching NIP-65's union semantics.
/// Non-root paths and query strings remain distinct targets. Tag order is
/// preserved here so every bounded selection below is deterministic ("first
/// four" in the author's published order).
fn canonical_relay_entries(
    event: &Event,
    policy: &OutboundTargetPolicy,
) -> Vec<(String, Option<RelayMetadata>)> {
    if event.kind != Kind::RelayList {
        return Vec::new();
    }
    let mut positions: HashMap<String, usize> = HashMap::new();
    let mut entries: Vec<(String, Option<RelayMetadata>)> = Vec::new();
    for tag in event.tags.iter() {
        // Parse with the same upstream semantics as
        // `nip65::extract_relay_list`, but keep the tag's original URL
        // string: the hygiene length rule measures the wire form, which
        // normalization can shorten.
        let Ok(nip65::Nip65Tag::RelayMetadata {
            relay_url: relay,
            metadata: marker,
        }) = nip65::Nip65Tag::try_from(tag)
        else {
            continue;
        };
        let Some(original) = tag.as_slice().get(1) else {
            continue;
        };
        if !target_hygiene::accepts(original, &relay, policy) {
            continue;
        }
        let Ok(key) = canonical_relay_key(relay.as_str()) else {
            continue;
        };
        match positions.get(&key) {
            None => {
                positions.insert(key.clone(), entries.len());
                entries.push((key, marker));
            }
            Some(&position) => {
                if entries[position].1 != marker {
                    entries[position].1 = None;
                }
            }
        }
    }
    entries
}

/// Up to [`MAX_RELAYS_PER_AUTHOR_PURPOSE`] canonical `read`/unmarked relays
/// in published tag order: the author's live inbox coverage.
pub fn inbox_relays(event: &Event, policy: &OutboundTargetPolicy) -> HashSet<String> {
    canonical_relay_entries(event, policy)
        .into_iter()
        .filter(|(_, marker)| matches!(marker, None | Some(RelayMetadata::Read)))
        .map(|(relay, _)| relay)
        .take(MAX_RELAYS_PER_AUTHOR_PURPOSE)
        .collect()
}

/// Up to [`MAX_RELAYS_PER_AUTHOR_PURPOSE`] canonical `write`/unmarked relays
/// in published tag order: identity-refresh sources for the author.
pub fn outbox_relays(event: &Event, policy: &OutboundTargetPolicy) -> HashSet<String> {
    canonical_relay_entries(event, policy)
        .into_iter()
        .filter(|(_, marker)| matches!(marker, None | Some(RelayMetadata::Write)))
        .map(|(relay, _)| relay)
        .take(MAX_RELAYS_PER_AUTHOR_PURPOSE)
        .collect()
}

/// Authors whose identity is part of accepted Full repository state: owners
/// and declared maintainers. Root authors are merged by the caller because
/// their compact candidate index is maintained separately.
pub fn accepted_repository_authors<'a>(
    announcements: impl IntoIterator<Item = &'a Event>,
    repositories: &HashMap<String, RepoSyncNeeds>,
) -> HashSet<PublicKey> {
    accepted_repository_author_repositories(announcements, repositories)
        .into_keys()
        .collect()
}

/// Associate owners and declared maintainers with each accepted Full
/// repository. The caller may use this for repository-scoped mailbox history;
/// keeping the coordinate provenance here prevents one maintainer's relay list
/// from broadening coverage to unrelated repositories.
pub fn accepted_repository_author_repositories<'a>(
    announcements: impl IntoIterator<Item = &'a Event>,
    repositories: &HashMap<String, RepoSyncNeeds>,
) -> HashMap<PublicKey, HashSet<String>> {
    let mut author_repositories: HashMap<PublicKey, HashSet<String>> = HashMap::new();
    for event in announcements {
        if event.kind != Kind::GitRepoAnnouncement {
            continue;
        }
        let Some(identifier) = event.tags.iter().find_map(|tag| {
            let values = tag.as_slice();
            (values.first().map(String::as_str) == Some("d") && values.len() >= 2)
                .then(|| values[1].clone())
        }) else {
            continue;
        };
        let repository = format!("30617:{}:{identifier}", event.pubkey);
        if !repositories
            .get(&repository)
            .is_some_and(|needs| needs.sync_level == SyncLevel::Full)
        {
            continue;
        }
        author_repositories
            .entry(event.pubkey)
            .or_default()
            .insert(repository.clone());
        // Include every currently-listed maintainer (active `M`/`m` role tags
        // or the deprecated maintainers fallback). Invited pubkeys are
        // included deliberately: their announcements must be fetched so we
        // notice when they accept the role. Ended roles are excluded.
        if let Ok(announcement) =
            crate::nostr::events::RepositoryAnnouncement::from_event(event.clone())
        {
            for author in announcement
                .listed_maintainers()
                .iter()
                .filter_map(|value| PublicKey::from_hex(value).ok())
            {
                author_repositories
                    .entry(author)
                    .or_default()
                    .insert(repository.clone());
            }
        }
    }
    author_repositories
}

/// Associate each accepted root author with their own roots and each accepted
/// descendant author with the root provenance derived for their events.
pub fn mailbox_author_roots(
    roots: &[AcceptedRoot],
    participant_roots: impl IntoIterator<Item = (PublicKey, HashSet<EventId>)>,
) -> HashMap<PublicKey, HashSet<EventId>> {
    let mut author_roots: HashMap<PublicKey, HashSet<EventId>> = HashMap::new();
    for root in roots {
        author_roots.entry(root.author).or_default().insert(root.id);
    }
    for (author, accepted_roots) in participant_roots {
        author_roots
            .entry(author)
            .or_default()
            .extend(accepted_roots);
    }
    author_roots
}

pub fn merge_inbox_roots(
    targets: &mut HashMap<String, RelaySyncNeeds>,
    inbox_roots: &HashMap<String, HashSet<EventId>>,
) {
    for (relay, roots) in inbox_roots {
        targets
            .entry(relay.clone())
            .or_default()
            .root_events
            .extend(roots.iter().copied());
    }
}

pub fn build_inbox_root_overlay(
    author_roots: &HashMap<PublicKey, HashSet<EventId>>,
    author_inboxes: &HashMap<PublicKey, HashSet<String>>,
    fallback_authors: &HashSet<PublicKey>,
    fallback_relays: &HashSet<String>,
) -> HashMap<String, HashSet<EventId>> {
    let mut overlay: HashMap<String, HashSet<EventId>> = HashMap::new();
    for (author, inboxes) in author_inboxes {
        let Some(roots) = author_roots.get(author) else {
            continue;
        };
        for inbox in inboxes {
            overlay
                .entry(inbox.clone())
                .or_default()
                .extend(roots.iter().copied());
        }
    }
    for author in fallback_authors {
        let Some(roots) = author_roots.get(author) else {
            continue;
        };
        for relay in fallback_relays {
            overlay
                .entry(relay.clone())
                .or_default()
                .extend(roots.iter().copied());
        }
    }
    overlay
}

/// Build the history-only repository scope advertised by accepted repository
/// owners and maintainers. This is deliberately separate from root provenance:
/// repository scope may discover roots not yet present locally, while a thread
/// participant remains constrained to roots in which they actually appeared.
pub fn build_mailbox_repository_overlay(
    author_repositories: &HashMap<PublicKey, HashSet<String>>,
    author_mailboxes: &HashMap<PublicKey, HashSet<String>>,
    fallback_authors: &HashSet<PublicKey>,
    fallback_relays: &HashSet<String>,
) -> HashMap<String, HashSet<String>> {
    let mut overlay: HashMap<String, HashSet<String>> = HashMap::new();
    for (author, mailboxes) in author_mailboxes {
        let Some(repositories) = author_repositories.get(author) else {
            continue;
        };
        for mailbox in mailboxes {
            overlay
                .entry(mailbox.clone())
                .or_default()
                .extend(repositories.iter().cloned());
        }
    }
    for author in fallback_authors {
        let Some(repositories) = author_repositories.get(author) else {
            continue;
        };
        for relay in fallback_relays {
            overlay
                .entry(relay.clone())
                .or_default()
                .extend(repositories.iter().cloned());
        }
    }
    overlay
}

/// Up to [`MAX_RELAYS_PER_AUTHOR_PURPOSE`] canonical relays on which an
/// author's conversation history should be probed. `write` and unmarked
/// relays are preferred in published tag order because authored contributions
/// are downloaded from where the author publishes; any remaining slots are
/// filled from read-only relays in published order. Deduplication by
/// canonical key happens before selection, so an unmarked relay serving both
/// roles consumes exactly one slot.
pub fn mailbox_relays(event: &Event, policy: &OutboundTargetPolicy) -> HashSet<String> {
    let entries = canonical_relay_entries(event, policy);
    let mut selected: Vec<String> = entries
        .iter()
        .filter(|(_, marker)| matches!(marker, None | Some(RelayMetadata::Write)))
        .map(|(relay, _)| relay.clone())
        .take(MAX_RELAYS_PER_AUTHOR_PURPOSE)
        .collect();
    selected.extend(
        entries
            .iter()
            .filter(|(_, marker)| matches!(marker, Some(RelayMetadata::Read)))
            .map(|(relay, _)| relay.clone())
            .take(MAX_RELAYS_PER_AUTHOR_PURPOSE - selected.len()),
    );
    selected.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(keys: &Keys, kind: Kind, tags: Vec<Tag>, timestamp: u64) -> Event {
        EventBuilder::new(kind, "")
            .tags(tags)
            .custom_created_at(Timestamp::from(timestamp))
            .finalize(keys)
            .expect("sign event")
    }

    #[test]
    fn accepted_roots_require_a_known_repository() {
        let keys = Keys::generate();
        let coord = format!("30617:{}:repo", keys.public_key());
        let accepted = event(
            &keys,
            Kind::GitIssue,
            vec![Tag::custom("a", vec![coord.clone()])],
            1,
        );
        let unrelated = event(
            &keys,
            Kind::GitIssue,
            vec![Tag::custom("a", vec!["30617:other:repo"])],
            2,
        );
        let reply = event(
            &keys,
            Kind::TextNote,
            vec![Tag::custom("a", vec![coord.clone()])],
            3,
        );
        let roots = accepted_roots(
            [&accepted, &unrelated, &reply],
            &HashSet::from([coord.clone()]),
        );
        assert_eq!(
            roots,
            vec![AcceptedRoot {
                id: accepted.id,
                author: keys.public_key(),
                repository: coord,
            }]
        );
    }

    #[test]
    fn relay_list_maps_read_and_unmarked_but_not_write() {
        let keys = Keys::generate();
        let relay_list = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", vec!["wss://read.example", "read"]),
                Tag::custom("r", vec!["wss://write.example", "write"]),
                Tag::custom("r", vec!["wss://both.example"]),
            ],
            1,
        );
        assert_eq!(
            inbox_relays(&relay_list, &OutboundTargetPolicy::default()),
            HashSet::from([
                "wss://read.example".to_string(),
                "wss://both.example".to_string()
            ])
        );
    }

    #[test]
    fn relay_list_maps_write_and_unmarked_outboxes_but_not_read() {
        let keys = Keys::generate();
        let relay_list = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", ["wss://read.example", "read"]),
                Tag::custom("r", ["wss://write.example", "write"]),
                Tag::custom("r", ["wss://both.example"]),
            ],
            1,
        );
        assert_eq!(
            outbox_relays(&relay_list, &OutboundTargetPolicy::default()),
            HashSet::from([
                "wss://write.example".to_string(),
                "wss://both.example".to_string(),
            ])
        );
    }

    #[test]
    fn relay_list_maps_read_write_and_unmarked_participant_mailboxes() {
        let keys = Keys::generate();
        let relay_list = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", ["wss://read.example", "read"]),
                Tag::custom("r", ["wss://write.example", "write"]),
                Tag::custom("r", ["wss://both.example"]),
            ],
            1,
        );
        assert_eq!(
            mailbox_relays(&relay_list, &OutboundTargetPolicy::default()),
            HashSet::from([
                "wss://read.example".to_string(),
                "wss://write.example".to_string(),
                "wss://both.example".to_string(),
            ])
        );
    }

    #[test]
    fn relay_extraction_applies_target_hygiene_to_every_role() {
        let keys = Keys::generate();
        let relay_list = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", ["wss://read.example", "read"]),
                Tag::custom("r", ["wss://write.example", "write"]),
                Tag::custom("r", ["wss://spam.example/alpha-bravo", "read"]),
                Tag::custom("r", ["wss://spam.example/foxtrot-yonder", "write"]),
                Tag::custom("r", ["wss://hidden.onion"]),
                Tag::custom("r", ["ws://127.0.0.1:7334"]),
            ],
            1,
        );
        let policy = OutboundTargetPolicy::default();
        assert_eq!(
            inbox_relays(&relay_list, &policy),
            HashSet::from(["wss://read.example".to_string()])
        );
        assert_eq!(
            outbox_relays(&relay_list, &policy),
            HashSet::from(["wss://write.example".to_string()])
        );
        assert_eq!(
            mailbox_relays(&relay_list, &policy),
            HashSet::from([
                "wss://read.example".to_string(),
                "wss://write.example".to_string(),
            ])
        );
    }

    #[test]
    fn canonical_duplicates_consume_one_selection_slot() {
        let keys = Keys::generate();
        // Three syntactic variants of one relay must occupy one slot, leaving
        // the remaining three slots for later distinct relays.
        let relay_list = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", ["wss://a.example/", "read"]),
                Tag::custom("r", ["wss://a.example", "read"]),
                Tag::custom("r", ["wss://a.example:443", "read"]),
                Tag::custom("r", ["wss://b.example", "read"]),
                Tag::custom("r", ["wss://c.example", "read"]),
                Tag::custom("r", ["wss://d.example", "read"]),
            ],
            1,
        );
        assert_eq!(
            inbox_relays(&relay_list, &OutboundTargetPolicy::default()),
            HashSet::from([
                "wss://a.example".to_string(),
                "wss://b.example".to_string(),
                "wss://c.example".to_string(),
                "wss://d.example".to_string(),
            ])
        );
    }

    #[test]
    fn oversized_wire_urls_are_rejected_before_normalization_shrinks_them() {
        let keys = Keys::generate();
        // The explicit default port is stripped by parsing, so this URL
        // serializes below the length ceiling while the tag's wire form
        // exceeds it. Hygiene must see the wire form.
        let base = "wss://big.example:443/";
        let oversized = format!(
            "{base}{}",
            "a".repeat(target_hygiene::MAX_PEER_RELAY_URL_BYTES + 1 - base.len())
        );
        let relay_list = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", [oversized.as_str(), "read"]),
                Tag::custom("r", ["wss://small.example", "read"]),
            ],
            1,
        );
        assert_eq!(
            inbox_relays(&relay_list, &OutboundTargetPolicy::default()),
            HashSet::from(["wss://small.example".to_string()])
        );
    }

    #[test]
    fn duplicate_listings_with_conflicting_markers_widen_to_both_roles() {
        let keys = Keys::generate();
        // One relay listed twice (as slash variants) with disagreeing markers
        // serves both roles per NIP-65 union semantics, from one slot.
        let relay_list = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", ["wss://dual.example/", "read"]),
                Tag::custom("r", ["wss://dual.example", "write"]),
            ],
            1,
        );
        let policy = OutboundTargetPolicy::default();
        let expected = HashSet::from(["wss://dual.example".to_string()]);
        assert_eq!(inbox_relays(&relay_list, &policy), expected);
        assert_eq!(outbox_relays(&relay_list, &policy), expected);
        assert_eq!(mailbox_relays(&relay_list, &policy), expected);
    }

    #[test]
    fn selection_is_bounded_to_four_in_published_tag_order() {
        let keys = Keys::generate();
        let tags: Vec<Tag> = (1..=6)
            .map(|n| {
                Tag::custom(
                    "r",
                    [format!("wss://relay-{n}.example"), "read".to_string()],
                )
            })
            .collect();
        let relay_list = event(&keys, Kind::RelayList, tags, 1);
        let policy = OutboundTargetPolicy::default();
        let expected: HashSet<String> = (1..=4)
            .map(|n| format!("wss://relay-{n}.example"))
            .collect();
        assert_eq!(inbox_relays(&relay_list, &policy), expected);
        // Selection is deterministic across repeated evaluations.
        assert_eq!(
            inbox_relays(&relay_list, &policy),
            inbox_relays(&relay_list, &policy)
        );
    }

    #[test]
    fn rejected_urls_do_not_consume_selection_slots() {
        let keys = Keys::generate();
        // Hygiene rejections precede selection, so hostile entries cannot
        // crowd legitimate relays out of the four slots.
        let relay_list = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", ["wss://hidden.onion", "read"]),
                Tag::custom("r", ["wss://spam.example/alpha-bravo", "read"]),
                Tag::custom("r", ["wss://one.example", "read"]),
                Tag::custom("r", ["wss://two.example", "read"]),
                Tag::custom("r", ["wss://three.example", "read"]),
                Tag::custom("r", ["wss://four.example", "read"]),
            ],
            1,
        );
        assert_eq!(
            inbox_relays(&relay_list, &OutboundTargetPolicy::default()),
            HashSet::from([
                "wss://one.example".to_string(),
                "wss://two.example".to_string(),
                "wss://three.example".to_string(),
                "wss://four.example".to_string(),
            ])
        );
    }

    #[test]
    fn participant_history_prefers_write_and_unmarked_relays() {
        let keys = Keys::generate();
        let policy = OutboundTargetPolicy::default();
        // Enough write/unmarked relays: read-only relays are not selected.
        let write_heavy = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", ["wss://read-1.example", "read"]),
                Tag::custom("r", ["wss://write-1.example", "write"]),
                Tag::custom("r", ["wss://unmarked.example"]),
                Tag::custom("r", ["wss://write-2.example", "write"]),
                Tag::custom("r", ["wss://write-3.example", "write"]),
                Tag::custom("r", ["wss://write-4.example", "write"]),
            ],
            1,
        );
        assert_eq!(
            mailbox_relays(&write_heavy, &policy),
            HashSet::from([
                "wss://write-1.example".to_string(),
                "wss://unmarked.example".to_string(),
                "wss://write-2.example".to_string(),
                "wss://write-3.example".to_string(),
            ])
        );
        // Too few write/unmarked relays: read-only relays fill the remaining
        // slots in published order.
        let read_heavy = event(
            &keys,
            Kind::RelayList,
            vec![
                Tag::custom("r", ["wss://read-1.example", "read"]),
                Tag::custom("r", ["wss://read-2.example", "read"]),
                Tag::custom("r", ["wss://write-1.example", "write"]),
                Tag::custom("r", ["wss://read-3.example", "read"]),
                Tag::custom("r", ["wss://read-4.example", "read"]),
            ],
            2,
        );
        assert_eq!(
            mailbox_relays(&read_heavy, &policy),
            HashSet::from([
                "wss://write-1.example".to_string(),
                "wss://read-1.example".to_string(),
                "wss://read-2.example".to_string(),
                "wss://read-3.example".to_string(),
            ])
        );
    }

    #[test]
    fn oversized_relay_list_contributes_bounded_targets_per_purpose() {
        let keys = Keys::generate();
        // The 983-relay corpus shape: one large, machine-generated, unmarked
        // list. Every purpose stays within its four-slot ceiling.
        let tags: Vec<Tag> = (1..=40)
            .map(|n| Tag::custom("r", [format!("wss://generated-{n}.example")]))
            .collect();
        let relay_list = event(&keys, Kind::RelayList, tags, 1);
        let policy = OutboundTargetPolicy::default();
        assert_eq!(
            inbox_relays(&relay_list, &policy).len(),
            MAX_RELAYS_PER_AUTHOR_PURPOSE
        );
        assert_eq!(
            outbox_relays(&relay_list, &policy).len(),
            MAX_RELAYS_PER_AUTHOR_PURPOSE
        );
        assert_eq!(
            mailbox_relays(&relay_list, &policy).len(),
            MAX_RELAYS_PER_AUTHOR_PURPOSE
        );
    }

    #[test]
    fn identity_authors_are_bounded_to_full_repo_owners_and_maintainers() {
        let owner = Keys::generate();
        let maintainer = Keys::generate();
        let ignored = Keys::generate();
        let identifier = "accepted";
        let accepted = event(
            &owner,
            Kind::GitRepoAnnouncement,
            vec![
                Tag::identifier(identifier),
                Tag::custom("maintainers", [maintainer.public_key().to_hex()]),
            ],
            1,
        );
        let state_only = event(
            &ignored,
            Kind::GitRepoAnnouncement,
            vec![Tag::identifier("pending")],
            1,
        );
        let repositories = HashMap::from([
            (
                format!("30617:{}:{identifier}", owner.public_key()),
                RepoSyncNeeds {
                    sync_level: SyncLevel::Full,
                    ..RepoSyncNeeds::default()
                },
            ),
            (
                format!("30617:{}:pending", ignored.public_key()),
                RepoSyncNeeds {
                    sync_level: SyncLevel::StateOnly,
                    ..RepoSyncNeeds::default()
                },
            ),
        ]);

        assert_eq!(
            accepted_repository_authors([&accepted, &state_only], &repositories),
            HashSet::from([owner.public_key(), maintainer.public_key()])
        );
        let author_repositories =
            accepted_repository_author_repositories([&accepted, &state_only], &repositories);
        let accepted_repository = format!("30617:{}:{identifier}", owner.public_key());
        assert_eq!(
            author_repositories,
            HashMap::from([
                (
                    owner.public_key(),
                    HashSet::from([accepted_repository.clone()]),
                ),
                (
                    maintainer.public_key(),
                    HashSet::from([accepted_repository]),
                ),
            ])
        );
    }

    #[test]
    fn descendant_authors_receive_only_their_derived_root_provenance() {
        let first_root_author = Keys::generate().public_key();
        let second_root_author = Keys::generate().public_key();
        let participant = Keys::generate().public_key();
        let first_root = EventId::from_byte_array([12; 32]);
        let second_root = EventId::from_byte_array([13; 32]);
        let roots = vec![
            AcceptedRoot {
                id: first_root,
                author: first_root_author,
                repository: "30617:owner:first".to_string(),
            },
            AcceptedRoot {
                id: second_root,
                author: second_root_author,
                repository: "30617:owner:second".to_string(),
            },
        ];

        let author_roots =
            mailbox_author_roots(&roots, [(participant, HashSet::from([second_root]))]);

        assert_eq!(
            author_roots[&first_root_author],
            HashSet::from([first_root])
        );
        assert_eq!(
            author_roots[&second_root_author],
            HashSet::from([second_root])
        );
        assert_eq!(author_roots[&participant], HashSet::from([second_root]));
    }

    #[test]
    fn latest_relay_list_uses_nip01_replacement_order() {
        let keys = Keys::generate();
        let older = event(&keys, Kind::RelayList, vec![], 1);
        let newer = event(&keys, Kind::RelayList, vec![], 2);
        let selected =
            latest_relay_lists([newer.clone(), older], &HashSet::from([keys.public_key()]));
        assert_eq!(
            selected.get(&keys.public_key()).map(|event| event.id),
            Some(newer.id)
        );
    }

    #[test]
    fn inbox_overlay_adds_only_root_work() {
        let root = EventId::from_byte_array([7; 32]);
        let mut targets = HashMap::new();
        merge_inbox_roots(
            &mut targets,
            &HashMap::from([("wss://inbox.example".to_string(), HashSet::from([root]))]),
        );
        let target = &targets["wss://inbox.example"];
        assert_eq!(target.root_events, HashSet::from([root]));
        assert!(target.repos.is_empty());
        assert!(target.state_only_repos.is_empty());
    }

    #[test]
    fn replacement_and_root_removal_subtract_from_desired_overlay() {
        let author = Keys::generate().public_key();
        let root = EventId::from_byte_array([8; 32]);
        let roots = HashMap::from([(author, HashSet::from([root]))]);
        let first = build_inbox_root_overlay(
            &roots,
            &HashMap::from([(author, HashSet::from(["wss://a.example".to_string()]))]),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert_eq!(first["wss://a.example"], HashSet::from([root]));

        let replacement = build_inbox_root_overlay(
            &roots,
            &HashMap::from([(author, HashSet::from(["wss://b.example".to_string()]))]),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(!replacement.contains_key("wss://a.example"));
        assert_eq!(replacement["wss://b.example"], HashSet::from([root]));
        assert!(build_inbox_root_overlay(
            &HashMap::new(),
            &HashMap::new(),
            &HashSet::new(),
            &HashSet::new()
        )
        .is_empty());
    }

    #[test]
    fn removing_overlay_preserves_ordinary_root_ownership() {
        let root = EventId::from_byte_array([9; 32]);
        let relay = "wss://shared.example".to_string();
        let mut targets = HashMap::from([(
            relay.clone(),
            RelaySyncNeeds {
                root_events: HashSet::from([root]),
                ..RelaySyncNeeds::default()
            },
        )]);
        merge_inbox_roots(&mut targets, &HashMap::new());
        assert_eq!(targets[&relay].root_events, HashSet::from([root]));
    }

    #[test]
    fn state_only_root_becomes_an_inbox_source_after_promotion() {
        let author = Keys::generate().public_key();
        let root = AcceptedRoot {
            id: EventId::from_byte_array([10; 32]),
            author,
            repository: "30617:owner:repo".to_string(),
        };
        let mut repositories = HashMap::from([(
            root.repository.clone(),
            RepoSyncNeeds {
                sync_level: SyncLevel::StateOnly,
                ..RepoSyncNeeds::default()
            },
        )]);
        assert!(accepted_root_candidates([&root], &repositories).is_empty());

        repositories.get_mut(&root.repository).unwrap().sync_level = SyncLevel::Full;
        let accepted = accepted_root_candidates([&root], &repositories);
        let author_roots = accepted.into_iter().fold(
            HashMap::<PublicKey, HashSet<EventId>>::new(),
            |mut roots, accepted| {
                roots
                    .entry(accepted.author)
                    .or_default()
                    .insert(accepted.id);
                roots
            },
        );
        let overlay = build_inbox_root_overlay(
            &author_roots,
            &HashMap::from([(author, HashSet::from(["wss://inbox.example".to_string()]))]),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert_eq!(overlay["wss://inbox.example"], HashSet::from([root.id]));
    }

    #[test]
    fn missing_list_authors_use_only_bounded_fallback_relays() {
        let author = Keys::generate().public_key();
        let unrelated = Keys::generate().public_key();
        let root = EventId::from_byte_array([11; 32]);
        let overlay = build_inbox_root_overlay(
            &HashMap::from([(author, HashSet::from([root]))]),
            &HashMap::new(),
            &HashSet::from([author, unrelated]),
            &HashSet::from([
                "wss://fallback-one.example".to_string(),
                "wss://fallback-two.example".to_string(),
            ]),
        );

        assert_eq!(overlay.len(), 2);
        assert!(overlay
            .values()
            .all(|roots| roots == &HashSet::from([root])));
    }

    #[test]
    fn maintainer_mailboxes_receive_only_their_accepted_repositories() {
        let maintainer = Keys::generate().public_key();
        let unrelated = Keys::generate().public_key();
        let repository = "30617:owner:accepted".to_string();
        let overlay = build_mailbox_repository_overlay(
            &HashMap::from([(maintainer, HashSet::from([repository.clone()]))]),
            &HashMap::from([
                (
                    maintainer,
                    HashSet::from(["wss://maintainer.example".to_string()]),
                ),
                (
                    unrelated,
                    HashSet::from(["wss://unrelated.example".to_string()]),
                ),
            ]),
            &HashSet::new(),
            &HashSet::new(),
        );

        assert_eq!(
            overlay,
            HashMap::from([(
                "wss://maintainer.example".to_string(),
                HashSet::from([repository]),
            )])
        );
    }

    #[test]
    fn missing_maintainer_lists_use_the_bounded_fallback_scope() {
        let maintainer = Keys::generate().public_key();
        let repository = "30617:owner:accepted".to_string();
        let overlay = build_mailbox_repository_overlay(
            &HashMap::from([(maintainer, HashSet::from([repository.clone()]))]),
            &HashMap::new(),
            &HashSet::from([maintainer]),
            &HashSet::from(["wss://fallback.example".to_string()]),
        );

        assert_eq!(
            overlay,
            HashMap::from([(
                "wss://fallback.example".to_string(),
                HashSet::from([repository]),
            )])
        );
    }

    #[test]
    fn identity_selection_keeps_latest_profile_and_relay_list_per_author() {
        let author = Keys::generate();
        let unrelated = Keys::generate();
        let event = |keys: &Keys, kind: Kind, timestamp: u64| {
            EventBuilder::new(kind, timestamp.to_string())
                .custom_created_at(Timestamp::from_secs(timestamp))
                .finalize(keys)
                .unwrap()
        };
        let old_profile = event(&author, Kind::Metadata, 10);
        let profile = event(&author, Kind::Metadata, 20);
        let relay_list = event(&author, Kind::RelayList, 30);
        let ignored = event(&unrelated, Kind::Metadata, 40);

        let selected = latest_identity_events(
            vec![old_profile, profile.clone(), relay_list.clone(), ignored],
            &HashSet::from([author.public_key()]),
        );
        assert_eq!(
            selected
                .iter()
                .map(|event| event.id)
                .collect::<HashSet<_>>(),
            HashSet::from([profile.id, relay_list.id])
        );
    }
}
