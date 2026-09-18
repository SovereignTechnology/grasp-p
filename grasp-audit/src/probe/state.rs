//! Read-side authority and ref comparison for the selected probe coordinate.

use nostr_sdk::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};

fn preferred(left: &Event, right: &Event) -> std::cmp::Ordering {
    left.created_at
        .cmp(&right.created_at)
        .then_with(|| right.id.cmp(&left.id))
}

struct Roles {
    active_author: bool,
    maintainers: HashSet<PublicKey>,
    leads: HashSet<PublicKey>,
}

fn roles(event: &Event) -> Roles {
    let mut result = Roles {
        active_author: true,
        maintainers: HashSet::new(),
        leads: HashSet::new(),
    };
    let mut indexed = false;
    let mut explicit_self = false;
    for tag in event.tags.iter() {
        let values = tag.as_slice();
        if !matches!(values.first().map(String::as_str), Some("M" | "m" | "o")) {
            continue;
        }
        indexed = true;
        let Some(key) = values.get(1).and_then(|key| PublicKey::from_hex(key).ok()) else {
            continue;
        };
        explicit_self |= key == event.pubkey;
        let boundaries = &values[2..];
        // Only a final numeric start (or an untimed role) is active.
        // Ended, deferred and malformed roles grant no current authority.
        let active = (boundaries.is_empty() || boundaries.len() % 2 == 1)
            && boundaries.iter().all(|value| value.parse::<u64>().is_ok());
        if values[0] != "o" && active {
            result.maintainers.insert(key);
            if values[0] == "M" {
                result.leads.insert(key);
            }
        }
    }
    if indexed {
        result.active_author = !explicit_self || result.maintainers.contains(&event.pubkey);
    } else if let Some(tag) = event
        .tags
        .iter()
        .find(|tag| tag.as_slice()[0] == "maintainers")
    {
        result.maintainers.extend(
            tag.as_slice()[1..]
                .iter()
                .filter_map(|key| PublicKey::from_hex(key).ok()),
        );
    }
    result
}

/// Resolve current state publishers from the selected coordinate, not every
/// repository that happens to share its identifier.
fn state_authors(
    announcements: &HashMap<PublicKey, &Event>,
    selected: PublicKey,
) -> Result<HashSet<PublicKey>, String> {
    let graph: HashMap<_, _> = announcements
        .iter()
        .map(|(key, event)| (*key, roles(event)))
        .collect();
    let mut root = selected;
    let mut followed_lead = false;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(root) {
            return Err("repository authority has a lead cycle".into());
        }
        let node = graph
            .get(&root)
            .ok_or("repository authority announcement is missing")?;
        match node.leads.len() {
            0 if !followed_lead && node.active_author => break,
            0 => {
                return Err(
                    "repository authority has an inactive author or incomplete lead path".into(),
                )
            }
            1 => {
                let lead = *node.leads.iter().next().expect("one lead");
                if lead == root {
                    break;
                }
                root = lead;
                followed_lead = true;
            }
            _ => return Err("repository authority has ambiguous active leads".into()),
        }
    }

    let mut confirmed = HashSet::from([root]);
    loop {
        let mut additions = HashSet::new();
        for member in &confirmed {
            for candidate in &graph[member].maintainers {
                if confirmed.contains(candidate) {
                    continue;
                }
                if let Some(node) = graph.get(candidate) {
                    if node.active_author && !node.maintainers.is_disjoint(&confirmed) {
                        additions.insert(*candidate);
                    }
                }
            }
        }
        if additions.is_empty() {
            return Ok(confirmed);
        }
        confirmed.extend(additions);
    }
}

pub(super) fn scoped_state_refs<'a>(
    events: impl IntoIterator<Item = &'a Event>,
    selected: PublicKey,
    identifier: &str,
) -> Result<HashMap<String, String>, String> {
    let events: Vec<_> = events
        .into_iter()
        .filter(|event| {
            matches!(event.kind, Kind::GitRepoAnnouncement | Kind::RepoState)
                && event.tags.identifier().as_deref() == Some(identifier)
                && event.verify().is_ok()
        })
        .collect();
    let mut announcements: HashMap<PublicKey, &Event> = HashMap::new();
    for event in events
        .iter()
        .copied()
        .filter(|event| event.kind == Kind::GitRepoAnnouncement)
    {
        let current = announcements.entry(event.pubkey).or_insert(event);
        if preferred(event, current).is_gt() {
            *current = event;
        }
    }
    let authors = state_authors(&announcements, selected)?;
    let winner = events
        .into_iter()
        .filter(|event| event.kind == Kind::RepoState && authors.contains(&event.pubkey))
        .max_by(|left, right| preferred(left, right))
        .ok_or("no authorized kind:30618 state events found for this repository")?;
    Ok(super::expected_state_refs([winner]))
}

/// Compare only branches and unpeeled tags. HEAD, protocol capabilities,
/// peeled annotated tags and refs/nostr are not repository-state refs.
pub(super) fn ref_mismatches(
    expected: &HashMap<String, String>,
    actual: &[(String, String)],
) -> Vec<String> {
    let actual: BTreeMap<_, _> = actual
        .iter()
        .filter(|(name, _)| {
            (name.starts_with("refs/heads/") || name.starts_with("refs/tags/"))
                && !name.ends_with("^{}")
        })
        .map(|(name, hash)| (name.as_str(), hash.as_str()))
        .collect();
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|(name, hash)| (name.as_str(), hash.as_str()))
        .collect();
    let mut mismatches = Vec::new();
    for (name, hash) in &expected {
        match actual.get(name) {
            Some(actual) if actual == hash => {}
            Some(actual) => mismatches.push(format!("{name}: expected {hash} got {actual}")),
            None => mismatches.push(format!("{name}: expected {hash} not found in refs")),
        }
    }
    for name in actual.keys() {
        if !expected.contains_key(name) {
            mismatches.push(format!("{name}: unexpected ref"));
        }
    }
    mismatches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announcement(keys: &Keys, tags: Vec<Tag>, time: u64) -> Event {
        EventBuilder::new(Kind::GitRepoAnnouncement, "")
            .tags(std::iter::once(Tag::identifier("repo")).chain(tags))
            .custom_created_at(Timestamp::from_secs(time))
            .finalize(keys)
            .unwrap()
    }

    fn role(letter: &str, keys: &Keys, history: &[&str]) -> Tag {
        Tag::custom(
            letter,
            std::iter::once(keys.public_key().to_hex())
                .chain(history.iter().map(|value| value.to_string())),
        )
    }

    fn state(keys: &Keys, time: u64, hash: &str) -> Event {
        EventBuilder::new(Kind::RepoState, "")
            .tags([
                Tag::identifier("repo"),
                Tag::custom("refs/heads/main", [hash]),
            ])
            .custom_created_at(Timestamp::from_secs(time))
            .finalize(keys)
            .unwrap()
    }

    fn selected(events: &[Event], owner: &Keys) -> Result<String, String> {
        scoped_state_refs(events, owner.public_key(), "repo")
            .map(|refs| refs["refs/heads/main"].clone())
    }

    #[test]
    fn unrelated_and_unaccepted_authors_cannot_supply_state() {
        let owner = Keys::generate();
        let unrelated = Keys::generate();
        let invited = Keys::generate();
        let events = vec![
            announcement(&owner, vec![role("m", &invited, &[])], 1),
            announcement(&unrelated, vec![], 1),
            announcement(&invited, vec![], 1),
            state(&owner, 2, "owner"),
            state(&unrelated, 3, "unrelated"),
            state(&invited, 4, "unaccepted"),
        ];
        assert_eq!(selected(&events, &owner).unwrap(), "owner");
    }

    #[test]
    fn reciprocal_membership_reaches_transitive_maintainers() {
        let owner = Keys::generate();
        let member = Keys::generate();
        let third = Keys::generate();
        for legacy in [false, true] {
            let tags = |keys: &[&Keys]| {
                if legacy {
                    vec![Tag::custom(
                        "maintainers",
                        keys.iter().map(|key| key.public_key().to_hex()),
                    )]
                } else {
                    keys.iter().map(|key| role("m", key, &[])).collect()
                }
            };
            let events = vec![
                announcement(&owner, tags(&[&member]), 1),
                announcement(&member, tags(&[&owner, &third]), 1),
                announcement(&third, tags(&[&member]), 1),
                state(&owner, 2, "owner"),
                state(&third, 3, "third"),
            ];
            assert_eq!(selected(&events, &owner).unwrap(), "third");
        }
    }

    #[test]
    fn indexed_roles_override_legacy_and_exclude_inactive_or_moderator_authors() {
        let owner = Keys::generate();
        let member = Keys::generate();
        for self_role in [
            role("m", &member, &["1", "2"]),
            role("m", &member, &["1", "defer"]),
            role("m", &member, &["bad"]),
            role("o", &member, &[]),
        ] {
            let events = vec![
                announcement(&owner, vec![role("m", &member, &[])], 1),
                announcement(&member, vec![role("m", &owner, &[]), self_role], 1),
                state(&owner, 2, "owner"),
                state(&member, 3, "inactive"),
            ];
            assert_eq!(selected(&events, &owner).unwrap(), "owner");
        }
        let events = vec![
            announcement(
                &owner,
                vec![
                    role("o", &member, &[]),
                    Tag::custom("maintainers", [member.public_key().to_hex()]),
                ],
                1,
            ),
            announcement(&member, vec![role("m", &owner, &[])], 1),
            state(&owner, 2, "owner"),
            state(&member, 3, "moderator"),
        ];
        assert_eq!(selected(&events, &owner).unwrap(), "owner");
    }

    #[test]
    fn lead_redirect_does_not_restore_removed_author() {
        let lead = Keys::generate();
        let former = Keys::generate();
        let events = vec![
            announcement(&lead, vec![role("M", &lead, &[])], 1),
            announcement(
                &former,
                vec![role("M", &lead, &[]), role("m", &former, &["1", "2"])],
                1,
            ),
            state(&lead, 2, "lead"),
            state(&former, 3, "removed"),
        ];
        assert_eq!(selected(&events, &former).unwrap(), "lead");
    }

    #[test]
    fn missing_ambiguous_and_cyclic_lead_paths_fail_closed() {
        let owner = Keys::generate();
        let lead = Keys::generate();
        let mut events = vec![
            announcement(&owner, vec![role("M", &lead, &[])], 1),
            state(&owner, 2, "owner"),
        ];
        assert!(selected(&events, &owner).unwrap_err().contains("missing"));
        events.push(announcement(&lead, vec![], 1));
        assert!(selected(&events, &owner)
            .unwrap_err()
            .contains("incomplete"));
        events.pop();
        events.push(announcement(&lead, vec![role("M", &owner, &[])], 1));
        assert!(selected(&events, &owner).unwrap_err().contains("cycle"));
        events[0] = announcement(
            &owner,
            vec![role("M", &owner, &[]), role("M", &lead, &[])],
            1,
        );
        assert!(selected(&events, &owner).unwrap_err().contains("ambiguous"));
    }

    #[test]
    fn latest_announcement_controls_membership_including_same_second_ties() {
        let owner = Keys::generate();
        let member = Keys::generate();
        let mut announcements = [
            announcement(&owner, vec![], 1),
            announcement(&owner, vec![role("m", &member, &[])], 1),
        ];
        announcements.sort_by_key(|event| event.id);
        let grants = roles(&announcements[0])
            .maintainers
            .contains(&member.public_key());
        for reverse in [false, true] {
            let mut events = announcements.to_vec();
            if reverse {
                events.reverse();
            }
            events.extend([
                announcement(&member, vec![role("m", &owner, &[])], 1),
                state(&owner, 2, "owner"),
                state(&member, 3, "member"),
            ]);
            assert_eq!(
                selected(&events, &owner).unwrap(),
                if grants { "member" } else { "owner" }
            );
            events.push(announcement(&owner, vec![], 4));
            assert_eq!(selected(&events, &owner).unwrap(), "owner");
        }
    }

    #[test]
    fn unrelated_identifiers_and_invalid_signatures_are_ignored() {
        let owner = Keys::generate();
        let mut invalid = state(&owner, 100, "invalid");
        invalid.content = "tampered".into();
        let other = EventBuilder::new(Kind::RepoState, "")
            .tags([
                Tag::identifier("other"),
                Tag::custom("refs/heads/main", ["other"]),
            ])
            .custom_created_at(Timestamp::from_secs(100))
            .finalize(&owner)
            .unwrap();
        let events = vec![
            announcement(&owner, vec![], 1),
            state(&owner, 2, "owner"),
            invalid,
            other,
        ];
        assert_eq!(selected(&events, &owner).unwrap(), "owner");
        assert!(scoped_state_refs(&events[..1], owner.public_key(), "repo").is_err());
        assert!(scoped_state_refs(&events[1..], owner.public_key(), "repo").is_err());
    }

    #[test]
    fn ref_comparison_requires_complete_branch_and_tag_set() {
        let expected: HashMap<String, String> = HashMap::from([
            ("refs/heads/main".into(), "abc".into()),
            ("refs/tags/v1".into(), "def".into()),
        ]);
        let mut actual: Vec<_> = expected
            .iter()
            .map(|(name, hash)| (name.clone(), hash.clone()))
            .collect();
        actual.extend([
            ("HEAD".into(), "abc".into()),
            ("refs/nostr/test".into(), "abc".into()),
            ("refs/tags/v1^{}".into(), "abc".into()),
        ]);
        assert!(ref_mismatches(&expected, &actual).is_empty());
        actual.push(("refs/heads/stale".into(), "abc".into()));
        actual.push(("refs/tags/stale".into(), "def".into()));
        assert_eq!(
            ref_mismatches(&expected, &actual),
            [
                "refs/heads/stale: unexpected ref",
                "refs/tags/stale: unexpected ref",
            ]
        );
        assert_eq!(ref_mismatches(&HashMap::new(), &actual).len(), 4);
        assert!(ref_mismatches(&HashMap::new(), &[]).is_empty());
        assert_eq!(ref_mismatches(&expected, &[]).len(), 2);
        actual[0].1 = "wrong".into();
        assert!(ref_mismatches(&expected, &actual)
            .iter()
            .any(|error| error.contains("got wrong")));
    }
}
