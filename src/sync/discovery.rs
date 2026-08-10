//! Narrow GRASP-03 mailbox discovery primitives.

use std::collections::{HashMap, HashSet};

use nostr::nips::nip65::{self, RelayMetadata};
use nostr_sdk::prelude::*;

use super::algorithms::RelaySyncNeeds;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRoot {
    pub id: EventId,
    pub author: PublicKey,
    pub repository: String,
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

pub fn inbox_relays(event: &Event) -> HashSet<String> {
    if event.kind != Kind::RelayList {
        return HashSet::new();
    }
    nip65::extract_relay_list(event)
        .into_iter()
        .filter_map(|(relay, marker)| {
            matches!(marker, None | Some(RelayMetadata::Read)).then(|| relay.to_string())
        })
        .collect()
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
            inbox_relays(&relay_list),
            HashSet::from([
                "wss://read.example".to_string(),
                "wss://both.example".to_string()
            ])
        );
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
            &HashMap::from([("wss://inbox.example/".to_string(), HashSet::from([root]))]),
        );
        let target = &targets["wss://inbox.example/"];
        assert_eq!(target.root_events, HashSet::from([root]));
        assert!(target.repos.is_empty());
        assert!(target.state_only_repos.is_empty());
    }
}
