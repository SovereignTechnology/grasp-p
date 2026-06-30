//! Temporary operator repair for redundant NIP-09 deletion request rows.
//!
//! The live write path now rejects covered kind-5 requests and compacts older
//! superseded requests. This command applies the same idea to an existing LMDB
//! database so production relays can remove historical kind-5 pollution.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;
use nostr_lmdb::NostrLmdb;
use nostr_relay_builder::prelude::{Event, EventId, Filter, Kind, NostrDatabase};

/// Arguments for the hidden `repair-deletion-requests` subcommand.
#[derive(Debug, Args)]
pub struct RepairDeletionRequestsArgs {
    /// Path to the LMDB relay data directory (contains the nostr event database).
    #[arg(long, env = "NGIT_RELAY_DATA_PATH", default_value = "./data/relay")]
    pub relay_data_path: String,

    /// Actually remove redundant kind-5 deletion request events.
    ///
    /// Without this flag the command runs in dry-run mode and only reports what
    /// would be deleted. Stop the relay service before using this flag.
    #[arg(long, default_value_t = false)]
    pub execute: bool,
}

#[derive(Debug, Default)]
struct ActionableTargets {
    e_ids: HashSet<EventId>,
    a_coordinates: HashSet<String>,
}

impl ActionableTargets {
    fn len(&self) -> usize {
        self.e_ids.len() + self.a_coordinates.len()
    }

    fn is_empty(&self) -> bool {
        self.e_ids.is_empty() && self.a_coordinates.is_empty()
    }
}

#[derive(Debug, Clone)]
struct DeletionRequestSummary {
    id: EventId,
    id_hex: String,
    author_hex: String,
    created_at: u64,
    target_count: usize,
}

impl DeletionRequestSummary {
    fn from_event(event: &Event, targets: &ActionableTargets) -> Self {
        Self {
            id: event.id,
            id_hex: event.id.to_hex(),
            author_hex: event.pubkey.to_hex(),
            created_at: event.created_at.as_secs(),
            target_count: targets.len(),
        }
    }
}

#[derive(Debug)]
struct DeletionRequestAnalysis {
    total: usize,
    actionable: usize,
    keep_ids: HashSet<EventId>,
    remove_ids: Vec<EventId>,
}

/// Run the repair-deletion-requests subcommand.
pub async fn run(args: &RepairDeletionRequestsArgs) -> Result<()> {
    let relay_data_path = Path::new(&args.relay_data_path);

    if args.execute {
        println!("=== repair-deletion-requests (EXECUTE MODE) ===");
        println!("WARNING: This will permanently delete redundant kind-5 rows.");
        println!("Stop the relay service before running in execute mode.");
    } else {
        println!("=== repair-deletion-requests (DRY-RUN MODE) ===");
        println!("Pass --execute to actually delete. Stop the relay first.");
    }
    println!();
    println!("Relay data path: {}", relay_data_path.display());
    println!();

    let main_db = open_lmdb(relay_data_path)
        .await
        .with_context(|| format!("Failed to open main LMDB at {}", relay_data_path.display()))?;

    repair_database("main relay DB", main_db, args.execute).await?;

    let tombstone_path = relay_data_path.join("tombstones");
    if tombstone_path.exists() {
        let tombstone_db = open_lmdb(&tombstone_path).await.with_context(|| {
            format!(
                "Failed to open tombstone LMDB at {}",
                tombstone_path.display()
            )
        })?;
        repair_database("tombstone DB", tombstone_db, args.execute).await?;
    } else {
        println!(
            "tombstone DB: skipped ({} does not exist)",
            tombstone_path.display()
        );
    }

    Ok(())
}

async fn open_lmdb(path: &Path) -> Result<Arc<dyn NostrDatabase>> {
    let db = NostrLmdb::builder(path)
        .process_nip09(false)
        .process_nip62(false)
        .build()
        .await?;
    Ok(Arc::new(db))
}

async fn repair_database(
    name: &str,
    database: Arc<dyn NostrDatabase>,
    execute: bool,
) -> Result<()> {
    println!("{}: querying kind-5 deletion requests...", name);
    let deletion_requests: Vec<Event> = database
        .query(Filter::new().kind(Kind::EventDeletion))
        .await
        .with_context(|| format!("Failed to query kind-5 events from {name}"))?
        .into_iter()
        .collect();

    let analysis = analyze_deletion_requests(&deletion_requests);
    println!("{}: found {} kind-5 event(s)", name, analysis.total);
    println!(
        "{}: {} actionable, {} kept, {} redundant",
        name,
        analysis.actionable,
        analysis.keep_ids.len(),
        analysis.remove_ids.len()
    );

    if analysis.remove_ids.is_empty() {
        println!("{}: nothing to remove", name);
        println!();
        return Ok(());
    }

    if !execute {
        println!(
            "{}: DRY-RUN would delete {} redundant kind-5 event(s)",
            name,
            analysis.remove_ids.len()
        );
        println!();
        return Ok(());
    }

    let deleted = delete_ids_in_chunks(database.as_ref(), &analysis.remove_ids).await?;
    println!("{}: deleted {} redundant kind-5 event(s)", name, deleted);
    println!();

    Ok(())
}

async fn delete_ids_in_chunks(database: &dyn NostrDatabase, ids: &[EventId]) -> Result<usize> {
    let mut deleted = 0usize;
    for chunk in ids.chunks(1_000) {
        database
            .delete(Filter::new().ids(chunk.to_vec()))
            .await
            .context("Failed to delete redundant kind-5 events")?;
        deleted += chunk.len();
    }
    Ok(deleted)
}

fn analyze_deletion_requests(events: &[Event]) -> DeletionRequestAnalysis {
    let mut summaries: HashMap<EventId, DeletionRequestSummary> = HashMap::new();
    let mut e_best: HashMap<(String, EventId), DeletionRequestSummary> = HashMap::new();
    let mut a_best: HashMap<(String, String), DeletionRequestSummary> = HashMap::new();
    let mut no_actionable_ids = HashSet::new();
    let mut actionable = 0usize;

    for event in events {
        let targets = actionable_targets(event);
        let summary = DeletionRequestSummary::from_event(event, &targets);

        if targets.is_empty() {
            no_actionable_ids.insert(event.id);
            summaries.insert(event.id, summary);
            continue;
        }

        actionable += 1;

        for target_id in targets.e_ids {
            keep_best(
                &mut e_best,
                (summary.author_hex.clone(), target_id),
                summary.clone(),
                compare_event_target_keeper,
            );
        }

        for coordinate in targets.a_coordinates {
            keep_best(
                &mut a_best,
                (summary.author_hex.clone(), coordinate),
                summary.clone(),
                compare_coordinate_keeper,
            );
        }

        summaries.insert(event.id, summary);
    }

    let mut keep_ids = no_actionable_ids;
    keep_ids.extend(e_best.values().map(|summary| summary.id));
    keep_ids.extend(a_best.values().map(|summary| summary.id));

    let mut remove_ids: Vec<EventId> = summaries
        .keys()
        .copied()
        .filter(|id| !keep_ids.contains(id))
        .collect();
    remove_ids.sort_by_key(|id| id.to_hex());

    DeletionRequestAnalysis {
        total: events.len(),
        actionable,
        keep_ids,
        remove_ids,
    }
}

fn actionable_targets(event: &Event) -> ActionableTargets {
    let author_hex = event.pubkey.to_hex();
    let mut targets = ActionableTargets::default();

    for tag in event.tags.iter() {
        let v = tag.as_slice();
        if v.len() < 2 {
            continue;
        }

        match v[0].as_str() {
            "e" => {
                if let Ok(target_id) = EventId::from_hex(&v[1]) {
                    targets.e_ids.insert(target_id);
                }
            }
            "a" => {
                let coordinate = &v[1];
                if coordinate
                    .split(':')
                    .nth(1)
                    .map(|owner| owner == author_hex)
                    .unwrap_or(false)
                {
                    targets.a_coordinates.insert(coordinate.clone());
                }
            }
            _ => {}
        }
    }

    targets
}

fn keep_best<K>(
    map: &mut HashMap<K, DeletionRequestSummary>,
    key: K,
    candidate: DeletionRequestSummary,
    compare: fn(&DeletionRequestSummary, &DeletionRequestSummary) -> Ordering,
) where
    K: Eq + std::hash::Hash,
{
    match map.get(&key) {
        Some(existing) if compare(&candidate, existing) != Ordering::Greater => {}
        _ => {
            map.insert(key, candidate);
        }
    }
}

fn compare_event_target_keeper(
    candidate: &DeletionRequestSummary,
    existing: &DeletionRequestSummary,
) -> Ordering {
    candidate
        .target_count
        .cmp(&existing.target_count)
        .then_with(|| candidate.created_at.cmp(&existing.created_at))
        // Prefer the lower event id for stable tie-breaking.
        .then_with(|| existing.id_hex.cmp(&candidate.id_hex))
}

fn compare_coordinate_keeper(
    candidate: &DeletionRequestSummary,
    existing: &DeletionRequestSummary,
) -> Ordering {
    candidate
        .created_at
        .cmp(&existing.created_at)
        .then_with(|| candidate.target_count.cmp(&existing.target_count))
        // Prefer the lower event id for stable tie-breaking.
        .then_with(|| existing.id_hex.cmp(&candidate.id_hex))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::FinalizeEvent;
    use nostr_relay_builder::prelude::{EventBuilder, Keys, Tag, Timestamp};

    fn deletion_by_event(keys: &Keys, target: EventId, created_at: u64) -> Event {
        EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target)])
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .unwrap()
    }

    fn deletion_by_coordinate(keys: &Keys, coordinate: &str, created_at: u64) -> Event {
        EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::custom("a", vec![coordinate.to_string()])])
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .unwrap()
    }

    #[test]
    fn duplicate_event_id_deletion_keeps_one_request() {
        let keys = Keys::generate();
        let target = EventId::all_zeros();
        let older = deletion_by_event(&keys, target, 1_000);
        let newer = deletion_by_event(&keys, target, 1_001);

        let analysis = analyze_deletion_requests(&[older.clone(), newer.clone()]);

        assert_eq!(analysis.keep_ids.len(), 1);
        assert_eq!(analysis.remove_ids.len(), 1);
        assert!(analysis.keep_ids.contains(&newer.id));
        assert_eq!(analysis.remove_ids, vec![older.id]);
    }

    #[test]
    fn newer_coordinate_deletion_replaces_older_request() {
        let keys = Keys::generate();
        let coordinate = format!("30618:{}:my-repo", keys.public_key().to_hex());
        let older = deletion_by_coordinate(&keys, &coordinate, 1_000);
        let newer = deletion_by_coordinate(&keys, &coordinate, 1_100);

        let analysis = analyze_deletion_requests(&[older.clone(), newer.clone()]);

        assert_eq!(analysis.keep_ids.len(), 1);
        assert!(analysis.keep_ids.contains(&newer.id));
        assert_eq!(analysis.remove_ids, vec![older.id]);
    }

    #[test]
    fn no_op_deletion_requests_are_left_alone() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::EventDeletion, "")
            .custom_created_at(Timestamp::from_secs(1_000))
            .finalize(&keys)
            .unwrap();

        let analysis = analyze_deletion_requests(std::slice::from_ref(&event));

        assert_eq!(analysis.keep_ids.len(), 1);
        assert!(analysis.keep_ids.contains(&event.id));
        assert!(analysis.remove_ids.is_empty());
    }

    #[test]
    fn coordinate_for_other_author_is_not_actionable() {
        let signer = Keys::generate();
        let other = Keys::generate();
        let coordinate = format!("30618:{}:my-repo", other.public_key().to_hex());
        let event = deletion_by_coordinate(&signer, &coordinate, 1_000);

        let analysis = analyze_deletion_requests(std::slice::from_ref(&event));

        assert_eq!(analysis.keep_ids.len(), 1);
        assert!(analysis.keep_ids.contains(&event.id));
        assert!(analysis.remove_ids.is_empty());
    }

    #[test]
    fn broader_request_can_replace_single_target_request() {
        let keys = Keys::generate();
        let target = EventId::all_zeros();
        let coordinate = format!("30618:{}:my-repo", keys.public_key().to_hex());
        let single = deletion_by_event(&keys, target, 1_000);
        let broader = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(target), Tag::custom("a", vec![coordinate])])
            .custom_created_at(Timestamp::from_secs(1_100))
            .finalize(&keys)
            .unwrap();

        let analysis = analyze_deletion_requests(&[single.clone(), broader.clone()]);

        assert_eq!(analysis.keep_ids.len(), 1);
        assert!(analysis.keep_ids.contains(&broader.id));
        assert_eq!(analysis.remove_ids, vec![single.id]);
    }
}
