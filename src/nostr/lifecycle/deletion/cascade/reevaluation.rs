/// Legacy Re-evaluation Engine - Determines event retention after announcement deletion
///
/// When a repository announcement is deleted, this module re-evaluates all dependent
/// events to determine which should be kept (still acceptable through other announcements)
/// vs deleted (no longer acceptable).
///
/// This is critical for multi-maintainer scenarios where one maintainer deletes their
/// announcement but other maintainers' announcements should keep the events alive.
///
/// This module is retained for legacy/offline reconciliation callers. The
/// production NIP-09 announcement cascade algorithm lives in `orchestration.rs`.
use std::collections::{HashMap, HashSet};

use nostr_relay_builder::prelude::{Event, EventId, Filter, Kind};

use crate::nostr::SharedDatabase;

/// Result of re-evaluating events after an announcement deletion
#[derive(Debug, Clone)]
pub struct ReevaluationResult {
    /// Events that should be KEPT (still acceptable through other announcements)
    pub keep: HashMap<EventId, RetentionReason>,
    /// Events that should be DELETED (no longer acceptable)
    pub delete: HashSet<EventId>,
}

/// Reason why an event is being kept after re-evaluation
#[derive(Debug, Clone)]
pub struct RetentionReason {
    /// Event ID being retained
    pub event_id: EventId,
    /// Announcement addresses that make this event acceptable
    pub valid_announcements: Vec<String>,
    /// Event type description for logging
    pub event_type: String,
}

/// Re-evaluate events that were dependent on a deleted announcement
///
/// Legacy reconciliation helper. Do not use this as a description of the
/// production NIP-09 announcement cascade.
///
/// This function determines which events should be kept vs deleted when an
/// announcement is removed. It checks if events have alternative retention
/// reasons through other valid announcements.
///
/// # Arguments
/// * `database` - Database to query for announcements and events
/// * `deleted_address` - Address of the deleted announcement (format: `30617:<pubkey>:<identifier>`)
/// * `potentially_affected` - Event IDs that might be affected by the deletion
///
/// # Returns
/// `ReevaluationResult` with events to keep (with reasons) and events to delete
///
/// # Algorithm
/// For each potentially affected event:
/// 1. Query all active repository announcements (kind 30617) from database
/// 2. Extract all `a` tags from the event that reference announcements
/// 3. Check if any of those `a` tags reference announcements OTHER than the deleted one
/// 4. If YES: event is KEPT (has alternative retention reason)
/// 5. If NO: check if event is a repository announcement itself (multi-maintainer case)
/// 6. If repository announcement: check if other maintainers have announcements for same identifier
/// 7. If YES: event is KEPT (other maintainers exist)
/// 8. If NO: event is DELETED (no valid announcements remain)
pub async fn reevaluate_events_without_announcement(
    database: &SharedDatabase,
    deleted_address: &str,
    potentially_affected: &HashSet<EventId>,
) -> Result<ReevaluationResult, String> {
    let mut result = ReevaluationResult {
        keep: HashMap::new(),
        delete: HashSet::new(),
    };

    // Parse the deleted address to get identifier
    let deleted_identifier = parse_identifier_from_address(deleted_address)?;

    // Query all active repository announcements (kind 30617) for this identifier
    let active_announcements = query_active_announcements(database, &deleted_identifier).await?;

    // Build a set of valid announcement addresses (excluding the deleted one)
    let valid_addresses: HashSet<String> = active_announcements
        .iter()
        .map(build_announcement_address)
        .filter(|addr| addr != deleted_address)
        .collect();

    tracing::debug!(
        deleted_address = %deleted_address,
        identifier = %deleted_identifier,
        active_count = active_announcements.len(),
        valid_count = valid_addresses.len(),
        "Re-evaluating {} events after announcement deletion",
        potentially_affected.len()
    );

    // Re-evaluate each potentially affected event
    for event_id in potentially_affected {
        // Query the event from database
        let filter = Filter::new().id(*event_id);
        let events: Vec<Event> = database
            .query(filter)
            .await
            .map_err(|e| format!("Database query failed: {}", e))?
            .into_iter()
            .collect();

        if events.is_empty() {
            tracing::debug!(
                event_id = %event_id,
                "Event not found in database during re-evaluation, marking for deletion (fail-secure)"
            );
            // If event is not in database, mark it for deletion (fail-secure)
            result.delete.insert(*event_id);
            continue;
        }

        let event = &events[0];

        // Determine if this event should be kept or deleted
        match evaluate_event_retention(event, &deleted_identifier, &valid_addresses).await {
            Ok(Some(reason)) => {
                tracing::debug!(
                    event_id = %event_id,
                    event_type = %reason.event_type,
                    valid_announcements = ?reason.valid_announcements,
                    "Event KEPT: has alternative retention reason"
                );
                result.keep.insert(*event_id, reason);
            }
            Ok(None) => {
                tracing::debug!(
                    event_id = %event_id,
                    kind = %event.kind,
                    "Event DELETED: no valid announcements remain"
                );
                result.delete.insert(*event_id);
            }
            Err(e) => {
                tracing::error!(
                    event_id = %event_id,
                    error = %e,
                    "Error evaluating event retention, marking for deletion (fail-secure)"
                );
                result.delete.insert(*event_id);
            }
        }
    }

    tracing::info!(
        deleted_address = %deleted_address,
        keep_count = result.keep.len(),
        delete_count = result.delete.len(),
        "Re-evaluation complete: {} kept, {} deleted",
        result.keep.len(),
        result.delete.len()
    );

    Ok(result)
}

/// Evaluate whether a single event should be retained after announcement deletion
///
/// Returns Some(RetentionReason) if event should be kept, None if it should be deleted.
async fn evaluate_event_retention(
    event: &Event,
    _deleted_identifier: &str,
    valid_addresses: &HashSet<String>,
) -> Result<Option<RetentionReason>, String> {
    let event_type = get_event_type_description(event);

    // Special case: Repository announcements (kind 30617)
    // These are kept if there are OTHER announcements for the same identifier
    if event.kind == Kind::GitRepoAnnouncement {
        let event_address = build_announcement_address(event);

        // If this IS the deleted announcement, it should be deleted
        if !valid_addresses.contains(&event_address) {
            return Ok(None);
        }

        // This is a different announcement for the same identifier - keep it
        return Ok(Some(RetentionReason {
            event_id: event.id,
            valid_announcements: vec![event_address],
            event_type,
        }));
    }

    // For all other events: check if they have `a` tags referencing valid announcements
    let referenced_announcements = extract_announcement_references(event);

    #[cfg(test)]
    println!(
        "Event {}: referenced {} announcements, {} valid addresses",
        event.id,
        referenced_announcements.len(),
        valid_addresses.len()
    );

    // Filter to only valid announcements (excluding deleted one)
    let valid_refs: Vec<String> = referenced_announcements
        .into_iter()
        .filter(|addr| valid_addresses.contains(addr))
        .collect();

    if valid_refs.is_empty() {
        // No valid announcement references - event should be deleted
        tracing::debug!(
            event_id = %event.id,
            "No valid announcement references found"
        );
        return Ok(None);
    }

    // Event has valid announcement references - keep it
    tracing::debug!(
        event_id = %event.id,
        valid_refs_count = valid_refs.len(),
        "Event has valid announcement references, keeping"
    );
    Ok(Some(RetentionReason {
        event_id: event.id,
        valid_announcements: valid_refs,
        event_type,
    }))
}

/// Query all active repository announcements for a given identifier
///
/// Returns all kind 30617 events with matching `d` tag (identifier).
async fn query_active_announcements(
    database: &SharedDatabase,
    identifier: &str,
) -> Result<Vec<Event>, String> {
    // Query all repository announcements
    let filter = Filter::new().kind(Kind::GitRepoAnnouncement);

    let all_announcements: Vec<Event> = database
        .query(filter)
        .await
        .map_err(|e| format!("Database query failed: {}", e))?
        .into_iter()
        .collect();

    // Filter by identifier manually (some databases don't support custom_tag queries properly)
    let events: Vec<Event> = all_announcements
        .into_iter()
        .filter(|event| {
            event.tags.iter().any(|tag| {
                let tag_vec = tag.as_slice();
                tag_vec.len() >= 2 && tag_vec[0] == "d" && tag_vec[1] == identifier
            })
        })
        .collect();

    Ok(events)
}

/// Extract all announcement references (`a` tags) from an event
///
/// Returns addresses in format: `30617:<pubkey>:<identifier>`
fn extract_announcement_references(event: &Event) -> Vec<String> {
    let mut refs = Vec::new();

    for tag in event.tags.iter() {
        let tag_vec = tag.as_slice();
        if tag_vec.len() >= 2 && tag_vec[0] == "a" {
            let address = &tag_vec[1];
            // Only include kind 30617 (repository announcement) references
            if address.starts_with("30617:") {
                refs.push(address.to_string());
            }
        }
    }

    refs
}

/// Build announcement address from event
///
/// Format: `30617:<pubkey>:<identifier>`
fn build_announcement_address(event: &Event) -> String {
    let identifier = event
        .tags
        .iter()
        .find_map(|tag| {
            let tag_vec = tag.as_slice();
            if tag_vec.len() >= 2 && tag_vec[0] == "d" {
                Some(tag_vec[1].to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    format!("30617:{}:{}", event.pubkey.to_hex(), identifier)
}

/// Parse identifier from announcement address
///
/// Address format: `30617:<pubkey>:<identifier>`
fn parse_identifier_from_address(address: &str) -> Result<String, String> {
    let parts: Vec<&str> = address.split(':').collect();
    if parts.len() != 3 {
        return Err(format!("Invalid address format: {}", address));
    }

    if parts[0] != "30617" {
        return Err(format!(
            "Not a repository announcement address: {}",
            address
        ));
    }

    Ok(parts[2].to_string())
}

/// Get human-readable event type description for logging
fn get_event_type_description(event: &Event) -> String {
    match event.kind {
        Kind::GitRepoAnnouncement => "Repository Announcement".to_string(),
        Kind::RepoState => "Repository State".to_string(),
        Kind::GitPullRequest => "Pull Request".to_string(),
        Kind::GitPullRequestUpdate => "PR Update".to_string(),
        kind if kind == Kind::from(1621) => "Issue".to_string(),
        kind if kind == Kind::from(1617) => "Patch".to_string(),
        kind if kind == Kind::from(1630) => "Issue Status".to_string(),
        kind if kind == Kind::from(1631) => "PR Status".to_string(),
        kind if kind == Kind::from(1632) => "Patch Status".to_string(),
        kind if kind == Kind::from(1633) => "Repository Status".to_string(),
        _ => format!("Event (kind {})", event.kind.as_u16()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::FinalizeEvent;
    use nostr_memory::MemoryDatabase;
    use nostr_relay_builder::prelude::{EventBuilder, Keys, NostrDatabase, Tag};
    use std::sync::Arc;

    /// Helper to create a test repository announcement
    fn create_announcement(keys: &Keys, identifier: &str, domain: &str) -> Event {
        EventBuilder::new(Kind::GitRepoAnnouncement, "Test repository")
            .tags(vec![
                Tag::custom("d", vec![identifier.to_string()]),
                Tag::custom("clone", vec![format!("https://{}/{}", domain, identifier)]),
                Tag::custom("relays", vec![format!("wss://{}", domain)]),
            ])
            .finalize(keys)
            .unwrap()
    }

    /// Helper to create a test issue event
    fn create_issue(keys: &Keys, announcement_address: &str) -> Event {
        EventBuilder::new(Kind::from(1621), "Test issue")
            .tags(vec![Tag::custom(
                "a",
                vec![announcement_address.to_string()],
            )])
            .finalize(keys)
            .unwrap()
    }

    /// Helper to create a test patch event
    fn create_patch(keys: &Keys, announcement_address: &str) -> Event {
        EventBuilder::new(Kind::from(1617), "Test patch")
            .tags(vec![Tag::custom(
                "a",
                vec![announcement_address.to_string()],
            )])
            .finalize(keys)
            .unwrap()
    }

    #[tokio::test]
    async fn test_single_maintainer_all_deleted() {
        // Setup: Single maintainer with announcement and dependent events
        let keys = Keys::generate();
        let identifier = "test-repo";
        let domain = "relay.example.com";

        let announcement = create_announcement(&keys, identifier, domain);
        let announcement_addr = build_announcement_address(&announcement);

        let issue = create_issue(&keys, &announcement_addr);
        let patch = create_patch(&keys, &announcement_addr);

        // Create in-memory database and store events
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        db.save_event(&announcement).await.unwrap();
        db.save_event(&issue).await.unwrap();
        db.save_event(&patch).await.unwrap();

        // Re-evaluate after deleting the only announcement
        let affected = HashSet::from([issue.id, patch.id]);
        let result = reevaluate_events_without_announcement(&db, &announcement_addr, &affected)
            .await
            .unwrap();

        // All events should be deleted (no other announcements)
        assert_eq!(result.keep.len(), 0);
        assert_eq!(result.delete.len(), 2);
        assert!(result.delete.contains(&issue.id));
        assert!(result.delete.contains(&patch.id));
    }

    #[tokio::test]
    async fn test_two_maintainers_one_deletes() {
        // Setup: Two maintainers with announcements for same repository
        let maintainer1 = Keys::generate();
        let maintainer2 = Keys::generate();
        let identifier = "shared-repo";
        let domain = "relay.example.com";

        let announcement1 = create_announcement(&maintainer1, identifier, domain);
        let announcement2 = create_announcement(&maintainer2, identifier, domain);
        let addr1 = build_announcement_address(&announcement1);
        let addr2 = build_announcement_address(&announcement2);

        // Create issue referencing both announcements
        let issue = EventBuilder::new(Kind::from(1621), "Test issue")
            .tags(vec![
                Tag::custom("a", vec![addr1.clone()]),
                Tag::custom("a", vec![addr2.clone()]),
            ])
            .finalize(&maintainer1)
            .unwrap();

        // Create patch referencing only first announcement
        let patch = create_patch(&maintainer1, &addr1);

        // Store in database
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        db.save_event(&announcement1).await.unwrap();
        db.save_event(&announcement2).await.unwrap();
        db.save_event(&issue).await.unwrap();
        db.save_event(&patch).await.unwrap();

        // Re-evaluate after deleting first announcement
        let affected = HashSet::from([issue.id, patch.id]);
        let result = reevaluate_events_without_announcement(&db, &addr1, &affected)
            .await
            .unwrap();

        // Issue should be kept (references announcement2)
        assert_eq!(result.keep.len(), 1);
        assert!(result.keep.contains_key(&issue.id));
        let issue_reason = result.keep.get(&issue.id).unwrap();
        assert_eq!(issue_reason.valid_announcements.len(), 1);
        assert_eq!(issue_reason.valid_announcements[0], addr2);

        // Patch should be deleted (only referenced announcement1)
        assert_eq!(result.delete.len(), 1);
        assert!(result.delete.contains(&patch.id));
    }

    #[tokio::test]
    async fn test_multiple_announcement_references() {
        // Setup: Event with multiple announcement references
        let maintainer1 = Keys::generate();
        let maintainer2 = Keys::generate();
        let maintainer3 = Keys::generate();
        let identifier = "multi-repo";
        let domain = "relay.example.com";

        let announcement1 = create_announcement(&maintainer1, identifier, domain);
        let announcement2 = create_announcement(&maintainer2, identifier, domain);
        let announcement3 = create_announcement(&maintainer3, identifier, domain);
        let addr1 = build_announcement_address(&announcement1);
        let addr2 = build_announcement_address(&announcement2);
        let addr3 = build_announcement_address(&announcement3);

        // Create issue referencing all three announcements
        let issue = EventBuilder::new(Kind::from(1621), "Test issue")
            .tags(vec![
                Tag::custom("a", vec![addr1.clone()]),
                Tag::custom("a", vec![addr2.clone()]),
                Tag::custom("a", vec![addr3.clone()]),
            ])
            .finalize(&maintainer1)
            .unwrap();

        // Store in database
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        db.save_event(&announcement1).await.unwrap();
        db.save_event(&announcement2).await.unwrap();
        db.save_event(&announcement3).await.unwrap();
        db.save_event(&issue).await.unwrap();

        // Re-evaluate after deleting first announcement
        let affected = HashSet::from([issue.id]);
        let result = reevaluate_events_without_announcement(&db, &addr1, &affected)
            .await
            .unwrap();

        // Issue should be kept (still has announcement2 and announcement3)
        assert_eq!(result.keep.len(), 1);
        assert!(result.keep.contains_key(&issue.id));
        let reason = result.keep.get(&issue.id).unwrap();
        assert_eq!(reason.valid_announcements.len(), 2);
        assert!(reason.valid_announcements.contains(&addr2));
        assert!(reason.valid_announcements.contains(&addr3));
        assert!(!reason.valid_announcements.contains(&addr1));

        assert_eq!(result.delete.len(), 0);
    }

    #[tokio::test]
    async fn test_no_valid_announcements() {
        // Setup: Event with no valid announcement references
        let keys = Keys::generate();
        let identifier = "orphan-repo";
        let domain = "relay.example.com";

        let announcement = create_announcement(&keys, identifier, domain);
        let announcement_addr = build_announcement_address(&announcement);

        // Create issue with no announcement references
        let issue = EventBuilder::new(Kind::from(1621), "Orphan issue")
            .finalize(&keys)
            .unwrap();

        // Store in database
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        db.save_event(&announcement).await.unwrap();
        db.save_event(&issue).await.unwrap();

        // Re-evaluate after deleting announcement
        let affected = HashSet::from([issue.id]);
        let result = reevaluate_events_without_announcement(&db, &announcement_addr, &affected)
            .await
            .unwrap();

        // Issue should be deleted (no announcement references)
        assert_eq!(result.keep.len(), 0);
        assert_eq!(result.delete.len(), 1);
        assert!(result.delete.contains(&issue.id));
    }

    #[tokio::test]
    async fn test_repository_announcement_deletion() {
        // Setup: Multiple announcements for same identifier
        let maintainer1 = Keys::generate();
        let maintainer2 = Keys::generate();
        let identifier = "shared-repo";
        let domain = "relay.example.com";

        let announcement1 = create_announcement(&maintainer1, identifier, domain);
        let announcement2 = create_announcement(&maintainer2, identifier, domain);
        let addr1 = build_announcement_address(&announcement1);
        let _addr2 = build_announcement_address(&announcement2);

        // Store in database
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::unbounded());
        db.save_event(&announcement1).await.unwrap();
        db.save_event(&announcement2).await.unwrap();

        // Re-evaluate announcements after deleting first one
        let affected = HashSet::from([announcement1.id, announcement2.id]);
        let result = reevaluate_events_without_announcement(&db, &addr1, &affected)
            .await
            .unwrap();

        // announcement2 should be kept (different maintainer)
        assert_eq!(result.keep.len(), 1);
        assert!(result.keep.contains_key(&announcement2.id));

        // announcement1 should be deleted (it's the deleted one)
        assert_eq!(result.delete.len(), 1);
        assert!(result.delete.contains(&announcement1.id));
    }

    #[test]
    fn test_parse_identifier_from_address() {
        let address = "30617:abc123:my-repo";
        let identifier = parse_identifier_from_address(address).unwrap();
        assert_eq!(identifier, "my-repo");
    }

    #[test]
    fn test_parse_identifier_invalid_format() {
        let address = "invalid";
        let result = parse_identifier_from_address(address);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_identifier_wrong_kind() {
        let address = "30618:abc123:my-repo";
        let result = parse_identifier_from_address(address);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_announcement_references() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::from(1621), "Test")
            .tags(vec![
                Tag::custom("a", vec!["30617:abc:repo1".to_string()]),
                Tag::custom("a", vec!["30617:def:repo2".to_string()]),
                Tag::custom("a", vec!["30618:ghi:state".to_string()]), // Wrong kind
                Tag::custom("e", vec!["event123".to_string()]),        // Not an 'a' tag
            ])
            .finalize(&keys)
            .unwrap();

        let refs = extract_announcement_references(&event);
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"30617:abc:repo1".to_string()));
        assert!(refs.contains(&"30617:def:repo2".to_string()));
    }

    #[test]
    fn test_build_announcement_address() {
        let keys = Keys::generate();
        let event = create_announcement(&keys, "my-repo", "example.com");
        let address = build_announcement_address(&event);

        assert!(address.starts_with("30617:"));
        assert!(address.ends_with(":my-repo"));
        assert_eq!(address.split(':').count(), 3);
    }

    #[test]
    fn test_get_event_type_description() {
        let keys = Keys::generate();

        let announcement = EventBuilder::new(Kind::GitRepoAnnouncement, "")
            .finalize(&keys)
            .unwrap();
        assert_eq!(
            get_event_type_description(&announcement),
            "Repository Announcement"
        );

        let issue = EventBuilder::new(Kind::from(1621), "")
            .finalize(&keys)
            .unwrap();
        assert_eq!(get_event_type_description(&issue), "Issue");

        let pr = EventBuilder::new(Kind::GitPullRequest, "")
            .finalize(&keys)
            .unwrap();
        assert_eq!(get_event_type_description(&pr), "Pull Request");
    }
}
