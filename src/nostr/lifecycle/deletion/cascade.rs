use std::collections::{HashMap, HashSet, VecDeque};

use nostr_sdk::prelude::{
    Alphabet, Event, EventId, Filter, Kind, PublicKey, SingleLetterTag, Timestamp,
};

use super::policy::{
    announcement_address_of, identifier_from_event, owner_directory_component, DeletionPolicy,
};
use crate::nostr::lifecycle::{DeletionSource, HoldingMetadata, HOLDING_METADATA_KIND};
use crate::nostr::SharedDatabase;

use super::DeletionOutcome;
use crate::nostr::lifecycle::history::HISTORY_METADATA_KIND;

const MAX_CASCADE_CANDIDATE_EVENTS: usize = 50_000;
const MAX_CASCADE_GRAPH_EDGES: usize = 250_000;
const MAX_CASCADE_ORPHAN_DELETES: usize = 20_000;
const CASCADE_QUERY_CHUNK_SIZE: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RefKey {
    Event(EventId),
    Address(String),
}

struct ParsedAddressRef {
    kind: Kind,
    pubkey: PublicKey,
    identifier: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct CascadeDeletionPlan {
    kept_event_ids: HashSet<EventId>,
    orphan_event_ids: HashSet<EventId>,
    component_nodes: usize,
    component_edges: usize,
}

#[derive(Debug, Default)]
struct CascadeGraph {
    nodes: HashMap<EventId, Event>,
    event_to_refs: HashMap<EventId, HashSet<RefKey>>,
    identity_to_event_ids: HashMap<RefKey, HashSet<EventId>>,
    ref_to_referencing_event_ids: HashMap<RefKey, HashSet<EventId>>,
}

impl CascadeGraph {
    fn add_event(&mut self, event: Event) {
        let event_id = event.id;
        let refs = extract_accepted_reference_keys(&event);

        self.event_to_refs.insert(event_id, refs.clone());
        for ref_key in refs {
            self.ref_to_referencing_event_ids
                .entry(ref_key)
                .or_default()
                .insert(event_id);
        }

        if let Some(address) = event_address(&event) {
            self.identity_to_event_ids
                .entry(RefKey::Address(address))
                .or_default()
                .insert(event_id);
        }
        self.identity_to_event_ids
            .entry(RefKey::Event(event_id))
            .or_default()
            .insert(event_id);

        self.nodes.insert(event_id, event);
    }

    fn edge_count(&self) -> usize {
        self.ref_to_referencing_event_ids
            .values()
            .map(HashSet::len)
            .sum()
    }
}

#[derive(Debug)]
enum CascadeExpansionError {
    Query(String),
    NodeCap { max: usize },
    EdgeCap { max: usize },
}

impl std::fmt::Display for CascadeExpansionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Query(e) => write!(f, "{e}"),
            Self::NodeCap { max } => write!(f, "cascade graph node cap exceeded ({max})"),
            Self::EdgeCap { max } => write!(f, "cascade graph edge cap exceeded ({max})"),
        }
    }
}

impl DeletionPolicy {
    /// Graph-based cascade deletion of a repository announcement.
    ///
    /// Mirrors [`crate::nostr::policy::related::RelatedEventPolicy`] by loading
    /// the affected main-DB reference component from the deleted announcement's
    /// event/address, following both outgoing accepted-reference tags and
    /// incoming tag-index matches. The retained set is then recomputed as a
    /// fixed point after excluding the deleted announcement: surviving
    /// independently accepted anchors are kept, any node referencing a kept node
    /// is kept, and any node referenced by a kept node is kept. Nodes in the
    /// loaded component without a surviving acceptance path are moved to holding
    /// and hard-deleted from the main DB.
    ///
    /// Holding orchestration is active in this cascade path via
    /// [`Self::archive_and_delete_filter`]: every deleted orphan/coordinate
    /// target is moved into holding before main-DB deletion, and announcement
    /// deletions include git archive metadata linkage for cleanup lifecycle.
    /// Recovery orchestration lives in `crate::nostr::lifecycle::deletion::recovery`.
    pub(in crate::nostr::lifecycle::deletion) async fn cascade_delete_announcement(
        &self,
        author: &PublicKey,
        announcement_addr: &str,
        deletion_created_at: Timestamp,
        source: DeletionSource,
    ) -> DeletionOutcome {
        let mut outcome = DeletionOutcome::default();
        let mut moved_ids = HashSet::new();

        // Parse `30617:<pubkey>:<identifier>` (already validated as a 30617
        // coordinate for this author, but re-parse defensively).
        let parts: Vec<&str> = announcement_addr.splitn(3, ':').collect();
        if parts.len() != 3 {
            return outcome;
        }
        let identifier = parts[2];

        let deletable_announcements = match self
            .query_address_events_until(announcement_addr, deletion_created_at)
            .await
        {
            Ok(events) => events
                .into_iter()
                .filter(|event| event.kind == Kind::GitRepoAnnouncement)
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::warn!(error = %e, announcement = %announcement_addr, "Cascade deletion: failed to verify announcement versions under deletion cutoff");
                return DeletionOutcome {
                    failures: 1,
                    ..Default::default()
                };
            }
        };

        if deletable_announcements.is_empty() {
            tracing::debug!(
                announcement = %announcement_addr,
                deletion_created_at = deletion_created_at.as_secs(),
                "Cascade deletion skipped: no announcement version is deletable under NIP-09 cutoff"
            );
            return outcome;
        }

        let plan = match plan_deleted_announcement_cascade(
            &self.ctx.database,
            &deletable_announcements,
            &self.ctx.config.domain,
        )
        .await
        {
            Ok(plan) => plan,
            Err(e) => {
                tracing::warn!(error = %e, "Cascade deletion: graph expansion failed; falling back to simple coordinate deletion");
                return self
                    .delete_announcement_coordinate_and_maybe_state(
                        author,
                        announcement_addr,
                        identifier,
                        deletion_created_at,
                        &mut moved_ids,
                        source,
                    )
                    .await;
            }
        };

        tracing::info!(
            announcement = %announcement_addr,
            component_nodes = plan.component_nodes,
            component_edges = plan.component_edges,
            kept = plan.kept_event_ids.len(),
            deleted = plan.orphan_event_ids.len(),
            "Announcement cascade deletion: acceptance reachability complete"
        );

        // Hard-delete the orphaned dependent events by id.
        let orphan_ids: Vec<EventId> = plan.orphan_event_ids.into_iter().collect();
        if orphan_ids.len() > MAX_CASCADE_ORPHAN_DELETES {
            tracing::warn!(
                announcement = %announcement_addr,
                orphan_deletes = orphan_ids.len(),
                max = MAX_CASCADE_ORPHAN_DELETES,
                "Cascade deletion orphan set exceeds limit; deleting announcement coordinate only"
            );
            return self
                .delete_announcement_coordinate_and_maybe_state(
                    author,
                    announcement_addr,
                    identifier,
                    deletion_created_at,
                    &mut moved_ids,
                    source,
                )
                .await;
        }
        if !orphan_ids.is_empty() {
            tracing::debug!(
                count = orphan_ids.len(),
                "Cascade deletion: hard-deleting orphaned events"
            );
            let filter = Filter::new().ids(orphan_ids);
            let metadata = HoldingMetadata {
                deleted_at: deletion_created_at,
                source,
                coordinate: Some(announcement_addr.to_string()),
                identifier: Some(identifier.to_string()),
                owner_pubkey: Some(author.to_hex()),
                git_archive: self
                    .ensure_repo_archive(
                        &owner_directory_component(author),
                        identifier,
                        deletion_created_at,
                    )
                    .await,
            };
            outcome.merge(
                self.archive_and_delete_filter(
                    filter,
                    &metadata,
                    &mut moved_ids,
                    "cascade orphan deletion",
                )
                .await,
            );
        }

        // Step 5b: hard-delete the announcement coordinate itself (up to the
        // deletion's created_at, per NIP-09), exactly as the simple path does,
        // then clean state if this identifier is now unanchored.
        outcome.merge(
            self.delete_announcement_coordinate_and_maybe_state(
                author,
                announcement_addr,
                identifier,
                deletion_created_at,
                &mut moved_ids,
                source,
            )
            .await,
        );
        outcome
    }

    /// Apply operator-driven blacklist deletion for a stored kind-30617
    /// announcement.
    ///
    /// This path intentionally bypasses `deletion_request_disrespector` and uses
    /// the same cascade + holding/archive flow as user NIP-09 deletions, but
    /// marks holding metadata with `DeletionSource::Blacklist`.
    pub async fn apply_blacklist_deletion_for_announcement(
        &self,
        announcement: &Event,
    ) -> anyhow::Result<()> {
        if announcement.kind != Kind::GitRepoAnnouncement {
            return Err(anyhow::anyhow!(
                "blacklist deletion requires kind 30617 announcement, got {}",
                announcement.kind.as_u16()
            ));
        }

        let Some(identifier) = identifier_from_event(announcement) else {
            return Err(anyhow::anyhow!(
                "announcement {} missing identifier tag",
                announcement.id.to_hex()
            ));
        };

        let coordinate = format!("30617:{}:{}", announcement.pubkey.to_hex(), identifier);
        let _ = self
            .cascade_delete_announcement(
                &announcement.pubkey,
                &coordinate,
                Timestamp::now(),
                DeletionSource::Blacklist,
            )
            .await;

        Ok(())
    }

    /// Apply operator-driven whitelist deletion for a stored kind-30617
    /// announcement.
    ///
    /// Uses the same cascade + holding/archive flow as NIP-09 deletions, but
    /// marks holding metadata with `DeletionSource::Whitelist`.
    pub async fn apply_whitelist_deletion_for_announcement(
        &self,
        announcement: &Event,
    ) -> anyhow::Result<()> {
        if announcement.kind != Kind::GitRepoAnnouncement {
            return Err(anyhow::anyhow!(
                "whitelist deletion requires kind 30617 announcement, got {}",
                announcement.kind.as_u16()
            ));
        }

        let Some(identifier) = identifier_from_event(announcement) else {
            return Err(anyhow::anyhow!(
                "announcement {} missing identifier tag",
                announcement.id.to_hex()
            ));
        };

        let coordinate = format!("30617:{}:{}", announcement.pubkey.to_hex(), identifier);
        self.cascade_delete_announcement(
            &announcement.pubkey,
            &coordinate,
            Timestamp::now(),
            DeletionSource::Whitelist,
        )
        .await;

        Ok(())
    }

    /// Delete kind-30618 state events for `identifier` when the repository is
    /// now unanchored (no surviving kind-30617 announcement with that `d` tag).
    ///
    /// This is separate from graph traversal because state events are keyed by
    /// identifier rather than `a`/`e`/`q` relationships.
    async fn delete_repo_state_if_identifier_is_unanchored(
        &self,
        identifier: &str,
        deletion_created_at: Timestamp,
        moved_ids: &mut HashSet<EventId>,
        source: DeletionSource,
    ) -> DeletionOutcome {
        let announcement_filter = Filter::new().kind(Kind::GitRepoAnnouncement).custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            identifier.to_string(),
        );

        let remaining_announcements = match self.ctx.database.query(announcement_filter).await {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    identifier = %identifier,
                    "Cascade deletion: failed to check remaining announcements for identifier"
                );
                return DeletionOutcome {
                    failures: 1,
                    ..Default::default()
                };
            }
        };

        if !remaining_announcements.is_empty() {
            return DeletionOutcome::default();
        }

        let state_filter = Filter::new().kind(Kind::RepoState).custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            identifier.to_string(),
        );

        let metadata = HoldingMetadata {
            deleted_at: deletion_created_at,
            source,
            coordinate: None,
            identifier: Some(identifier.to_string()),
            owner_pubkey: None,
            git_archive: None,
        };
        self.archive_and_delete_filter(
            state_filter,
            &metadata,
            moved_ids,
            "unanchored state deletion",
        )
        .await
    }

    async fn delete_announcement_coordinate_and_maybe_state(
        &self,
        author: &PublicKey,
        announcement_addr: &str,
        identifier: &str,
        deletion_created_at: Timestamp,
        moved_ids: &mut HashSet<EventId>,
        source: DeletionSource,
    ) -> DeletionOutcome {
        let mut outcome = self
            .delete_coordinate_from_main_db(
                author,
                announcement_addr,
                deletion_created_at,
                moved_ids,
                source,
            )
            .await;

        // Repository state (30618) is keyed by identifier, not by graph edges.
        // After deleting this announcement coordinate, delete state events for
        // the identifier only when no announcement for that identifier remains
        // in the main DB. This must also run on coordinate-only fallbacks.
        outcome.merge(
            self.delete_repo_state_if_identifier_is_unanchored(
                identifier,
                deletion_created_at,
                moved_ids,
                source,
            )
            .await,
        );
        outcome
    }

    async fn query_address_events_until(
        &self,
        address: &str,
        until: Timestamp,
    ) -> Result<Vec<Event>, String> {
        query_address_events_with_until(&self.ctx.database, address, Some(until)).await
    }
}

async fn plan_deleted_announcement_cascade(
    database: &SharedDatabase,
    deleted_announcements: &[Event],
    domain: &str,
) -> Result<CascadeDeletionPlan, String> {
    let deleted_announcement_ids: HashSet<EventId> = deleted_announcements
        .iter()
        .filter(|event| event.kind == Kind::GitRepoAnnouncement)
        .map(|event| event.id)
        .collect();

    if deleted_announcement_ids.is_empty() {
        return Ok(CascadeDeletionPlan::default());
    }

    let seed_addresses: HashSet<String> = deleted_announcements
        .iter()
        .filter(|event| event.kind == Kind::GitRepoAnnouncement)
        .map(announcement_address_of)
        .collect();

    let graph =
        expand_cascade_graph_from_db(database, deleted_announcement_ids.clone(), seed_addresses)
            .await
            .map_err(|e| e.to_string())?;
    let kept_event_ids = compute_retained_events(&graph, &deleted_announcement_ids, domain);
    let orphan_event_ids =
        compute_deletable_events(&graph, &kept_event_ids, &deleted_announcement_ids);

    Ok(CascadeDeletionPlan {
        kept_event_ids,
        orphan_event_ids,
        component_nodes: graph.nodes.len(),
        component_edges: graph.edge_count(),
    })
}

async fn expand_cascade_graph_from_db(
    database: &SharedDatabase,
    seed_event_ids: HashSet<EventId>,
    seed_addresses: HashSet<String>,
) -> Result<CascadeGraph, CascadeExpansionError> {
    let mut graph = CascadeGraph::default();
    let mut event_queue: VecDeque<EventId> = seed_event_ids.into_iter().collect();
    let mut address_queue: VecDeque<String> = seed_addresses.into_iter().collect();
    let mut visited_event_ids = HashSet::new();
    let mut visited_addresses = HashSet::new();
    let mut queried_incoming_event_refs = HashSet::new();
    let mut queried_incoming_address_refs = HashSet::new();

    while !event_queue.is_empty() || !address_queue.is_empty() {
        let mut loaded = Vec::new();

        let mut id_batch = Vec::new();
        while id_batch.len() < CASCADE_QUERY_CHUNK_SIZE {
            let Some(event_id) = event_queue.pop_front() else {
                break;
            };
            if visited_event_ids.insert(event_id) {
                id_batch.push(event_id);
            }
        }
        if !id_batch.is_empty() {
            loaded.extend(query_events_by_ids(database, &id_batch).await?);
            for event_id in id_batch {
                if queried_incoming_event_refs.insert(event_id) {
                    let incoming = query_incoming_event_refs(database, event_id).await?;
                    enqueue_loaded_events(incoming, &mut loaded, &mut event_queue);
                }
            }
        }

        let mut address_batch = Vec::new();
        while address_batch.len() < CASCADE_QUERY_CHUNK_SIZE {
            let Some(address) = address_queue.pop_front() else {
                break;
            };
            if visited_addresses.insert(address.clone()) {
                address_batch.push(address);
            }
        }
        for address in address_batch {
            loaded.extend(
                query_address_events_with_until(database, &address, None)
                    .await
                    .map_err(CascadeExpansionError::Query)?,
            );
            if queried_incoming_address_refs.insert(address.clone()) {
                let incoming = query_incoming_address_refs(database, &address).await?;
                enqueue_loaded_events(incoming, &mut loaded, &mut event_queue);
            }
        }

        for event in loaded {
            if should_exclude_from_generic_graph(&event) {
                continue;
            }

            let is_new = !graph.nodes.contains_key(&event.id);
            graph.add_event(event.clone());
            if graph.nodes.len() > MAX_CASCADE_CANDIDATE_EVENTS {
                return Err(CascadeExpansionError::NodeCap {
                    max: MAX_CASCADE_CANDIDATE_EVENTS,
                });
            }
            if graph.edge_count() > MAX_CASCADE_GRAPH_EDGES {
                return Err(CascadeExpansionError::EdgeCap {
                    max: MAX_CASCADE_GRAPH_EDGES,
                });
            }

            if !is_new || should_not_recurse_through(&event) {
                continue;
            }

            for ref_key in extract_accepted_reference_keys(&event) {
                match ref_key {
                    RefKey::Event(event_id) => {
                        if !visited_event_ids.contains(&event_id) {
                            event_queue.push_back(event_id);
                        }
                    }
                    RefKey::Address(address) => {
                        if !visited_addresses.contains(&address) {
                            address_queue.push_back(address);
                        }
                    }
                }
            }

            if queried_incoming_event_refs.insert(event.id) {
                let incoming = query_incoming_event_refs(database, event.id).await?;
                enqueue_loaded_events(incoming, &mut Vec::new(), &mut event_queue);
            }
            if let Some(address) = event_address(&event) {
                if queried_incoming_address_refs.insert(address.clone()) {
                    let incoming = query_incoming_address_refs(database, &address).await?;
                    enqueue_loaded_events(incoming, &mut Vec::new(), &mut event_queue);
                }
            }
        }
    }

    Ok(graph)
}

fn enqueue_loaded_events(
    events: Vec<Event>,
    loaded: &mut Vec<Event>,
    event_queue: &mut VecDeque<EventId>,
) {
    for event in events {
        event_queue.push_back(event.id);
        loaded.push(event);
    }
}

async fn query_events_by_ids(
    database: &SharedDatabase,
    ids: &[EventId],
) -> Result<Vec<Event>, CascadeExpansionError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    database
        .query(Filter::new().ids(ids.iter().copied()))
        .await
        .map(|events| events.into_iter().collect())
        .map_err(|e| CascadeExpansionError::Query(format!("query ids failed: {e}")))
}

async fn query_address_events_with_until(
    database: &SharedDatabase,
    address: &str,
    until: Option<Timestamp>,
) -> Result<Vec<Event>, String> {
    let Some(parsed) = parse_accepted_address_ref(address) else {
        return Ok(Vec::new());
    };

    let mut filter = Filter::new().kind(parsed.kind).author(parsed.pubkey);
    if let Some(identifier) = parsed.identifier {
        filter = filter.custom_tag(SingleLetterTag::lowercase(Alphabet::D), identifier);
    }
    if let Some(until) = until {
        filter = filter.until(until);
    }

    database
        .query(filter)
        .await
        .map(|events| events.into_iter().collect())
        .map_err(|e| format!("query address {address} failed: {e}"))
}

fn parse_accepted_address_ref(address: &str) -> Option<ParsedAddressRef> {
    let parts: Vec<&str> = address.splitn(3, ':').collect();
    if parts.len() < 2 {
        return None;
    }

    let kind = Kind::from(parts[0].parse::<u16>().ok()?);
    let pubkey = PublicKey::from_hex(parts[1]).ok()?;

    if kind.is_addressable() {
        let identifier = parts.get(2)?;
        return Some(ParsedAddressRef {
            kind,
            pubkey,
            identifier: Some((*identifier).to_string()),
        });
    }

    if kind.is_replaceable() && parts.len() == 2 {
        return Some(ParsedAddressRef {
            kind,
            pubkey,
            identifier: None,
        });
    }

    None
}

async fn query_incoming_event_refs(
    database: &SharedDatabase,
    event_id: EventId,
) -> Result<Vec<Event>, CascadeExpansionError> {
    let hex = event_id.to_hex();
    query_tag_variants(
        database,
        &[
            SingleLetterTag::lowercase(Alphabet::E),
            SingleLetterTag::uppercase(Alphabet::E),
            SingleLetterTag::lowercase(Alphabet::Q),
        ],
        &hex,
    )
    .await
}

async fn query_incoming_address_refs(
    database: &SharedDatabase,
    address: &str,
) -> Result<Vec<Event>, CascadeExpansionError> {
    query_tag_variants(
        database,
        &[
            SingleLetterTag::lowercase(Alphabet::A),
            SingleLetterTag::uppercase(Alphabet::A),
            SingleLetterTag::lowercase(Alphabet::Q),
        ],
        address,
    )
    .await
}

async fn query_tag_variants(
    database: &SharedDatabase,
    tags: &[SingleLetterTag],
    value: &str,
) -> Result<Vec<Event>, CascadeExpansionError> {
    let mut by_id = HashMap::new();
    for tag in tags {
        let events = database
            .query(Filter::new().custom_tag(*tag, value.to_string()))
            .await
            .map_err(|e| {
                CascadeExpansionError::Query(format!("query tag #{tag}={value} failed: {e}"))
            })?;
        for event in events {
            by_id.insert(event.id, event);
        }
    }
    Ok(by_id.into_values().collect())
}

fn compute_retained_events(
    graph: &CascadeGraph,
    deleted_announcement_ids: &HashSet<EventId>,
    domain: &str,
) -> HashSet<EventId> {
    let mut kept = HashSet::new();
    let mut vetoed_pr_graph_nodes = HashSet::new();

    for event in graph.nodes.values() {
        if deleted_announcement_ids.contains(&event.id) || vetoed_pr_graph_nodes.contains(&event.id)
        {
            continue;
        }
        if is_independent_anchor(event, deleted_announcement_ids, domain) {
            kept.insert(event.id);
        }
    }

    loop {
        let before = kept.len();
        let kept_refs = refs_for_kept_events(graph, &kept);

        for event in graph.nodes.values() {
            if kept.contains(&event.id)
                || vetoed_pr_graph_nodes.contains(&event.id)
                || deleted_announcement_ids.contains(&event.id)
                || should_exclude_from_generic_graph(event)
                || should_not_recurse_through(event)
            {
                continue;
            }

            let own_refs = graph
                .event_to_refs
                .get(&event.id)
                .cloned()
                .unwrap_or_default();
            let own_keys = event_identity_keys(event);

            if own_refs
                .iter()
                .any(|ref_key| kept_refs.identities.contains(ref_key))
                || own_keys
                    .iter()
                    .any(|ref_key| kept_refs.outgoing.contains(ref_key))
            {
                kept.insert(event.id);
            }
        }

        let vetoed = veto_unanchored_pr_graph_nodes(graph, &kept, domain);
        if !vetoed.is_empty() {
            for id in vetoed {
                kept.remove(&id);
                vetoed_pr_graph_nodes.insert(id);
            }
            continue;
        }

        if kept.len() == before {
            break;
        }
    }

    kept
}

#[derive(Debug, Default)]
struct KeptRefSets {
    identities: HashSet<RefKey>,
    outgoing: HashSet<RefKey>,
}

fn refs_for_kept_events(graph: &CascadeGraph, kept: &HashSet<EventId>) -> KeptRefSets {
    let mut refs = KeptRefSets::default();
    for event_id in kept {
        if let Some(event) = graph.nodes.get(event_id) {
            refs.identities.extend(event_identity_keys(event));
        }
        if let Some(event_refs) = graph.event_to_refs.get(event_id) {
            refs.outgoing.extend(event_refs.iter().cloned());
        }
    }
    refs
}

fn compute_deletable_events(
    graph: &CascadeGraph,
    kept: &HashSet<EventId>,
    deleted_announcement_ids: &HashSet<EventId>,
) -> HashSet<EventId> {
    graph
        .nodes
        .values()
        .filter(|event| {
            !kept.contains(&event.id)
                && !deleted_announcement_ids.contains(&event.id)
                && !should_exclude_from_generic_graph(event)
                && !should_not_recurse_through(event)
        })
        .map(|event| event.id)
        .collect()
}

fn is_independent_anchor(
    event: &Event,
    deleted_announcement_ids: &HashSet<EventId>,
    domain: &str,
) -> bool {
    if event.kind == Kind::GitRepoAnnouncement {
        return !deleted_announcement_ids.contains(&event.id);
    }

    if event.kind == Kind::GitUserGraspList {
        return true;
    }

    crate::grasp06::policy::event_names_relays_prs_endpoint(event, domain)
}

fn veto_unanchored_pr_graph_nodes(
    graph: &CascadeGraph,
    kept: &HashSet<EventId>,
    domain: &str,
) -> HashSet<EventId> {
    graph
        .nodes
        .values()
        .filter(|event| kept.contains(&event.id))
        .filter(|event| {
            matches!(
                event.kind,
                Kind::GitPullRequest | Kind::GitPullRequestUpdate
            )
        })
        .filter(|event| !crate::grasp06::policy::event_names_relays_prs_endpoint(event, domain))
        .filter(|event| !event_references_kept_repo_announcement(event, graph, kept))
        .map(|event| event.id)
        .collect()
}

fn event_references_kept_repo_announcement(
    event: &Event,
    graph: &CascadeGraph,
    kept: &HashSet<EventId>,
) -> bool {
    graph
        .event_to_refs
        .get(&event.id)
        .into_iter()
        .flatten()
        .any(|ref_key| {
            graph.identity_to_event_ids.get(ref_key).is_some_and(|ids| {
                ids.iter().any(|id| {
                    kept.contains(id)
                        && graph
                            .nodes
                            .get(id)
                            .is_some_and(|node| node.kind == Kind::GitRepoAnnouncement)
                })
            })
        })
}

fn extract_accepted_reference_keys(event: &Event) -> HashSet<RefKey> {
    let mut refs = HashSet::new();
    for tag in event.tags.iter() {
        let tag_vec = tag.as_slice();
        if tag_vec.len() < 2 {
            continue;
        }
        match tag_vec[0].as_str() {
            "a" | "A" => {
                if parse_accepted_address_ref(&tag_vec[1]).is_some() {
                    refs.insert(RefKey::Address(tag_vec[1].to_string()));
                }
            }
            "e" | "E" => {
                if let Ok(event_id) = EventId::from_hex(&tag_vec[1]) {
                    refs.insert(RefKey::Event(event_id));
                }
            }
            "q" if tag_vec[1].contains(':') => {
                if parse_accepted_address_ref(&tag_vec[1]).is_some() {
                    refs.insert(RefKey::Address(tag_vec[1].to_string()));
                }
            }
            "q" => {
                if let Ok(event_id) = EventId::from_hex(&tag_vec[1]) {
                    refs.insert(RefKey::Event(event_id));
                }
            }
            _ => {}
        }
    }
    refs
}

fn event_identity_keys(event: &Event) -> HashSet<RefKey> {
    let mut keys = HashSet::from([RefKey::Event(event.id)]);
    if let Some(address) = event_address(event) {
        keys.insert(RefKey::Address(address));
    }
    keys
}

fn event_address(event: &Event) -> Option<String> {
    if event.kind == Kind::GitRepoAnnouncement {
        return Some(announcement_address_of(event));
    }

    if event.kind.is_addressable() {
        let identifier = event.tags.iter().find_map(|tag| {
            let tag_vec = tag.as_slice();
            if tag_vec.len() >= 2 && tag_vec[0] == "d" {
                Some(tag_vec[1].clone())
            } else {
                None
            }
        })?;
        Some(format!(
            "{}:{}:{}",
            event.kind.as_u16(),
            event.pubkey.to_hex(),
            identifier
        ))
    } else if event.kind.is_replaceable() {
        Some(format!("{}:{}", event.kind.as_u16(), event.pubkey.to_hex()))
    } else {
        None
    }
}

fn should_exclude_from_generic_graph(event: &Event) -> bool {
    event.kind == Kind::RepoState
}

fn should_not_recurse_through(event: &Event) -> bool {
    event.kind == Kind::EventDeletion
        || event.kind == Kind::from(62)
        || event.kind == Kind::from(HOLDING_METADATA_KIND)
        || event.kind == Kind::from(HISTORY_METADATA_KIND)
}
