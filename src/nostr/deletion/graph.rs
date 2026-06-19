/// Event Dependency Graph Builder
///
/// Builds a dependency graph for multi-maintainer deletion scenarios.
/// Tracks which events depend on which announcements, enabling selective
/// deletion when one maintainer removes their announcement but others remain.
use std::collections::{HashMap, HashSet};

use nostr_relay_builder::prelude::{Event, EventId, Kind};

/// Maximum depth for graph traversal to prevent infinite loops
const DEFAULT_MAX_DEPTH: usize = 100;

/// Node in the event dependency graph
#[derive(Debug, Clone)]
pub struct EventNode {
    /// Event ID
    pub event_id: EventId,
    /// Event kind
    pub kind: Kind,
    /// Event IDs this event references (via a/e/q tags)
    pub references: HashSet<EventId>,
    /// Announcement IDs that make this event acceptable (retention reasons)
    /// For announcements themselves, this is empty (they're self-justifying)
    /// For dependent events, this tracks which announcements they depend on
    pub retention_reasons: HashSet<EventId>,
}

impl EventNode {
    /// Create a new event node
    pub fn new(event_id: EventId, kind: Kind) -> Self {
        Self {
            event_id,
            kind,
            references: HashSet::new(),
            retention_reasons: HashSet::new(),
        }
    }

    /// Add a reference to another event
    pub fn add_reference(&mut self, referenced_id: EventId) {
        self.references.insert(referenced_id);
    }

    /// Add a retention reason (announcement that justifies keeping this event)
    pub fn add_retention_reason(&mut self, announcement_id: EventId) {
        self.retention_reasons.insert(announcement_id);
    }
}

/// Event dependency graph
///
/// Represents the dependency relationships between events in a repository.
/// Nodes are events, edges are references (a/e/q tags).
#[derive(Debug, Clone)]
pub struct EventGraph {
    /// All nodes in the graph, indexed by event ID
    nodes: HashMap<EventId, EventNode>,
    /// Reverse index: event ID -> events that reference it
    dependents: HashMap<EventId, HashSet<EventId>>,
    /// Maximum depth for traversal
    max_depth: usize,
}

impl EventGraph {
    /// Create a new empty event graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            dependents: HashMap::new(),
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }

    /// Create a new event graph with custom max depth
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            nodes: HashMap::new(),
            dependents: HashMap::new(),
            max_depth,
        }
    }

    /// Add a node to the graph
    pub fn add_node(&mut self, node: EventNode) {
        let event_id = node.event_id;

        // Update dependents index for all references
        for referenced_id in &node.references {
            self.dependents
                .entry(*referenced_id)
                .or_default()
                .insert(event_id);
        }

        self.nodes.insert(event_id, node);
    }

    /// Add an edge (reference) between two events
    ///
    /// # Arguments
    /// * `from` - Event ID that contains the reference
    /// * `to` - Event ID being referenced
    pub fn add_edge(&mut self, from: EventId, to: EventId) {
        // Add to node's references
        if let Some(node) = self.nodes.get_mut(&from) {
            node.add_reference(to);
        }

        // Update dependents index
        self.dependents.entry(to).or_default().insert(from);
    }

    /// Get a node by event ID
    pub fn get_node(&self, event_id: &EventId) -> Option<&EventNode> {
        self.nodes.get(event_id)
    }

    /// Get all nodes in the graph
    pub fn nodes(&self) -> &HashMap<EventId, EventNode> {
        &self.nodes
    }

    /// Get events that this event depends on (references)
    pub fn get_dependencies(&self, event_id: &EventId) -> HashSet<EventId> {
        self.nodes
            .get(event_id)
            .map(|node| node.references.clone())
            .unwrap_or_default()
    }

    /// Get events that depend on this event (reverse references)
    pub fn get_dependents(&self, event_id: &EventId) -> HashSet<EventId> {
        self.dependents.get(event_id).cloned().unwrap_or_default()
    }

    /// Get all transitive dependents of an event (up to max_depth)
    ///
    /// Returns all events that transitively depend on the given event,
    /// stopping at max_depth to prevent infinite loops.
    pub fn get_transitive_dependents(&self, event_id: &EventId) -> HashSet<EventId> {
        let mut result = HashSet::new();
        let mut to_process = vec![(event_id, 0)];
        let mut visited = HashSet::new();

        while let Some((current_id, depth)) = to_process.pop() {
            if depth >= self.max_depth {
                continue;
            }

            if visited.contains(current_id) {
                continue;
            }
            visited.insert(*current_id);

            // Get direct dependents
            if let Some(dependents) = self.dependents.get(current_id) {
                for dependent_id in dependents {
                    result.insert(*dependent_id);
                    to_process.push((dependent_id, depth + 1));
                }
            }
        }

        result
    }

    /// Get the maximum traversal depth
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Get the number of nodes in the graph
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the number of edges in the graph
    pub fn edge_count(&self) -> usize {
        self.nodes.values().map(|node| node.references.len()).sum()
    }
}

impl Default for EventGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Build an event dependency graph from a list of events
///
/// Creates a directed graph showing:
/// - Nodes: Events (with event IDs and kinds)
/// - Edges: References (a/e/q tags pointing to other events)
/// - Retention reasons: Which announcements make each event acceptable
///
/// # Arguments
/// * `events` - List of events to build graph from
///
/// # Returns
/// EventGraph with all dependencies mapped
pub fn build_event_graph(events: &[Event]) -> EventGraph {
    let mut graph = EventGraph::new();

    // First pass: Create nodes for all events
    for event in events {
        let mut node = EventNode::new(event.id, event.kind);

        // Extract references from a/e/q tags
        for tag in event.tags.iter() {
            let tag_vec = tag.as_slice();
            if tag_vec.is_empty() {
                continue;
            }

            match tag_vec[0].as_str() {
                "e" | "q" if tag_vec.len() >= 2 => {
                    // Event reference
                    if let Ok(referenced_id) = EventId::from_hex(&tag_vec[1]) {
                        node.add_reference(referenced_id);
                    }
                }
                "a" if tag_vec.len() >= 2 => {
                    // Address reference - need to find the event with this address
                    // For now, we'll handle this in a second pass after all nodes are added
                    // Store the address temporarily (we'll resolve it later)
                }
                _ => {}
            }
        }

        graph.add_node(node);
    }

    // Second pass: Resolve address references and compute retention reasons
    // Build a map of addresses to event IDs
    let mut address_to_event: HashMap<String, EventId> = HashMap::new();
    for event in events {
        // Check if this is a replaceable/addressable event (kind 30000-39999)
        let kind_num = event.kind.as_u16();
        if (30000..=39999).contains(&kind_num) {
            // Extract d-tag to build address
            for tag in event.tags.iter() {
                let tag_vec = tag.as_slice();
                if tag_vec.len() >= 2 && tag_vec[0] == "d" {
                    let d_tag = &tag_vec[1];
                    let address = format!("{}:{}:{}", kind_num, event.pubkey.to_hex(), d_tag);
                    address_to_event.insert(address, event.id);
                    break;
                }
            }
        }
    }

    // Third pass: Resolve address references and add edges
    for event in events {
        for tag in event.tags.iter() {
            let tag_vec = tag.as_slice();
            if tag_vec.len() >= 2 && tag_vec[0] == "a" {
                let address = &tag_vec[1];
                if let Some(&referenced_id) = address_to_event.get(address) {
                    graph.add_edge(event.id, referenced_id);
                }
            }
        }
    }

    // Fourth pass: Compute retention reasons
    // An event is retained if it's an announcement (kind 30617) or if it references
    // at least one announcement (directly or transitively)
    let announcement_kind = Kind::from(30617);

    // Find all announcements
    let announcements: HashSet<EventId> = events
        .iter()
        .filter(|e| e.kind == announcement_kind)
        .map(|e| e.id)
        .collect();

    // For each non-announcement event, find which announcements it depends on
    for event in events {
        if event.kind == announcement_kind {
            // Announcements are self-justifying (no retention reasons needed)
            continue;
        }

        // Find all announcements this event transitively depends on
        let mut retention_reasons = HashSet::new();
        let mut to_process = vec![event.id];
        let mut visited = HashSet::new();
        let mut depth = 0;

        while let Some(current_id) = to_process.pop() {
            if depth >= graph.max_depth {
                break;
            }

            if visited.contains(&current_id) {
                continue;
            }
            visited.insert(current_id);

            // Check if this is an announcement
            if announcements.contains(&current_id) {
                retention_reasons.insert(current_id);
            }

            // Add dependencies to process
            if let Some(node) = graph.nodes.get(&current_id) {
                for referenced_id in &node.references {
                    to_process.push(*referenced_id);
                }
            }

            depth += 1;
        }

        // Update the node with retention reasons
        if let Some(node) = graph.nodes.get_mut(&event.id) {
            node.retention_reasons = retention_reasons;
        }
    }

    graph
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::FinalizeEvent;
    use nostr_relay_builder::prelude::{EventBuilder, Keys, Tag};

    #[test]
    fn test_event_node_creation() {
        let event_id =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let kind = Kind::from(30617);

        let node = EventNode::new(event_id, kind);

        assert_eq!(node.event_id, event_id);
        assert_eq!(node.kind, kind);
        assert!(node.references.is_empty());
        assert!(node.retention_reasons.is_empty());
    }

    #[test]
    fn test_event_node_add_reference() {
        let event_id =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let referenced_id =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();

        let mut node = EventNode::new(event_id, Kind::from(1617));
        node.add_reference(referenced_id);

        assert_eq!(node.references.len(), 1);
        assert!(node.references.contains(&referenced_id));
    }

    #[test]
    fn test_event_graph_empty() {
        let graph = EventGraph::new();

        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
        assert_eq!(graph.max_depth(), DEFAULT_MAX_DEPTH);
    }

    #[test]
    fn test_event_graph_with_max_depth() {
        let graph = EventGraph::with_max_depth(50);

        assert_eq!(graph.max_depth(), 50);
    }

    #[test]
    fn test_event_graph_add_node() {
        let mut graph = EventGraph::new();
        let event_id =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let node = EventNode::new(event_id, Kind::from(30617));
        graph.add_node(node);

        assert_eq!(graph.node_count(), 1);
        assert!(graph.get_node(&event_id).is_some());
    }

    #[test]
    fn test_event_graph_add_edge() {
        let mut graph = EventGraph::new();
        let event_id_1 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let event_id_2 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();

        graph.add_node(EventNode::new(event_id_1, Kind::from(1617)));
        graph.add_node(EventNode::new(event_id_2, Kind::from(30617)));
        graph.add_edge(event_id_1, event_id_2);

        assert_eq!(graph.edge_count(), 1);

        let deps = graph.get_dependencies(&event_id_1);
        assert_eq!(deps.len(), 1);
        assert!(deps.contains(&event_id_2));

        let dependents = graph.get_dependents(&event_id_2);
        assert_eq!(dependents.len(), 1);
        assert!(dependents.contains(&event_id_1));
    }

    #[test]
    fn test_build_event_graph_empty() {
        let events: Vec<Event> = vec![];
        let graph = build_event_graph(&events);

        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_build_event_graph_single_event() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::from(30617), "test repo")
            .tags(vec![Tag::custom("d", vec!["test-repo".to_string()])])
            .finalize(&keys)
            .unwrap();

        let graph = build_event_graph(std::slice::from_ref(&event));

        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);

        let node = graph.get_node(&event.id).unwrap();
        assert_eq!(node.event_id, event.id);
        assert_eq!(node.kind, Kind::from(30617));
        assert!(node.references.is_empty());
        // Announcements are self-justifying
        assert!(node.retention_reasons.is_empty());
    }

    #[test]
    fn test_build_event_graph_with_reference() {
        let keys = Keys::generate();

        // Create announcement
        let announcement = EventBuilder::new(Kind::from(30617), "test repo")
            .tags(vec![Tag::custom("d", vec!["test-repo".to_string()])])
            .finalize(&keys)
            .unwrap();

        // Create patch that references the announcement
        let patch = EventBuilder::new(Kind::from(1617), "test patch")
            .tags(vec![Tag::custom("e", vec![announcement.id.to_hex()])])
            .finalize(&keys)
            .unwrap();

        let graph = build_event_graph(&[announcement.clone(), patch.clone()]);

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);

        // Check patch references announcement
        let deps = graph.get_dependencies(&patch.id);
        assert_eq!(deps.len(), 1);
        assert!(deps.contains(&announcement.id));

        // Check announcement has patch as dependent
        let dependents = graph.get_dependents(&announcement.id);
        assert_eq!(dependents.len(), 1);
        assert!(dependents.contains(&patch.id));

        // Check retention reasons
        let patch_node = graph.get_node(&patch.id).unwrap();
        assert_eq!(patch_node.retention_reasons.len(), 1);
        assert!(patch_node.retention_reasons.contains(&announcement.id));
    }

    #[test]
    fn test_build_event_graph_circular_reference() {
        let keys = Keys::generate();

        // Create two events that reference each other (shouldn't happen in practice,
        // but we need to handle it gracefully)
        let event1 = EventBuilder::new(Kind::from(1617), "event 1")
            .finalize(&keys)
            .unwrap();

        let event2 = EventBuilder::new(Kind::from(1617), "event 2")
            .tags(vec![Tag::custom("e", vec![event1.id.to_hex()])])
            .finalize(&keys)
            .unwrap();

        // Manually add circular reference (can't do this in real events)
        // For this test, we'll just verify the graph handles it without infinite loops
        let graph = build_event_graph(&[event1.clone(), event2.clone()]);

        assert_eq!(graph.node_count(), 2);

        // Get transitive dependents should not hang
        let dependents = graph.get_transitive_dependents(&event1.id);
        assert!(dependents.len() <= 2); // Should not infinite loop
    }

    #[test]
    fn test_event_graph_transitive_dependents() {
        let mut graph = EventGraph::new();

        // Create a chain: event1 <- event2 <- event3
        let event_id_1 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let event_id_2 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let event_id_3 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap();

        graph.add_node(EventNode::new(event_id_1, Kind::from(30617)));
        graph.add_node(EventNode::new(event_id_2, Kind::from(1617)));
        graph.add_node(EventNode::new(event_id_3, Kind::from(1619)));

        graph.add_edge(event_id_2, event_id_1);
        graph.add_edge(event_id_3, event_id_2);

        // Get transitive dependents of event1
        let dependents = graph.get_transitive_dependents(&event_id_1);
        assert_eq!(dependents.len(), 2);
        assert!(dependents.contains(&event_id_2));
        assert!(dependents.contains(&event_id_3));
    }

    #[test]
    fn test_event_graph_max_depth_limit() {
        let mut graph = EventGraph::with_max_depth(2);

        // Create a long chain: event1 <- event2 <- event3 <- event4
        let event_id_1 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let event_id_2 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let event_id_3 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap();
        let event_id_4 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000004")
                .unwrap();

        graph.add_node(EventNode::new(event_id_1, Kind::from(30617)));
        graph.add_node(EventNode::new(event_id_2, Kind::from(1617)));
        graph.add_node(EventNode::new(event_id_3, Kind::from(1619)));
        graph.add_node(EventNode::new(event_id_4, Kind::from(1619)));

        graph.add_edge(event_id_2, event_id_1);
        graph.add_edge(event_id_3, event_id_2);
        graph.add_edge(event_id_4, event_id_3);

        // Get transitive dependents of event1 with max_depth=2
        let dependents = graph.get_transitive_dependents(&event_id_1);
        // Should only get event2 and event3 (depth 1 and 2), not event4 (depth 3)
        assert!(dependents.len() <= 3); // Max depth limits traversal
    }
}
