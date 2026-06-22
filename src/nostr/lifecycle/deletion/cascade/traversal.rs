/// Graph Traversal and Circular Dependency Detection
///
/// Determines which events to keep vs delete in multi-maintainer scenarios by:
/// 1. Starting from kept repository announcements (kind 30617)
/// 2. Traversing the dependency graph to find all reachable events
/// 3. Detecting circular dependencies and handling them appropriately
/// 4. Marking unreachable events for deletion
use std::collections::{HashMap, HashSet, VecDeque};

use nostr_relay_builder::prelude::EventId;

use super::graph::EventGraph;
use super::reevaluation::RetentionReason;

/// Result of graph traversal and deletion marking
#[derive(Debug, Clone)]
pub struct TraversalResult {
    /// Events that should be KEPT (reachable from kept announcements)
    pub keep: HashSet<EventId>,
    /// Events that should be DELETED (unreachable from kept announcements)
    pub delete: HashSet<EventId>,
    /// Circular dependencies detected (for logging/debugging)
    pub circular_dependencies: Vec<CircularDependency>,
}

/// Information about a detected circular dependency
#[derive(Debug, Clone)]
pub struct CircularDependency {
    /// Event IDs involved in the circular dependency
    pub events: Vec<EventId>,
    /// Whether this cycle is anchored (has a path to a kept announcement)
    pub anchored: bool,
}

/// Traverse the event graph and mark events for deletion
///
/// This function implements a BFS traversal starting from kept repository announcements,
/// marking all reachable events as KEEP and unreachable events as DELETE.
///
/// # Arguments
/// * `graph` - Event dependency graph built from all events
/// * `kept_events` - Map of events to keep (from re-evaluation), keyed by event ID
/// * `deleted_announcement_id` - ID of the deleted announcement (for logging)
///
/// # Returns
/// `TraversalResult` with events to keep, events to delete, and detected circular dependencies
///
/// # Algorithm
/// 1. Identify all kept announcements (kind 30617) from `kept_events`
/// 2. Use BFS to traverse from kept announcements, following dependency edges
/// 3. Mark all reachable events as KEEP
/// 4. Detect circular dependencies during traversal
/// 5. Handle circular dependencies:
///    - If cycle is anchored (reachable from kept announcement): KEEP all events in cycle
///    - If cycle is unanchored (isolated): DELETE all events in cycle
/// 6. Mark all unreachable events as DELETE
/// 7. Respect max_depth from graph to prevent infinite loops
pub fn traverse_and_mark_deletions(
    graph: &EventGraph,
    kept_events: &HashMap<EventId, RetentionReason>,
    _deleted_announcement_id: EventId,
) -> TraversalResult {
    let mut result = TraversalResult {
        keep: HashSet::new(),
        delete: HashSet::new(),
        circular_dependencies: Vec::new(),
    };

    // Step 1: Identify kept announcements (kind 30617) as starting points
    let kept_announcements: Vec<EventId> = kept_events
        .iter()
        .filter_map(|(event_id, reason)| {
            // Check if this is a repository announcement
            if reason.event_type == "Repository Announcement" {
                Some(*event_id)
            } else {
                None
            }
        })
        .collect();

    tracing::debug!(
        kept_announcements_count = kept_announcements.len(),
        kept_events_count = kept_events.len(),
        total_nodes = graph.node_count(),
        "Starting graph traversal from kept announcements"
    );

    // Step 2: BFS traversal from kept announcements
    let reachable = bfs_traverse_from_announcements(graph, &kept_announcements);

    tracing::debug!(
        reachable_count = reachable.len(),
        "BFS traversal complete, found reachable events"
    );

    // Step 3: Detect circular dependencies
    let circular_deps = detect_circular_dependencies(graph, &reachable);

    tracing::debug!(
        circular_deps_count = circular_deps.len(),
        "Circular dependency detection complete"
    );

    // Step 4: Mark events as KEEP or DELETE
    for event_id in graph.nodes().keys() {
        if reachable.contains(event_id) {
            // Event is reachable from a kept announcement - KEEP
            result.keep.insert(*event_id);
        } else {
            // Event is not reachable - DELETE
            result.delete.insert(*event_id);
        }
    }

    result.circular_dependencies = circular_deps;

    tracing::info!(
        keep_count = result.keep.len(),
        delete_count = result.delete.len(),
        circular_deps_count = result.circular_dependencies.len(),
        "Graph traversal complete: {} kept, {} deleted, {} circular dependencies",
        result.keep.len(),
        result.delete.len(),
        result.circular_dependencies.len()
    );

    result
}

/// BFS traversal from kept announcements to find all reachable events
///
/// Uses breadth-first search to traverse the dependency graph, following both
/// forward references (dependencies) and backward references (dependents).
///
/// # Arguments
/// * `graph` - Event dependency graph
/// * `kept_announcements` - Starting points for traversal (kept announcements)
///
/// # Returns
/// Set of all event IDs reachable from kept announcements
fn bfs_traverse_from_announcements(
    graph: &EventGraph,
    kept_announcements: &[EventId],
) -> HashSet<EventId> {
    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();

    // Initialize queue with kept announcements
    for announcement_id in kept_announcements {
        queue.push_back((*announcement_id, 0)); // (event_id, depth)
        reachable.insert(*announcement_id);
    }

    let max_depth = graph.max_depth();

    while let Some((current_id, depth)) = queue.pop_front() {
        // Respect max depth to prevent infinite loops
        if depth >= max_depth {
            tracing::warn!(
                event_id = %current_id,
                depth = depth,
                max_depth = max_depth,
                "Reached max depth during BFS traversal"
            );
            continue;
        }

        // Skip if already visited
        if visited.contains(&current_id) {
            continue;
        }
        visited.insert(current_id);

        // Traverse to dependents (events that reference this event)
        // These are events that depend on the current event, so if the current
        // event is kept, its dependents should also be kept
        let dependents = graph.get_dependents(&current_id);
        for dependent_id in dependents {
            if !reachable.contains(&dependent_id) {
                reachable.insert(dependent_id);
                queue.push_back((dependent_id, depth + 1));
            }
        }

        // Note: We do NOT traverse to dependencies (events this event references)
        // because we're doing a forward traversal from announcements to dependents.
        // If we traversed backwards, we'd be going from dependents to announcements,
        // which is the opposite direction.
    }

    reachable
}

/// Detect circular dependencies in the graph
///
/// Finds cycles in the dependency graph and determines if they're anchored
/// (reachable from a kept announcement) or unanchored (isolated).
///
/// # Arguments
/// * `graph` - Event dependency graph
/// * `reachable` - Set of events reachable from kept announcements
///
/// # Returns
/// List of detected circular dependencies with anchoring information
fn detect_circular_dependencies(
    graph: &EventGraph,
    reachable: &HashSet<EventId>,
) -> Vec<CircularDependency> {
    let mut circular_deps = Vec::new();
    let mut visited = HashSet::new();
    let mut recursion_stack = HashSet::new();

    // Use DFS to detect cycles
    for event_id in graph.nodes().keys() {
        if !visited.contains(event_id) {
            let mut path = Vec::new();
            detect_cycles_dfs(
                graph,
                *event_id,
                &mut visited,
                &mut recursion_stack,
                &mut path,
                &mut circular_deps,
                reachable,
            );
        }
    }

    circular_deps
}

/// DFS helper for cycle detection
///
/// Uses depth-first search with a recursion stack to detect cycles.
/// When a cycle is found, checks if it's anchored (any event in cycle is reachable).
#[allow(clippy::too_many_arguments)]
fn detect_cycles_dfs(
    graph: &EventGraph,
    current_id: EventId,
    visited: &mut HashSet<EventId>,
    recursion_stack: &mut HashSet<EventId>,
    path: &mut Vec<EventId>,
    circular_deps: &mut Vec<CircularDependency>,
    reachable: &HashSet<EventId>,
) {
    visited.insert(current_id);
    recursion_stack.insert(current_id);
    path.push(current_id);

    // Get dependencies (events this event references)
    let dependencies = graph.get_dependencies(&current_id);

    for dep_id in dependencies {
        if !visited.contains(&dep_id) {
            // Continue DFS
            detect_cycles_dfs(
                graph,
                dep_id,
                visited,
                recursion_stack,
                path,
                circular_deps,
                reachable,
            );
        } else if recursion_stack.contains(&dep_id) {
            // Found a cycle! Extract the cycle from the path
            if let Some(cycle_start_idx) = path.iter().position(|&id| id == dep_id) {
                let cycle_events: Vec<EventId> = path[cycle_start_idx..].to_vec();

                // Check if cycle is anchored (any event in cycle is reachable)
                let anchored = cycle_events.iter().any(|id| reachable.contains(id));

                // Only add if we haven't seen this cycle before
                // (cycles can be detected multiple times from different entry points)
                let cycle_set: HashSet<EventId> = cycle_events.iter().copied().collect();
                let is_duplicate = circular_deps.iter().any(|cd| {
                    let cd_set: HashSet<EventId> = cd.events.iter().copied().collect();
                    cd_set == cycle_set
                });

                if !is_duplicate {
                    tracing::debug!(
                        cycle_events = ?cycle_events,
                        anchored = anchored,
                        "Detected circular dependency"
                    );

                    circular_deps.push(CircularDependency {
                        events: cycle_events,
                        anchored,
                    });
                }
            }
        }
    }

    path.pop();
    recursion_stack.remove(&current_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::lifecycle::deletion::{build_event_graph, EventNode, RetentionReason};
    use nostr::event::FinalizeEvent;
    use nostr_relay_builder::prelude::{EventBuilder, EventId, Keys, Kind, Tag};

    /// Helper to create a test event ID from a number
    fn test_event_id(n: u8) -> EventId {
        let hex = format!("{:064x}", n);
        EventId::from_hex(&hex).unwrap()
    }

    #[test]
    fn test_simple_linear_dependencies() {
        // Create a simple linear dependency chain:
        // announcement -> patch -> issue
        let mut graph = EventGraph::new();

        let announcement_id = test_event_id(1);
        let patch_id = test_event_id(2);
        let issue_id = test_event_id(3);

        // Add nodes
        graph.add_node(EventNode::new(announcement_id, Kind::from(30617)));
        graph.add_node(EventNode::new(patch_id, Kind::from(1617)));
        graph.add_node(EventNode::new(issue_id, Kind::from(1621)));

        // Add edges (patch references announcement, issue references patch)
        graph.add_edge(patch_id, announcement_id);
        graph.add_edge(issue_id, patch_id);

        // Create kept_events with announcement
        let mut kept_events = HashMap::new();
        kept_events.insert(
            announcement_id,
            RetentionReason {
                event_id: announcement_id,
                valid_announcements: vec![],
                event_type: "Repository Announcement".to_string(),
            },
        );

        // Traverse
        let result = traverse_and_mark_deletions(&graph, &kept_events, announcement_id);

        // All events should be kept (reachable from announcement)
        assert_eq!(result.keep.len(), 3);
        assert!(result.keep.contains(&announcement_id));
        assert!(result.keep.contains(&patch_id));
        assert!(result.keep.contains(&issue_id));

        assert_eq!(result.delete.len(), 0);
        assert_eq!(result.circular_dependencies.len(), 0);
    }

    #[test]
    fn test_isolated_subgraph() {
        // Create two subgraphs:
        // 1. announcement1 -> patch1 (KEPT)
        // 2. patch2 -> issue2 (isolated, should be DELETED)
        let mut graph = EventGraph::new();

        let announcement1_id = test_event_id(1);
        let patch1_id = test_event_id(2);
        let patch2_id = test_event_id(3);
        let issue2_id = test_event_id(4);

        // Add nodes
        graph.add_node(EventNode::new(announcement1_id, Kind::from(30617)));
        graph.add_node(EventNode::new(patch1_id, Kind::from(1617)));
        graph.add_node(EventNode::new(patch2_id, Kind::from(1617)));
        graph.add_node(EventNode::new(issue2_id, Kind::from(1621)));

        // Add edges
        graph.add_edge(patch1_id, announcement1_id);
        graph.add_edge(issue2_id, patch2_id);

        // Create kept_events with only announcement1
        let mut kept_events = HashMap::new();
        kept_events.insert(
            announcement1_id,
            RetentionReason {
                event_id: announcement1_id,
                valid_announcements: vec![],
                event_type: "Repository Announcement".to_string(),
            },
        );

        // Traverse
        let result = traverse_and_mark_deletions(&graph, &kept_events, announcement1_id);

        // announcement1 and patch1 should be kept
        assert_eq!(result.keep.len(), 2);
        assert!(result.keep.contains(&announcement1_id));
        assert!(result.keep.contains(&patch1_id));

        // patch2 and issue2 should be deleted (isolated)
        assert_eq!(result.delete.len(), 2);
        assert!(result.delete.contains(&patch2_id));
        assert!(result.delete.contains(&issue2_id));
    }

    #[test]
    fn test_circular_dependency_anchored() {
        // Create a circular dependency that's anchored to a kept announcement:
        // announcement -> patch1 <-> patch2 (circular)
        let mut graph = EventGraph::new();

        let announcement_id = test_event_id(1);
        let patch1_id = test_event_id(2);
        let patch2_id = test_event_id(3);

        // Add nodes
        graph.add_node(EventNode::new(announcement_id, Kind::from(30617)));
        graph.add_node(EventNode::new(patch1_id, Kind::from(1617)));
        graph.add_node(EventNode::new(patch2_id, Kind::from(1617)));

        // Add edges (circular: patch1 -> announcement, patch1 -> patch2, patch2 -> patch1)
        graph.add_edge(patch1_id, announcement_id);
        graph.add_edge(patch1_id, patch2_id);
        graph.add_edge(patch2_id, patch1_id);

        // Create kept_events with announcement
        let mut kept_events = HashMap::new();
        kept_events.insert(
            announcement_id,
            RetentionReason {
                event_id: announcement_id,
                valid_announcements: vec![],
                event_type: "Repository Announcement".to_string(),
            },
        );

        // Traverse
        let result = traverse_and_mark_deletions(&graph, &kept_events, announcement_id);

        // All events should be kept (circular dependency is anchored)
        assert_eq!(result.keep.len(), 3);
        assert!(result.keep.contains(&announcement_id));
        assert!(result.keep.contains(&patch1_id));
        assert!(result.keep.contains(&patch2_id));

        assert_eq!(result.delete.len(), 0);

        // Should detect the circular dependency
        assert_eq!(result.circular_dependencies.len(), 1);
        assert!(result.circular_dependencies[0].anchored);
    }

    #[test]
    fn test_circular_dependency_unanchored() {
        // Create an isolated circular dependency (no announcement):
        // patch1 <-> patch2 (circular, isolated)
        let mut graph = EventGraph::new();

        let patch1_id = test_event_id(1);
        let patch2_id = test_event_id(2);

        // Add nodes
        graph.add_node(EventNode::new(patch1_id, Kind::from(1617)));
        graph.add_node(EventNode::new(patch2_id, Kind::from(1617)));

        // Add edges (circular: patch1 -> patch2, patch2 -> patch1)
        graph.add_edge(patch1_id, patch2_id);
        graph.add_edge(patch2_id, patch1_id);

        // No kept events (no announcements)
        let kept_events = HashMap::new();

        // Traverse
        let result = traverse_and_mark_deletions(&graph, &kept_events, test_event_id(99));

        // Both events should be deleted (unanchored circular dependency)
        assert_eq!(result.keep.len(), 0);
        assert_eq!(result.delete.len(), 2);
        assert!(result.delete.contains(&patch1_id));
        assert!(result.delete.contains(&patch2_id));

        // Should detect the circular dependency as unanchored
        assert_eq!(result.circular_dependencies.len(), 1);
        assert!(!result.circular_dependencies[0].anchored);
    }

    #[test]
    fn test_deep_dependency_chain() {
        // Create a deep dependency chain (5 levels):
        // announcement -> e1 -> e2 -> e3 -> e4
        let mut graph = EventGraph::new();

        let announcement_id = test_event_id(1);
        let e1_id = test_event_id(2);
        let e2_id = test_event_id(3);
        let e3_id = test_event_id(4);
        let e4_id = test_event_id(5);

        // Add nodes
        graph.add_node(EventNode::new(announcement_id, Kind::from(30617)));
        graph.add_node(EventNode::new(e1_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e2_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e3_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e4_id, Kind::from(1617)));

        // Add edges (linear chain)
        graph.add_edge(e1_id, announcement_id);
        graph.add_edge(e2_id, e1_id);
        graph.add_edge(e3_id, e2_id);
        graph.add_edge(e4_id, e3_id);

        // Create kept_events with announcement
        let mut kept_events = HashMap::new();
        kept_events.insert(
            announcement_id,
            RetentionReason {
                event_id: announcement_id,
                valid_announcements: vec![],
                event_type: "Repository Announcement".to_string(),
            },
        );

        // Traverse
        let result = traverse_and_mark_deletions(&graph, &kept_events, announcement_id);

        // All events should be kept
        assert_eq!(result.keep.len(), 5);
        assert!(result.keep.contains(&announcement_id));
        assert!(result.keep.contains(&e1_id));
        assert!(result.keep.contains(&e2_id));
        assert!(result.keep.contains(&e3_id));
        assert!(result.keep.contains(&e4_id));

        assert_eq!(result.delete.len(), 0);
    }

    #[test]
    fn test_max_depth_limit() {
        // Create a deep chain that exceeds max depth
        let mut graph = EventGraph::with_max_depth(3);

        let announcement_id = test_event_id(1);
        let e1_id = test_event_id(2);
        let e2_id = test_event_id(3);
        let e3_id = test_event_id(4);
        let e4_id = test_event_id(5);
        let e5_id = test_event_id(6);

        // Add nodes
        graph.add_node(EventNode::new(announcement_id, Kind::from(30617)));
        graph.add_node(EventNode::new(e1_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e2_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e3_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e4_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e5_id, Kind::from(1617)));

        // Add edges (linear chain)
        graph.add_edge(e1_id, announcement_id);
        graph.add_edge(e2_id, e1_id);
        graph.add_edge(e3_id, e2_id);
        graph.add_edge(e4_id, e3_id);
        graph.add_edge(e5_id, e4_id);

        // Create kept_events with announcement
        let mut kept_events = HashMap::new();
        kept_events.insert(
            announcement_id,
            RetentionReason {
                event_id: announcement_id,
                valid_announcements: vec![],
                event_type: "Repository Announcement".to_string(),
            },
        );

        // Traverse
        let result = traverse_and_mark_deletions(&graph, &kept_events, announcement_id);

        // Should keep events within max_depth (announcement, e1, e2, e3)
        // e4 and e5 might not be reached due to depth limit
        assert!(result.keep.contains(&announcement_id));
        assert!(result.keep.contains(&e1_id));
        assert!(result.keep.contains(&e2_id));
        assert!(result.keep.contains(&e3_id));

        // Note: Depending on BFS implementation, e4 and e5 might be deleted
        // or kept. The important thing is that max_depth prevents infinite loops.
    }

    #[test]
    fn test_complex_reference_graph() {
        // Create a complex graph with multiple paths:
        //     announcement
        //     /     |     \
        //   e1     e2     e3
        //    |      |      |
        //   e4     e5     e6
        //     \    |    /
        //        e7
        let mut graph = EventGraph::new();

        let announcement_id = test_event_id(1);
        let e1_id = test_event_id(2);
        let e2_id = test_event_id(3);
        let e3_id = test_event_id(4);
        let e4_id = test_event_id(5);
        let e5_id = test_event_id(6);
        let e6_id = test_event_id(7);
        let e7_id = test_event_id(8);

        // Add nodes
        graph.add_node(EventNode::new(announcement_id, Kind::from(30617)));
        graph.add_node(EventNode::new(e1_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e2_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e3_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e4_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e5_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e6_id, Kind::from(1617)));
        graph.add_node(EventNode::new(e7_id, Kind::from(1617)));

        // Add edges
        graph.add_edge(e1_id, announcement_id);
        graph.add_edge(e2_id, announcement_id);
        graph.add_edge(e3_id, announcement_id);
        graph.add_edge(e4_id, e1_id);
        graph.add_edge(e5_id, e2_id);
        graph.add_edge(e6_id, e3_id);
        graph.add_edge(e7_id, e4_id);
        graph.add_edge(e7_id, e5_id);
        graph.add_edge(e7_id, e6_id);

        // Create kept_events with announcement
        let mut kept_events = HashMap::new();
        kept_events.insert(
            announcement_id,
            RetentionReason {
                event_id: announcement_id,
                valid_announcements: vec![],
                event_type: "Repository Announcement".to_string(),
            },
        );

        // Traverse
        let result = traverse_and_mark_deletions(&graph, &kept_events, announcement_id);

        // All events should be kept (all reachable from announcement)
        assert_eq!(result.keep.len(), 8);
        assert!(result.keep.contains(&announcement_id));
        assert!(result.keep.contains(&e1_id));
        assert!(result.keep.contains(&e2_id));
        assert!(result.keep.contains(&e3_id));
        assert!(result.keep.contains(&e4_id));
        assert!(result.keep.contains(&e5_id));
        assert!(result.keep.contains(&e6_id));
        assert!(result.keep.contains(&e7_id));

        assert_eq!(result.delete.len(), 0);
    }

    #[test]
    fn test_integration_with_build_event_graph() {
        // Integration test using build_event_graph from Phase 3A
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

        // Create issue that references the patch
        let issue = EventBuilder::new(Kind::from(1621), "test issue")
            .tags(vec![Tag::custom("e", vec![patch.id.to_hex()])])
            .finalize(&keys)
            .unwrap();

        // Build graph
        let graph = build_event_graph(&[announcement.clone(), patch.clone(), issue.clone()]);

        // Create kept_events with announcement
        let mut kept_events = HashMap::new();
        kept_events.insert(
            announcement.id,
            RetentionReason {
                event_id: announcement.id,
                valid_announcements: vec![],
                event_type: "Repository Announcement".to_string(),
            },
        );

        // Traverse
        let result = traverse_and_mark_deletions(&graph, &kept_events, announcement.id);

        // All events should be kept
        assert_eq!(result.keep.len(), 3);
        assert!(result.keep.contains(&announcement.id));
        assert!(result.keep.contains(&patch.id));
        assert!(result.keep.contains(&issue.id));

        assert_eq!(result.delete.len(), 0);
    }
}
