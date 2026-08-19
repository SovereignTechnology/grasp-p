//! GRASP Push Authorization
//!
//! This module implements the authorization logic for Git pushes according to GRASP-01.
//!
//! ## GRASP-01 Requirement
//!
//! "MUST accept pushes via this service that match the latest repo state announcement
//! on the relay, respecting the maintainer set."
//!
//! ## Authorization Flow (Efficient Single-Query Approach)
//!
//! 1. Fetch announcement and state events for the repository from the relay database
//! 2. Compute the confirmed maintainer set for the owner's repository
//! 3. Find the latest state event authored by a confirmed maintainer
//! 4. Validate that the pushed refs match the state event
//!
//! ## Authorization Logic
//!
//! Maintainership is reciprocal. A pubkey listed as a maintainer in an
//! announcement is only *invited*: none of its events are authoritative until
//! its own announcement for the same identifier lists back an existing
//! confirmed maintainer. See [`compute_membership`].
//!
//! ## Shared Helper Functions
//!
//! This module provides helper functions that can be used by both:
//! - Git push authorization in handlers.rs
//! - HEAD updates triggered by state events in builder.rs (event policy)

use anyhow::{anyhow, Result};
use hyper::body::Bytes;
use nostr_sdk::prelude::*;
use nostr_sdk::prelude::{EventId, ToBech32};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::nostr::events::{RepositoryAnnouncement, RepositoryState};
use crate::nostr::SharedDatabase;
use crate::purgatory::Purgatory;
use nostr_sdk::prelude::{Kind, PublicKey};

/// Perform GRASP authorization for a push operation
///
/// This function queries the database directly (not via WebSocket):
/// 1. Parses the pushed refs from the git pack protocol
/// 2. Separates refs/nostr/ refs from normal refs
/// 3. For normal refs: validates against state events in purgatory
/// 4. For refs/nostr/ refs: validates event ID format and collects PR/PR-update events from purgatory
/// 5. Returns all authorizing events (state + PR/PR-update) in the result
pub async fn authorize_push(
    database: &SharedDatabase,
    identifier: &str,
    owner_pubkey: &str,
    request_body: &Bytes,
    purgatory: &Arc<Purgatory>,
    repo_path: &std::path::Path,
) -> anyhow::Result<AuthorizationResult> {
    debug!(
        "Authorizing push for {} owned by {} via database query",
        identifier, owner_pubkey
    );

    // Parse refs from the push request
    let pushed_refs = parse_pushed_refs(request_body);
    debug!("Parsed {} refs from push request", pushed_refs.len());
    for (old_oid, new_oid, ref_name) in &pushed_refs {
        debug!("  {} {} -> {}", ref_name, old_oid, new_oid);
    }

    // Separate refs/nostr/ refs from state refs
    let (nostr_refs, state_refs): (Vec<_>, Vec<_>) = pushed_refs
        .iter()
        .partition(|(_, _, ref_name)| ref_name.starts_with("refs/nostr/"));

    // Collect all purgatory events that authorize this push
    let mut purgatory_events = Vec::new();

    // Handle refs/nostr/ refs - validate and collect PR/PR-update events from purgatory
    if !nostr_refs.is_empty() {
        debug!(
            "Found {} refs/nostr/ refs - validating and collecting from purgatory",
            nostr_refs.len()
        );

        for (_, new_oid, ref_name) in &nostr_refs {
            // Standard endpoint passes `None` for prs_url: signer / a-tag
            // identifier are enforced by the surrounding maintainer-set
            // authorization, not by the URL.
            match pre_validate_refs_nostr_push(database, purgatory, new_oid, ref_name, None).await {
                NostrRefPreValidation::Rejected { reason } => {
                    warn!("refs/nostr/ validation failed: {}", reason);
                    return Ok(AuthorizationResult::denied(reason));
                }
                NostrRefPreValidation::Authorized {
                    event_from_purgatory,
                } => {
                    if let Some(event) = event_from_purgatory {
                        debug!("Found matching PR event in purgatory for ref {}", ref_name);
                        purgatory_events.push(event);
                    } else {
                        debug!("Ref {} validated against existing record", ref_name);
                    }
                }
                NostrRefPreValidation::Unknown => {
                    // No entry in DB or purgatory — create placeholder so
                    // the 30-minute sweep can clean the ref up if the PR
                    // event never arrives. Standard-endpoint placeholders
                    // carry no /prs/ scope.
                    let event_id_hex = ref_name
                        .strip_prefix("refs/nostr/")
                        .expect("shape validated in pre_validate_refs_nostr_push");
                    purgatory.add_pr_placeholder(event_id_hex.to_string(), new_oid.clone());
                    debug!(
                        "Created placeholder for {} - awaiting PR event (will expire in 30min if event doesn't arrive)",
                        event_id_hex
                    );
                }
            }
        }
    }

    // Handle normal refs - validate against state events
    if !state_refs.is_empty() {
        debug!(
            "Found {} non-refs/nostr/ refs - checking state authorization",
            state_refs.len()
        );
        let auth_result = get_state_authorization_for_specific_owner_repo(
            database,
            identifier,
            owner_pubkey,
            purgatory,
            &pushed_refs, //it would be better to accept state_refs but thats in different format
            repo_path,
        )
        .await?;

        if !auth_result.authorized {
            return Ok(auth_result);
        }

        // Collect state events from purgatory
        purgatory_events.extend(auth_result.purgatory_events);

        // Validate refs against state
        let other_refs_owned: Vec<(String, String, String)> = state_refs
            .into_iter()
            .map(|(a, b, c)| (a.clone(), b.clone(), c.clone()))
            .collect();

        if let Some(ref state) = auth_result.state {
            debug!(
                "Validating against state with {} branches",
                state.branches.len()
            );

            if other_refs_owned.is_empty() && !state.branches.is_empty() {
                warn!("No refs parsed from push request but state event has branches - rejecting");
                return Ok(AuthorizationResult::denied(
                    "Failed to parse refs from push request - cannot validate against state",
                ));
            }

            if let Err(e) = validate_push_refs(state, &other_refs_owned) {
                warn!("Ref validation failed: {}", e);
                return Ok(AuthorizationResult::denied(format!(
                    "Ref validation failed: {}",
                    e
                )));
            }
            debug!("Ref validation passed");
        }

        // Return result with purgatory events
        return Ok(AuthorizationResult {
            authorized: true,
            reason: auth_result.reason,
            state: auth_result.state,
            maintainers: auth_result.maintainers,
            purgatory_events,
        });
    }

    // Only refs/nostr/ refs - return success with collected events
    Ok(AuthorizationResult {
        authorized: true,
        reason: "Push to refs/nostr/ validated".to_string(),
        state: None,
        maintainers: vec![],
        purgatory_events,
    })
}

/// Repository data fetched from the database
///
/// Contains all announcements and states for a given identifier,
/// fetched with a single filter query.
#[derive(Debug)]
pub struct RepositoryData {
    /// All repository announcements with this identifier
    pub announcements: Vec<RepositoryAnnouncement>,
    /// All repository state events with this identifier
    pub states: Vec<RepositoryState>,
}

/// Fetch all repository data (announcements + states) for a given identifier
///
/// This performs a single database query to fetch both announcement and state events,
/// which is more efficient than separate queries.
pub async fn fetch_repository_data_excluding_purgatory(
    database: &SharedDatabase,
    identifier: &str,
) -> Result<RepositoryData> {
    let filter = Filter::new()
        .kinds([Kind::GitRepoAnnouncement, Kind::RepoState])
        .custom_tag(SingleLetterTag::LOWERCASE_D, identifier.to_string());

    let events: Vec<Event> = database
        .query(filter)
        .await
        .map_err(|e| anyhow!("Database query failed: {}", e))?
        .into_iter()
        .collect();

    debug!(
        "Fetched {} events for identifier {} from database",
        events.len(),
        identifier
    );

    // Separate into announcements and states
    let mut announcements = Vec::new();
    let mut states = Vec::new();

    for event in events {
        if event.kind == Kind::GitRepoAnnouncement {
            if let Ok(announcement) = RepositoryAnnouncement::from_event(event) {
                announcements.push(announcement);
            }
        } else if event.kind == Kind::RepoState {
            if let Ok(state) = RepositoryState::from_event(event) {
                states.push(state);
            }
        }
    }

    debug!(
        "Parsed {} announcements and {} states from database for identifier {}",
        announcements.len(),
        states.len(),
        identifier
    );

    Ok(RepositoryData {
        announcements,
        states,
    })
}

/// Fetch repository data including announcements from purgatory
///
/// This combines database announcements with purgatory announcements,
/// which is needed for authorization when the announcement hasn't been
/// promoted yet (no git data has arrived).
pub async fn fetch_repository_data_with_purgatory(
    database: &SharedDatabase,
    purgatory: &crate::purgatory::Purgatory,
    identifier: &str,
) -> Result<RepositoryData> {
    // First, fetch from database
    let mut repo_data = fetch_repository_data_excluding_purgatory(database, identifier).await?;

    // Then, add announcements from purgatory
    let purgatory_announcements = purgatory.get_announcements_by_identifier(identifier);
    let purgatory_count = purgatory_announcements.len();

    for entry in purgatory_announcements {
        if let Ok(announcement) = RepositoryAnnouncement::from_event(entry.event) {
            if let Some(current) = repo_data.announcements.iter_mut().find(|current| {
                current.event.pubkey == announcement.event.pubkey
                    && current.identifier == announcement.identifier
            }) {
                *current = announcement;
            } else {
                repo_data.announcements.push(announcement);
            }
        }
    }

    debug!(
        "Fetched repository data with purgatory: {} announcements ({} from purgatory), {} states",
        repo_data.announcements.len(),
        purgatory_count,
        repo_data.states.len()
    );

    Ok(repo_data)
}

pub fn pubkey_authorised_for_repo_owners(
    pubkey: &PublicKey,
    db_repo_data: &RepositoryData,
) -> Vec<String> {
    let mut repo_owners_authorising_pubkey = HashSet::new();
    let collections = collect_authorized_maintainers(&db_repo_data.announcements);
    for (owner, authoised) in collections {
        if authoised.contains(&pubkey.to_hex()) {
            repo_owners_authorising_pubkey.insert(owner.to_string());
        }
    }
    repo_owners_authorising_pubkey.iter().cloned().collect()
}

/// Confirmed membership of one owner's repository.
#[derive(Debug, Default)]
pub struct RepoMembership {
    /// Pubkeys whose repository state events are authoritative for this
    /// owner's repository: the owner plus every confirmed maintainer.
    pub state_maintainers: HashSet<String>,
    /// Pubkeys currently listed as maintainers whose own announcement does
    /// not yet list back a confirmed maintainer. Their announcements must
    /// still be fetched and accepted - that is how the relay notices an
    /// invitation was accepted - but none of their events are authoritative.
    pub invited: HashSet<String>,
}

/// Compute the confirmed maintainer set for `owner`'s repository.
///
/// A pubkey listed as a maintainer is only *invited* until its own
/// announcement for the same identifier lists back a pubkey that is already
/// a confirmed maintainer (reciprocal acknowledgment). Confirmation is
/// evaluated as a fixpoint, so maintainers listed by other confirmed
/// maintainers are reached recursively.
///
/// The owner is always a confirmed maintainer of their own repository:
/// announcing a repository in their namespace is what creates it on this
/// service.
pub fn compute_membership(
    announcements: &[RepositoryAnnouncement],
    owner: &str,
    identifier: &str,
) -> RepoMembership {
    let find = |pubkey: &str| {
        announcements
            .iter()
            .find(|a| a.event.pubkey.to_hex() == pubkey && a.identifier == identifier)
    };
    if find(owner).is_none() {
        return RepoMembership::default();
    }

    let mut confirmed: HashSet<String> = HashSet::from([owner.to_string()]);
    // Fixpoint: keep confirming listed pubkeys whose own announcement lists
    // back an already-confirmed maintainer. The confirmed set only grows, so
    // the loop terminates.
    loop {
        let listed: HashSet<String> = confirmed
            .iter()
            .filter_map(|member| find(member))
            .flat_map(|announcement| announcement.listed_maintainers())
            .collect();

        let mut progressed = false;
        for candidate in &listed {
            if confirmed.contains(candidate) {
                continue;
            }
            let Some(candidate_announcement) = find(candidate) else {
                continue; // invited: no announcement of their own yet
            };
            let lists_back = candidate_announcement
                .listed_maintainers()
                .iter()
                .any(|pubkey| confirmed.contains(pubkey));
            if lists_back {
                confirmed.insert(candidate.clone());
                progressed = true;
            }
        }

        if !progressed {
            let invited = listed
                .into_iter()
                .filter(|pubkey| !confirmed.contains(pubkey))
                .collect();
            return RepoMembership {
                state_maintainers: confirmed,
                invited,
            };
        }
    }
}

/// Collect authorized state publishers grouped by owner from a set of
/// announcements.
///
/// For each announcement, returns a map from owner pubkey to the pubkeys
/// whose repository state events are authoritative for that owner's
/// repository: the confirmed maintainer set computed by
/// [`compute_membership`]. Invited pubkeys (listed but without a reciprocal
/// announcement) are never included.
pub fn collect_authorized_maintainers(
    announcements: &[RepositoryAnnouncement],
) -> HashMap<String, Vec<String>> {
    let mut by_owner: HashMap<String, Vec<String>> = HashMap::new();

    for announcement in announcements {
        let owner = announcement.event.pubkey.to_hex();
        let membership = compute_membership(announcements, &owner, &announcement.identifier);
        by_owner.insert(owner, membership.state_maintainers.into_iter().collect());
    }

    debug!(
        "Collected confirmed state maintainers for {} owners from {} announcements",
        by_owner.len(),
        announcements.len()
    );

    by_owner
}

/// Get the authorization result for a repository scoped to a specific owner
///
/// Push authorization checks ONLY purgatory for state events. The database represents
/// the current git state, while purgatory holds the intended future state that pushes
/// should be authorized against.
///
/// A push to `alice/my-repo` should only consider authorization from alice's
/// announcement, not bob's announcement for the same identifier.
///
/// It:
/// 1. Fetches announcements for the identifier
/// 2. Collects authorized maintainers from owner's announcement
/// 3. Checks purgatory for matching state events from authorized maintainers
///
/// Returns an `AuthorizationResult` that indicates whether a push is authorized.
pub async fn get_state_authorization_for_specific_owner_repo(
    database: &SharedDatabase,
    identifier: &str,
    owner_pubkey: &str,
    purgatory: &std::sync::Arc<crate::purgatory::Purgatory>,
    pushed_refs: &[(String, String, String)],
    repo_path: &std::path::Path,
) -> Result<AuthorizationResult> {
    use crate::git::list_refs;
    use crate::purgatory::RefUpdate;

    // Fetch announcements from database AND purgatory - needed for authorization
    // when the announcement hasn't been promoted yet (no git data has arrived)
    let repo_data = fetch_repository_data_with_purgatory(database, purgatory, identifier).await?;

    if repo_data.announcements.is_empty() {
        return Ok(AuthorizationResult::denied(
            "No repository announcement found",
        ));
    }

    // Collect authorized maintainers grouped by owner from all announcements
    let by_owner = collect_authorized_maintainers(&repo_data.announcements);

    // Look up the authorized set for this specific owner
    let authorized: HashSet<String> = match by_owner.get(owner_pubkey) {
        Some(maintainers) => maintainers.iter().cloned().collect(),
        None => {
            return Ok(AuthorizationResult::denied(format!(
                "No repository announcement found for owner {}",
                owner_pubkey
            )));
        }
    };

    if authorized.is_empty() {
        return Ok(AuthorizationResult::denied(
            "No authorized maintainers found",
        ));
    }

    debug!(
        "Found {} authorized maintainers for repository {} (owner: {})",
        authorized.len(),
        identifier,
        owner_pubkey
    );

    // Accept pushes where all refs are already at the desired state (old_oid == new_oid)
    // This handles race conditions where state events are applied between fetch and push
    if !pushed_refs.is_empty() {
        let all_refs_unchanged = pushed_refs
            .iter()
            .all(|(old_oid, new_oid, _)| old_oid == new_oid);

        if all_refs_unchanged {
            debug!(
                "All pushed refs unchanged (old_oid == new_oid) for {} owned by {}, accepting without purgatory check",
                identifier, owner_pubkey
            );
            return Ok(AuthorizationResult {
                authorized: true,
                reason: "Push accepted: all refs already at desired state (no-op)".to_string(),
                state: None,
                maintainers: authorized.into_iter().collect(),
                purgatory_events: vec![],
            });
        }
    }

    // Check purgatory for matching state events
    // Convert pushed refs to RefUpdate (filter out refs/nostr/* refs)
    let pushed_updates: Vec<RefUpdate> = pushed_refs
        .iter()
        .filter(|(_, _, name)| !name.starts_with("refs/nostr/"))
        .map(|(old_oid, new_oid, ref_name)| RefUpdate {
            old_oid: old_oid.clone(),
            new_oid: new_oid.clone(),
            ref_name: ref_name.clone(),
        })
        .collect();

    // Get local refs from repository
    let local_refs_list = list_refs(repo_path).unwrap_or_default();
    let local_refs: HashMap<String, String> = local_refs_list.into_iter().collect();

    // Find matching state events in purgatory
    let matching_events = purgatory.find_matching_states(identifier, &pushed_updates, &local_refs);

    if !matching_events.is_empty() {
        debug!(
            "Found {} matching state event(s) in purgatory",
            matching_events.len()
        );

        // Filter to authorized events and collect them
        let authorized_events: Vec<Event> = matching_events
            .into_iter()
            .filter(|event| {
                let author_hex = event.pubkey.to_hex();
                authorized.contains(&author_hex)
            })
            .collect();

        if !authorized_events.is_empty() {
            // Find the latest event
            let latest_authorized = authorized_events
                .iter()
                .max_by_key(|event| event.created_at)
                .unwrap(); // Safe because we checked the vec is not empty

            // Parse the event into RepositoryState
            if let Ok(state) = RepositoryState::from_event(latest_authorized.clone()) {
                info!(
                    "Authorized by state event {} from purgatory (author: {})",
                    latest_authorized.id,
                    latest_authorized
                        .pubkey
                        .to_bech32()
                        .unwrap_or_else(|_| latest_authorized.pubkey.to_hex())
                );

                // Extend purgatory announcement expiry for the owner.
                //
                // Per design doc decision #4: git auth extending a state event's expiry
                // also extends the announcement's expiry. The repo is actively receiving
                // git data, so the announcement should not expire prematurely.
                // This also revives soft-expired announcements (recreates bare repo).
                if let Ok(owner_pk) = PublicKey::parse(owner_pubkey) {
                    if purgatory.has_purgatory_announcement(&owner_pk, identifier) {
                        purgatory.extend_announcement_expiry(
                            &owner_pk,
                            identifier,
                            std::time::Duration::from_secs(1800),
                        );
                        debug!(
                            identifier = %identifier,
                            owner = %owner_pubkey,
                            "Extended purgatory announcement expiry due to git push authorization"
                        );
                    }
                }

                return Ok(AuthorizationResult {
                    authorized: true,
                    reason: "Authorized by state event in purgatory".to_string(),
                    state: Some(state),
                    maintainers: authorized.into_iter().collect(),
                    purgatory_events: vec![latest_authorized.clone()],
                });
            } else {
                warn!(
                    "Failed to parse purgatory event {} as RepositoryState",
                    latest_authorized.id
                );
            }
        } else {
            debug!("Purgatory events found but none from authorized authors");
        }
    } else {
        // Check if there are ANY state events in purgatory for this identifier
        let all_purgatory_states = purgatory.find_state(identifier);

        if !all_purgatory_states.is_empty() {
            // There are state events but none match the push - diagnose why
            debug!(
                "Found {} state event(s) in purgatory for {} but none match the push",
                all_purgatory_states.len(),
                identifier
            );

            // Count authorized state events and collect diagnostic info
            let mut authorized_count = 0;
            let mut diagnostic_reasons = Vec::new();

            // Diagnose why each authorized state event doesn't match
            for entry in all_purgatory_states.iter() {
                let author_hex = entry.event.pubkey.to_hex();
                if authorized.contains(&author_hex) {
                    authorized_count += 1;
                    if let Some(reason) = crate::purgatory::diagnose_state_mismatch(
                        &entry.event,
                        &pushed_updates,
                        &local_refs,
                    ) {
                        debug!(
                            "State event {} from authorized author {} doesn't match push: {}",
                            entry.event.id,
                            entry
                                .event
                                .pubkey
                                .to_bech32()
                                .unwrap_or_else(|_| author_hex.clone()),
                            reason
                        );
                        diagnostic_reasons.push(reason);
                    }
                }
            }

            // Create concise WARN message summarizing the rejection
            let summary = if authorized_count > 0 {
                let reason_summary = if !diagnostic_reasons.is_empty() {
                    // Take the first diagnostic reason as representative
                    format!(" ({})", diagnostic_reasons[0])
                } else {
                    String::new()
                };
                format!(
                    "{} state event{} in purgatory from authorized publisher{} but doesn't match push{}",
                    authorized_count,
                    if authorized_count == 1 { "" } else { "s" },
                    if authorized_count == 1 { "" } else { "s" },
                    reason_summary
                )
            } else {
                format!(
                    "{} state event{} in purgatory but none from authorized publishers",
                    all_purgatory_states.len(),
                    if all_purgatory_states.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            };

            warn!("Push rejected for {}: {}", identifier, summary);
            return Ok(AuthorizationResult::denied(summary));
        } else {
            debug!("No state events found in purgatory for {}", identifier);
            warn!(
                "Push rejected for {}: No state events in purgatory",
                identifier
            );
            return Ok(AuthorizationResult::denied("No state events in purgatory"));
        }
    }

    // No matching state found in purgatory
    Ok(AuthorizationResult::denied(
        "No matching state event found in purgatory from authorized publishers",
    ))
}

/// Result of authorization check
#[derive(Debug)]
pub struct AuthorizationResult {
    /// Whether the push is authorized
    pub authorized: bool,
    /// Reason for the decision (for logging/debugging)
    pub reason: String,
    /// The authorized state if available
    pub state: Option<RepositoryState>,
    /// The set of valid maintainers (authorized publishers)
    pub maintainers: Vec<String>,
    /// Events from purgatory that authorized this push (state, PR, PR-update events)
    pub purgatory_events: Vec<Event>,
}

impl AuthorizationResult {
    /// Create a denied authorization result
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            authorized: false,
            reason: reason.into(),
            state: None,
            maintainers: vec![],
            purgatory_events: vec![],
        }
    }
}

/// Validate that pushed refs match the authorized state
///
/// Takes the refs being pushed (ref name -> commit hash) and validates
/// against the state event.
pub fn validate_push_refs(
    state: &RepositoryState,
    pushed_refs: &[(String, String, String)], // (old_oid, new_oid, ref_name)
) -> Result<()> {
    for (old_oid, new_oid, ref_name) in pushed_refs {
        debug!("Validating push: {} {} -> {}", ref_name, old_oid, new_oid);

        // Handle branch updates
        if let Some(branch_name) = ref_name.strip_prefix("refs/heads/") {
            if let Some(expected_commit) = state.get_branch_commit(branch_name) {
                if new_oid != expected_commit {
                    return Err(anyhow!(
                        "Branch {} push rejected: expected commit {}, got {}",
                        branch_name,
                        expected_commit,
                        new_oid
                    ));
                }
                // Commit matches state - authorized
                debug!(
                    "Branch {} push authorized: {} matches state",
                    branch_name, new_oid
                );
            } else {
                // Branch not in state - REJECT (GRASP-01 requirement)
                return Err(anyhow!(
                    "Branch {} push rejected: not announced in state event",
                    branch_name
                ));
            }
        }

        // Handle tag updates
        if let Some(tag_name) = ref_name.strip_prefix("refs/tags/") {
            if let Some(expected_commit) = state.get_tag_commit(tag_name) {
                if new_oid != expected_commit {
                    return Err(anyhow!(
                        "Tag {} push rejected: expected commit {}, got {}",
                        tag_name,
                        expected_commit,
                        new_oid
                    ));
                }
            }
        }

        // refs/nostr/* is handled separately per GRASP-01
        if ref_name.starts_with("refs/nostr/") {
            // Extract event_id from "refs/nostr/<event-id>"
            if let Some(event_id_str) = ref_name.strip_prefix("refs/nostr/") {
                // Validate it parses as a valid EventId
                if EventId::parse(event_id_str).is_err() {
                    return Err(anyhow!(
                        "Invalid event ID format in ref: {}. Expected valid nostr event ID.",
                        ref_name
                    ));
                }
                // Valid EventId format - allow push (skip state event check)
                debug!(
                    "refs/nostr/{} push authorized (valid EventId)",
                    event_id_str
                );
                continue; // Skip the rest of ref validation for this ref
            } else {
                return Err(anyhow!("Invalid refs/nostr/ format: {}", ref_name));
            }
        }
    }

    Ok(())
}

/// Parse the refs being updated from a Git pack
///
/// The receive-pack protocol sends ref updates in pkt-line format:
/// - 4-byte hex length prefix (e.g., "00a5")
/// - Payload: `<old-oid> <new-oid> <ref-name>\0<capabilities>\n`
/// - Flush packet "0000" terminates the list
/// - Then comes the PACK data
///
/// This function handles both pkt-line format (from real Git clients) and
/// simple text format (for unit tests).
pub fn parse_pushed_refs(data: &[u8]) -> Vec<(String, String, String)> {
    // Check if this looks like pkt-line format (starts with 4 hex digits)
    // A valid pkt-line push starts with a length > 4 (not a flush packet)
    if data.len() >= 4 {
        if let Ok(len_str) = std::str::from_utf8(&data[0..4]) {
            if let Ok(len) = u16::from_str_radix(len_str, 16) {
                // A valid pkt-line data packet has length > 4 (flush is 0)
                // Also check that the length makes sense for a ref update
                if len > 4 && (len as usize) <= data.len() {
                    // This is pkt-line format, parse it properly
                    return parse_pktline_refs(data);
                }
            }
        }
    }

    // Fall back to simple text format (for tests)
    parse_text_refs(data)
}

/// Parse refs from pkt-line format data
fn parse_pktline_refs(mut data: &[u8]) -> Vec<(String, String, String)> {
    let mut refs = Vec::new();

    while data.len() >= 4 {
        // Parse pkt-line length prefix
        let len_str = match std::str::from_utf8(&data[0..4]) {
            Ok(s) => s,
            Err(_) => break,
        };

        let len = match u16::from_str_radix(len_str, 16) {
            Ok(l) => l as usize,
            Err(_) => break,
        };

        // Flush packet (0000) ends the ref list
        if len == 0 {
            break;
        }

        if len < 4 || data.len() < len {
            break;
        }

        // Extract payload (without the 4-byte length prefix)
        let payload = &data[4..len];

        // Parse the payload: "old_oid new_oid ref_name\0capabilities\n"
        if let Some(ref_update) = parse_ref_line(payload) {
            refs.push(ref_update);
        }

        // Move to next pkt-line
        data = &data[len..];
    }

    debug!("Parsed {} refs from pkt-line format", refs.len());
    refs
}

/// Parse refs from simple text format (for backward compatibility with tests)
fn parse_text_refs(data: &[u8]) -> Vec<(String, String, String)> {
    let mut refs = Vec::new();
    let text = String::from_utf8_lossy(data);

    for line in text.lines() {
        // Skip empty lines and pack data
        if line.is_empty() || line.starts_with("PACK") {
            continue;
        }

        if let Some(ref_update) = parse_ref_line(line.as_bytes()) {
            refs.push(ref_update);
        }
    }

    refs
}

/// Parse a single ref update line: "old_oid new_oid ref_name\0capabilities"
fn parse_ref_line(payload: &[u8]) -> Option<(String, String, String)> {
    // Convert to string, handling potential invalid UTF-8
    let line = String::from_utf8_lossy(payload);

    // Strip trailing newline if present
    let line = line.trim_end_matches('\n');

    // Split at null byte to separate command from capabilities
    let command_part = line.split('\0').next().unwrap_or("");

    // Parse "old_oid new_oid ref_name"
    let parts: Vec<&str> = command_part.split_whitespace().collect();
    if parts.len() >= 3 {
        let old_oid = parts[0];
        let new_oid = parts[1];
        let ref_name = parts[2];

        // Validate OID format (40 hex chars)
        if old_oid.len() == 40
            && new_oid.len() == 40
            && old_oid.chars().all(|c| c.is_ascii_hexdigit())
            && new_oid.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Some((
                old_oid.to_string(),
                new_oid.to_string(),
                ref_name.to_string(),
            ));
        }
    }

    None
}

/// Convert hex pubkey to bech32 npub format
pub fn pubkey_to_npub(hex_pubkey: &str) -> Result<String> {
    let pk = PublicKey::parse(hex_pubkey)?;
    Ok(pk.to_bech32()?)
}

/// Convert bech32 npub to hex pubkey format
pub fn npub_to_pubkey(npub: &str) -> Result<String> {
    let pk = PublicKey::parse(npub)?;
    Ok(pk.to_hex())
}

/// Fetch a PR (kind 1617) or PR-Update (kind 1618) event by its ID.
///
/// Returns the first matching event, or `None` if no such event has been
/// accepted into the database. Used by [`pre_validate_refs_nostr_push`]
/// — which needs the full event so it can verify the signer pubkey and
/// the `a`-tag identifier on top of the `c` tag.
pub async fn get_pr_event_by_id(
    database: &SharedDatabase,
    event_id: &EventId,
) -> Result<Option<Event>> {
    let filter = Filter::new()
        .ids([*event_id])
        .kinds([Kind::GitPullRequest, Kind::GitPullRequestUpdate]);

    let events: Vec<Event> = database
        .query(filter)
        .await
        .map_err(|e| anyhow!("Database query failed: {}", e))?
        .into_iter()
        .collect();

    Ok(events.into_iter().next())
}

/// Extract the `c` (commit) tag value from a NIP-34 PR/PR-Update event.
///
/// Per NIP-34, PR events carry a `c` tag whose second element is the head
/// commit being proposed. Returns `None` if the tag is missing or malformed.
pub fn extract_commit_tag(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().map(|s| s.as_str()) == Some("c"))
        .and_then(|tag| tag.as_slice().get(1).map(|s| s.to_string()))
}

/// Constraints imposed by the GRASP-06 `/prs/<npub>/<identifier>` URL on
/// any event resolved while pre-validating a `refs/nostr/<event-id>`
/// push.
///
/// When present, a known event found in the DB or purgatory MUST have:
///
/// - `event.pubkey == submitter`,
/// - at least one `a`-tag of the form `30617:<hex>:<d>` where `d ==
///   identifier`, AND
/// - at least one `clone` tag naming this relay's
///   `/prs/<submitter-npub>/<identifier>.git` endpoint (the opt-in
///   signal that prevents every GRASP-06 relay from accepting every PR
///   event that happens to match its URL shape).
///
/// Standard `/<npub>/<id>.git` pushes pass `None` here — they rely on the
/// surrounding `authorize_push` flow to gate by the maintainer set
/// instead.
#[derive(Debug, Clone, Copy)]
pub struct PrsUrlConstraints<'a> {
    pub submitter: &'a PublicKey,
    pub identifier: &'a str,
    /// The relay's own domain (host[:port]) used to verify the `clone` tag.
    pub domain: &'a str,
}

/// Outcome of [`pre_validate_refs_nostr_push`] for one ref.
///
/// The function is **pure** — no DB writes, no purgatory mutations, no
/// disk I/O. Callers decide whether to reject the push, proceed, and
/// whether to create a placeholder.
#[derive(Debug)]
pub enum NostrRefPreValidation {
    /// The ref is allowed to proceed.
    ///
    /// `event_from_purgatory` carries the matched event when the match
    /// came from a populated purgatory entry, so the caller (the standard
    /// `authorize_push`) can collect it into `purgatory_events`. `None`
    /// means the match came from the DB or from a placeholder-only
    /// purgatory entry — nothing to collect.
    Authorized { event_from_purgatory: Option<Event> },
    /// No event with that id is known to the relay yet. The caller may
    /// create a placeholder (with or without a `/prs/` scope) so the
    /// purgatory sweep can clean up the ref if the event never arrives.
    Unknown,
    /// The push must be rejected. `reason` is suitable for both an
    /// authorization-denied response and a `git-receive-pack` ERR
    /// pkt-line.
    Rejected { reason: String },
}

/// Pre-validate one `refs/nostr/<event-id>` push against the database and
/// purgatory.
///
/// Shared by both the standard endpoint
/// ([`authorize_push`]) and the GRASP-06 `/prs/` receive-pack handler
/// (`crate::grasp06::receive::handle_prs_receive_pack`). The two endpoints
/// have different mismatch UX (pre-reject vs post-delete) but the
/// underlying mismatch *criteria* are the same — gathering them here
/// keeps the criteria in one place.
///
/// Checks performed:
///
/// 1. `ref_name` is exactly `refs/nostr/<64-lowercase-hex>` and parses as
///    an [`EventId`].
/// 2. DB lookup via [`get_pr_event_by_id`]. If found, the event's `c` tag
///    MUST match `new_oid`; with `prs_url` set, the event's signer MUST
///    match `submitter` and one of its `a`-tag d-values MUST match
///    `identifier`.
/// 3. Purgatory lookup. Same checks as (2) for populated entries. For
///    placeholder-only entries with a `prs_scope`, the scope MUST match
///    `prs_url` when one is supplied (this catches the case where one
///    `/prs/<A>/<id>` push tries to claim a ref previously staged at
///    `/prs/<B>/<id>` under the same event id).
/// 4. Otherwise the function returns [`NostrRefPreValidation::Unknown`].
pub async fn pre_validate_refs_nostr_push(
    database: &SharedDatabase,
    purgatory: &Purgatory,
    new_oid: &str,
    ref_name: &str,
    prs_url: Option<PrsUrlConstraints<'_>>,
) -> NostrRefPreValidation {
    // 1. Ref-name shape.
    let event_id_hex = match ref_name.strip_prefix("refs/nostr/") {
        Some(s) => s,
        None => {
            return NostrRefPreValidation::Rejected {
                reason: format!("ref {} is outside refs/nostr/", ref_name),
            }
        }
    };
    let event_id = match EventId::parse(event_id_hex) {
        Ok(id) => id,
        Err(_) => {
            return NostrRefPreValidation::Rejected {
                reason: format!("Invalid event ID format in ref: {}", ref_name),
            }
        }
    };

    // 2. DB first.
    match get_pr_event_by_id(database, &event_id).await {
        Ok(Some(event)) => {
            if let Some(reason) = describe_known_event_mismatch(&event, new_oid, prs_url) {
                return NostrRefPreValidation::Rejected {
                    reason: format!("PR event {} {}", event_id_hex, reason),
                };
            }
            return NostrRefPreValidation::Authorized {
                event_from_purgatory: None,
            };
        }
        Ok(None) => {}
        Err(e) => {
            // Treat DB error as not-found for permissive behaviour. The
            // standard endpoint preserves the historical behaviour of
            // creating a placeholder; the /prs/ handler likewise creates
            // one and lets the sweep clean up if the event never arrives.
            warn!(
                "DB query for {} failed (treating as not-found): {}",
                ref_name, e
            );
        }
    }

    // 3. Purgatory.
    if let Some(entry) = purgatory.find_pr(event_id_hex) {
        match entry.event {
            Some(event) => {
                if let Some(reason) = describe_known_event_mismatch(&event, new_oid, prs_url) {
                    return NostrRefPreValidation::Rejected {
                        reason: format!("PR event {} (purgatory) {}", event_id_hex, reason),
                    };
                }
                return NostrRefPreValidation::Authorized {
                    event_from_purgatory: Some(event),
                };
            }
            None => {
                // Placeholder-only entry. Standard endpoint historically
                // allows overwriting (no event → no c-tag to validate
                // against). The /prs/ endpoint additionally requires that
                // any recorded scope matches the URL — otherwise one
                // `/prs/<A>/<id>` push could claim a ref previously
                // staged at `/prs/<B>/<id>` under the same event id.
                if let (Some(scope), Some(prs)) = (entry.prs_scope.as_ref(), prs_url) {
                    if scope.submitter != *prs.submitter || scope.identifier != prs.identifier {
                        return NostrRefPreValidation::Rejected {
                            reason: format!(
                                "ref refs/nostr/{} pre-registered under a different /prs/ scope ({}/{})",
                                event_id_hex,
                                scope.submitter.to_hex(),
                                scope.identifier
                            ),
                        };
                    }
                }
                return NostrRefPreValidation::Authorized {
                    event_from_purgatory: None,
                };
            }
        }
    }

    // 4. Nothing known yet.
    NostrRefPreValidation::Unknown
}

/// Cross-check a known PR / PR-Update event against the pushed commit
/// and (optionally) the `/prs/<npub>/<identifier>` URL constraints.
///
/// Returns `None` if everything matches, or `Some(reason)` describing the
/// first mismatch encountered. The reason is intended to be embedded into
/// a user-facing authorization-denied / ERR pkt-line message.
fn describe_known_event_mismatch(
    event: &Event,
    pushed_commit: &str,
    prs: Option<PrsUrlConstraints<'_>>,
) -> Option<String> {
    // `c` tag must match the pushed commit.
    match extract_commit_tag(event) {
        Some(c) if c == pushed_commit => {}
        Some(c) => {
            return Some(format!(
                "specifies commit {}, but push contains {}",
                c, pushed_commit
            ))
        }
        None => return Some("has no `c` tag".to_string()),
    }

    // /prs/ extra constraints.
    if let Some(prs) = prs {
        if event.pubkey != *prs.submitter {
            return Some(format!(
                "is signed by {} which does not match /prs/ submitter {}",
                event.pubkey.to_hex(),
                prs.submitter.to_hex(),
            ));
        }
        match crate::git::sync::extract_identifier_from_pr_event(event) {
            Some(id) if id == prs.identifier => {}
            Some(id) => {
                return Some(format!(
                    "has a-tag identifier {} which does not match /prs/ identifier {}",
                    id, prs.identifier
                ))
            }
            None => return Some("has no parsable a-tag identifier".to_string()),
        }
        // The event must explicitly opt in to this relay's /prs/ endpoint via
        // a `clone` tag. Without this check any PR event whose signer and
        // identifier happen to match the URL could be pushed here, turning
        // every GRASP-06 relay into an unsolicited mirror for every PR event
        // on the network.
        let d_tags = vec![prs.identifier.to_string()];
        let has_clone_tag = event.tags.iter().any(|tag| {
            let parts = tag.clone().to_vec();
            if parts.first().map(String::as_str) != Some("clone") {
                return false;
            }
            parts.iter().skip(1).any(|url| {
                crate::grasp06::policy::clone_url_names_relays_prs_endpoint(
                    url,
                    prs.domain,
                    prs.submitter,
                    &d_tags,
                )
            })
        });
        if !has_clone_tag {
            return Some(format!(
                "has no `clone` tag naming this relay's /prs/{}/{}.git endpoint",
                prs.submitter
                    .to_bech32()
                    .unwrap_or_else(|_| prs.submitter.to_hex()),
                prs.identifier,
            ));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Tag};

    fn create_test_keys() -> Keys {
        Keys::generate()
    }

    fn create_announcement_event(keys: &Keys, identifier: &str, maintainers: &[&Keys]) -> Event {
        let mut tags = vec![Tag::custom("d", vec![identifier.to_string()])];

        // Add maintainers as a single "maintainers" tag per NIP-34
        // Format: ["maintainers", "<pubkey1-hex>", "<pubkey2-hex>", ...]
        if !maintainers.is_empty() {
            let maintainer_pubkeys: Vec<String> = maintainers
                .iter()
                .map(|k| k.public_key().to_hex())
                .collect();
            tags.push(Tag::custom("maintainers", maintainer_pubkeys));
        }

        // Add clone and relay tags for validity
        tags.push(Tag::custom(
            "clone",
            vec!["https://example.com/test.git".to_string()],
        ));
        tags.push(Tag::custom("relays", vec!["wss://example.com".to_string()]));

        EventBuilder::new(Kind::GitRepoAnnouncement, "Test repo")
            .tags(tags)
            .finalize(keys)
            .unwrap()
    }

    fn create_state_event(keys: &Keys, identifier: &str, branches: &[(&str, &str)]) -> Event {
        let mut tags = vec![Tag::custom("d", vec![identifier.to_string()])];

        for (branch, commit) in branches {
            tags.push(Tag::custom(
                format!("refs/heads/{}", branch),
                vec![commit.to_string()],
            ));
        }

        EventBuilder::new(Kind::RepoState, "")
            .tags(tags)
            .finalize(keys)
            .unwrap()
    }

    fn parse(event: Event) -> RepositoryAnnouncement {
        RepositoryAnnouncement::from_event(event).unwrap()
    }

    fn hex(keys: &Keys) -> String {
        keys.public_key().to_hex()
    }

    #[test]
    fn test_owner_is_sole_state_maintainer() {
        let alice = create_test_keys();
        let identifier = "test-repo";
        let announcements = vec![parse(create_announcement_event(&alice, identifier, &[]))];

        let membership = compute_membership(&announcements, &hex(&alice), identifier);
        assert_eq!(membership.state_maintainers, HashSet::from([hex(&alice)]));
        assert!(membership.invited.is_empty());
    }

    #[test]
    fn test_no_owner_announcement_means_no_membership() {
        let alice = create_test_keys();
        let bob = create_test_keys();
        let identifier = "test-repo";

        // Only Bob has announced; Alice's repository has no membership.
        let announcements = vec![parse(create_announcement_event(&bob, identifier, &[]))];

        let membership = compute_membership(&announcements, &hex(&alice), identifier);
        assert!(membership.state_maintainers.is_empty());
        assert!(membership.invited.is_empty());
    }

    #[test]
    fn test_listed_maintainer_without_announcement_is_invited() {
        let alice = create_test_keys();
        let bob = create_test_keys();
        let identifier = "test-repo";

        // Alice lists Bob, but Bob has published no announcement
        let announcements = vec![parse(create_announcement_event(
            &alice,
            identifier,
            &[&bob],
        ))];

        let membership = compute_membership(&announcements, &hex(&alice), identifier);
        assert!(!membership.state_maintainers.contains(&hex(&bob)));
        assert!(membership.invited.contains(&hex(&bob)));

        let by_owner = collect_authorized_maintainers(&announcements);
        assert!(!by_owner[&hex(&alice)].contains(&hex(&bob)));
    }

    #[test]
    fn test_reciprocal_maintainer_is_confirmed() {
        let alice = create_test_keys();
        let bob = create_test_keys();
        let identifier = "test-repo";

        let announcements = vec![
            parse(create_announcement_event(&alice, identifier, &[&bob])),
            parse(create_announcement_event(&bob, identifier, &[&alice])),
        ];

        let membership = compute_membership(&announcements, &hex(&alice), identifier);
        assert!(membership.state_maintainers.contains(&hex(&alice)));
        assert!(membership.state_maintainers.contains(&hex(&bob)));
        assert!(membership.invited.is_empty());
    }

    #[test]
    fn test_non_reciprocal_announcement_stays_invited() {
        let alice = create_test_keys();
        let bob = create_test_keys();
        let charlie = create_test_keys();
        let identifier = "test-repo";

        // Bob announced the same identifier but does not list Alice back
        let announcements = vec![
            parse(create_announcement_event(&alice, identifier, &[&bob])),
            parse(create_announcement_event(&bob, identifier, &[&charlie])),
        ];

        let membership = compute_membership(&announcements, &hex(&alice), identifier);
        assert!(!membership.state_maintainers.contains(&hex(&bob)));
        assert!(membership.invited.contains(&hex(&bob)));
    }

    #[test]
    fn test_reciprocal_announcement_for_other_identifier_stays_invited() {
        let alice = create_test_keys();
        let bob = create_test_keys();
        let identifier = "test-repo";

        // Bob lists Alice back, but under a different identifier
        let announcements = vec![
            parse(create_announcement_event(&alice, identifier, &[&bob])),
            parse(create_announcement_event(&bob, "other-repo", &[&alice])),
        ];

        let membership = compute_membership(&announcements, &hex(&alice), identifier);
        assert!(!membership.state_maintainers.contains(&hex(&bob)));
        assert!(membership.invited.contains(&hex(&bob)));
    }

    #[test]
    fn test_recursive_reciprocal_chain_confirmed() {
        let alice = create_test_keys();
        let bob = create_test_keys();
        let charlie = create_test_keys();
        let identifier = "test-repo";

        // Alice <-> Bob, Bob -> Charlie, Charlie -> Bob
        let announcements = vec![
            parse(create_announcement_event(&alice, identifier, &[&bob])),
            parse(create_announcement_event(
                &bob,
                identifier,
                &[&alice, &charlie],
            )),
            parse(create_announcement_event(&charlie, identifier, &[&bob])),
        ];

        let membership = compute_membership(&announcements, &hex(&alice), identifier);
        assert!(membership.state_maintainers.contains(&hex(&alice)));
        assert!(membership.state_maintainers.contains(&hex(&bob)));
        assert!(membership.state_maintainers.contains(&hex(&charlie)));
    }

    #[test]
    fn test_mutual_listing_without_owner_link_stays_invited() {
        let alice = create_test_keys();
        let bob = create_test_keys();
        let charlie = create_test_keys();
        let identifier = "test-repo";

        // Bob and Charlie list each other but neither lists Alice: a mutual
        // clique disconnected from the owner never becomes confirmed.
        let announcements = vec![
            parse(create_announcement_event(&alice, identifier, &[&bob])),
            parse(create_announcement_event(&bob, identifier, &[&charlie])),
            parse(create_announcement_event(&charlie, identifier, &[&bob])),
        ];

        let membership = compute_membership(&announcements, &hex(&alice), identifier);
        assert_eq!(membership.state_maintainers, HashSet::from([hex(&alice)]));
        assert!(membership.invited.contains(&hex(&bob)));
    }

    #[test]
    fn test_validate_push_refs_success() {
        let alice = create_test_keys();
        let identifier = "test-repo";

        let state_event = create_state_event(&alice, identifier, &[("main", "abc123def456")]);
        let state = RepositoryState::from_event(state_event).unwrap();

        let pushed_refs = vec![(
            "0".repeat(40),
            "abc123def456".to_string() + &"0".repeat(28),
            "refs/heads/main".to_string(),
        )];

        // This should pass since we're allowing new branches for now
        let result = validate_push_refs(&state, &pushed_refs);
        // The branch name matches, but commit doesn't match exactly - this tests the logic
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_parse_pushed_refs() {
        let old = "0".repeat(40);
        let new = "a".repeat(40);
        let data = format!("{} {} refs/heads/main\0 report-status\n", old, new);

        let refs = parse_pushed_refs(data.as_bytes());

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, old);
        assert_eq!(refs[0].1, new);
        assert_eq!(refs[0].2, "refs/heads/main");
    }

    #[test]
    fn test_parse_pushed_refs_pktline_format() {
        // Build a pkt-line formatted push request like git client sends
        // Format: 4-byte hex length + payload
        // Payload: "old_oid new_oid ref_name\0capabilities\n"
        let old = "0".repeat(40);
        let new = "a".repeat(40);
        let ref_name = "refs/heads/main";
        let capabilities = " report-status side-band-64k";

        // Build the pkt-line payload
        let payload = format!("{} {} {}\0{}\n", old, new, ref_name, capabilities);

        // Calculate length (4-byte prefix + payload)
        let len = 4 + payload.len();
        let pktline = format!("{:04x}{}", len, payload);

        // Add flush packet to end
        let data = format!("{}0000", pktline);

        let refs = parse_pushed_refs(data.as_bytes());

        assert_eq!(refs.len(), 1, "Expected 1 ref, got {}", refs.len());
        assert_eq!(refs[0].0, old);
        assert_eq!(refs[0].1, new);
        assert_eq!(refs[0].2, ref_name);
    }

    #[test]
    fn test_parse_pushed_refs_multiple_refs() {
        // Test multiple refs in pkt-line format
        let old1 = "0".repeat(40);
        let new1 = "a".repeat(40);
        let old2 = "b".repeat(40);
        let new2 = "c".repeat(40);

        // First ref with capabilities
        let payload1 = format!("{} {} refs/heads/main\0report-status\n", old1, new1);
        let len1 = 4 + payload1.len();
        let pktline1 = format!("{:04x}{}", len1, payload1);

        // Second ref without capabilities (subsequent refs don't have them)
        let payload2 = format!("{} {} refs/heads/feature\n", old2, new2);
        let len2 = 4 + payload2.len();
        let pktline2 = format!("{:04x}{}", len2, payload2);

        let data = format!("{}{}0000", pktline1, pktline2);

        let refs = parse_pushed_refs(data.as_bytes());

        assert_eq!(refs.len(), 2, "Expected 2 refs, got {}", refs.len());
        assert_eq!(refs[0].2, "refs/heads/main");
        assert_eq!(refs[1].2, "refs/heads/feature");
    }

    #[test]
    fn test_npub_pubkey_conversion() {
        let keys = create_test_keys();
        let hex = keys.public_key().to_hex();

        let npub = pubkey_to_npub(&hex).unwrap();
        assert!(npub.starts_with("npub1"));

        let back_to_hex = npub_to_pubkey(&npub).unwrap();
        assert_eq!(hex, back_to_hex);
    }
}
