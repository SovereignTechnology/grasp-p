//! Reconcile served Git refs with the Nostr events that authorize them.
//!
//! This is intentionally separate from [`super::integrity`]. The storage pass
//! proves that objects, packs, alternates, and ref targets are structurally
//! sound. This pass proves that the refs exposed by each repository view are
//! exactly those justified by accepted State, PR, and PR Update events.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use nostr::types::url::Url;
use nostr_sdk::prelude::{Event, EventId, FromBech32, Kind, PublicKey, ToBech32};
use tracing::{error, info, warn};

use super::authorization::{compute_membership, extract_commit_tag, RepositoryData};
use super::integrity::{
    discover_families, discover_views, list_refs, select_families, FamilyRepairSource,
};
use super::storage::{FamilyKey, LocalGitStorage, ObjectFormat};
use crate::nostr::events::RepositoryState;
use crate::purgatory::sync::RealSyncContext;
use crate::purgatory::{PrPurgatoryEntry, StatePurgatoryEntry};

const MAX_ISSUES_PER_VIEW: usize = 16;

#[derive(Debug, Default)]
struct PassStats {
    families: usize,
    views_checked: usize,
    healthy: usize,
    repaired: usize,
    repair_needed: usize,
    manual_inspection: usize,
    failed: usize,
    refs_created: usize,
    refs_updated: usize,
    refs_deleted: usize,
    heads_set: usize,
}

#[derive(Debug, Default)]
struct RepairCounts {
    created: usize,
    updated: usize,
    deleted: usize,
    heads_set: usize,
}

impl RepairCounts {
    fn any(&self) -> bool {
        self.created + self.updated + self.deleted + self.heads_set > 0
    }
}

#[derive(Clone, Copy)]
struct PassMode {
    repair: bool,
    trigger: &'static str,
}

struct ReconcileAccumulator<'a> {
    repair: bool,
    repairs: &'a mut RepairCounts,
    issues: &'a mut Vec<IntegrityIssue>,
}

#[derive(Debug)]
struct IntegrityIssue {
    category: &'static str,
    reference: String,
    actual_oid: Option<String>,
    expected_oid: Option<String>,
    detail: String,
}

impl IntegrityIssue {
    fn new(
        category: &'static str,
        reference: impl Into<String>,
        actual_oid: Option<String>,
        expected_oid: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            category,
            reference: reference.into(),
            actual_oid,
            expected_oid,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone)]
enum ViewIdentity {
    Owner { pubkey: PublicKey },
    Prs { submitter: PublicKey },
}

impl ViewIdentity {
    fn kind(&self) -> &'static str {
        match self {
            Self::Owner { .. } => "owner",
            Self::Prs { .. } => "prs",
        }
    }

    fn pubkey_hex(&self) -> String {
        match self {
            Self::Owner { pubkey } => pubkey.to_hex(),
            Self::Prs { submitter } => submitter.to_hex(),
        }
    }
}

#[derive(Debug, Default)]
struct ViewExpectation {
    state_refs: BTreeMap<String, String>,
    state_head: Option<String>,
    has_authoritative_state: bool,
    state_deferred: bool,
    pr_refs: BTreeMap<String, String>,
    pending_pr_refs: BTreeMap<String, String>,
    ambiguous_placeholders: BTreeMap<String, String>,
    issues: Vec<IntegrityIssue>,
}

/// Run the authorization-aware pass after storage integrity has completed.
///
/// The relay is already serving traffic while this runs. Missing objects are
/// fetched only through the hardened integrity-fetch path, and each family is
/// leased only for the short local ref reconciliation phase.
pub async fn run_startup_pass(
    storage: &LocalGitStorage,
    source: &RealSyncContext,
    identifiers: &[String],
) {
    let mut stats = PassStats::default();
    let (families, missing) =
        match discover_families(storage).map(|families| select_families(families, identifiers)) {
            Ok(selection) => selection,
            Err(error) => {
                error!(%error, "Git authorization-integrity startup discovery failed");
                stats.failed = 1;
                log_startup_completion(&stats, !identifiers.is_empty(), identifiers.len());
                return;
            }
        };
    stats.failed = missing.len();
    for identifier in missing {
        error!(
            %identifier,
            manual_inspection = true,
            "Configured startup authorization-integrity identifier matched no installed family"
        );
    }
    let accepted_prs = match source.accepted_pr_events_for_integrity().await {
        Ok(events) => events,
        Err(error) => {
            error!(%error, "Git authorization-integrity authoritative event query failed");
            stats.families = families.len();
            stats.failed += 1;
            log_startup_completion(&stats, !identifiers.is_empty(), identifiers.len());
            return;
        }
    };
    let pending_prs = source.pending_pr_entries_for_integrity();

    info!(
        families = families.len(),
        accepted_pr_events = accepted_prs.len(),
        pending_pr_entries = pending_prs.len(),
        scoped = !identifiers.is_empty(),
        requested_identifiers = identifiers.len(),
        "Git authorization-integrity startup pass started"
    );

    run_families(
        storage,
        source,
        families,
        &accepted_prs,
        &pending_prs,
        PassMode {
            repair: true,
            trigger: "startup",
        },
        &mut stats,
    )
    .await;

    log_startup_completion(&stats, !identifiers.is_empty(), identifiers.len());
}

/// Run the same authorization reconciliation for one operator-selected
/// identifier. `repair = false` is a non-mutating comparison; `repair = true`
/// applies the same safe automatic fixes as the startup pass.
pub(crate) async fn run_identifier_pass(
    storage: &LocalGitStorage,
    source: &RealSyncContext,
    identifier: &str,
    repair: bool,
) {
    let scope = [identifier.to_owned()];
    let mut stats = PassStats::default();
    let (families, missing) =
        match discover_families(storage).map(|families| select_families(families, &scope)) {
            Ok(selection) => selection,
            Err(error) => {
                error!(%identifier, %error, "Manual Git authorization-integrity discovery failed");
                stats.failed = 1;
                log_manual_completion(&stats, identifier, repair);
                return;
            }
        };
    if !missing.is_empty() {
        error!(
            %identifier,
            manual_inspection = true,
            "Manual Git authorization-integrity request matched no installed family"
        );
        stats.failed = missing.len();
        log_manual_completion(&stats, identifier, repair);
        return;
    }
    let accepted_prs = match source.accepted_pr_events_for_integrity().await {
        Ok(events) => events
            .into_iter()
            .filter(|event| {
                event_relevant_to_identifier(
                    event,
                    identifier,
                    source.service_address_for_integrity(),
                )
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            error!(
                %identifier,
                %error,
                "Manual Git authorization-integrity authoritative event query failed"
            );
            stats.families = families.len();
            stats.failed = 1;
            log_manual_completion(&stats, identifier, repair);
            return;
        }
    };
    let pending_prs = source.pending_pr_entries_for_integrity();
    info!(
        %identifier,
        repair,
        families = families.len(),
        accepted_pr_events = accepted_prs.len(),
        pending_pr_entries = pending_prs.len(),
        "Manual Git authorization-integrity request started"
    );
    run_families(
        storage,
        source,
        families,
        &accepted_prs,
        &pending_prs,
        PassMode {
            repair,
            trigger: "manual",
        },
        &mut stats,
    )
    .await;
    log_manual_completion(&stats, identifier, repair);
}

async fn run_families(
    storage: &LocalGitStorage,
    source: &RealSyncContext,
    families: Vec<FamilyKey>,
    accepted_prs: &[Event],
    pending_prs: &[(String, PrPurgatoryEntry)],
    mode: PassMode,
    stats: &mut PassStats,
) {
    for key in families {
        stats.families += 1;
        if let Err(error) = check_family(
            storage,
            source,
            &key,
            accepted_prs,
            pending_prs,
            mode,
            stats,
        )
        .await
        {
            stats.failed += 1;
            error!(
                identifier = %key.identifier,
                object_format = %key.object_format,
                trigger = mode.trigger,
                repair = mode.repair,
                %error,
                manual_inspection = true,
                "Git authorization-integrity family check failed"
            );
        }
        tokio::task::yield_now().await;
    }
}

fn log_startup_completion(stats: &PassStats, scoped: bool, requested_identifiers: usize) {
    info!(
        families = stats.families,
        views_checked = stats.views_checked,
        healthy = stats.healthy,
        repaired = stats.repaired,
        repair_needed = stats.repair_needed,
        manual_inspection = stats.manual_inspection,
        failed = stats.failed,
        refs_created = stats.refs_created,
        refs_updated = stats.refs_updated,
        refs_deleted = stats.refs_deleted,
        heads_set = stats.heads_set,
        scoped,
        requested_identifiers,
        "Git authorization-integrity startup pass completed"
    );
}

fn log_manual_completion(stats: &PassStats, identifier: &str, repair: bool) {
    info!(
        %identifier,
        repair,
        families = stats.families,
        views_checked = stats.views_checked,
        healthy = stats.healthy,
        repaired = stats.repaired,
        repair_needed = stats.repair_needed,
        manual_inspection = stats.manual_inspection,
        failed = stats.failed,
        refs_created = stats.refs_created,
        refs_updated = stats.refs_updated,
        refs_deleted = stats.refs_deleted,
        heads_set = stats.heads_set,
        "Manual Git authorization-integrity request completed"
    );
}

async fn check_family(
    storage: &LocalGitStorage,
    source: &RealSyncContext,
    key: &FamilyKey,
    accepted_prs: &[Event],
    pending_prs: &[(String, PrPurgatoryEntry)],
    mode: PassMode,
    stats: &mut PassStats,
) -> Result<()> {
    let PassMode { repair, trigger } = mode;
    let repo_data = source
        .accepted_repository_data_for_integrity(&key.identifier)
        .await
        .with_context(|| format!("load accepted events for {}", key.identifier))?;
    let pending_states = source.pending_state_events_for_integrity(&key.identifier);
    let views = discover_views(storage, key)?;
    let mut checks = Vec::with_capacity(views.len());

    for view in views {
        let identity = view_identity(storage, &view)?;
        let baseline_refs: BTreeMap<_, _> = list_refs(&view)?.into_iter().collect();
        let baseline_head = symbolic_head(&view)?;
        let expectation = build_expectation(
            &identity,
            &key.identifier,
            &repo_data,
            accepted_prs,
            pending_prs,
            &pending_states,
            source.service_address_for_integrity(),
        );
        checks.push((view, identity, expectation, baseline_refs, baseline_head));
    }

    // Repair missing expected objects before taking the family lease: the
    // hardened fetch path takes that same lease while installing objects.
    let family = storage.family_repo_path(key);
    let mut missing = BTreeSet::new();
    for (_, _, expectation, _, _) in &checks {
        for oid in expectation
            .state_refs
            .values()
            .chain(expectation.pr_refs.values())
        {
            if valid_oid(key.object_format, oid) && !oid_exists(&family, oid)? {
                missing.insert(oid.clone());
            }
        }
    }
    if repair && !missing.is_empty() {
        if let Some((target_view, _, _, _, _)) = checks.first() {
            fetch_missing_expected_oids(source, &key.identifier, target_view, &missing).await;
        }
    }

    let _lease = storage.write_lease(key).await?;
    // The pass is online and remote object recovery may have taken time.
    // Revalidate State and every candidate PR ID while the family is leased,
    // and refuse to mutate a ref that changed since the initial snapshot.
    let repo_data = source
        .accepted_repository_data_for_integrity(&key.identifier)
        .await
        .with_context(|| format!("refresh accepted events for {}", key.identifier))?;
    let pending_states = source.pending_state_events_for_integrity(&key.identifier);
    let mut candidate_pr_ids: BTreeSet<EventId> = accepted_prs
        .iter()
        .filter(|event| {
            event_relevant_to_identifier(
                event,
                &key.identifier,
                source.service_address_for_integrity(),
            )
        })
        .map(|event| event.id)
        .collect();
    for (view, _, _, _, _) in &checks {
        for (reference, _) in list_refs(view)? {
            if let Some(event_id) = reference.strip_prefix("refs/nostr/") {
                if let Ok(event_id) = EventId::from_hex(event_id) {
                    candidate_pr_ids.insert(event_id);
                }
            }
        }
    }
    let fresh_prs = source
        .accepted_pr_events_by_id_for_integrity(&candidate_pr_ids.into_iter().collect::<Vec<_>>())
        .await
        .with_context(|| format!("refresh accepted PR events for {}", key.identifier))?;
    let pending_prs = source.pending_pr_entries_for_integrity();

    for (view, identity, _, baseline_refs, baseline_head) in checks {
        let expectation = build_expectation(
            &identity,
            &key.identifier,
            &repo_data,
            &fresh_prs,
            &pending_prs,
            &pending_states,
            source.service_address_for_integrity(),
        );
        stats.views_checked += 1;
        match reconcile_view(
            &view,
            key.object_format,
            expectation,
            &baseline_refs,
            baseline_head.as_deref(),
            repair,
        ) {
            Ok((repairs, issues)) => {
                stats.refs_created += repairs.created;
                stats.refs_updated += repairs.updated;
                stats.refs_deleted += repairs.deleted;
                stats.heads_set += repairs.heads_set;
                if repairs.any() {
                    if repair {
                        stats.repaired += 1;
                        info!(
                            identifier = %key.identifier,
                            object_format = %key.object_format,
                            view = %view.display(),
                            view_type = identity.kind(),
                            pubkey = %identity.pubkey_hex(),
                            trigger,
                            repair,
                            refs_created = repairs.created,
                            refs_updated = repairs.updated,
                            refs_deleted = repairs.deleted,
                            heads_set = repairs.heads_set,
                            "Git authorization-integrity repaired repository view"
                        );
                    } else {
                        stats.repair_needed += 1;
                        warn!(
                            identifier = %key.identifier,
                            object_format = %key.object_format,
                            view = %view.display(),
                            view_type = identity.kind(),
                            pubkey = %identity.pubkey_hex(),
                            trigger,
                            repair,
                            refs_to_create = repairs.created,
                            refs_to_update = repairs.updated,
                            refs_to_delete = repairs.deleted,
                            head_to_set = repairs.heads_set,
                            "Git authorization-integrity repository view differs from authoritative events"
                        );
                    }
                } else if issues.is_empty() {
                    stats.healthy += 1;
                }
                if !issues.is_empty() {
                    stats.manual_inspection += 1;
                    log_issues(key, &view, &identity, &issues, trigger, repair);
                }
            }
            Err(error) => {
                stats.failed += 1;
                error!(
                    identifier = %key.identifier,
                    object_format = %key.object_format,
                    view = %view.display(),
                    view_type = identity.kind(),
                    pubkey = %identity.pubkey_hex(),
                    trigger,
                    repair,
                    %error,
                    manual_inspection = true,
                    "Git authorization-integrity repository check failed"
                );
            }
        }
    }
    Ok(())
}

async fn fetch_missing_expected_oids(
    source: &RealSyncContext,
    identifier: &str,
    target_view: &Path,
    missing: &BTreeSet<String>,
) {
    let urls = match source.accepted_clone_urls(identifier).await {
        Ok(urls) => urls,
        Err(error) => {
            warn!(%identifier, %error, "Authorization-integrity could not load repair sources");
            return;
        }
    };
    let mut remaining: Vec<String> = missing.iter().cloned().collect();
    for url in urls {
        if remaining.is_empty() {
            break;
        }
        match source
            .fetch_missing_oids(target_view, &url, &remaining)
            .await
        {
            Ok(_) => remaining.retain(|oid| !super::oid_exists(target_view, oid)),
            Err(error) => warn!(
                %identifier,
                %url,
                %error,
                "Authorization-integrity repair source failed"
            ),
        }
    }
}

fn build_expectation(
    identity: &ViewIdentity,
    identifier: &str,
    repo_data: &RepositoryData,
    accepted_prs: &[Event],
    pending_prs: &[(String, PrPurgatoryEntry)],
    pending_states: &[StatePurgatoryEntry],
    service_address: Option<&str>,
) -> ViewExpectation {
    let mut expected = ViewExpectation::default();
    let maintainers = match identity {
        ViewIdentity::Owner { pubkey } => {
            let membership =
                compute_membership(&repo_data.announcements, &pubkey.to_hex(), identifier);
            let mut maintainers: Vec<_> = membership.state_maintainers.into_iter().collect();
            maintainers.sort();
            if let Some(state) =
                super::sync::latest_authorized_state(&maintainers, &repo_data.states)
            {
                expected.has_authoritative_state = true;
                add_state_expectation(&mut expected, state);
            }
            expected.state_deferred = pending_states
                .iter()
                .any(|entry| maintainers.contains(&entry.author.to_hex()));
            Some(maintainers)
        }
        ViewIdentity::Prs { .. } => None,
    };

    for event in accepted_prs {
        if event_applies_to_view(
            event,
            identity,
            identifier,
            maintainers.as_deref(),
            service_address,
        ) {
            add_pr_expectation(&mut expected, event);
        }
    }

    for (event_id, entry) in pending_prs {
        let reference = format!("refs/nostr/{event_id}");
        if entry.event.is_none() {
            if let ViewIdentity::Owner { pubkey } = identity {
                if let Some(record) = entry
                    .standard_refs
                    .iter()
                    .find(|record| record.owner == *pubkey && record.identifier == identifier)
                {
                    expected
                        .pending_pr_refs
                        .insert(reference, record.commit.clone());
                    continue;
                }
            }
        }
        match &entry.event {
            Some(event)
                if event_applies_to_view(
                    event,
                    identity,
                    identifier,
                    maintainers.as_deref(),
                    service_address,
                ) =>
            {
                expected
                    .pending_pr_refs
                    .insert(reference, entry.commit.clone());
            }
            None if placeholder_applies_to_view(entry, identity, identifier) => {
                expected
                    .pending_pr_refs
                    .insert(reference, entry.commit.clone());
            }
            None if entry.prs_scope.is_none()
                && entry.standard_refs.is_empty()
                && matches!(identity, ViewIdentity::Owner { .. }) =>
            {
                // Legacy standard-endpoint placeholders did not record their
                // owner/identifier. Preserve a matching ref, but make the
                // uncertainty visible rather than treating it as authority.
                expected
                    .ambiguous_placeholders
                    .insert(reference, entry.commit.clone());
            }
            _ => {}
        }
    }

    expected
}

fn add_state_expectation(expected: &mut ViewExpectation, state: &RepositoryState) {
    for branch in &state.branches {
        insert_expected_ref(
            &mut expected.state_refs,
            format!("refs/heads/{}", branch.name),
            branch.commit.clone(),
            &mut expected.issues,
            "conflicting_state_ref",
        );
    }
    for tag in &state.tags {
        insert_expected_ref(
            &mut expected.state_refs,
            format!("refs/tags/{}", tag.name),
            tag.commit.clone(),
            &mut expected.issues,
            "conflicting_state_ref",
        );
    }
    expected.state_head = state.head.clone();
}

fn add_pr_expectation(expected: &mut ViewExpectation, event: &Event) {
    let reference = format!("refs/nostr/{}", event.id);
    let Some(commit) = extract_commit_tag(event) else {
        expected.issues.push(IntegrityIssue::new(
            "accepted_pr_missing_commit",
            reference,
            None,
            None,
            format!("accepted event {} has no usable c tag", event.id),
        ));
        return;
    };
    insert_expected_ref(
        &mut expected.pr_refs,
        reference,
        commit,
        &mut expected.issues,
        "conflicting_pr_ref",
    );
}

fn insert_expected_ref(
    refs: &mut BTreeMap<String, String>,
    reference: String,
    oid: String,
    issues: &mut Vec<IntegrityIssue>,
    category: &'static str,
) {
    if let Some(previous) = refs.insert(reference.clone(), oid.clone()) {
        if previous != oid {
            issues.push(IntegrityIssue::new(
                category,
                reference,
                Some(previous),
                Some(oid),
                "authoritative events specify conflicting targets",
            ));
        }
    }
}

fn event_applies_to_view(
    event: &Event,
    identity: &ViewIdentity,
    identifier: &str,
    maintainers: Option<&[String]>,
    service_address: Option<&str>,
) -> bool {
    match identity {
        ViewIdentity::Owner { pubkey } => {
            let tagged = tagged_owners(event, identifier);
            maintainers.is_some_and(|maintainers| {
                maintainers
                    .iter()
                    .any(|maintainer| tagged.contains(maintainer))
            }) || service_address.is_some_and(|service| {
                standard_clone_coordinates(event, service).iter().any(
                    |(clone_owner, clone_identifier)| {
                        clone_owner == pubkey && clone_identifier == identifier
                    },
                )
            })
        }
        ViewIdentity::Prs { submitter } => {
            event.pubkey == *submitter
                && service_address.is_some_and(|domain| {
                    crate::grasp06::policy::prs_identifiers_named_by_event_clone_tags(event, domain)
                        .iter()
                        .any(|candidate| candidate == identifier)
                })
        }
    }
}

fn tagged_owners(event: &Event, identifier: &str) -> HashSet<String> {
    event
        .tags
        .iter()
        .filter_map(|tag| {
            let values = tag.as_slice();
            if values.first().map(String::as_str) != Some("a") {
                return None;
            }
            let coordinate = values.get(1)?;
            let mut parts = coordinate.splitn(3, ':');
            if parts.next()? != "30617" {
                return None;
            }
            let owner = PublicKey::parse(parts.next()?).ok()?;
            (parts.next()? == identifier).then(|| owner.to_hex())
        })
        .collect()
}

fn event_mentions_identifier(event: &Event, identifier: &str) -> bool {
    !tagged_owners(event, identifier).is_empty()
}

fn event_relevant_to_identifier(
    event: &Event,
    identifier: &str,
    service_address: Option<&str>,
) -> bool {
    event_mentions_identifier(event, identifier)
        || service_address.is_some_and(|domain| {
            crate::grasp06::policy::prs_identifiers_named_by_event_clone_tags(event, domain)
                .iter()
                .any(|candidate| candidate == identifier)
                || standard_clone_coordinates(event, domain)
                    .iter()
                    .any(|(_, candidate)| candidate == identifier)
        })
}

/// Return exact owner-view coordinates named by a PR event's standard clone URLs.
///
/// The configured service may include a mount path. URLs must use HTTP(S),
/// match that authority and mount exactly, contain no credentials/query/fragment,
/// and end at the canonical `/<npub>/<identifier>.git` repository root.
fn standard_clone_coordinates(event: &Event, service: &str) -> Vec<(PublicKey, String)> {
    if !matches!(
        event.kind,
        Kind::GitPullRequest | Kind::GitPullRequestUpdate
    ) {
        return Vec::new();
    }

    let mut coordinates = Vec::new();
    for tag in event.tags.iter() {
        let values = tag.as_slice();
        if values.first().map(String::as_str) != Some("clone") {
            continue;
        }
        for raw_url in values.iter().skip(1) {
            if let Some(coordinate) = standard_clone_coordinate(raw_url, service) {
                if !coordinates.contains(&coordinate) {
                    coordinates.push(coordinate);
                }
            }
        }
    }
    coordinates
}

fn standard_clone_coordinate(raw_url: &str, service: &str) -> Option<(PublicKey, String)> {
    let url = Url::parse(raw_url).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !crate::outbound::url_matches_service_domain(raw_url, service)
    {
        return None;
    }

    let configured = service.trim().trim_end_matches('/');
    let configured = if configured.contains("://") {
        configured.to_owned()
    } else {
        format!("http://{configured}")
    };
    let service_url = Url::parse(&configured).ok()?;
    let service_path = service_url.path().trim_end_matches('/');
    let repository_path = if service_path.is_empty() {
        url.path()
    } else {
        url.path()
            .strip_prefix(service_path)
            .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))?
    };
    let (npub, identifier) = super::parse_repository_root_url(repository_path)?;
    Some((PublicKey::from_bech32(&npub).ok()?, identifier))
}

fn placeholder_applies_to_view(
    entry: &PrPurgatoryEntry,
    identity: &ViewIdentity,
    identifier: &str,
) -> bool {
    let (ViewIdentity::Prs { submitter }, Some(scope)) = (identity, &entry.prs_scope) else {
        return false;
    };
    scope.submitter == *submitter && scope.identifier == identifier
}

fn reconcile_view(
    view: &Path,
    object_format: ObjectFormat,
    mut expected: ViewExpectation,
    baseline_refs: &BTreeMap<String, String>,
    baseline_head: Option<&str>,
    repair: bool,
) -> Result<(RepairCounts, Vec<IntegrityIssue>)> {
    let current: BTreeMap<_, _> = list_refs(view)?.into_iter().collect();
    let mut repairs = RepairCounts::default();

    if expected.state_deferred {
        expected.issues.push(IntegrityIssue::new(
            "pending_authorized_state",
            "HEAD and refs/heads/*, refs/tags/*",
            None,
            None,
            "an authorized State event is still in purgatory; automatic State reconciliation was deferred",
        ));
    } else if expected.has_authoritative_state {
        for (reference, actual) in current.iter().filter(|(reference, _)| {
            reference.starts_with("refs/heads/") || reference.starts_with("refs/tags/")
        }) {
            if !expected.state_refs.contains_key(reference) {
                if baseline_refs.get(reference) != Some(actual) {
                    expected.issues.push(IntegrityIssue::new(
                        "concurrent_ref_change",
                        reference,
                        Some(actual.clone()),
                        None,
                        "preserved because the ref changed while the online integrity pass was running",
                    ));
                    continue;
                }
                if repair {
                    match delete_ref_cas(view, reference, actual) {
                        Ok(()) => repairs.deleted += 1,
                        Err(error) => expected.issues.push(IntegrityIssue::new(
                            "stale_state_ref_repair_failed",
                            reference,
                            Some(actual.clone()),
                            None,
                            error.to_string(),
                        )),
                    }
                } else {
                    repairs.deleted += 1;
                }
            }
        }
        reconcile_expected_refs(
            view,
            object_format,
            &current,
            baseline_refs,
            &expected.state_refs,
            &mut ReconcileAccumulator {
                repair,
                repairs: &mut repairs,
                issues: &mut expected.issues,
            },
        );
        reconcile_head(
            view,
            expected.state_head.as_deref(),
            &expected.state_refs,
            baseline_head,
            repair,
            &mut repairs,
            &mut expected.issues,
        );
    } else {
        for (reference, actual) in current.iter().filter(|(reference, _)| {
            reference.starts_with("refs/heads/") || reference.starts_with("refs/tags/")
        }) {
            expected.issues.push(IntegrityIssue::new(
                "state_ref_without_authoritative_state",
                reference,
                Some(actual.clone()),
                None,
                "preserved because no accepted State event authorizes an automatic decision",
            ));
        }
    }

    reconcile_expected_refs(
        view,
        object_format,
        &current,
        baseline_refs,
        &expected.pr_refs,
        &mut ReconcileAccumulator {
            repair,
            repairs: &mut repairs,
            issues: &mut expected.issues,
        },
    );

    for (reference, actual) in current
        .iter()
        .filter(|(reference, _)| reference.starts_with("refs/nostr/"))
    {
        if expected.pr_refs.contains_key(reference) {
            continue;
        }
        if expected.pending_pr_refs.get(reference) == Some(actual) {
            continue;
        }
        if expected.ambiguous_placeholders.get(reference) == Some(actual) {
            expected.issues.push(IntegrityIssue::new(
                "unscoped_pending_placeholder",
                reference,
                Some(actual.clone()),
                Some(actual.clone()),
                "preserved, but the legacy placeholder does not record which owner and identifier received the push",
            ));
            continue;
        }
        expected.issues.push(IntegrityIssue::new(
            "unauthorized_pr_ref",
            reference,
            Some(actual.clone()),
            expected.pending_pr_refs.get(reference).cloned(),
            "preserved for manual inspection because no accepted or exactly scoped pending PR event authorizes it",
        ));
    }

    for (reference, actual) in &current {
        if reference.starts_with("refs/heads/")
            || reference.starts_with("refs/tags/")
            || reference.starts_with("refs/nostr/")
        {
            continue;
        }
        expected.issues.push(IntegrityIssue::new(
            "unrecognized_served_ref",
            reference,
            Some(actual.clone()),
            None,
            "preserved for manual inspection because this ref namespace is not derived from State or PR events",
        ));
    }

    Ok((repairs, expected.issues))
}

fn reconcile_expected_refs(
    view: &Path,
    object_format: ObjectFormat,
    current: &BTreeMap<String, String>,
    baseline: &BTreeMap<String, String>,
    expected: &BTreeMap<String, String>,
    accumulator: &mut ReconcileAccumulator<'_>,
) {
    for (reference, target) in expected {
        let actual = current.get(reference);
        if actual == Some(target) {
            continue;
        }
        if baseline.get(reference) != actual {
            accumulator.issues.push(IntegrityIssue::new(
                "concurrent_ref_change",
                reference,
                actual.cloned(),
                Some(target.clone()),
                "preserved because the ref changed while the online integrity pass was running",
            ));
            continue;
        }
        if !valid_oid(object_format, target) {
            accumulator.issues.push(IntegrityIssue::new(
                "invalid_authoritative_oid",
                reference,
                actual.cloned(),
                Some(target.clone()),
                "authoritative event target is not a valid object ID for this family",
            ));
            continue;
        }
        if !super::oid_exists(view, target) {
            accumulator.issues.push(IntegrityIssue::new(
                "missing_authoritative_object",
                reference,
                actual.cloned(),
                Some(target.clone()),
                "the expected object remains unavailable after accepted-source repair attempts",
            ));
            continue;
        }
        if !accumulator.repair {
            if actual.is_some() {
                accumulator.repairs.updated += 1;
            } else {
                accumulator.repairs.created += 1;
            }
            continue;
        }
        match update_ref_cas(
            view,
            reference,
            target,
            actual.map(String::as_str),
            object_format,
        ) {
            Ok(()) if actual.is_some() => accumulator.repairs.updated += 1,
            Ok(()) => accumulator.repairs.created += 1,
            Err(error) => accumulator.issues.push(IntegrityIssue::new(
                "authorized_ref_repair_failed",
                reference,
                actual.cloned(),
                Some(target.clone()),
                error.to_string(),
            )),
        }
    }
}

fn reconcile_head(
    view: &Path,
    expected_head: Option<&str>,
    state_refs: &BTreeMap<String, String>,
    baseline_head: Option<&str>,
    repair: bool,
    repairs: &mut RepairCounts,
    issues: &mut Vec<IntegrityIssue>,
) {
    let Some(expected_head) = expected_head else {
        return;
    };
    if !expected_head.starts_with("refs/heads/") || !state_refs.contains_key(expected_head) {
        issues.push(IntegrityIssue::new(
            "invalid_authoritative_head",
            "HEAD",
            symbolic_head(view).ok().flatten(),
            Some(expected_head.to_owned()),
            "State HEAD must name a branch declared by the same State event",
        ));
        return;
    }
    let actual = match symbolic_head(view) {
        Ok(actual) => actual,
        Err(error) => {
            issues.push(IntegrityIssue::new(
                "head_inspection_failed",
                "HEAD",
                None,
                Some(expected_head.to_owned()),
                error.to_string(),
            ));
            return;
        }
    };
    if actual.as_deref() == Some(expected_head) {
        return;
    }
    if actual.as_deref() != baseline_head {
        issues.push(IntegrityIssue::new(
            "concurrent_head_change",
            "HEAD",
            actual,
            Some(expected_head.to_owned()),
            "preserved because HEAD changed while the online integrity pass was running",
        ));
        return;
    }
    if !repair {
        repairs.heads_set += 1;
        return;
    }
    match super::set_repository_head(view, expected_head) {
        Ok(()) => repairs.heads_set += 1,
        Err(error) => issues.push(IntegrityIssue::new(
            "head_repair_failed",
            "HEAD",
            actual,
            Some(expected_head.to_owned()),
            error,
        )),
    }
}

fn view_identity(storage: &LocalGitStorage, view: &Path) -> Result<ViewIdentity> {
    let relative = view
        .strip_prefix(storage.git_data_path())
        .with_context(|| format!("view {} escapes Git data path", view.display()))?;
    let parts: Vec<_> = relative.components().collect();
    match parts.as_slice() {
        [owner, _repo] => {
            let owner = owner.as_os_str().to_string_lossy();
            let pubkey = PublicKey::from_bech32(&owner)
                .with_context(|| format!("invalid owner directory {owner}"))?;
            if pubkey.to_bech32().ok().as_deref() != Some(owner.as_ref()) {
                return Err(anyhow!("non-canonical owner directory {owner}"));
            }
            Ok(ViewIdentity::Owner { pubkey })
        }
        [namespace, submitter, _repo]
            if namespace.as_os_str() == crate::grasp06::paths::PRS_DISK_PREFIX =>
        {
            let submitter = submitter.as_os_str().to_string_lossy();
            let pubkey = PublicKey::parse(submitter.as_ref())
                .with_context(|| format!("invalid PR submitter directory {submitter}"))?;
            if pubkey.to_hex() != submitter {
                return Err(anyhow!("non-canonical PR submitter directory {submitter}"));
            }
            Ok(ViewIdentity::Prs { submitter: pubkey })
        }
        _ => Err(anyhow!("unrecognized repository view {}", view.display())),
    }
}

fn valid_oid(object_format: ObjectFormat, oid: &str) -> bool {
    let length = match object_format {
        ObjectFormat::Sha1 => 40,
        ObjectFormat::Sha256 => 64,
    };
    oid.len() == length && oid.chars().all(|character| character.is_ascii_hexdigit())
}

fn oid_exists(repo: &Path, oid: &str) -> Result<bool> {
    let status = Command::new("git")
        .args(["cat-file", "-e", oid])
        .current_dir(repo)
        .status()
        .with_context(|| format!("inspect object {oid} in {}", repo.display()))?;
    Ok(status.success())
}

fn update_ref_cas(
    repo: &Path,
    reference: &str,
    target: &str,
    actual: Option<&str>,
    object_format: ObjectFormat,
) -> Result<()> {
    let zero = match object_format {
        ObjectFormat::Sha1 => "0000000000000000000000000000000000000000",
        ObjectFormat::Sha256 => "0000000000000000000000000000000000000000000000000000000000000000",
    };
    let output = Command::new("git")
        .args(["update-ref", reference, target, actual.unwrap_or(zero)])
        .current_dir(repo)
        .output()
        .with_context(|| format!("update {reference} in {}", repo.display()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "git update-ref failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn delete_ref_cas(repo: &Path, reference: &str, actual: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["update-ref", "-d", reference, actual])
        .current_dir(repo)
        .output()
        .with_context(|| format!("delete {reference} in {}", repo.display()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "git update-ref -d failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn symbolic_head(repo: &Path) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .current_dir(repo)
        .output()
        .with_context(|| format!("inspect HEAD in {}", repo.display()))?;
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
    } else if output.status.code() == Some(1) {
        Ok(None)
    } else {
        Err(anyhow!(
            "git symbolic-ref failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn log_issues(
    key: &FamilyKey,
    view: &Path,
    identity: &ViewIdentity,
    issues: &[IntegrityIssue],
    trigger: &'static str,
    repair: bool,
) {
    for issue in issues.iter().take(MAX_ISSUES_PER_VIEW) {
        error!(
            identifier = %key.identifier,
            object_format = %key.object_format,
            view = %view.display(),
            view_type = identity.kind(),
            pubkey = %identity.pubkey_hex(),
            trigger,
            repair,
            category = issue.category,
            reference = %issue.reference,
            actual_oid = issue.actual_oid.as_deref().unwrap_or(""),
            expected_oid = issue.expected_oid.as_deref().unwrap_or(""),
            detail = %issue.detail,
            manual_inspection = true,
            "Git authorization-integrity requires manual inspection"
        );
    }
    if issues.len() > MAX_ISSUES_PER_VIEW {
        error!(
            identifier = %key.identifier,
            object_format = %key.object_format,
            view = %view.display(),
            trigger,
            repair,
            suppressed = issues.len() - MAX_ISSUES_PER_VIEW,
            manual_inspection = true,
            "Additional Git authorization-integrity issues suppressed for this view"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::Stdio;

    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};

    use super::*;
    use crate::nostr::events::RepositoryAnnouncement;

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn ref_exists(repo: &Path, reference: &str) -> bool {
        Command::new("git")
            .args(["show-ref", "--verify", "--quiet", reference])
            .current_dir(repo)
            .status()
            .unwrap()
            .success()
    }

    fn write_commit(repo: &Path, message: &str) -> String {
        let tree = git(repo, &["mktree"]);
        let contents = format!(
            "tree {tree}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\n{message}\n"
        );
        let mut child = Command::new("git")
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .current_dir(repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(contents.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn fixture() -> (
        tempfile::TempDir,
        LocalGitStorage,
        FamilyKey,
        PathBuf,
        Vec<String>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let storage = LocalGitStorage::new(temp.path().join("git"));
        let key = FamilyKey::sha1("project").unwrap();
        let family = storage.ensure_family(&key).unwrap();
        let commits = ["old", "new", "pr", "unexpected"]
            .into_iter()
            .map(|message| write_commit(&family, message))
            .collect::<Vec<_>>();
        let owner = Keys::generate().public_key().to_bech32().unwrap();
        let view = storage.git_data_path().join(owner).join("project.git");
        storage.create_thin_view(&key, &view).unwrap();
        (temp, storage, key, view, commits)
    }

    fn reconcile_fixture(
        view: &Path,
        expectation: ViewExpectation,
    ) -> (RepairCounts, Vec<IntegrityIssue>) {
        let baseline_refs = list_refs(view).unwrap().into_iter().collect();
        let baseline_head = symbolic_head(view).unwrap();
        reconcile_view(
            view,
            ObjectFormat::Sha1,
            expectation,
            &baseline_refs,
            baseline_head.as_deref(),
            true,
        )
        .unwrap()
    }

    #[test]
    fn repairs_authoritative_refs_and_preserves_unexpected_pr_evidence() {
        let (_temp, _storage, _key, view, commits) = fixture();
        let expected_pr = format!("refs/nostr/{}", "a".repeat(64));
        let unexpected_pr = format!("refs/nostr/{}", "b".repeat(64));
        git(&view, &["update-ref", "refs/heads/main", &commits[0]]);
        git(&view, &["update-ref", "refs/heads/stale", &commits[0]]);
        git(&view, &["update-ref", &unexpected_pr, &commits[3]]);
        let expectation = ViewExpectation {
            state_refs: BTreeMap::from([("refs/heads/main".to_owned(), commits[1].clone())]),
            state_head: Some("refs/heads/main".to_owned()),
            has_authoritative_state: true,
            pr_refs: BTreeMap::from([(expected_pr.clone(), commits[2].clone())]),
            ..ViewExpectation::default()
        };

        let (repairs, issues) = reconcile_fixture(&view, expectation);

        assert_eq!(repairs.updated, 1);
        assert_eq!(repairs.created, 1);
        assert_eq!(repairs.deleted, 1);
        assert_eq!(git(&view, &["rev-parse", "refs/heads/main"]), commits[1]);
        assert_eq!(git(&view, &["rev-parse", &expected_pr]), commits[2]);
        assert_eq!(git(&view, &["rev-parse", &unexpected_pr]), commits[3]);
        assert!(!ref_exists(&view, "refs/heads/stale"));
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].category, "unauthorized_pr_ref");
    }

    #[test]
    fn exact_authorized_view_is_healthy() {
        let (_temp, _storage, _key, view, commits) = fixture();
        let pr_ref = format!("refs/nostr/{}", "c".repeat(64));
        git(&view, &["update-ref", "refs/heads/main", &commits[0]]);
        git(&view, &["update-ref", &pr_ref, &commits[2]]);
        let expectation = ViewExpectation {
            state_refs: BTreeMap::from([("refs/heads/main".to_owned(), commits[0].clone())]),
            state_head: Some("refs/heads/main".to_owned()),
            has_authoritative_state: true,
            pr_refs: BTreeMap::from([(pr_ref, commits[2].clone())]),
            ..ViewExpectation::default()
        };

        let (repairs, issues) = reconcile_fixture(&view, expectation);

        assert!(!repairs.any());
        assert!(issues.is_empty(), "{issues:#?}");
    }

    #[test]
    fn check_only_reports_safe_repairs_without_mutating_refs() {
        let (_temp, _storage, _key, view, commits) = fixture();
        let expected_pr = format!("refs/nostr/{}", "d".repeat(64));
        git(&view, &["update-ref", "refs/heads/main", &commits[0]]);
        git(&view, &["update-ref", "refs/heads/stale", &commits[0]]);
        let baseline_refs = list_refs(&view).unwrap().into_iter().collect();
        let baseline_head = symbolic_head(&view).unwrap();
        let expectation = ViewExpectation {
            state_refs: BTreeMap::from([("refs/heads/main".to_owned(), commits[1].clone())]),
            state_head: Some("refs/heads/main".to_owned()),
            has_authoritative_state: true,
            pr_refs: BTreeMap::from([(expected_pr.clone(), commits[2].clone())]),
            ..ViewExpectation::default()
        };

        let (repairs, issues) = reconcile_view(
            &view,
            ObjectFormat::Sha1,
            expectation,
            &baseline_refs,
            baseline_head.as_deref(),
            false,
        )
        .unwrap();

        assert_eq!(repairs.updated, 1);
        assert_eq!(repairs.created, 1);
        assert_eq!(repairs.deleted, 1);
        assert!(issues.is_empty(), "{issues:#?}");
        assert_eq!(git(&view, &["rev-parse", "refs/heads/main"]), commits[0]);
        assert!(ref_exists(&view, "refs/heads/stale"));
        assert!(!ref_exists(&view, &expected_pr));
    }

    #[test]
    fn missing_authoritative_object_requires_manual_inspection() {
        let (_temp, _storage, _key, view, commits) = fixture();
        git(&view, &["update-ref", "refs/heads/main", &commits[0]]);
        let missing = "f".repeat(40);
        let expectation = ViewExpectation {
            state_refs: BTreeMap::from([("refs/heads/main".to_owned(), missing.clone())]),
            state_head: Some("refs/heads/main".to_owned()),
            has_authoritative_state: true,
            ..ViewExpectation::default()
        };

        let (repairs, issues) = reconcile_fixture(&view, expectation);

        assert!(!repairs.any());
        assert_eq!(git(&view, &["rev-parse", "refs/heads/main"]), commits[0]);
        assert!(issues.iter().any(|issue| {
            issue.category == "missing_authoritative_object"
                && issue.expected_oid.as_deref() == Some(missing.as_str())
        }));
    }

    #[test]
    fn online_pass_never_overwrites_a_ref_changed_after_its_snapshot() {
        let (_temp, _storage, _key, view, commits) = fixture();
        git(&view, &["update-ref", "refs/heads/main", &commits[0]]);
        let baseline_refs = list_refs(&view).unwrap().into_iter().collect();
        let baseline_head = symbolic_head(&view).unwrap();
        git(&view, &["update-ref", "refs/heads/main", &commits[1]]);
        let expectation = ViewExpectation {
            state_refs: BTreeMap::from([("refs/heads/main".to_owned(), commits[2].clone())]),
            state_head: Some("refs/heads/main".to_owned()),
            has_authoritative_state: true,
            ..ViewExpectation::default()
        };

        let (repairs, issues) = reconcile_view(
            &view,
            ObjectFormat::Sha1,
            expectation,
            &baseline_refs,
            baseline_head.as_deref(),
            true,
        )
        .unwrap();

        assert!(!repairs.any());
        assert_eq!(git(&view, &["rev-parse", "refs/heads/main"]), commits[1]);
        assert!(issues
            .iter()
            .any(|issue| issue.category == "concurrent_ref_change"));
    }

    #[test]
    fn expectations_follow_authorized_state_and_exact_pr_coordinates() {
        let owner = Keys::generate();
        let submitter = Keys::generate();
        let other_owner = Keys::generate();
        let commit = "1".repeat(40);
        let pr_commit = "2".repeat(40);
        let announcement_event = EventBuilder::new(Kind::GitRepoAnnouncement, "")
            .tags([Tag::identifier("project")])
            .finalize(&owner)
            .unwrap();
        let state_event = EventBuilder::new(Kind::RepoState, "")
            .tags([
                Tag::identifier("project"),
                Tag::custom("refs/heads/main", [commit.clone()]),
                Tag::custom("HEAD", ["ref: refs/heads/main"]),
            ])
            .finalize(&owner)
            .unwrap();
        let matching_pr = EventBuilder::new(Kind::GitPullRequest, "")
            .tags([
                Tag::custom(
                    "a",
                    [format!("30617:{}:project", owner.public_key().to_hex())],
                ),
                Tag::custom("c", [pr_commit.clone()]),
            ])
            .finalize(&submitter)
            .unwrap();
        let other_identifier_pr = EventBuilder::new(Kind::GitPullRequestUpdate, "")
            .tags([
                Tag::custom(
                    "a",
                    [format!(
                        "30617:{}:different-project",
                        other_owner.public_key().to_hex()
                    )],
                ),
                Tag::custom("c", ["3".repeat(40)]),
            ])
            .finalize(&submitter)
            .unwrap();
        let repo_data = RepositoryData {
            announcements: vec![RepositoryAnnouncement::from_event(announcement_event).unwrap()],
            states: vec![RepositoryState::from_event(state_event).unwrap()],
        };

        let expectation = build_expectation(
            &ViewIdentity::Owner {
                pubkey: owner.public_key(),
            },
            "project",
            &repo_data,
            &[matching_pr.clone(), other_identifier_pr],
            &[],
            &[],
            Some("relay.example"),
        );

        assert_eq!(expectation.state_refs.get("refs/heads/main"), Some(&commit));
        assert_eq!(expectation.state_head.as_deref(), Some("refs/heads/main"));
        assert_eq!(
            expectation
                .pr_refs
                .get(&format!("refs/nostr/{}", matching_pr.id)),
            Some(&pr_commit)
        );
        assert_eq!(expectation.pr_refs.len(), 1);
    }

    #[test]
    fn standard_placeholder_authorizes_only_recorded_owner_and_identifier() {
        let owner = Keys::generate().public_key();
        let other = Keys::generate().public_key();
        let purgatory = crate::purgatory::Purgatory::new(PathBuf::new());
        let id = "ab".repeat(32);
        let commit = "cd".repeat(20);
        purgatory.add_standard_pr_placeholder(id.clone(), commit.clone(), owner, "project".into());
        let pending = vec![(id.clone(), purgatory.find_pr(&id).unwrap())];
        let data = RepositoryData {
            announcements: vec![],
            states: vec![],
        };
        for (pubkey, identifier, matches) in [
            (owner, "project", true),
            (other, "project", false),
            (owner, "other", false),
        ] {
            let expectation = build_expectation(
                &ViewIdentity::Owner { pubkey },
                identifier,
                &data,
                &[],
                &pending,
                &[],
                None,
            );
            assert_eq!(
                expectation.pending_pr_refs.get(&format!("refs/nostr/{id}")),
                matches.then_some(&commit)
            );
            assert!(expectation.ambiguous_placeholders.is_empty());
        }
    }

    #[test]
    fn owner_view_accepts_only_its_exact_standard_clone_endpoint() {
        let source_owner = Keys::generate();
        let target_owner = Keys::generate();
        let other_owner = Keys::generate();
        let source_npub = source_owner.public_key().to_bech32().unwrap();
        let other_npub = other_owner.public_key().to_bech32().unwrap();
        let identity = ViewIdentity::Owner {
            pubkey: source_owner.public_key(),
        };
        let maintainers = vec![source_owner.public_key().to_hex()];
        let target = format!(
            "30617:{}:upstream-project",
            target_owner.public_key().to_hex()
        );
        let matching_url = format!("https://relay.example/grasp/{source_npub}/source-project.git");
        let event_with_clone = |url: String| {
            EventBuilder::new(Kind::GitPullRequest, "")
                .tags([
                    Tag::custom("a", [target.clone()]),
                    Tag::custom("c", ["1".repeat(40)]),
                    Tag::custom("clone", [url]),
                ])
                .finalize(&source_owner)
                .unwrap()
        };

        let matching = event_with_clone(matching_url.clone());
        assert!(event_applies_to_view(
            &matching,
            &identity,
            "source-project",
            Some(&maintainers),
            Some("relay.example/grasp"),
        ));
        assert!(event_relevant_to_identifier(
            &matching,
            "source-project",
            Some("relay.example/grasp"),
        ));

        let rejected_urls = [
            format!("https://relay.example/grasp/{other_npub}/source-project.git"),
            format!("https://relay.example/grasp/{source_npub}/other-project.git"),
            format!("https://other.example/grasp/{source_npub}/source-project.git"),
            format!("{matching_url}?download=1"),
            format!("{matching_url}#fragment"),
            format!("{matching_url}/info/refs"),
            format!("https://relay.example/grasp/prs/{source_npub}/source-project.git"),
        ];
        for url in rejected_urls {
            let event = event_with_clone(url.clone());
            assert!(
                !event_applies_to_view(
                    &event,
                    &identity,
                    "source-project",
                    Some(&maintainers),
                    Some("relay.example/grasp"),
                ),
                "unexpectedly accepted {url}"
            );
        }
    }

    #[test]
    fn owner_view_retains_base_repository_a_tag_authorization() {
        let owner = Keys::generate();
        let submitter = Keys::generate();
        let event = EventBuilder::new(Kind::GitPullRequestUpdate, "")
            .tags([
                Tag::custom(
                    "a",
                    [format!("30617:{}:project", owner.public_key().to_hex())],
                ),
                Tag::custom("c", ["2".repeat(40)]),
            ])
            .finalize(&submitter)
            .unwrap();

        assert!(event_applies_to_view(
            &event,
            &ViewIdentity::Owner {
                pubkey: owner.public_key(),
            },
            "project",
            Some(&[owner.public_key().to_hex()]),
            Some("relay.example"),
        ));
    }
}
