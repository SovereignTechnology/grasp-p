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
use nostr_sdk::prelude::{Event, EventId, FromBech32, PublicKey, ToBech32};
use tracing::{error, info, warn};

use super::authorization::{compute_membership, extract_commit_tag, RepositoryData};
use super::integrity::{discover_families, discover_views, list_refs, FamilyRepairSource};
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
pub async fn run_startup_pass(storage: &LocalGitStorage, source: &RealSyncContext) {
    let mut stats = PassStats::default();
    let families = match discover_families(storage) {
        Ok(families) => families,
        Err(error) => {
            error!(%error, "Git authorization-integrity startup discovery failed");
            stats.failed = 1;
            log_completion(&stats);
            return;
        }
    };
    let accepted_prs = match source.accepted_pr_events_for_integrity().await {
        Ok(events) => events,
        Err(error) => {
            error!(%error, "Git authorization-integrity authoritative event query failed");
            stats.families = families.len();
            stats.failed = 1;
            log_completion(&stats);
            return;
        }
    };
    let pending_prs = source.pending_pr_entries_for_integrity();

    info!(
        families = families.len(),
        accepted_pr_events = accepted_prs.len(),
        pending_pr_entries = pending_prs.len(),
        "Git authorization-integrity startup pass started"
    );

    for key in families {
        stats.families += 1;
        if let Err(error) = check_family(
            storage,
            source,
            &key,
            &accepted_prs,
            &pending_prs,
            &mut stats,
        )
        .await
        {
            stats.failed += 1;
            error!(
                identifier = %key.identifier,
                object_format = %key.object_format,
                %error,
                manual_inspection = true,
                "Git authorization-integrity family check failed"
            );
        }
        tokio::task::yield_now().await;
    }

    log_completion(&stats);
}

fn log_completion(stats: &PassStats) {
    info!(
        families = stats.families,
        views_checked = stats.views_checked,
        healthy = stats.healthy,
        repaired = stats.repaired,
        manual_inspection = stats.manual_inspection,
        failed = stats.failed,
        refs_created = stats.refs_created,
        refs_updated = stats.refs_updated,
        refs_deleted = stats.refs_deleted,
        heads_set = stats.heads_set,
        "Git authorization-integrity startup pass completed"
    );
}

async fn check_family(
    storage: &LocalGitStorage,
    source: &RealSyncContext,
    key: &FamilyKey,
    accepted_prs: &[Event],
    pending_prs: &[(String, PrPurgatoryEntry)],
    stats: &mut PassStats,
) -> Result<()> {
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
    if !missing.is_empty() {
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
        .filter(|event| event_mentions_identifier(event, &key.identifier))
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
        ) {
            Ok((repairs, issues)) => {
                stats.refs_created += repairs.created;
                stats.refs_updated += repairs.updated;
                stats.refs_deleted += repairs.deleted;
                stats.heads_set += repairs.heads_set;
                if issues.is_empty() {
                    if repairs.any() {
                        stats.repaired += 1;
                        info!(
                            identifier = %key.identifier,
                            object_format = %key.object_format,
                            view = %view.display(),
                            view_type = identity.kind(),
                            pubkey = %identity.pubkey_hex(),
                            refs_created = repairs.created,
                            refs_updated = repairs.updated,
                            refs_deleted = repairs.deleted,
                            heads_set = repairs.heads_set,
                            "Git authorization-integrity repaired repository view"
                        );
                    } else {
                        stats.healthy += 1;
                    }
                } else {
                    stats.manual_inspection += 1;
                    log_issues(key, &view, &identity, &issues);
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
            None if entry.prs_scope.is_none() && matches!(identity, ViewIdentity::Owner { .. }) => {
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
        ViewIdentity::Owner { .. } => {
            let tagged = tagged_owners(event, identifier);
            maintainers.is_some_and(|maintainers| {
                maintainers
                    .iter()
                    .any(|maintainer| tagged.contains(maintainer))
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
            }
        }
        reconcile_expected_refs(
            view,
            object_format,
            &current,
            baseline_refs,
            &expected.state_refs,
            &mut repairs,
            &mut expected.issues,
        );
        reconcile_head(
            view,
            expected.state_head.as_deref(),
            &expected.state_refs,
            baseline_head,
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
        &mut repairs,
        &mut expected.issues,
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
    repairs: &mut RepairCounts,
    issues: &mut Vec<IntegrityIssue>,
) {
    for (reference, target) in expected {
        let actual = current.get(reference);
        if actual == Some(target) {
            continue;
        }
        if baseline.get(reference) != actual {
            issues.push(IntegrityIssue::new(
                "concurrent_ref_change",
                reference,
                actual.cloned(),
                Some(target.clone()),
                "preserved because the ref changed while the online integrity pass was running",
            ));
            continue;
        }
        if !valid_oid(object_format, target) {
            issues.push(IntegrityIssue::new(
                "invalid_authoritative_oid",
                reference,
                actual.cloned(),
                Some(target.clone()),
                "authoritative event target is not a valid object ID for this family",
            ));
            continue;
        }
        if !super::oid_exists(view, target) {
            issues.push(IntegrityIssue::new(
                "missing_authoritative_object",
                reference,
                actual.cloned(),
                Some(target.clone()),
                "the expected object remains unavailable after accepted-source repair attempts",
            ));
            continue;
        }
        match update_ref_cas(
            view,
            reference,
            target,
            actual.map(String::as_str),
            object_format,
        ) {
            Ok(()) if actual.is_some() => repairs.updated += 1,
            Ok(()) => repairs.created += 1,
            Err(error) => issues.push(IntegrityIssue::new(
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

fn log_issues(key: &FamilyKey, view: &Path, identity: &ViewIdentity, issues: &[IntegrityIssue]) {
    for issue in issues.iter().take(MAX_ISSUES_PER_VIEW) {
        error!(
            identifier = %key.identifier,
            object_format = %key.object_format,
            view = %view.display(),
            view_type = identity.kind(),
            pubkey = %identity.pubkey_hex(),
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
}
