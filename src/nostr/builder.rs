/// Nostr Relay Builder Configuration
///
/// This module integrates nostr-relay-builder with NIP-34 validation logic
/// using modular sub-policies for each event type.
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use nostr::nips::nip19::ToBech32;
use nostr_lmdb::NostrLmdb;
use nostr_memory::MemoryDatabase;
use nostr_relay_builder::prelude::*;

use crate::config::{Config, DatabaseBackend};
use crate::nostr::events::RepositoryAnnouncement;
use crate::nostr::policy::{
    AnnouncementPolicy, AnnouncementResult, DeletionPolicy, PolicyContext, PrEventPolicy,
    ReferenceResult, RelatedEventPolicy, StatePolicy, StateResult,
};

/// Type alias for the shared database used by the relay
pub type SharedDatabase = Arc<dyn NostrDatabase>;

/// Build a rejection carrying the `invalid:` NIP-01 machine-readable prefix.
///
/// Use for client-fault rejections: malformed/unparseable events, failed
/// validation, bad refs, accepted-deletion-request, etc.
fn reject_invalid(message: impl Into<std::borrow::Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::reject(MachineReadablePrefix::Invalid, message)
}

/// Build a rejection carrying the `error:` NIP-01 machine-readable prefix.
///
/// Use for server-fault rejections: database/git failures and other internal
/// errors where the client is not at fault.
fn reject_error(message: impl Into<std::borrow::Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::reject(MachineReadablePrefix::Error, message)
}

/// Build a rejection carrying the `restricted:` NIP-01 machine-readable prefix.
///
/// Use for authorization-style rejections, e.g. an event that does not
/// reference an accepted repository or accepted event.
fn reject_restricted(message: impl Into<std::borrow::Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::reject(MachineReadablePrefix::Restricted, message)
}

/// Build an "accepted but not yet served" response (`status: true`) for events
/// parked in purgatory while awaiting their git data.
///
/// Uses the `duplicate:` prefix as the closest standard machine-readable hint
/// that the client should treat the submission as successfully received and
/// not retry immediately.
fn accepted_purgatory(message: impl Into<std::borrow::Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::ok_msg(MachineReadablePrefix::Duplicate, message)
}

/// Build a "duplicate, already have it" response (`status: true`).
fn duplicate(message: impl Into<std::borrow::Cow<'static, str>>) -> WritePolicyResult {
    WritePolicyResult::ok_msg(MachineReadablePrefix::Duplicate, message)
}


/// NIP-34 Write Policy with Full GRASP-01 Event Validation
///
/// Validates all events according to GRASP-01 specification using modular sub-policies:
/// - `AnnouncementPolicy` - Repository announcement validation
/// - `StatePolicy` - State event validation + ref alignment
/// - `PrEventPolicy` - PR/PR Update validation
/// - `RelatedEventPolicy` - Forward/backward reference checking
/// - `DeletionPolicy` - NIP-09 event deletion request handling
///
/// Uses stateful database queries to check event relationships.
#[derive(Clone)]
pub struct Nip34WritePolicy {
    ctx: PolicyContext,
    announcement_policy: AnnouncementPolicy,
    state_policy: StatePolicy,
    pr_event_policy: PrEventPolicy,
    related_event_policy: RelatedEventPolicy,
    deletion_policy: DeletionPolicy,
}

impl std::fmt::Debug for Nip34WritePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nip34WritePolicy")
            .field("domain", &self.ctx.domain)
            .field("git_data_path", &self.ctx.git_data_path)
            .field("database", &"<database>")
            .finish()
    }
}

impl Nip34WritePolicy {
    pub fn new(
        database: SharedDatabase,
        git_data_path: impl Into<std::path::PathBuf>,
        purgatory: std::sync::Arc<crate::purgatory::Purgatory>,
        config: crate::config::Config,
        repo_init_locks: crate::grasp06::receive::RepoInitLocks,
    ) -> Self {
        let ctx = PolicyContext::new(
            &config.domain,
            database,
            git_data_path,
            purgatory,
            config.clone(),
            repo_init_locks,
        );
        Self {
            announcement_policy: AnnouncementPolicy::new(ctx.clone(), config.clone()),
            state_policy: StatePolicy::new(ctx.clone()),
            pr_event_policy: PrEventPolicy::new(ctx.clone()),
            related_event_policy: RelatedEventPolicy::new(ctx.clone()),
            deletion_policy: DeletionPolicy::new(ctx.clone()),
            ctx,
        }
    }

    /// Check if an event author is blacklisted
    ///
    /// Returns Some(reason) if blacklisted, None if not blacklisted.
    fn check_event_blacklist(&self, event: &Event) -> Option<String> {
        let event_blacklist = self.ctx.config.event_blacklist_config();
        if !event_blacklist.enabled() {
            return None;
        }

        let npub = event.pubkey.to_bech32().ok()?;
        event_blacklist.check(&npub)
    }

    /// Get a reference to the purgatory for read-only access
    pub fn purgatory(&self) -> &std::sync::Arc<crate::purgatory::Purgatory> {
        &self.ctx.purgatory
    }

    /// Set the local relay for purgatory notifications.
    ///
    /// This must be called after the relay is created since the relay depends
    /// on this policy, but purgatory sync needs the relay to notify subscribers.
    pub fn set_local_relay(&self, relay: nostr_relay_builder::LocalRelay) {
        self.ctx.set_local_relay(relay);
    }

    /// Extract repository identifier from event's 'd' tag.
    ///
    /// Used for structured logging when parsing fails - we try to extract
    /// the identifier even if full parsing failed.
    fn extract_identifier_from_event(event: &Event) -> String {
        event
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Extract ALL repository identifiers from PR event's 'a' tags.
    ///
    /// PR events can reference multiple repositories via multiple 'a' tags
    /// (e.g., when there are multiple maintainers). Each tag has format
    /// `30617:<owner_pubkey>:<identifier>`.
    ///
    /// Returns a vector of unique identifiers, or `["unknown"]` if none found.
    fn extract_repos_from_pr_event(event: &Event) -> Vec<String> {
        let repos: Vec<String> = event
            .tags
            .iter()
            .filter_map(|tag| {
                let tag_vec = tag.clone().to_vec();
                if tag_vec.len() >= 2 && tag_vec[0] == "a" && tag_vec[1].starts_with("30617:") {
                    // Format: 30617:<owner_pubkey>:<identifier>
                    let parts: Vec<&str> = tag_vec[1].split(':').collect();
                    if parts.len() >= 3 {
                        Some(parts[2].to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Deduplicate while preserving order
        let mut seen = std::collections::HashSet::new();
        let unique_repos: Vec<String> = repos
            .into_iter()
            .filter(|r| seen.insert(r.clone()))
            .collect();

        if unique_repos.is_empty() {
            vec!["unknown".to_string()]
        } else {
            unique_repos
        }
    }

    /// Handle repository announcement event
    async fn handle_announcement(&self, event: &Event) -> WritePolicyResult {
        let event_id_str = event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex());

        match self.announcement_policy.validate(event).await {
            AnnouncementResult::Accept | AnnouncementResult::AcceptArchive => {
                // Parse announcement to get repository details
                match RepositoryAnnouncement::from_event(event.clone()) {
                    Ok(announcement) => {
                        // Try to create bare repository if it doesn't exist
                        if let Err(e) = self
                            .announcement_policy
                            .ensure_bare_repository(&announcement)
                        {
                            tracing::warn!(
                                "Failed to create bare repository for {}: {}",
                                event_id_str,
                                e
                            );
                            // Note: We still accept the event even if repo creation fails
                        }

                        tracing::debug!("Accepted repository announcement: {}", event_id_str);

                        // Check purgatory for state events that might now be authorized
                        self.check_purgatory_state_events_for_identifier(&announcement.identifier)
                            .await;

                        WritePolicyResult::Accept
                    }
                    Err(e) => {
                        let npub = event
                            .pubkey
                            .to_bech32()
                            .unwrap_or_else(|_| event.pubkey.to_hex());
                        let event_id_short = &event.id.to_hex()[..12];
                        // Try to extract repo identifier from 'd' tag even if parsing failed
                        let repo = Self::extract_identifier_from_event(event);
                        // Structured log for migration scripts
                        tracing::warn!(
                            "[PARSE_FAIL] kind={} event_id={}... reason=\"{}\" repo={} npub={}",
                            event.kind.as_u16(),
                            event_id_short,
                            e,
                            repo,
                            npub
                        );
                        reject_invalid(format!("Failed to parse announcement: {}", e))
                    }
                }
            }
            AnnouncementResult::AcceptPurgatory => {
                // New announcement - add to purgatory
                match self.announcement_policy.add_to_purgatory(event) {
                    Ok(()) => {
                        tracing::info!(
                            "Accepted announcement to purgatory: {} (waiting for git data)",
                            event_id_str
                        );

                        accepted_purgatory("purgatory: won't be served until git data arrives")
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to add announcement to purgatory {}: {}",
                            event_id_str,
                            e
                        );
                        reject_error(e)
                    }
                }
            }
            AnnouncementResult::AcceptMaintainer => {
                // Parse announcement to get details for logging
                match RepositoryAnnouncement::from_event(event.clone()) {
                    Ok(announcement) => {
                        tracing::info!(
                            "Accepted maintainer announcement {} (author {} is listed as maintainer for {})",
                            event_id_str,
                            event.pubkey.to_hex(),
                            announcement.identifier
                        );
                        // Don't create bare repository for external announcements

                        // Check purgatory for state events that might now be authorized
                        self.check_purgatory_state_events_for_identifier(&announcement.identifier)
                            .await;

                        WritePolicyResult::Accept
                    }
                    Err(e) => {
                        let npub = event
                            .pubkey
                            .to_bech32()
                            .unwrap_or_else(|_| event.pubkey.to_hex());
                        let event_id_short = &event.id.to_hex()[..12];
                        // Try to extract repo identifier from 'd' tag even if parsing failed
                        let repo = Self::extract_identifier_from_event(event);
                        // Structured log for migration scripts
                        tracing::warn!(
                            "[PARSE_FAIL] kind={} event_id={}... reason=\"{}\" repo={} npub={}",
                            event.kind.as_u16(),
                            event_id_short,
                            e,
                            repo,
                            npub
                        );
                        reject_invalid(format!("Failed to parse announcement: {}", e))
                    }
                }
            }
            AnnouncementResult::Reject(reason) => {
                tracing::warn!(
                    "Rejected repository announcement {}: {}",
                    event_id_str,
                    reason
                );
                reject_invalid(reason)
            }
        }
    }

    /// Handle repository state event
    ///
    /// # Arguments
    /// * `event` - The state event to validate
    /// * `is_synced` - True if this event came from proactive sync (vs user-submitted)
    async fn handle_state(&self, event: &Event, is_synced: bool) -> WritePolicyResult {
        match self.state_policy.validate(event) {
            StateResult::Accept => {
                // Process state alignment asynchronously
                match self
                    .state_policy
                    .process_state_event(event, is_synced)
                    .await
                {
                    Ok(poilicy_result) => poilicy_result,
                    Err(e) => {
                        let npub = event
                            .pubkey
                            .to_bech32()
                            .unwrap_or_else(|_| event.pubkey.to_hex());
                        let event_id_short = &event.id.to_hex()[..12];
                        // Try to extract repo identifier from 'd' tag even if parsing failed
                        let repo = Self::extract_identifier_from_event(event);
                        // Structured log for migration scripts
                        tracing::warn!(
                            "[PARSE_FAIL] kind={} event_id={}... reason=\"{}\" repo={} npub={}",
                            event.kind.as_u16(),
                            event_id_short,
                            e,
                            repo,
                            npub
                        );
                        // reject if processing failed
                        WritePolicyResult::Reject {
                            status: false,
                            prefix: MachineReadablePrefix::Error,
                            message: format!("error: {e}").into(),
                        }
                    }
                }
            }
            StateResult::Reject(reason) => {
                let npub = event
                    .pubkey
                    .to_bech32()
                    .unwrap_or_else(|_| event.pubkey.to_hex());
                let event_id_short = &event.id.to_hex()[..12];
                // Try to extract repo identifier from 'd' tag even if parsing failed
                let repo = Self::extract_identifier_from_event(event);
                // Structured log for migration scripts
                tracing::warn!(
                    "[PARSE_FAIL] kind={} event_id={}... reason=\"{}\" repo={} npub={}",
                    event.kind.as_u16(),
                    event_id_short,
                    reason,
                    repo,
                    npub
                );
                reject_invalid(reason)
            }
        }
    }

    /// Handle PR or PR Update event
    ///
    /// # Arguments
    /// * `event` - The PR event to validate
    /// * `is_synced` - True if this event came from proactive sync (vs user-submitted)
    async fn handle_pr_event(&self, event: &Event, is_synced: bool) -> WritePolicyResult {
        let event_id_str = event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex());

        // duplicate check in purgatory
        let in_purgatory = self
            .ctx
            .purgatory
            .find_pr(&event.id.to_hex())
            .is_some_and(|e| e.event.is_some());
        if in_purgatory {
            tracing::debug!(
                "processed PR event duplicate (already in purgatory): {}",
                event.id,
            );
            return duplicate("duplicate: in purgatory");
        }

        // duplicate check in db
        match &self.ctx.database.check_id(&event.id).await {
            Ok(DatabaseEventStatus::Saved) => {
                return duplicate("duplicate");
            }
            Ok(DatabaseEventStatus::Deleted) => {
                return reject_invalid("invalid: accepted deletion request for this event");
            }
            Err(e) => {
                return reject_error(format!("error: internal error: {e}"));
            }
            _ => {} // continue
        }

        // Reject PRs unrelated to stored repositories / events.
        //
        // GRASP-06 (06.md lines 21–24) relaxes this: a PR / PR-Update event
        // whose `clone` tag names this relay's
        // `/prs/<signer-npub>/<d>.git` endpoint (and which carries a
        // matching `a` tag of the form `30617:<hex>:<d>`) MUST be accepted
        // even when no announcement for the target coord is on this relay.
        // Such events skip the related-event check and fall through to the
        // git-data-check + purgatory branch below.
        match self.handle_related_event(event, "PR").await {
            WritePolicyResult::Accept => {} // continue
            rejected => {
                if !crate::grasp06::policy::event_qualifies_for_pr_relaxation(
                    event,
                    &self.ctx.config,
                ) {
                    return rejected;
                }
                tracing::info!(
                    "Accepted orphan PR event {} under GRASP-06: clone tag names this relay's /prs/ endpoint",
                    event_id_str,
                );
            }
        }

        // Check if git data exists (delete any incorrect commits at refs/nostr/<event-id>, copies correct data to relivant repositories)
        match self.pr_event_policy.git_data_check(event).await {
            Ok(false) => {
                // Only reject expired events if they're from sync (not user-submitted)
                // User-submitted events should be allowed to retry in case git data became available
                if is_synced && self.ctx.purgatory.is_expired(&event.id) {
                    tracing::debug!(
                        event_id = %event_id_str,
                        "PR event previously expired from purgatory (synced), rejecting to prevent re-sync loop"
                    );
                    return reject_invalid(
                        "invalid: previously expired from purgatory without git data",
                    );
                }

                // No git data exists - add to purgatory
                let commit = event
                    .tags
                    .iter()
                    .find_map(|tag| {
                        let tag_vec = tag.clone().to_vec();
                        if tag_vec.len() >= 2 && tag_vec[0] == "c" {
                            Some(tag_vec[1].clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                tracing::info!(
                    "PR event {} added to purgatory: waiting for git push with commit {}",
                    event_id_str,
                    commit
                );

                // Add to purgatory
                self.ctx.purgatory.add_pr(
                    event.clone(),
                    event.id.to_hex(),
                    commit.clone(),
                    is_synced,
                );

                WritePolicyResult::Reject {
                    status: true, // Client sees OK
                    prefix: MachineReadablePrefix::Duplicate,
                    message: format!(
                        "purgatory: PR event stored, waiting for git push with commit {}",
                        commit
                    )
                    .into(),
                }
            }
            Ok(true) => {
                // Git data exists - proceed with normal validation
                tracing::debug!("Git data exists for PR event {}", event_id_str);
                WritePolicyResult::Accept
            }
            Err(e) => {
                // Error checking git data - reject event
                let npub = event
                    .pubkey
                    .to_bech32()
                    .unwrap_or_else(|_| event.pubkey.to_hex());
                let event_id_short = &event.id.to_hex()[..12];
                // Extract ALL repo identifiers from 'a' tags for PR events
                // (PR events can reference multiple repos when there are multiple maintainers)
                let repos = Self::extract_repos_from_pr_event(event);
                // Structured log for migration scripts - log once per repo
                for repo in &repos {
                    tracing::warn!(
                        "[PARSE_FAIL] kind={} event_id={}... reason=\"git data check failed: {}\" repo={} npub={}",
                        event.kind.as_u16(),
                        event_id_short,
                        e,
                        repo,
                        npub
                    );
                }
                reject_error(format!("Failed to check git data: {}", e))
            }
        }
    }

    /// Check purgatory for state events that might now be authorized by a new announcement
    ///
    /// When an announcement is accepted, state events in purgatory that were previously
    /// rejected due to missing announcements might now be authorized. This method:
    /// 1. Finds all state events in purgatory for the identifier
    /// 2. Re-evaluates authorization for each event
    /// 3. Processes authorized events (releases from purgatory)
    /// 4. Keeps unauthorized events in purgatory (will expire naturally)
    async fn check_purgatory_state_events_for_identifier(&self, identifier: &str) {
        let state_events = self.ctx.purgatory.find_state(identifier);

        if state_events.is_empty() {
            return;
        }

        tracing::debug!(
            identifier = %identifier,
            count = state_events.len(),
            "Checking purgatory state events after announcement acceptance"
        );

        for entry in state_events {
            // Re-evaluate authorization with the new announcement
            match self
                .state_policy
                .process_state_event(&entry.event, false)
                .await
            {
                Ok(WritePolicyResult::Accept) => {
                    tracing::info!(
                        event_id = %entry.event.id,
                        identifier = %identifier,
                        "State event in purgatory now authorized, will be processed"
                    );
                    // Event will be automatically removed from purgatory by process_state_event
                    // and broadcast to subscribers
                }
                Ok(WritePolicyResult::Reject { message, .. }) => {
                    if message.contains("not authorized") {
                        tracing::debug!(
                            event_id = %entry.event.id,
                            identifier = %identifier,
                            "State event in purgatory still not authorized, keeping in purgatory"
                        );
                        // Keep in purgatory - will expire naturally after 30 minutes
                    } else {
                        tracing::debug!(
                            event_id = %entry.event.id,
                            identifier = %identifier,
                            reason = %message,
                            "State event in purgatory rejected for other reason"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        event_id = %entry.event.id,
                        identifier = %identifier,
                        error = %e,
                        "Error re-evaluating state event in purgatory"
                    );
                }
            }
        }
    }

    /// Handle events that must reference accepted repositories or events
    async fn handle_related_event(&self, event: &Event, event_type: &str) -> WritePolicyResult {
        let event_id_str = event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex());

        match self.related_event_policy.check_references(event).await {
            Ok(ReferenceResult::ReferencesRepository(addr_ref)) => {
                tracing::debug!(
                    "Accepted {} event {}: references accepted repository {}",
                    event_type,
                    event_id_str,
                    addr_ref
                );
                WritePolicyResult::Accept
            }
            Ok(ReferenceResult::ReferencesEvent(event_ref)) => {
                tracing::debug!(
                    "Accepted {} event {}: references accepted event {}",
                    event_type,
                    event_id_str,
                    event_ref
                );
                WritePolicyResult::Accept
            }
            Ok(ReferenceResult::ReferencedByAccepted) => {
                tracing::debug!(
                    "Accepted {} event {}: referenced by accepted event",
                    event_type,
                    event_id_str
                );
                WritePolicyResult::Accept
            }
            Ok(ReferenceResult::Orphan) => {
                let (addressable_refs, event_refs) =
                    RelatedEventPolicy::extract_reference_tags(event);
                tracing::info!(
                    "Rejected orphan {} event {} (kind={}, pubkey={}): no references to accepted repos or events (checked {} addressable, {} event refs)",
                    event_type,
                    event.id.to_hex(),
                    event.kind.as_u16(),
                    event.pubkey.to_hex(),
                    addressable_refs.len(),
                    event_refs.len()
                );
                reject_restricted(format!(
                    "{} event must reference an accepted repository or accepted event",
                    event_type
                ))
            }
            Err(e) => {
                tracing::warn!(
                    "Database query failed for {} {}, rejecting (fail-secure): {}",
                    event_type,
                    event_id_str,
                    e
                );
                reject_error(format!("Database query failed: {}", e))
            }
        }
    }
}

impl WritePolicy for Nip34WritePolicy {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr_relay_builder::prelude::Event,
        addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, WritePolicyResult> {
        Box::pin(async move {
            // Check event blacklist FIRST - it overrides everything
            if let Some(reason) = self.check_event_blacklist(event) {
                tracing::debug!(
                    event_id = %event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex()),
                    author = %event.pubkey.to_hex(),
                    reason = %reason,
                    "Rejected event from blacklisted author"
                );
                return WritePolicyResult::reject(MachineReadablePrefix::Blocked, reason);
            }

            // Detect if this is a synced event (from proactive sync) vs user-submitted
            // Sync uses localhost:0 as a dummy address
            let is_synced = addr.ip().is_loopback() && addr.port() == 0;

            match event.kind {
                Kind::GitRepoAnnouncement => self.handle_announcement(event).await,
                Kind::RepoState => self.handle_state(event, is_synced).await,
                Kind::GitPullRequest | Kind::GitPullRequestUpdate => {
                    self.handle_pr_event(event, is_synced).await
                }
                Kind::GitUserGraspList => {
                    // Accept all kind 10317 (User Grasp List) events
                    // for better GRASP repository discovery
                    tracing::debug!(
                        event_id = %event.id.to_bech32().unwrap_or_else(|_| event.id.to_hex()),
                        author = %event.pubkey.to_hex(),
                        "Accepted kind 10317 user grasp list"
                    );
                    WritePolicyResult::Accept
                }
                Kind::EventDeletion => self.deletion_policy.handle(event).await,
                _ => self.handle_related_event(event, "Event").await,
            }
        })
    }
}

/// Result of creating a relay - includes relay, database, and write policy
pub struct RelayWithDatabase {
    /// The local relay instance
    pub relay: LocalRelay,
    /// The database Arc that can be used for direct queries
    pub database: SharedDatabase,
    /// The write policy used for event validation
    pub write_policy: Nip34WritePolicy,
}

/// Create a configured LocalRelay with full GRASP-01 validation
///
/// Returns a `RelayWithDatabase` struct containing:
/// - The `LocalRelay` for handling WebSocket connections
/// - The `SharedDatabase` for direct database queries (e.g., push authorization)
pub async fn create_relay(
    config: &Config,
    purgatory: Arc<crate::purgatory::Purgatory>,
    repo_init_locks: crate::grasp06::receive::RepoInitLocks,
) -> Result<RelayWithDatabase> {
    tracing::info!("Configuring nostr relay with GRASP-01 validation...");

    // Determine database path
    let db_path = Path::new(&config.relay_data_path);

    // Create database based on configuration
    let database: SharedDatabase = match config.database_backend {
        DatabaseBackend::Memory => {
            tracing::info!("Using in-memory database (no persistence)");
            Arc::new(MemoryDatabase::bounded(NonZeroUsize::new(100_000).unwrap()))
        }
        DatabaseBackend::Lmdb => {
            tracing::info!("Using LMDB backend at: {}", db_path.display());
            // Ensure the database directory exists
            std::fs::create_dir_all(db_path).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create LMDB directory {}: {}",
                    db_path.display(),
                    e
                )
            })?;
            Arc::new(NostrLmdb::open(db_path).await.map_err(|e| {
                anyhow::anyhow!(
                    "Failed to open LMDB database at {}: {}",
                    db_path.display(),
                    e
                )
            })?)
        }
    };

    // Build relay with GRASP-01 validation
    // Clone Arc for the write policy so both relay and policy can access the database
    let git_data_path = config.effective_git_data_path();

    // Log archive configuration (config.validate() must be called at startup)
    let archive_config = config.archive_config();
    if archive_config.enabled() {
        tracing::info!(
            "GRASP-05 archive mode enabled: archive_all={}, whitelist_entries={}, read_only={}",
            archive_config.archive_all,
            archive_config.whitelist.len(),
            archive_config.read_only
        );
    }

    // Log repository configuration
    let repository_config = config.repository_config();
    if repository_config.enabled() {
        tracing::info!(
            "Repository whitelist enabled: whitelist_entries={}",
            repository_config.whitelist.len()
        );
    }

    // Create write policy with purgatory integration
    let write_policy = Nip34WritePolicy::new(
        database.clone(),
        &git_data_path,
        purgatory,
        config.clone(),
        repo_init_locks,
    );

    let mut builder = LocalRelayBuilder::default()
        .database(database.clone())
        .write_policy(write_policy.clone())
        // Explicitly set rate limits (make defaults visible in code)
        // Per-connection limits: 500 max subscriptions, 60 events/min
        .rate_limit(RateLimit {
            max_reqs: 500,        // Max concurrent subscriptions per connection
            notes_per_minute: 60, // Max events per minute per connection
        });

    if let Some(max) = config.max_connections {
        builder = builder.max_connections(max);
    }

    let relay = builder.build();

    tracing::info!(
        "Relay configured with GRASP-01 validation for domain: {}",
        config.domain
    );

    Ok(RelayWithDatabase {
        relay,
        database,
        write_policy,
    })
}
