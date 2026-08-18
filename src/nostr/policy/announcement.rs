/// Announcement Policy - Repository announcement validation
///
/// Handles validation of NIP-34 repository announcements (kind 30617)
/// according to GRASP-01 specification.
use nostr_sdk::prelude::{Event, Filter, Kind, PublicKey, SingleLetterTag};
use std::collections::HashSet;
use std::time::Duration;

use super::PolicyContext;
use crate::config::Config;
use crate::nostr::events::{validate_announcement, RepositoryAnnouncement};
use crate::private::PrivateAccess;

/// Result of announcement policy evaluation
#[derive(Debug, Clone, PartialEq)]
pub enum AnnouncementResult {
    /// Accept: Event lists our service (GRASP-01 compliant) - replacement announcement
    Accept,
    /// Accept as maintainer: Event accepted via maintainer exception (multi-maintainer)
    AcceptMaintainer,
    /// Accept as archive: Event accepted via GRASP-05 archive whitelist (read-only)
    AcceptArchive,
    /// Accept to purgatory: New announcement, waiting for git data
    AcceptPurgatory,
    /// Reject: Event fails validation with reason
    Reject(String),
}

/// Policy for validating repository announcements
#[derive(Clone)]
pub struct AnnouncementPolicy {
    ctx: PolicyContext,
    config: Config,
    /// GRASP-08 live effective member set; `Some` only in private mode.
    private_access: Option<PrivateAccess>,
}

impl AnnouncementPolicy {
    pub fn new(ctx: PolicyContext, config: Config, private_access: Option<PrivateAccess>) -> Self {
        Self {
            ctx,
            config,
            private_access,
        }
    }

    /// Validate a repository announcement event
    ///
    /// Returns:
    /// - `Accept` if this is a replacement announcement (active announcement exists in DB or
    ///   purgatory)
    /// - `AcceptPurgatory` if this is a new announcement (no active announcement exists)
    /// - `AcceptMaintainer` if accepted via maintainer exception
    /// - `AcceptArchive` if accepted via GRASP-05 archive config
    /// - `Reject` with reason if validation fails
    pub async fn validate(&self, event: &Event) -> AnnouncementResult {
        // GRASP-08: on a private service, admitting an announcement expands
        // hosting and — via its referenced relays' NIP-11 owners — the member
        // set itself. Only a current effective member may therefore introduce
        // one; the check runs against the live member set at admission time
        // and covers every arrival path, since all announcement admission
        // funnels through this method. Removal is not retroactive:
        // repositories admitted while their author was a member stay hosted.
        if let Some(access) = &self.private_access {
            if !access.contains(&event.pubkey) {
                return AnnouncementResult::Reject(
                    "Announcement author is not authorized on this private service".to_string(),
                );
            }
        }

        // First, try validation (GRASP-01 + GRASP-05)
        let validation_result = validate_announcement(event, &self.config);

        match validation_result {
            AnnouncementResult::Reject(reason) => {
                // Validation failed - check maintainer exception
                // GRASP-01 Exception: Accept announcements from recursive maintainers
                match RepositoryAnnouncement::from_event(event.clone()) {
                    Ok(announcement) => {
                        // If this pubkey+identifier has a purgatory entry AND the incoming
                        // event is strictly newer, the owner is sending a replacement that
                        // removes our service. Clear the purgatory entry and its bare repo.
                        //
                        // If the incoming event is older than the purgatory entry (e.g. a
                        // relay replay of a superseded announcement), ignore it — the newer
                        // purgatory entry takes precedence and must not be evicted.
                        let should_evict = self
                            .ctx
                            .purgatory
                            .find_announcement(&event.pubkey, &announcement.identifier)
                            .is_some_and(|entry| event.created_at > entry.event.created_at);

                        if should_evict {
                            self.remove_purgatory_announcement(
                                &event.pubkey,
                                &announcement.identifier,
                            );
                        }

                        // Owner de-list replacement for an already served repo:
                        // do NOT allow maintainer-exception acceptance to bypass
                        // de-list enforcement when the previous announcement
                        // actually listed this service. An external maintainer
                        // announcement never listed this service, so its
                        // replacement must remain eligible for the maintainer
                        // exception instead of being mistaken for a de-list.
                        let service = self.config.service_address();
                        let lists_service = announcement.lists_service(&service);
                        if !lists_service {
                            match self
                                .db_announcement(&event.pubkey, &announcement.identifier)
                                .await
                            {
                                Ok(Some(current_event)) => {
                                    let current =
                                        match RepositoryAnnouncement::from_event(current_event) {
                                            Ok(current) => current,
                                            Err(_) => return AnnouncementResult::Reject(reason),
                                        };
                                    if current.lists_service(&service) {
                                        return AnnouncementResult::Reject(reason);
                                    }
                                }
                                Ok(None) => {}
                                Err(_) => return AnnouncementResult::Reject(reason),
                            }
                        }

                        match self
                            .is_maintainer_in_any_announcement(
                                &announcement.identifier,
                                &event.pubkey,
                            )
                            .await
                        {
                            Ok(true) => AnnouncementResult::AcceptMaintainer,
                            Ok(false) => AnnouncementResult::Reject(reason),
                            Err(_) => {
                                // Fail-secure: reject on database errors
                                AnnouncementResult::Reject(reason)
                            }
                        }
                    }
                    Err(_) => AnnouncementResult::Reject(reason),
                }
            }
            AnnouncementResult::Accept | AnnouncementResult::AcceptArchive => {
                // Parse announcement to check for existing active announcement
                match RepositoryAnnouncement::from_event(event.clone()) {
                    Ok(announcement) => {
                        let db_announcement = match self
                            .db_announcement(&event.pubkey, &announcement.identifier)
                            .await
                        {
                            Ok(event) => event,
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "Failed to check for existing DB announcement - rejecting"
                                );
                                return AnnouncementResult::Reject(format!(
                                    "Database error checking existing announcement: {}",
                                    e
                                ));
                            }
                        };

                        if let Some(current_event) = db_announcement {
                            let current = match RepositoryAnnouncement::from_event(current_event) {
                                Ok(current) => current,
                                Err(e) => {
                                    return AnnouncementResult::Reject(format!(
                                        "Failed to parse stored announcement: {e}"
                                    ))
                                }
                            };
                            let current_maintainers: HashSet<&str> =
                                current.maintainers.iter().map(String::as_str).collect();
                            let incoming_maintainers: HashSet<&str> = announcement
                                .maintainers
                                .iter()
                                .map(String::as_str)
                                .collect();
                            if current_maintainers != incoming_maintainers {
                                tracing::debug!(
                                    identifier = %announcement.identifier,
                                    "Replacement announcement changes maintainers - routing through purgatory"
                                );
                                return AnnouncementResult::AcceptPurgatory;
                            }

                            // Replacement announcement with DB entry - accept immediately
                            tracing::debug!(
                                identifier = %announcement.identifier,
                                "Replacement announcement (DB) - accepting immediately"
                            );
                            return validation_result;
                        }

                        let in_purgatory = self
                            .ctx
                            .purgatory
                            .has_purgatory_announcement(&event.pubkey, &announcement.identifier);

                        if in_purgatory {
                            // Replacement announcement with purgatory entry - replace it and
                            // extend expiry so the new announcement gets a fresh 30-minute window.
                            tracing::debug!(
                                identifier = %announcement.identifier,
                                "Replacement announcement (purgatory) - replacing purgatory entry"
                            );
                            self.replace_purgatory_announcement(event, &announcement);
                            // Return AcceptPurgatory - git data hasn't arrived yet so the
                            // announcement must NOT be saved to the database. The purgatory
                            // entry has already been updated above with the newer event.
                            return AnnouncementResult::AcceptPurgatory;
                        }

                        // No existing announcement - route to purgatory
                        tracing::debug!(
                            identifier = %announcement.identifier,
                            "New announcement - routing to purgatory"
                        );
                        AnnouncementResult::AcceptPurgatory
                    }
                    Err(e) => {
                        AnnouncementResult::Reject(format!("Failed to parse announcement: {}", e))
                    }
                }
            }
            // AcceptPurgatory shouldn't come from validate_announcement, but handle it
            result => result,
        }
    }

    /// Replace a purgatory announcement entry with a newer event.
    ///
    /// Called when a replacement announcement arrives for a (pubkey, identifier) pair
    /// that is currently in purgatory. Updates the purgatory entry and extends the
    /// expiry so the new announcement has a fresh waiting window.
    fn replace_purgatory_announcement(&self, event: &Event, announcement: &RepositoryAnnouncement) {
        let repo_path = self.ctx.git_data_path.join(announcement.repo_path());
        let relays: HashSet<String> = announcement.relays.iter().cloned().collect();

        // add_announcement uses the (owner, identifier) key so it overwrites the old entry
        self.ctx.purgatory.add_announcement(
            event.clone(),
            announcement.identifier.clone(),
            event.pubkey,
            repo_path,
            relays,
        );

        if self
            .ctx
            .purgatory
            .has_pending_events(&announcement.identifier)
        {
            self.ctx
                .purgatory
                .enqueue_sync_immediate(&announcement.identifier);
        }

        // Extend the announcement's expiry (reset to full 30 min window)
        self.ctx.purgatory.extend_announcement_expiry(
            &event.pubkey,
            &announcement.identifier,
            Duration::from_secs(1800),
        );

        // Also extend any state events waiting for this identifier
        let state_entries = self.ctx.purgatory.find_state(&announcement.identifier);
        if !state_entries.is_empty() {
            let state_ids: Vec<_> = state_entries.iter().map(|e| e.event.id).collect();
            self.ctx.purgatory.extend_expiry(
                &announcement.identifier,
                &state_ids,
                Duration::from_secs(1800),
            );
        }
    }

    /// Remove a purgatory announcement and clean up associated resources.
    ///
    /// Called when a replacement announcement is rejected (owner removed our service).
    /// Deletes the bare repository from disk and removes any state events waiting for
    /// this identifier.
    fn remove_purgatory_announcement(&self, pubkey: &PublicKey, identifier: &str) {
        // Get the repo path before removing from purgatory
        if let Some(entry) = self.ctx.purgatory.find_announcement(pubkey, identifier) {
            // Delete the bare repository from disk
            if entry.repo_path.exists() {
                if let Err(e) = std::fs::remove_dir_all(&entry.repo_path) {
                    tracing::warn!(
                        path = %entry.repo_path.display(),
                        error = %e,
                        "Failed to delete bare repository during purgatory cleanup"
                    );
                } else {
                    tracing::info!(
                        path = %entry.repo_path.display(),
                        "Deleted bare repository for rejected purgatory announcement"
                    );
                }
            }
        }

        // Remove the announcement from purgatory
        self.ctx.purgatory.remove_announcement(pubkey, identifier);

        // Only remove state events if no other owner still has an announcement in purgatory
        // for this identifier. State events are keyed by identifier alone, so blindly removing
        // them would also discard state events legitimately belonging to a different owner's
        // repository that happens to share the same identifier string.
        let other_owners_remain = !self
            .ctx
            .purgatory
            .get_announcements_by_identifier(identifier)
            .is_empty();

        if !other_owners_remain {
            self.ctx.purgatory.remove_state(identifier);
        }

        tracing::info!(
            identifier = %identifier,
            other_owners_remain = %other_owners_remain,
            "Cleared purgatory entry: owner removed our service from announcement"
        );
    }

    /// Return the NIP-01-preferred served announcement for this coordinate.
    async fn db_announcement(
        &self,
        pubkey: &PublicKey,
        identifier: &str,
    ) -> Result<Option<Event>, String> {
        let filter = Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .author(*pubkey)
            .custom_tag(SingleLetterTag::LOWERCASE_D, identifier.to_string());

        let events: Vec<Event> = match self.ctx.database.query(filter).await {
            Ok(events) => events.into_iter().collect(),
            Err(e) => return Err(format!("Database query failed: {}", e)),
        };

        Ok(events.into_iter().max_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| right.id.cmp(&left.id))
        }))
    }

    /// Add an announcement to purgatory
    ///
    /// Creates the bare repository and stores the announcement in purgatory
    /// until git data arrives.
    pub fn add_to_purgatory(&self, event: &Event) -> Result<(), String> {
        let announcement = RepositoryAnnouncement::from_event(event.clone())
            .map_err(|e| format!("Failed to parse announcement: {}", e))?;

        // Create bare repository
        self.ensure_bare_repository(&announcement)?;

        // Build repo path
        let repo_path = self.ctx.git_data_path.join(announcement.repo_path());

        // Extract relays from announcement
        let relays: HashSet<String> = announcement.relays.iter().cloned().collect();

        // Add to purgatory
        self.ctx.purgatory.add_announcement(
            event.clone(),
            announcement.identifier.clone(),
            event.pubkey,
            repo_path,
            relays,
        );

        if self
            .ctx
            .purgatory
            .has_pending_events(&announcement.identifier)
        {
            self.ctx
                .purgatory
                .enqueue_sync_immediate(&announcement.identifier);
        }

        tracing::info!(
            identifier = %announcement.identifier,
            event_id = %event.id,
            "Added announcement to purgatory"
        );

        Ok(())
    }

    /// Create a bare git repository if it doesn't exist
    /// Path format: <git_data_path>/<npub>/<identifier>.git
    pub fn ensure_bare_repository(
        &self,
        announcement: &RepositoryAnnouncement,
    ) -> Result<(), String> {
        let repo_path = self.ctx.git_data_path.join(announcement.repo_path());

        // Check if repository already exists
        if repo_path.exists() {
            tracing::debug!("Repository already exists at {}", repo_path.display());
            return Ok(());
        }

        // Create parent directory (npub directory)
        let parent = repo_path
            .parent()
            .ok_or_else(|| format!("Invalid repository path: {}", repo_path.display()))?;

        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory {}: {}", parent.display(), e))?;

        // Initialize bare repository using git command
        let output = std::process::Command::new("git")
            .args(["init", "--bare", repo_path.to_str().unwrap()])
            .output()
            .map_err(|e| format!("Failed to execute git init: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git init failed: {}", stderr));
        }

        tracing::info!("Created bare repository at {}", repo_path.display());
        Ok(())
    }

    /// Check if a pubkey is listed as a maintainer in any announcement for this identifier
    ///
    /// A pubkey is considered a maintainer if:
    /// 1. They are the owner (pubkey) of an accepted announcement with this identifier, OR
    /// 2. They are listed in the maintainers tag of ANY announcement with this identifier
    ///
    /// This enables accepting announcements from maintainers even when they don't list
    /// this GRASP server, for maintainer chain discovery and GRASP-02 sync.
    ///
    /// Checks both the database (promoted announcements) and purgatory (announcements
    /// waiting for git data). This is necessary because a maintainer's announcement
    /// (which lists the recursive maintainer) may still be in purgatory when the
    /// recursive maintainer's announcement arrives.
    async fn is_maintainer_in_any_announcement(
        &self,
        identifier: &str,
        author: &PublicKey,
    ) -> Result<bool, String> {
        // Query all announcements with this identifier that are already in the database
        let filter = Filter::new()
            .kind(Kind::GitRepoAnnouncement)
            .custom_tag(SingleLetterTag::LOWERCASE_D, identifier.to_string());

        let db_announcements: Vec<Event> = match self.ctx.database.query(filter).await {
            Ok(events) => events.into_iter().collect(),
            Err(e) => return Err(format!("Database query failed: {}", e)),
        };

        // Also collect purgatory announcements for this identifier
        let purgatory_announcements: Vec<Event> = self
            .ctx
            .purgatory
            .get_announcements_by_identifier(identifier)
            .into_iter()
            .map(|entry| entry.event)
            .collect();

        let all_announcements: Vec<&Event> = db_announcements
            .iter()
            .chain(purgatory_announcements.iter())
            .collect();

        if all_announcements.is_empty() {
            // No existing announcements for this identifier - author cannot be a maintainer
            return Ok(false);
        }

        let author_hex = author.to_hex();

        // Check each announcement to see if author is listed as a maintainer
        for event in &all_announcements {
            // Check if author is the owner of this announcement
            if event.pubkey == *author {
                return Ok(true);
            }

            // Check if author is listed in the maintainers tag
            if let Ok(announcement) = RepositoryAnnouncement::from_event((*event).clone()) {
                if announcement.maintainers.contains(&author_hex) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Tag, ToBech32};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn policy(private_access: Option<PrivateAccess>) -> AnnouncementPolicy {
        let config = Config::for_testing();
        let ctx = PolicyContext::new_for_test(
            config.domain.clone(),
            Arc::new(nostr_memory::MemoryDatabase::unbounded()),
            PathBuf::new(),
            Arc::new(crate::purgatory::Purgatory::new(PathBuf::new())),
            config.clone(),
        );
        AnnouncementPolicy::new(ctx, config, private_access)
    }

    /// A GRASP-01-valid announcement listing the test service in both the
    /// `clone` and `relays` tags.
    fn service_announcement(keys: &Keys, domain: &str) -> Event {
        let npub = keys.public_key().to_bech32().expect("author npub");
        EventBuilder::new(Kind::GitRepoAnnouncement, "")
            .tags(vec![
                Tag::identifier("membership-gate-repo"),
                Tag::custom(
                    "clone",
                    [format!("https://{domain}/{npub}/membership-gate-repo.git")],
                ),
                Tag::custom("relays", [format!("wss://{domain}")]),
            ])
            .finalize(keys)
            .expect("signed announcement")
    }

    #[tokio::test]
    async fn private_mode_rejects_announcement_from_nonmember_author() {
        let member = Keys::generate();
        let outsider = Keys::generate();
        let policy = policy(Some(PrivateAccess::new([member.public_key()])));

        let event = service_announcement(&outsider, &policy.config.domain);
        let result = policy.validate(&event).await;

        assert!(
            matches!(result, AnnouncementResult::Reject(_)),
            "non-member author must be rejected in private mode: {result:?}"
        );
    }

    #[tokio::test]
    async fn private_mode_accepts_announcement_from_member_author() {
        let member = Keys::generate();
        let policy = policy(Some(PrivateAccess::new([member.public_key()])));

        let event = service_announcement(&member, &policy.config.domain);
        let result = policy.validate(&event).await;

        assert_eq!(
            result,
            AnnouncementResult::AcceptPurgatory,
            "member-authored announcement must pass the membership gate"
        );
    }

    #[tokio::test]
    async fn public_mode_ignores_the_membership_gate() {
        let author = Keys::generate();
        let policy = policy(None);

        let event = service_announcement(&author, &policy.config.domain);
        let result = policy.validate(&event).await;

        assert_eq!(
            result,
            AnnouncementResult::AcceptPurgatory,
            "public mode admission must be unchanged"
        );
    }
}
